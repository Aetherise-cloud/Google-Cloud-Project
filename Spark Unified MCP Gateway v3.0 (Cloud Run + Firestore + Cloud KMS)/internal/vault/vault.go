package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"spark-mcp-gateway/internal/store"
)

// TokenData represents decrypted credentials for an upstream provider connection.
type TokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"` // IsZero() means non-expiring (e.g. GitHub classic)
	Scope        string    `json:"scope,omitempty"`
	CloudID      string    `json:"cloud_id,omitempty"`      // For Jira Cloud
	SiteURL      string    `json:"site_url,omitempty"`      // For Jira Cloud
	AccountLabel string    `json:"account_label,omitempty"` // User handle/email
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

type cachedItem struct {
	token     *TokenData
	expiresAt time.Time
}

type sfCall struct {
	wg  sync.WaitGroup
	val *TokenData
	err error
}

// RefreshTokenFunc is the callback invoked to exchange a refresh token for new credentials.
type RefreshTokenFunc func(ctx context.Context, provider string, current *TokenData) (*TokenData, error)

// TokenVault manages envelope-encrypted credentials and distributed refresh leases.
type TokenVault struct {
	instanceID  string
	store       store.Store
	kms         KMSClient
	kmsKeyName  string
	refreshFunc RefreshTokenFunc

	cacheMu sync.RWMutex
	cache   map[string]*cachedItem

	sfMu    sync.Mutex
	sfCalls map[string]*sfCall
}

// NewTokenVault creates a new TokenVault instance.
func NewTokenVault(instanceID string, s store.Store, kms KMSClient, kmsKeyName string, refreshFunc RefreshTokenFunc) *TokenVault {
	if instanceID == "" {
		instanceID = generateInstanceID()
	}
	return &TokenVault{
		instanceID:  instanceID,
		store:       s,
		kms:         kms,
		kmsKeyName:  kmsKeyName,
		refreshFunc: refreshFunc,
		cache:       make(map[string]*cachedItem),
		sfCalls:     make(map[string]*sfCall),
	}
}

func generateInstanceID() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("inst-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("inst-%x", b)
}

func cacheKey(userID, provider string) string {
	return fmt.Sprintf("%s:%s", userID, provider)
}

func buildAAD(userID, provider string) []byte {
	return []byte(fmt.Sprintf("uid:%s|prv:%s", userID, provider))
}

// InvalidateCache clears the in-memory cache for a user connection.
func (v *TokenVault) InvalidateCache(userID, provider string) {
	v.cacheMu.Lock()
	delete(v.cache, cacheKey(userID, provider))
	v.cacheMu.Unlock()
}

// StoreToken encrypts and saves provider credentials into store.
func (v *TokenVault) StoreToken(ctx context.Context, userID, provider string, token *TokenData) error {
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		return err
	}

	// 1. Generate fresh per-record 32-byte AES-256 DEK
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return fmt.Errorf("failed generating DEK: %w", err)
	}

	// 2. Encrypt token JSON with AES-256-GCM using AAD
	block, err := aes.NewCipher(dek)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed generating nonce: %w", err)
	}

	aad := buildAAD(userID, provider)
	ciphertext := gcm.Seal(nil, nonce, tokenBytes, aad)

	// 3. Wrap DEK via KMS
	wrappedDEK, keyVer, err := v.kms.Encrypt(ctx, v.kmsKeyName, dek)
	if err != nil {
		return fmt.Errorf("failed wrapping DEK with KMS: %w", err)
	}

	// 4. Save to Store
	conn := &store.EncryptedConnection{
		UserID:        userID,
		Provider:      provider,
		WrappedDEK:    wrappedDEK,
		Nonce:         nonce,
		Ciphertext:    ciphertext,
		KMSKeyVersion: keyVer,
		UpdatedAt:     time.Now(),
	}

	if err := v.store.SaveConnection(ctx, conn); err != nil {
		return err
	}

	// 5. Invalidate and refresh cache
	v.cacheMu.Lock()
	v.cache[cacheKey(userID, provider)] = &cachedItem{
		token:     token,
		expiresAt: time.Now().Add(60 * time.Second),
	}
	v.cacheMu.Unlock()

	return nil
}

// DecryptConnection unencrypts credentials from an EncryptedConnection.
func (v *TokenVault) DecryptConnection(ctx context.Context, conn *store.EncryptedConnection) (*TokenData, error) {
	// 1. Unwrap DEK with KMS
	dek, err := v.kms.Decrypt(ctx, v.kmsKeyName, conn.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed unwrapping DEK: %w", err)
	}
	if len(dek) != 32 {
		return nil, errors.New("unwrapped DEK is not 32 bytes")
	}

	// 2. Decrypt ciphertext with AES-256-GCM using AAD
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	aad := buildAAD(conn.UserID, conn.Provider)
	plaintext, err := gcm.Open(nil, conn.Nonce, conn.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (possible tampering or AAD mismatch): %w", err)
	}

	var token TokenData
	if err := json.Unmarshal(plaintext, &token); err != nil {
		return nil, fmt.Errorf("failed unmarshaling token data: %w", err)
	}

	return &token, nil
}

// DeleteToken removes connection credentials from store and invalidates cache.
func (v *TokenVault) DeleteToken(ctx context.Context, userID, provider string) error {
	v.InvalidateCache(userID, provider)
	return v.store.DeleteConnection(ctx, userID, provider)
}

// GetValidAccessToken returns valid credentials, executing distributed CAS refresh if necessary.
func (v *TokenVault) GetValidAccessToken(ctx context.Context, userID, provider string) (*TokenData, error) {
	ck := cacheKey(userID, provider)

	// Check local fast-path cache
	v.cacheMu.RLock()
	item, ok := v.cache[ck]
	v.cacheMu.RUnlock()

	now := time.Now()
	if ok && item.expiresAt.After(now) {
		// If non-expiring or plenty of time remaining (> 60s)
		if item.token.ExpiresAt.IsZero() || time.Until(item.token.ExpiresAt) > 60*time.Second {
			return item.token, nil
		}
	}

	// In-process singleflight to collapse concurrent local goroutines
	v.sfMu.Lock()
	if call, ok := v.sfCalls[ck]; ok {
		v.sfMu.Unlock()
		call.wg.Wait()
		return call.val, call.err
	}
	call := &sfCall{}
	call.wg.Add(1)
	v.sfCalls[ck] = call
	v.sfMu.Unlock()

	defer func() {
		v.sfMu.Lock()
		delete(v.sfCalls, ck)
		v.sfMu.Unlock()
		call.wg.Done()
	}()

	tok, err := v.getValidAccessTokenLocked(ctx, userID, provider)
	call.val = tok
	call.err = err
	return tok, err
}

func (v *TokenVault) getValidAccessTokenLocked(ctx context.Context, userID, provider string) (*TokenData, error) {
	ck := cacheKey(userID, provider)

	// 1. Read connection from store
	conn, err := v.store.GetConnection(ctx, userID, provider)
	if err != nil {
		return nil, err
	}

	token, err := v.DecryptConnection(ctx, conn)
	if err != nil {
		return nil, err
	}

	// Non-expiring tokens (e.g. GitHub classic) skip refresh cleanly
	if token.ExpiresAt.IsZero() {
		v.cacheMu.Lock()
		v.cache[ck] = &cachedItem{token: token, expiresAt: time.Now().Add(60 * time.Second)}
		v.cacheMu.Unlock()
		return token, nil
	}

	// If token has plenty of validity remaining (> 60s), cache and return
	if time.Until(token.ExpiresAt) > 60*time.Second {
		v.cacheMu.Lock()
		v.cache[ck] = &cachedItem{token: token, expiresAt: time.Now().Add(60 * time.Second)}
		v.cacheMu.Unlock()
		return token, nil
	}

	// Token is expired or expiring within 60s -> Distributed CAS Refresh Lease
	if v.refreshFunc == nil {
		return nil, errors.New("token requires refresh but no refreshFunc is registered")
	}

	deadline := time.Now().Add(12 * time.Second)
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timeout waiting for distributed token refresh lease")
		}

		// Try to acquire distributed lease (15s lease duration)
		curConn, acquired, err := v.store.AcquireConnectionLease(ctx, userID, provider, v.instanceID, 15*time.Second)
		if err != nil {
			return nil, err
		}

		if acquired {
			// This instance acquired the lease! Perform upstream refresh.
			curToken, err := v.DecryptConnection(ctx, curConn)
			if err != nil {
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				return nil, err
			}

			// Re-verify if another lease completed right before us
			if time.Until(curToken.ExpiresAt) > 60*time.Second {
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				v.cacheMu.Lock()
				v.cache[ck] = &cachedItem{token: curToken, expiresAt: time.Now().Add(60 * time.Second)}
				v.cacheMu.Unlock()
				return curToken, nil
			}

			refreshedToken, err := v.refreshFunc(ctx, provider, curToken)
			if err != nil {
				// Release lease so others can retry if needed
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				return nil, fmt.Errorf("upstream token refresh failed: %w", err)
			}

			// Encrypt refreshed token
			refreshedBytes, err := json.Marshal(refreshedToken)
			if err != nil {
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				return nil, err
			}

			dek := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, dek); err != nil {
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				return nil, fmt.Errorf("failed generating refreshed DEK: %w", err)
			}
			block, err := aes.NewCipher(dek)
			if err != nil {
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				return nil, err
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				return nil, err
			}
			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				return nil, fmt.Errorf("failed generating refreshed nonce: %w", err)
			}
			aad := buildAAD(userID, provider)
			ct := gcm.Seal(nil, nonce, refreshedBytes, aad)

			wrappedDEK, keyVer, err := v.kms.Encrypt(ctx, v.kmsKeyName, dek)
			if err != nil {
				_ = v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, nil)
				return nil, fmt.Errorf("failed wrapping refreshed DEK: %w", err)
			}

			newConn := &store.EncryptedConnection{
				UserID:        userID,
				Provider:      provider,
				WrappedDEK:    wrappedDEK,
				Nonce:         nonce,
				Ciphertext:    ct,
				KMSKeyVersion: keyVer,
			}

			// Release lease and atomically save new connection
			if err := v.store.ReleaseConnectionLease(ctx, userID, provider, v.instanceID, newConn); err != nil {
				return nil, fmt.Errorf("failed releasing lease with new connection: %w", err)
			}

			v.cacheMu.Lock()
			v.cache[ck] = &cachedItem{token: refreshedToken, expiresAt: time.Now().Add(60 * time.Second)}
			v.cacheMu.Unlock()

			return refreshedToken, nil
		}

		// Another instance holds active lease: back off with 300ms + jitter
		jitter, err := rand.Int(rand.Reader, big.NewInt(150))
		sleepJitter := 50 * time.Millisecond
		if err == nil {
			sleepJitter = time.Duration(jitter.Int64()) * time.Millisecond
		}
		sleepDuration := 300*time.Millisecond + sleepJitter

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleepDuration):
		}

		// Check if the other instance has finished refresh
		latestConn, err := v.store.GetConnection(ctx, userID, provider)
		if err == nil {
			latestToken, err := v.DecryptConnection(ctx, latestConn)
			if err == nil && time.Until(latestToken.ExpiresAt) > 60*time.Second {
				// Refresh was successfully completed by lease holder!
				v.cacheMu.Lock()
				v.cache[ck] = &cachedItem{token: latestToken, expiresAt: time.Now().Add(60 * time.Second)}
				v.cacheMu.Unlock()
				return latestToken, nil
			}
		}
	}
}

// InstanceID returns this vault instance's ID.
func (v *TokenVault) InstanceID() string {
	return v.instanceID
}
