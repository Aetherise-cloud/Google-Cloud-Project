package vault

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"spark-mcp-gateway/internal/store"
)

func TestEnvelopeEncryptionAndAADTamper(t *testing.T) {
	ctx := context.Background()
	s := store.NewMemoryStore()

	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	kms, err := NewLocalAEADKMS(masterKey)
	if err != nil {
		t.Fatalf("failed creating local KMS: %v", err)
	}

	vault := NewTokenVault("inst-1", s, kms, "test-kek", nil)

	initialToken := &TokenData{
		AccessToken:  "initial-gh-token",
		ExpiresAt:    time.Time{}, // Non-expiring
		AccountLabel: "octocat",
	}

	userID := "admin@example.com"
	provider := "github"

	if err := vault.StoreToken(ctx, userID, provider, initialToken); err != nil {
		t.Fatalf("failed storing token: %v", err)
	}

	// 1. Valid read and decryption
	conn, err := s.GetConnection(ctx, userID, provider)
	if err != nil {
		t.Fatalf("failed reading conn: %v", err)
	}

	decrypted, err := vault.DecryptConnection(ctx, conn)
	if err != nil {
		t.Fatalf("failed decrypting: %v", err)
	}
	if decrypted.AccessToken != "initial-gh-token" {
		t.Errorf("expected initial-gh-token, got %s", decrypted.AccessToken)
	}

	// 2. Tamper test: attempt to decrypt with wrong userID
	connTamperedUser := *conn
	connTamperedUser.UserID = "attacker@example.com"
	_, err = vault.DecryptConnection(ctx, &connTamperedUser)
	if err == nil {
		t.Fatal("expected decryption failure due to AAD mismatch on wrong userID")
	}

	// 3. Tamper test: attempt to decrypt with wrong provider
	connTamperedProvider := *conn
	connTamperedProvider.Provider = "jira"
	_, err = vault.DecryptConnection(ctx, &connTamperedProvider)
	if err == nil {
		t.Fatal("expected decryption failure due to AAD mismatch on wrong provider")
	}

	// 4. Non-expiring token: verify GetValidAccessToken skips refresh
	retrieved, err := vault.GetValidAccessToken(ctx, userID, provider)
	if err != nil {
		t.Fatalf("unexpected error getting non-expiring token: %v", err)
	}
	if retrieved.AccessToken != "initial-gh-token" {
		t.Errorf("expected initial-gh-token, got %s", retrieved.AccessToken)
	}
}

func Test20GoroutineMultiInstanceRefreshRace(t *testing.T) {
	ctx := context.Background()
	sharedStore := store.NewMemoryStore()

	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	kms, _ := NewLocalAEADKMS(masterKey)

	// Mock Atlassian token server with single-use refresh token verification
	var upstreamRefreshCount int64
	var tokenServerMu sync.Mutex
	validRefreshToken := "atlassian-rt-v1"

	refreshFunc := func(ctx context.Context, provider string, cur *TokenData) (*TokenData, error) {
		tokenServerMu.Lock()
		defer tokenServerMu.Unlock()

		atomic.AddInt64(&upstreamRefreshCount, 1)

		// If refresh token has already been rotated / reused, fail immediately!
		if cur.RefreshToken != validRefreshToken {
			return nil, errors.New("400 invalid_grant: refresh token already consumed/invalidated")
		}

		// Rotate refresh token
		validRefreshToken = "atlassian-rt-v2-rotated"
		return &TokenData{
			AccessToken:  "atlassian-access-new",
			RefreshToken: validRefreshToken,
			ExpiresAt:    time.Now().Add(3600 * time.Second), // 1 hour validity
			CloudID:      cur.CloudID,
			SiteURL:      cur.SiteURL,
			AccountLabel: cur.AccountLabel,
		}, nil
	}

	// Instantiate 3 separate TokenVault instances (representing 3 Cloud Run instances)
	v1 := NewTokenVault("instance-alpha", sharedStore, kms, "test-kek", refreshFunc)
	v2 := NewTokenVault("instance-beta", sharedStore, kms, "test-kek", refreshFunc)
	v3 := NewTokenVault("instance-gamma", sharedStore, kms, "test-kek", refreshFunc)
	instances := []*TokenVault{v1, v2, v3}

	userID := "brendon.ang20011007@gmail.com"
	provider := "jira"

	// Initial token expiring in 30 seconds (triggers refresh since <= 60s)
	initialToken := &TokenData{
		AccessToken:  "atlassian-access-old",
		RefreshToken: "atlassian-rt-v1",
		ExpiresAt:    time.Now().Add(30 * time.Second),
		CloudID:      "cloud-123",
		SiteURL:      "https://example.atlassian.net",
		AccountLabel: "admin",
	}

	if err := v1.StoreToken(ctx, userID, provider, initialToken); err != nil {
		t.Fatalf("failed storing initial token: %v", err)
	}

	// Fire 20 concurrent GetValidAccessToken calls distributed across the 3 instances
	var wg sync.WaitGroup
	errCh := make(chan error, 20)
	results := make([]*TokenData, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		inst := instances[i%len(instances)]
		go func(idx int, vault *TokenVault) {
			defer wg.Done()
			tok, err := vault.GetValidAccessToken(ctx, userID, provider)
			if err != nil {
				errCh <- fmt.Errorf("goroutine %d failed: %w", idx, err)
				return
			}
			results[idx] = tok
		}(i, inst)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent refresh error: %v", err)
	}

	// Verify upstream refresh count is EXACTLY 1
	refreshes := atomic.LoadInt64(&upstreamRefreshCount)
	if refreshes != 1 {
		t.Fatalf("CRITICAL: expected upstream refresh count == 1, got %d (race condition occurred!)", refreshes)
	}

	// Verify all 20 callers received the newly rotated access token
	for i, tok := range results {
		if tok == nil {
			t.Fatalf("caller %d got nil token", i)
		}
		if tok.AccessToken != "atlassian-access-new" {
			t.Errorf("caller %d expected token 'atlassian-access-new', got %q", i, tok.AccessToken)
		}
		if tok.RefreshToken != "atlassian-rt-v2-rotated" {
			t.Errorf("caller %d expected refresh token 'atlassian-rt-v2-rotated', got %q", i, tok.RefreshToken)
		}
	}
}
