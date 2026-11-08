package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const MaxActiveClientsCap = 50

// MemoryStore is an in-memory, thread-safe implementation of Store.
type MemoryStore struct {
	mu            sync.RWMutex
	clients       map[string]*OAuthClient
	codes         map[string]*AuthCode
	refreshTokens map[string]*RefreshTokenRecord
	states        map[string]*OAuthState
	connections   map[string]*EncryptedConnection
}

// NewMemoryStore creates a new concurrency-safe MemoryStore instance.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:       make(map[string]*OAuthClient),
		codes:         make(map[string]*AuthCode),
		refreshTokens: make(map[string]*RefreshTokenRecord),
		states:        make(map[string]*OAuthState),
		connections:   make(map[string]*EncryptedConnection),
	}
}

func connKey(userID, provider string) string {
	return fmt.Sprintf("%s:%s", userID, provider)
}

func (m *MemoryStore) SaveOAuthClient(ctx context.Context, client *OAuthClient) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	// Count active clients
	active := 0
	for _, c := range m.clients {
		if c.ExpiresAt.After(now) {
			active++
		}
	}
	if _, exists := m.clients[client.ClientID]; !exists && active >= MaxActiveClientsCap {
		return ErrClientCapExceeded
	}

	cloned := *client
	m.clients[client.ClientID] = &cloned
	return nil
}

func (m *MemoryStore) GetOAuthClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, ok := m.clients[clientID]
	if !ok || (!c.ExpiresAt.IsZero() && time.Now().After(c.ExpiresAt)) {
		return nil, ErrNotFound
	}
	cloned := *c
	return &cloned, nil
}

func (m *MemoryStore) CountActiveClients(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, c := range m.clients {
		if c.ExpiresAt.IsZero() || c.ExpiresAt.After(now) {
			count++
		}
	}
	return count, nil
}

func (m *MemoryStore) SaveAuthCode(ctx context.Context, code *AuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cloned := *code
	m.codes[code.Code] = &cloned
	return nil
}

func (m *MemoryStore) GetAndConsumeAuthCode(ctx context.Context, codeStr string) (*AuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.codes[codeStr]
	if !ok || time.Now().After(c.ExpiresAt) {
		return nil, ErrNotFound
	}
	if c.Used {
		return nil, ErrAlreadyConsumed
	}
	c.Used = true
	cloned := *c
	return &cloned, nil
}

func (m *MemoryStore) SaveRefreshToken(ctx context.Context, record *RefreshTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cloned := *record
	m.refreshTokens[record.TokenHash] = &cloned
	return nil
}

func (m *MemoryStore) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshTokenRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.refreshTokens[tokenHash]
	if !ok || time.Now().After(rec.ExpiresAt) {
		return nil, ErrNotFound
	}
	cloned := *rec
	return &cloned, nil
}

func (m *MemoryStore) ConsumeRefreshToken(ctx context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.refreshTokens[tokenHash]
	if !ok || time.Now().After(rec.ExpiresAt) {
		return ErrNotFound
	}
	if rec.Revoked {
		return ErrAlreadyConsumed
	}
	rec.Revoked = true
	return nil
}

func (m *MemoryStore) RevokeTokenFamily(ctx context.Context, familyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, rec := range m.refreshTokens {
		if rec.FamilyID == familyID {
			rec.Revoked = true
		}
	}
	return nil
}

func (m *MemoryStore) SaveOAuthState(ctx context.Context, state *OAuthState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cloned := *state
	m.states[state.State] = &cloned
	return nil
}

func (m *MemoryStore) GetAndConsumeOAuthState(ctx context.Context, stateStr string) (*OAuthState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.states[stateStr]
	if !ok || time.Now().After(s.ExpiresAt) {
		return nil, ErrNotFound
	}
	delete(m.states, stateStr)
	cloned := *s
	return &cloned, nil
}

func (m *MemoryStore) GetConnection(ctx context.Context, userID, provider string) (*EncryptedConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := connKey(userID, provider)
	conn, ok := m.connections[key]
	if !ok {
		return nil, ErrNotFound
	}
	cloned := *conn
	return &cloned, nil
}

func (m *MemoryStore) SaveConnection(ctx context.Context, conn *EncryptedConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := connKey(conn.UserID, conn.Provider)
	cloned := *conn
	cloned.Version++
	cloned.UpdateTime = time.Now()
	cloned.UpdatedAt = time.Now()
	m.connections[key] = &cloned
	return nil
}

func (m *MemoryStore) DeleteConnection(ctx context.Context, userID, provider string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := connKey(userID, provider)
	delete(m.connections, key)
	return nil
}

func (m *MemoryStore) ListConnections(ctx context.Context, userID string) ([]*EncryptedConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []*EncryptedConnection
	for _, conn := range m.connections {
		if conn.UserID == userID {
			cloned := *conn
			list = append(list, &cloned)
		}
	}
	return list, nil
}

func (m *MemoryStore) AcquireConnectionLease(ctx context.Context, userID, provider, instanceID string, leaseDuration time.Duration) (*EncryptedConnection, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := connKey(userID, provider)
	conn, ok := m.connections[key]
	if !ok {
		return nil, false, ErrNotFound
	}

	now := time.Now()
	// Check if active lease held by another instance
	if conn.LeaseHolder != "" && conn.LeaseExpiresAt.After(now) && conn.LeaseHolder != instanceID {
		cloned := *conn
		return &cloned, false, nil
	}

	// Acquire or renew lease
	conn.LeaseHolder = instanceID
	conn.LeaseExpiresAt = now.Add(leaseDuration)
	conn.Version++
	conn.UpdateTime = now

	cloned := *conn
	return &cloned, true, nil
}

func (m *MemoryStore) ReleaseConnectionLease(ctx context.Context, userID, provider, instanceID string, newConn *EncryptedConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := connKey(userID, provider)
	conn, ok := m.connections[key]
	if !ok {
		return ErrNotFound
	}

	// Guard: only clear lease if this instance is the current lease holder (P1-2)
	if conn.LeaseHolder != instanceID {
		return nil
	}

	now := time.Now()
	if newConn != nil {
		conn.WrappedDEK = newConn.WrappedDEK
		conn.Nonce = newConn.Nonce
		conn.Ciphertext = newConn.Ciphertext
		conn.KMSKeyVersion = newConn.KMSKeyVersion
		conn.UpdatedAt = now
	}

	conn.LeaseHolder = ""
	conn.LeaseExpiresAt = time.Time{}
	conn.Version++
	conn.UpdateTime = now
	return nil
}
