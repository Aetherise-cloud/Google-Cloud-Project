package store

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestMemoryStoreOAuthClients(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	client := &OAuthClient{
		ClientID:     "client-1",
		ClientName:   "Cursor Client",
		RedirectURIs: []string{"cursor://callback"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
	}

	if err := s.SaveOAuthClient(ctx, client); err != nil {
		t.Fatalf("failed saving client: %v", err)
	}

	got, err := s.GetOAuthClient(ctx, "client-1")
	if err != nil {
		t.Fatalf("failed getting client: %v", err)
	}
	if got.ClientName != "Cursor Client" {
		t.Errorf("expected client name Cursor Client, got %s", got.ClientName)
	}

	// Test active count
	count, err := s.CountActiveClients(ctx)
	if err != nil || count != 1 {
		t.Errorf("expected 1 active client, got %d (err: %v)", count, err)
	}

	// Test max cap of 50
	for i := 2; i <= 50; i++ {
		c := &OAuthClient{
			ClientID:   fmt.Sprintf("client-%d", i),
			ClientName: "Test",
			ExpiresAt:  time.Now().Add(time.Hour),
		}
		if err := s.SaveOAuthClient(ctx, c); err != nil {
			t.Fatalf("unexpected error saving client %d: %v", i, err)
		}
	}

	// 51st client should fail with ErrClientCapExceeded
	c51 := &OAuthClient{
		ClientID:   "client-51",
		ClientName: "Test",
		ExpiresAt:  time.Now().Add(time.Hour),
	}
	if err := s.SaveOAuthClient(ctx, c51); err != ErrClientCapExceeded {
		t.Errorf("expected ErrClientCapExceeded, got: %v", err)
	}
}

func TestMemoryStoreAuthCodeSingleUse(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	code := &AuthCode{
		Code:          "auth-code-123",
		ClientID:      "client-1",
		AdminEmail:    "admin@example.com",
		CodeChallenge: "challenge-xyz",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}

	if err := s.SaveAuthCode(ctx, code); err != nil {
		t.Fatalf("failed saving auth code: %v", err)
	}

	// First consume must succeed
	got, err := s.GetAndConsumeAuthCode(ctx, "auth-code-123")
	if err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if got.AdminEmail != "admin@example.com" {
		t.Errorf("expected admin@example.com, got %s", got.AdminEmail)
	}

	// Second consume must fail with ErrAlreadyConsumed
	_, err = s.GetAndConsumeAuthCode(ctx, "auth-code-123")
	if err != ErrAlreadyConsumed {
		t.Errorf("expected ErrAlreadyConsumed on second call, got: %v", err)
	}
}

func TestMemoryStoreRefreshTokenReplayRevocation(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	famID := "family-xyz"
	r1 := &RefreshTokenRecord{
		TokenHash:  "hash-1",
		FamilyID:   famID,
		ClientID:   "client-1",
		AdminEmail: "admin@example.com",
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
	}
	r2 := &RefreshTokenRecord{
		TokenHash:  "hash-2",
		FamilyID:   famID,
		ClientID:   "client-1",
		AdminEmail: "admin@example.com",
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
	}

	_ = s.SaveRefreshToken(ctx, r1)
	_ = s.SaveRefreshToken(ctx, r2)

	// Consume r1
	if err := s.ConsumeRefreshToken(ctx, "hash-1"); err != nil {
		t.Fatalf("consume failed: %v", err)
	}

	// Replay consumption of r1 should fail with ErrAlreadyConsumed
	if err := s.ConsumeRefreshToken(ctx, "hash-1"); err != ErrAlreadyConsumed {
		t.Errorf("expected ErrAlreadyConsumed, got %v", err)
	}

	// Revoke entire family
	if err := s.RevokeTokenFamily(ctx, famID); err != nil {
		t.Fatalf("revoke family failed: %v", err)
	}

	// r2 should now be revoked
	got2, err := s.GetRefreshToken(ctx, "hash-2")
	if err != nil {
		t.Fatalf("get r2 failed: %v", err)
	}
	if !got2.Revoked {
		t.Error("expected r2 to be revoked after family revocation")
	}
}

func TestMemoryStoreCASLease(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	conn := &EncryptedConnection{
		UserID:        "user-1",
		Provider:      "jira",
		WrappedDEK:    []byte("wrapped-dek"),
		Nonce:         []byte("nonce"),
		Ciphertext:    []byte("ciphertext"),
		KMSKeyVersion: "v1",
	}
	if err := s.SaveConnection(ctx, conn); err != nil {
		t.Fatalf("failed saving conn: %v", err)
	}

	// Instance 1 acquires lease
	_, acquired, err := s.AcquireConnectionLease(ctx, "user-1", "jira", "instance-1", 10*time.Second)
	if err != nil || !acquired {
		t.Fatalf("instance-1 failed to acquire lease: %v, acquired: %v", err, acquired)
	}

	// Instance 2 attempts to acquire lease concurrently -> should fail
	_, acquired2, err := s.AcquireConnectionLease(ctx, "user-1", "jira", "instance-2", 10*time.Second)
	if err != nil {
		t.Fatalf("instance-2 unexpected error: %v", err)
	}
	if acquired2 {
		t.Error("expected instance-2 to be rejected while instance-1 holds lease")
	}

	// Instance 1 releases lease with updated connection
	updatedConn := &EncryptedConnection{
		WrappedDEK: []byte("new-dek"),
	}
	if err := s.ReleaseConnectionLease(ctx, "user-1", "jira", "instance-1", updatedConn); err != nil {
		t.Fatalf("failed releasing lease: %v", err)
	}

	// Now instance 2 can acquire lease
	_, acquired3, err := s.AcquireConnectionLease(ctx, "user-1", "jira", "instance-2", 10*time.Second)
	if err != nil || !acquired3 {
		t.Errorf("instance-2 should succeed acquiring lease after release, got %v (err: %v)", acquired3, err)
	}

	// Test P1-2: Stale instance-1 calling ReleaseConnectionLease MUST NOT clobber instance-2's active lease!
	_ = s.ReleaseConnectionLease(ctx, "user-1", "jira", "instance-1", nil)
	checkConn, _ := s.GetConnection(ctx, "user-1", "jira")
	if checkConn.LeaseHolder != "instance-2" {
		t.Errorf("SECURITY/CONCURRENCY BUG: stale instance-1 clobbered instance-2's lease; holder is now %q", checkConn.LeaseHolder)
	}
}

func TestMemoryStoreConcurrentLeases(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	conn := &EncryptedConnection{
		UserID:   "user-conc",
		Provider: "jira",
	}
	_ = s.SaveConnection(ctx, conn)

	var wg sync.WaitGroup
	var acquiredCount int
	var mu sync.Mutex

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			instID := fmt.Sprintf("instance-%d", id)
			_, acq, err := s.AcquireConnectionLease(ctx, "user-conc", "jira", instID, 5*time.Second)
			if err == nil && acq {
				mu.Lock()
				acquiredCount++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	if acquiredCount != 1 {
		t.Errorf("expected exactly 1 instance to acquire lease concurrently, got %d", acquiredCount)
	}
}

func TestFirestoreRESTStoreWithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "PATCH" && r.URL.Path == "/v1/projects/proj/databases/db/documents/oauth_clients/c1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"oauth_clients/c1"}`))
		case r.Method == "GET" && r.URL.Path == "/v1/projects/proj/databases/db/documents/oauth_clients/c1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"fields": {
					"client_id": {"stringValue": "c1"},
					"client_name": {"stringValue": "Test Client"},
					"client_secret": {"stringValue": "s1"},
					"redirect_uris": {"arrayValue": {"values": [{"stringValue": "https://example.com"}]}},
					"expires_at": {"timestampValue": "2030-01-01T00:00:00Z"}
				}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	fs := NewFirestoreRESTStore("proj", "db", server.Client(), func(ctx context.Context) (string, error) {
		return "test-token", nil
	})
	fs.SetBaseURL(server.URL + "/v1")

	ctx := context.Background()
	err := fs.SaveOAuthClient(ctx, &OAuthClient{
		ClientID:     "c1",
		ClientName:   "Test Client",
		RedirectURIs: []string{"https://example.com"},
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("failed saving client: %v", err)
	}

	got, err := fs.GetOAuthClient(ctx, "c1")
	if err != nil {
		t.Fatalf("failed getting client: %v", err)
	}
	if got.ClientName != "Test Client" {
		t.Errorf("expected Test Client, got %s", got.ClientName)
	}
}
