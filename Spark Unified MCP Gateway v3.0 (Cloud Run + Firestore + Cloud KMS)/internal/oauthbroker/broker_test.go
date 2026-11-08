package oauthbroker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"spark-mcp-gateway/internal/auth"
	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/store"
	"spark-mcp-gateway/internal/vault"
)

func newTestBroker(t *testing.T) (*Broker, *store.MemoryStore, *vault.TokenVault, *auth.SessionManager, *config.Config) {
	s := store.NewMemoryStore()
	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	kms, _ := vault.NewLocalAEADKMS(masterKey)
	v := vault.NewTokenVault("broker-inst", s, kms, "test-kek", nil)

	cfg := &config.Config{
		ServiceURL:              "http://127.0.0.1:8080",
		AdminAllowedEmails:      []string{"admin@example.com"},
		SessionHMACKey:          []byte("secret-key-32-bytes-long-1234567"),
		GitHubOAuthClientID:     "gh-client-id",
		GitHubOAuthClientSecret: "gh-client-secret",
		JiraOAuthClientID:       "jira-client-id",
		JiraOAuthClientSecret:   "jira-client-secret",
		GCPProjectID:            "my-gcp-project",
	}

	sm := auth.NewSessionManager(cfg.ServiceURL, cfg.SessionHMACKey)
	b := NewBroker(cfg, s, v, sm, nil)
	return b, s, v, sm, cfg
}

func TestBrokerDashboardAndConnect(t *testing.T) {
	b, _, _, sm, _ := newTestBroker(t)
	mux := http.NewServeMux()
	b.RegisterRoutes(mux)

	adminEmail := "admin@example.com"
	cookieVal := fmt.Sprintf("%s:%d:%s", adminEmail, time.Now().Unix(), sm.GenerateCSRFToken(adminEmail)) // valid format
	// Actually issue valid session cookie
	recSession := httptest.NewRecorder()
	sm.SetAdminSession(recSession, adminEmail)
	cookie := recSession.Result().Cookies()[0]

	// 1. Unauthenticated /dashboard -> 302
	reqUnauth := httptest.NewRequest("GET", "/dashboard", nil)
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusFound {
		t.Errorf("expected 302 redirect for unauthenticated /dashboard, got %d", recUnauth.Code)
	}

	// 2. Authenticated /dashboard -> 200
	reqAuth := httptest.NewRequest("GET", "/dashboard", nil)
	reqAuth.AddCookie(cookie)
	recAuth := httptest.NewRecorder()
	mux.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK for authenticated /dashboard, got %d", recAuth.Code)
	}

	// 3. Connect GitHub -> 302 to GitHub
	reqConnect := httptest.NewRequest("GET", "/oauth/connect/github?mode=read_only", nil)
	reqConnect.AddCookie(cookie)
	recConnect := httptest.NewRecorder()
	mux.ServeHTTP(recConnect, reqConnect)

	if recConnect.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect to GitHub, got %d", recConnect.Code)
	}
	loc := recConnect.Header().Get("Location")
	if !strings.Contains(loc, "github.com/login/oauth/authorize") {
		t.Errorf("unexpected redirect location: %s", loc)
	}
	_ = cookieVal
}

func TestBrokerGitHubCallback(t *testing.T) {
	b, s, v, sm, _ := newTestBroker(t)
	adminEmail := "admin@example.com"

	// Mock upstream GitHub OAuth and API servers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/access_token":
			_, _ = w.Write([]byte(`{
				"access_token": "gh-access-token-999",
				"token_type": "Bearer",
				"scope": "read:user"
			}`))
		case r.Method == "GET" && r.URL.Path == "/user":
			_, _ = w.Write([]byte(`{"login": "octocat"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	b.GitHubOAuthURL = server.URL
	b.GitHubAPIURL = server.URL
	b.httpClient = server.Client()

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)

	// Save pre-existing state
	stateStr := "state-github-123"
	_ = s.SaveOAuthState(context.Background(), &store.OAuthState{
		State:      stateStr,
		Provider:   "github",
		Mode:       "read_only",
		AdminEmail: adminEmail,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	})

	recSession := httptest.NewRecorder()
	sm.SetAdminSession(recSession, adminEmail)
	cookie := recSession.Result().Cookies()[0]

	// Callback request
	callbackReq := httptest.NewRequest("GET", "/oauth/callback/github?code=code-123&state="+stateStr, nil)
	callbackReq.AddCookie(cookie)
	recCallback := httptest.NewRecorder()
	mux.ServeHTTP(recCallback, callbackReq)

	if recCallback.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from callback, got %d", recCallback.Code)
	}

	// Verify token was securely stored in TokenVault
	tok, err := v.GetValidAccessToken(context.Background(), adminEmail, "github")
	if err != nil {
		t.Fatalf("failed retrieving token from vault: %v", err)
	}
	if tok.AccessToken != "gh-access-token-999" {
		t.Errorf("expected gh-access-token-999, got %s", tok.AccessToken)
	}
	if tok.AccountLabel != "@octocat" {
		t.Errorf("expected @octocat account label, got %s", tok.AccountLabel)
	}

	// Test Disconnect
	csrfToken := sm.GenerateCSRFToken(adminEmail)
	disconnectReq := httptest.NewRequest("POST", "/api/connections/github/disconnect", strings.NewReader("csrf_token="+csrfToken))
	disconnectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	disconnectReq.AddCookie(cookie)
	recDisconnect := httptest.NewRecorder()
	mux.ServeHTTP(recDisconnect, disconnectReq)

	if recDisconnect.Code != http.StatusFound {
		t.Errorf("expected 302 redirect after disconnect, got %d", recDisconnect.Code)
	}

	// Token should now be gone
	_, err = v.GetValidAccessToken(context.Background(), adminEmail, "github")
	if err == nil {
		t.Error("expected error retrieving deleted token from vault")
	}
}

func TestBrokerJiraCallback(t *testing.T) {
	b, s, v, sm, _ := newTestBroker(t)
	adminEmail := "admin@example.com"

	// Mock upstream Atlassian servers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/oauth/token":
			_, _ = w.Write([]byte(`{
				"access_token": "jira-access-111",
				"refresh_token": "jira-refresh-222",
				"expires_in": 3600,
				"scope": "read:jira-work"
			}`))
		case r.Method == "GET" && r.URL.Path == "/oauth/token/accessible-resources":
			_, _ = w.Write([]byte(`[
				{
					"id": "cloud-jira-uuid",
					"url": "https://my-team.atlassian.net",
					"name": "My Team Jira"
				}
			]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	b.AtlassianTokenURL = server.URL + "/oauth/token"
	b.AtlassianAPIURL = server.URL
	b.httpClient = server.Client()

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)

	stateStr := "state-jira-456"
	_ = s.SaveOAuthState(context.Background(), &store.OAuthState{
		State:        stateStr,
		Provider:     "jira",
		Mode:         "read_only",
		AdminEmail:   adminEmail,
		CodeVerifier: "code-verifier-pkce-xyz",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	recSession := httptest.NewRecorder()
	sm.SetAdminSession(recSession, adminEmail)
	cookie := recSession.Result().Cookies()[0]

	callbackReq := httptest.NewRequest("GET", "/oauth/callback/jira?code=code-jira&state="+stateStr, nil)
	callbackReq.AddCookie(cookie)
	recCallback := httptest.NewRecorder()
	mux.ServeHTTP(recCallback, callbackReq)

	if recCallback.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from jira callback, got %d", recCallback.Code)
	}

	tok, err := v.GetValidAccessToken(context.Background(), adminEmail, "jira")
	if err != nil {
		t.Fatalf("failed retrieving token from vault: %v", err)
	}
	if tok.AccessToken != "jira-access-111" {
		t.Errorf("expected jira-access-111, got %s", tok.AccessToken)
	}
	if tok.CloudID != "cloud-jira-uuid" {
		t.Errorf("expected cloud-jira-uuid, got %s", tok.CloudID)
	}
	if tok.SiteURL != "https://my-team.atlassian.net" {
		t.Errorf("expected site URL https://my-team.atlassian.net, got %s", tok.SiteURL)
	}

	// Test GET /api/connections
	listReq := httptest.NewRequest("GET", "/api/connections", nil)
	listReq.AddCookie(cookie)
	recList := httptest.NewRecorder()
	mux.ServeHTTP(recList, listReq)

	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/connections, got %d", recList.Code)
	}

	var statusMap map[string]struct {
		Connected bool `json:"connected"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &statusMap); err != nil {
		t.Fatalf("failed unmarshaling /api/connections: %v", err)
	}
	if !statusMap["jira"].Connected {
		t.Error("expected jira to be connected in /api/connections")
	}
}
