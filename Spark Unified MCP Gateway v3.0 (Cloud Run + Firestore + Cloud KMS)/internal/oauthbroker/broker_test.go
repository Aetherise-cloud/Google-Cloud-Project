package oauthbroker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
}

func TestBrokerOAuthConfigKMS(t *testing.T) {
	b, _, _, sm, cfg := newTestBroker(t)
	// Clear env config so only KMS stores it
	cfg.GitHubOAuthClientID = ""
	cfg.GitHubOAuthClientSecret = ""

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)

	adminEmail := "admin@example.com"
	csrfToken := sm.GenerateCSRFToken(adminEmail)
	recSession := httptest.NewRecorder()
	sm.SetAdminSession(recSession, adminEmail)
	cookie := recSession.Result().Cookies()[0]

	// Configure GitHub OAuth Client credentials in TokenVault
	form := url.Values{
		"client_id":           {"kms-gh-id"},
		"client_secret":       {"example-sec"},
		"allowed_write_repos": {"octo/spark"},
		"csrf_token":          {csrfToken},
	}
	req := httptest.NewRequest("POST", "/api/connectors/github/oauth-config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/connectors/github/oauth-config, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify resolveOAuthCredentials returns KMS credentials
	id, sec, repos := b.ResolveOAuthCredentials(context.Background(), "github")
	if id != "kms-gh-id" || sec != "example-sec" || repos != "octo/spark" {
		t.Errorf("unexpected resolved credentials: id=%s, sec=%s, repos=%s", id, sec, repos)
	}

	// Verify /oauth/connect/github now succeeds with KMS client ID
	reqConnect := httptest.NewRequest("GET", "/oauth/connect/github", nil)
	reqConnect.AddCookie(cookie)
	recConnect := httptest.NewRecorder()
	mux.ServeHTTP(recConnect, reqConnect)

	if recConnect.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", recConnect.Code)
	}
	if !strings.Contains(recConnect.Header().Get("Location"), "client_id=kms-gh-id") {
		t.Errorf("redirect URI missing KMS client ID: %s", recConnect.Header().Get("Location"))
	}
}

func TestBrokerGitHubPAT(t *testing.T) {
	b, _, v, sm, _ := newTestBroker(t)
	adminEmail := "admin@example.com"

	// Mock GitHub /user
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer example-pat" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"brendon-dev"}`))
	}))
	defer server.Close()
	b.GitHubAPIURL = server.URL

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)

	csrfToken := sm.GenerateCSRFToken(adminEmail)
	recSession := httptest.NewRecorder()
	sm.SetAdminSession(recSession, adminEmail)
	cookie := recSession.Result().Cookies()[0]

	// POST /api/connectors/github/pat
	patJSON := `{
		"access_token": "example-pat",
		"scope_mode": "read_only",
		"csrf_token": "` + csrfToken + `"
	}`
	req := httptest.NewRequest("POST", "/api/connectors/github/pat", strings.NewReader(patJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/connectors/github/pat, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		OK           bool   `json:"ok"`
		AccountLabel string `json:"account_label"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if !res.OK || res.AccountLabel != "@brendon-dev" {
		t.Errorf("unexpected PAT response: %+v", res)
	}

	// Verify vault has PAT token
	tok, err := v.GetValidAccessToken(context.Background(), adminEmail, "github")
	if err != nil {
		t.Fatalf("failed retrieving PAT from vault: %v", err)
	}
	if tok.ConnectorType != "pat" || tok.AccessToken != "example-pat" {
		t.Errorf("unexpected stored PAT token: %+v", tok)
	}
}

func TestBrokerCustomConnectorAndDisconnect(t *testing.T) {
	b, _, v, sm, _ := newTestBroker(t)
	b.AllowLoopbackForTest = true
	adminEmail := "admin@example.com"

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)

	csrfToken := sm.GenerateCSRFToken(adminEmail)
	recSession := httptest.NewRecorder()
	sm.SetAdminSession(recSession, adminEmail)
	cookie := recSession.Result().Cookies()[0]

	// 1. Add custom connector via POST /api/connectors/custom
	customJSON := `{
		"slug": "slack",
		"name": "Team Slack",
		"connector_type": "remote_mcp",
		"endpoint_url": "` + mockServer.URL + `",
		"auth_token": "example-tok",
		"csrf_token": "` + csrfToken + `"
	}`
	reqAdd := httptest.NewRequest("POST", "/api/connectors/custom", strings.NewReader(customJSON))
	reqAdd.Header.Set("Content-Type", "application/json")
	reqAdd.AddCookie(cookie)
	recAdd := httptest.NewRecorder()
	mux.ServeHTTP(recAdd, reqAdd)

	if recAdd.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from adding custom connector, got %d: %s", recAdd.Code, recAdd.Body.String())
	}

	// Verify TokenVault stored custom connector
	tok, err := v.GetValidAccessToken(context.Background(), adminEmail, "custom:slack")
	if err != nil {
		t.Fatalf("failed retrieving custom:slack from vault: %v", err)
	}
	if tok.ConnectorName != "Team Slack" || tok.ConnectorType != "remote_mcp" {
		t.Errorf("unexpected custom connector data: %+v", tok)
	}

	// 2. Disconnect custom connector via POST /api/connections/custom:slack/disconnect
	reqDisc := httptest.NewRequest("POST", "/api/connections/custom:slack/disconnect", strings.NewReader("csrf_token="+csrfToken))
	reqDisc.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqDisc.Header.Set("Accept", "application/json")
	reqDisc.AddCookie(cookie)
	recDisc := httptest.NewRecorder()
	mux.ServeHTTP(recDisc, reqDisc)

	if recDisc.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from disconnecting custom:slack, got %d: %s", recDisc.Code, recDisc.Body.String())
	}

	_, err = v.GetValidAccessToken(context.Background(), adminEmail, "custom:slack")
	if err == nil {
		t.Error("expected custom:slack to be removed from vault after disconnect")
	}
}

func TestBrokerGitHubCallback(t *testing.T) {
	b, s, v, sm, _ := newTestBroker(t)
	adminEmail := "admin@example.com"

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

	callbackReq := httptest.NewRequest("GET", "/oauth/callback/github?code=code-123&state="+stateStr, nil)
	callbackReq.AddCookie(cookie)
	recCallback := httptest.NewRecorder()
	mux.ServeHTTP(recCallback, callbackReq)

	if recCallback.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from callback, got %d", recCallback.Code)
	}

	tok, err := v.GetValidAccessToken(context.Background(), adminEmail, "github")
	if err != nil {
		t.Fatalf("failed retrieving token from vault: %v", err)
	}
	if tok.AccessToken != "gh-access-token-999" {
		t.Errorf("expected gh-access-token-999, got %s", tok.AccessToken)
	}
}

func TestBrokerJiraCallback(t *testing.T) {
	b, s, v, sm, _ := newTestBroker(t)
	adminEmail := "admin@example.com"

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
}

type mockRoundTripper func(req *http.Request) (*http.Response, error)

func (m mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func TestBrokerWorkspaceEndpoints(t *testing.T) {
	b, _, v, sm, _ := newTestBroker(t)
	adminEmail := "admin@example.com"

	b.GitHubAPIURL = "http://mock.github"
	b.AtlassianAPIURL = "http://mock.atlassian"

	b.httpClient = &http.Client{
		Transport: mockRoundTripper(func(r *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/user/orgs":
				_ = json.NewEncoder(rec).Encode([]map[string]string{
					{"login": "aetherise-cloud"},
				})
			case r.URL.Path == "/user/repos":
				_ = json.NewEncoder(rec).Encode([]map[string]string{
					{"full_name": "aetherise-cloud/spark-mcp-gateway"},
				})
			case r.URL.Path == "/orgs/aetherise-cloud/repos":
				_ = json.NewEncoder(rec).Encode([]map[string]string{
					{"full_name": "aetherise-cloud/spark-mcp-gateway"},
				})
			case strings.HasPrefix(r.URL.Path, "/ex/jira/") && strings.HasSuffix(r.URL.Path, "/rest/api/3/project/search"):
				_ = json.NewEncoder(rec).Encode(map[string]interface{}{
					"values": []map[string]string{
						{"key": "SPARK", "name": "Spark Gateway"},
						{"key": "ONB", "name": "Onboarding"},
					},
				})
			default:
				rec.WriteHeader(http.StatusNotFound)
			}
			return rec.Result(), nil
		}),
	}

	mux := http.NewServeMux()
	b.RegisterRoutes(mux)

	recSession := httptest.NewRecorder()
	sm.SetAdminSession(recSession, adminEmail)
	cookie := recSession.Result().Cookies()[0]
	csrfToken := sm.GenerateCSRFToken(adminEmail)

	// 1. Unauthenticated check
	reqUnauth := httptest.NewRequest("GET", "/api/connectors/github/workspaces", nil)
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauth workspaces, got %d", recUnauth.Code)
	}

	// 2. Unconnected check
	reqUnconn := httptest.NewRequest("GET", "/api/connectors/github/workspaces", nil)
	reqUnconn.AddCookie(cookie)
	recUnconn := httptest.NewRecorder()
	mux.ServeHTTP(recUnconn, reqUnconn)
	if recUnconn.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unconnected GitHub, got %d: %s", recUnconn.Code, recUnconn.Body.String())
	}

	// 3. Connect GitHub into vault
	ghTok := &vault.TokenData{
		AccessToken:       "mock-gh-pat",
		AccountLabel:      "octocat",
		SelectedOrgs:      []string{"aetherise-cloud"},
		AllowedReadRepos:  []string{"aetherise-cloud/*"},
		AllowedWriteRepos: "aetherise-cloud/spark-mcp-gateway",
	}
	if err := v.StoreToken(context.Background(), adminEmail, "github", ghTok); err != nil {
		t.Fatalf("failed storing gh token: %v", err)
	}

	// Test GET /api/connectors/github/workspaces
	reqGH := httptest.NewRequest("GET", "/api/connectors/github/workspaces", nil)
	reqGH.AddCookie(cookie)
	recGH := httptest.NewRecorder()
	mux.ServeHTTP(recGH, reqGH)
	if recGH.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from github workspaces, got %d: %s", recGH.Code, recGH.Body.String())
	}

	var ghResp struct {
		Orgs              []string `json:"orgs"`
		Repos             []string `json:"repos"`
		SelectedOrgs      []string `json:"selected_orgs"`
		AllowedReadRepos  []string `json:"allowed_read_repos"`
		AllowedWriteRepos []string `json:"allowed_write_repos"`
	}
	if err := json.Unmarshal(recGH.Body.Bytes(), &ghResp); err != nil {
		t.Fatalf("failed parsing gh workspaces json: %v", err)
	}
	if len(ghResp.Orgs) == 0 || ghResp.Orgs[0] != "aetherise-cloud" {
		t.Errorf("unexpected orgs: %v", ghResp.Orgs)
	}
	if len(ghResp.Repos) == 0 || ghResp.Repos[0] != "aetherise-cloud/spark-mcp-gateway" {
		t.Errorf("unexpected repos: %v", ghResp.Repos)
	}
	if len(ghResp.AllowedWriteRepos) == 0 || ghResp.AllowedWriteRepos[0] != "aetherise-cloud/spark-mcp-gateway" {
		t.Errorf("unexpected allowed write repos: %v", ghResp.AllowedWriteRepos)
	}

	// 4. Connect Jira into vault
	jiraTok := &vault.TokenData{
		AccessToken:      "mock-jira-token",
		CloudID:          "jira-cloud-123",
		SiteURL:          "https://aetherise.atlassian.net",
		SiteName:         "Aetherise",
		AllowedSpaceKeys: []string{"SPARK"},
	}
	if err := v.StoreToken(context.Background(), adminEmail, "jira", jiraTok); err != nil {
		t.Fatalf("failed storing jira token: %v", err)
	}

	// Test GET /api/connectors/jira/workspaces
	reqJira := httptest.NewRequest("GET", "/api/connectors/jira/workspaces", nil)
	reqJira.AddCookie(cookie)
	recJira := httptest.NewRecorder()
	mux.ServeHTTP(recJira, reqJira)
	if recJira.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from jira workspaces, got %d: %s", recJira.Code, recJira.Body.String())
	}

	var jiraResp struct {
		CloudID          string `json:"cloud_id"`
		SiteURL          string `json:"site_url"`
		SiteName         string `json:"site_name"`
		Spaces           []struct{ Key, Name string } `json:"spaces"`
		AllowedSpaceKeys []string `json:"allowed_space_keys"`
	}
	if err := json.Unmarshal(recJira.Body.Bytes(), &jiraResp); err != nil {
		t.Fatalf("failed parsing jira workspaces json: %v", err)
	}
	if jiraResp.CloudID != "jira-cloud-123" || len(jiraResp.Spaces) < 2 {
		t.Errorf("unexpected jira workspaces response: %+v", jiraResp)
	}

	// 5. Test POST /api/connectors/workspaces (CSRF failure)
	saveBadCSRF := `{"provider":"jira","csrf_token":"invalid","allowed_space_keys":["SPARK","ONB"]}`
	reqBadCSRF := httptest.NewRequest("POST", "/api/connectors/workspaces", strings.NewReader(saveBadCSRF))
	reqBadCSRF.Header.Set("Content-Type", "application/json")
	reqBadCSRF.AddCookie(cookie)
	recBadCSRF := httptest.NewRecorder()
	mux.ServeHTTP(recBadCSRF, reqBadCSRF)
	if recBadCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for bad CSRF, got %d", recBadCSRF.Code)
	}

	// 6. Test POST /api/connectors/workspaces (valid save for Jira)
	saveJira := fmt.Sprintf(`{"provider":"jira","csrf_token":%q,"allowed_space_keys":["SPARK","ONB"]}`, csrfToken)
	reqSaveJira := httptest.NewRequest("POST", "/api/connectors/workspaces", strings.NewReader(saveJira))
	reqSaveJira.Header.Set("Content-Type", "application/json")
	reqSaveJira.AddCookie(cookie)
	recSaveJira := httptest.NewRecorder()
	mux.ServeHTTP(recSaveJira, reqSaveJira)
	if recSaveJira.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for save jira workspaces, got %d: %s", recSaveJira.Code, recSaveJira.Body.String())
	}

	updatedJira, err := v.GetValidAccessToken(context.Background(), adminEmail, "jira")
	if err != nil {
		t.Fatalf("failed getting updated jira token: %v", err)
	}
	if len(updatedJira.AllowedSpaceKeys) != 2 || updatedJira.AllowedSpaceKeys[1] != "ONB" {
		t.Errorf("expected allowed space keys [SPARK ONB], got %v", updatedJira.AllowedSpaceKeys)
	}

	// 7. Test POST /api/connectors/workspaces (valid save for GitHub)
	saveGH := fmt.Sprintf(`{"provider":"github","csrf_token":%q,"selected_orgs":["aetherise-cloud"],"allowed_read_repos":["aetherise-cloud/*"],"allowed_write_repos":["aetherise-cloud/spark-mcp-gateway"]}`, csrfToken)
	reqSaveGH := httptest.NewRequest("POST", "/api/connectors/workspaces", strings.NewReader(saveGH))
	reqSaveGH.Header.Set("Content-Type", "application/json")
	reqSaveGH.AddCookie(cookie)
	recSaveGH := httptest.NewRecorder()
	mux.ServeHTTP(recSaveGH, reqSaveGH)
	if recSaveGH.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for save github workspaces, got %d: %s", recSaveGH.Code, recSaveGH.Body.String())
	}

	updatedGH, err := v.GetValidAccessToken(context.Background(), adminEmail, "github")
	if err != nil {
		t.Fatalf("failed getting updated github token: %v", err)
	}
	if len(updatedGH.SelectedOrgs) != 1 || updatedGH.SelectedOrgs[0] != "aetherise-cloud" {
		t.Errorf("unexpected selected_orgs: %v", updatedGH.SelectedOrgs)
	}
	if updatedGH.AllowedWriteRepos != "aetherise-cloud/spark-mcp-gateway" {
		t.Errorf("unexpected allowed_write_repos: %s", updatedGH.AllowedWriteRepos)
	}
}
