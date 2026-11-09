package main_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"spark-mcp-gateway/internal/auth"
	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/mcp"
	"spark-mcp-gateway/internal/oauthbroker"
	"spark-mcp-gateway/internal/providers"
	"spark-mcp-gateway/internal/store"
	"spark-mcp-gateway/internal/vault"
)

func TestFullStackE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---------------------------------------------------------
	// 0. Setup Mock Upstream Servers (Mock GitHub, Mock Remote MCP, Mock REST API)
	// ---------------------------------------------------------
	mockGitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if !strings.Contains(authHdr, "example-pat-token-123") {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/user" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"login": "qa-octocat",
				"id":    12345,
				"name":  "QA Octocat",
			})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/repos/") && strings.HasSuffix(r.URL.Path, "/pulls") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"number": 42, "title": "feat: E2E pull request", "state": "open"},
			})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/contents/") {
			w.Header().Set("Content-Type", "application/vnd.github.raw+json")
			_, _ = w.Write([]byte("Verbatim README content from mock GitHub!"))
			return
		}
		http.NotFound(w, r)
	}))
	defer mockGitHub.Close()

	mockRemoteMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			ID     interface{}     `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")

		if req.Method == "tools/list" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"tools": []map[string]interface{}{
						{
							"name":           "post_message",
							"description":    "Post message to Slack channel",
							"required_scope": "read_only",
							"inputSchema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"channel": map[string]interface{}{"type": "string"},
									"text":    map[string]interface{}{"type": "string"},
								},
								"required": []string{"channel", "text"},
							},
						},
						{
							"name":           "delete_message",
							"description":    "Delete message from Slack channel",
							"required_scope": "full_access",
							"inputSchema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"channel": map[string]interface{}{"type": "string"},
									"ts":      map[string]interface{}{"type": "string"},
								},
								"required": []string{"channel", "ts"},
							},
						},
					},
				},
			})
			return
		}

		if req.Method == "tools/call" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]interface{}{
					"content": []map[string]interface{}{
						{"type": "text", "text": "Slack message sent successfully: channel=general, ts=1731000000.000100"},
					},
					"isError": false,
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockRemoteMCP.Close()

	mockRESTAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" && r.URL.Path == "/items" {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": "item-101", "name": "Cloud Quantum Processor", "stock": 5},
			})
			return
		}
		if r.Method == "DELETE" && r.URL.Path == "/items/item-101" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"deleted": true,
				"id":      "item-101",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockRESTAPI.Close()

	// ---------------------------------------------------------
	// 1. Boot Full Gateway Stack (OAuthServer + Broker + MCPServer + MemoryStore + LocalAEADKMS)
	// ---------------------------------------------------------
	jwtPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating ECDSA key: %v", err)
	}

	sessionKey := make([]byte, 32)
	_, _ = rand.Read(sessionKey)

	kms, err := vault.NewLocalAEADKMS(sessionKey)
	if err != nil {
		t.Fatalf("failed initializing Local AEAD KMS: %v", err)
	}

	st := store.NewMemoryStore()
	tokenVault := vault.NewTokenVault("e2e-gateway-inst", st, kms, "test-kek", nil)

	cfg := &config.Config{
		ServiceURL:              "", // populated after httptest server boots
		Port:                    "8080",
		AdminAllowedEmails:      []string{"brendon.ang20011007@gmail.com"},
		SessionHMACKey:          sessionKey,
		JWTES256PrivateKey:      jwtPrivKey,
		DevMode:                 true,
		GitHubOAuthClientID:     "", // Empty to trigger "SETUP REQUIRED"
		GitHubOAuthClientSecret: "",
		JiraOAuthClientID:       "",
		JiraOAuthClientSecret:   "",
		GCPProjectID:            "test-gcp-project",
		GCPRegion:               "us-central1",
	}

	toolRegistry := providers.NewRegistry(cfg, nil, func(ctx context.Context) (string, error) {
		return "mock-gcp-adc-token", nil
	})
	toolRegistry.GitHubBaseURL = mockGitHub.URL

	authServer := auth.NewOAuthServer(cfg, st, nil)
	broker := oauthbroker.NewBroker(cfg, st, tokenVault, authServer.SessionManager(), nil)
	broker.GitHubAPIURL = mockGitHub.URL
	broker.AllowLoopbackForTest = true

	mcpServer := mcp.NewServer(cfg, toolRegistry, tokenVault, st)
	mcpServer.AllowLoopbackForTest = true

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	authServer.RegisterRoutes(mux)
	broker.RegisterRoutes(mux)
	mux.Handle("/mcp", mcpServer)

	gatewayServer := httptest.NewServer(mux)
	defer gatewayServer.Close()

	cfg.ServiceURL = gatewayServer.URL

	// Client with cookie jar for browser session simulation
	jar, _ := cookiejar.New(nil)
	noRedirectClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	t.Logf("=== Full Gateway Stack booted at %s ===", gatewayServer.URL)

	// =========================================================================
	// FLOW 1: RFC 9728 Protected Resource Discovery (Root & /mcp path appended)
	// =========================================================================
	t.Run("1_ProtectedResourceDiscovery", func(t *testing.T) {
		endpoints := []string{
			"/.well-known/oauth-protected-resource",
			"/.well-known/oauth-protected-resource/mcp",
		}
		for _, ep := range endpoints {
			resp, err := noRedirectClient.Get(gatewayServer.URL + ep)
			if err != nil {
				t.Fatalf("GET %s failed: %v", ep, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s returned %d, want 200", ep, resp.StatusCode)
			}
			var disc struct {
				Resource             string   `json:"resource"`
				AuthorizationServers []string `json:"authorization_servers"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
				t.Fatalf("failed decoding discovery JSON for %s: %v", ep, err)
			}
			expectedResource := gatewayServer.URL + "/mcp"
			if disc.Resource != expectedResource {
				t.Errorf("%s resource mismatch: got %q, want %q", ep, disc.Resource, expectedResource)
			}
			if len(disc.AuthorizationServers) == 0 || disc.AuthorizationServers[0] != gatewayServer.URL {
				t.Errorf("%s authorization_servers mismatch: got %v, want [%s]", ep, disc.AuthorizationServers, gatewayServer.URL)
			}
		}
		t.Log("PASS: Flow 1 - Protected Resource Discovery RFC 9728 §3.1 root & /mcp validated.")
	})

	// =========================================================================
	// FLOW 2: DCR Google OpenAuth Whitelist & Evil Host Rejection
	// =========================================================================
	t.Run("2_DCROpenAuthAllowlistAndEvilRejection", func(t *testing.T) {
		validURIs := []string{
			"https://oauth-redirect.googleusercontent.com/r/custom-mcp-123",
			"https://aisandbox-pa.googleapis.com/oauth/callback",
			"https://claude.ai/api/mcp/auth_callback",
		}

		for i, u := range validURIs {
			body, _ := json.Marshal(map[string]interface{}{
				"client_name":   fmt.Sprintf("Google Client %d", i),
				"redirect_uris": []string{u},
			})
			resp, err := noRedirectClient.Post(gatewayServer.URL+"/api/oauth/register", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("DCR registration failed for %s: %v", u, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Errorf("expected 201 Created for valid URI %s, got %d", u, resp.StatusCode)
			}
		}

		evilURIs := []string{
			"https://evil.googleusercontent.com/callback",
			"https://evil.storage.googleapis.com/callback",
			"https://attacker.evil.com/callback",
		}

		for _, u := range evilURIs {
			body, _ := json.Marshal(map[string]interface{}{
				"client_name":   "Malicious Client",
				"redirect_uris": []string{u},
			})
			resp, err := noRedirectClient.Post(gatewayServer.URL+"/api/oauth/register", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("DCR post failed for %s: %v", u, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400 Bad Request for evil URI %s, got %d", u, resp.StatusCode)
			}
		}
		t.Log("PASS: Flow 2 - DCR Google OpenAuth allowlist allowed valid hosts and rejected evil hosts.")
	})

	// =========================================================================
	// FLOW 3: Admin Login -> Static Client -> Trailing Slash Prefix Auth -> Confidential Token Exchange
	// =========================================================================
	var jwtToken string
	t.Run("3_AdminLoginStaticClientAndConfidentialTokenExchange", func(t *testing.T) {
		adminEmail := "brendon.ang20011007@gmail.com"

		// 3.1 Admin dev login
		loginForm := url.Values{"email": {adminEmail}}
		respLogin, err := noRedirectClient.PostForm(gatewayServer.URL+"/auth/dev/login", loginForm)
		if err != nil {
			t.Fatalf("POST /auth/dev/login failed: %v", err)
		}
		respLogin.Body.Close()
		if respLogin.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 Found from /auth/dev/login, got %d", respLogin.StatusCode)
		}

		// 3.2 Fetch Dashboard to extract CSRF token
		respDash, err := noRedirectClient.Get(gatewayServer.URL + "/dashboard")
		if err != nil {
			t.Fatalf("GET /dashboard failed: %v", err)
		}
		dashHTMLBytes, _ := io.ReadAll(respDash.Body)
		respDash.Body.Close()
		dashHTML := string(dashHTMLBytes)

		csrfToken := authServer.SessionManager().GenerateCSRFToken(adminEmail)

		// 3.3 Create static client with trailing slash prefix
		staticReqBody, _ := json.Marshal(map[string]interface{}{
			"client_name":   "Google Spark Static Client",
			"redirect_uris": []string{"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-777/"},
			"csrf_token":    csrfToken,
		})
		reqStatic, _ := http.NewRequest("POST", gatewayServer.URL+"/api/oauth/clients/static", bytes.NewReader(staticReqBody))
		reqStatic.Header.Set("Content-Type", "application/json")
		reqStatic.Header.Set("X-CSRF-Token", csrfToken)
		respStatic, err := noRedirectClient.Do(reqStatic)
		if err != nil {
			t.Fatalf("POST /api/oauth/clients/static failed: %v", err)
		}
		defer respStatic.Body.Close()
		if respStatic.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(respStatic.Body)
			t.Fatalf("expected 201 Created for static client, got %d: %s", respStatic.StatusCode, string(body))
		}

		var staticResp struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		_ = json.NewDecoder(respStatic.Body).Decode(&staticResp)
		if !strings.HasPrefix(staticResp.ClientID, "spark-static-client-") {
			t.Fatalf("expected client_id starting with spark-static-client-, got %q", staticResp.ClientID)
		}
		if staticResp.ClientSecret == "" {
			t.Fatalf("expected non-empty client_secret for static client")
		}

		// 3.4 PKCE S256 parameters
		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-very-long-verifier-123456789"
		h := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

		// 3.5 Authorize with trailing-slash subpath redirect_uri
		redirectURI := "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-777/callback"
		authForm := url.Values{
			"client_id":             {staticResp.ClientID},
			"redirect_uri":          {redirectURI},
			"response_type":         {"code"},
			"state":                 {"qa-state-xyz"},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"decision":              {"approve"},
			"preset":                {"read_only"},
			"csrf_token":            {csrfToken},
		}

		respAuth, err := noRedirectClient.PostForm(gatewayServer.URL+"/authorize", authForm)
		if err != nil {
			t.Fatalf("POST /authorize failed: %v", err)
		}
		respAuth.Body.Close()
		if respAuth.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 Found from /authorize, got %d", respAuth.StatusCode)
		}

		loc := respAuth.Header.Get("Location")
		uLoc, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("failed parsing redirect Location: %v", err)
		}
		authCode := uLoc.Query().Get("code")
		if authCode == "" {
			t.Fatalf("authorization code not returned in redirect location: %s", loc)
		}

		// 3.6 Exchange code for token using HTTP Basic Auth (client_secret_basic)
		tokenForm := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {redirectURI},
			"code_verifier": {codeVerifier},
		}
		reqToken, _ := http.NewRequest("POST", gatewayServer.URL+"/api/oauth/token", strings.NewReader(tokenForm.Encode()))
		reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqToken.SetBasicAuth(staticResp.ClientID, staticResp.ClientSecret)

		respToken, err := noRedirectClient.Do(reqToken)
		if err != nil {
			t.Fatalf("POST /api/oauth/token failed: %v", err)
		}
		defer respToken.Body.Close()
		if respToken.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(respToken.Body)
			t.Fatalf("expected 200 OK from /api/oauth/token, got %d: %s", respToken.StatusCode, string(body))
		}

		var tokResp struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
		}
		_ = json.NewDecoder(respToken.Body).Decode(&tokResp)
		if tokResp.AccessToken == "" || tokResp.TokenType != "Bearer" {
			t.Fatalf("invalid token response: %+v", tokResp)
		}
		jwtToken = tokResp.AccessToken

		// Verify ES256 JWT cryptographic signature
		claims, err := auth.VerifyJWT(jwtToken, &jwtPrivKey.PublicKey, gatewayServer.URL, gatewayServer.URL+"/mcp")
		if err != nil {
			t.Fatalf("JWT validation failed against gateway public key: %v", err)
		}
		if claims.Subject != "admin:"+adminEmail {
			t.Errorf("claims.Subject mismatch: got %q, want admin:%s", claims.Subject, adminEmail)
		}
		if claims.Scopes["github"] != "read_only" {
			t.Errorf("expected read_only github scope, got %q", claims.Scopes["github"])
		}

		t.Logf("PASS: Flow 3 - Static client minted, prefix redirect matched, basic auth exchanged for valid ES256 JWT: %s...", jwtToken[:30])
		_ = dashHTML
	})

	// =========================================================================
	// FLOW 4: Dashboard UI Inspection (SETUP REQUIRED, 10 Catalog Templates, Modals)
	// =========================================================================
	t.Run("4_DashboardUIAndCatalogTemplates", func(t *testing.T) {
		resp, err := noRedirectClient.Get(gatewayServer.URL + "/dashboard")
		if err != nil {
			t.Fatalf("GET /dashboard failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from /dashboard, got %d", resp.StatusCode)
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed reading dashboard body: %v", err)
		}
		html := string(bodyBytes)

		// 1. Verify "SETUP REQUIRED" badge for GitHub (since GITHUB_OAUTH_CLIENT_ID is empty)
		if !strings.Contains(html, "SETUP REQUIRED") {
			t.Errorf("dashboard HTML missing 'SETUP REQUIRED' badge")
		}

		// 2. Verify modal triggers
		if !strings.Contains(html, "openCatalogModal") {
			t.Errorf("dashboard HTML missing 'openCatalogModal' JavaScript function/trigger")
		}
		if !strings.Contains(html, "openGeminiGuideModal") {
			t.Errorf("dashboard HTML missing 'openGeminiGuideModal' JavaScript function/trigger")
		}
		if !strings.Contains(html, "tutorial-modal") {
			t.Errorf("dashboard HTML missing '#tutorial-modal' pop-out setup tutorial element")
		}

		// 3. Verify all 10 Catalog Templates
		catalogTemplates := []string{
			"GitHub",
			"Atlassian Jira",
			"Linear",
			"Notion",
			"Slack",
			"Cloudflare",
			"Sentry",
			"Supabase",
			"Custom Remote MCP Server",
			"Custom REST API Connector",
		}
		for _, tmpl := range catalogTemplates {
			if !strings.Contains(html, tmpl) {
				t.Errorf("dashboard catalog missing required template: %q", tmpl)
			}
		}

		t.Log("PASS: Flow 4 - Dashboard rendered SETUP REQUIRED, openCatalogModal, openGeminiGuideModal, #tutorial-modal, and all 10 catalog templates.")
	})

	// =========================================================================
	// FLOW 5: In-Dashboard KMS OAuth App Configuration (github oauth-config)
	// =========================================================================
	t.Run("5_KMSOAuthConfigGitHub", func(t *testing.T) {
		csrfToken := authServer.SessionManager().GenerateCSRFToken("brendon.ang20011007@gmail.com")

		cfgPayload, _ := json.Marshal(map[string]interface{}{
			"client_id":           "kms-injected-gh-client-id-888",
			"client_secret":       "kms-injected-gh-client-secret-999",
			"allowed_write_repos": "octocat/hello-world,brendon/test-repo",
			"csrf_token":          csrfToken,
		})

		req, _ := http.NewRequest("POST", gatewayServer.URL+"/api/connectors/github/oauth-config", bytes.NewReader(cfgPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrfToken)

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			t.Fatalf("POST /api/connectors/github/oauth-config failed: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for oauth-config, got %d", resp.StatusCode)
		}

		// Verify GET /oauth/connect/github now generates redirect containing the KMS client_id
		respConnect, err := noRedirectClient.Get(gatewayServer.URL + "/oauth/connect/github")
		if err != nil {
			t.Fatalf("GET /oauth/connect/github failed: %v", err)
		}
		respConnect.Body.Close()
		if respConnect.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 Found from /oauth/connect/github, got %d", respConnect.StatusCode)
		}
		connectLoc := respConnect.Header.Get("Location")
		if !strings.Contains(connectLoc, "client_id=kms-injected-gh-client-id-888") {
			t.Errorf("expected Location to contain kms client_id, got %q", connectLoc)
		}

		t.Log("PASS: Flow 5 - KMS OAuth Config saved and loaded into /oauth/connect/github redirect.")
	})

	// =========================================================================
	// FLOW 6: GitHub PAT Quick-Connect & MCP Tool Listing
	// =========================================================================
	t.Run("6_GitHubPATQuickConnectAndMCPListing", func(t *testing.T) {
		csrfToken := authServer.SessionManager().GenerateCSRFToken("brendon.ang20011007@gmail.com")

		patPayload, _ := json.Marshal(map[string]interface{}{
			"pat":        "example-pat-token-123",
			"scope_mode": "read_only",
			"csrf_token": csrfToken,
		})

		req, _ := http.NewRequest("POST", gatewayServer.URL+"/api/connectors/github/pat", bytes.NewReader(patPayload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrfToken)

		resp, err := noRedirectClient.Do(req)
		if err != nil {
			t.Fatalf("POST /api/connectors/github/pat failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 OK for github pat, got %d: %s", resp.StatusCode, string(b))
		}

		var patResp struct {
			OK           bool   `json:"ok"`
			AccountLabel string `json:"account_label"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&patResp)
		if !patResp.OK || patResp.AccountLabel != "@qa-octocat" {
			t.Errorf("unexpected PAT response: %+v", patResp)
		}

		// Verify Dashboard reflects CONNECTED and @qa-octocat
		respDash, err := noRedirectClient.Get(gatewayServer.URL + "/dashboard")
		if err != nil {
			t.Fatalf("GET /dashboard failed: %v", err)
		}
		dashBytes, _ := io.ReadAll(respDash.Body)
		respDash.Body.Close()
		if !strings.Contains(string(dashBytes), "@qa-octocat") {
			t.Errorf("dashboard HTML missing '@qa-octocat' after PAT connection")
		}

		// Verify POST /mcp (tools/list) with Bearer token exposes github_list_prs & github_read_file
		rpcBody, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/list",
		})
		reqMCP, _ := http.NewRequest("POST", gatewayServer.URL+"/mcp", bytes.NewReader(rpcBody))
		reqMCP.Header.Set("Content-Type", "application/json")
		reqMCP.Header.Set("Authorization", "Bearer "+jwtToken)

		respMCP, err := noRedirectClient.Do(reqMCP)
		if err != nil {
			t.Fatalf("POST /mcp tools/list failed: %v", err)
		}
		defer respMCP.Body.Close()
		if respMCP.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from /mcp, got %d", respMCP.StatusCode)
		}

		var mcpListResp struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		_ = json.NewDecoder(respMCP.Body).Decode(&mcpListResp)
		toolMap := make(map[string]bool)
		for _, tool := range mcpListResp.Result.Tools {
			toolMap[tool.Name] = true
		}

		if !toolMap["github_list_prs"] {
			t.Errorf("tools/list missing 'github_list_prs'")
		}
		if !toolMap["github_read_file"] {
			t.Errorf("tools/list missing 'github_read_file'")
		}

		t.Log("PASS: Flow 6 - GitHub PAT connected, @qa-octocat stored, github tools exposed in /mcp tools/list.")
	})

	// =========================================================================
	// FLOW 7: Custom Connectors SSRF Protection, Tool Federation, XML Spotlighting, and Disconnect
	// =========================================================================
	t.Run("7_CustomConnectorsSSRFAndFederatedExecution", func(t *testing.T) {
		csrfToken := authServer.SessionManager().GenerateCSRFToken("brendon.ang20011007@gmail.com")

		// 7.1 SSRF Attacks blocked
		ssrfAttacks := []string{
			"http://169.254.169.254/latest/meta-data", // Cloud metadata link-local
			"http://10.0.0.1/admin",                   // RFC 1918 private
			"http://192.168.1.1/api",                  // RFC 1918 private
			"http://172.16.0.1/api",                   // RFC 1918 private
		}

		for _, badURL := range ssrfAttacks {
			body, _ := json.Marshal(map[string]interface{}{
				"slug":           "evil-conn",
				"name":           "Evil Connector",
				"connector_type": "rest_api",
				"endpoint_url":   badURL,
				"csrf_token":     csrfToken,
			})
			req, _ := http.NewRequest("POST", gatewayServer.URL+"/api/connectors/custom", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", csrfToken)

			resp, err := noRedirectClient.Do(req)
			if err != nil {
				t.Fatalf("POST /api/connectors/custom failed: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400 Bad Request for SSRF target %s, got %d", badURL, resp.StatusCode)
			}
		}

		// 7.2 Register valid custom remote_mcp connector ("slack")
		slackBody, _ := json.Marshal(map[string]interface{}{
			"slug":           "slack",
			"name":           "Slack Operations",
			"connector_type": "remote_mcp",
			"endpoint_url":   mockRemoteMCP.URL,
			"access_token":   "example-tok-slack-999",
			"scope_mode":     "read_only",
			"csrf_token":     csrfToken,
		})
		reqSlack, _ := http.NewRequest("POST", gatewayServer.URL+"/api/connectors/custom", bytes.NewReader(slackBody))
		reqSlack.Header.Set("Content-Type", "application/json")
		reqSlack.Header.Set("X-CSRF-Token", csrfToken)
		respSlack, err := noRedirectClient.Do(reqSlack)
		if err != nil {
			t.Fatalf("POST /api/connectors/custom (slack) failed: %v", err)
		}
		respSlack.Body.Close()
		if respSlack.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for custom remote_mcp, got %d", respSlack.StatusCode)
		}

		// 7.3 Register valid custom rest_api connector ("inventory")
		invBody, _ := json.Marshal(map[string]interface{}{
			"slug":           "inventory",
			"name":           "Enterprise Inventory",
			"connector_type": "rest_api",
			"endpoint_url":   mockRESTAPI.URL,
			"access_token":   "inv-secret-api-key",
			"auth_header":    "X-API-Key",
			"scope_mode":     "read_only",
			"csrf_token":     csrfToken,
		})
		reqInv, _ := http.NewRequest("POST", gatewayServer.URL+"/api/connectors/custom", bytes.NewReader(invBody))
		reqInv.Header.Set("Content-Type", "application/json")
		reqInv.Header.Set("X-CSRF-Token", csrfToken)
		respInv, err := noRedirectClient.Do(reqInv)
		if err != nil {
			t.Fatalf("POST /api/connectors/custom (inventory) failed: %v", err)
		}
		respInv.Body.Close()
		if respInv.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for custom rest_api, got %d", respInv.StatusCode)
		}

		// 7.4 Verify POST /mcp (tools/list) federates tools with scope filtering
		listReq, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      10,
			"method":  "tools/list",
		})
		reqTools, _ := http.NewRequest("POST", gatewayServer.URL+"/mcp", bytes.NewReader(listReq))
		reqTools.Header.Set("Content-Type", "application/json")
		reqTools.Header.Set("Authorization", "Bearer "+jwtToken)

		respTools, err := noRedirectClient.Do(reqTools)
		if err != nil {
			t.Fatalf("POST /mcp tools/list failed: %v", err)
		}
		defer respTools.Body.Close()
		if respTools.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK from /mcp, got %d", respTools.StatusCode)
		}

		var toolsResp struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		_ = json.NewDecoder(respTools.Body).Decode(&toolsResp)
		toolMap := make(map[string]bool)
		for _, tool := range toolsResp.Result.Tools {
			toolMap[tool.Name] = true
		}

		// slack__post_message is read_only -> should appear
		if !toolMap["slack__post_message"] {
			t.Errorf("tools/list missing federated tool 'slack__post_message'")
		}
		// slack__delete_message requires full_access -> should be filtered out under read_only JWT
		if toolMap["slack__delete_message"] {
			t.Errorf("tools/list should have filtered out full_access tool 'slack__delete_message'")
		}
		// inventory_api_request -> should appear
		if !toolMap["inventory_api_request"] {
			t.Errorf("tools/list missing federated tool 'inventory_api_request'")
		}

		// 7.5 Call federated remote_mcp tool (slack__post_message) -> verify XML Spotlighting
		callSlackReq, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      11,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "slack__post_message",
				"arguments": map[string]interface{}{
					"channel": "general",
					"text":    "Hello E2E test",
				},
			},
		})
		reqCallSlack, _ := http.NewRequest("POST", gatewayServer.URL+"/mcp", bytes.NewReader(callSlackReq))
		reqCallSlack.Header.Set("Content-Type", "application/json")
		reqCallSlack.Header.Set("Authorization", "Bearer "+jwtToken)

		respCallSlack, err := noRedirectClient.Do(reqCallSlack)
		if err != nil {
			t.Fatalf("tools/call slack failed: %v", err)
		}
		defer respCallSlack.Body.Close()
		var callSlackResp struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		_ = json.NewDecoder(respCallSlack.Body).Decode(&callSlackResp)
		slackText := callSlackResp.Result.Content[0].Text
		if !strings.Contains(slackText, "<untrusted_upstream_data provider=\"custom:slack\" tool=\"slack__post_message\">") {
			t.Errorf("slack response missing XML spotlighting wrapper tag: %s", slackText)
		}
		if !strings.Contains(slackText, "Slack message sent successfully") {
			t.Errorf("slack response missing upstream payload text: %s", slackText)
		}

		// 7.6 Call federated REST API (inventory_api_request GET) -> verify XML Spotlighting
		callGetInvReq, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      12,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "inventory_api_request",
				"arguments": map[string]interface{}{
					"method": "GET",
					"path":   "/items",
				},
			},
		})
		reqCallGetInv, _ := http.NewRequest("POST", gatewayServer.URL+"/mcp", bytes.NewReader(callGetInvReq))
		reqCallGetInv.Header.Set("Content-Type", "application/json")
		reqCallGetInv.Header.Set("Authorization", "Bearer "+jwtToken)

		respCallGetInv, err := noRedirectClient.Do(reqCallGetInv)
		if err != nil {
			t.Fatalf("tools/call inventory GET failed: %v", err)
		}
		defer respCallGetInv.Body.Close()
		var callGetInvResp struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		_ = json.NewDecoder(respCallGetInv.Body).Decode(&callGetInvResp)
		invGetText := callGetInvResp.Result.Content[0].Text
		if !strings.Contains(invGetText, "<untrusted_upstream_data provider=\"custom:inventory\" tool=\"inventory_api_request\">") {
			t.Errorf("inventory GET missing XML spotlighting: %s", invGetText)
		}
		if !strings.Contains(invGetText, "Cloud Quantum Processor") {
			t.Errorf("inventory GET missing expected payload: %s", invGetText)
		}

		// 7.7 Call federated REST API (inventory_api_request DELETE) under read_only scope -> must be blocked
		callDelInvReq, _ := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      13,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name": "inventory_api_request",
				"arguments": map[string]interface{}{
					"method": "DELETE",
					"path":   "/items/item-101",
				},
			},
		})
		reqCallDelInv, _ := http.NewRequest("POST", gatewayServer.URL+"/mcp", bytes.NewReader(callDelInvReq))
		reqCallDelInv.Header.Set("Content-Type", "application/json")
		reqCallDelInv.Header.Set("Authorization", "Bearer "+jwtToken)

		respCallDelInv, err := noRedirectClient.Do(reqCallDelInv)
		if err != nil {
			t.Fatalf("tools/call inventory DELETE failed: %v", err)
		}
		defer respCallDelInv.Body.Close()
		var callDelInvResp struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		_ = json.NewDecoder(respCallDelInv.Body).Decode(&callDelInvResp)
		if !callDelInvResp.Result.IsError {
			t.Errorf("expected isError=true when invoking DELETE under read_only scope")
		}
		delErrorText := callDelInvResp.Result.Content[0].Text
		if !strings.Contains(delErrorText, "requires full_access scope, but token only grants read_only") {
			t.Errorf("unexpected error text for denied DELETE: %s", delErrorText)
		}

		// 7.8 Disconnect custom connector ("custom:slack")
		discReq, _ := http.NewRequest("POST", gatewayServer.URL+"/api/connections/custom:slack/disconnect", strings.NewReader("csrf_token="+url.QueryEscape(csrfToken)))
		discReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		discReq.Header.Set("Accept", "application/json")
		discReq.Header.Set("X-CSRF-Token", csrfToken)
		respDisc, err := noRedirectClient.Do(discReq)
		if err != nil {
			t.Fatalf("POST disconnect failed: %v", err)
		}
		respDisc.Body.Close()
		if respDisc.StatusCode != http.StatusOK && respDisc.StatusCode != http.StatusFound && respDisc.StatusCode != http.StatusSeeOther {
			t.Fatalf("expected 200, 302 or 303 from disconnect, got %d", respDisc.StatusCode)
		}

		// 7.9 Verify tools/list no longer contains "slack__post_message"
		reqTools2, _ := http.NewRequest("POST", gatewayServer.URL+"/mcp", bytes.NewReader(listReq))
		reqTools2.Header.Set("Content-Type", "application/json")
		reqTools2.Header.Set("Authorization", "Bearer "+jwtToken)
		respTools2, err := noRedirectClient.Do(reqTools2)
		if err != nil {
			t.Fatalf("POST /mcp tools/list after disconnect failed: %v", err)
		}
		defer respTools2.Body.Close()
		var toolsResp2 struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		_ = json.NewDecoder(respTools2.Body).Decode(&toolsResp2)
		for _, tool := range toolsResp2.Result.Tools {
			if tool.Name == "slack__post_message" {
				t.Fatalf("slack__post_message still exposed in tools/list after disconnect!")
			}
		}

		t.Log("PASS: Flow 7 - SSRF rejected, remote_mcp & rest_api federated, XML spotlighted, DELETE blocked under read_only, and disconnect cleanly removed tools.")
	})
	_ = ctx
}
