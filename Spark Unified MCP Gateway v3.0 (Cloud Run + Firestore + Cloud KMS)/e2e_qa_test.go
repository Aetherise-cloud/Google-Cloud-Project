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

// -----------------------------------------------------------------------------
// V4 Developer Fix Manual End-to-End QA Verification (In-Memory, Zero TCP Sockets)
// -----------------------------------------------------------------------------

type mockRoundTripper func(*http.Request) (*http.Response, error)

func (m mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func mockJSONResponse(req *http.Request, status int, data interface{}) (*http.Response, error) {
	b, _ := json.Marshal(data)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
		Request:    req,
	}, nil
}

func TestV4DeveloperFixManualE2E(t *testing.T) {
	ctx := context.Background()

	// 1. In-Memory Mock Upstream RoundTripper (Zero Sockets Bound)
	rt := mockRoundTripper(func(req *http.Request) (*http.Response, error) {
		// Mock GitHub API
		if req.URL.Host == "mock-github.internal" {
			if req.URL.Path == "/user/orgs" {
				return mockJSONResponse(req, http.StatusOK, []map[string]string{
					{"login": "aetherise-cloud"},
				})
			}
			if req.URL.Path == "/user/repos" || req.URL.Path == "/orgs/aetherise-cloud/repos" {
				return mockJSONResponse(req, http.StatusOK, []map[string]string{
					{"full_name": "aetherise-cloud/spark-mcp-gateway"},
				})
			}
			if strings.HasPrefix(req.URL.Path, "/repos/aetherise-cloud/spark-mcp-gateway/pulls") {
				return mockJSONResponse(req, http.StatusOK, []map[string]interface{}{
					{"number": 101, "title": "feat: V4 PR", "state": "open"},
				})
			}
			return mockJSONResponse(req, http.StatusNotFound, map[string]string{"message": "not found"})
		}

		// Mock Jira API
		if req.URL.Host == "mock-jira.internal" {
			if strings.HasSuffix(req.URL.Path, "/project/search") {
				return mockJSONResponse(req, http.StatusOK, map[string]interface{}{
					"values": []map[string]string{
						{"key": "SPARK", "name": "Spark Core"},
						{"key": "ONB", "name": "Onboarding"},
					},
				})
			}
			if req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/issue") {
				return mockJSONResponse(req, http.StatusCreated, map[string]interface{}{
					"id":   "10001",
					"key":  "SPARK-101",
					"self": "https://mock-jira.internal/rest/api/3/issue/10001",
				})
			}
			if strings.HasSuffix(req.URL.Path, "/search") {
				return mockJSONResponse(req, http.StatusOK, map[string]interface{}{
					"issues": []map[string]interface{}{
						{
							"id":  "10001",
							"key": "SPARK-101",
							"fields": map[string]interface{}{
								"summary": "Spark Test Issue",
								"status":  map[string]string{"name": "In Progress"},
							},
						},
					},
				})
			}
			return mockJSONResponse(req, http.StatusNotFound, map[string]string{"message": "not found"})
		}

		// Mock Cloud Run API
		if req.URL.Host == "mock-cloudrun.internal" {
			if strings.Contains(req.URL.Path, "/services/spark-gateway") {
				return mockJSONResponse(req, http.StatusOK, map[string]interface{}{
					"name":       "projects/test-gcp-project/locations/us-central1/services/spark-gateway",
					"uri":        "https://spark-gateway.run.app",
					"ingress":    "INGRESS_TRAFFIC_ALL",
					"createTime": "2026-11-09T00:00:00Z",
					"updateTime": "2026-11-09T01:00:00Z",
					"template": map[string]interface{}{
						"serviceAccount": "spark-sa@test-gcp-project.iam.gserviceaccount.com",
						"scaling":        map[string]interface{}{"minInstanceCount": 1, "maxInstanceCount": 10},
						"containers": []map[string]interface{}{
							{
								"image": "gcr.io/test-gcp-project/spark-gateway:v4",
								"resources": map[string]interface{}{
									"limits": map[string]string{"cpu": "2", "memory": "1Gi"},
								},
								"env": []map[string]string{
									{"name": "DATABASE_PASSWORD", "value": "super-secret-password-123"},
									{"name": "API_KEY", "value": "secret-api-key-xyz"},
								},
								"secret_key_ref": map[string]string{
									"secret":  "db-secret",
									"version": "latest",
								},
								"volumeMounts": []map[string]string{
									{"name": "secret-volume", "mountPath": "/etc/secrets"},
								},
								"secrets": []map[string]string{
									{"name": "private-key", "path": "tls.key"},
								},
							},
						},
					},
					"traffic": []map[string]interface{}{
						{"percent": 100, "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"},
					},
				})
			}
			return mockJSONResponse(req, http.StatusNotFound, map[string]string{"message": "not found"})
		}

		return mockJSONResponse(req, http.StatusNotFound, map[string]string{"message": "unknown host"})
	})

	inMemoryClient := &http.Client{Transport: rt}

	// 2. Initialize In-Memory Gateway Core
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
	tokenVault := vault.NewTokenVault("v4-inmemory-inst", st, kms, "test-kek", nil)

	cfg := &config.Config{
		ServiceURL:         "https://spark-gateway.internal",
		Port:               "8080",
		AdminAllowedEmails: []string{"brendon.ang20011007@gmail.com"},
		SessionHMACKey:     sessionKey,
		JWTES256PrivateKey: jwtPrivKey,
		DevMode:            true,
		GCPProjectID:       "test-gcp-project",
		GCPRegion:          "us-central1",
	}

	toolRegistry := providers.NewRegistry(cfg, inMemoryClient, func(ctx context.Context) (string, error) {
		return "mock-adc-token", nil
	})
	toolRegistry.GitHubBaseURL = "https://mock-github.internal"
	toolRegistry.JiraBaseURL = "https://mock-jira.internal"
	toolRegistry.CloudRunBaseURL = "https://mock-cloudrun.internal"

	authServer := auth.NewOAuthServer(cfg, st, inMemoryClient)
	broker := oauthbroker.NewBroker(cfg, st, tokenVault, authServer.SessionManager(), inMemoryClient)
	broker.GitHubAPIURL = "https://mock-github.internal"
	broker.AtlassianAPIURL = "https://mock-jira.internal"
	broker.AllowLoopbackForTest = true

	mcpServer := mcp.NewServer(cfg, toolRegistry, tokenVault, st)
	mcpServer.AllowLoopbackForTest = true

	mux := http.NewServeMux()
	authServer.RegisterRoutes(mux)
	broker.RegisterRoutes(mux)
	mux.Handle("/mcp", mcpServer)

	// Simulated downstream 503 handler
	mux.HandleFunc("POST /mcp/simulate-coldstart", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Service Unavailable: container cold-starting"))
	})
	mux.HandleFunc("POST /mcp/simulate-panic", func(w http.ResponseWriter, r *http.Request) {
		panic("simulated unhandled panic in MCP handler")
	})

	handler := mcp.JSONErrorMiddleware(mux)

	adminEmail := "brendon.ang20011007@gmail.com"
	var adminCookie *http.Cookie
	var csrfToken string
	var clientID, clientSecret string
	var jwtToken string

	// =========================================================================
	// FLOW 1: OAuth 2.1 DCR & Interactive Workspace Picker
	// =========================================================================
	t.Run("V4_Flow1_OAuth21DCRAndWorkspacePicker", func(t *testing.T) {
		// 1.1 POST /register (RFC 7591 root alias)
		regBody := `{"client_name":"Gemini Web Client","redirect_uris":["https://gemini.google.com/callback"]}`
		reqReg := httptest.NewRequest("POST", "/register", strings.NewReader(regBody))
		reqReg.Header.Set("Content-Type", "application/json")
		recReg := httptest.NewRecorder()
		handler.ServeHTTP(recReg, reqReg)

		if recReg.Code != http.StatusCreated {
			t.Fatalf("POST /register returned %d, want 201 Created: %s", recReg.Code, recReg.Body.String())
		}
		var regResp struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		_ = json.NewDecoder(recReg.Body).Decode(&regResp)
		if !strings.HasPrefix(regResp.ClientID, "spark-client-") {
			t.Errorf("expected client_id starting with 'spark-client-', got %q", regResp.ClientID)
		}
		clientID = regResp.ClientID
		clientSecret = regResp.ClientSecret

		// 1.2 Admin login & CSRF token
		loginForm := url.Values{"email": {adminEmail}}
		reqLogin := httptest.NewRequest("POST", "/auth/dev/login", strings.NewReader(loginForm.Encode()))
		reqLogin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recLogin := httptest.NewRecorder()
		handler.ServeHTTP(recLogin, reqLogin)

		if recLogin.Code != http.StatusFound {
			t.Fatalf("POST /auth/dev/login returned %d, want 302 Found", recLogin.Code)
		}
		for _, c := range recLogin.Result().Cookies() {
			if strings.Contains(c.Name, "spark_admin") {
				adminCookie = c
				break
			}
		}
		if adminCookie == nil {
			t.Fatalf("session cookie not found, cookies: %v", recLogin.Result().Cookies())
		}
		csrfToken = authServer.SessionManager().GenerateCSRFToken(adminEmail)

		// 1.3 Pre-store active tokens for GitHub and Jira so workspaces can be queried
		ghTok := &vault.TokenData{
			AccessToken:   "example-pat-token-123",
			ConnectorType: "oauth2",
			Scope:         "full_access",
			AccountLabel:  "octocat",
			UpdatedAt:     time.Now(),
		}
		if err := tokenVault.StoreToken(ctx, adminEmail, "github", ghTok); err != nil {
			t.Fatalf("failed storing gh token: %v", err)
		}

		jiraTok := &vault.TokenData{
			AccessToken:   "example-jira-token-456",
			ConnectorType: "oauth2",
			Scope:         "full_access",
			CloudID:       "jira-cloud-123",
			SiteURL:       "https://aetherise.atlassian.net",
			SiteName:      "Aetherise Jira",
			AccountLabel:  "admin@aetherise.com",
			UpdatedAt:     time.Now(),
		}
		if err := tokenVault.StoreToken(ctx, adminEmail, "jira", jiraTok); err != nil {
			t.Fatalf("failed storing jira token: %v", err)
		}

		// 1.4 GET /api/connectors/github/workspaces
		reqGHWork := httptest.NewRequest("GET", "/api/connectors/github/workspaces", nil)
		reqGHWork.AddCookie(adminCookie)
		recGHWork := httptest.NewRecorder()
		handler.ServeHTTP(recGHWork, reqGHWork)

		if recGHWork.Code != http.StatusOK {
			t.Fatalf("GET /api/connectors/github/workspaces returned %d: %s", recGHWork.Code, recGHWork.Body.String())
		}
		var ghWorkResp struct {
			Orgs  []string `json:"orgs"`
			Repos []string `json:"repos"`
		}
		_ = json.NewDecoder(recGHWork.Body).Decode(&ghWorkResp)
		if len(ghWorkResp.Orgs) == 0 || ghWorkResp.Orgs[0] != "aetherise-cloud" {
			t.Errorf("expected org 'aetherise-cloud', got: %v", ghWorkResp.Orgs)
		}
		if len(ghWorkResp.Repos) == 0 || ghWorkResp.Repos[0] != "aetherise-cloud/spark-mcp-gateway" {
			t.Errorf("expected repo 'aetherise-cloud/spark-mcp-gateway', got: %v", ghWorkResp.Repos)
		}

		// 1.5 GET /api/connectors/jira/workspaces
		reqJiraWork := httptest.NewRequest("GET", "/api/connectors/jira/workspaces", nil)
		reqJiraWork.AddCookie(adminCookie)
		recJiraWork := httptest.NewRecorder()
		handler.ServeHTTP(recJiraWork, reqJiraWork)

		if recJiraWork.Code != http.StatusOK {
			t.Fatalf("GET /api/connectors/jira/workspaces returned %d: %s", recJiraWork.Code, recJiraWork.Body.String())
		}
		var jiraWorkResp struct {
			Spaces []struct {
				Key  string `json:"key"`
				Name string `json:"name"`
			} `json:"spaces"`
		}
		_ = json.NewDecoder(recJiraWork.Body).Decode(&jiraWorkResp)
		if len(jiraWorkResp.Spaces) < 2 || jiraWorkResp.Spaces[0].Key != "SPARK" {
			t.Errorf("expected Jira spaces [SPARK, ONB], got: %+v", jiraWorkResp.Spaces)
		}

		// 1.6 POST /api/connectors/workspaces (GitHub)
		saveGHBody := fmt.Sprintf(`{
			"provider": "github",
			"csrf_token": %q,
			"selected_orgs": ["aetherise-cloud"],
			"allowed_read_repos": ["aetherise-cloud/*"],
			"allowed_write_repos": ["aetherise-cloud/spark-mcp-gateway"]
		}`, csrfToken)
		reqSaveGH := httptest.NewRequest("POST", "/api/connectors/workspaces", strings.NewReader(saveGHBody))
		reqSaveGH.Header.Set("Content-Type", "application/json")
		reqSaveGH.AddCookie(adminCookie)
		recSaveGH := httptest.NewRecorder()
		handler.ServeHTTP(recSaveGH, reqSaveGH)

		if recSaveGH.Code != http.StatusOK {
			t.Fatalf("POST /api/connectors/workspaces (github) returned %d: %s", recSaveGH.Code, recSaveGH.Body.String())
		}

		// 1.7 POST /api/connectors/workspaces (Jira)
		saveJiraBody := fmt.Sprintf(`{
			"provider": "jira",
			"csrf_token": %q,
			"allowed_space_keys": ["SPARK"]
		}`, csrfToken)
		reqSaveJira := httptest.NewRequest("POST", "/api/connectors/workspaces", strings.NewReader(saveJiraBody))
		reqSaveJira.Header.Set("Content-Type", "application/json")
		reqSaveJira.AddCookie(adminCookie)
		recSaveJira := httptest.NewRecorder()
		handler.ServeHTTP(recSaveJira, reqSaveJira)

		if recSaveJira.Code != http.StatusOK {
			t.Fatalf("POST /api/connectors/workspaces (jira) returned %d: %s", recSaveJira.Code, recSaveJira.Body.String())
		}

		// Verify TokenVault has saved workspaces
		savedGH, err := tokenVault.GetValidAccessToken(ctx, adminEmail, "github")
		if err != nil || len(savedGH.SelectedOrgs) == 0 || savedGH.SelectedOrgs[0] != "aetherise-cloud" {
			t.Fatalf("TokenVault did not store selected_orgs properly: %+v", savedGH)
		}
		savedJira, err := tokenVault.GetValidAccessToken(ctx, adminEmail, "jira")
		if err != nil || len(savedJira.AllowedSpaceKeys) == 0 || savedJira.AllowedSpaceKeys[0] != "SPARK" {
			t.Fatalf("TokenVault did not store allowed_space_keys properly: %+v", savedJira)
		}

		// 1.8 Authorize & Token Root Alias (POST /token)
		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-very-long-verifier-123456789"
		h := sha256.Sum256([]byte(codeVerifier))
		codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

		authForm := url.Values{
			"client_id":             {clientID},
			"redirect_uri":          {"https://gemini.google.com/callback"},
			"response_type":         {"code"},
			"state":                 {"v4-state-123"},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"decision":              {"approve"},
			"preset":                {"full_access"},
			"csrf_token":            {csrfToken},
		}
		reqAuth := httptest.NewRequest("POST", "/authorize", strings.NewReader(authForm.Encode()))
		reqAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqAuth.AddCookie(adminCookie)
		recAuth := httptest.NewRecorder()
		handler.ServeHTTP(recAuth, reqAuth)

		if recAuth.Code != http.StatusFound {
			t.Fatalf("POST /authorize returned %d, want 302 Found: %s", recAuth.Code, recAuth.Body.String())
		}
		loc := recAuth.Header().Get("Location")
		uLoc, _ := url.Parse(loc)
		authCode := uLoc.Query().Get("code")
		if authCode == "" {
			t.Fatalf("missing authorization code in redirect Location: %s", loc)
		}

		// Token exchange via root alias POST /token
		tokenForm := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {"https://gemini.google.com/callback"},
			"client_id":     {clientID},
			"code_verifier": {codeVerifier},
		}
		reqToken := httptest.NewRequest("POST", "/token", strings.NewReader(tokenForm.Encode()))
		reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if clientSecret != "" {
			reqToken.SetBasicAuth(clientID, clientSecret)
		}
		recToken := httptest.NewRecorder()
		handler.ServeHTTP(recToken, reqToken)

		if recToken.Code != http.StatusOK {
			t.Fatalf("POST /token returned %d: %s", recToken.Code, recToken.Body.String())
		}
		var tokResp struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		_ = json.NewDecoder(recToken.Body).Decode(&tokResp)
		if tokResp.AccessToken == "" {
			t.Fatalf("empty access_token received from /token")
		}
		jwtToken = tokResp.AccessToken

		// Verify ES256 JWT claims
		claims, err := auth.VerifyJWT(jwtToken, &jwtPrivKey.PublicKey, cfg.ServiceURL, cfg.ServiceURL+"/mcp")
		if err != nil {
			t.Fatalf("VerifyJWT failed: %v", err)
		}
		if claims.Scopes["github"] != "full_access" || claims.Scopes["jira"] != "full_access" {
			t.Errorf("expected full_access scopes, got: %+v", claims.Scopes)
		}

		// 1.9 GET /dashboard renders badges and #workspace-modal
		reqDash := httptest.NewRequest("GET", "/dashboard", nil)
		reqDash.AddCookie(adminCookie)
		recDash := httptest.NewRecorder()
		handler.ServeHTTP(recDash, reqDash)

		if recDash.Code != http.StatusOK {
			t.Fatalf("GET /dashboard returned %d", recDash.Code)
		}
		dashHTML := recDash.Body.String()
		if !strings.Contains(dashHTML, "aetherise-cloud") {
			t.Errorf("dashboard missing 'aetherise-cloud' org badge")
		}
		if !strings.Contains(dashHTML, "SPARK") {
			t.Errorf("dashboard missing 'SPARK' Jira space badge")
		}
		if !strings.Contains(dashHTML, "workspace-modal") {
			t.Errorf("dashboard missing '#workspace-modal' element")
		}

		t.Log("PASS: Flow 1 - DCR POST /register, Workspaces Discovery, POST /token, and Dashboard Badges validated.")
	})

	// =========================================================================
	// FLOW 2: Hot-Path Scope & Write Guardrails + New Jira Tools
	// =========================================================================
	t.Run("V4_Flow2_GuardrailsAndNewTools", func(t *testing.T) {
		// 2.1 Allowed GitHub PR list
		callAllowedPR := `{
			"jsonrpc": "2.0",
			"id": 201,
			"method": "tools/call",
			"params": {
				"name": "github_list_prs",
				"arguments": {
					"owner": "aetherise-cloud",
					"repo": "spark-mcp-gateway"
				}
			}
		}`
		reqPR1 := httptest.NewRequest("POST", "/mcp", strings.NewReader(callAllowedPR))
		reqPR1.Header.Set("Content-Type", "application/json")
		reqPR1.Header.Set("Authorization", "Bearer "+jwtToken)
		recPR1 := httptest.NewRecorder()
		handler.ServeHTTP(recPR1, reqPR1)

		if recPR1.Code != http.StatusOK {
			t.Fatalf("POST /mcp github_list_prs (allowed) returned %d: %s", recPR1.Code, recPR1.Body.String())
		}
		var rpcPR1 struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		_ = json.NewDecoder(recPR1.Body).Decode(&rpcPR1)
		if rpcPR1.Result.IsError || !strings.Contains(rpcPR1.Result.Content[0].Text, "feat: V4 PR") {
			t.Errorf("expected allowed PR list to succeed, got: %+v", rpcPR1)
		}

		// 2.2 Blocked GitHub PR list (outside SelectedOrgs/AllowedReadRepos)
		callBlockedPR := `{
			"jsonrpc": "2.0",
			"id": 202,
			"method": "tools/call",
			"params": {
				"name": "github_list_prs",
				"arguments": {
					"owner": "evil-org",
					"repo": "secret-repo"
				}
			}
		}`
		reqPR2 := httptest.NewRequest("POST", "/mcp", strings.NewReader(callBlockedPR))
		reqPR2.Header.Set("Content-Type", "application/json")
		reqPR2.Header.Set("Authorization", "Bearer "+jwtToken)
		recPR2 := httptest.NewRecorder()
		handler.ServeHTTP(recPR2, reqPR2)

		var rpcPR2 struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(recPR2.Body).Decode(&rpcPR2)
		outText := ""
		if len(rpcPR2.Result.Content) > 0 {
			outText = rpcPR2.Result.Content[0].Text
		} else if rpcPR2.Error != nil {
			outText = rpcPR2.Error.Message
		}
		if !rpcPR2.Result.IsError && !strings.Contains(outText, "not in allowed GitHub read scope") {
			t.Errorf("expected blocked PR request to fail, got: %s", outText)
		}

		// 2.3 Allowed Jira Create Issue (SPARK)
		callJiraCreate := `{
			"jsonrpc": "2.0",
			"id": 203,
			"method": "tools/call",
			"params": {
				"name": "jira_create_issue",
				"arguments": {
					"project_key": "SPARK",
					"summary": "Implement V4 Feature"
				}
			}
		}`
		reqJiraCreate := httptest.NewRequest("POST", "/mcp", strings.NewReader(callJiraCreate))
		reqJiraCreate.Header.Set("Content-Type", "application/json")
		reqJiraCreate.Header.Set("Authorization", "Bearer "+jwtToken)
		recJiraCreate := httptest.NewRecorder()
		handler.ServeHTTP(recJiraCreate, reqJiraCreate)

		var rpcJiraCreate struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		_ = json.NewDecoder(recJiraCreate.Body).Decode(&rpcJiraCreate)
		if rpcJiraCreate.Result.IsError || !strings.Contains(rpcJiraCreate.Result.Content[0].Text, "SPARK-101") {
			t.Errorf("expected jira_create_issue to succeed, got: %+v", rpcJiraCreate)
		}

		// 2.4 Allowed Jira Search Issues (SPARK)
		callJiraSearch := `{
			"jsonrpc": "2.0",
			"id": 204,
			"method": "tools/call",
			"params": {
				"name": "jira_search_issues",
				"arguments": {
					"project_key": "SPARK"
				}
			}
		}`
		reqJiraSearch := httptest.NewRequest("POST", "/mcp", strings.NewReader(callJiraSearch))
		reqJiraSearch.Header.Set("Content-Type", "application/json")
		reqJiraSearch.Header.Set("Authorization", "Bearer "+jwtToken)
		recJiraSearch := httptest.NewRecorder()
		handler.ServeHTTP(recJiraSearch, reqJiraSearch)

		var rpcJiraSearch struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		_ = json.NewDecoder(recJiraSearch.Body).Decode(&rpcJiraSearch)
		if rpcJiraSearch.Result.IsError || !strings.Contains(rpcJiraSearch.Result.Content[0].Text, "SPARK-101") {
			t.Errorf("expected jira_search_issues to succeed, got: %+v", rpcJiraSearch)
		}

		// 2.5 Blocked Jira Get Issue (FORBIDDEN-1)
		callJiraBlock := `{
			"jsonrpc": "2.0",
			"id": 205,
			"method": "tools/call",
			"params": {
				"name": "jira_get_issue",
				"arguments": {
					"issue_key": "FORBIDDEN-1"
				}
			}
		}`
		reqJiraBlock := httptest.NewRequest("POST", "/mcp", strings.NewReader(callJiraBlock))
		reqJiraBlock.Header.Set("Content-Type", "application/json")
		reqJiraBlock.Header.Set("Authorization", "Bearer "+jwtToken)
		recJiraBlock := httptest.NewRecorder()
		handler.ServeHTTP(recJiraBlock, reqJiraBlock)

		var rpcJiraBlock struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(recJiraBlock.Body).Decode(&rpcJiraBlock)
		jiraErr := ""
		if len(rpcJiraBlock.Result.Content) > 0 {
			jiraErr = rpcJiraBlock.Result.Content[0].Text
		} else if rpcJiraBlock.Error != nil {
			jiraErr = rpcJiraBlock.Error.Message
		}
		if !rpcJiraBlock.Result.IsError && !strings.Contains(jiraErr, "not in allowed_space_keys") {
			t.Errorf("expected FORBIDDEN-1 to be blocked, got: %s", jiraErr)
		}

		// 2.6 GCP Cloud Run Redaction
		callCloudRun := `{
			"jsonrpc": "2.0",
			"id": 206,
			"method": "tools/call",
			"params": {
				"name": "gcp_get_cloudrun_service",
				"arguments": {
					"service_name": "spark-gateway"
				}
			}
		}`
		reqCR := httptest.NewRequest("POST", "/mcp", strings.NewReader(callCloudRun))
		reqCR.Header.Set("Content-Type", "application/json")
		reqCR.Header.Set("Authorization", "Bearer "+jwtToken)
		recCR := httptest.NewRecorder()
		handler.ServeHTTP(recCR, reqCR)

		if recCR.Code != http.StatusOK {
			t.Fatalf("POST /mcp gcp_get_cloudrun_service returned %d: %s", recCR.Code, recCR.Body.String())
		}
		var rpcCR struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		_ = json.NewDecoder(recCR.Body).Decode(&rpcCR)
		crText := rpcCR.Result.Content[0].Text

		if !strings.Contains(crText, "spark-gateway") {
			t.Errorf("cloud run output missing service name: %s", crText)
		}
		sensitiveTokens := []string{
			"super-secret-password-123",
			"secret-api-key-xyz",
			"db-secret",
			"secret-volume",
			"tls.key",
		}
		for _, token := range sensitiveTokens {
			if strings.Contains(crText, token) {
				t.Errorf("leak detected! output contains sensitive token %q", token)
			}
		}

		t.Log("PASS: Flow 2 - Scope guardrails for GitHub/Jira and Cloud Run secret redaction verified.")
	})

	// =========================================================================
	// FLOW 3: Anti-503 JSON-RPC Middleware, 401 Auto-Refresh & Clickable Re-Auth
	// =========================================================================
	t.Run("V4_Flow3_Anti503AndAuthErrors", func(t *testing.T) {
		// 3.1 Unauthenticated POST /mcp returns HTTP 401 with WWW-Authenticate & JSON-RPC 2.0 error -32001
		unauthReq := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":301,"method":"tools/list"}`))
		unauthReq.Header.Set("Content-Type", "application/json")
		recUnauth := httptest.NewRecorder()
		handler.ServeHTTP(recUnauth, unauthReq)

		if recUnauth.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for unauth /mcp, got %d", recUnauth.Code)
		}
		wwwAuth := recUnauth.Header().Get("WWW-Authenticate")
		if !strings.Contains(wwwAuth, "Bearer resource_metadata=") {
			t.Errorf("expected WWW-Authenticate header with resource_metadata, got %q", wwwAuth)
		}
		var unauthResp struct {
			JSONRPC string `json:"jsonrpc"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(recUnauth.Body).Decode(&unauthResp)
		if unauthResp.JSONRPC != "2.0" || unauthResp.Error.Code != -32001 {
			t.Errorf("expected JSON-RPC 2.0 error code -32001, got %+v", unauthResp)
		}

		// 3.2 Simulated 503 downstream failure wrapped by JSONErrorMiddleware returns HTTP 503 JSON-RPC code -32003
		coldReq := httptest.NewRequest("POST", "/mcp/simulate-coldstart", strings.NewReader(`{"jsonrpc":"2.0","id":302,"method":"tools/list"}`))
		coldReq.Header.Set("Content-Type", "application/json")
		coldReq.Header.Set("Accept", "application/json")
		recCold := httptest.NewRecorder()
		handler.ServeHTTP(recCold, coldReq)

		if recCold.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable, got %d", recCold.Code)
		}
		if !strings.Contains(recCold.Header().Get("Content-Type"), "application/json") {
			t.Errorf("expected application/json Content-Type, got %q", recCold.Header().Get("Content-Type"))
		}
		var coldResp struct {
			JSONRPC string `json:"jsonrpc"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(recCold.Body).Decode(&coldResp)
		if coldResp.JSONRPC != "2.0" || coldResp.Error.Code != -32003 {
			t.Errorf("expected JSON-RPC 2.0 error code -32003, got %+v", coldResp)
		}
		if !strings.Contains(coldResp.Error.Message, "Upstream service temporarily unavailable or cold-starting") {
			t.Errorf("unexpected error message: %s", coldResp.Error.Message)
		}

		// 3.3 Panic recovery to JSON-RPC 503
		panicReq := httptest.NewRequest("POST", "/mcp/simulate-panic", strings.NewReader(`{"jsonrpc":"2.0","id":303,"method":"tools/list"}`))
		panicReq.Header.Set("Content-Type", "application/json")
		recPanic := httptest.NewRecorder()
		handler.ServeHTTP(recPanic, panicReq)

		if recPanic.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 from recovered panic, got %d", recPanic.Code)
		}
		var panicResp struct {
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(recPanic.Body).Decode(&panicResp)
		if panicResp.Error.Code != -32003 {
			t.Errorf("expected code -32003 from panic recovery, got %+v", panicResp)
		}

		t.Log("PASS: Flow 3 - Anti-503 JSON-RPC Middleware, WWW-Authenticate header, and panic recovery validated.")
	})
}