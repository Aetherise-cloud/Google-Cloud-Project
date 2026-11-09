package oauthbroker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"spark-mcp-gateway/internal/auth"
	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/providers"
	"spark-mcp-gateway/internal/store"
	"spark-mcp-gateway/internal/ui"
	"spark-mcp-gateway/internal/vault"
)

var slugRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,30}$`)

// Broker handles upstream 3LO OAuth authorization broker handshakes (GitHub & Jira) and Custom Connectors.
type Broker struct {
	cfg        *config.Config
	store      store.Store
	vault      *vault.TokenVault
	session    *auth.SessionManager
	httpClient *http.Client

	AllowLoopbackForTest bool

	// Optional base URLs for testing with httptest
	GitHubOAuthURL    string
	GitHubAPIURL      string
	AtlassianAuthURL  string
	AtlassianTokenURL string
	AtlassianAPIURL   string
}

// NewBroker creates a new OAuth broker instance.
func NewBroker(cfg *config.Config, s store.Store, v *vault.TokenVault, sm *auth.SessionManager, httpClient *http.Client) *Broker {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Broker{
		cfg:               cfg,
		store:             s,
		vault:             v,
		session:           sm,
		httpClient:        httpClient,
		GitHubOAuthURL:    "https://github.com/login/oauth",
		GitHubAPIURL:      "https://api.github.com",
		AtlassianAuthURL:  "https://auth.atlassian.com/authorize",
		AtlassianTokenURL: "https://auth.atlassian.com/oauth/token",
		AtlassianAPIURL:   "https://api.atlassian.com",
	}
}

// RegisterRoutes registers broker routes onto an http.ServeMux.
func (b *Broker) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /dashboard", b.handleDashboard)
	mux.HandleFunc("GET /oauth/connect/{app}", b.handleConnect)
	mux.HandleFunc("GET /oauth/callback/{app}", b.handleCallback)
	mux.HandleFunc("POST /api/connections/{app}/disconnect", b.handleDisconnect)
	mux.HandleFunc("GET /api/connections", b.handleListConnections)

	// Dynamic KMS-encrypted OAuth config, GitHub PAT, and Custom Connector endpoints
	mux.HandleFunc("POST /api/connectors/{app}/oauth-config", b.handleOAuthConfig)
	mux.HandleFunc("POST /api/connectors/github/pat", b.handleGitHubPAT)
	mux.HandleFunc("POST /api/connectors/custom", b.handleCustomConnector)

	// V4 Workspace Discovery & Persistence endpoints
	mux.HandleFunc("GET /api/connectors/github/workspaces", b.handleGitHubWorkspaces)
	mux.HandleFunc("GET /api/connectors/jira/workspaces", b.handleJiraWorkspaces)
	mux.HandleFunc("POST /api/connectors/workspaces", b.handleSaveWorkspaces)
	mux.HandleFunc("GET /api/catalog/templates", b.handleCatalogTemplates)
}

// ResolveOAuthCredentials resolves OAuth Client ID and Secret from TokenVault (__oauth_app_config__) with fallback to env.
func (b *Broker) ResolveOAuthCredentials(ctx context.Context, app string) (clientID, clientSecret, allowedWriteRepos string) {
	return b.resolveOAuthCredentials(ctx, app)
}

func (b *Broker) resolveOAuthCredentials(ctx context.Context, app string) (string, string, string) {
	if b.store != nil && b.vault != nil {
		conn, err := b.store.GetConnection(ctx, "__oauth_app_config__", app)
		if err == nil && conn != nil {
			tok, err := b.vault.DecryptConnection(ctx, conn)
			if err == nil && tok != nil && tok.OAuthClientID != "" && tok.OAuthClientSecret != "" {
				return tok.OAuthClientID, tok.OAuthClientSecret, tok.AllowedWriteRepos
			}
		}
	}

	if app == "github" {
		return b.cfg.GitHubOAuthClientID, b.cfg.GitHubOAuthClientSecret, strings.Join(b.cfg.GitHubAllowedWriteRepos, ",")
	}
	if app == "jira" {
		return b.cfg.JiraOAuthClientID, b.cfg.JiraOAuthClientSecret, ""
	}
	return "", "", ""
}

// GET /dashboard
func (b *Broker) handleDashboard(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		http.Redirect(w, r, "/auth/login?return_to=/dashboard", http.StatusFound)
		return
	}

	csrfToken := b.session.GenerateCSRFToken(adminEmail)
	flashMsg := r.URL.Query().Get("flash")

	// Query active connections from TokenVault / Store
	connectors := []ui.ConnectorView{
		b.buildConnectorView(r.Context(), adminEmail, "github", "GitHub", "Pull requests, code browsing, and issue creation"),
		b.buildConnectorView(r.Context(), adminEmail, "jira", "Atlassian Jira", "Issue inspection and status transitions"),
		{
			ID:            "gcp",
			Name:          "Google Cloud Platform (GCP MCP)",
			Description:   "Read-only Cloud Run, Logging, Storage, Artifact Registry, Monitoring & IAM via keyless ADC",
			Connected:     true,
			KeylessADC:    true,
			ConnectorType: "keyless_adc",
			OAuthConfigOK: true,
			TemplateID:    "gcp",
			ScopeMode:     "read_only",
			AccountLabel:  fmt.Sprintf("%s (Keyless ADC)", b.cfg.GCPProjectID),
		},
		{
			ID:            "gdk",
			Name:          "Google Developer Knowledge",
			Description:   "Developer Knowledge documentation search via keyless ADC",
			Connected:     true,
			KeylessADC:    true,
			ConnectorType: "keyless_adc",
			OAuthConfigOK: true,
			TemplateID:    "gdk",
			ScopeMode:     "read_only",
			AccountLabel:  fmt.Sprintf("%s (Keyless ADC)", b.cfg.GCPProjectID),
		},
		func() ui.ConnectorView {
			gflowView := ui.ConnectorView{
				ID:            "gflow",
				Name:          "Google Flow (gflow MCP)",
				Description:   "AI image (Nano Banana / Imagen) & video (Veo) generation, upscaling & character catalog",
				Connected:     true,
				KeylessADC:    true,
				ConnectorType: "keyless_adc",
				OAuthConfigOK: true,
				TemplateID:    "gflow",
				ScopeMode:     "full_access",
				AccountLabel:  fmt.Sprintf("%s (Keyless ADC + Flow)", b.cfg.GCPProjectID),
			}
			if conn, err := b.store.GetConnection(r.Context(), adminEmail, "gflow"); err == nil && conn != nil {
				if tok, err := b.vault.DecryptConnection(r.Context(), conn); err == nil && tok != nil {
					if tok.EndpointURL != "" {
						gflowView.EndpointURL = tok.EndpointURL
						gflowView.ConnectorType = "remote_mcp"
					}
					if tok.AccountLabel != "" {
						gflowView.AccountLabel = tok.AccountLabel
					}
					if tok.Scope != "" {
						gflowView.ScopeMode = tok.Scope
					}
				}
			}
			return gflowView
		}(),
		func() ui.ConnectorView {
			notionConnected := b.cfg.NotionAPIToken != ""
			accountLabel := ""
			scopeMode := "full_access"
			if notionConnected {
				accountLabel = "Secret Manager (NOTION_API_TOKEN)"
			}
			notionView := ui.ConnectorView{
				ID:            "notion",
				Name:          "Notion",
				Description:   "Workspaces, databases, and pages via Notion API",
				Connected:     notionConnected,
				KeylessADC:    b.cfg.NotionAPIToken != "",
				ConnectorType: "rest_api",
				OAuthConfigOK: true,
				TemplateID:    "notion",
				ScopeMode:     scopeMode,
				AccountLabel:  accountLabel,
			}
			if conn, err := b.store.GetConnection(r.Context(), adminEmail, "notion"); err == nil && conn != nil {
				if tok, err := b.vault.DecryptConnection(r.Context(), conn); err == nil && tok != nil {
					notionView.Connected = true
					if tok.AccountLabel != "" {
						notionView.AccountLabel = tok.AccountLabel
					}
					if tok.Scope != "" {
						notionView.ScopeMode = tok.Scope
					}
					if !conn.UpdatedAt.IsZero() {
						notionView.UpdatedAt = conn.UpdatedAt.Format("2006-01-02 15:04:05")
					}
				}
			}
			return notionView
		}(),
	}

	// Add custom connectors registered for this admin
	if conns, err := b.store.ListConnections(r.Context(), adminEmail); err == nil {
		for _, conn := range conns {
			if strings.HasPrefix(conn.Provider, "custom:") {
				tok, err := b.vault.DecryptConnection(r.Context(), conn)
				if err == nil && tok != nil {
					updatedAtStr := ""
					if !conn.UpdatedAt.IsZero() {
						updatedAtStr = conn.UpdatedAt.Format("2006-01-02 15:04:05")
					}
					connectors = append(connectors, ui.ConnectorView{
						ID:            conn.Provider,
						Name:          tok.ConnectorName,
						Description:   tok.Description,
						Connected:     true,
						IsCustom:      true,
						ConnectorType: tok.ConnectorType,
						OAuthConfigOK: true,
						EndpointURL:   tok.EndpointURL,
						ScopeMode:     tok.Scope,
						AccountLabel:  tok.AccountLabel,
						TemplateID:    tok.TemplateID,
						UpdatedAt:     updatedAtStr,
					})
				}
			}
		}
	}

	pageData := ui.DashboardPageData{
		AdminEmail:   adminEmail,
		ServiceURL:   b.cfg.ServiceURL,
		MCPEndpoint:  b.cfg.ServiceURL + "/mcp",
		CSRFToken:    csrfToken,
		Connectors:   connectors,
		FlashMessage: flashMsg,
	}

	_ = ui.RenderDashboard(w, http.StatusOK, pageData)
}

func (b *Broker) buildConnectorView(ctx context.Context, adminEmail, id, name, desc string) ui.ConnectorView {
	clientID, _, _ := b.resolveOAuthCredentials(ctx, id)
	view := ui.ConnectorView{
		ID:            id,
		Name:          name,
		Description:   desc,
		Connected:     false,
		ConnectorType: "oauth2",
		TemplateID:    id,
		OAuthConfigOK: clientID != "",
	}

	conn, err := b.store.GetConnection(ctx, adminEmail, id)
	if err == nil && conn != nil {
		token, err := b.vault.DecryptConnection(ctx, conn)
		if err == nil && token != nil {
			view.Connected = true
			if token.ConnectorType != "" {
				view.ConnectorType = token.ConnectorType
			}
			view.ScopeMode = token.Scope
			if view.ScopeMode == "" {
				view.ScopeMode = "read_only"
			}
			view.AccountLabel = token.AccountLabel
			view.SelectedOrgs = token.SelectedOrgs
			view.AllowedReadRepos = token.AllowedReadRepos
			view.AllowedWriteRepos = splitCSV(token.AllowedWriteRepos)
			view.AllowedSpaceKeys = token.AllowedSpaceKeys
			view.SiteName = token.SiteName
			view.CloudID = token.CloudID
			if !conn.UpdatedAt.IsZero() {
				view.UpdatedAt = conn.UpdatedAt.Format("2006-01-02 15:04:05")
			}
		}
	}

	view.NeedsConfig = !view.Connected && clientID == ""
	return view
}

// GET /oauth/connect/{app}?mode=read_only|full_access
func (b *Broker) handleConnect(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}

	app := strings.ToLower(r.PathValue("app"))
	if app != "github" && app != "jira" {
		http.Error(w, "unknown connector application", http.StatusNotFound)
		return
	}

	clientID, _, _ := b.resolveOAuthCredentials(r.Context(), app)
	if clientID == "" {
		http.Error(w, fmt.Sprintf("%s OAuth is not configured on this server. Please configure Client ID and Secret in Dashboard.", strings.ToUpper(app[:1])+app[1:]), http.StatusServiceUnavailable)
		return
	}

	mode := strings.ToLower(r.URL.Query().Get("mode"))
	if mode != "full_access" {
		mode = "read_only"
	}

	stateBytes := make([]byte, 24)
	_, _ = rand.Read(stateBytes)
	stateStr := hex.EncodeToString(stateBytes)

	oauthState := &store.OAuthState{
		State:      stateStr,
		Provider:   app,
		Mode:       mode,
		AdminEmail: adminEmail,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(10 * time.Minute),
	}

	callbackURI := fmt.Sprintf("%s/oauth/callback/%s", b.cfg.ServiceURL, app)

	if app == "github" {
		scopes := "read:user,repo:status,public_repo"
		if mode == "full_access" {
			scopes = "read:user,repo"
		}
		_ = b.store.SaveOAuthState(r.Context(), oauthState)

		u := fmt.Sprintf("%s/authorize?client_id=%s&redirect_uri=%s&state=%s&scope=%s",
			b.GitHubOAuthURL,
			url.QueryEscape(clientID),
			url.QueryEscape(callbackURI),
			url.QueryEscape(stateStr),
			url.QueryEscape(scopes),
		)
		http.Redirect(w, r, u, http.StatusFound)
		return
	}

	if app == "jira" {
		verifierBytes := make([]byte, 32)
		_, _ = rand.Read(verifierBytes)
		verifier := hex.EncodeToString(verifierBytes)
		challenge := auth.ComputePKCES256(verifier)

		oauthState.CodeVerifier = verifier
		_ = b.store.SaveOAuthState(r.Context(), oauthState)

		scopes := "read:jira-work read:jira-user offline_access"
		if mode == "full_access" {
			scopes = "read:jira-work write:jira-work read:jira-user offline_access"
		}

		u := fmt.Sprintf("%s?audience=api.atlassian.com&client_id=%s&scope=%s&redirect_uri=%s&state=%s&response_type=code&prompt=consent&code_challenge=%s&code_challenge_method=S256",
			b.AtlassianAuthURL,
			url.QueryEscape(clientID),
			url.QueryEscape(scopes),
			url.QueryEscape(callbackURI),
			url.QueryEscape(stateStr),
			url.QueryEscape(challenge),
		)
		http.Redirect(w, r, u, http.StatusFound)
		return
	}
}

// GET /oauth/callback/{app}
func (b *Broker) handleCallback(w http.ResponseWriter, r *http.Request) {
	app := strings.ToLower(r.PathValue("app"))
	stateParam := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		_ = ui.RenderOAuthCallback(w, http.StatusOK, ui.CallbackPageData{
			Provider:     app,
			ProviderName: strings.ToUpper(app),
			Success:      false,
			ErrorMessage: "OAuth access was denied by user",
		})
		return
	}

	oauthState, err := b.store.GetAndConsumeOAuthState(r.Context(), stateParam)
	if err != nil || oauthState.Provider != app {
		_ = ui.RenderOAuthCallback(w, http.StatusBadRequest, ui.CallbackPageData{
			Provider:     app,
			ProviderName: strings.ToUpper(app),
			Success:      false,
			ErrorMessage: "Invalid or expired OAuth state parameter",
		})
		return
	}

	var tokenData *vault.TokenData
	if app == "github" {
		tokenData, err = b.exchangeGitHubCode(r.Context(), code, oauthState.Mode)
	} else if app == "jira" {
		tokenData, err = b.exchangeJiraCode(r.Context(), code, oauthState.CodeVerifier, oauthState.Mode)
	}

	if err != nil {
		_ = ui.RenderOAuthCallback(w, http.StatusOK, ui.CallbackPageData{
			Provider:     app,
			ProviderName: strings.ToUpper(app),
			Success:      false,
			ErrorMessage: fmt.Sprintf("Token exchange failed: %v", err),
		})
		return
	}

	if err := b.vault.StoreToken(r.Context(), oauthState.AdminEmail, app, tokenData); err != nil {
		_ = ui.RenderOAuthCallback(w, http.StatusInternalServerError, ui.CallbackPageData{
			Provider:     app,
			ProviderName: strings.ToUpper(app),
			Success:      false,
			ErrorMessage: "Failed securely saving credentials to vault",
		})
		return
	}

	_ = ui.RenderOAuthCallback(w, http.StatusOK, ui.CallbackPageData{
		Provider:     app,
		ProviderName: strings.ToUpper(app),
		ScopeMode:    oauthState.Mode,
		Success:      true,
	})
}

func (b *Broker) exchangeGitHubCode(ctx context.Context, code, mode string) (*vault.TokenData, error) {
	clientID, clientSecret, allowedWriteRepos := b.resolveOAuthCredentials(ctx, "github")
	callbackURI := fmt.Sprintf("%s/oauth/callback/github", b.cfg.ServiceURL)
	payload := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"redirect_uri":  {callbackURI},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", b.GitHubOAuthURL+"/access_token", strings.NewReader(payload.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return nil, err
	}
	if tokenRes.Error != "" || tokenRes.AccessToken == "" {
		return nil, fmt.Errorf("github error: %s", tokenRes.Error)
	}

	accountLabel := "GitHub Account"
	userReq, err := http.NewRequestWithContext(ctx, "GET", b.GitHubAPIURL+"/user", nil)
	if err == nil {
		userReq.Header.Set("Authorization", "Bearer "+tokenRes.AccessToken)
		userReq.Header.Set("User-Agent", "spark-mcp-gateway/3.0")
		if userResp, err := b.httpClient.Do(userReq); err == nil {
			defer userResp.Body.Close()
			var userObj struct {
				Login string `json:"login"`
			}
			if err := json.NewDecoder(userResp.Body).Decode(&userObj); err == nil && userObj.Login != "" {
				accountLabel = "@" + userObj.Login
			}
		}
	}

	return &vault.TokenData{
		AccessToken:       tokenRes.AccessToken,
		ConnectorType:     "oauth2",
		ExpiresAt:         time.Time{}, // Non-expiring classic
		Scope:             mode,
		AccountLabel:      accountLabel,
		AllowedWriteRepos: allowedWriteRepos,
		UpdatedAt:         time.Now(),
	}, nil
}

func (b *Broker) exchangeJiraCode(ctx context.Context, code, verifier, mode string) (*vault.TokenData, error) {
	clientID, clientSecret, _ := b.resolveOAuthCredentials(ctx, "jira")
	callbackURI := fmt.Sprintf("%s/oauth/callback/jira", b.cfg.ServiceURL)
	payload := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
		"redirect_uri":  callbackURI,
		"code_verifier": verifier,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", b.AtlassianTokenURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenRes struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return nil, err
	}
	if tokenRes.Error != "" || tokenRes.AccessToken == "" {
		return nil, fmt.Errorf("atlassian error: %s", tokenRes.Error)
	}

	cloudID := ""
	siteURL := ""
	siteName := ""
	accountLabel := "Atlassian Jira"

	resReq, err := http.NewRequestWithContext(ctx, "GET", b.AtlassianAPIURL+"/oauth/token/accessible-resources", nil)
	if err == nil {
		resReq.Header.Set("Authorization", "Bearer "+tokenRes.AccessToken)
		resReq.Header.Set("Accept", "application/json")
		if resResp, err := b.httpClient.Do(resReq); err == nil {
			defer resResp.Body.Close()
			var resources []struct {
				ID   string `json:"id"`
				URL  string `json:"url"`
				Name string `json:"name"`
			}
			if err := json.NewDecoder(resResp.Body).Decode(&resources); err == nil && len(resources) > 0 {
				cloudID = resources[0].ID
				siteURL = resources[0].URL
				siteName = resources[0].Name
				accountLabel = fmt.Sprintf("%s (%s)", resources[0].Name, resources[0].URL)
			}
		}
	}

	if cloudID == "" {
		return nil, errors.New("no accessible Jira sites found for user account")
	}

	// Best-effort call to project search to discover and bind default allowed spaces
	var allowedSpaceKeys []string
	projReq, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/ex/jira/%s/rest/api/3/project/search", b.AtlassianAPIURL, cloudID), nil)
	if err == nil {
		projReq.Header.Set("Authorization", "Bearer "+tokenRes.AccessToken)
		projReq.Header.Set("Accept", "application/json")
		if projResp, err := b.httpClient.Do(projReq); err == nil {
			defer projResp.Body.Close()
			if projResp.StatusCode == http.StatusOK {
				bodyBytes, _ := io.ReadAll(projResp.Body)
				var searchRes struct {
					Values []struct {
						Key string `json:"key"`
					} `json:"values"`
				}
				if err := json.Unmarshal(bodyBytes, &searchRes); err == nil && len(searchRes.Values) > 0 {
					for _, v := range searchRes.Values {
						if v.Key != "" {
							allowedSpaceKeys = append(allowedSpaceKeys, v.Key)
						}
					}
				} else {
					var rawList []struct {
						Key string `json:"key"`
					}
					if err := json.Unmarshal(bodyBytes, &rawList); err == nil && len(rawList) > 0 {
						for _, v := range rawList {
							if v.Key != "" {
								allowedSpaceKeys = append(allowedSpaceKeys, v.Key)
							}
						}
					}
				}
			}
		}
	}

	expiresAt := time.Now().Add(time.Duration(tokenRes.ExpiresIn) * time.Second)

	return &vault.TokenData{
		AccessToken:      tokenRes.AccessToken,
		RefreshToken:     tokenRes.RefreshToken,
		ConnectorType:    "oauth2",
		ExpiresAt:        expiresAt,
		Scope:            mode,
		CloudID:          cloudID,
		SiteURL:          siteURL,
		SiteName:         siteName,
		AccountLabel:     accountLabel,
		AllowedSpaceKeys: allowedSpaceKeys,
		UpdatedAt:        time.Now(),
	}, nil
}

// POST /api/connectors/{app}/oauth-config
func (b *Broker) handleOAuthConfig(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "unauthorized",
			"error_description": "Admin session required",
		})
		return
	}

	app := strings.ToLower(r.PathValue("app"))
	if app != "github" && app != "jira" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "unknown_connector",
			"error_description": fmt.Sprintf("Unknown connector %q: must be github or jira", app),
		})
		return
	}

	var clientID, clientSecret, allowedRepos, csrf string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			ClientID          string `json:"client_id"`
			ClientSecret      string `json:"client_secret"`
			AllowedWriteRepos string `json:"allowed_write_repos"`
			CSRFToken         string `json:"csrf_token"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req)
		clientID = strings.TrimSpace(req.ClientID)
		clientSecret = strings.TrimSpace(req.ClientSecret)
		allowedRepos = strings.TrimSpace(req.AllowedWriteRepos)
		csrf = req.CSRFToken
	} else {
		_ = r.ParseForm()
		clientID = strings.TrimSpace(r.FormValue("client_id"))
		clientSecret = strings.TrimSpace(r.FormValue("client_secret"))
		allowedRepos = strings.TrimSpace(r.FormValue("allowed_write_repos"))
		csrf = r.FormValue("csrf_token")
	}

	if csrf == "" {
		csrf = r.Header.Get("X-CSRF-Token")
	}
	if !b.session.ValidateCSRFToken(csrf, adminEmail) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_csrf",
			"error_description": "CSRF token validation failed",
		})
		return
	}

	if clientID == "" || clientSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_credentials",
			"error_description": "client_id and client_secret are required",
		})
		return
	}

	cfgData := &vault.TokenData{
		OAuthClientID:     clientID,
		OAuthClientSecret: clientSecret,
		AllowedWriteRepos: allowedRepos,
		ConnectorType:     "oauth2",
		UpdatedAt:         time.Now(),
	}

	if err := b.vault.StoreToken(r.Context(), "__oauth_app_config__", app, cfgData); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": fmt.Sprintf("Failed saving encrypted credentials to vault: %v", err),
		})
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/dashboard?flash=OAuth+configuration+saved+for+%s", app), http.StatusSeeOther)
}

// POST /api/connectors/github/pat
func (b *Broker) handleGitHubPAT(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "unauthorized",
			"error_description": "Admin session required",
		})
		return
	}

	var pat, scopeMode, csrf string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			AccessToken string `json:"access_token"`
			PAT         string `json:"pat"`
			ScopeMode   string `json:"scope_mode"`
			CSRFToken   string `json:"csrf_token"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req)
		pat = strings.TrimSpace(req.AccessToken)
		if pat == "" {
			pat = strings.TrimSpace(req.PAT)
		}
		scopeMode = req.ScopeMode
		csrf = req.CSRFToken
	} else {
		_ = r.ParseForm()
		pat = strings.TrimSpace(r.FormValue("access_token"))
		if pat == "" {
			pat = strings.TrimSpace(r.FormValue("pat"))
		}
		scopeMode = r.FormValue("scope_mode")
		csrf = r.FormValue("csrf_token")
	}

	if csrf == "" {
		csrf = r.Header.Get("X-CSRF-Token")
	}
	if !b.session.ValidateCSRFToken(csrf, adminEmail) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_csrf",
			"error_description": "CSRF token validation failed",
		})
		return
	}

	if pat == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "access_token is required",
		})
		return
	}
	if scopeMode != "full_access" {
		scopeMode = "read_only"
	}

	userReq, err := http.NewRequestWithContext(r.Context(), "GET", b.GitHubAPIURL+"/user", nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": fmt.Sprintf("Failed creating GitHub validation request: %v", err),
		})
		return
	}
	userReq.Header.Set("Authorization", "Bearer "+pat)
	userReq.Header.Set("User-Agent", "spark-mcp-gateway/3.0")

	userResp, err := b.httpClient.Do(userReq)
	if err != nil || userResp.StatusCode != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		statusDesc := "network error"
		if userResp != nil {
			statusDesc = fmt.Sprintf("GitHub API returned HTTP %d", userResp.StatusCode)
		} else if err != nil {
			statusDesc = err.Error()
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_pat",
			"error_description": fmt.Sprintf("Failed validating GitHub Personal Access Token (%s)", statusDesc),
		})
		return
	}
	defer userResp.Body.Close()

	var userObj struct {
		Login string `json:"login"`
	}
	_ = json.NewDecoder(userResp.Body).Decode(&userObj)
	login := userObj.Login
	if login == "" {
		login = "github-user"
	}
	accountLabel := "@" + login

	_, _, allowedWriteRepos := b.resolveOAuthCredentials(r.Context(), "github")

	patData := &vault.TokenData{
		AccessToken:       pat,
		TokenType:         "pat",
		ConnectorType:     "pat",
		Scope:             scopeMode,
		AccountLabel:      accountLabel,
		AllowedWriteRepos: allowedWriteRepos,
		UpdatedAt:         time.Now(),
	}

	if err := b.vault.StoreToken(r.Context(), adminEmail, "github", patData); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": fmt.Sprintf("Failed saving encrypted credentials to vault: %v", err),
		})
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "account_label": accountLabel})
		return
	}

	http.Redirect(w, r, "/dashboard?flash=GitHub+connected+via+Personal+Access+Token", http.StatusSeeOther)
}

// POST /api/connectors/custom
func (b *Broker) handleCustomConnector(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "unauthorized",
			"error_description": "Admin session required",
		})
		return
	}

	var slug, name, desc, connType, templateID, endpointURL, token, authHeader, scopeMode, csrf string
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			Slug          string `json:"slug"`
			Name          string `json:"name"`
			Description   string `json:"description"`
			ConnectorType string `json:"connector_type"`
			TemplateID    string `json:"template_id"`
			EndpointURL   string `json:"endpoint_url"`
			AccessToken   string `json:"access_token"`
			AuthToken     string `json:"auth_token"`
			AuthHeader    string `json:"auth_header"`
			ScopeMode     string `json:"scope_mode"`
			CSRFToken     string `json:"csrf_token"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&req)
		slug = strings.TrimSpace(strings.ToLower(req.Slug))
		name = strings.TrimSpace(req.Name)
		desc = strings.TrimSpace(req.Description)
		connType = strings.TrimSpace(req.ConnectorType)
		templateID = strings.TrimSpace(req.TemplateID)
		endpointURL = strings.TrimSpace(req.EndpointURL)
		token = strings.TrimSpace(req.AccessToken)
		if token == "" {
			token = strings.TrimSpace(req.AuthToken)
		}
		authHeader = strings.TrimSpace(req.AuthHeader)
		scopeMode = strings.TrimSpace(req.ScopeMode)
		csrf = req.CSRFToken
	} else {
		_ = r.ParseForm()
		slug = strings.TrimSpace(strings.ToLower(r.FormValue("slug")))
		name = strings.TrimSpace(r.FormValue("name"))
		desc = strings.TrimSpace(r.FormValue("description"))
		connType = strings.TrimSpace(r.FormValue("connector_type"))
		templateID = strings.TrimSpace(r.FormValue("template_id"))
		endpointURL = strings.TrimSpace(r.FormValue("endpoint_url"))
		token = strings.TrimSpace(r.FormValue("access_token"))
		if token == "" {
			token = strings.TrimSpace(r.FormValue("auth_token"))
		}
		authHeader = strings.TrimSpace(r.FormValue("auth_header"))
		scopeMode = strings.TrimSpace(r.FormValue("scope_mode"))
		csrf = r.FormValue("csrf_token")
	}

	if csrf == "" {
		csrf = r.Header.Get("X-CSRF-Token")
	}
	if !b.session.ValidateCSRFToken(csrf, adminEmail) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_csrf",
			"error_description": "CSRF token validation failed",
		})
		return
	}

	if !slugRegex.MatchString(slug) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_slug",
			"error_description": "slug must be 2-30 alphanumeric characters",
		})
		return
	}

	if name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "name is required",
		})
		return
	}

	if connType != "remote_mcp" && connType != "rest_api" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_connector_type",
			"error_description": "connector_type must be 'remote_mcp' or 'rest_api'",
		})
		return
	}

	// SSRF protection
	if err := providers.ValidateUpstreamURLWithTestOption(endpointURL, b.AllowLoopbackForTest); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_endpoint_url",
			"error_description": err.Error(),
		})
		return
	}

	if authHeader == "" {
		authHeader = "Authorization"
	}
	if scopeMode != "full_access" {
		scopeMode = "read_only"
	}
	if templateID == "" {
		templateID = "custom_mcp"
		if connType == "rest_api" {
			templateID = "custom_api"
		}
	}

	customData := &vault.TokenData{
		ConnectorName: name,
		Description:   desc,
		ConnectorType: connType,
		TemplateID:    templateID,
		EndpointURL:   endpointURL,
		AccessToken:   token,
		AuthHeader:    authHeader,
		Scope:         scopeMode,
		AccountLabel:  endpointURL,
		UpdatedAt:     time.Now(),
	}

	providerKey := "custom:" + slug
	if err := b.vault.StoreToken(r.Context(), adminEmail, providerKey, customData); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": fmt.Sprintf("Failed saving encrypted credentials to vault: %v", err),
		})
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "id": providerKey})
		return
	}

	http.Redirect(w, r, "/dashboard?flash=Custom+connector+added+successfully", http.StatusSeeOther)
}

// POST /api/connections/{app}/disconnect
func (b *Broker) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	app := strings.ToLower(r.PathValue("app"))
	if strings.HasPrefix(app, "custom-") {
		app = "custom:" + strings.TrimPrefix(app, "custom-")
	}

	if app != "github" && app != "jira" && app != "notion" && !strings.HasPrefix(app, "custom:") {
		http.Error(w, "unknown connector", http.StatusBadRequest)
		return
	}

	csrf := r.FormValue("csrf_token")
	if csrf == "" {
		csrf = r.Header.Get("X-CSRF-Token")
	}
	if !b.session.ValidateCSRFToken(csrf, adminEmail) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}

	if err := b.vault.DeleteToken(r.Context(), adminEmail, app); err != nil {
		http.Error(w, "failed disconnecting", http.StatusInternalServerError)
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/dashboard?flash=Successfully+disconnected+%s", app), http.StatusFound)
}

// GET /api/connections
func (b *Broker) handleListConnections(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ghView := b.buildConnectorView(r.Context(), adminEmail, "github", "GitHub", "")
	jiraView := b.buildConnectorView(r.Context(), adminEmail, "jira", "Atlassian Jira", "")

	resp := map[string]interface{}{
		"github": map[string]interface{}{
			"connected":      ghView.Connected,
			"scope_mode":     ghView.ScopeMode,
			"account_label":  ghView.AccountLabel,
			"connector_type": ghView.ConnectorType,
		},
		"jira": map[string]interface{}{
			"connected":      jiraView.Connected,
			"scope_mode":     jiraView.ScopeMode,
			"account_label":  jiraView.AccountLabel,
			"connector_type": jiraView.ConnectorType,
		},
		"gcp": map[string]interface{}{
			"connected":   true,
			"keyless_adc": true,
			"scope_mode":  "read_only",
		},
		"gdk": map[string]interface{}{
			"connected":   true,
			"keyless_adc": true,
			"scope_mode":  "read_only",
		},
		"gflow": map[string]interface{}{
			"connected":   true,
			"keyless_adc": true,
			"scope_mode":  "full_access",
		},
		"notion": map[string]interface{}{
			"connected":        b.cfg.NotionAPIToken != "",
			"scope_mode":       "full_access",
			"account_label":    "Secret Manager (NOTION_API_TOKEN)",
			"oauth_configured": b.cfg.NotionAPIToken != "",
			"connector_type":   "rest_api",
		},
	}

	if conn, err := b.store.GetConnection(r.Context(), adminEmail, "notion"); err == nil && conn != nil {
		if tok, err := b.vault.DecryptConnection(r.Context(), conn); err == nil && tok != nil {
			if notionMap, ok := resp["notion"].(map[string]interface{}); ok {
				notionMap["connected"] = true
				if tok.Scope != "" {
					notionMap["scope_mode"] = tok.Scope
				}
				if tok.AccountLabel != "" {
					notionMap["account_label"] = tok.AccountLabel
				}
				if tok.ConnectorType != "" {
					notionMap["connector_type"] = tok.ConnectorType
				}
			}
		}
	}

	if conn, err := b.store.GetConnection(r.Context(), adminEmail, "gflow"); err == nil && conn != nil {
		if tok, err := b.vault.DecryptConnection(r.Context(), conn); err == nil && tok != nil {
			if gflowMap, ok := resp["gflow"].(map[string]interface{}); ok {
				if tok.Scope != "" {
					gflowMap["scope_mode"] = tok.Scope
				}
				if tok.AccountLabel != "" {
					gflowMap["account_label"] = tok.AccountLabel
				}
				if tok.EndpointURL != "" {
					gflowMap["endpoint_url"] = tok.EndpointURL
					gflowMap["connector_type"] = "remote_mcp"
				}
			}
		}
	}

	if conns, err := b.store.ListConnections(r.Context(), adminEmail); err == nil {
		for _, conn := range conns {
			if strings.HasPrefix(conn.Provider, "custom:") {
				tok, err := b.vault.DecryptConnection(r.Context(), conn)
				if err == nil && tok != nil {
					resp[conn.Provider] = map[string]interface{}{
						"connected":      true,
						"scope_mode":     tok.Scope,
						"account_label":  tok.AccountLabel,
						"connector_type": tok.ConnectorType,
						"name":           tok.ConnectorName,
					}
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// GET /api/connectors/github/workspaces
func (b *Broker) handleGitHubWorkspaces(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	tok, err := b.vault.GetValidAccessToken(r.Context(), adminEmail, "github")
	if err != nil || tok == nil || tok.AccessToken == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "not_connected",
			"error_description": "GitHub is not connected",
		})
		return
	}

	var orgs []string
	orgsReq, err := http.NewRequestWithContext(r.Context(), "GET", b.GitHubAPIURL+"/user/orgs", nil)
	if err == nil {
		orgsReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		orgsReq.Header.Set("Accept", "application/vnd.github.v3+json")
		orgsReq.Header.Set("User-Agent", "Spark-Unified-MCP-Gateway")
		if resp, err := b.httpClient.Do(orgsReq); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var orgList []struct {
					Login string `json:"login"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&orgList); err == nil {
					for _, o := range orgList {
						if o.Login != "" {
							orgs = append(orgs, o.Login)
						}
					}
				}
			}
		}
	}

	var repos []string
	repoSeen := make(map[string]bool)
	reposReq, err := http.NewRequestWithContext(r.Context(), "GET", b.GitHubAPIURL+"/user/repos?per_page=100&sort=updated", nil)
	if err == nil {
		reposReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		reposReq.Header.Set("Accept", "application/vnd.github.v3+json")
		reposReq.Header.Set("User-Agent", "Spark-Unified-MCP-Gateway")
		if resp, err := b.httpClient.Do(reposReq); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var repoList []struct {
					FullName string `json:"full_name"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&repoList); err == nil {
					for _, rp := range repoList {
						if rp.FullName != "" && !repoSeen[rp.FullName] {
							repoSeen[rp.FullName] = true
							repos = append(repos, rp.FullName)
						}
					}
				}
			}
		}
	}

	for i, org := range orgs {
		if i >= 5 {
			break
		}
		oReq, err := http.NewRequestWithContext(r.Context(), "GET", fmt.Sprintf("%s/orgs/%s/repos?per_page=50", b.GitHubAPIURL, url.PathEscape(org)), nil)
		if err == nil {
			oReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			oReq.Header.Set("Accept", "application/vnd.github.v3+json")
			oReq.Header.Set("User-Agent", "Spark-Unified-MCP-Gateway")
			if oResp, err := b.httpClient.Do(oReq); err == nil {
				defer oResp.Body.Close()
				if oResp.StatusCode == http.StatusOK {
					var orgRepos []struct {
						FullName string `json:"full_name"`
					}
					if err := json.NewDecoder(oResp.Body).Decode(&orgRepos); err == nil {
						for _, rp := range orgRepos {
							if rp.FullName != "" && !repoSeen[rp.FullName] {
								repoSeen[rp.FullName] = true
								repos = append(repos, rp.FullName)
							}
						}
					}
				}
			}
		}
	}

	selectedOrgs := tok.SelectedOrgs
	if selectedOrgs == nil {
		selectedOrgs = []string{}
	}
	allowedRead := tok.AllowedReadRepos
	if allowedRead == nil {
		allowedRead = []string{}
	}
	allowedWrite := splitCSV(tok.AllowedWriteRepos)
	if allowedWrite == nil {
		allowedWrite = []string{}
	}
	if orgs == nil {
		orgs = []string{}
	}
	if repos == nil {
		repos = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"orgs":                orgs,
		"repos":               repos,
		"selected_orgs":       selectedOrgs,
		"allowed_read_repos":  allowedRead,
		"allowed_write_repos": allowedWrite,
	})
}

// GET /api/connectors/jira/workspaces
func (b *Broker) handleJiraWorkspaces(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	tok, err := b.vault.GetValidAccessToken(r.Context(), adminEmail, "jira")
	if err != nil || tok == nil || tok.AccessToken == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "not_connected",
			"error_description": "Jira is not connected",
		})
		return
	}

	type JiraSpace struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	var spaces []JiraSpace

	if tok.CloudID != "" {
		projURL := fmt.Sprintf("%s/ex/jira/%s/rest/api/3/project/search", b.AtlassianAPIURL, tok.CloudID)
		pReq, err := http.NewRequestWithContext(r.Context(), "GET", projURL, nil)
		if err == nil {
			pReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			pReq.Header.Set("Accept", "application/json")
			if pResp, err := b.httpClient.Do(pReq); err == nil {
				defer pResp.Body.Close()
				if pResp.StatusCode == http.StatusOK {
					bodyBytes, _ := io.ReadAll(pResp.Body)
					var searchRes struct {
						Values []JiraSpace `json:"values"`
					}
					if err := json.Unmarshal(bodyBytes, &searchRes); err == nil && len(searchRes.Values) > 0 {
						spaces = searchRes.Values
					} else {
						var rawList []JiraSpace
						if err := json.Unmarshal(bodyBytes, &rawList); err == nil {
							spaces = rawList
						}
					}
				}
			}
		}
	}

	if spaces == nil {
		spaces = []JiraSpace{}
	}
	allowedSpaceKeys := tok.AllowedSpaceKeys
	if allowedSpaceKeys == nil {
		allowedSpaceKeys = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"cloud_id":           tok.CloudID,
		"site_url":           tok.SiteURL,
		"site_name":          tok.SiteName,
		"spaces":             spaces,
		"allowed_space_keys": allowedSpaceKeys,
	})
}

// POST /api/connectors/workspaces
func (b *Broker) handleSaveWorkspaces(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	var provider, csrf string
	var selectedOrgs, allowedReadRepos, allowedWriteRepos, allowedSpaceKeys []string
	isJSON := strings.Contains(r.Header.Get("Content-Type"), "application/json")

	if isJSON {
		var req struct {
			CSRFToken         string   `json:"csrf_token"`
			Provider          string   `json:"provider"`
			SelectedOrgs      []string `json:"selected_orgs"`
			AllowedReadRepos  []string `json:"allowed_read_repos"`
			AllowedWriteRepos []string `json:"allowed_write_repos"`
			AllowedSpaceKeys  []string `json:"allowed_space_keys"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_json"})
			return
		}
		csrf = req.CSRFToken
		provider = strings.ToLower(strings.TrimSpace(req.Provider))
		selectedOrgs = req.SelectedOrgs
		allowedReadRepos = req.AllowedReadRepos
		allowedWriteRepos = req.AllowedWriteRepos
		allowedSpaceKeys = req.AllowedSpaceKeys
	} else {
		_ = r.ParseForm()
		csrf = r.FormValue("csrf_token")
		provider = strings.ToLower(strings.TrimSpace(r.FormValue("provider")))
		selectedOrgs = parseFormStringSlice(r.Form, "selected_orgs")
		allowedReadRepos = parseFormStringSlice(r.Form, "allowed_read_repos")
		allowedWriteRepos = parseFormStringSlice(r.Form, "allowed_write_repos")
		allowedSpaceKeys = parseFormStringSlice(r.Form, "allowed_space_keys")
	}

	if csrf == "" {
		csrf = r.Header.Get("X-CSRF-Token")
	}
	if !b.session.ValidateCSRFToken(csrf, adminEmail) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_csrf"})
		return
	}

	if provider != "github" && provider != "jira" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_provider", "error_description": "provider must be 'github' or 'jira'"})
		return
	}

	conn, err := b.store.GetConnection(r.Context(), adminEmail, provider)
	if err != nil || conn == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not_connected", "error_description": fmt.Sprintf("%s is not connected", provider)})
		return
	}

	tok, err := b.vault.DecryptConnection(r.Context(), conn)
	if err != nil || tok == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "decryption_failed",
			"error_description": fmt.Sprintf("Failed decrypting connection: %v", err),
		})
		return
	}

	if provider == "github" {
		tok.SelectedOrgs = selectedOrgs
		tok.AllowedReadRepos = allowedReadRepos
		tok.AllowedWriteRepos = strings.Join(allowedWriteRepos, ",")
	} else if provider == "jira" {
		tok.AllowedSpaceKeys = allowedSpaceKeys
	}
	tok.UpdatedAt = time.Now()

	if err := b.vault.StoreToken(r.Context(), adminEmail, provider, tok); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": fmt.Sprintf("Failed saving encrypted credentials to vault: %v", err),
		})
		return
	}

	if isJSON || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
		return
	}

	http.Redirect(w, r, "/dashboard?flash=Workspace+scopes+updated", http.StatusSeeOther)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseFormStringSlice(form url.Values, key string) []string {
	vals, exists := form[key]
	if !exists || len(vals) == 0 {
		return nil
	}
	var res []string
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.Contains(v, ",") {
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					res = append(res, part)
				}
			}
		} else {
			res = append(res, v)
		}
	}
	return res
}

// CatalogTemplate describes a connector template available in the catalog.
type CatalogTemplate struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Category      string `json:"category"`
	ConnectorType string `json:"connector_type"`
	Badge         string `json:"badge"`
}

// CatalogTemplates returns the predefined templates for available connectors.
func CatalogTemplates() []CatalogTemplate {
	return []CatalogTemplate{
		{
			ID:            "github",
			Name:          "GitHub",
			Description:   "Repository issues, code search, and PRs via OAuth 2.0 or Personal Access Token.",
			Category:      "dev",
			ConnectorType: "oauth2",
			Badge:         "OAuth / PAT",
		},
		{
			ID:            "jira",
			Name:          "Atlassian Jira",
			Description:   "Jira workspace project and issue tracking via Atlassian 3LO OAuth 2.0.",
			Category:      "dev prod",
			ConnectorType: "oauth2",
			Badge:         "3LO OAuth",
		},
		{
			ID:            "gcp",
			Name:          "Google Cloud Platform (GCP MCP)",
			Description:   "Read-only Cloud Run, Logging, Storage, Artifact Registry, Monitoring & IAM via keyless ADC",
			Category:      "dev mcp",
			ConnectorType: "keyless_adc",
			Badge:         "Keyless ADC",
		},
		{
			ID:            "gdk",
			Name:          "Google Developer Knowledge",
			Description:   "Developer Knowledge documentation search via keyless ADC",
			Category:      "dev mcp",
			ConnectorType: "keyless_adc",
			Badge:         "Keyless ADC",
		},
		{
			ID:            "gflow",
			Name:          "Google Flow (gflow MCP)",
			Description:   "AI image (Nano Banana / Imagen) & video (Veo) generation, upscaling & character catalog",
			Category:      "mcp prod",
			ConnectorType: "keyless_adc",
			Badge:         "Keyless ADC + Flow",
		},
		{
			ID:            "linear",
			Name:          "Linear",
			Description:   "Linear issues and project sync via Remote MCP at mcp.linear.app + API Key.",
			Category:      "mcp prod",
			ConnectorType: "remote_mcp",
			Badge:         "Remote MCP",
		},
		{
			ID:            "notion",
			Name:          "Notion",
			Description:   "Workspaces, databases, and pages via Notion API + Integration Secret.",
			Category:      "prod",
			ConnectorType: "rest_api",
			Badge:         "REST / MCP",
		},
		{
			ID:            "slack",
			Name:          "Slack",
			Description:   "Workspace channels, message search, and posting via Slack Bot Token.",
			Category:      "prod",
			ConnectorType: "rest_api",
			Badge:         "REST / MCP",
		},
		{
			ID:            "cloudflare",
			Name:          "Cloudflare",
			Description:   "DNS, Workers, and KV management via Cloudflare Remote MCP / API Token.",
			Category:      "mcp dev",
			ConnectorType: "remote_mcp",
			Badge:         "Remote MCP",
		},
		{
			ID:            "sentry",
			Name:          "Sentry",
			Description:   "Application error issues, stack traces, and releases via Sentry MCP / Auth Token.",
			Category:      "mcp dev",
			ConnectorType: "remote_mcp",
			Badge:         "Remote MCP",
		},
		{
			ID:            "supabase",
			Name:          "Supabase",
			Description:   "Postgres tables, storage, and auth via Supabase Remote MCP + PAT.",
			Category:      "mcp dev",
			ConnectorType: "remote_mcp",
			Badge:         "Remote MCP",
		},
		{
			ID:            "custom_mcp",
			Name:          "Custom Remote MCP Server",
			Description:   "Streamable HTTP JSON-RPC /mcp upstream endpoint + optional Bearer Token.",
			Category:      "custom mcp",
			ConnectorType: "remote_mcp",
			Badge:         "Custom",
		},
		{
			ID:            "custom_api",
			Name:          "Custom REST API Connector",
			Description:   "Any enterprise HTTPS REST API endpoint + custom Authorization Header.",
			Category:      "custom",
			ConnectorType: "rest_api",
			Badge:         "Custom",
		},
	}
}

func (b *Broker) handleCatalogTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(CatalogTemplates())
}
