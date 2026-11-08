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
			Name:          "Google Cloud Run",
			Description:   "Cloud Run inspection via keyless ADC",
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
				accountLabel = fmt.Sprintf("%s (%s)", resources[0].Name, resources[0].URL)
			}
		}
	}

	if cloudID == "" {
		return nil, errors.New("no accessible Jira sites found for user account")
	}

	expiresAt := time.Now().Add(time.Duration(tokenRes.ExpiresIn) * time.Second)

	return &vault.TokenData{
		AccessToken:   tokenRes.AccessToken,
		RefreshToken:  tokenRes.RefreshToken,
		ConnectorType: "oauth2",
		ExpiresAt:     expiresAt,
		Scope:         mode,
		CloudID:       cloudID,
		SiteURL:       siteURL,
		AccountLabel:  accountLabel,
		UpdatedAt:     time.Now(),
	}, nil
}

// POST /api/connectors/{app}/oauth-config
func (b *Broker) handleOAuthConfig(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	app := strings.ToLower(r.PathValue("app"))
	if app != "github" && app != "jira" {
		http.Error(w, `{"error":"unknown_connector"}`, http.StatusBadRequest)
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
		http.Error(w, `{"error":"invalid_csrf"}`, http.StatusForbidden)
		return
	}

	if clientID == "" || clientSecret == "" {
		http.Error(w, `{"error":"invalid_credentials","error_description":"client_id and client_secret are required"}`, http.StatusBadRequest)
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
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
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
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
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
		http.Error(w, `{"error":"invalid_csrf"}`, http.StatusForbidden)
		return
	}

	if pat == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"access_token is required"}`, http.StatusBadRequest)
		return
	}
	if scopeMode != "full_access" {
		scopeMode = "read_only"
	}

	userReq, err := http.NewRequestWithContext(r.Context(), "GET", b.GitHubAPIURL+"/user", nil)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}
	userReq.Header.Set("Authorization", "Bearer "+pat)
	userReq.Header.Set("User-Agent", "spark-mcp-gateway/3.0")

	userResp, err := b.httpClient.Do(userReq)
	if err != nil || userResp.StatusCode != http.StatusOK {
		http.Error(w, `{"error":"invalid_pat","error_description":"Failed validating GitHub Personal Access Token"}`, http.StatusBadRequest)
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
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
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
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
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
		http.Error(w, `{"error":"invalid_csrf"}`, http.StatusForbidden)
		return
	}

	if !slugRegex.MatchString(slug) {
		http.Error(w, `{"error":"invalid_slug","error_description":"slug must be 2-30 alphanumeric characters"}`, http.StatusBadRequest)
		return
	}

	if name == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"name is required"}`, http.StatusBadRequest)
		return
	}

	if connType != "remote_mcp" && connType != "rest_api" {
		http.Error(w, `{"error":"invalid_connector_type","error_description":"connector_type must be 'remote_mcp' or 'rest_api'"}`, http.StatusBadRequest)
		return
	}

	// SSRF protection
	if err := providers.ValidateUpstreamURLWithTestOption(endpointURL, b.AllowLoopbackForTest); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid_endpoint_url","error_description":%q}`, err.Error()), http.StatusBadRequest)
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
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
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

	if app != "github" && app != "jira" && !strings.HasPrefix(app, "custom:") {
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
