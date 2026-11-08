package oauthbroker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"spark-mcp-gateway/internal/auth"
	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/store"
	"spark-mcp-gateway/internal/ui"
	"spark-mcp-gateway/internal/vault"
)

// Broker handles upstream 3LO OAuth authorization broker handshakes (GitHub & Jira).
type Broker struct {
	cfg        *config.Config
	store      store.Store
	vault      *vault.TokenVault
	session    *auth.SessionManager
	httpClient *http.Client

	// Optional base URLs for testing with httptest
	GitHubOAuthURL     string
	GitHubAPIURL       string
	AtlassianAuthURL   string
	AtlassianTokenURL  string
	AtlassianAPIURL    string
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
			ID:           "gcp",
			Name:         "Google Cloud Run",
			Description:  "Cloud Run inspection via keyless ADC",
			Connected:    true,
			KeylessADC:   true,
			ScopeMode:    "read_only",
			AccountLabel: fmt.Sprintf("%s (Keyless ADC)", b.cfg.GCPProjectID),
		},
		{
			ID:           "gdk",
			Name:         "Google Developer Knowledge",
			Description:  "Developer Knowledge documentation search via keyless ADC",
			Connected:    true,
			KeylessADC:   true,
			ScopeMode:    "read_only",
			AccountLabel: fmt.Sprintf("%s (Keyless ADC)", b.cfg.GCPProjectID),
		},
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
	view := ui.ConnectorView{
		ID:          id,
		Name:        name,
		Description: desc,
		Connected:   false,
	}

	conn, err := b.store.GetConnection(ctx, adminEmail, id)
	if err == nil && conn != nil {
		token, err := b.vault.DecryptConnection(ctx, conn)
		if err == nil && token != nil {
			view.Connected = true
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

	mode := strings.ToLower(r.URL.Query().Get("mode"))
	if mode != "full_access" {
		mode = "read_only"
	}

	// Generate 10-minute HMAC CSRF state
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
		if b.cfg.GitHubOAuthClientID == "" {
			http.Error(w, "GitHub OAuth is not configured on this server", http.StatusServiceUnavailable)
			return
		}
		scopes := "read:user,repo:status,public_repo"
		if mode == "full_access" {
			scopes = "read:user,repo"
		}
		_ = b.store.SaveOAuthState(r.Context(), oauthState)

		u := fmt.Sprintf("%s/authorize?client_id=%s&redirect_uri=%s&state=%s&scope=%s",
			b.GitHubOAuthURL,
			url.QueryEscape(b.cfg.GitHubOAuthClientID),
			url.QueryEscape(callbackURI),
			url.QueryEscape(stateStr),
			url.QueryEscape(scopes),
		)
		http.Redirect(w, r, u, http.StatusFound)
		return
	}

	if app == "jira" {
		if b.cfg.JiraOAuthClientID == "" {
			http.Error(w, "Jira OAuth is not configured on this server", http.StatusServiceUnavailable)
			return
		}
		// PKCE S256 for Jira 3LO
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
			url.QueryEscape(b.cfg.JiraOAuthClientID),
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

	// Save encrypted credentials in TokenVault
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
	callbackURI := fmt.Sprintf("%s/oauth/callback/github", b.cfg.ServiceURL)
	payload := url.Values{
		"client_id":     {b.cfg.GitHubOAuthClientID},
		"client_secret": {b.cfg.GitHubOAuthClientSecret},
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

	// Discover username
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
		AccessToken:  tokenRes.AccessToken,
		ExpiresAt:    time.Time{}, // GitHub classic tokens do not expire
		Scope:        mode,
		AccountLabel: accountLabel,
		UpdatedAt:    time.Now(),
	}, nil
}

func (b *Broker) exchangeJiraCode(ctx context.Context, code, verifier, mode string) (*vault.TokenData, error) {
	callbackURI := fmt.Sprintf("%s/oauth/callback/jira", b.cfg.ServiceURL)
	payload := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     b.cfg.JiraOAuthClientID,
		"client_secret": b.cfg.JiraOAuthClientSecret,
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

	// Discover Jira cloudId and siteUrl via /oauth/token/accessible-resources
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
		AccessToken:  tokenRes.AccessToken,
		RefreshToken: tokenRes.RefreshToken,
		ExpiresAt:    expiresAt,
		Scope:        mode,
		CloudID:      cloudID,
		SiteURL:      siteURL,
		AccountLabel: accountLabel,
		UpdatedAt:    time.Now(),
	}, nil
}

// POST /api/connections/{app}/disconnect
func (b *Broker) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := b.session.GetAdminSession(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	app := strings.ToLower(r.PathValue("app"))
	if app != "github" && app != "jira" {
		http.Error(w, "unknown connector", http.StatusBadRequest)
		return
	}

	// Validate CSRF
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"github": map[string]interface{}{
			"connected":     ghView.Connected,
			"scope_mode":    ghView.ScopeMode,
			"account_label": ghView.AccountLabel,
		},
		"jira": map[string]interface{}{
			"connected":     jiraView.Connected,
			"scope_mode":    jiraView.ScopeMode,
			"account_label": jiraView.AccountLabel,
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
	})
}
