package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/store"
	"spark-mcp-gateway/internal/ui"
)

var controlCharRegex = regexp.MustCompile(`[\x00-\x1F\x7F<>"']`)

// OAuthServer handles admin authentication, DCR, and OAuth 2.1 authorization server flows.
type OAuthServer struct {
	cfg         *config.Config
	store       store.Store
	session     *SessionManager
	rateLimiter *IPRateLimiter
	httpClient  *http.Client

	// Configurable endpoints for testing
	GoogleTokenURL string
	GoogleVerifier *GoogleOIDCVerifier
}

// NewOAuthServer creates a new OAuthServer instance.
func NewOAuthServer(cfg *config.Config, s store.Store, httpClient *http.Client) *OAuthServer {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &OAuthServer{
		cfg:            cfg,
		store:          s,
		session:        NewSessionManager(cfg.ServiceURL, cfg.SessionHMACKey),
		rateLimiter:    NewIPRateLimiter(10, 10), // 10 req/min/IP
		httpClient:     httpClient,
		GoogleTokenURL: "https://oauth2.googleapis.com/token",
		GoogleVerifier: NewGoogleOIDCVerifier("https://www.googleapis.com/oauth2/v3/certs", httpClient),
	}
}

// SetGoogleJWKSURL allows overriding the Google certs URL for unit testing.
func (s *OAuthServer) SetGoogleJWKSURL(urlStr string) {
	s.GoogleVerifier = NewGoogleOIDCVerifier(urlStr, s.httpClient)
}

// SessionManager returns the session manager.
func (s *OAuthServer) SessionManager() *SessionManager {
	return s.session
}

// RegisterRoutes registers OAuth and Auth routes onto an http.ServeMux.
func (s *OAuthServer) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.handleProtectedResource)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthorizationServerMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)

	mux.HandleFunc("POST /api/oauth/register", s.handleRegisterClient)
	mux.HandleFunc("GET /authorize", s.handleAuthorizeGet)
	mux.HandleFunc("POST /authorize", s.handleAuthorizePost)
	mux.HandleFunc("POST /api/oauth/token", s.handleToken)

	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/google/login", s.handleGoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", s.handleGoogleCallback)
	mux.HandleFunc("POST /auth/dev/login", s.handleDevLogin)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
}

// RFC 9728
func (s *OAuthServer) handleProtectedResource(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"resource":                 s.cfg.ServiceURL + "/mcp",
		"authorization_servers":    []string{s.cfg.ServiceURL},
		"bearer_methods_supported": []string{"header"},
	})
}

// RFC 8414
func (s *OAuthServer) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"issuer":                                s.cfg.ServiceURL,
		"authorization_endpoint":                s.cfg.ServiceURL + "/authorize",
		"token_endpoint":                        s.cfg.ServiceURL + "/api/oauth/token",
		"registration_endpoint":                 s.cfg.ServiceURL + "/api/oauth/register",
		"jwks_uri":                              s.cfg.ServiceURL + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
	})
}

func (s *OAuthServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	jwk := PublicKeyToJWK(&s.cfg.JWTES256PrivateKey.PublicKey)
	_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{jwk}})
}

// RFC 7591 Dynamic Client Registration
func (s *OAuthServer) handleRegisterClient(w http.ResponseWriter, r *http.Request) {
	if !s.rateLimiter.Allow(r) {
		http.Error(w, `{"error":"rate_limit_exceeded","error_description":"Rate limit of 10 registrations/min exceeded"}`, http.StatusTooManyRequests)
		return
	}

	var req struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request","error_description":"Invalid JSON payload"}`, http.StatusBadRequest)
		return
	}

	if len(req.RedirectURIs) == 0 {
		http.Error(w, `{"error":"invalid_redirect_uri","error_description":"At least one redirect_uri is required"}`, http.StatusBadRequest)
		return
	}

	// Validate each redirect_uri
	for _, rawURI := range req.RedirectURIs {
		if !s.isValidRedirectURI(rawURI) {
			http.Error(w, fmt.Sprintf(`{"error":"invalid_redirect_uri","error_description":"Redirect URI %q is not permitted"}`, html.EscapeString(rawURI)), http.StatusBadRequest)
			return
		}
	}

	// Sanitize client_name
	cleanName := controlCharRegex.ReplaceAllString(req.ClientName, "")
	cleanName = strings.TrimSpace(cleanName)
	if cleanName == "" {
		cleanName = "Spark MCP Client"
	}

	// Generate client credentials with checked entropy
	clientIDBytes := make([]byte, 16)
	clientSecretBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientIDBytes); err != nil {
		http.Error(w, `{"error":"server_error","error_description":"failed generating client id"}`, http.StatusInternalServerError)
		return
	}
	if _, err := io.ReadFull(rand.Reader, clientSecretBytes); err != nil {
		http.Error(w, `{"error":"server_error","error_description":"failed generating client secret"}`, http.StatusInternalServerError)
		return
	}

	clientID := fmt.Sprintf("spark-client-%x", clientIDBytes)
	clientSecret := hex.EncodeToString(clientSecretBytes)

	client := &store.OAuthClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ClientName:   cleanName,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour), // 30 days Native TTL
	}

	if err := s.store.SaveOAuthClient(r.Context(), client); err != nil {
		if err == store.ErrClientCapExceeded {
			http.Error(w, `{"error":"client_limit_reached","error_description":"Max active client registrations (50) reached"}`, http.StatusForbidden)
			return
		}
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id":                client.ClientID,
		"client_secret":            client.ClientSecret,
		"client_name":              client.ClientName,
		"redirect_uris":            client.RedirectURIs,
		"token_endpoint_auth_mode": "none",
		"expires_at":               client.ExpiresAt.Unix(),
	})
}

// isValidRedirectURI enforces strict OAuth 2.1 URI validation (P1-3).
func (s *OAuthServer) isValidRedirectURI(rawURI string) bool {
	rawURI = strings.TrimSpace(rawURI)
	if rawURI == "" {
		return false
	}

	// Reject userinfo (@) or backslash traversal
	if strings.Contains(rawURI, "@") || strings.Contains(rawURI, "\\") {
		return false
	}

	u, err := url.Parse(rawURI)
	if err != nil || u.Scheme == "" || u.User != nil || u.Fragment != "" {
		return false
	}

	// Path traversal check
	if strings.Contains(u.Path, "..") || strings.Contains(u.RawPath, "..") {
		return false
	}

	// Custom Cursor desktop scheme
	if strings.EqualFold(u.Scheme, "cursor") {
		return u.Host != ""
	}

	// Local development clients when permitted
	if s.cfg.AllowLocalClients {
		if strings.EqualFold(u.Scheme, "http") && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost") {
			return true
		}
	}

	// Must be https://
	if !strings.EqualFold(u.Scheme, "https") {
		return false
	}

	host := strings.ToLower(u.Hostname())
	if host == "gemini.google.com" ||
		host == "aisandbox-pa.googleapis.com" ||
		strings.HasSuffix(host, ".google.com") {
		return true
	}

	// Optional explicitly allowed redirect hosts from environment
	if envAllowed := os.Getenv("ALLOWED_REDIRECT_HOSTS"); envAllowed != "" {
		for _, h := range strings.Split(envAllowed, ",") {
			h = strings.TrimSpace(strings.ToLower(h))
			if h != "" && (host == h || strings.HasSuffix(host, "."+h)) {
				return true
			}
		}
	}

	return false
}

// sanitizeReturnTo prevents open-redirect and header injection attacks.
func sanitizeReturnTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/dashboard"
	}
	if strings.ContainsAny(raw, "\r\n") {
		return "/dashboard"
	}
	if !strings.HasPrefix(raw, "/") {
		return "/dashboard"
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") {
		return "/dashboard"
	}
	return raw
}

// GET /authorize
func (s *OAuthServer) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	// 1. Admin session gate
	adminEmail, err := s.session.GetAdminSession(r)
	if err != nil {
		returnTo := sanitizeReturnTo(r.URL.RequestURI())
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	// 2. Validate OAuth 2.1 parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMeth := r.URL.Query().Get("code_challenge_method")
	state := r.URL.Query().Get("state")
	resource := r.URL.Query().Get("resource")

	if responseType != "code" {
		http.Error(w, "invalid_request: response_type must be 'code'", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" || codeChallengeMeth != "S256" {
		http.Error(w, "invalid_request: PKCE code_challenge and code_challenge_method=S256 required", http.StatusBadRequest)
		return
	}

	client, err := s.store.GetOAuthClient(r.Context(), clientID)
	if err != nil {
		http.Error(w, "unauthorized_client: unknown client_id", http.StatusBadRequest)
		return
	}

	matchedURI := false
	for _, u := range client.RedirectURIs {
		if u == redirectURI {
			matchedURI = true
			break
		}
	}
	if !matchedURI {
		http.Error(w, "invalid_redirect_uri: redirect_uri does not match client registration", http.StatusBadRequest)
		return
	}

	csrfToken := s.session.GenerateCSRFToken(adminEmail)
	connectors := []ui.ConnectorView{
		{ID: "github", Name: "GitHub", Description: "Pull requests, code browsing, and issue creation", ScopeMode: "read_only"},
		{ID: "jira", Name: "Atlassian Jira", Description: "Issue inspection and status transitions", ScopeMode: "read_only"},
		{ID: "gcp", Name: "Google Cloud Run", Description: "Cloud Run inspection via keyless ADC", KeylessADC: true, Connected: true, ScopeMode: "read_only"},
		{ID: "gdk", Name: "Google Developer Knowledge", Description: "Developer Knowledge documentation search via keyless ADC", KeylessADC: true, Connected: true, ScopeMode: "read_only"},
	}

	pageData := ui.AuthorizePageData{
		AdminEmail:        adminEmail,
		ServiceURL:        s.cfg.ServiceURL,
		ClientID:          clientID,
		ClientName:        client.ClientName,
		RedirectURI:       redirectURI,
		State:             state,
		CodeChallenge:     codeChallenge,
		CodeChallengeMeth: codeChallengeMeth,
		Resource:          resource,
		CSRFToken:         csrfToken,
		IsCustomDCRClient: strings.HasPrefix(clientID, "spark-client-"),
		DefaultPreset:     "read_only",
		Connectors:        connectors,
	}

	_ = ui.RenderAuthorize(w, http.StatusOK, pageData)
}

// POST /authorize
func (s *OAuthServer) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	adminEmail, err := s.session.GetAdminSession(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	// Verify CSRF
	csrfToken := r.FormValue("csrf_token")
	if !s.session.ValidateCSRFToken(csrfToken, adminEmail) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	decision := r.FormValue("decision")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMeth := r.FormValue("code_challenge_method")
	resource := r.FormValue("resource")

	// Verify client and redirect_uri
	client, err := s.store.GetOAuthClient(r.Context(), clientID)
	if err != nil {
		http.Error(w, "unauthorized_client", http.StatusBadRequest)
		return
	}
	matched := false
	for _, u := range client.RedirectURIs {
		if u == redirectURI {
			matched = true
			break
		}
	}
	if !matched {
		http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
		return
	}

	// Handle Deny
	if decision != "approve" {
		targetURL := fmt.Sprintf("%s?error=access_denied&state=%s", redirectURI, url.QueryEscape(state))
		http.Redirect(w, r, targetURL, http.StatusFound)
		return
	}

	// Calculate Scopes Map from preset
	preset := r.FormValue("preset")
	scopes := make(map[string]string)
	switch preset {
	case "minimal":
		scopes["github"] = "none"
		scopes["jira"] = "none"
		scopes["gcp"] = "read_only"
		scopes["gdk"] = "read_only"
	case "full_access":
		scopes["github"] = "full_access"
		scopes["jira"] = "full_access"
		scopes["gcp"] = "read_only"
		scopes["gdk"] = "read_only"
	case "custom":
		scopes["github"] = r.FormValue("scope_github")
		scopes["jira"] = r.FormValue("scope_jira")
		scopes["gcp"] = r.FormValue("scope_gcp")
		scopes["gdk"] = r.FormValue("scope_gdk")
	default: // "read_only"
		scopes["github"] = "read_only"
		scopes["jira"] = "read_only"
		scopes["gcp"] = "read_only"
		scopes["gdk"] = "read_only"
	}

	// Generate 32-byte authorization code with checked entropy
	codeBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, codeBytes); err != nil {
		http.Error(w, "internal server error: entropy read failed", http.StatusInternalServerError)
		return
	}
	codeStr := hex.EncodeToString(codeBytes)

	authCode := &store.AuthCode{
		Code:                codeStr,
		ClientID:            clientID,
		AdminEmail:          adminEmail,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMeth,
		Resource:            resource,
		Scopes:              scopes,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(5 * time.Minute), // 5 min TTL
		Used:                false,
	}

	if err := s.store.SaveAuthCode(r.Context(), authCode); err != nil {
		http.Error(w, "failed saving auth code", http.StatusInternalServerError)
		return
	}

	targetURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, url.QueryEscape(codeStr), url.QueryEscape(state))
	http.Redirect(w, r, targetURL, http.StatusFound)
}

// POST /api/oauth/token
func (s *OAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	switch grantType {
	case "authorization_code":
		s.handleTokenAuthCode(w, r)
	case "refresh_token":
		s.handleTokenRefreshToken(w, r)
	default:
		http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
	}
}

// handleTokenAuthCode implements RFC 6749 §4.1.3 & OAuth 2.1 token issuance (P0-2).
func (s *OAuthServer) handleTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	codeStr := strings.TrimSpace(r.FormValue("code"))
	verifier := strings.TrimSpace(r.FormValue("code_verifier"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	reqResource := strings.TrimSpace(r.FormValue("resource"))

	if codeStr == "" || verifier == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"code and code_verifier required"}`, http.StatusBadRequest)
		return
	}

	// RFC 6749 §4.1.3 & OAuth 2.1: client_id and redirect_uri are mandatory on token endpoint
	if clientID == "" {
		http.Error(w, `{"error":"invalid_grant","error_description":"client_id mismatch or missing"}`, http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		http.Error(w, `{"error":"invalid_grant","error_description":"redirect_uri mismatch or missing"}`, http.StatusBadRequest)
		return
	}

	authCode, err := s.store.GetAndConsumeAuthCode(r.Context(), codeStr)
	if err != nil {
		http.Error(w, `{"error":"invalid_grant","error_description":"authorization code invalid, expired, or already consumed"}`, http.StatusBadRequest)
		return
	}

	if authCode.ClientID != clientID {
		http.Error(w, `{"error":"invalid_grant","error_description":"client_id mismatch or missing"}`, http.StatusBadRequest)
		return
	}

	if authCode.RedirectURI != redirectURI {
		http.Error(w, `{"error":"invalid_grant","error_description":"redirect_uri mismatch or missing"}`, http.StatusBadRequest)
		return
	}

	// Verify PKCE S256 with constant-time comparison
	if !VerifyPKCES256(verifier, authCode.CodeChallenge) {
		http.Error(w, `{"error":"invalid_grant","error_description":"PKCE verification failed"}`, http.StatusBadRequest)
		return
	}

	// Verify RFC 8707 Resource binding if provided
	expectedAudience := s.cfg.ServiceURL + "/mcp"
	if reqResource != "" && reqResource != s.cfg.ServiceURL && reqResource != expectedAudience {
		http.Error(w, `{"error":"invalid_target","error_description":"resource parameter does not match service"}`, http.StatusBadRequest)
		return
	}

	// Mint 15m ES256 JWT
	now := time.Now().Unix()
	jtiBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, jtiBytes); err != nil {
		http.Error(w, `{"error":"server_error","error_description":"failed generating jti"}`, http.StatusInternalServerError)
		return
	}

	claims := &Claims{
		Issuer:    s.cfg.ServiceURL,
		Audience:  expectedAudience,
		Subject:   "admin:" + authCode.AdminEmail,
		ExpiresAt: now + 900, // 15m
		IssuedAt:  now,
		JWTID:     hex.EncodeToString(jtiBytes),
		Scopes:    authCode.Scopes,
	}

	jwtStr, err := SignJWT(s.cfg.JWTES256PrivateKey, claims)
	if err != nil {
		http.Error(w, `{"error":"server_error","error_description":"failed signing token"}`, http.StatusInternalServerError)
		return
	}

	// Generate rotating Refresh Token with checked entropy
	rtBytes := make([]byte, 32)
	famBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, rtBytes); err != nil {
		http.Error(w, `{"error":"server_error","error_description":"failed generating refresh token"}`, http.StatusInternalServerError)
		return
	}
	if _, err := io.ReadFull(rand.Reader, famBytes); err != nil {
		http.Error(w, `{"error":"server_error","error_description":"failed generating family id"}`, http.StatusInternalServerError)
		return
	}

	rtPlain := hex.EncodeToString(rtBytes)
	rtHash := sha256Hex(rtPlain)
	familyID := hex.EncodeToString(famBytes)

	rtRecord := &store.RefreshTokenRecord{
		TokenHash:  rtHash,
		FamilyID:   familyID,
		ClientID:   authCode.ClientID,
		AdminEmail: authCode.AdminEmail,
		Resource:   expectedAudience,
		Scopes:     authCode.Scopes,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour), // 30 days
		Revoked:    false,
	}

	_ = s.store.SaveRefreshToken(r.Context(), rtRecord)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  jwtStr,
		"token_type":    "Bearer",
		"expires_in":    900,
		"refresh_token": rtPlain,
		"scope":         "mcp",
	})
}

func (s *OAuthServer) handleTokenRefreshToken(w http.ResponseWriter, r *http.Request) {
	rtPlain := strings.TrimSpace(r.FormValue("refresh_token"))
	if rtPlain == "" {
		http.Error(w, `{"error":"invalid_request","error_description":"refresh_token required"}`, http.StatusBadRequest)
		return
	}

	rtHash := sha256Hex(rtPlain)
	rec, err := s.store.GetRefreshToken(r.Context(), rtHash)
	if err != nil {
		http.Error(w, `{"error":"invalid_grant","error_description":"invalid refresh token"}`, http.StatusBadRequest)
		return
	}

	// Token-Family Replay Revocation!
	if rec.Revoked {
		// Replay detected! Revoke the entire token family immediately
		_ = s.store.RevokeTokenFamily(r.Context(), rec.FamilyID)
		http.Error(w, `{"error":"invalid_grant","error_description":"token family revoked due to token replay"}`, http.StatusBadRequest)
		return
	}

	// Consume this refresh token
	_ = s.store.ConsumeRefreshToken(r.Context(), rtHash)

	// Issue rotated refresh token in the SAME family
	newRTBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newRTBytes); err != nil {
		http.Error(w, `{"error":"server_error","error_description":"failed generating refresh token"}`, http.StatusInternalServerError)
		return
	}
	newRTPlain := hex.EncodeToString(newRTBytes)
	newRTHash := sha256Hex(newRTPlain)

	newRecord := &store.RefreshTokenRecord{
		TokenHash:  newRTHash,
		FamilyID:   rec.FamilyID,
		ClientID:   rec.ClientID,
		AdminEmail: rec.AdminEmail,
		Resource:   rec.Resource,
		Scopes:     rec.Scopes,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
		Revoked:    false,
	}
	_ = s.store.SaveRefreshToken(r.Context(), newRecord)

	// Mint new 15m ES256 JWT
	now := time.Now().Unix()
	jtiBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, jtiBytes); err != nil {
		http.Error(w, `{"error":"server_error","error_description":"failed generating jti"}`, http.StatusInternalServerError)
		return
	}

	claims := &Claims{
		Issuer:    s.cfg.ServiceURL,
		Audience:  rec.Resource,
		Subject:   "admin:" + rec.AdminEmail,
		ExpiresAt: now + 900,
		IssuedAt:  now,
		JWTID:     hex.EncodeToString(jtiBytes),
		Scopes:    rec.Scopes,
	}

	jwtStr, err := SignJWT(s.cfg.JWTES256PrivateKey, claims)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  jwtStr,
		"token_type":    "Bearer",
		"expires_in":    900,
		"refresh_token": newRTPlain,
		"scope":         "mcp",
	})
}

// GET /auth/login
func (s *OAuthServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	// If already authenticated, redirect to return_to or dashboard
	if _, err := s.session.GetAdminSession(r); err == nil {
		returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	data := ui.LoginPageData{
		ServiceURL:   s.cfg.ServiceURL,
		ErrorMessage: r.URL.Query().Get("error"),
		ReturnTo:     sanitizeReturnTo(r.URL.Query().Get("return_to")),
		DevMode:      s.cfg.DevMode,
	}
	_ = ui.RenderLogin(w, http.StatusOK, data)
}

func (s *OAuthServer) oidcStateCookieName() string {
	if strings.HasPrefix(strings.ToLower(s.cfg.ServiceURL), "https://") {
		return "__Host-spark_oidc_state"
	}
	return "spark_oidc_state"
}

// GET /auth/google/login (P0-1: CSRF & Open Redirect Protected)
func (s *OAuthServer) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	safeReturnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))

	// 1. Generate 32-byte cryptographically random nonce
	nonceBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		http.Error(w, "internal server error: entropy read failed", http.StatusInternalServerError)
		return
	}
	nonce := hex.EncodeToString(nonceBytes)

	// 2. Build signed state: nonce | expUnix | base64(safeReturnTo)
	expUnix := time.Now().Add(10 * time.Minute).Unix()
	encodedReturnTo := base64.RawURLEncoding.EncodeToString([]byte(safeReturnTo))
	payload := fmt.Sprintf("%s|%d|%s", nonce, expUnix, encodedReturnTo)
	sig := s.session.sign("oidc_state:" + payload)
	signedState := payload + "." + sig

	// 3. Set short-lived OIDC state cookie containing nonce
	isSecure := strings.HasPrefix(strings.ToLower(s.cfg.ServiceURL), "https://")
	http.SetCookie(w, &http.Cookie{
		Name:     s.oidcStateCookieName(),
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	redirectURI := s.cfg.ServiceURL + "/auth/google/callback"
	u := fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=%s&redirect_uri=%s&scope=openid%%20email%%20profile&state=%s&prompt=select_account",
		url.QueryEscape(s.cfg.GoogleOIDCClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(signedState),
	)

	http.Redirect(w, r, u, http.StatusFound)
}

// GET /auth/google/callback (P0-1 & P2-2: RS256 Verification & Nonce Validation)
func (s *OAuthServer) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	cookieName := s.oidcStateCookieName()
	oidcCookie, err := r.Cookie(cookieName)

	// Immediately clear the state cookie
	isSecure := strings.HasPrefix(strings.ToLower(s.cfg.ServiceURL), "https://")
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	if err != nil || oidcCookie.Value == "" {
		http.Error(w, "Forbidden: Missing OIDC state cookie (CSRF protection)", http.StatusForbidden)
		return
	}

	stateParam := r.URL.Query().Get("state")
	parts := strings.Split(stateParam, ".")
	if len(parts) != 2 {
		http.Error(w, "Forbidden: Invalid OIDC state format", http.StatusForbidden)
		return
	}

	payload := parts[0]
	providedSig := parts[1]
	expectedSig := s.session.sign("oidc_state:" + payload)

	if subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) != 1 {
		http.Error(w, "Forbidden: Invalid OIDC state signature", http.StatusForbidden)
		return
	}

	payloadParts := strings.Split(payload, "|")
	if len(payloadParts) != 3 {
		http.Error(w, "Forbidden: Malformed OIDC state payload", http.StatusForbidden)
		return
	}

	nonce := payloadParts[0]
	expUnixStr := payloadParts[1]
	encodedReturnTo := payloadParts[2]

	expUnix, err := strconv.ParseInt(expUnixStr, 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		http.Error(w, "Forbidden: Expired OIDC state", http.StatusForbidden)
		return
	}

	if subtle.ConstantTimeCompare([]byte(nonce), []byte(oidcCookie.Value)) != 1 {
		http.Error(w, "Forbidden: OIDC state nonce mismatch (CSRF detected)", http.StatusForbidden)
		return
	}

	rawReturnToBytes, _ := base64.RawURLEncoding.DecodeString(encodedReturnTo)
	returnTo := sanitizeReturnTo(string(rawReturnToBytes))

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/auth/login?error=missing_code", http.StatusFound)
		return
	}

	// Exchange code for Google tokens
	redirectURI := s.cfg.ServiceURL + "/auth/google/callback"
	data := url.Values{
		"code":          {code},
		"client_id":     {s.cfg.GoogleOIDCClientID},
		"client_secret": {s.cfg.GoogleOIDCClientSecret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}

	tokenResp, err := s.httpClient.PostForm(s.GoogleTokenURL, data)
	if err != nil || tokenResp.StatusCode != http.StatusOK {
		http.Redirect(w, r, "/auth/login?error=google_auth_failed", http.StatusFound)
		return
	}
	defer tokenResp.Body.Close()

	var tokenRes struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenRes); err != nil || tokenRes.IDToken == "" {
		http.Redirect(w, r, "/auth/login?error=google_token_invalid", http.StatusFound)
		return
	}

	// RS256 cryptographic verification of Google ID token
	email, err := s.GoogleVerifier.VerifyIDToken(r.Context(), tokenRes.IDToken, s.cfg.GoogleOIDCClientID)
	if err != nil {
		http.Redirect(w, r, "/auth/login?error=invalid_id_token", http.StatusFound)
		return
	}

	// Strict case-insensitive check in ADMIN_ALLOWED_EMAILS
	if !s.cfg.IsAdminAllowed(email) {
		http.Redirect(w, r, "/auth/login?error=unauthorized_email", http.StatusFound)
		return
	}

	// Issue admin session
	s.session.SetAdminSession(w, email)
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// POST /auth/dev/login (QA-1: Requires email, validates allowlist, sanitizes return_to)
func (s *OAuthServer) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DevMode {
		http.Error(w, "Forbidden: Dev sign-in is disabled in production", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	reqEmail := strings.TrimSpace(r.FormValue("email"))
	if reqEmail == "" {
		http.Error(w, "missing email", http.StatusBadRequest)
		return
	}

	if !s.cfg.IsAdminAllowed(reqEmail) {
		http.Error(w, "Forbidden: unauthorized email address", http.StatusForbidden)
		return
	}

	s.session.SetAdminSession(w, reqEmail)
	returnTo := sanitizeReturnTo(r.FormValue("return_to"))
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// POST /auth/logout
func (s *OAuthServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.session.ClearAdminSession(w)
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
