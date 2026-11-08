package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/store"
)

func newTestAuthServer(t *testing.T) (*OAuthServer, *config.Config, *store.MemoryStore) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating test key: %v", err)
	}

	cfg := &config.Config{
		ServiceURL:         "http://127.0.0.1:8080",
		AdminAllowedEmails: []string{"brendon.ang20011007@gmail.com"},
		SessionHMACKey:     []byte("test-32-byte-secret-key-12345678"),
		JWTES256PrivateKey: key,
		DevMode:            true,
		AllowLocalClients:  true,
		GoogleOIDCClientID: "test-google-client-id",
	}

	s := store.NewMemoryStore()
	server := NewOAuthServer(cfg, s, nil)
	return server, cfg, s
}

func TestOAuth21DCRRedirectURIRestrictions(t *testing.T) {
	server, _, _ := newTestAuthServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// 1. Allowed redirect_uri: cursor://callback
	bodyAllowed := `{"client_name":"Cursor Client","redirect_uris":["cursor://callback"]}`
	req := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(bodyAllowed))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201 for cursor://, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Allowed redirect_uri: exact Google OpenAuth DCR hosts & Gemini domains
	bodyGoogle := `{
		"client_name":"Gemini Spark Client",
		"token_endpoint_auth_method":"client_secret_post",
		"redirect_uris":[
			"https://oauth-redirect.googleusercontent.com/r/abc",
			"https://oauth-redirect.googleusercontent.com/r/def",
			"https://oauth-redirect.googleusercontent.com/a/ghi",
			"https://oauth-redirect-sandbox.googleusercontent.com/r/jkl",
			"https://gemini.google.com/oauth/callback",
			"https://vertexaisearch.cloud.google.com/oauth-redirect"
		]
	}`
	req2 := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(bodyGoogle))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusCreated {
		t.Fatalf("expected status 201 for Google OpenAuth DCR URIs, got %d: %s", rec2.Code, rec2.Body.String())
	}

	var dcrRes struct {
		ClientID                string `json:"client_id"`
		ClientSecret            string `json:"client_secret"`
		TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
		TokenEndpointAuthMode   string `json:"token_endpoint_auth_mode"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &dcrRes); err != nil {
		t.Fatalf("failed decoding DCR response: %v", err)
	}
	if dcrRes.TokenEndpointAuthMethod != "client_secret_post" || dcrRes.TokenEndpointAuthMode != "client_secret_post" {
		t.Errorf("expected token_endpoint_auth_method client_secret_post, got %q", dcrRes.TokenEndpointAuthMethod)
	}

	// 3. Disallowed: evil attacker domain https://evil.attacker.com/callback
	bodyEvil := `{"client_name":"Evil Client","redirect_uris":["https://evil.attacker.com/callback"]}`
	req3 := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(bodyEvil))
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for evil domain, got %d", rec3.Code)
	}

	// 4a. Disallowed: googleusercontent.com wildcard user-content subdomains MUST be rejected (P1-1)
	bodyGUC := `{"client_name":"GUC Client","redirect_uris":["https://evil.googleusercontent.com/cb"]}`
	req4 := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(bodyGUC))
	req4.Header.Set("Content-Type", "application/json")
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for evil.googleusercontent.com, got %d", rec4.Code)
	}

	// 4b. Disallowed: storage.googleapis.com user bucket MUST be rejected (P1-1)
	bodyGCS := `{"client_name":"GCS Client","redirect_uris":["https://evil.storage.googleapis.com/cb"]}`
	reqGCS := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(bodyGCS))
	reqGCS.Header.Set("Content-Type", "application/json")
	recGCS := httptest.NewRecorder()
	mux.ServeHTTP(recGCS, reqGCS)
	if recGCS.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for evil.storage.googleapis.com, got %d", recGCS.Code)
	}

	// 4c. Disallowed: >25 redirect URIs
	tooMany := make([]string, 26)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("https://gemini.google.com/cb%d", i)
	}
	tooManyBytes, _ := json.Marshal(map[string]interface{}{"redirect_uris": tooMany})
	reqTooMany := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(string(tooManyBytes)))
	reqTooMany.Header.Set("Content-Type", "application/json")
	recTooMany := httptest.NewRecorder()
	mux.ServeHTTP(recTooMany, reqTooMany)
	if recTooMany.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for >25 redirect_uris, got %d", recTooMany.Code)
	}

	// 5. Disallowed: @ userinfo bypass
	bodyAt := `{"client_name":"At Client","redirect_uris":["https://gemini.google.com@evil.com/cb"]}`
	req5 := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(bodyAt))
	req5.Header.Set("Content-Type", "application/json")
	rec5 := httptest.NewRecorder()
	mux.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for @ userinfo, got %d", rec5.Code)
	}

	// 6. Disallowed: URL fragments
	bodyFrag := `{"client_name":"Frag Client","redirect_uris":["https://gemini.google.com/cb#fragment"]}`
	req6 := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(bodyFrag))
	req6.Header.Set("Content-Type", "application/json")
	rec6 := httptest.NewRecorder()
	mux.ServeHTTP(rec6, req6)
	if rec6.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for URI with fragment, got %d", rec6.Code)
	}

	// 7. Disallowed: path traversal
	bodyTrav := `{"client_name":"Trav Client","redirect_uris":["https://gemini.google.com/../cb"]}`
	req7 := httptest.NewRequest("POST", "/api/oauth/register", strings.NewReader(bodyTrav))
	req7.Header.Set("Content-Type", "application/json")
	rec7 := httptest.NewRecorder()
	mux.ServeHTTP(rec7, req7)
	if rec7.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for URI with path traversal, got %d", rec7.Code)
	}
}

func TestProtectedResourceMCPDiscovery(t *testing.T) {
	server, cfg, _ := newTestAuthServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// RFC 9728 §3.1 path-appended discovery probed by Google OpenAuth
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/mcp", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /.well-known/oauth-protected-resource/mcp, got %d", rec.Code)
	}

	var res struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed unmarshaling protected resource response: %v", err)
	}
	expectedRes := cfg.ServiceURL + "/mcp"
	if res.Resource != expectedRes {
		t.Errorf("expected resource %s, got %s", expectedRes, res.Resource)
	}
}

func TestStaticClientAndConfidentialClientTokenExchange(t *testing.T) {
	server, cfg, _ := newTestAuthServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	adminEmail := "brendon.ang20011007@gmail.com"
	csrfToken := server.SessionManager().GenerateCSRFToken(adminEmail)

	// 1. Mint static client via POST /api/oauth/clients/static
	staticBody := `{
		"client_name": "Gemini Spark Static Client",
		"csrf_token": "` + csrfToken + `"
	}`
	reqStatic := httptest.NewRequest("POST", "/api/oauth/clients/static", strings.NewReader(staticBody))
	reqStatic.Header.Set("Content-Type", "application/json")
	cookieHeader := server.SessionManager().cookieName + "=" + fmt.Sprintf("%s:%d:%s", adminEmail, time.Now().Unix(), server.SessionManager().sign(fmt.Sprintf("%s:%d", adminEmail, time.Now().Unix())))
	reqStatic.Header.Set("Cookie", cookieHeader)
	recStatic := httptest.NewRecorder()
	mux.ServeHTTP(recStatic, reqStatic)

	if recStatic.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from /api/oauth/clients/static, got %d: %s", recStatic.Code, recStatic.Body.String())
	}

	var staticClient struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.Unmarshal(recStatic.Body.Bytes(), &staticClient); err != nil {
		t.Fatalf("failed decoding static client JSON: %v", err)
	}

	if !strings.HasPrefix(staticClient.ClientID, "spark-static-client-") {
		t.Errorf("expected static client ID prefix spark-static-client-, got %s", staticClient.ClientID)
	}

	// 2. Authorize with static client prefix matching (Google custom-mcp dynamic redirect URI)
	dynamicURI := "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-12345"
	authForm := url.Values{
		"decision":     {"approve"},
		"client_id":    {staticClient.ClientID},
		"redirect_uri": {dynamicURI},
		"state":        {"xyz-state"},
		"csrf_token":   {csrfToken},
		"preset":       {"read_only"},
	}
	reqAuth := httptest.NewRequest("POST", "/authorize", strings.NewReader(authForm.Encode()))
	reqAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAuth.Header.Set("Cookie", cookieHeader)
	recAuth := httptest.NewRecorder()
	mux.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect from /authorize with static client prefix matching, got %d: %s", recAuth.Code, recAuth.Body.String())
	}

	loc, _ := url.Parse(recAuth.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("expected authorization code in redirect location")
	}

	// 3. Token exchange using client_secret_basic (RFC 6749 §2.3.1 Authorization: Basic ...)
	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {dynamicURI},
	}
	reqToken := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(tokenForm.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqToken.SetBasicAuth(staticClient.ClientID, staticClient.ClientSecret)
	recToken := httptest.NewRecorder()
	mux.ServeHTTP(recToken, reqToken)

	if recToken.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from token exchange using client_secret_basic, got %d: %s", recToken.Code, recToken.Body.String())
	}

	var tokenRes struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(recToken.Body.Bytes(), &tokenRes); err != nil {
		t.Fatalf("failed decoding token response: %v", err)
	}
	if tokenRes.AccessToken == "" {
		t.Error("expected non-empty access_token")
	}

	claims, err := VerifyJWT(tokenRes.AccessToken, &cfg.JWTES256PrivateKey.PublicKey, cfg.ServiceURL, cfg.ServiceURL+"/mcp")
	if err != nil {
		t.Fatalf("JWT verification failed on static client token: %v", err)
	}
	if claims.Subject != "admin:"+adminEmail {
		t.Errorf("expected subject admin:%s, got %s", adminEmail, claims.Subject)
	}
}

func TestPKCEAndJWTVerification(t *testing.T) {
	server, cfg, s := newTestAuthServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// Register client
	client := &store.OAuthClient{
		ClientID:     "test-client-pkce",
		ClientName:   "PKCE Client",
		RedirectURIs: []string{"cursor://callback"},
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = s.SaveOAuthClient(context.Background(), client)

	// PKCE parameters
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := ComputePKCES256(codeVerifier)

	// Setup admin session
	adminEmail := "brendon.ang20011007@gmail.com"
	csrfToken := server.SessionManager().GenerateCSRFToken(adminEmail)

	// Helper to get an authorization code
	getAuthCode := func(challenge string) string {
		authForm := url.Values{
			"decision":              {"approve"},
			"client_id":             {"test-client-pkce"},
			"redirect_uri":          {"cursor://callback"},
			"state":                 {"state123"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
			"csrf_token":            {csrfToken},
			"preset":                {"read_only"},
		}
		reqAuth := httptest.NewRequest("POST", "/authorize", strings.NewReader(authForm.Encode()))
		reqAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		cookieHeader := server.SessionManager().cookieName + "=" + fmt.Sprintf("%s:%d:%s", adminEmail, time.Now().Unix(), server.SessionManager().sign(fmt.Sprintf("%s:%d", adminEmail, time.Now().Unix())))
		reqAuth.Header.Set("Cookie", cookieHeader)
		recAuth := httptest.NewRecorder()
		mux.ServeHTTP(recAuth, reqAuth)
		if recAuth.Code != http.StatusFound {
			t.Fatalf("expected 302 redirect from /authorize, got %d", recAuth.Code)
		}
		redirURL, _ := url.Parse(recAuth.Header().Get("Location"))
		return redirURL.Query().Get("code")
	}

	// 1. Token exchange with INVALID code_verifier -> MUST fail
	badCode := getAuthCode(codeChallenge)
	badTokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"test-client-pkce"},
		"redirect_uri":  {"cursor://callback"},
		"code":          {badCode},
		"code_verifier": {"wrong_code_verifier_123"},
	}
	reqBadToken := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(badTokenForm.Encode()))
	reqBadToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recBadToken := httptest.NewRecorder()
	mux.ServeHTTP(recBadToken, reqBadToken)

	if recBadToken.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for bad PKCE verifier, got %d", recBadToken.Code)
	}

	// 2. Token exchange missing client_id (P0-2) -> MUST fail
	missingCIDCode := getAuthCode(codeChallenge)
	reqMissingCID := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {"cursor://callback"},
		"code":          {missingCIDCode},
		"code_verifier": {codeVerifier},
	}.Encode()))
	reqMissingCID.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recMissingCID := httptest.NewRecorder()
	mux.ServeHTTP(recMissingCID, reqMissingCID)
	if recMissingCID.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for missing client_id, got %d", recMissingCID.Code)
	}

	// 3. Token exchange missing redirect_uri (P0-2) -> MUST fail
	missingRUCode := getAuthCode(codeChallenge)
	reqMissingRU := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"test-client-pkce"},
		"code":          {missingRUCode},
		"code_verifier": {codeVerifier},
	}.Encode()))
	reqMissingRU.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recMissingRU := httptest.NewRecorder()
	mux.ServeHTTP(recMissingRU, reqMissingRU)
	if recMissingRU.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for missing redirect_uri, got %d", recMissingRU.Code)
	}

	// 4. Token exchange with mismatched redirect_uri (P0-2) -> MUST fail
	mismatchedRUCode := getAuthCode(codeChallenge)
	reqMismatchedRU := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"test-client-pkce"},
		"redirect_uri":  {"https://gemini.google.com/wrong"},
		"code":          {mismatchedRUCode},
		"code_verifier": {codeVerifier},
	}.Encode()))
	reqMismatchedRU.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recMismatchedRU := httptest.NewRecorder()
	mux.ServeHTTP(recMismatchedRU, reqMismatchedRU)
	if recMismatchedRU.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for mismatched redirect_uri, got %d", recMismatchedRU.Code)
	}

	// 5. Token exchange with VALID code_verifier and invalid RFC 8707 resource -> MUST fail
	badResCode := getAuthCode(codeChallenge)
	badResourceForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"test-client-pkce"},
		"redirect_uri":  {"cursor://callback"},
		"code":          {badResCode},
		"code_verifier": {codeVerifier},
		"resource":      {"https://attacker.com/api"},
	}
	reqBadRes := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(badResourceForm.Encode()))
	reqBadRes.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recBadRes := httptest.NewRecorder()
	mux.ServeHTTP(recBadRes, reqBadRes)

	if recBadRes.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for invalid resource, got %d", recBadRes.Code)
	}

	// 6. Token exchange with VALID code_verifier, VALID redirect_uri, and VALID resource -> MUST succeed
	goodCode := getAuthCode(codeChallenge)
	validTokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"test-client-pkce"},
		"redirect_uri":  {"cursor://callback"},
		"code":          {goodCode},
		"code_verifier": {codeVerifier},
		"resource":      {cfg.ServiceURL + "/mcp"},
	}
	reqGoodToken := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(validTokenForm.Encode()))
	reqGoodToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recGoodToken := httptest.NewRecorder()
	mux.ServeHTTP(recGoodToken, reqGoodToken)

	if recGoodToken.Code != http.StatusOK {
		t.Fatalf("expected status 200 for valid token exchange, got %d: %s", recGoodToken.Code, recGoodToken.Body.String())
	}

	var tokenRes struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(recGoodToken.Body.Bytes(), &tokenRes); err != nil {
		t.Fatalf("failed parsing token response: %v", err)
	}

	// 7. Verify Access Token JWT signature and audience against public key
	claims, err := VerifyJWT(tokenRes.AccessToken, &cfg.JWTES256PrivateKey.PublicKey, cfg.ServiceURL, cfg.ServiceURL+"/mcp")
	if err != nil {
		t.Fatalf("JWT verification failed: %v", err)
	}
	if claims.Subject != "admin:"+adminEmail {
		t.Errorf("expected subject admin:%s, got %s", adminEmail, claims.Subject)
	}
	if claims.Scopes["github"] != "read_only" {
		t.Errorf("expected github scope read_only, got %s", claims.Scopes["github"])
	}

	// 8. Verify JWKS Endpoint returns matching public key
	reqJWKS := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	recJWKS := httptest.NewRecorder()
	mux.ServeHTTP(recJWKS, reqJWKS)

	if recJWKS.Code != http.StatusOK {
		t.Fatalf("expected status 200 from JWKS, got %d", recJWKS.Code)
	}
	var jwks JWKS
	if err := json.Unmarshal(recJWKS.Body.Bytes(), &jwks); err != nil || len(jwks.Keys) == 0 {
		t.Fatalf("invalid jwks response: %v", err)
	}
	if jwks.Keys[0].Alg != "ES256" || jwks.Keys[0].Crv != "P-256" {
		t.Errorf("unexpected JWK: %+v", jwks.Keys[0])
	}

	// 9. Test Refresh Token Rotation and Replay Revocation
	rt1 := tokenRes.RefreshToken
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt1},
	}

	// First refresh -> succeeds and rotates refresh token
	reqRefresh1 := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(refreshForm.Encode()))
	reqRefresh1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recRefresh1 := httptest.NewRecorder()
	mux.ServeHTTP(recRefresh1, reqRefresh1)

	if recRefresh1.Code != http.StatusOK {
		t.Fatalf("expected status 200 on first refresh, got %d: %s", recRefresh1.Code, recRefresh1.Body.String())
	}
	var refreshRes1 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(recRefresh1.Body.Bytes(), &refreshRes1)
	rt2 := refreshRes1.RefreshToken
	if rt2 == rt1 {
		t.Error("expected refresh token to be rotated to a new string")
	}

	// REPLAY ATTACK: Attacker tries to use already consumed rt1 again!
	reqReplay := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(refreshForm.Encode()))
	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recReplay := httptest.NewRecorder()
	mux.ServeHTTP(recReplay, reqReplay)

	if recReplay.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 on replay of consumed refresh token, got %d", recReplay.Code)
	}
	if !strings.Contains(recReplay.Body.String(), "token family revoked") {
		t.Errorf("expected token family revocation notice, got: %s", recReplay.Body.String())
	}

	// Legitimate client tries to use rt2 -> MUST now be revoked because family was revoked!
	reqLegitAfterReplay := httptest.NewRequest("POST", "/api/oauth/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt2},
	}.Encode()))
	reqLegitAfterReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recLegitAfterReplay := httptest.NewRecorder()
	mux.ServeHTTP(recLegitAfterReplay, reqLegitAfterReplay)

	if recLegitAfterReplay.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 on rt2 after family revocation, got %d", recLegitAfterReplay.Code)
	}
}

func TestAdminDevLoginAndSession(t *testing.T) {
	server, _, _ := newTestAuthServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// 1. Missing email -> 400
	reqMissing := httptest.NewRequest("POST", "/auth/dev/login", strings.NewReader("return_to=/dashboard"))
	reqMissing.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recMissing := httptest.NewRecorder()
	mux.ServeHTTP(recMissing, reqMissing)
	if recMissing.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on missing email, got %d", recMissing.Code)
	}

	// 2. Unauthorized email -> 403 (QA-1)
	unauthForm := url.Values{
		"email":     {"attacker@evil.com"},
		"return_to": {"/dashboard"},
	}
	reqUnauth := httptest.NewRequest("POST", "/auth/dev/login", strings.NewReader(unauthForm.Encode()))
	reqUnauth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusForbidden {
		t.Errorf("expected 403 on unauthorized email, got %d", recUnauth.Code)
	}

	// 3. Authorized email with open redirect payload -> sanitized (P0-1 / QA-1)
	authForm := url.Values{
		"email":     {"brendon.ang20011007@gmail.com"},
		"return_to": {"//attacker.com/evil"},
	}
	reqAuth := httptest.NewRequest("POST", "/auth/dev/login", strings.NewReader(authForm.Encode()))
	reqAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recAuth := httptest.NewRecorder()
	mux.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect from /auth/dev/login, got %d", recAuth.Code)
	}
	loc := recAuth.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected open redirect '//attacker.com/evil' to be sanitized to '/dashboard', got %q", loc)
	}

	cookies := recAuth.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == server.SessionManager().cookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie to be set")
	}

	// Validate session cookie
	reqProtected := httptest.NewRequest("GET", "/dashboard", nil)
	reqProtected.AddCookie(sessionCookie)
	email, err := server.SessionManager().GetAdminSession(reqProtected)
	if err != nil {
		t.Fatalf("failed extracting admin session: %v", err)
	}
	if email != "brendon.ang20011007@gmail.com" {
		t.Errorf("expected default admin email, got %s", email)
	}
}

func TestGoogleOIDCLoginAndVerification(t *testing.T) {
	server, cfg, _ := newTestAuthServer(t)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// 1. GET /auth/google/login sets nonce cookie and returns redirect with signed state
	reqLogin := httptest.NewRequest("GET", "/auth/google/login?return_to=/custom_page", nil)
	recLogin := httptest.NewRecorder()
	mux.ServeHTTP(recLogin, reqLogin)

	if recLogin.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect from /auth/google/login, got %d", recLogin.Code)
	}

	cookies := recLogin.Result().Cookies()
	var oidcCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == server.oidcStateCookieName() {
			oidcCookie = c
			break
		}
	}
	if oidcCookie == nil || oidcCookie.Value == "" {
		t.Fatal("expected OIDC state cookie to be set on /auth/google/login")
	}

	loc, _ := url.Parse(recLogin.Header().Get("Location"))
	stateParam := loc.Query().Get("state")
	if stateParam == "" {
		t.Fatal("expected state parameter in redirect to Google")
	}

	// 2. Callback with missing cookie -> MUST return 403 Forbidden
	reqNoCookie := httptest.NewRequest("GET", "/auth/google/callback?code=test-code&state="+url.QueryEscape(stateParam), nil)
	recNoCookie := httptest.NewRecorder()
	mux.ServeHTTP(recNoCookie, reqNoCookie)
	if recNoCookie.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing OIDC state cookie, got %d", recNoCookie.Code)
	}

	// 3. Callback with tampered state -> MUST return 403 Forbidden
	reqTampered := httptest.NewRequest("GET", "/auth/google/callback?code=test-code&state="+url.QueryEscape(stateParam+"tampered"), nil)
	reqTampered.AddCookie(oidcCookie)
	recTampered := httptest.NewRecorder()
	mux.ServeHTTP(recTampered, reqTampered)
	if recTampered.Code != http.StatusForbidden {
		t.Errorf("expected 403 for tampered state signature, got %d", recTampered.Code)
	}

	// 4. Generate RSA key pair for testing Google ID token RS256 signature verification (P2-2)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating rsa key: %v", err)
	}

	// Convert RSA key to JWK
	nBytes := rsaKey.N.Bytes()
	eBytes := big.NewInt(int64(rsaKey.E)).Bytes()
	testKid := "google-test-kid-1"

	jwkMap := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": testKid,
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}

	// Mock Google JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwkMap)
	}))
	defer jwksServer.Close()
	server.SetGoogleJWKSURL(jwksServer.URL)

	// Helper to sign an RS256 ID Token
	signIDToken := func(key *rsa.PrivateKey, kid, iss, aud, email string, exp int64, emailVerified bool) string {
		header := map[string]string{
			"alg": "RS256",
			"typ": "JWT",
			"kid": kid,
		}
		claims := map[string]interface{}{
			"iss":            iss,
			"aud":            aud,
			"email":          email,
			"email_verified": emailVerified,
			"exp":            exp,
		}
		hb, _ := json.Marshal(header)
		cb, _ := json.Marshal(claims)
		signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
		digest := sha256.Sum256([]byte(signingInput))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	validIDToken := signIDToken(rsaKey, testKid, "https://accounts.google.com", cfg.GoogleOIDCClientID, "brendon.ang20011007@gmail.com", time.Now().Add(time.Hour).Unix(), true)

	// Mock Google Token exchange server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "mock-access-token",
			"id_token":     validIDToken,
		})
	}))
	defer tokenServer.Close()
	server.GoogleTokenURL = tokenServer.URL

	// Execute valid callback
	reqValid := httptest.NewRequest("GET", "/auth/google/callback?code=mock-code&state="+url.QueryEscape(stateParam), nil)
	reqValid.AddCookie(oidcCookie)
	recValid := httptest.NewRecorder()
	mux.ServeHTTP(recValid, reqValid)

	if recValid.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect after successful OIDC login, got %d", recValid.Code)
	}
	if recValid.Header().Get("Location") != "/custom_page" {
		t.Errorf("expected redirect to /custom_page, got %q", recValid.Header().Get("Location"))
	}

	// 5. Verify forged token signature fails verification
	otherRSAKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	forgedToken := signIDToken(otherRSAKey, testKid, "https://accounts.google.com", cfg.GoogleOIDCClientID, "brendon.ang20011007@gmail.com", time.Now().Add(time.Hour).Unix(), true)
	_, err = server.GoogleVerifier.VerifyIDToken(context.Background(), forgedToken, cfg.GoogleOIDCClientID)
	if err == nil {
		t.Error("expected verification error for forged signature")
	}

	// 6. Verify wrong audience fails verification
	wrongAudToken := signIDToken(rsaKey, testKid, "https://accounts.google.com", "wrong-client-id", "brendon.ang20011007@gmail.com", time.Now().Add(time.Hour).Unix(), true)
	_, err = server.GoogleVerifier.VerifyIDToken(context.Background(), wrongAudToken, cfg.GoogleOIDCClientID)
	if err == nil {
		t.Error("expected verification error for audience mismatch")
	}
}
