package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FirestoreRESTStore implements Store targeting Google Cloud Firestore REST API v1.
type FirestoreRESTStore struct {
	projectID  string
	databaseID string
	baseURL    string
	httpClient *http.Client
	tokenFunc  func(ctx context.Context) (string, error)
}

// NewFirestoreRESTStore creates a Firestore REST store instance.
func NewFirestoreRESTStore(projectID, databaseID string, httpClient *http.Client, tokenFunc func(ctx context.Context) (string, error)) *FirestoreRESTStore {
	if databaseID == "" {
		databaseID = "(default)"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if tokenFunc == nil {
		tokenFunc = fetchGCEMetadataToken
	}
	return &FirestoreRESTStore{
		projectID:  projectID,
		databaseID: databaseID,
		baseURL:    "https://firestore.googleapis.com/v1",
		httpClient: httpClient,
		tokenFunc:  tokenFunc,
	}
}

// SetBaseURL overrides the default Firestore REST endpoint (used for unit testing with httptest).
func (s *FirestoreRESTStore) SetBaseURL(url string) {
	s.baseURL = strings.TrimSuffix(url, "/")
}

func (s *FirestoreRESTStore) docBase() string {
	return fmt.Sprintf("%s/projects/%s/databases/%s/documents", s.baseURL, s.projectID, s.databaseID)
}

func fetchGCEMetadataToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed reaching GCE metadata server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned status %d", resp.StatusCode)
	}

	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

func (s *FirestoreRESTStore) doRequest(ctx context.Context, method, url string, body any) ([]byte, int, error) {
	token, err := s.tokenFunc(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("auth token error: %w", err)
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return respBytes, resp.StatusCode, nil
}

// SaveOAuthClient stores a registered client with Native TTL (expires_at).
func (s *FirestoreRESTStore) SaveOAuthClient(ctx context.Context, client *OAuthClient) error {
	docURL := fmt.Sprintf("%s/oauth_clients/%s", s.docBase(), client.ClientID)

	redirectValues := make([]map[string]any, len(client.RedirectURIs))
	for i, u := range client.RedirectURIs {
		redirectValues[i] = map[string]any{"stringValue": u}
	}

	fields := map[string]any{
		"client_id":     map[string]any{"stringValue": client.ClientID},
		"client_name":   map[string]any{"stringValue": client.ClientName},
		"client_secret": map[string]any{"stringValue": client.ClientSecret},
		"redirect_uris": map[string]any{"arrayValue": map[string]any{"values": redirectValues}},
		"created_at":    map[string]any{"timestampValue": client.CreatedAt.UTC().Format(time.RFC3339Nano)},
		"expires_at":    map[string]any{"timestampValue": client.ExpiresAt.UTC().Format(time.RFC3339Nano)},
	}

	body := map[string]any{"fields": fields}
	_, status, err := s.doRequest(ctx, "PATCH", docURL, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("firestore save oauth client error: HTTP %d", status)
	}
	return nil
}

// GetOAuthClient retrieves an OAuth client document.
func (s *FirestoreRESTStore) GetOAuthClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	docURL := fmt.Sprintf("%s/oauth_clients/%s", s.docBase(), clientID)
	data, status, err := s.doRequest(ctx, "GET", docURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("firestore get oauth client error: HTTP %d", status)
	}

	var doc struct {
		Fields map[string]map[string]any `json:"fields"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	client := &OAuthClient{
		ClientID:     doc.Fields["client_id"]["stringValue"].(string),
		ClientName:   doc.Fields["client_name"]["stringValue"].(string),
		ClientSecret: doc.Fields["client_secret"]["stringValue"].(string),
	}

	if expStr, ok := doc.Fields["expires_at"]["timestampValue"].(string); ok {
		client.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expStr)
		if !client.ExpiresAt.IsZero() && time.Now().After(client.ExpiresAt) {
			return nil, ErrNotFound
		}
	}

	if arr, ok := doc.Fields["redirect_uris"]["arrayValue"].(map[string]any); ok {
		if vals, ok := arr["values"].([]any); ok {
			for _, v := range vals {
				if vm, ok := v.(map[string]any); ok {
					client.RedirectURIs = append(client.RedirectURIs, vm["stringValue"].(string))
				}
			}
		}
	}

	return client, nil
}

// CountActiveClients counts registered clients.
func (s *FirestoreRESTStore) CountActiveClients(ctx context.Context) (int, error) {
	url := fmt.Sprintf("%s/oauth_clients", s.docBase())
	data, status, err := s.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	if status == http.StatusNotFound {
		return 0, nil
	}
	if status < 200 || status >= 300 {
		return 0, fmt.Errorf("firestore count clients error: HTTP %d", status)
	}

	var res struct {
		Documents []any `json:"documents"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return 0, err
	}
	return len(res.Documents), nil
}

// SaveAuthCode saves a single-use authorization code with Native TTL.
func (s *FirestoreRESTStore) SaveAuthCode(ctx context.Context, code *AuthCode) error {
	docURL := fmt.Sprintf("%s/auth_codes/%s", s.docBase(), code.Code)

	scopeValues := make(map[string]any, len(code.Scopes))
	for k, v := range code.Scopes {
		scopeValues[k] = map[string]any{"stringValue": v}
	}

	fields := map[string]any{
		"code":                  map[string]any{"stringValue": code.Code},
		"client_id":             map[string]any{"stringValue": code.ClientID},
		"admin_email":           map[string]any{"stringValue": code.AdminEmail},
		"redirect_uri":          map[string]any{"stringValue": code.RedirectURI},
		"code_challenge":        map[string]any{"stringValue": code.CodeChallenge},
		"code_challenge_method": map[string]any{"stringValue": code.CodeChallengeMethod},
		"resource":              map[string]any{"stringValue": code.Resource},
		"scopes":                map[string]any{"mapValue": map[string]any{"fields": scopeValues}},
		"created_at":            map[string]any{"timestampValue": code.CreatedAt.UTC().Format(time.RFC3339Nano)},
		"expires_at":            map[string]any{"timestampValue": code.ExpiresAt.UTC().Format(time.RFC3339Nano)},
		"used":                  map[string]any{"booleanValue": code.Used},
	}

	body := map[string]any{"fields": fields}
	_, status, err := s.doRequest(ctx, "PATCH", docURL, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("firestore save auth code error: HTTP %d", status)
	}
	return nil
}

// GetAndConsumeAuthCode marks the authorization code as used atomically.
func (s *FirestoreRESTStore) GetAndConsumeAuthCode(ctx context.Context, codeStr string) (*AuthCode, error) {
	docURL := fmt.Sprintf("%s/auth_codes/%s", s.docBase(), codeStr)
	data, status, err := s.doRequest(ctx, "GET", docURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("firestore get auth code error: HTTP %d", status)
	}

	var doc struct {
		Fields     map[string]map[string]any `json:"fields"`
		UpdateTime string                    `json:"updateTime"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	if used, ok := doc.Fields["used"]["booleanValue"].(bool); ok && used {
		return nil, ErrAlreadyConsumed
	}

	authCode := &AuthCode{
		Code:                codeStr,
		ClientID:            doc.Fields["client_id"]["stringValue"].(string),
		AdminEmail:          doc.Fields["admin_email"]["stringValue"].(string),
		RedirectURI:         doc.Fields["redirect_uri"]["stringValue"].(string),
		CodeChallenge:       doc.Fields["code_challenge"]["stringValue"].(string),
		CodeChallengeMethod: doc.Fields["code_challenge_method"]["stringValue"].(string),
		Resource:            doc.Fields["resource"]["stringValue"].(string),
		Scopes:              make(map[string]string),
	}

	if expStr, ok := doc.Fields["expires_at"]["timestampValue"].(string); ok {
		authCode.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expStr)
		if time.Now().After(authCode.ExpiresAt) {
			return nil, ErrNotFound
		}
	}

	if m, ok := doc.Fields["scopes"]["mapValue"].(map[string]any); ok {
		if fields, ok := m["fields"].(map[string]any); ok {
			for k, v := range fields {
				if vm, ok := v.(map[string]any); ok {
					authCode.Scopes[k] = vm["stringValue"].(string)
				}
			}
		}
	}

	// Atomically mark used
	patchBody := map[string]any{
		"fields": map[string]any{
			"used": map[string]any{"booleanValue": true},
		},
	}
	patchURL := fmt.Sprintf("%s?updateMask.fieldPaths=used&currentDocument.updateTime=%s", docURL, doc.UpdateTime)
	_, patchStatus, err := s.doRequest(ctx, "PATCH", patchURL, patchBody)
	if err != nil {
		return nil, err
	}
	if patchStatus == http.StatusPreconditionFailed {
		return nil, ErrAlreadyConsumed
	}
	if patchStatus < 200 || patchStatus >= 300 {
		return nil, fmt.Errorf("failed to consume auth code: HTTP %d", patchStatus)
	}

	return authCode, nil
}

// SaveRefreshToken saves a hashed refresh token with Native TTL.
func (s *FirestoreRESTStore) SaveRefreshToken(ctx context.Context, record *RefreshTokenRecord) error {
	docURL := fmt.Sprintf("%s/refresh_tokens/%s", s.docBase(), record.TokenHash)

	scopeValues := make(map[string]any, len(record.Scopes))
	for k, v := range record.Scopes {
		scopeValues[k] = map[string]any{"stringValue": v}
	}

	fields := map[string]any{
		"token_hash":  map[string]any{"stringValue": record.TokenHash},
		"family_id":   map[string]any{"stringValue": record.FamilyID},
		"client_id":   map[string]any{"stringValue": record.ClientID},
		"admin_email": map[string]any{"stringValue": record.AdminEmail},
		"resource":    map[string]any{"stringValue": record.Resource},
		"scopes":      map[string]any{"mapValue": map[string]any{"fields": scopeValues}},
		"created_at":  map[string]any{"timestampValue": record.CreatedAt.UTC().Format(time.RFC3339Nano)},
		"expires_at":  map[string]any{"timestampValue": record.ExpiresAt.UTC().Format(time.RFC3339Nano)},
		"revoked":     map[string]any{"booleanValue": record.Revoked},
	}

	body := map[string]any{"fields": fields}
	_, status, err := s.doRequest(ctx, "PATCH", docURL, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("firestore save refresh token error: HTTP %d", status)
	}
	return nil
}

// GetRefreshToken retrieves a refresh token record.
func (s *FirestoreRESTStore) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshTokenRecord, error) {
	docURL := fmt.Sprintf("%s/refresh_tokens/%s", s.docBase(), tokenHash)
	data, status, err := s.doRequest(ctx, "GET", docURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("firestore get refresh token error: HTTP %d", status)
	}

	var doc struct {
		Fields map[string]map[string]any `json:"fields"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	rec := &RefreshTokenRecord{
		TokenHash:  tokenHash,
		FamilyID:   doc.Fields["family_id"]["stringValue"].(string),
		ClientID:   doc.Fields["client_id"]["stringValue"].(string),
		AdminEmail: doc.Fields["admin_email"]["stringValue"].(string),
		Resource:   doc.Fields["resource"]["stringValue"].(string),
		Revoked:    doc.Fields["revoked"]["booleanValue"].(bool),
		Scopes:     make(map[string]string),
	}

	if expStr, ok := doc.Fields["expires_at"]["timestampValue"].(string); ok {
		rec.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expStr)
		if time.Now().After(rec.ExpiresAt) {
			return nil, ErrNotFound
		}
	}

	if m, ok := doc.Fields["scopes"]["mapValue"].(map[string]any); ok {
		if fields, ok := m["fields"].(map[string]any); ok {
			for k, v := range fields {
				if vm, ok := v.(map[string]any); ok {
					rec.Scopes[k] = vm["stringValue"].(string)
				}
			}
		}
	}

	return rec, nil
}

// ConsumeRefreshToken marks a refresh token as revoked.
func (s *FirestoreRESTStore) ConsumeRefreshToken(ctx context.Context, tokenHash string) error {
	docURL := fmt.Sprintf("%s/refresh_tokens/%s?updateMask.fieldPaths=revoked", s.docBase(), tokenHash)
	patchBody := map[string]any{
		"fields": map[string]any{
			"revoked": map[string]any{"booleanValue": true},
		},
	}
	_, status, err := s.doRequest(ctx, "PATCH", docURL, patchBody)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return ErrNotFound
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("firestore consume refresh token error: HTTP %d", status)
	}
	return nil
}

// RevokeTokenFamily revokes all tokens belonging to the specified family.
func (s *FirestoreRESTStore) RevokeTokenFamily(ctx context.Context, familyID string) error {
	// Query tokens by familyID and mark revoked
	queryURL := fmt.Sprintf("%s/refresh_tokens", s.docBase())
	data, status, err := s.doRequest(ctx, "GET", queryURL, nil)
	if err != nil || status != http.StatusOK {
		return nil
	}
	var res struct {
		Documents []struct {
			Name   string                    `json:"name"`
			Fields map[string]map[string]any `json:"fields"`
		} `json:"documents"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return err
	}

	for _, doc := range res.Documents {
		if fam, ok := doc.Fields["family_id"]["stringValue"].(string); ok && fam == familyID {
			patchURL := fmt.Sprintf("%s/%s?updateMask.fieldPaths=revoked", s.baseURL, doc.Name)
			patchBody := map[string]any{
				"fields": map[string]any{
					"revoked": map[string]any{"booleanValue": true},
				},
			}
			_, _, _ = s.doRequest(ctx, "PATCH", patchURL, patchBody)
		}
	}
	return nil
}

// SaveOAuthState saves CSRF state with 10-minute Native TTL.
func (s *FirestoreRESTStore) SaveOAuthState(ctx context.Context, state *OAuthState) error {
	docURL := fmt.Sprintf("%s/oauth_states/%s", s.docBase(), state.State)

	fields := map[string]any{
		"state":         map[string]any{"stringValue": state.State},
		"provider":      map[string]any{"stringValue": state.Provider},
		"mode":          map[string]any{"stringValue": state.Mode},
		"admin_email":   map[string]any{"stringValue": state.AdminEmail},
		"code_verifier": map[string]any{"stringValue": state.CodeVerifier},
		"created_at":    map[string]any{"timestampValue": state.CreatedAt.UTC().Format(time.RFC3339Nano)},
		"expires_at":    map[string]any{"timestampValue": state.ExpiresAt.UTC().Format(time.RFC3339Nano)},
	}

	body := map[string]any{"fields": fields}
	_, status, err := s.doRequest(ctx, "PATCH", docURL, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("firestore save oauth state error: HTTP %d", status)
	}
	return nil
}

// GetAndConsumeOAuthState retrieves and deletes CSRF state.
func (s *FirestoreRESTStore) GetAndConsumeOAuthState(ctx context.Context, stateStr string) (*OAuthState, error) {
	docURL := fmt.Sprintf("%s/oauth_states/%s", s.docBase(), stateStr)
	data, status, err := s.doRequest(ctx, "GET", docURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("firestore get oauth state error: HTTP %d", status)
	}

	var doc struct {
		Fields map[string]map[string]any `json:"fields"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	state := &OAuthState{
		State:        stateStr,
		Provider:     doc.Fields["provider"]["stringValue"].(string),
		Mode:         doc.Fields["mode"]["stringValue"].(string),
		AdminEmail:   doc.Fields["admin_email"]["stringValue"].(string),
		CodeVerifier: doc.Fields["code_verifier"]["stringValue"].(string),
	}

	if expStr, ok := doc.Fields["expires_at"]["timestampValue"].(string); ok {
		state.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expStr)
		if time.Now().After(state.ExpiresAt) {
			return nil, ErrNotFound
		}
	}

	// Delete state
	_, _, _ = s.doRequest(ctx, "DELETE", docURL, nil)
	return state, nil
}

func firestoreConnDocID(userID, provider string) string {
	raw := fmt.Sprintf("%s_%s", userID, provider)
	return strings.ReplaceAll(raw, "@", "_at_")
}

// GetConnection reads an encrypted connection document.
func (s *FirestoreRESTStore) GetConnection(ctx context.Context, userID, provider string) (*EncryptedConnection, error) {
	docID := firestoreConnDocID(userID, provider)
	docURL := fmt.Sprintf("%s/connections/%s", s.docBase(), docID)
	data, status, err := s.doRequest(ctx, "GET", docURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("firestore get connection error: HTTP %d", status)
	}

	var doc struct {
		Fields     map[string]map[string]any `json:"fields"`
		UpdateTime string                    `json:"updateTime"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	return parseConnectionDoc(userID, provider, doc.Fields, doc.UpdateTime)
}

func parseConnectionDoc(userID, provider string, fields map[string]map[string]any, updateTimeStr string) (*EncryptedConnection, error) {
	conn := &EncryptedConnection{
		UserID:        userID,
		Provider:      provider,
		KMSKeyVersion: fields["kms_key_version"]["stringValue"].(string),
	}

	if b64, ok := fields["wrapped_dek"]["bytesValue"].(string); ok {
		conn.WrappedDEK, _ = base64.StdEncoding.DecodeString(b64)
	}
	if b64, ok := fields["nonce"]["bytesValue"].(string); ok {
		conn.Nonce, _ = base64.StdEncoding.DecodeString(b64)
	}
	if b64, ok := fields["ciphertext"]["bytesValue"].(string); ok {
		conn.Ciphertext, _ = base64.StdEncoding.DecodeString(b64)
	}
	if holder, ok := fields["lease_holder"]["stringValue"].(string); ok {
		conn.LeaseHolder = holder
	}
	if leaseExp, ok := fields["lease_expires_at"]["timestampValue"].(string); ok {
		conn.LeaseExpiresAt, _ = time.Parse(time.RFC3339Nano, leaseExp)
	}
	if updateTimeStr != "" {
		conn.UpdateTime, _ = time.Parse(time.RFC3339Nano, updateTimeStr)
	}
	return conn, nil
}

// SaveConnection saves or overwrites an encrypted connection.
func (s *FirestoreRESTStore) SaveConnection(ctx context.Context, conn *EncryptedConnection) error {
	docID := firestoreConnDocID(conn.UserID, conn.Provider)
	docURL := fmt.Sprintf("%s/connections/%s", s.docBase(), docID)

	fields := map[string]any{
		"user_id":          map[string]any{"stringValue": conn.UserID},
		"provider":         map[string]any{"stringValue": conn.Provider},
		"wrapped_dek":      map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(conn.WrappedDEK)},
		"nonce":            map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(conn.Nonce)},
		"ciphertext":       map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(conn.Ciphertext)},
		"kms_key_version":  map[string]any{"stringValue": conn.KMSKeyVersion},
		"lease_holder":     map[string]any{"stringValue": conn.LeaseHolder},
		"lease_expires_at": map[string]any{"timestampValue": conn.LeaseExpiresAt.UTC().Format(time.RFC3339Nano)},
		"updated_at":       map[string]any{"timestampValue": time.Now().UTC().Format(time.RFC3339Nano)},
	}

	body := map[string]any{"fields": fields}
	_, status, err := s.doRequest(ctx, "PATCH", docURL, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("firestore save connection error: HTTP %d", status)
	}
	return nil
}

// DeleteConnection deletes a connection document.
func (s *FirestoreRESTStore) DeleteConnection(ctx context.Context, userID, provider string) error {
	docID := firestoreConnDocID(userID, provider)
	docURL := fmt.Sprintf("%s/connections/%s", s.docBase(), docID)
	_, status, err := s.doRequest(ctx, "DELETE", docURL, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("firestore delete connection error: HTTP %d", status)
	}
	return nil
}

// ListConnections lists all connections for a user.
func (s *FirestoreRESTStore) ListConnections(ctx context.Context, userID string) ([]*EncryptedConnection, error) {
	url := fmt.Sprintf("%s/connections", s.docBase())
	data, status, err := s.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("firestore list connections error: HTTP %d", status)
	}

	var res struct {
		Documents []struct {
			Fields     map[string]map[string]any `json:"fields"`
			UpdateTime string                    `json:"updateTime"`
		} `json:"documents"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}

	var list []*EncryptedConnection
	for _, doc := range res.Documents {
		uid, _ := doc.Fields["user_id"]["stringValue"].(string)
		if uid == userID {
			prov, _ := doc.Fields["provider"]["stringValue"].(string)
			conn, err := parseConnectionDoc(uid, prov, doc.Fields, doc.UpdateTime)
			if err == nil {
				list = append(list, conn)
			}
		}
	}
	return list, nil
}

// AcquireConnectionLease executes an ACID CAS lease update via Firestore beginTransaction + commit.
func (s *FirestoreRESTStore) AcquireConnectionLease(ctx context.Context, userID, provider, instanceID string, leaseDuration time.Duration) (*EncryptedConnection, bool, error) {
	// Begin transaction
	beginURL := fmt.Sprintf("%s/projects/%s/databases/%s/documents:beginTransaction", s.baseURL, s.projectID, s.databaseID)
	txData, status, err := s.doRequest(ctx, "POST", beginURL, map[string]any{})
	if err != nil {
		return nil, false, err
	}
	if status != http.StatusOK {
		return nil, false, fmt.Errorf("failed to begin transaction: HTTP %d", status)
	}

	var txRes struct {
		Transaction string `json:"transaction"`
	}
	if err := json.Unmarshal(txData, &txRes); err != nil {
		return nil, false, err
	}

	// Read connection under transaction
	docID := firestoreConnDocID(userID, provider)
	docURL := fmt.Sprintf("%s/connections/%s?transaction=%s", s.docBase(), docID, txRes.Transaction)
	docBytes, status, err := s.doRequest(ctx, "GET", docURL, nil)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNotFound {
		return nil, false, ErrNotFound
	}
	if status != http.StatusOK {
		return nil, false, fmt.Errorf("failed to read connection under transaction: HTTP %d", status)
	}

	var doc struct {
		Name       string                    `json:"name"`
		Fields     map[string]map[string]any `json:"fields"`
		UpdateTime string                    `json:"updateTime"`
	}
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, false, err
	}

	conn, err := parseConnectionDoc(userID, provider, doc.Fields, doc.UpdateTime)
	if err != nil {
		return nil, false, err
	}

	now := time.Now()
	// Check lease availability
	if conn.LeaseHolder != "" && conn.LeaseExpiresAt.After(now) && conn.LeaseHolder != instanceID {
		return conn, false, nil
	}

	// Commit update with precondition updateTime
	newExpiresAt := now.Add(leaseDuration)
	commitURL := fmt.Sprintf("%s/projects/%s/databases/%s/documents:commit", s.baseURL, s.projectID, s.databaseID)
	commitBody := map[string]any{
		"transaction": txRes.Transaction,
		"writes": []map[string]any{
			{
				"update": map[string]any{
					"name": doc.Name,
					"fields": map[string]any{
						"user_id":          doc.Fields["user_id"],
						"provider":         doc.Fields["provider"],
						"wrapped_dek":      doc.Fields["wrapped_dek"],
						"nonce":            doc.Fields["nonce"],
						"ciphertext":       doc.Fields["ciphertext"],
						"kms_key_version":  doc.Fields["kms_key_version"],
						"lease_holder":     map[string]any{"stringValue": instanceID},
						"lease_expires_at": map[string]any{"timestampValue": newExpiresAt.UTC().Format(time.RFC3339Nano)},
						"updated_at":       map[string]any{"timestampValue": now.UTC().Format(time.RFC3339Nano)},
					},
				},
				"currentDocument": map[string]any{
					"updateTime": doc.UpdateTime,
				},
			},
		},
	}

	_, commitStatus, err := s.doRequest(ctx, "POST", commitURL, commitBody)
	if err != nil {
		return nil, false, err
	}
	if commitStatus == http.StatusPreconditionFailed || commitStatus == http.StatusConflict {
		return conn, false, nil
	}
	if commitStatus != http.StatusOK {
		return nil, false, fmt.Errorf("failed committing lease: HTTP %d", commitStatus)
	}

	conn.LeaseHolder = instanceID
	conn.LeaseExpiresAt = newExpiresAt
	return conn, true, nil
}

// ReleaseConnectionLease commits token updates and releases the distributed lease under ACID transaction, verifying instanceID (P1-2).
func (s *FirestoreRESTStore) ReleaseConnectionLease(ctx context.Context, userID, provider, instanceID string, newConn *EncryptedConnection) error {
	beginURL := fmt.Sprintf("%s/projects/%s/databases/%s/documents:beginTransaction", s.baseURL, s.projectID, s.databaseID)
	txData, status, err := s.doRequest(ctx, "POST", beginURL, map[string]any{})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("failed to begin transaction: HTTP %d", status)
	}

	var txRes struct {
		Transaction string `json:"transaction"`
	}
	if err := json.Unmarshal(txData, &txRes); err != nil {
		return err
	}

	docID := firestoreConnDocID(userID, provider)
	docURL := fmt.Sprintf("%s/connections/%s?transaction=%s", s.docBase(), docID, txRes.Transaction)
	docBytes, status, err := s.doRequest(ctx, "GET", docURL, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return ErrNotFound
	}
	if status != http.StatusOK {
		return fmt.Errorf("failed reading connection under transaction: HTTP %d", status)
	}

	var doc struct {
		Name       string                    `json:"name"`
		Fields     map[string]map[string]any `json:"fields"`
		UpdateTime string                    `json:"updateTime"`
	}
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return err
	}

	existingHolder, _ := doc.Fields["lease_holder"]["stringValue"].(string)
	// Guard: If this instance is no longer the lease holder, do NOT clobber! (P1-2)
	if existingHolder != instanceID {
		return nil
	}

	now := time.Now()
	updateFields := map[string]any{
		"user_id":          doc.Fields["user_id"],
		"provider":         doc.Fields["provider"],
		"lease_holder":     map[string]any{"stringValue": ""},
		"lease_expires_at": map[string]any{"timestampValue": time.Time{}.UTC().Format(time.RFC3339Nano)},
		"updated_at":       map[string]any{"timestampValue": now.UTC().Format(time.RFC3339Nano)},
	}

	if newConn != nil {
		updateFields["wrapped_dek"] = map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(newConn.WrappedDEK)}
		updateFields["nonce"] = map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(newConn.Nonce)}
		updateFields["ciphertext"] = map[string]any{"bytesValue": base64.StdEncoding.EncodeToString(newConn.Ciphertext)}
		updateFields["kms_key_version"] = map[string]any{"stringValue": newConn.KMSKeyVersion}
	} else {
		updateFields["wrapped_dek"] = doc.Fields["wrapped_dek"]
		updateFields["nonce"] = doc.Fields["nonce"]
		updateFields["ciphertext"] = doc.Fields["ciphertext"]
		updateFields["kms_key_version"] = doc.Fields["kms_key_version"]
	}

	commitURL := fmt.Sprintf("%s/projects/%s/databases/%s/documents:commit", s.baseURL, s.projectID, s.databaseID)
	commitBody := map[string]any{
		"transaction": txRes.Transaction,
		"writes": []map[string]any{
			{
				"update": map[string]any{
					"name":   doc.Name,
					"fields": updateFields,
				},
				"currentDocument": map[string]any{
					"updateTime": doc.UpdateTime,
				},
			},
		},
	}

	_, commitStatus, err := s.doRequest(ctx, "POST", commitURL, commitBody)
	if err != nil {
		return err
	}
	if commitStatus != http.StatusOK && commitStatus != http.StatusPreconditionFailed {
		return fmt.Errorf("failed releasing lease: HTTP %d", commitStatus)
	}
	return nil
}
