package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GoogleJWK represents an RSA public key in Google's OIDC certs.
type GoogleJWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// GoogleOIDCVerifier handles RS256 signature verification of Google ID tokens.
type GoogleOIDCVerifier struct {
	jwksURL    string
	httpClient *http.Client
	keysMu     sync.RWMutex
	keys       map[string]*rsa.PublicKey
	expiresAt  time.Time
}

// NewGoogleOIDCVerifier creates an OIDC verifier.
func NewGoogleOIDCVerifier(jwksURL string, client *http.Client) *GoogleOIDCVerifier {
	if jwksURL == "" {
		jwksURL = "https://www.googleapis.com/oauth2/v3/certs"
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &GoogleOIDCVerifier{
		jwksURL:    jwksURL,
		httpClient: client,
		keys:       make(map[string]*rsa.PublicKey),
	}
}

func decodeB64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func (v *GoogleOIDCVerifier) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed fetching google jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("google jwks endpoint returned HTTP %d: %s", resp.StatusCode, string(b))
	}

	var jwks struct {
		Keys []GoogleJWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed parsing google jwks json: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := decodeB64URL(k.N)
		if err != nil {
			continue
		}
		eBytes, err := decodeB64URL(k.E)
		if err != nil {
			continue
		}

		var e int
		for _, b := range eBytes {
			e = (e << 8) | int(b)
		}
		n := new(big.Int).SetBytes(nBytes)

		newKeys[k.Kid] = &rsa.PublicKey{
			N: n,
			E: e,
		}
	}

	v.keysMu.Lock()
	v.keys = newKeys
	v.expiresAt = time.Now().Add(1 * time.Hour)
	v.keysMu.Unlock()

	return nil
}

func (v *GoogleOIDCVerifier) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.keysMu.RLock()
	expired := time.Now().After(v.expiresAt)
	key, ok := v.keys[kid]
	v.keysMu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	// Refresh keys
	if err := v.refreshKeys(ctx); err != nil {
		if ok {
			return key, nil // Fall back to stale key if refresh fails
		}
		return nil, err
	}

	v.keysMu.RLock()
	defer v.keysMu.RUnlock()
	key, ok = v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("public key with kid %q not found in google jwks", kid)
	}
	return key, nil
}

// VerifyIDToken parses and verifies an RS256 Google ID token, returning verified email.
func (v *GoogleOIDCVerifier) VerifyIDToken(ctx context.Context, idToken string, expectedClientID string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid id_token format: must contain 3 parts")
	}

	// 1. Header
	headerBytes, err := decodeB64URL(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid header base64: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("invalid header json: %w", err)
	}
	if header.Alg != "RS256" {
		return "", fmt.Errorf("unsupported id_token alg %q (expected RS256)", header.Alg)
	}

	// 2. Fetch RSA public key by kid
	pubKey, err := v.getKey(ctx, header.Kid)
	if err != nil {
		return "", err
	}

	// 3. Verify RS256 cryptographic signature
	sigBytes, err := decodeB64URL(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid signature base64: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return "", fmt.Errorf("id_token signature verification failed: %w", err)
	}

	// 4. Validate Claims
	payloadBytes, err := decodeB64URL(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid payload base64: %w", err)
	}

	var claims struct {
		Email         string      `json:"email"`
		EmailVerified bool        `json:"email_verified"`
		Audience      interface{} `json:"aud"`
		Issuer        string      `json:"iss"`
		ExpiresAt     int64       `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("invalid payload json: %w", err)
	}

	// Clock skew: 30 seconds tolerance
	now := time.Now().Unix()
	if claims.ExpiresAt <= now-30 {
		return "", errors.New("id_token has expired")
	}

	if claims.Issuer != "accounts.google.com" && claims.Issuer != "https://accounts.google.com" {
		return "", fmt.Errorf("invalid id_token issuer %q", claims.Issuer)
	}

	// Validate Audience (string or array of strings)
	if expectedClientID != "" {
		matchedAud := false
		switch aud := claims.Audience.(type) {
		case string:
			if aud == expectedClientID {
				matchedAud = true
			}
		case []interface{}:
			for _, item := range aud {
				if s, ok := item.(string); ok && s == expectedClientID {
					matchedAud = true
					break
				}
			}
		}
		if !matchedAud {
			return "", fmt.Errorf("id_token audience mismatch: expected %q, got %+v", expectedClientID, claims.Audience)
		}
	}

	if !claims.EmailVerified {
		return "", errors.New("email is not verified")
	}

	if claims.Email == "" {
		return "", errors.New("missing email in id_token")
	}

	return claims.Email, nil
}
