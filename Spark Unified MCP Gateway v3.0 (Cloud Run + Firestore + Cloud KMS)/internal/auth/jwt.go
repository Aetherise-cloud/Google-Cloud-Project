package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Claims represents JWT payload claims for gateway Bearer access tokens.
type Claims struct {
	Issuer    string            `json:"iss"`
	Audience  string            `json:"aud"`
	Subject   string            `json:"sub"`
	ExpiresAt int64             `json:"exp"`
	IssuedAt  int64             `json:"iat"`
	JWTID     string            `json:"jti"`
	Scopes    map[string]string `json:"scopes"` // connector -> mode
}

// JWK represents a public key in JSON Web Key format.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func computeKeyID(pub *ecdsa.PublicKey) string {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	h := sha256.Sum256(append(xBytes, yBytes...))
	return fmt.Sprintf("spark-key-%x", h[:8])
}

// PublicKeyToJWK converts an ECDSA P-256 public key into a JWK.
func PublicKeyToJWK(pub *ecdsa.PublicKey) JWK {
	// P-256 coordinate size is 32 bytes
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	// Pad with leading zeros if shorter than 32 bytes
	xPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	yPadded := make([]byte, byteLen)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Alg: "ES256",
		Use: "sig",
		Kid: computeKeyID(pub),
		X:   base64.RawURLEncoding.EncodeToString(xPadded),
		Y:   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

// SignJWT creates an ES256-signed JWT string.
func SignJWT(priv *ecdsa.PrivateKey, claims *Claims) (string, error) {
	kid := computeKeyID(&priv.PublicKey)
	header := map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	hashed := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed signing token: %w", err)
	}

	// IEEE P1363 signature format: r || s (each 32 bytes for P-256)
	curveBits := priv.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	sig := make([]byte, keyBytes*2)
	copy(sig[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(sig[keyBytes*2-len(sBytes):], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

// VerifyJWT parses and verifies an ES256 JWT against an ECDSA public key.
func VerifyJWT(tokenStr string, pub *ecdsa.PublicKey, expectedIssuer, expectedAudience string) (*Claims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt format: must contain 3 parts")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid jwt header encoding: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid jwt header json: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported jwt alg %q (expected ES256)", header.Alg)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid jwt payload encoding: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid jwt payload json: %w", err)
	}

	// Verify cryptographic signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid jwt signature encoding: %w", err)
	}

	curveBits := pub.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8
	if len(sigBytes) != keyBytes*2 {
		return nil, errors.New("invalid signature length for ES256")
	}

	r := new(big.Int).SetBytes(sigBytes[:keyBytes])
	s := new(big.Int).SetBytes(sigBytes[keyBytes:])

	signingInput := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signingInput))

	if !ecdsa.Verify(pub, hashed[:], r, s) {
		return nil, errors.New("invalid jwt signature")
	}

	// Verify claims
	now := time.Now().Unix()
	if claims.ExpiresAt <= now {
		return nil, errors.New("jwt token has expired")
	}
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid jwt issuer: expected %s, got %s", expectedIssuer, claims.Issuer)
	}
	if expectedAudience != "" && claims.Audience != expectedAudience {
		return nil, fmt.Errorf("invalid jwt audience: expected %s, got %s", expectedAudience, claims.Audience)
	}

	return &claims, nil
}

// ComputePKCES256 returns base64url unpadded SHA256 of code_verifier.
func ComputePKCES256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// VerifyPKCES256 checks if BASE64URL(SHA256(verifier)) == challenge using constant-time comparison.
func VerifyPKCES256(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	computed := ComputePKCES256(verifier)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
