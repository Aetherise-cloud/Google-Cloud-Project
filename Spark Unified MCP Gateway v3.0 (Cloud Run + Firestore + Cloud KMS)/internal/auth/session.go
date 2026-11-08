package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const sessionDuration = 24 * time.Hour

// SessionManager manages admin HTTP session cookies and CSRF tokens.
type SessionManager struct {
	cookieName string
	isSecure   bool
	hmacKey    []byte
}

// NewSessionManager creates a SessionManager.
func NewSessionManager(serviceURL string, hmacKey []byte) *SessionManager {
	isSecure := strings.HasPrefix(strings.ToLower(serviceURL), "https://")
	cookieName := "spark_admin"
	if isSecure {
		cookieName = "__Host-spark_admin"
	}
	return &SessionManager{
		cookieName: cookieName,
		isSecure:   isSecure,
		hmacKey:    hmacKey,
	}
}

func (s *SessionManager) sign(payload string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// SetAdminSession issues a signed session cookie.
func (s *SessionManager) SetAdminSession(w http.ResponseWriter, email string) {
	now := time.Now().Unix()
	payload := fmt.Sprintf("%s:%d", strings.ToLower(email), now)
	sig := s.sign(payload)
	cookieVal := fmt.Sprintf("%s:%s", payload, sig)

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
}

// ClearAdminSession removes the session cookie.
func (s *SessionManager) ClearAdminSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// GetAdminSession extracts and validates the admin session from request cookies.
func (s *SessionManager) GetAdminSession(r *http.Request) (string, error) {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return "", errors.New("unauthenticated: no session cookie")
	}

	parts := strings.Split(c.Value, ":")
	if len(parts) != 3 {
		return "", errors.New("invalid session cookie format")
	}

	email := parts[0]
	tsStr := parts[1]
	providedSig := parts[2]

	expectedSig := s.sign(fmt.Sprintf("%s:%s", email, tsStr))
	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return "", errors.New("invalid session signature")
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", errors.New("invalid session timestamp")
	}

	if time.Now().Unix()-ts > int64(sessionDuration.Seconds()) {
		return "", errors.New("session expired")
	}

	return email, nil
}

// GenerateCSRFToken generates an HMAC-bound CSRF token for the session.
func (s *SessionManager) GenerateCSRFToken(email string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte("csrf:" + strings.ToLower(email)))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateCSRFToken checks the CSRF token using constant-time comparison.
func (s *SessionManager) ValidateCSRFToken(token, email string) bool {
	if token == "" || email == "" {
		return false
	}
	expected := s.GenerateCSRFToken(email)
	return hmac.Equal([]byte(token), []byte(expected))
}
