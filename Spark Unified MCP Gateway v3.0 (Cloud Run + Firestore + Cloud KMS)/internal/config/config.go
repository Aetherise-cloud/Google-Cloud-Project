package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config represents runtime gateway configuration parsed from environment variables.
type Config struct {
	Port                    string
	ServiceURL              string
	GCPProjectID            string
	GCPRegion               string
	FirestoreDatabaseID     string
	StoreBackend            string // "memory" or "firestore"
	KMSKeyName              string
	AdminAllowedEmails      []string
	GoogleOIDCClientID      string
	GoogleOIDCClientSecret  string
	GitHubOAuthClientID     string
	GitHubOAuthClientSecret string
	GitHubAllowedWriteRepos []string
	JiraOAuthClientID       string
	JiraOAuthClientSecret   string
	JWTES256PrivateKey      *ecdsa.PrivateKey
	JWTES256PrivateKeyPEM   string
	SessionHMACKey          []byte
	AllowLocalClients       bool
	DevMode                 bool
}

// LoadFromEnv loads and validates configuration from environment variables.
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		Port:                getEnvOrDefault("PORT", "8080"),
		ServiceURL:          strings.TrimSuffix(getEnvOrDefault("SERVICE_URL", "http://127.0.0.1:8080"), "/"),
		GCPProjectID:        getEnvOrDefault("GCP_PROJECT_ID", getEnvOrDefault("GOOGLE_CLOUD_PROJECT", "spark-mcp-project")),
		GCPRegion:           getEnvOrDefault("GCP_REGION", "asia-southeast1"),
		FirestoreDatabaseID: getEnvOrDefault("FIRESTORE_DATABASE_ID", "spark-mcp-db"),
		StoreBackend:        strings.ToLower(getEnvOrDefault("STORE_BACKEND", "memory")),
		KMSKeyName:          os.Getenv("KMS_KEY_NAME"),
		AllowLocalClients:   parseBool(os.Getenv("ALLOW_LOCAL_CLIENTS"), false),
		DevMode:             parseBool(os.Getenv("DEV_MODE"), false),

		GoogleOIDCClientID:      os.Getenv("GOOGLE_OIDC_CLIENT_ID"),
		GoogleOIDCClientSecret:  os.Getenv("GOOGLE_OIDC_CLIENT_SECRET"),
		GitHubOAuthClientID:     os.Getenv("GITHUB_OAUTH_CLIENT_ID"),
		GitHubOAuthClientSecret: os.Getenv("GITHUB_OAUTH_CLIENT_SECRET"),
		JiraOAuthClientID:       os.Getenv("JIRA_OAUTH_CLIENT_ID"),
		JiraOAuthClientSecret:   os.Getenv("JIRA_OAUTH_CLIENT_SECRET"),
	}

	// Validate service URL
	u, err := url.Parse(cfg.ServiceURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid SERVICE_URL %q: must be valid absolute URL", cfg.ServiceURL)
	}

	// Parse admin allowed emails (default: brendon.ang20011007@gmail.com)
	adminEmailsRaw := os.Getenv("ADMIN_ALLOWED_EMAILS")
	if strings.TrimSpace(adminEmailsRaw) == "" {
		adminEmailsRaw = "brendon.ang20011007@gmail.com"
	}
	for _, e := range strings.Split(adminEmailsRaw, ",") {
		e = strings.TrimSpace(strings.ToLower(e))
		if e != "" {
			cfg.AdminAllowedEmails = append(cfg.AdminAllowedEmails, e)
		}
	}

	// Parse GitHub write allowed repos
	writeReposRaw := os.Getenv("GITHUB_ALLOWED_WRITE_REPOS")
	if strings.TrimSpace(writeReposRaw) != "" {
		for _, r := range strings.Split(writeReposRaw, ",") {
			r = strings.TrimSpace(strings.ToLower(r))
			if r != "" {
				cfg.GitHubAllowedWriteRepos = append(cfg.GitHubAllowedWriteRepos, r)
			}
		}
	}

	// Session HMAC key
	hmacSecret := os.Getenv("SESSION_HMAC_KEY")
	if strings.TrimSpace(hmacSecret) != "" {
		cfg.SessionHMACKey = []byte(hmacSecret)
	} else if cfg.DevMode || cfg.StoreBackend == "memory" {
		// Generate random 32-byte ephemeral key for dev/memory mode
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, fmt.Errorf("failed generating ephemeral session HMAC key: %w", err)
		}
		cfg.SessionHMACKey = k
	} else {
		return nil, errors.New("SESSION_HMAC_KEY environment variable is required in production")
	}

	// ES256 Private Key
	jwtKeyPEM := os.Getenv("JWT_ES256_PRIVATE_KEY")
	if strings.TrimSpace(jwtKeyPEM) != "" {
		key, err := parseECPrivateKeyPEM([]byte(jwtKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("invalid JWT_ES256_PRIVATE_KEY: %w", err)
		}
		cfg.JWTES256PrivateKey = key
		cfg.JWTES256PrivateKeyPEM = jwtKeyPEM
	} else if cfg.DevMode || cfg.StoreBackend == "memory" {
		// Generate ephemeral P-256 key for local dev and tests
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed generating ephemeral ES256 key: %w", err)
		}
		cfg.JWTES256PrivateKey = key
		der, _ := x509.MarshalECPrivateKey(key)
		cfg.JWTES256PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}))
	} else {
		return nil, errors.New("JWT_ES256_PRIVATE_KEY environment variable is required in production")
	}

	// Production hardening guards when DevMode == false (Item 8)
	if !cfg.DevMode {
		if cfg.StoreBackend != "firestore" {
			return nil, errors.New("STORE_BACKEND must be 'firestore' in production (DevMode=false)")
		}
		if strings.TrimSpace(cfg.KMSKeyName) == "" {
			return nil, errors.New("KMS_KEY_NAME environment variable is required in production (DevMode=false)")
		}
		if len(cfg.SessionHMACKey) < 32 {
			return nil, errors.New("SESSION_HMAC_KEY must be at least 32 bytes in production (DevMode=false)")
		}
	}

	return cfg, nil
}

// IsAdminAllowed checks if an email matches the allowed admin list case-insensitively.
func (c *Config) IsAdminAllowed(email string) bool {
	norm := strings.TrimSpace(strings.ToLower(email))
	if norm == "" {
		return false
	}
	for _, a := range c.AdminAllowedEmails {
		if a == norm {
			return true
		}
	}
	return false
}

// IsRepoAllowedForWrite checks if the owner/repo is permitted for mutating operations.
// If GITHUB_ALLOWED_WRITE_REPOS is non-empty, only listed repos are allowed.
func (c *Config) IsRepoAllowedForWrite(owner, repo string) bool {
	if len(c.GitHubAllowedWriteRepos) == 0 {
		return true
	}
	target := strings.ToLower(fmt.Sprintf("%s/%s", strings.TrimSpace(owner), strings.TrimSpace(repo)))
	for _, r := range c.GitHubAllowedWriteRepos {
		if strings.ToLower(r) == target {
			return true
		}
	}
	return false
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseBool(v string, fallback bool) bool {
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func parseECPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed decoding PEM block")
	}

	// Try SEC1 EC private key
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8 private key
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, errors.New("PKCS#8 key is not an ECDSA private key")
	}

	return nil, fmt.Errorf("unable to parse EC private key: %w", err)
}
