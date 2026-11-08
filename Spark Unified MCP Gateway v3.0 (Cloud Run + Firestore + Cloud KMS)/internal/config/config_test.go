package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	// Set DEV_MODE=true so dev defaults (memory store, local keys) can load
	os.Setenv("DEV_MODE", "true")
	defer os.Unsetenv("DEV_MODE")

	os.Unsetenv("PORT")
	os.Unsetenv("SERVICE_URL")
	os.Unsetenv("GCP_PROJECT_ID")
	os.Unsetenv("GCP_REGION")
	os.Unsetenv("FIRESTORE_DATABASE_ID")
	os.Unsetenv("STORE_BACKEND")
	os.Unsetenv("ADMIN_ALLOWED_EMAILS")
	os.Unsetenv("GITHUB_ALLOWED_WRITE_REPOS")
	os.Unsetenv("ALLOW_LOCAL_CLIENTS")
	os.Unsetenv("SESSION_HMAC_KEY")
	os.Unsetenv("JWT_ES256_PRIVATE_KEY")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error loading defaults: %v", err)
	}

	if cfg.Port != "8080" {
		t.Errorf("expected port 8080, got %s", cfg.Port)
	}
	if cfg.ServiceURL != "http://127.0.0.1:8080" {
		t.Errorf("expected service URL http://127.0.0.1:8080, got %s", cfg.ServiceURL)
	}
	if cfg.FirestoreDatabaseID != "spark-mcp-db" {
		t.Errorf("expected db spark-mcp-db, got %s", cfg.FirestoreDatabaseID)
	}
	if cfg.GCPRegion != "asia-southeast1" {
		t.Errorf("expected region asia-southeast1, got %s", cfg.GCPRegion)
	}

	// Test default admin email
	if !cfg.IsAdminAllowed("brendon.ang20011007@gmail.com") {
		t.Error("expected default admin email to be allowed")
	}
	if !cfg.IsAdminAllowed("BRENDON.ANG20011007@GMAIL.COM") {
		t.Error("expected case-insensitive match for admin email")
	}
	if cfg.IsAdminAllowed("intruder@example.com") {
		t.Error("expected unauthorized email to be rejected")
	}

	// All write repos allowed when none specified
	if !cfg.IsRepoAllowedForWrite("owner", "repo") {
		t.Error("expected any repo allowed when write repos list is empty")
	}
}

func TestConfigAllowedWriteRepos(t *testing.T) {
	os.Setenv("DEV_MODE", "true")
	defer os.Unsetenv("DEV_MODE")

	os.Setenv("GITHUB_ALLOWED_WRITE_REPOS", "org/repo1, org/repo2")
	defer os.Unsetenv("GITHUB_ALLOWED_WRITE_REPOS")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.IsRepoAllowedForWrite("org", "repo1") {
		t.Error("expected org/repo1 to be allowed")
	}
	if !cfg.IsRepoAllowedForWrite("ORG", "REPO2") {
		t.Error("expected ORG/REPO2 to be allowed case-insensitively")
	}
	if cfg.IsRepoAllowedForWrite("org", "repo3") {
		t.Error("expected org/repo3 to be disallowed")
	}
}

func TestProductionConfigGuards(t *testing.T) {
	os.Setenv("DEV_MODE", "false")
	defer os.Unsetenv("DEV_MODE")

	// 1. Should fail because STORE_BACKEND is memory
	os.Setenv("STORE_BACKEND", "memory")
	_, err := LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "STORE_BACKEND must be 'firestore'") {
		t.Fatalf("expected STORE_BACKEND error in production, got: %v", err)
	}

	// 2. Set STORE_BACKEND to firestore, should fail on missing KMS_KEY_NAME
	os.Setenv("STORE_BACKEND", "firestore")
	defer os.Unsetenv("STORE_BACKEND")
	os.Setenv("SESSION_HMAC_KEY", "12345678901234567890123456789012") // 32 bytes
	defer os.Unsetenv("SESSION_HMAC_KEY")
	// Provide a valid PEM for JWT_ES256_PRIVATE_KEY
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	os.Setenv("JWT_ES256_PRIVATE_KEY", string(pemBytes))
	defer os.Unsetenv("JWT_ES256_PRIVATE_KEY")
	os.Unsetenv("KMS_KEY_NAME")

	_, err = LoadFromEnv()
	if err == nil || !strings.Contains(err.Error(), "KMS_KEY_NAME") {
		t.Fatalf("expected KMS_KEY_NAME error in production, got: %v", err)
	}
}
