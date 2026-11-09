package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"spark-mcp-gateway/internal/auth"
	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/logging"
	"spark-mcp-gateway/internal/mcp"
	"spark-mcp-gateway/internal/oauthbroker"
	"spark-mcp-gateway/internal/providers"
	"spark-mcp-gateway/internal/store"
	"spark-mcp-gateway/internal/vault"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	logger := logging.NewLogger(cfg.GCPProjectID, os.Stdout)
	logger.Info(fmt.Sprintf("Starting Spark MCP Gateway v3.0 on port %s (DevMode=%v, Store=%s)", cfg.Port, cfg.DevMode, cfg.StoreBackend), nil)

	// Initialize Store
	var st store.Store
	if cfg.StoreBackend == "firestore" {
		logger.Info(fmt.Sprintf("Connecting to Firestore database %s in project %s", cfg.FirestoreDatabaseID, cfg.GCPProjectID), nil)
		st = store.NewFirestoreRESTStore(cfg.GCPProjectID, cfg.FirestoreDatabaseID, nil, nil)
	} else {
		logger.Info("Using in-memory concurrency-safe Store", nil)
		st = store.NewMemoryStore()
	}

	// Initialize KMS
	var kms vault.KMSClient
	if cfg.KMSKeyName != "" {
		logger.Info(fmt.Sprintf("Using Cloud KMS key: %s", cfg.KMSKeyName), nil)
		kms = vault.NewCloudKMSClient(nil, nil)
	} else {
		logger.Info("Using Local AEAD KMS master key", nil)
		localKMS, err := vault.NewLocalAEADKMS(cfg.SessionHMACKey)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed initializing Local AEAD KMS: %v", err), nil)
			os.Exit(1)
		}
		kms = localKMS
	}

	// Provider token refresh handler for distributed TokenVault
	var broker *oauthbroker.Broker
	refreshFunc := func(ctx context.Context, provider string, cur *vault.TokenData) (*vault.TokenData, error) {
		if provider == "jira" {
			return refreshJiraToken(ctx, cfg, broker, cur)
		}
		return nil, fmt.Errorf("provider %s does not support token refresh", provider)
	}

	tokenVault := vault.NewTokenVault("", st, kms, cfg.KMSKeyName, refreshFunc)
	toolRegistry := providers.NewRegistry(cfg, nil, nil)
	authServer := auth.NewOAuthServer(cfg, st, nil)
	authServer.SetTokenVault(tokenVault)
	broker = oauthbroker.NewBroker(cfg, st, tokenVault, authServer.SessionManager(), nil)
	mcpServer := mcp.NewServer(cfg, toolRegistry, tokenVault, st)

	mux := http.NewServeMux()

	// Health check endpoints: /health and /healthz
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","version":"3.0.0","service":"spark-mcp-gateway"}`))
	}
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /healthz", healthHandler)

	// Wire Auth & OAuth 2.1 routes
	authServer.RegisterRoutes(mux)

	// Wire OAuth broker routes (/dashboard, /oauth/connect/..., /oauth/callback/..., /api/connections)
	broker.RegisterRoutes(mux)

	// Wire MCP Streamable HTTP endpoint
	mux.Handle("/mcp", mcpServer)

	// Security headers and logging middleware with anti-503 JSON-RPC error protection
	handler := securityHeadersMiddleware(logger.HTTPMiddleware(mcp.JSONErrorMiddleware(mux)))

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info(fmt.Sprintf("Gateway HTTP server listening at %s (ServiceURL: %s)", server.Addr, cfg.ServiceURL), nil)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error(fmt.Sprintf("HTTP server error: %v", err), nil)
			os.Exit(1)
		}
	}()

	sig := <-stop
	logger.Info(fmt.Sprintf("Received shutdown signal (%s), draining active connections...", sig), nil)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error(fmt.Sprintf("Server graceful shutdown failed: %v", err), nil)
	} else {
		logger.Info("Server stopped cleanly.", nil)
	}
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func refreshJiraToken(ctx context.Context, cfg *config.Config, broker *oauthbroker.Broker, cur *vault.TokenData) (*vault.TokenData, error) {
	if cur.RefreshToken == "" {
		return nil, errors.New("no refresh token available for Jira")
	}

	clientID := cfg.JiraOAuthClientID
	clientSecret := cfg.JiraOAuthClientSecret
	if broker != nil {
		if id, sec, _ := broker.ResolveOAuthCredentials(ctx, "jira"); id != "" && sec != "" {
			clientID = id
			clientSecret = sec
		}
	}

	payload := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"refresh_token": cur.RefreshToken,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://auth.atlassian.com/oauth/token", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jira token refresh HTTP %d", resp.StatusCode)
	}

	var res struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	return &vault.TokenData{
		AccessToken:       res.AccessToken,
		RefreshToken:      res.RefreshToken,
		ConnectorType:     "oauth2",
		ExpiresAt:         time.Now().Add(time.Duration(res.ExpiresIn) * time.Second),
		Scope:             cur.Scope,
		CloudID:           cur.CloudID,
		SiteURL:           cur.SiteURL,
		SiteName:          cur.SiteName,
		AccountLabel:      cur.AccountLabel,
		SelectedOrgs:      cur.SelectedOrgs,
		AllowedReadRepos:  cur.AllowedReadRepos,
		AllowedWriteRepos: cur.AllowedWriteRepos,
		AllowedSpaceKeys:  cur.AllowedSpaceKeys,
		UpdatedAt:         time.Now(),
	}, nil
}
