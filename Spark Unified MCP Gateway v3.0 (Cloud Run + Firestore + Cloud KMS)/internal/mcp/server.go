package mcp

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"spark-mcp-gateway/internal/auth"
	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/providers"
	"spark-mcp-gateway/internal/store"
	"spark-mcp-gateway/internal/vault"
)

const MaxPayloadBytes = 512 * 1024 // 512 KB

var spotlightTagRegex = regexp.MustCompile(`(?i)<\s*/?\s*untrusted_upstream_data[^>]*>`)

// JSONRPCRequest represents a JSON-RPC 2.0 incoming request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 outgoing response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Server implements the MCP Streamable HTTP JSON-RPC 2.0 endpoint.
type Server struct {
	cfg      *config.Config
	registry *providers.Registry
	vault    *vault.TokenVault
	store    store.Store
	jwtKey   *ecdsa.PublicKey
}

// NewServer creates a new MCP server.
func NewServer(cfg *config.Config, registry *providers.Registry, vault *vault.TokenVault, s store.Store) *Server {
	return &Server{
		cfg:      cfg,
		registry: registry,
		vault:    vault,
		store:    s,
		jwtKey:   &cfg.JWTES256PrivateKey.PublicKey,
	}
}

// ServeHTTP handles /mcp endpoint requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed: MCP Streamable HTTP endpoint requires POST", http.StatusMethodNotAllowed)
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Authenticate Bearer JWT
	claims, err := s.authenticateRequest(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, s.cfg.ServiceURL))
		http.Error(w, fmt.Sprintf(`{"error":"unauthorized","error_description":%q}`, err.Error()), http.StatusUnauthorized)
		return
	}

	// 2. Decode JSON-RPC 2.0 request
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxPayloadBytes))
	if err != nil {
		writeRPCError(w, nil, -32700, "Parse error: unable to read request body")
		return
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, nil, -32700, "Parse error: invalid JSON")
		return
	}

	// Extract admin email from subject ("admin:email")
	adminEmail := strings.TrimPrefix(claims.Subject, "admin:")

	// 3. Dispatch JSON-RPC methods
	switch req.Method {
	case "initialize":
		s.handleInitialize(w, req)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "ping":
		writeRPCResult(w, req.ID, map[string]interface{}{})
	case "tools/list":
		s.handleToolsList(w, r, req, claims, adminEmail)
	case "tools/call":
		s.handleToolsCall(w, r, req, claims, adminEmail)
	default:
		writeRPCError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func (s *Server) authenticateRequest(r *http.Request) (*auth.Claims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, fmt.Errorf("invalid Authorization header format; expected Bearer token")
	}

	tokenStr := strings.TrimSpace(parts[1])
	expectedAudience := s.cfg.ServiceURL + "/mcp"
	return auth.VerifyJWT(tokenStr, s.jwtKey, s.cfg.ServiceURL, expectedAudience)
}

func (s *Server) handleInitialize(w http.ResponseWriter, req JSONRPCRequest) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(req.Params, &params)

	protocolVersion := "2025-06-18"
	if params.ProtocolVersion == "2025-03-26" {
		protocolVersion = "2025-03-26"
	}

	writeRPCResult(w, req.ID, map[string]interface{}{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{
				"listChanged": false,
			},
		},
		"serverInfo": map[string]interface{}{
			"name":    "spark-mcp-gateway",
			"version": "3.0.0",
		},
	})
}

func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request, req JSONRPCRequest, claims *auth.Claims, adminEmail string) {
	allTools := s.registry.ListTools()
	filtered := make([]providers.ToolDefinition, 0)

	// Check connection statuses for 3LO providers
	githubConnected := s.isProviderConnected(r.Context(), adminEmail, "github")
	jiraConnected := s.isProviderConnected(r.Context(), adminEmail, "jira")

	for _, t := range allTools {
		// 1. Check provider connection (unconnected github/jira tools are hidden; gcp & gdk stay active)
		if t.Provider == "github" && !githubConnected {
			continue
		}
		if t.Provider == "jira" && !jiraConnected {
			continue
		}

		// 2. Check scope restrictions granted by token claims
		scopeMode := claims.Scopes[t.Provider]
		if scopeMode == "none" {
			continue
		}

		// If caller's granted scope is read_only, hide mutating tools
		if scopeMode == "read_only" && t.RequiredScope == "full_access" {
			continue
		}

		// If scopes indicate minimal preset, only minimal_baseline tools are exposed
		isMinimal := isMinimalScopes(claims.Scopes)
		if isMinimal && !t.MinimalBaseline {
			continue
		}

		filtered = append(filtered, t)
	}

	writeRPCResult(w, req.ID, map[string]interface{}{
		"tools": filtered,
	})
}

func isMinimalScopes(scopes map[string]string) bool {
	if scopes == nil {
		return false
	}
	gh := scopes["github"]
	jira := scopes["jira"]
	return (gh == "none" || gh == "") && (jira == "none" || jira == "")
}

func (s *Server) isProviderConnected(ctx context.Context, adminEmail, provider string) bool {
	conn, err := s.store.GetConnection(ctx, adminEmail, provider)
	return err == nil && conn != nil
}

func (s *Server) handleToolsCall(w http.ResponseWriter, r *http.Request, req JSONRPCRequest, claims *auth.Claims, adminEmail string) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeRPCError(w, req.ID, -32602, "Invalid params: unable to parse tool call")
		return
	}

	toolDef, ok := s.registry.GetTool(params.Name)
	if !ok {
		writeRPCError(w, req.ID, -32601, fmt.Sprintf("Tool not found: %s", params.Name))
		return
	}

	// 1. Verify Scope Gate at execution time
	scopeMode := claims.Scopes[toolDef.Provider]
	if scopeMode == "none" {
		writeToolError(w, req.ID, fmt.Sprintf("Access denied: token has no permission for provider %s", toolDef.Provider))
		return
	}
	if toolDef.RequiredScope == "full_access" && scopeMode != "full_access" {
		writeToolError(w, req.ID, fmt.Sprintf("Access denied: tool %s requires full_access scope, but token only grants %q", toolDef.Name, scopeMode))
		return
	}
	if isMinimalScopes(claims.Scopes) && !toolDef.MinimalBaseline {
		writeToolError(w, req.ID, fmt.Sprintf("Access denied: minimal scope preset only allows baseline tools"))
		return
	}

	// 2. Obtain provider credentials from TokenVault if required (github or jira)
	var tokenData *vault.TokenData
	if toolDef.Provider == "github" || toolDef.Provider == "jira" {
		tok, err := s.vault.GetValidAccessToken(r.Context(), adminEmail, toolDef.Provider)
		if err != nil {
			writeToolError(w, req.ID, fmt.Sprintf("Provider %s is not connected or credentials expired: %v", toolDef.Provider, err))
			return
		}
		tokenData = tok
	}

	// 3. Execute tool
	rawOutput, err := s.registry.Execute(r.Context(), toolDef.Name, params.Arguments, tokenData)
	if err != nil {
		writeToolError(w, req.ID, fmt.Sprintf("Tool execution error: %v", err))
		return
	}

	// 4. Enforce 512 KB truncation cap
	if len(rawOutput) > MaxPayloadBytes {
		rawOutput = rawOutput[:MaxPayloadBytes] + "\n[...output truncated at 512 KB limit...]"
	}

	// 5. SEC-05 / Anti-prompt-injection: Neutralize any case-insensitive or whitespace breakout tags (P2-4)
	escapedOutput := spotlightTagRegex.ReplaceAllString(rawOutput, "[REDACTED_TAG_ATTEMPT]")

	// 6. Wrap in XML Spotlight boundary
	spotlightText := fmt.Sprintf("<untrusted_upstream_data provider=%q tool=%q>\n%s\n</untrusted_upstream_data>",
		toolDef.Provider, toolDef.Name, escapedOutput)

	writeRPCResult(w, req.ID, map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": spotlightText,
			},
		},
		"isError": false,
	})
}

func writeToolError(w http.ResponseWriter, id interface{}, msg string) {
	writeRPCResult(w, id, map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": msg,
			},
		},
		"isError": true,
	})
}

func writeRPCResult(w http.ResponseWriter, id interface{}, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	})
}
