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
	"time"

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
	cfg                  *config.Config
	registry             *providers.Registry
	vault                *vault.TokenVault
	store                store.Store
	jwtKey               *ecdsa.PublicKey
	AllowLoopbackForTest bool
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
		// 1. Check provider connection
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

	// Federate Custom Connectors (custom:<slug>)
	if conns, err := s.store.ListConnections(r.Context(), adminEmail); err == nil {
		for _, conn := range conns {
			if strings.HasPrefix(conn.Provider, "custom:") {
				slug := strings.TrimPrefix(conn.Provider, "custom:")
				tok, err := s.vault.DecryptConnection(r.Context(), conn)
				if err != nil || tok == nil {
					continue
				}

				scopeMode := claims.Scopes[conn.Provider]
				if scopeMode == "none" {
					continue
				}
				if scopeMode == "" {
					if ghScope, ok := claims.Scopes["github"]; ok && ghScope != "" && ghScope != "none" {
						scopeMode = ghScope
					} else if isMinimalScopes(claims.Scopes) && !hasAnyCustomScope(claims.Scopes) {
						continue
					} else {
						scopeMode = "read_only"
					}
				}

				if tok.ConnectorType == "remote_mcp" {
					// P1-3: If custom remote_mcp connector is marked full_access, hide tools unless token has full_access
					if tok.Scope == "full_access" && scopeMode != "full_access" {
						continue
					}
					ctxTimeout, cancel := context.WithTimeout(r.Context(), 5*time.Second)
					client := providers.NewSSRFSafeHTTPClientWithTestOption(5*time.Second, s.AllowLoopbackForTest)
					upstreamTools, err := providers.CallRemoteMCPToolsList(ctxTimeout, client, tok.EndpointURL, tok.AuthHeader, tok.AccessToken)
					cancel()
					if err == nil {
						for _, ut := range upstreamTools {
							if scopeMode == "read_only" && ut.RequiredScope == "full_access" {
								continue
							}
							ut.Name = fmt.Sprintf("%s__%s", slug, ut.Name)
							ut.Provider = conn.Provider
							filtered = append(filtered, ut)
						}
					}
				} else if tok.ConnectorType == "rest_api" {
					filtered = append(filtered, providers.ToolDefinition{
						Name:          fmt.Sprintf("%s_api_request", slug),
						Description:   fmt.Sprintf("Send an authenticated HTTP request to %s (%s)", tok.ConnectorName, tok.EndpointURL),
						Provider:      conn.Provider,
						RequiredScope: "read_only",
						InputSchema: map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"method": map[string]interface{}{
									"type":        "string",
									"description": "HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD)",
								},
								"path": map[string]interface{}{
									"type":        "string",
									"description": "API endpoint path (e.g. /v1/users)",
								},
								"body": map[string]interface{}{
									"type":        "string",
									"description": "Optional request payload (JSON or plain text)",
								},
							},
							"required": []interface{}{"method", "path"},
						},
					})
				}
			}
		}
	}

	writeRPCResult(w, req.ID, map[string]interface{}{
		"tools": filtered,
	})
}

func hasAnyCustomScope(scopes map[string]string) bool {
	for k, v := range scopes {
		if strings.HasPrefix(k, "custom:") && v != "" && v != "none" {
			return true
		}
	}
	return false
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

	// 1. Check if tool call targets a federated custom connector
	isCustomRemoteMCP := strings.Contains(params.Name, "__")
	isCustomREST := strings.HasSuffix(params.Name, "_api_request")

	if isCustomRemoteMCP || isCustomREST {
		var slug, upstreamTool string
		if isCustomRemoteMCP {
			parts := strings.SplitN(params.Name, "__", 2)
			slug = parts[0]
			upstreamTool = parts[1]
		} else {
			slug = strings.TrimSuffix(params.Name, "_api_request")
		}

		providerKey := "custom:" + slug
		conn, err := s.store.GetConnection(r.Context(), adminEmail, providerKey)
		if err != nil || conn == nil {
			writeToolError(w, req.ID, fmt.Sprintf("Custom connector %s not found or disconnected", providerKey))
			return
		}

		tok, err := s.vault.DecryptConnection(r.Context(), conn)
		if err != nil || tok == nil {
			writeToolError(w, req.ID, fmt.Sprintf("Failed decrypting credentials for %s", providerKey))
			return
		}

		scopeMode := claims.Scopes[providerKey]
		if scopeMode == "none" {
			writeToolError(w, req.ID, fmt.Sprintf("Access denied: token has no permission for connector %s", providerKey))
			return
		}
		if scopeMode == "" {
			if ghScope, ok := claims.Scopes["github"]; ok && ghScope != "" && ghScope != "none" {
				scopeMode = ghScope
			} else {
				scopeMode = "read_only"
			}
		}

		httpClient := providers.NewSSRFSafeHTTPClientWithTestOption(15*time.Second, s.AllowLoopbackForTest)
		var rawOutput string

		if isCustomRemoteMCP {
			// P1-3: Enforce connector-level RequiredScope ("full_access") for remote MCP tools
			if tok.Scope == "full_access" && scopeMode != "full_access" {
				writeToolError(w, req.ID, fmt.Sprintf("Access denied: custom remote MCP connector %s requires full_access scope, but token only grants %q", providerKey, scopeMode))
				return
			}
			rawOutput, err = providers.CallRemoteMCPToolsCall(r.Context(), httpClient, tok.EndpointURL, tok.AuthHeader, tok.AccessToken, upstreamTool, params.Arguments)
			if err != nil {
				writeToolError(w, req.ID, fmt.Sprintf("Custom remote MCP error: %v", err))
				return
			}
		} else {
			method := "GET"
			if m, ok := params.Arguments["method"].(string); ok && m != "" {
				method = strings.ToUpper(strings.TrimSpace(m))
			}
			path := "/"
			if p, ok := params.Arguments["path"].(string); ok && p != "" {
				path = strings.TrimSpace(p)
			}
			body := ""
			if b, ok := params.Arguments["body"].(string); ok {
				body = b
			}

			if scopeMode == "read_only" && method != "GET" && method != "HEAD" {
				writeToolError(w, req.ID, fmt.Sprintf("Access denied: method %s requires full_access scope, but token only grants read_only", method))
				return
			}

			rawOutput, err = providers.CallCustomRESTAPI(r.Context(), httpClient, tok.EndpointURL, tok.AuthHeader, tok.AccessToken, method, path, body)
			if err != nil {
				writeToolError(w, req.ID, fmt.Sprintf("Custom REST API error: %v", err))
				return
			}
		}

		if len(rawOutput) > MaxPayloadBytes {
			rawOutput = rawOutput[:MaxPayloadBytes] + "\n[...output truncated at 512 KB limit...]"
		}

		escapedOutput := spotlightTagRegex.ReplaceAllString(rawOutput, "[REDACTED_TAG_ATTEMPT]")
		spotlightText := fmt.Sprintf("<untrusted_upstream_data provider=%q tool=%q>\n%s\n</untrusted_upstream_data>",
			providerKey, params.Name, escapedOutput)

		writeRPCResult(w, req.ID, map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": spotlightText,
				},
			},
			"isError": false,
		})
		return
	}

	// 2. Standard built-in tools
	toolDef, ok := s.registry.GetTool(params.Name)
	if !ok {
		writeRPCError(w, req.ID, -32601, fmt.Sprintf("Tool not found: %s", params.Name))
		return
	}

	// Scope Gate check
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
		writeToolError(w, req.ID, "Access denied: minimal scope preset only allows baseline tools")
		return
	}

	var tokenData *vault.TokenData
	if toolDef.Provider == "github" || toolDef.Provider == "jira" {
		tok, err := s.vault.GetValidAccessToken(r.Context(), adminEmail, toolDef.Provider)
		if err != nil {
			writeToolError(w, req.ID, fmt.Sprintf("Provider %s is not connected or credentials expired: %v", toolDef.Provider, err))
			return
		}
		tokenData = tok
	}

	rawOutput, err := s.registry.Execute(r.Context(), toolDef.Name, params.Arguments, tokenData)
	if err != nil {
		writeToolError(w, req.ID, fmt.Sprintf("Tool execution error: %v", err))
		return
	}

	if len(rawOutput) > MaxPayloadBytes {
		rawOutput = rawOutput[:MaxPayloadBytes] + "\n[...output truncated at 512 KB limit...]"
	}

	escapedOutput := spotlightTagRegex.ReplaceAllString(rawOutput, "[REDACTED_TAG_ATTEMPT]")
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
