package providers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/vault"
)

// ToolDefinition describes an MCP tool conforming to MCP JSON Schema specification.
type ToolDefinition struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Provider        string                 `json:"provider"`         // "github", "jira", "gcp", "gdk"
	RequiredScope   string                 `json:"required_scope"`   // "read_only" or "full_access"
	MinimalBaseline bool                   `json:"minimal_baseline"` // true for tools in minimal tier
	InputSchema     map[string]interface{} `json:"inputSchema"`
}

// ToolHandler executes a tool invocation.
type ToolHandler func(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error)

type registeredTool struct {
	def     ToolDefinition
	handler ToolHandler
}

// Registry manages tool definitions and their execution dispatchers.
type Registry struct {
	cfg        *config.Config
	httpClient *http.Client
	tools      map[string]*registeredTool
	adcFunc    func(ctx context.Context) (string, error)

	GitHubBaseURL           string
	JiraBaseURL             string
	CloudRunBaseURL         string
	GDKBaseURL              string
	LoggingBaseURL          string
	StorageBaseURL          string
	ArtifactRegistryBaseURL string
	MonitoringBaseURL       string
	IAMBaseURL              string
	GFlowBaseURL            string
}

// NewRegistry creates and registers all 8 MCP tools.
func NewRegistry(cfg *config.Config, httpClient *http.Client, adcFunc func(ctx context.Context) (string, error)) *Registry {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if adcFunc == nil {
		adcFunc = fetchADCDefault
	}

	r := &Registry{
		cfg:                     cfg,
		httpClient:              httpClient,
		tools:                   make(map[string]*registeredTool),
		adcFunc:                 adcFunc,
		GitHubBaseURL:           "https://api.github.com",
		JiraBaseURL:             "https://api.atlassian.com",
		CloudRunBaseURL:         "https://run.googleapis.com",
		GDKBaseURL:              "https://developerknowledge.googleapis.com",
		LoggingBaseURL:          "https://logging.googleapis.com",
		StorageBaseURL:          "https://storage.googleapis.com",
		ArtifactRegistryBaseURL: "https://artifactregistry.googleapis.com",
		MonitoringBaseURL:       "https://monitoring.googleapis.com",
		IAMBaseURL:              "https://iam.googleapis.com",
		GFlowBaseURL:            "",
	}

	r.registerAllTools()
	r.registerGFlowTools()
	return r
}

func fetchADCDefault(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server unreachable: %w", err)
	}
	defer resp.Body.Close()

	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := parseJSON(resp.Body, &res); err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

func (r *Registry) RegisterTool(def ToolDefinition, handler ToolHandler) {
	r.tools[def.Name] = &registeredTool{
		def:     def,
		handler: handler,
	}
}

// GetTool retrieves a tool definition by name.
func (r *Registry) GetTool(name string) (ToolDefinition, bool) {
	t, ok := r.tools[name]
	if !ok {
		return ToolDefinition{}, false
	}
	return t.def, true
}

// ListTools returns all registered tool definitions.
func (r *Registry) ListTools() []ToolDefinition {
	list := make([]ToolDefinition, 0, len(r.tools))
	for _, t := range r.tools {
		list = append(list, t.def)
	}
	return list
}

// Execute runs a tool with timeout and returns output text.
func (r *Registry) Execute(ctx context.Context, name string, args map[string]interface{}, token *vault.TokenData) (string, error) {
	t, ok := r.tools[name]
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
	}

	// Enforce 15-second execution timeout
	execCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	return t.handler(execCtx, args, token)
}

func getStringArg(args map[string]interface{}, key, fallback string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return fallback
}
