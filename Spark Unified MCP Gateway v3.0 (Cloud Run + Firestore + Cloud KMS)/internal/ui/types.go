package ui

import "net/http"

// ConnectorView represents the view model for a third-party or keyless connector.
type ConnectorView struct {
	ID            string // "github", "jira", "gcp", "gdk", or "custom:<slug>"
	Name          string // Display name
	Description   string
	Connected     bool
	KeylessADC    bool   // true for "gcp" and "gdk"
	IsCustom      bool   // true for user-added connectors ("custom:<slug>")
	ConnectorType string // "oauth2", "keyless_adc", "remote_mcp", "rest_api", "pat"
	NeedsConfig   bool   // true when OAuth 2.0 Client ID/Secret is not configured yet
	OAuthConfigOK bool   // true when OAuth 2.0 Client ID/Secret is configured (env or KMS)
	EndpointURL   string // Upstream MCP or REST API base URL for custom connectors
	ScopeMode     string // "read_only", "full_access", or "minimal"
	AccountLabel  string
	UpdatedAt     string
	TemplateID    string // "github", "jira", "slack", "notion", "linear", "cloudflare", "sentry", "supabase", "custom_mcp", "custom_api"

	SelectedOrgs      []string // V4 Workspace Picker: selected GitHub organizations (e.g. ["aetherise-cloud"])
	AllowedReadRepos  []string // V4 Workspace Picker: allowed GitHub read repositories (e.g. ["aetherise-cloud/*"])
	AllowedWriteRepos []string // V4 Workspace Picker: allowed GitHub write repositories (e.g. ["aetherise-cloud/spark-mcp-gateway"])
	AllowedSpaceKeys  []string // V4 Workspace Picker: allowed Jira project/space keys (e.g. ["SPARK", "ONB"])
	SiteName          string   // V4 Workspace Picker: bound Atlassian Jira site name
	CloudID           string   // V4 Workspace Picker: bound Atlassian Jira cloudId
}

// LoginPageData holds data passed to RenderLogin.
type LoginPageData struct {
	ServiceURL   string
	ErrorMessage string
	ReturnTo     string
	DevMode      bool // when true, renders an optional local Dev Sign-In form (POST /auth/dev/login) below Google Sign-In
}

// DashboardPageData holds data passed to RenderDashboard.
type DashboardPageData struct {
	AdminEmail   string
	ServiceURL   string
	MCPEndpoint  string // e.g. ServiceURL + "/mcp"
	CSRFToken    string
	Connectors   []ConnectorView
	FlashMessage string
}

// AuthorizePageData holds data passed to RenderAuthorize.
type AuthorizePageData struct {
	AdminEmail        string
	ServiceURL        string
	ClientID          string
	ClientName        string
	RedirectURI       string
	State             string
	CodeChallenge     string
	CodeChallengeMeth string
	Resource          string
	CSRFToken         string
	IsCustomDCRClient bool
	DefaultPreset     string // "read_only"
	Connectors        []ConnectorView
}

// CallbackPageData holds data passed to RenderOAuthCallback.
type CallbackPageData struct {
	Provider     string // "github" or "jira"
	ProviderName string
	ScopeMode    string // "read_only" or "full_access"
	Success      bool
	ErrorMessage string
}

// RenderLogin renders the login page view (/auth/login).
func RenderLogin(w http.ResponseWriter, status int, data LoginPageData) error {
	return renderTemplate(w, status, loginTmpl, "login.html", data)
}

// RenderDashboard renders the admin dashboard view (/dashboard).
func RenderDashboard(w http.ResponseWriter, status int, data DashboardPageData) error {
	return renderTemplate(w, status, dashboardTmpl, "dashboard.html", data)
}

// RenderAuthorize renders the OAuth 2.1 consent screen view (/authorize).
func RenderAuthorize(w http.ResponseWriter, status int, data AuthorizePageData) error {
	return renderTemplate(w, status, authorizeTmpl, "authorize.html", data)
}

// RenderOAuthCallback renders the OAuth popup callback view (/oauth/callback/{app}).
func RenderOAuthCallback(w http.ResponseWriter, status int, data CallbackPageData) error {
	return renderTemplate(w, status, callbackTmpl, "callback.html", data)
}
