package ui

import "net/http"

// ConnectorView represents the view model for a third-party or keyless connector.
type ConnectorView struct {
	ID           string // "github", "jira", "gcp", "gdk"
	Name         string // "GitHub", "Atlassian Jira", "Google Cloud Run", "Google Developer Knowledge"
	Description  string
	Connected    bool
	KeylessADC   bool   // true for "gcp" and "gdk" (always active, no Connect/Disconnect buttons)
	ScopeMode    string // "read_only", "full_access", or "minimal"
	AccountLabel string // e.g. "octocat", "team.atlassian.net", "group-511516 (Keyless ADC)"
	UpdatedAt    string
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
