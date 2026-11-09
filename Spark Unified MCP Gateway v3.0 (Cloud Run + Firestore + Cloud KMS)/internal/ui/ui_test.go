package ui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"spark-mcp-gateway/internal/ui"
)

// assertSecurityHeaders verifies all required security headers on the response.
func assertSecurityHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	expectedHeaders := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Cache-Control":           "no-store",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'",
	}

	for header, expectedVal := range expectedHeaders {
		got := rec.Header().Get(header)
		if got != expectedVal {
			t.Errorf("Header %q: expected %q, got %q", header, expectedVal, got)
		}
	}

	// Specifically verify CSP has frame-ancestors 'none'
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP header must contain frame-ancestors 'none', got %q", csp)
	}
}

func TestRenderLogin(t *testing.T) {
	t.Run("Standard render without dev mode", func(t *testing.T) {
		rec := httptest.NewRecorder()
		data := ui.LoginPageData{
			ServiceURL:   "https://spark-gateway.internal",
			ErrorMessage: "",
			ReturnTo:     "/dashboard",
			DevMode:      false,
		}

		err := ui.RenderLogin(rec, http.StatusOK, data)
		if err != nil {
			t.Fatalf("RenderLogin failed: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		assertSecurityHeaders(t, rec)

		body := rec.Body.String()
		if !strings.Contains(body, "Spark Unified MCP Gateway v3.0") {
			t.Errorf("expected body to contain title")
		}
		if !strings.Contains(body, "Sign in with Google OIDC") {
			t.Errorf("expected body to contain Google sign-in button")
		}
		if !strings.Contains(body, "/auth/google/login?return_to=%2Fdashboard") {
			t.Errorf("expected URL-encoded return_to parameter in google login link")
		}
		if strings.Contains(body, "Local Dev Mode Sign-In") {
			t.Errorf("dev mode form should not be present when DevMode=false")
		}
	})

	t.Run("Render with DevMode enabled", func(t *testing.T) {
		rec := httptest.NewRecorder()
		data := ui.LoginPageData{
			ServiceURL:   "https://spark-gateway.internal",
			ErrorMessage: "",
			ReturnTo:     "/authorize?client_id=test",
			DevMode:      true,
		}

		err := ui.RenderLogin(rec, http.StatusOK, data)
		if err != nil {
			t.Fatalf("RenderLogin failed: %v", err)
		}

		assertSecurityHeaders(t, rec)

		body := rec.Body.String()
		if !strings.Contains(body, "Local Dev Mode Sign-In") {
			t.Errorf("expected dev mode banner when DevMode=true")
		}
		if !strings.Contains(body, `action="/auth/dev/login"`) {
			t.Errorf("expected dev login form targeting /auth/dev/login")
		}
		if !strings.Contains(body, `name="return_to" value="/authorize?client_id=test"`) {
			t.Errorf("expected hidden return_to input")
		}
	})

	t.Run("XSS auto-escaping in ErrorMessage", func(t *testing.T) {
		rec := httptest.NewRecorder()
		data := ui.LoginPageData{
			ServiceURL:   "https://spark-gateway.internal",
			ErrorMessage: "<img src=x onerror=alert(1)>",
			ReturnTo:     "/dashboard",
			DevMode:      false,
		}

		err := ui.RenderLogin(rec, http.StatusBadRequest, data)
		if err != nil {
			t.Fatalf("RenderLogin failed: %v", err)
		}

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rec.Code)
		}

		body := rec.Body.String()
		if strings.Contains(body, "<img src=x onerror=alert(1)>") {
			t.Errorf("raw XSS payload detected in HTML response")
		}
		if !strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
			t.Errorf("expected HTML-escaped error message")
		}
	})
}

func TestRenderDashboard(t *testing.T) {
	connectors := []ui.ConnectorView{
		{
			ID:           "gcp",
			Name:         "Google Cloud Run",
			Description:  "Read and inspect Cloud Run services across regional clusters",
			Connected:    true,
			KeylessADC:   true,
			ScopeMode:    "read_only",
			AccountLabel: "spark-mcp-sa@project.iam.gserviceaccount.com (Keyless ADC)",
			UpdatedAt:    "2026-11-08T12:00:00Z",
		},
		{
			ID:           "gdk",
			Name:         "Google Developer Knowledge",
			Description:  "Official Google Developer reference documents and query engine",
			Connected:    true,
			KeylessADC:   true,
			ScopeMode:    "read_only",
			AccountLabel: "spark-mcp-sa@project.iam.gserviceaccount.com (Keyless ADC)",
			UpdatedAt:    "2026-11-08T12:00:00Z",
		},
		{
			ID:           "github",
			Name:         "GitHub",
			Description:  "GitHub repository, issue, and code search integration",
			Connected:    true,
			KeylessADC:   false,
			ScopeMode:    "read_only",
			AccountLabel: "octocat",
			UpdatedAt:    "2026-11-08T14:00:00Z",
		},
		{
			ID:           "jira",
			Name:         "Atlassian Jira",
			Description:  "Jira workspace issue and project tracking",
			Connected:    false,
			KeylessADC:   false,
			ScopeMode:    "read_only",
			AccountLabel: "",
			UpdatedAt:    "",
		},
	}

	rec := httptest.NewRecorder()
	data := ui.DashboardPageData{
		AdminEmail:   "admin@example.com",
		ServiceURL:   "https://gateway.example.com",
		MCPEndpoint:  "https://gateway.example.com/mcp",
		CSRFToken:    "test-csrf-token-12345",
		Connectors:   connectors,
		FlashMessage: "Connected to GitHub successfully",
	}

	err := ui.RenderDashboard(rec, http.StatusOK, data)
	if err != nil {
		t.Fatalf("RenderDashboard failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	assertSecurityHeaders(t, rec)

	body := rec.Body.String()

	// Admin email and logout form
	if !strings.Contains(body, "admin@example.com") {
		t.Errorf("expected admin email in dashboard header")
	}
	if !strings.Contains(body, `action="/auth/logout"`) {
		t.Errorf("expected logout form")
	}
	if !strings.Contains(body, `value="test-csrf-token-12345"`) {
		t.Errorf("expected CSRF token in logout form")
	}

	// MCP Endpoint banner
	if !strings.Contains(body, "https://gateway.example.com/mcp") {
		t.Errorf("expected MCP endpoint to be rendered")
	}
	if !strings.Contains(body, "Gemini Spark / Cursor Direct-Link Endpoint") {
		t.Errorf("expected endpoint banner title")
	}

	// Flash message
	if !strings.Contains(body, "Connected to GitHub successfully") {
		t.Errorf("expected flash message banner")
	}

	// Keyless ADC Connectors
	if !strings.Contains(body, "Active (Keyless ADC)") {
		t.Errorf("expected Keyless ADC badge")
	}
	if !strings.Contains(body, "spark-mcp-sa@project.iam.gserviceaccount.com (Keyless ADC)") {
		t.Errorf("expected Keyless ADC account label")
	}

	// OAuth Connectors
	if !strings.Contains(body, "badge-connected") || !strings.Contains(body, "Connected") {
		t.Errorf("expected Connected status badge for github")
	}
	if !strings.Contains(body, "badge-disconnected") || !strings.Contains(body, "Not Connected") {
		t.Errorf("expected Not Connected status badge for jira")
	}
	if !strings.Contains(body, `/api/connections/github/disconnect`) {
		t.Errorf("expected disconnect form for connected github")
	}
	// Jira should have Connect button, not Disconnect
	if strings.Contains(body, `/api/connections/jira/disconnect`) {
		t.Errorf("disconnected Jira should not have disconnect form")
	}

	// Strict postMessage listener check
	if !strings.Contains(body, "if (event.origin !== window.location.origin) return;") {
		t.Errorf("expected strict window.location.origin check in event listener")
	}
	if !strings.Contains(body, "event.data.type === 'spark-mcp-connected'") {
		t.Errorf("expected check for spark-mcp-connected message event")
	}

	// Ensure NO insecure postMessage wildcard
	if strings.Contains(body, `postMessage("*")`) || strings.Contains(body, `postMessage('*')`) ||
		strings.Contains(body, `postMessage(`) && strings.Contains(body, `*`) {
		t.Errorf("insecure wildcard postMessage detected")
	}
}

func TestRenderDashboard_MarketplaceAndCatalog(t *testing.T) {
	connectors := []ui.ConnectorView{
		{
			ID:            "github",
			Name:          "GitHub",
			Description:   "GitHub repository, issue, and code search integration",
			Connected:     false,
			NeedsConfig:   true,
			ConnectorType: "oauth2",
		},
		{
			ID:            "jira",
			Name:          "Atlassian Jira",
			Description:   "Jira workspace issue and project tracking",
			Connected:     true,
			NeedsConfig:   false,
			AccountLabel:  "team.atlassian.net",
			ConnectorType: "oauth2",
		},
		{
			ID:            "custom:linear",
			Name:          "Linear",
			Description:   "Linear issues via Remote MCP",
			Connected:     true,
			IsCustom:      true,
			ConnectorType: "remote_mcp",
			EndpointURL:   "https://mcp.linear.app/mcp",
			ScopeMode:     "read_only",
			TemplateID:    "linear",
		},
	}

	rec := httptest.NewRecorder()
	data := ui.DashboardPageData{
		AdminEmail:  "admin@example.com",
		ServiceURL:  "https://gateway.example.com",
		MCPEndpoint: "https://gateway.example.com/mcp",
		CSRFToken:   "csrf-marketplace-token",
		Connectors:  connectors,
	}

	err := ui.RenderDashboard(rec, http.StatusOK, data)
	if err != nil {
		t.Fatalf("RenderDashboard failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	assertSecurityHeaders(t, rec)
	body := rec.Body.String()

	// + Add Connector button
	if !strings.Contains(body, "+ Add Connector") || !strings.Contains(body, "openCatalogModal()") {
		t.Errorf("expected + Add Connector button invoking openCatalogModal()")
	}

	// Gemini Setup Guide button
	if !strings.Contains(body, "Gemini Setup Guide") || !strings.Contains(body, "openClientGuideModal()") {
		t.Errorf("expected Gemini Setup Guide button in direct-link banner")
	}

	// NeedsConfig warning badge on GitHub
	if !strings.Contains(body, "Needs OAuth Setup") {
		t.Errorf("expected Needs OAuth Setup badge for connector with NeedsConfig=true")
	}

	// Connect button on NeedsConfig opens setup modal
	if !strings.Contains(body, `onclick="openSetupModal('github')"`) {
		t.Errorf("expected Connect button on unconfigured GitHub to open setup modal")
	}

	// Tutorial & Configure button on built-in cards
	if !strings.Contains(body, "Tutorial &amp; Configure") {
		t.Errorf("expected Tutorial & Configure button on connector card")
	}

	// Custom connector rendering
	if !strings.Contains(body, "https://mcp.linear.app/mcp") {
		t.Errorf("expected custom connector endpoint URL to be rendered in meta")
	}
	if !strings.Contains(body, "Tutorial &amp; Edit") {
		t.Errorf("expected Tutorial & Edit button on custom connector card")
	}
	if !strings.Contains(body, `/api/connections/custom:linear/disconnect`) {
		t.Errorf("expected disconnect/remove form for custom connector")
	}

	// Verify Catalog Modal templates
	expectedTemplates := []string{
		"data-name=\"github\"",
		"data-name=\"atlassian jira\"",
		"data-name=\"linear\"",
		"data-name=\"notion\"",
		"data-name=\"slack\"",
		"data-name=\"cloudflare\"",
		"data-name=\"sentry\"",
		"data-name=\"supabase\"",
		"data-name=\"custom remote mcp server\"",
		"data-name=\"custom rest api connector\"",
	}
	for _, tpl := range expectedTemplates {
		if !strings.Contains(body, tpl) {
			t.Errorf("missing catalog connector template: %s", tpl)
		}
	}

	// Verify Setup Modal elements
	if !strings.Contains(body, "id=\"setup-modal\"") {
		t.Errorf("expected setup modal dialog")
	}
	if !strings.Contains(body, "Quick Connect (Personal Access Token)") {
		t.Errorf("expected GitHub PAT tab")
	}
	if !strings.Contains(body, "OAuth 2.0 App (Popup Flow)") {
		t.Errorf("expected GitHub OAuth tab")
	}
	if !strings.Contains(body, "https://gateway.example.com/oauth/callback/github") {
		t.Errorf("expected GitHub OAuth callback URL snippet")
	}
	if !strings.Contains(body, "https://gateway.example.com/oauth/callback/jira") {
		t.Errorf("expected Jira OAuth callback URL snippet")
	}

	// Verify Client Setup Guide Modal elements
	if !strings.Contains(body, "id=\"client-guide-modal\"") {
		t.Errorf("expected client guide modal dialog")
	}
	if !strings.Contains(body, "btn-gen-static-client") {
		t.Errorf("expected static OAuth client generator button")
	}
}

func TestRenderAuthorize(t *testing.T) {
	connectors := []ui.ConnectorView{
		{
			ID:         "gcp",
			Name:       "Google Cloud Run",
			Connected:  true,
			KeylessADC: true,
			ScopeMode:  "read_only",
		},
		{
			ID:         "github",
			Name:       "GitHub",
			Connected:  true,
			KeylessADC: false,
			ScopeMode:  "read_only",
		},
	}

	t.Run("Default preset read_only and hidden OAuth parameters", func(t *testing.T) {
		rec := httptest.NewRecorder()
		data := ui.AuthorizePageData{
			AdminEmail:        "admin@example.com",
			ServiceURL:        "https://gateway.example.com",
			ClientID:          "cursor-mcp-client-id",
			ClientName:        "Cursor IDE MCP Client",
			RedirectURI:       "http://127.0.0.1:45123/callback",
			State:             "xyzState123",
			CodeChallenge:     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			CodeChallengeMeth: "S256",
			Resource:          "https://gateway.example.com/mcp",
			CSRFToken:         "csrf-token-auth",
			IsCustomDCRClient: false,
			DefaultPreset:     "read_only",
			Connectors:        connectors,
		}

		err := ui.RenderAuthorize(rec, http.StatusOK, data)
		if err != nil {
			t.Fatalf("RenderAuthorize failed: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		assertSecurityHeaders(t, rec)

		body := rec.Body.String()

		// Hidden form inputs
		expectedHidden := []string{
			`name="csrf_token" value="csrf-token-auth"`,
			`name="client_id" value="cursor-mcp-client-id"`,
			`name="redirect_uri" value="http://127.0.0.1:45123/callback"`,
			`name="state" value="xyzState123"`,
			`name="code_challenge" value="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"`,
			`name="code_challenge_method" value="S256"`,
			`name="resource" value="https://gateway.example.com/mcp"`,
		}
		for _, field := range expectedHidden {
			if !strings.Contains(body, field) {
				t.Errorf("missing expected hidden field in authorize form: %s", field)
			}
		}

		// Client details
		if !strings.Contains(body, "Cursor IDE MCP Client") {
			t.Errorf("expected client name")
		}
		if !strings.Contains(body, "cursor-mcp-client-id") {
			t.Errorf("expected client ID")
		}

		// Scope presets
		if !strings.Contains(body, `value="minimal"`) {
			t.Errorf("expected minimal preset option")
		}
		if !strings.Contains(body, `value="read_only"`) {
			t.Errorf("expected read_only preset option")
		}
		if !strings.Contains(body, `value="full_access"`) {
			t.Errorf("expected full_access preset option")
		}
		if !strings.Contains(body, `value="custom"`) {
			t.Errorf("expected custom preset option")
		}

		// Decision submit buttons
		if !strings.Contains(body, `name="decision" value="approve"`) {
			t.Errorf("expected approve button")
		}
		if !strings.Contains(body, `name="decision" value="deny"`) {
			t.Errorf("expected deny button")
		}

		// IsCustomDCRClient=false should NOT show DCR warning
		if strings.Contains(body, "Unverified Dynamic Client (RFC 7591)") {
			t.Errorf("unverified DCR warning should NOT be shown for standard client")
		}

		// Strict origin check in event listener
		if !strings.Contains(body, "if (event.origin !== window.location.origin) return;") {
			t.Errorf("expected strict window.location.origin check in authorize event listener")
		}
	})

	t.Run("Custom DCR Client renders RFC 7591 warning badge", func(t *testing.T) {
		rec := httptest.NewRecorder()
		data := ui.AuthorizePageData{
			AdminEmail:        "admin@example.com",
			ServiceURL:        "https://gateway.example.com",
			ClientID:          "dcr-client-999",
			ClientName:        "Untrusted Agent Client",
			RedirectURI:       "https://untrusted.app/oauth/callback",
			State:             "state123",
			CodeChallenge:     "challenge123",
			CodeChallengeMeth: "S256",
			CSRFToken:         "csrf-dcr",
			IsCustomDCRClient: true,
			DefaultPreset:     "minimal",
			Connectors:        connectors,
		}

		err := ui.RenderAuthorize(rec, http.StatusOK, data)
		if err != nil {
			t.Fatalf("RenderAuthorize failed: %v", err)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "Unverified Dynamic Client (RFC 7591)") {
			t.Errorf("expected RFC 7591 warning badge for IsCustomDCRClient=true")
		}
	})

	t.Run("Preset selection rendering for all modes", func(t *testing.T) {
		presets := []string{"", "read_only", "minimal", "full_access", "custom"}
		for _, preset := range presets {
			rec := httptest.NewRecorder()
			data := ui.AuthorizePageData{
				AdminEmail:    "admin@example.com",
				ClientID:      "client-1",
				ClientName:    "Test Client",
				RedirectURI:   "https://client.example.com/cb",
				DefaultPreset: preset,
				Connectors:    connectors,
			}

			if err := ui.RenderAuthorize(rec, http.StatusOK, data); err != nil {
				t.Fatalf("preset %q failed: %v", preset, err)
			}

			body := rec.Body.String()
			targetPreset := preset
			if targetPreset == "" {
				targetPreset = "read_only"
			}
			expectedCheckedFragment := `id="preset-` + targetPreset + `"`
			if !strings.Contains(body, expectedCheckedFragment) {
				t.Errorf("preset %q was not rendered in output", preset)
			}

			// Verify that the radio for targetPreset has 'checked'
			lines := strings.Split(body, "\n")
			matched := false
			for i, line := range lines {
				if strings.Contains(line, expectedCheckedFragment) {
					combined := line
					if i+1 < len(lines) {
						combined += " " + lines[i+1]
					}
					if strings.Contains(combined, "checked") {
						matched = true
						break
					}
				}
			}
			if !matched {
				t.Errorf("expected preset %q to have 'checked' attribute", targetPreset)
			}
		}
	})

	t.Run("XSS auto-escaping across multiple fields", func(t *testing.T) {
		rec := httptest.NewRecorder()
		data := ui.AuthorizePageData{
			AdminEmail:        "<script>admin@example.com</script>",
			ServiceURL:        "https://gateway.example.com",
			ClientID:          "\" onfocus=\"alert(1)",
			ClientName:        "<script>alert('client')</script>",
			RedirectURI:       "https://example.com/cb?q=<script>",
			State:             "\" style=\"xss",
			CodeChallenge:     "challenge<script>",
			CodeChallengeMeth: "S256",
			Resource:          "<img src=x onerror=alert('res')>",
			CSRFToken:         "csrf\"<tag>",
			IsCustomDCRClient: false,
			DefaultPreset:     "read_only",
			Connectors:        connectors,
		}

		err := ui.RenderAuthorize(rec, http.StatusOK, data)
		if err != nil {
			t.Fatalf("RenderAuthorize failed: %v", err)
		}

		body := rec.Body.String()
		if strings.Contains(body, "<script>alert('client')</script>") {
			t.Errorf("raw XSS script tag found in HTML output")
		}
		if strings.Contains(body, "<img src=x onerror=alert('res')>") {
			t.Errorf("raw XSS img tag found in HTML output")
		}
		if !strings.Contains(body, "&lt;script&gt;alert(&#39;client&#39;)&lt;/script&gt;") && !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("expected HTML escaping of script tags")
		}
	})

	t.Run("GFlow and GCP scope configuration in Authorize", func(t *testing.T) {
		gConnectors := []ui.ConnectorView{
			{
				ID:         "gcp",
				Name:       "Google Cloud Platform (GCP MCP)",
				Connected:  true,
				KeylessADC: true,
				ScopeMode:  "read_only",
			},
			{
				ID:         "gflow",
				Name:       "Google Flow (gflow MCP)",
				Connected:  true,
				KeylessADC: true,
				ScopeMode:  "read_only",
			},
		}

		rec := httptest.NewRecorder()
		data := ui.AuthorizePageData{
			AdminEmail:    "admin@example.com",
			ServiceURL:    "https://gateway.example.com",
			ClientID:      "test-client-id",
			ClientName:    "Test Client",
			RedirectURI:   "https://client.example.com/callback",
			CSRFToken:     "csrf-auth",
			DefaultPreset: "read_only",
			Connectors:    gConnectors,
		}

		err := ui.RenderAuthorize(rec, http.StatusOK, data)
		if err != nil {
			t.Fatalf("RenderAuthorize failed: %v", err)
		}

		body := rec.Body.String()

		// Verify custom scope wrapper
		if !strings.Contains(body, `id="custom-scope-wrapper"`) {
			t.Errorf("expected id=\"custom-scope-wrapper\" in authorize page")
		}

		// Verify gflow scope dropdown with full_access, read_only, and none
		if !strings.Contains(body, `id="scope_gflow"`) {
			t.Errorf("expected id=\"scope_gflow\" in authorize page")
		}
		if !strings.Contains(body, `<option value="full_access" selected>Full Access (AI Image &amp; Video Generation + Catalog)</option>`) {
			t.Errorf("expected full_access option for scope_gflow")
		}
		if !strings.Contains(body, `<option value="read_only">Read Only (Models, Projects, Characters &amp; Credits Only)</option>`) {
			t.Errorf("expected read_only option for scope_gflow")
		}
		if !strings.Contains(body, `<option value="none">None (Disabled)</option>`) {
			t.Errorf("expected none option for scope_gflow")
		}

		// Verify gcp scope dropdown
		if !strings.Contains(body, `id="scope_gcp"`) {
			t.Errorf("expected id=\"scope_gcp\" in authorize page")
		}
		if !strings.Contains(body, `<option value="read_only" selected>Read Only (Keyless ADC)</option>`) {
			t.Errorf("expected Read Only (Keyless ADC) option for scope_gcp")
		}
	})
}

func TestRenderAuthorize_CustomConnectors(t *testing.T) {
	connectors := []ui.ConnectorView{
		{
			ID:         "gcp",
			Name:       "Google Cloud Run",
			Connected:  true,
			KeylessADC: true,
		},
		{
			ID:         "github",
			Name:       "GitHub",
			Connected:  true,
			KeylessADC: false,
		},
		{
			ID:            "custom:slack",
			Name:          "Slack Workspace",
			Connected:     true,
			IsCustom:      true,
			ConnectorType: "rest_api",
		},
		{
			ID:            "custom:linear",
			Name:          "Linear Issues",
			Connected:     false,
			IsCustom:      true,
			ConnectorType: "remote_mcp",
		},
	}

	rec := httptest.NewRecorder()
	data := ui.AuthorizePageData{
		AdminEmail:    "admin@example.com",
		ServiceURL:    "https://gateway.example.com",
		ClientID:      "test-client",
		ClientName:    "Test MCP Client",
		RedirectURI:   "https://client.example.com/callback",
		State:         "state123",
		CSRFToken:     "csrf-auth",
		DefaultPreset: "read_only",
		Connectors:    connectors,
	}

	err := ui.RenderAuthorize(rec, http.StatusOK, data)
	if err != nil {
		t.Fatalf("RenderAuthorize failed: %v", err)
	}

	body := rec.Body.String()

	// Verify custom connector scope selects
	expectedScopeSelects := []string{
		`id="scope_custom:slack" name="scope_custom:slack"`,
		`id="scope_custom:linear" name="scope_custom:linear"`,
		`id="scope_github" name="scope_github"`,
		`id="scope_gcp" name="scope_gcp"`,
	}
	for _, sel := range expectedScopeSelects {
		if !strings.Contains(body, sel) {
			t.Errorf("missing scope select: %s", sel)
		}
	}

	// Verify custom connector names in upstream status
	if !strings.Contains(body, "Slack Workspace") {
		t.Errorf("expected custom connector name in upstream status")
	}
	if !strings.Contains(body, "Linear Issues") {
		t.Errorf("expected custom connector name in upstream status")
	}
}

func TestRenderDashboard_XSSAutoEscaping(t *testing.T) {
	connectors := []ui.ConnectorView{
		{
			ID:           "custom:xss",
			Name:         "<script>alert('name')</script>",
			Description:  "<img src=x onerror=alert('desc')>",
			AccountLabel: "<b>evil-account</b>",
			EndpointURL:  "https://evil.example.com/<script>",
			Connected:    true,
			IsCustom:     true,
		},
	}

	rec := httptest.NewRecorder()
	data := ui.DashboardPageData{
		AdminEmail:   "admin@example.com",
		MCPEndpoint:  "https://gateway.example.com/mcp",
		CSRFToken:    "token",
		Connectors:   connectors,
		FlashMessage: "<script>alert('flash')</script>",
	}

	err := ui.RenderDashboard(rec, http.StatusOK, data)
	if err != nil {
		t.Fatalf("RenderDashboard failed: %v", err)
	}

	body := rec.Body.String()

	if strings.Contains(body, "<script>alert('name')</script>") {
		t.Errorf("raw XSS script tag found for connector name")
	}
	if strings.Contains(body, "<img src=x onerror=alert('desc')>") {
		t.Errorf("raw XSS img tag found for connector description")
	}
	if strings.Contains(body, "<script>alert('flash')</script>") {
		t.Errorf("raw XSS script tag found for flash message")
	}
}

func TestRenderOAuthCallback(t *testing.T) {
	t.Run("Success callback postMessage strict origin", func(t *testing.T) {
		rec := httptest.NewRecorder()
		data := ui.CallbackPageData{
			Provider:     "github",
			ProviderName: "GitHub",
			ScopeMode:    "read_only",
			Success:      true,
			ErrorMessage: "",
		}

		err := ui.RenderOAuthCallback(rec, http.StatusOK, data)
		if err != nil {
			t.Fatalf("RenderOAuthCallback failed: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}

		assertSecurityHeaders(t, rec)

		body := rec.Body.String()

		// Success elements
		if !strings.Contains(body, "Connection Successful") {
			t.Errorf("expected connection successful heading")
		}
		if !strings.Contains(body, "GitHub") {
			t.Errorf("expected provider name")
		}
		if !strings.Contains(body, "/dashboard") {
			t.Errorf("expected fallback return to dashboard link")
		}

		// Strict origin check and targetOrigin
		if !strings.Contains(body, "window.opener.postMessage") {
			t.Errorf("expected window.opener.postMessage invocation")
		}
		if !strings.Contains(body, "window.location.origin") {
			t.Errorf("expected postMessage to target window.location.origin")
		}

		// Ensure NEVER postMessage with wildcard
		if strings.Contains(body, `postMessage("*")`) || strings.Contains(body, `postMessage('*')`) ||
			strings.Contains(body, `postMessage({`) && strings.Contains(body, `"*"`) {
			t.Errorf("insecure wildcard postMessage detected")
		}
	})

	t.Run("Failure callback safely escapes ErrorMessage", func(t *testing.T) {
		rec := httptest.NewRecorder()
		data := ui.CallbackPageData{
			Provider:     "jira",
			ProviderName: "Atlassian Jira",
			ScopeMode:    "full_access",
			Success:      false,
			ErrorMessage: "<img src=x onerror=alert(1)>",
		}

		err := ui.RenderOAuthCallback(rec, http.StatusOK, data)
		if err != nil {
			t.Fatalf("RenderOAuthCallback failed: %v", err)
		}

		assertSecurityHeaders(t, rec)

		body := rec.Body.String()

		// Failure elements
		if !strings.Contains(body, "Connection Failed") {
			t.Errorf("expected connection failed heading")
		}
		if strings.Contains(body, "<img src=x onerror=alert(1)>") {
			t.Errorf("raw XSS img tag found in failure output")
		}
		if !strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
			t.Errorf("expected ErrorMessage to be HTML escaped")
		}
		if !strings.Contains(body, "Close Window") {
			t.Errorf("expected Close Window button")
		}

		// Ensure postMessage is NOT called on failure
		if strings.Contains(body, "window.opener.postMessage") {
			t.Errorf("postMessage should not be called on failure")
		}
	})
}

func TestStrictPostMessageSecurityPolicy(t *testing.T) {
	connectors := []ui.ConnectorView{
		{ID: "github", Name: "GitHub", Connected: true, KeylessADC: false},
		{ID: "gcp", Name: "Google Cloud Run", Connected: true, KeylessADC: true},
	}

	dashboardRec := httptest.NewRecorder()
	_ = ui.RenderDashboard(dashboardRec, http.StatusOK, ui.DashboardPageData{
		AdminEmail:  "admin@example.com",
		MCPEndpoint: "https://gateway.example.com/mcp",
		CSRFToken:   "token",
		Connectors:  connectors,
	})

	authorizeRec := httptest.NewRecorder()
	_ = ui.RenderAuthorize(authorizeRec, http.StatusOK, ui.AuthorizePageData{
		AdminEmail:  "admin@example.com",
		ClientID:    "client-1",
		ClientName:  "Test Client",
		RedirectURI: "https://client.example.com/callback",
		Connectors:  connectors,
	})

	callbackRec := httptest.NewRecorder()
	_ = ui.RenderOAuthCallback(callbackRec, http.StatusOK, ui.CallbackPageData{
		Provider:     "github",
		ProviderName: "GitHub",
		ScopeMode:    "read_only",
		Success:      true,
	})

	pages := map[string]string{
		"dashboard": dashboardRec.Body.String(),
		"authorize": authorizeRec.Body.String(),
		"callback":  callbackRec.Body.String(),
	}

	for pageName, html := range pages {
		// Verify strict window.location.origin presence
		if !strings.Contains(html, "window.location.origin") {
			t.Errorf("[%s] missing required reference to window.location.origin", pageName)
		}

		// Ensure no wildcard postMessage anywhere
		if strings.Contains(html, `postMessage("*")`) || strings.Contains(html, `postMessage('*')`) {
			t.Errorf("[%s] forbidden wildcard postMessage detected", pageName)
		}

		// Ensure any postMessage invocation uses window.location.origin
		if strings.Contains(html, "postMessage(") {
			if !strings.Contains(html, "window.location.origin") {
				t.Errorf("[%s] postMessage call must explicitly use window.location.origin", pageName)
			}
		}

		// Verify CSP header on response
		var cspHeader string
		switch pageName {
		case "dashboard":
			cspHeader = dashboardRec.Header().Get("Content-Security-Policy")
		case "authorize":
			cspHeader = authorizeRec.Header().Get("Content-Security-Policy")
		case "callback":
			cspHeader = callbackRec.Header().Get("Content-Security-Policy")
		}
		if !strings.Contains(cspHeader, "frame-ancestors 'none'") {
			t.Errorf("[%s] CSP header missing frame-ancestors 'none'", pageName)
		}
	}
}

func TestRenderDashboard_WorkspacePicker(t *testing.T) {
	connectors := []ui.ConnectorView{
		{
			ID:                "github",
			Name:              "GitHub",
			Description:       "GitHub integration",
			Connected:         true,
			ConnectorType:     "oauth2",
			SelectedOrgs:      []string{"aetherise-cloud"},
			AllowedReadRepos:  []string{"aetherise-cloud/*"},
			AllowedWriteRepos: []string{"aetherise-cloud/spark-mcp-gateway"},
		},
		{
			ID:               "jira",
			Name:             "Atlassian Jira",
			Description:      "Jira integration",
			Connected:        true,
			ConnectorType:    "oauth2",
			SiteName:         "aetherise.atlassian.net",
			CloudID:          "cloud-id-test",
			AllowedSpaceKeys: []string{"SPARK", "ONB"},
		},
	}

	rec := httptest.NewRecorder()
	data := ui.DashboardPageData{
		AdminEmail:  "admin@example.com",
		ServiceURL:  "https://gateway.example.com",
		MCPEndpoint: "https://gateway.example.com/mcp",
		CSRFToken:   "csrf-token-ws",
		Connectors:  connectors,
	}

	err := ui.RenderDashboard(rec, http.StatusOK, data)
	if err != nil {
		t.Fatalf("RenderDashboard failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	assertSecurityHeaders(t, rec)
	body := rec.Body.String()

	// Verify Modal 4 presence and functions
	if !strings.Contains(body, `id="workspace-modal"`) {
		t.Errorf("expected id=\"workspace-modal\" in dashboard")
	}
	if !strings.Contains(body, "openWorkspaceModal") {
		t.Errorf("expected openWorkspaceModal in dashboard")
	}
	if !strings.Contains(body, `onclick="openWorkspaceModal('github')"`) {
		t.Errorf("expected openWorkspaceModal('github') button in dashboard")
	}
	if !strings.Contains(body, `onclick="openWorkspaceModal('jira')"`) {
		t.Errorf("expected openWorkspaceModal('jira') button in dashboard")
	}

	// Verify rendered metadata in connector cards
	if !strings.Contains(body, "aetherise-cloud") {
		t.Errorf("expected SelectedOrgs to render in dashboard")
	}
	if !strings.Contains(body, "aetherise-cloud/*") {
		t.Errorf("expected AllowedReadRepos to render in dashboard")
	}
	if !strings.Contains(body, "aetherise-cloud/spark-mcp-gateway") {
		t.Errorf("expected AllowedWriteRepos to render in dashboard")
	}
	if !strings.Contains(body, "SPARK") || !strings.Contains(body, "ONB") {
		t.Errorf("expected AllowedSpaceKeys to render in dashboard")
	}
	if !strings.Contains(body, "aetherise.atlassian.net") {
		t.Errorf("expected SiteName to render in dashboard")
	}

	// Verify workspace modal elements
	if !strings.Contains(body, `id="ws-gh-orgs-list"`) {
		t.Errorf("expected ws-gh-orgs-list in workspace modal")
	}
	if !strings.Contains(body, `id="ws-gh-read-repos-list"`) {
		t.Errorf("expected ws-gh-read-repos-list in workspace modal")
	}
	if !strings.Contains(body, `id="ws-gh-write-repos-list"`) {
		t.Errorf("expected ws-gh-write-repos-list in workspace modal")
	}
	if !strings.Contains(body, `id="ws-jira-spaces-list"`) {
		t.Errorf("expected ws-jira-spaces-list in workspace modal")
	}
	if !strings.Contains(body, `id="btn-save-workspace"`) {
		t.Errorf("expected btn-save-workspace in workspace modal")
	}
}

func TestRenderAuthorize_WorkspacePicker(t *testing.T) {
	connectors := []ui.ConnectorView{
		{
			ID:                "github",
			Name:              "GitHub",
			Description:       "GitHub integration",
			Connected:         true,
			ConnectorType:     "oauth2",
			SelectedOrgs:      []string{"aetherise-cloud"},
			AllowedReadRepos:  []string{"aetherise-cloud/*"},
			AllowedWriteRepos: []string{"aetherise-cloud/spark-mcp-gateway"},
		},
		{
			ID:               "jira",
			Name:             "Atlassian Jira",
			Description:      "Jira integration",
			Connected:        true,
			ConnectorType:    "oauth2",
			SiteName:         "aetherise.atlassian.net",
			CloudID:          "cloud-id-test",
			AllowedSpaceKeys: []string{"SPARK", "ONB"},
		},
	}

	rec := httptest.NewRecorder()
	data := ui.AuthorizePageData{
		AdminEmail:        "admin@example.com",
		ServiceURL:        "https://gateway.example.com",
		ClientID:          "test-client-id",
		ClientName:        "Test MCP Client",
		RedirectURI:       "https://client.example.com/callback",
		State:             "state123",
		CodeChallenge:     "challenge123",
		CodeChallengeMeth: "S256",
		Resource:          "https://gateway.example.com/mcp",
		CSRFToken:         "csrf-token-auth",
		DefaultPreset:     "read_only",
		Connectors:        connectors,
	}

	err := ui.RenderAuthorize(rec, http.StatusOK, data)
	if err != nil {
		t.Fatalf("RenderAuthorize failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	assertSecurityHeaders(t, rec)
	body := rec.Body.String()

	// Verify required card IDs
	if !strings.Contains(body, `id="workspace-picker-github"`) {
		t.Errorf("expected id=\"workspace-picker-github\" in authorize page")
	}
	if !strings.Contains(body, `id="workspace-picker-jira"`) {
		t.Errorf("expected id=\"workspace-picker-jira\" in authorize page")
	}

	// Verify discovery buttons and functions
	if !strings.Contains(body, "loadGitHubWorkspacesForAuthorize()") {
		t.Errorf("expected loadGitHubWorkspacesForAuthorize() button in authorize page")
	}
	if !strings.Contains(body, "loadJiraWorkspacesForAuthorize()") {
		t.Errorf("expected loadJiraWorkspacesForAuthorize() button in authorize page")
	}

	// Verify fallback inputs
	if !strings.Contains(body, `id="auth-gh-write-repos"`) || !strings.Contains(body, `name="allowed_write_repos"`) {
		t.Errorf("expected fallback input id=\"auth-gh-write-repos\" with name=\"allowed_write_repos\"")
	}
	if !strings.Contains(body, `id="auth-jira-space-keys"`) || !strings.Contains(body, `name="allowed_space_keys"`) {
		t.Errorf("expected fallback input id=\"auth-jira-space-keys\" with name=\"allowed_space_keys\"")
	}

	// Verify rendered pre-configured items
	if !strings.Contains(body, "aetherise-cloud") {
		t.Errorf("expected pre-configured SelectedOrgs in authorize page")
	}
	if !strings.Contains(body, "aetherise-cloud/*") {
		t.Errorf("expected pre-configured AllowedReadRepos in authorize page")
	}
	if !strings.Contains(body, "aetherise-cloud/spark-mcp-gateway") {
		t.Errorf("expected pre-configured AllowedWriteRepos in authorize page")
	}
	if !strings.Contains(body, "SPARK") || !strings.Contains(body, "ONB") {
		t.Errorf("expected pre-configured AllowedSpaceKeys in authorize page")
	}
	if !strings.Contains(body, "aetherise.atlassian.net") {
		t.Errorf("expected SiteName in authorize page")
	}
}

func TestRenderDashboard_GCPAndGFlowMCP(t *testing.T) {
	connectors := []ui.ConnectorView{
		{
			ID:           "gcp",
			Name:         "Google Cloud Platform (GCP MCP)",
			Description:  "Read and inspect Cloud Run services across regional clusters",
			Connected:    true,
			KeylessADC:   true,
			ScopeMode:    "read_only",
			AccountLabel: "spark-mcp-sa@project.iam.gserviceaccount.com (Keyless ADC)",
			UpdatedAt:    "2026-11-09T10:00:00Z",
		},
		{
			ID:           "gflow",
			Name:         "Google Flow (gflow MCP)",
			Description:  "AI Image & Video Generation engine powered by Google Flow",
			Connected:    true,
			KeylessADC:   true,
			ScopeMode:    "read_only",
			AccountLabel: "spark-mcp-sa@project.iam.gserviceaccount.com (Built-In + ADC)",
			UpdatedAt:    "2026-11-09T10:00:00Z",
		},
	}

	rec := httptest.NewRecorder()
	data := ui.DashboardPageData{
		AdminEmail:  "admin@example.com",
		ServiceURL:  "https://gateway.example.com",
		MCPEndpoint: "https://gateway.example.com/mcp",
		CSRFToken:   "csrf-gcp-gflow",
		Connectors:  connectors,
	}

	err := ui.RenderDashboard(rec, http.StatusOK, data)
	if err != nil {
		t.Fatalf("RenderDashboard failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	assertSecurityHeaders(t, rec)
	body := rec.Body.String()

	// 1. Verify GCP card capabilities row and Setup Guide button
	if !strings.Contains(body, "Tools (9 Read-Only): Cloud Run, Revisions, Cloud Logging, Storage Buckets, Artifact Registry, Monitoring Alerts, IAM Accounts, Resource Inspector") {
		t.Errorf("expected GCP MCP compact capabilities row in dashboard")
	}
	if !strings.Contains(body, `onclick="openTutorial('gcp')"`) {
		t.Errorf("expected Setup Guide button with openTutorial('gcp') in dashboard")
	}

	// 2. Verify GFlow card badges, capabilities row, and action buttons
	if !strings.Contains(body, "ACTIVE (BUILT-IN + ADC)") {
		t.Errorf("expected ACTIVE (BUILT-IN + ADC) badge on gflow card")
	}
	if !strings.Contains(body, "IMAGE &amp; VIDEO AI (11 TOOLS)") && !strings.Contains(body, "IMAGE & VIDEO AI (11 TOOLS)") {
		t.Errorf("expected IMAGE & VIDEO AI (11 TOOLS) badge on gflow card")
	}
	if !strings.Contains(body, "Models: Nano Banana 2.1 (nano2), Nano Pro, Imagen 4, Veo Fast / Quality (t2v, i2v, r2v), 2K/4K &amp; 1080p Upscale") &&
		!strings.Contains(body, "Models: Nano Banana 2.1 (nano2), Nano Pro, Imagen 4, Veo Fast / Quality (t2v, i2v, r2v), 2K/4K & 1080p Upscale") {
		t.Errorf("expected GFlow compact capabilities row in dashboard")
	}
	if !strings.Contains(body, `onclick="openTutorial('gflow')"`) {
		t.Errorf("expected Setup Guide button with openTutorial('gflow') in dashboard")
	}
	if !strings.Contains(body, `onclick="prefillCustomConnector('gflow-remote', 'Google Flow (Remote MCP)', 'remote_mcp', 'https://flow.google.com/mcp', 'Authorization')"`) {
		t.Errorf("expected Configure Remote GFlow Endpoint button in dashboard")
	}

	// 3. Verify Connector Catalog modal cards for GCP and GFlow
	if !strings.Contains(body, "Google Flow (gflow MCP)") {
		t.Errorf("expected Google Flow in catalog modal")
	}
	if !strings.Contains(body, "Google Cloud Platform (GCP Read-Only MCP)") {
		t.Errorf("expected Google Cloud Platform in catalog modal")
	}

	// 4. Verify TUTORIAL_GUIDES for GCP
	gcpTools := []string{
		"gcp_list_cloudrun_services",
		"gcp_get_cloudrun_service",
		"gcp_list_cloudrun_revisions",
		"gcp_query_cloud_logging",
		"gcp_list_storage_buckets",
		"gcp_list_artifact_repositories",
		"gcp_list_monitoring_alerts",
		"gcp_list_service_accounts",
		"gcp_describe_resource",
	}
	for _, tool := range gcpTools {
		if !strings.Contains(body, tool) {
			t.Errorf("TUTORIAL_GUIDES missing expected GCP tool: %s", tool)
		}
	}
	if !strings.Contains(body, "strict secret redaction") {
		t.Errorf("TUTORIAL_GUIDES missing strict secret redaction mention for GCP")
	}

	// 5. Verify TUTORIAL_GUIDES for GFlow
	gflowTools := []string{
		"gflow_generate_image",
		"gflow_generate_video",
		"gflow_upscale_image",
		"gflow_upscale_video",
		"gflow_list_models",
		"gflow_list_tools",
		"gflow_list_projects",
		"gflow_character_list",
		"gflow_character_show",
		"gflow_get_credits",
		"gflow_auth_status",
	}
	for _, tool := range gflowTools {
		if !strings.Contains(body, tool) {
			t.Errorf("TUTORIAL_GUIDES missing expected GFlow tool: %s", tool)
		}
	}
	if !strings.Contains(body, "https://flow.google.com/mcp") {
		t.Errorf("TUTORIAL_GUIDES missing https://flow.google.com/mcp for remote GFlow")
	}
}