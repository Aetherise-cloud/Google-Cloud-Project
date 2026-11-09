package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/vault"
)

func TestSSRFValidationAndClient(t *testing.T) {
	// 1. SSRF URL rejection tests
	blockedURLs := []string{
		"http://169.254.169.254/latest/meta-data", // Cloud metadata
		"https://127.0.0.1:8080/secret",           // Loopback
		"https://10.0.0.1/api",                    // RFC 1918 Class A
		"https://192.168.1.1/",                    // RFC 1918 Class C
		"https://172.16.0.5/",                     // RFC 1918 Class B
		"https://[::1]:8443",                      // IPv6 loopback
		"http://example.com/api",                  // Scheme not https
		"https://user:pass@example.com/api",       // Userinfo not allowed
		"https://localhost/api",                   // Localhost
	}

	for _, u := range blockedURLs {
		if err := ValidateUpstreamURL(u); err == nil {
			t.Errorf("expected ValidateUpstreamURL to block %q, but it passed", u)
		}
	}

	// 2. Localhost permitted when test loopback option enabled
	if err := ValidateUpstreamURLWithTestOption("http://127.0.0.1:8080/mcp", true); err != nil {
		t.Errorf("expected test loopback to be permitted, got error: %v", err)
	}

	// 3. SSRF-safe HTTP client blocks connection to restricted IP
	client := NewSSRFSafeHTTPClient(2 * time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://169.254.169.254/secret", nil)
	_, err := client.Do(req)
	if err == nil {
		t.Error("expected NewSSRFSafeHTTPClient to block dial to 169.254.169.254")
	}
}

func TestCustomRemoteMCPAndRESTAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/mcp":
			var rpcReq struct {
				Method string `json:"method"`
			}
			_ = json.NewDecoder(r.Body).Decode(&rpcReq)
			if rpcReq.Method == "tools/list" {
				_, _ = w.Write([]byte(`{
					"jsonrpc": "2.0",
					"id": 1,
					"result": {
						"tools": [
							{"name": "echo", "description": "Echoes text", "inputSchema": {}}
						]
					}
				}`))
			} else if rpcReq.Method == "tools/call" {
				_, _ = w.Write([]byte(`{
					"jsonrpc": "2.0",
					"id": 1,
					"result": {
						"content": [{"type": "text", "text": "remote tool executed successfully"}],
						"isError": false
					}
				}`))
			}
		case r.Method == "GET" && r.URL.Path == "/v1/users":
			_, _ = w.Write([]byte(`[{"id": "usr-1", "name": "Alice"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	testClient := NewSSRFSafeHTTPClientWithTestOption(5*time.Second, true)
	ctx := context.Background()

	// 1. CallRemoteMCPToolsList
	tools, err := CallRemoteMCPToolsList(ctx, testClient, server.URL+"/mcp", "Authorization", "token-xyz")
	if err != nil {
		t.Fatalf("CallRemoteMCPToolsList failed: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		t.Errorf("expected tool 'echo', got: %+v", tools)
	}

	// 2. CallRemoteMCPToolsCall
	callOut, err := CallRemoteMCPToolsCall(ctx, testClient, server.URL+"/mcp", "Authorization", "token-xyz", "echo", map[string]interface{}{})
	if err != nil {
		t.Fatalf("CallRemoteMCPToolsCall failed: %v", err)
	}
	if !strings.Contains(callOut, "remote tool executed successfully") {
		t.Errorf("expected success text, got: %s", callOut)
	}

	// 3. CallCustomRESTAPI
	restOut, err := CallCustomRESTAPI(ctx, testClient, server.URL, "Authorization", "token-xyz", "GET", "/v1/users", "")
	if err != nil {
		t.Fatalf("CallCustomRESTAPI failed: %v", err)
	}
	if !strings.Contains(restOut, "Alice") {
		t.Errorf("expected user Alice in REST response, got: %s", restOut)
	}

	// 4. CallCustomRESTAPI rejects path traversal
	_, err = CallCustomRESTAPI(ctx, testClient, server.URL, "Authorization", "token-xyz", "GET", "/v1/../../etc/passwd", "")
	if err == nil {
		t.Error("expected path traversal in REST API to be rejected")
	}
}

func TestGitHubTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-token-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/repos/owner/repo/pulls"):
			_, _ = w.Write([]byte(`[
				{
					"number": 42,
					"title": "Fix login bug",
					"state": "open",
					"html_url": "https://github.com/owner/repo/pull/42",
					"user": {"login": "dev1"}
				}
			]`))
		case r.Method == "GET" && r.URL.Path == "/repos/owner/repo/contents/README.md":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("# Readme content"))
		case r.Method == "POST" && r.URL.Path == "/repos/owner/repo/issues":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{
				"number": 101,
				"title": "New issue",
				"html_url": "https://github.com/owner/repo/issues/101",
				"state": "open"
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		GitHubAllowedWriteRepos: []string{"owner/repo"},
	}
	reg := NewRegistry(cfg, server.Client(), nil)
	reg.GitHubBaseURL = server.URL

	ctx := context.Background()
	tok := &vault.TokenData{AccessToken: "gh-token-123"}

	out, err := reg.Execute(ctx, "github_list_prs", map[string]interface{}{
		"owner": "owner",
		"repo":  "repo",
		"state": "open",
	}, tok)
	if err != nil {
		t.Fatalf("github_list_prs failed: %v", err)
	}
	if !strings.Contains(out, "#42: Fix login bug") {
		t.Errorf("expected PR #42 in output, got: %s", out)
	}

	fileOut, err := reg.Execute(ctx, "github_read_file", map[string]interface{}{
		"owner": "owner",
		"repo":  "repo",
		"path":  "README.md",
	}, tok)
	if err != nil {
		t.Fatalf("github_read_file failed: %v", err)
	}
	if fileOut != "# Readme content" {
		t.Errorf("expected readme content, got: %s", fileOut)
	}

	// Dynamic AllowedWriteRepos on TokenData permits issue creation even when env allowlist is empty
	dynReg := NewRegistry(&config.Config{}, server.Client(), nil)
	dynReg.GitHubBaseURL = server.URL
	dynTok := &vault.TokenData{
		AccessToken:       tok.AccessToken,
		AllowedWriteRepos: "owner/repo",
	}
	issueOut, err := dynReg.Execute(ctx, "github_create_issue", map[string]interface{}{
		"owner": "owner",
		"repo":  "repo",
		"title": "New issue",
	}, dynTok)
	if err != nil {
		t.Fatalf("github_create_issue with dynamic AllowedWriteRepos failed: %v", err)
	}
	if !strings.Contains(issueOut, "#101") {
		t.Errorf("expected issue #101 in output, got: %s", issueOut)
	}
}

func TestJiraToolsAndADFFlattener(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jira-token-xyz" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/ex/jira/cloud-123/rest/api/3/issue/PROJ-10":
			_, _ = w.Write([]byte(`{
				"key": "PROJ-10",
				"fields": {
					"summary": "Implement Auth",
					"status": {"name": "In Progress"},
					"description": {
						"type": "doc",
						"version": 1,
						"content": [
							{"type": "paragraph", "content": [{"type": "text", "text": "This is a paragraph description."}]}
						]
					}
				}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	reg := NewRegistry(&config.Config{}, server.Client(), nil)
	reg.JiraBaseURL = server.URL

	ctx := context.Background()
	tok := &vault.TokenData{
		AccessToken: "jira-token-xyz",
		CloudID:     "cloud-123",
	}

	out, err := reg.Execute(ctx, "jira_get_issue", map[string]interface{}{
		"issue_key": "PROJ-10",
	}, tok)
	if err != nil {
		t.Fatalf("jira_get_issue failed: %v", err)
	}
	if !strings.Contains(out, "This is a paragraph description.") {
		t.Errorf("expected paragraph text, got: %s", out)
	}
}

func TestGCPCloudRunRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/services"):
			_, _ = w.Write([]byte(`{
				"services": [
					{"name": "projects/p/locations/r/services/svc-1", "uri": "https://svc-1.run.app", "ingress": "INGRESS_TRAFFIC_ALL"}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &config.Config{GCPProjectID: "proj-123", GCPRegion: "asia-southeast1"}
	reg := NewRegistry(cfg, server.Client(), func(ctx context.Context) (string, error) {
		return "mock-adc-token", nil
	})
	reg.CloudRunBaseURL = server.URL

	listOut, err := reg.Execute(context.Background(), "gcp_list_cloudrun_services", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gcp_list_cloudrun_services failed: %v", err)
	}
	if !strings.Contains(listOut, "svc-1: https://svc-1.run.app") {
		t.Errorf("expected svc-1 in list, got: %s", listOut)
	}
}

func TestGDKSearchDocs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"documentChunks": [
				{
					"documentTitle": "Cloud Run Overview",
					"documentUri": "https://cloud.google.com/run/docs/overview",
					"chunkContent": "Cloud Run overview content."
				}
			]
		}`))
	}))
	defer server.Close()

	cfg := &config.Config{GCPProjectID: "my-gcp-project-123"}
	reg := NewRegistry(cfg, server.Client(), func(ctx context.Context) (string, error) {
		return "mock-adc-token", nil
	})
	reg.GDKBaseURL = server.URL

	out, err := reg.Execute(context.Background(), "gdk_search_docs", map[string]interface{}{
		"query": "cloud run overview",
	}, nil)
	if err != nil {
		t.Fatalf("gdk_search_docs failed: %v", err)
	}
	if !strings.Contains(out, "Cloud Run Overview") {
		t.Errorf("expected doc title in output, got: %s", out)
	}
}
