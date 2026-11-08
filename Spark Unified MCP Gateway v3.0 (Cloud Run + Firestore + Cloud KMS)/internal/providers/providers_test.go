package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"spark-mcp-gateway/internal/config"
	"spark-mcp-gateway/internal/vault"
)

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

	// 1. List PRs
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

	// 2. Read File - valid
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

	// 2b. Read File - path traversal attacks MUST be rejected before any HTTP call (P1-1)
	traversalPaths := []string{
		"../../users/octocat/repos",
		"..\\secret",
		"%2e%2e/secret",
		"foo/../../bar",
		"../etc/passwd",
		"foo/./bar/../secret",
	}
	for _, tp := range traversalPaths {
		_, err := reg.Execute(ctx, "github_read_file", map[string]interface{}{
			"owner": "owner",
			"repo":  "repo",
			"path":  tp,
		}, tok)
		if err == nil {
			t.Errorf("expected path traversal attack %q to be rejected, but it succeeded", tp)
		}
	}

	// 2c. Invalid owner/repo traversal
	_, err = reg.Execute(ctx, "github_read_file", map[string]interface{}{
		"owner": "../owner",
		"repo":  "repo",
		"path":  "README.md",
	}, tok)
	if err == nil {
		t.Error("expected owner traversal to be rejected")
	}

	// 3. Create Issue - allowed repo
	createOut, err := reg.Execute(ctx, "github_create_issue", map[string]interface{}{
		"owner": "owner",
		"repo":  "repo",
		"title": "New issue",
	}, tok)
	if err != nil {
		t.Fatalf("github_create_issue on allowed repo failed: %v", err)
	}
	if !strings.Contains(createOut, "Successfully created issue #101") {
		t.Errorf("expected success message, got: %s", createOut)
	}

	// 4. Create Issue - disallowed repo
	_, err = reg.Execute(ctx, "github_create_issue", map[string]interface{}{
		"owner": "other-org",
		"repo":  "secret-repo",
		"title": "Should fail",
	}, tok)
	if err == nil {
		t.Fatal("expected failure on repo outside GITHUB_ALLOWED_WRITE_REPOS")
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
					"assignee": {"displayName": "Alice"},
					"description": {
						"type": "doc",
						"version": 1,
						"content": [
							{
								"type": "paragraph",
								"content": [{"type": "text", "text": "This is a paragraph description."}]
							},
							{
								"type": "bulletList",
								"content": [
									{
										"type": "listItem",
										"content": [
											{
												"type": "paragraph",
												"content": [{"type": "text", "text": "First bullet item"}]
											}
										]
									}
								]
							},
							{
								"type": "codeBlock",
								"content": [{"type": "text", "text": "console.log('hi')"}]
							}
						]
					}
				}
			}`))
		case r.Method == "GET" && r.URL.Path == "/ex/jira/cloud-123/rest/api/3/issue/PROJ-10/transitions":
			_, _ = w.Write([]byte(`{
				"transitions": [
					{"id": "21", "name": "Done", "to": {"name": "Done"}},
					{"id": "31", "name": "In Review", "to": {"name": "In Review"}}
				]
			}`))
		case r.Method == "POST" && r.URL.Path == "/ex/jira/cloud-123/rest/api/3/issue/PROJ-10/transitions":
			var payload struct {
				Transition struct {
					ID string `json:"id"`
				} `json:"transition"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload.Transition.ID != "21" {
				http.Error(w, "wrong transition id", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
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

	// 1. Get issue with ADF flattener
	out, err := reg.Execute(ctx, "jira_get_issue", map[string]interface{}{
		"issue_key": "PROJ-10",
	}, tok)
	if err != nil {
		t.Fatalf("jira_get_issue failed: %v", err)
	}
	if !strings.Contains(out, "This is a paragraph description.") {
		t.Errorf("expected flattened paragraph text, got: %s", out)
	}
	if !strings.Contains(out, "- First bullet item") {
		t.Errorf("expected flattened bullet item, got: %s", out)
	}
	if !strings.Contains(out, "console.log('hi')") {
		t.Errorf("expected code block text, got: %s", out)
	}

	// 2. Transition status
	transOut, err := reg.Execute(ctx, "jira_update_issue_status", map[string]interface{}{
		"issue_key": "PROJ-10",
		"status":    "done", // Case-insensitive match for "Done"
	}, tok)
	if err != nil {
		t.Fatalf("jira_update_issue_status failed: %v", err)
	}
	if !strings.Contains(transOut, "Successfully transitioned PROJ-10 to \"done\"") {
		t.Errorf("expected transition success, got: %s", transOut)
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
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/services/svc-1"):
			// Upstream returns sensitive env vars and secret mounts that MUST be redacted!
			_, _ = w.Write([]byte(`{
				"name": "projects/p/locations/r/services/svc-1",
				"uri": "https://svc-1.run.app",
				"ingress": "INGRESS_TRAFFIC_ALL",
				"template": {
					"serviceAccount": "sa@example.iam.gserviceaccount.com",
					"scaling": {"minInstanceCount": 1, "maxInstanceCount": 5},
					"containers": [
						{
							"image": "gcr.io/p/svc:v1",
							"resources": {"limits": {"cpu": "1000m", "memory": "512Mi"}},
							"env": [
								{"name": "DB_PASSWORD", "value": "super_secret_db_pass"},
								{"name": "API_KEY", "value": "sk_live_12345"}
							],
							"volumeMounts": [
								{"name": "secret-vol", "mountPath": "/secrets"}
							]
						}
					]
				}
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

	ctx := context.Background()

	// 1. List services
	listOut, err := reg.Execute(ctx, "gcp_list_cloudrun_services", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gcp_list_cloudrun_services failed: %v", err)
	}
	if !strings.Contains(listOut, "svc-1: https://svc-1.run.app") {
		t.Errorf("expected svc-1 in list, got: %s", listOut)
	}

	// 2. Get service with secret redaction
	getOut, err := reg.Execute(ctx, "gcp_get_cloudrun_service", map[string]interface{}{
		"service_name": "svc-1",
	}, nil)
	if err != nil {
		t.Fatalf("gcp_get_cloudrun_service failed: %v", err)
	}

	// Assert: safe fields present
	if !strings.Contains(getOut, "gcr.io/p/svc:v1") {
		t.Errorf("expected container image in output, got: %s", getOut)
	}
	if !strings.Contains(getOut, "sa@example.iam.gserviceaccount.com") {
		t.Errorf("expected service account in output, got: %s", getOut)
	}

	// CRITICAL SECURITY ASSERTION (SEC-06): env secrets and volumeMounts MUST NOT be present!
	if strings.Contains(getOut, "super_secret_db_pass") || strings.Contains(getOut, "DB_PASSWORD") {
		t.Fatal("SECURITY VIOLATION: sensitive environment variable was not redacted!")
	}
	if strings.Contains(getOut, "sk_live_12345") || strings.Contains(getOut, "secret-vol") {
		t.Fatal("SECURITY VIOLATION: secret mounts or api keys were not redacted!")
	}
}

func TestGDKSearchDocs(t *testing.T) {
	var capturedUserProject string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserProject = r.Header.Get("X-Goog-User-Project")
		if r.Header.Get("Authorization") != "Bearer mock-adc-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"documentChunks": [
				{
					"documentTitle": "Cloud Run Overview",
					"documentUri": "https://cloud.google.com/run/docs/overview",
					"chunkContent": "Cloud Run is a managed compute platform that lets you run containers directly on top of Google infrastructure."
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

	ctx := context.Background()
	out, err := reg.Execute(ctx, "gdk_search_docs", map[string]interface{}{
		"query": "cloud run overview",
	}, nil)
	if err != nil {
		t.Fatalf("gdk_search_docs failed: %v", err)
	}

	if capturedUserProject != "my-gcp-project-123" {
		t.Errorf("expected X-Goog-User-Project: my-gcp-project-123, got: %s", capturedUserProject)
	}
	if !strings.Contains(out, "Cloud Run Overview") || !strings.Contains(out, "https://cloud.google.com/run/docs/overview") {
		t.Errorf("expected doc title and uri in output, got: %s", out)
	}
}
