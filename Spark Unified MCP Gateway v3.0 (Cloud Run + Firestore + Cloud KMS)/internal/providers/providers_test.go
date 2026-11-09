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

type mockTransport func(req *http.Request) (*http.Response, error)

func (m mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func TestGitHubScopeGuardrailsAndWildcard(t *testing.T) {
	// 1. Test wildcard in isDynamicRepoAllowed
	if !isDynamicRepoAllowed("aetherise-cloud/*", "aetherise-cloud", "spark-mcp-gateway") {
		t.Error("expected aetherise-cloud/* to match aetherise-cloud/spark-mcp-gateway")
	}
	if isDynamicRepoAllowed("aetherise-cloud/*", "other-org", "spark-mcp-gateway") {
		t.Error("expected aetherise-cloud/* to reject other-org/spark-mcp-gateway")
	}

	// 2. Test isGitHubReadAllowed with SelectedOrgs
	tokOrgs := &vault.TokenData{
		SelectedOrgs: []string{"aetherise-cloud"},
	}
	if !isGitHubReadAllowed(tokOrgs, "aetherise-cloud", "repo1") {
		t.Error("expected SelectedOrgs to allow aetherise-cloud/repo1")
	}
	if isGitHubReadAllowed(tokOrgs, "unauthorized-org", "repo1") {
		t.Error("expected SelectedOrgs to reject unauthorized-org/repo1")
	}

	// 3. Test isGitHubReadAllowed with AllowedReadRepos wildcard
	tokRead := &vault.TokenData{
		AccessToken:      "mock-token-xyz",
		AllowedReadRepos: []string{"aetherise-cloud/*"},
	}
	if !isGitHubReadAllowed(tokRead, "aetherise-cloud", "any-repo") {
		t.Error("expected AllowedReadRepos wildcard to allow aetherise-cloud/any-repo")
	}
	if isGitHubReadAllowed(tokRead, "forbidden-org", "any-repo") {
		t.Error("expected AllowedReadRepos wildcard to reject forbidden-org/any-repo")
	}

	// 4. Test enforcement in handleGitHubListPRs and handleGitHubReadFile
	mockClient := &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			if strings.Contains(req.URL.Path, "/pulls") {
				_, _ = rec.Write([]byte(`[]`))
			} else {
				_, _ = rec.Write([]byte(`content`))
			}
			return rec.Result(), nil
		}),
	}

	reg := NewRegistry(&config.Config{}, mockClient, nil)
	reg.GitHubBaseURL = "http://mock.github"

	// Calling on unauthorized org returns guardrail error
	_, err := reg.Execute(context.Background(), "github_list_prs", map[string]interface{}{
		"owner": "forbidden-org",
		"repo":  "repo1",
	}, tokRead)
	if err == nil || !strings.Contains(err.Error(), "not in allowed GitHub read scope") {
		t.Fatalf("expected read scope error for forbidden org on list_prs, got: %v", err)
	}

	_, err = reg.Execute(context.Background(), "github_read_file", map[string]interface{}{
		"owner": "forbidden-org",
		"repo":  "repo1",
		"path":  "file.txt",
	}, tokRead)
	if err == nil || !strings.Contains(err.Error(), "not in allowed GitHub read scope") {
		t.Fatalf("expected read scope error for forbidden org on read_file, got: %v", err)
	}

	// 5. Test handleGitHubCreateIssue with wildcard AllowedWriteRepos
	tokWriteWildcard := &vault.TokenData{
		AccessToken:       "gh-token",
		AllowedWriteRepos: "aetherise-cloud/*",
	}
	mockWriteClient := &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusCreated)
			_, _ = rec.Write([]byte(`{"number":102,"title":"Issue 102","html_url":"https://github.com/aetherise-cloud/spark/issues/102","state":"open"}`))
			return rec.Result(), nil
		}),
	}
	regWrite := NewRegistry(&config.Config{}, mockWriteClient, nil)
	regWrite.GitHubBaseURL = "http://mock.github"

	issueOut, err := regWrite.Execute(context.Background(), "github_create_issue", map[string]interface{}{
		"owner": "aetherise-cloud",
		"repo":  "spark",
		"title": "Issue 102",
	}, tokWriteWildcard)
	if err != nil {
		t.Fatalf("expected wildcard AllowedWriteRepos to allow issue creation, got error: %v", err)
	}
	if !strings.Contains(issueOut, "#102") {
		t.Errorf("expected #102 in output, got: %s", issueOut)
	}
}

func TestJiraAllowedSpaceKeysAndNewTools(t *testing.T) {
	tok := &vault.TokenData{
		AccessToken:      "jira-tok",
		CloudID:          "cloud-99",
		AllowedSpaceKeys: []string{"SPARK", "ONB"},
	}

	// 1. Test isJiraSpaceAllowed helper
	if !isJiraSpaceAllowed(tok, "SPARK-101") {
		t.Error("expected SPARK-101 to be allowed")
	}
	if !isJiraSpaceAllowed(tok, "onb-5") {
		t.Error("expected onb-5 to be allowed")
	}
	if isJiraSpaceAllowed(tok, "OTHER-99") {
		t.Error("expected OTHER-99 to be rejected")
	}

	mockClient := &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			switch {
			case req.Method == "POST" && strings.HasSuffix(req.URL.Path, "/issue"):
				rec.WriteHeader(http.StatusCreated)
				_, _ = rec.Write([]byte(`{"id":"iss-1","key":"SPARK-500"}`))
			case req.Method == "GET" && strings.HasSuffix(req.URL.Path, "/search"):
				_, _ = rec.Write([]byte(`{
					"issues": [
						{"key":"SPARK-10","fields":{"summary":"Task 10","status":{"name":"Open"}}}
					],
					"total": 1
				}`))
			default:
				http.NotFound(rec, req)
			}
			return rec.Result(), nil
		}),
	}

	reg := NewRegistry(&config.Config{}, mockClient, nil)
	reg.JiraBaseURL = "http://mock.jira"

	// 2. Guardrail on jira_get_issue
	_, err := reg.Execute(context.Background(), "jira_get_issue", map[string]interface{}{
		"issue_key": "OTHER-101",
	}, tok)
	if err == nil || !strings.Contains(err.Error(), "not in allowed_space_keys") {
		t.Fatalf("expected allowed_space_keys error for OTHER-101, got: %v", err)
	}

	// 3. jira_create_issue guardrail & execution
	_, err = reg.Execute(context.Background(), "jira_create_issue", map[string]interface{}{
		"project_key": "OTHER",
		"summary":     "Invalid space",
	}, tok)
	if err == nil || !strings.Contains(err.Error(), "not in allowed_space_keys") {
		t.Fatalf("expected allowed_space_keys error on create issue, got: %v", err)
	}

	createOut, err := reg.Execute(context.Background(), "jira_create_issue", map[string]interface{}{
		"project_key": "SPARK",
		"summary":     "Valid space task",
	}, tok)
	if err != nil {
		t.Fatalf("unexpected error creating issue in SPARK: %v", err)
	}
	if !strings.Contains(createOut, "SPARK-500") {
		t.Errorf("expected SPARK-500 in output, got: %s", createOut)
	}

	// 4. jira_search_issues guardrail & execution
	_, err = reg.Execute(context.Background(), "jira_search_issues", map[string]interface{}{
		"project_key": "OTHER",
	}, tok)
	if err == nil || !strings.Contains(err.Error(), "not in allowed_space_keys") {
		t.Fatalf("expected allowed_space_keys error on search issues, got: %v", err)
	}

	searchOut, err := reg.Execute(context.Background(), "jira_search_issues", map[string]interface{}{}, tok)
	if err != nil {
		t.Fatalf("unexpected error on search issues: %v", err)
	}
	if !strings.Contains(searchOut, "SPARK-10") {
		t.Errorf("expected SPARK-10 in search output, got: %s", searchOut)
	}
}

func TestGCPCloudRunServiceSecretRedaction(t *testing.T) {
	mockClient := &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			_, _ = rec.Write([]byte(`{
				"name": "projects/p/locations/asia-southeast1/services/my-service",
				"uri": "https://my-service.run.app",
				"ingress": "INGRESS_TRAFFIC_ALL",
				"template": {
					"serviceAccount": "sa@proj.iam.gserviceaccount.com",
					"scaling": {
						"maxInstanceCount": 10,
						"secret_key_ref": "scaling-secret-should-be-stripped",
						"env": "env-in-scaling-should-be-stripped"
					},
					"containers": [
						{
							"image": "gcr.io/p/img:v1",
							"env": [{"name":"SECRET_KEY","value":"shh"}],
							"volumeMounts": [{"name":"secret-vol"}],
							"resources": {
								"limits": {"cpu":"1","memory":"512Mi"},
								"secrets": "nested-secret-should-be-stripped"
							}
						}
					]
				},
				"traffic": [
					{
						"percent": 100,
						"secretKeyRef": "traffic-secret-should-be-stripped"
					}
				]
			}`))
			return rec.Result(), nil
		}),
	}

	reg := NewRegistry(&config.Config{GCPProjectID: "p", GCPRegion: "asia-southeast1"}, mockClient, func(ctx context.Context) (string, error) {
		return "adc-token", nil
	})
	reg.CloudRunBaseURL = "http://mock.cloudrun"

	out, err := reg.Execute(context.Background(), "gcp_get_cloudrun_service", map[string]interface{}{
		"service_name": "my-service",
	}, nil)
	if err != nil {
		t.Fatalf("gcp_get_cloudrun_service failed: %v", err)
	}

	for _, sensitive := range []string{
		"secret_key_ref",
		"secretKeyRef",
		"scaling-secret",
		"traffic-secret",
		"SECRET_KEY",
		"secret-vol",
		"nested-secret",
	} {
		if strings.Contains(out, sensitive) {
			t.Errorf("output leaked sensitive string %q:\n%s", sensitive, out)
		}
	}
}

func TestGCPExpandedReadOnlyTools(t *testing.T) {
	mockClient := &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			path := req.URL.Path

			switch {
			case req.Method == "GET" && strings.Contains(path, "/revisions"):
				rec.WriteHeader(http.StatusOK)
				_, _ = rec.Write([]byte(`{
					"revisions": [
						{
							"name": "rev-prod-001",
							"service": "spark-gateway",
							"env": "super-secret-env",
							"private_key": "raw-key"
						}
					]
				}`))
			case req.Method == "POST" && strings.Contains(path, "/v2/entries:list"):
				rec.WriteHeader(http.StatusOK)
				_, _ = rec.Write([]byte(`{
					"entries": [
						{
							"insertId": "log-entry-101",
							"textPayload": "Gateway healthy ready to serve",
							"secret_key_ref": "secret-token",
							"private_key": "sa-key-content"
						}
					]
				}`))
			case req.Method == "GET" && strings.Contains(path, "/storage/v1/b"):
				rec.WriteHeader(http.StatusOK)
				_, _ = rec.Write([]byte(`{
					"items": [
						{
							"name": "spark-prod-assets",
							"location": "ASIA-SOUTHEAST1",
							"storageClass": "STANDARD",
							"timeCreated": "2026-01-01T00:00:00Z"
						}
					]
				}`))
			case req.Method == "GET" && strings.Contains(path, "/repositories"):
				rec.WriteHeader(http.StatusOK)
				_, _ = rec.Write([]byte(`{
					"repositories": [
						{
							"name": "projects/p/locations/asia-southeast1/repositories/spark-docker",
							"format": "DOCKER",
							"description": "Spark Gateway Docker Containers",
							"updateTime": "2026-01-01T00:00:00Z"
						}
					]
				}`))
			case req.Method == "GET" && strings.Contains(path, "/alertPolicies"):
				rec.WriteHeader(http.StatusOK)
				_, _ = rec.Write([]byte(`{
					"alertPolicies": [
						{
							"name": "projects/p/alertPolicies/alert-high-latency",
							"displayName": "High P99 Latency Alert",
							"secret_key_ref": "should-be-stripped"
						}
					]
				}`))
			case req.Method == "GET" && strings.Contains(path, "/serviceAccounts"):
				rec.WriteHeader(http.StatusOK)
				_, _ = rec.Write([]byte(`{
					"accounts": [
						{
							"email": "spark-run@p.iam.gserviceaccount.com",
							"displayName": "Cloud Run Gateway Service Account",
							"disabled": false,
							"uniqueId": "1234567890",
							"private_key_data": "must-not-leak"
						}
					]
				}`))
			case req.Method == "GET" && strings.Contains(path, "/services/mock-service"):
				rec.WriteHeader(http.StatusOK)
				_, _ = rec.Write([]byte(`{
					"name": "projects/p/locations/asia-southeast1/services/mock-service",
					"uri": "https://mock-service.run.app",
					"ingress": "INGRESS_TRAFFIC_ALL",
					"env": "env-should-strip",
					"private_key": "pk-should-strip"
				}`))
			default:
				rec.WriteHeader(http.StatusNotFound)
				_, _ = rec.Write([]byte(`{"error":"not found"}`))
			}
			return rec.Result(), nil
		}),
	}

	reg := NewRegistry(&config.Config{GCPProjectID: "p", GCPRegion: "asia-southeast1"}, mockClient, func(ctx context.Context) (string, error) {
		return "mock-adc-bearer-token", nil
	})
	reg.CloudRunBaseURL = "http://mock.cloudrun.googleapis.com"
	reg.LoggingBaseURL = "http://mock.logging.googleapis.com"
	reg.StorageBaseURL = "http://mock.storage.googleapis.com"
	reg.ArtifactRegistryBaseURL = "http://mock.artifactregistry.googleapis.com"
	reg.MonitoringBaseURL = "http://mock.monitoring.googleapis.com"
	reg.IAMBaseURL = "http://mock.iam.googleapis.com"

	ctx := context.Background()

	// 1. gcp_list_cloudrun_revisions
	revOut, err := reg.Execute(ctx, "gcp_list_cloudrun_revisions", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gcp_list_cloudrun_revisions failed: %v", err)
	}
	if !strings.Contains(revOut, "rev-prod-001") {
		t.Errorf("expected rev-prod-001 in revision output, got: %s", revOut)
	}
	if strings.Contains(revOut, "super-secret-env") || strings.Contains(revOut, "raw-key") {
		t.Errorf("revision output leaked sensitive keys: %s", revOut)
	}

	// 2. gcp_query_cloud_logging
	logOut, err := reg.Execute(ctx, "gcp_query_cloud_logging", map[string]interface{}{
		"limit": 5,
	}, nil)
	if err != nil {
		t.Fatalf("gcp_query_cloud_logging failed: %v", err)
	}
	if !strings.Contains(logOut, "Gateway healthy ready to serve") {
		t.Errorf("expected textPayload in log output, got: %s", logOut)
	}
	if strings.Contains(logOut, "secret-token") || strings.Contains(logOut, "sa-key-content") {
		t.Errorf("logging output leaked sensitive keys: %s", logOut)
	}

	// 3. gcp_list_storage_buckets
	bucketOut, err := reg.Execute(ctx, "gcp_list_storage_buckets", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gcp_list_storage_buckets failed: %v", err)
	}
	if !strings.Contains(bucketOut, "spark-prod-assets") {
		t.Errorf("expected spark-prod-assets in bucket output, got: %s", bucketOut)
	}

	// 4. gcp_list_artifact_repositories
	repoOut, err := reg.Execute(ctx, "gcp_list_artifact_repositories", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gcp_list_artifact_repositories failed: %v", err)
	}
	if !strings.Contains(repoOut, "spark-docker") {
		t.Errorf("expected spark-docker in repo output, got: %s", repoOut)
	}

	// 5. gcp_list_monitoring_alerts
	alertOut, err := reg.Execute(ctx, "gcp_list_monitoring_alerts", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gcp_list_monitoring_alerts failed: %v", err)
	}
	if !strings.Contains(alertOut, "High P99 Latency Alert") {
		t.Errorf("expected alert in output, got: %s", alertOut)
	}
	if strings.Contains(alertOut, "should-be-stripped") {
		t.Errorf("alert output leaked sensitive keys: %s", alertOut)
	}

	// 6. gcp_list_service_accounts
	saOut, err := reg.Execute(ctx, "gcp_list_service_accounts", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gcp_list_service_accounts failed: %v", err)
	}
	if !strings.Contains(saOut, "spark-run@p.iam.gserviceaccount.com") {
		t.Errorf("expected service account in output, got: %s", saOut)
	}
	if strings.Contains(saOut, "must-not-leak") {
		t.Errorf("sa output leaked private_key_data: %s", saOut)
	}

	// 7. gcp_describe_resource (positive case)
	descOut, err := reg.Execute(ctx, "gcp_describe_resource", map[string]interface{}{
		"resource_url": "http://mock.cloudrun.googleapis.com/v2/projects/p/locations/asia-southeast1/services/mock-service",
	}, nil)
	if err != nil {
		t.Fatalf("gcp_describe_resource failed: %v", err)
	}
	if !strings.Contains(descOut, "mock-service") {
		t.Errorf("expected mock-service in describe output, got: %s", descOut)
	}
	if strings.Contains(descOut, "env-should-strip") || strings.Contains(descOut, "pk-should-strip") {
		t.Errorf("describe output leaked sensitive keys: %s", descOut)
	}

	// 8. gcp_describe_resource security violation guardrails
	securityViolationTests := []struct {
		name string
		url  string
	}{
		{"accessSecretVersion", "https://secretmanager.googleapis.com/v1/projects/p/secrets/s/versions/1:accessSecretVersion"},
		{"signBlob", "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa:signBlob"},
		{"signJwt", "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa:signJwt"},
		{"secretVersionsPath", "https://secretmanager.googleapis.com/v1/projects/p/secrets/my-sec/versions/1"},
		{"nonGoogleAPIsHost", "https://evil.attacker.com/metadata"},
	}

	for _, tc := range securityViolationTests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := reg.Execute(ctx, "gcp_describe_resource", map[string]interface{}{
				"resource_url": tc.url,
			}, nil)
			if err == nil || !strings.Contains(err.Error(), "security violation") {
				t.Fatalf("expected security violation error for %s (%s), got: %v", tc.name, tc.url, err)
			}
		})
	}
}

func TestGFlowMCPTools(t *testing.T) {
	reg := NewRegistry(&config.Config{GCPProjectID: "spark-flow-project"}, nil, func(ctx context.Context) (string, error) {
		return "adc-flow-token", nil
	})
	ctx := context.Background()

	// 1. gflow_list_models
	modelsOut, err := reg.Execute(ctx, "gflow_list_models", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gflow_list_models failed: %v", err)
	}
	for _, m := range []string{"nano2", "nano2-lite", "nano-pro", "image4", "veo_fast", "veo_quality", "veo_lite", "omni_flash"} {
		if !strings.Contains(modelsOut, m) {
			t.Errorf("expected model %q in gflow_list_models output", m)
		}
	}

	// 2. gflow_list_tools
	toolsOut, err := reg.Execute(ctx, "gflow_list_tools", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gflow_list_tools failed: %v", err)
	}
	for _, tl := range []string{"creative-director", "cinematic-lighting", "character-consistency", "storyboard-expander", "camera-motion"} {
		if !strings.Contains(toolsOut, tl) {
			t.Errorf("expected tool %q in gflow_list_tools output", tl)
		}
	}

	// 3. gflow_auth_status
	authOut, err := reg.Execute(ctx, "gflow_auth_status", map[string]interface{}{"profile": "prod"}, nil)
	if err != nil {
		t.Fatalf("gflow_auth_status failed: %v", err)
	}
	if !strings.Contains(authOut, `"authenticated": true`) || !strings.Contains(authOut, "keyless_adc") {
		t.Errorf("unexpected gflow_auth_status output: %s", authOut)
	}

	// 4. gflow_get_credits
	creditsOut, err := reg.Execute(ctx, "gflow_get_credits", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gflow_get_credits failed: %v", err)
	}
	if !strings.Contains(creditsOut, "enterprise_adc") || !strings.Contains(creditsOut, "remaining_images") {
		t.Errorf("unexpected gflow_get_credits output: %s", creditsOut)
	}

	// 5. gflow_list_projects
	projOut, err := reg.Execute(ctx, "gflow_list_projects", map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("gflow_list_projects failed: %v", err)
	}
	if !strings.Contains(projOut, "spark-flow-project") {
		t.Errorf("expected spark-flow-project in projects output, got: %s", projOut)
	}

	// 6. gflow_character_list
	charListOut, err := reg.Execute(ctx, "gflow_character_list", map[string]interface{}{
		"project": "spark-flow-project",
	}, nil)
	if err != nil {
		t.Fatalf("gflow_character_list failed: %v", err)
	}
	if !strings.Contains(charListOut, "char-spark-lead") {
		t.Errorf("expected char-spark-lead in character list: %s", charListOut)
	}

	// Error when project is omitted
	if _, err := reg.Execute(ctx, "gflow_character_list", map[string]interface{}{}, nil); err == nil {
		t.Error("expected error when project is missing from gflow_character_list")
	}

	// 7. gflow_character_show
	charShowOut, err := reg.Execute(ctx, "gflow_character_show", map[string]interface{}{
		"project":   "spark-flow-project",
		"entity_id": "char-spark-lead",
	}, nil)
	if err != nil {
		t.Fatalf("gflow_character_show failed: %v", err)
	}
	if !strings.Contains(charShowOut, "char-spark-lead") || !strings.Contains(charShowOut, "Spark Lead Architect") {
		t.Errorf("unexpected character show output: %s", charShowOut)
	}

	// 8. gflow_generate_image
	imgGenOut, err := reg.Execute(ctx, "gflow_generate_image", map[string]interface{}{
		"prompt": "Cyberpunk cloud fortress at dusk",
		"model":  "nano2",
		"aspect": "16:9",
		"count":  2,
	}, nil)
	if err != nil {
		t.Fatalf("gflow_generate_image failed: %v", err)
	}
	if !strings.Contains(imgGenOut, `"status": "completed"`) || !strings.Contains(imgGenOut, "media-gflow-nano2") {
		t.Errorf("unexpected image generation output: %s", imgGenOut)
	}

	// Validation on invalid model
	if _, err := reg.Execute(ctx, "gflow_generate_image", map[string]interface{}{
		"prompt": "Test",
		"model":  "unsupported_model",
	}, nil); err == nil {
		t.Error("expected error with unsupported model")
	}

	// 9. gflow_generate_video
	vidGenOut, err := reg.Execute(ctx, "gflow_generate_video", map[string]interface{}{
		"prompt": "Drone flight over glowing server racks",
		"model":  "veo_fast",
		"aspect": "16:9",
	}, nil)
	if err != nil {
		t.Fatalf("gflow_generate_video failed: %v", err)
	}
	if !strings.Contains(vidGenOut, `"status": "completed"`) || !strings.Contains(vidGenOut, "video-gflow-veo_fast") {
		t.Errorf("unexpected video generation output: %s", vidGenOut)
	}

	// 10. gflow_upscale_image
	imgUpscaleOut, err := reg.Execute(ctx, "gflow_upscale_image", map[string]interface{}{
		"media_id": "media-12345",
		"scale":    "4k",
	}, nil)
	if err != nil {
		t.Fatalf("gflow_upscale_image failed: %v", err)
	}
	if !strings.Contains(imgUpscaleOut, `"status": "completed"`) || !strings.Contains(imgUpscaleOut, "media-12345-upscaled-4k") {
		t.Errorf("unexpected image upscale output: %s", imgUpscaleOut)
	}

	// 11. gflow_upscale_video
	vidUpscaleOut, err := reg.Execute(ctx, "gflow_upscale_video", map[string]interface{}{
		"media_id": "video-67890",
		"scale":    "1080p",
	}, nil)
	if err != nil {
		t.Fatalf("gflow_upscale_video failed: %v", err)
	}
	if !strings.Contains(vidUpscaleOut, `"status": "completed"`) || !strings.Contains(vidUpscaleOut, "video-67890-upscaled-1080p") {
		t.Errorf("unexpected video upscale output: %s", vidUpscaleOut)
	}

	// 12. Test Remote HTTP Bridge with r.GFlowBaseURL
	bridgeClient := &http.Client{
		Transport: mockTransport(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", "application/json")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.Write([]byte(`{"upstream_bridge": true, "result": "generated-via-http-bridge"}`))
			return rec.Result(), nil
		}),
	}
	regBridge := NewRegistry(&config.Config{GCPProjectID: "spark-bridge"}, bridgeClient, func(ctx context.Context) (string, error) {
		return "bridge-adc", nil
	})
	regBridge.GFlowBaseURL = "http://mock.gflow.bridge"

	bridgeOut, err := regBridge.Execute(ctx, "gflow_generate_image", map[string]interface{}{
		"prompt": "Prompt via bridge",
	}, nil)
	if err != nil {
		t.Fatalf("gflow_generate_image via bridge failed: %v", err)
	}
	if !strings.Contains(bridgeOut, "generated-via-http-bridge") {
		t.Errorf("expected bridge output, got: %s", bridgeOut)
	}
}