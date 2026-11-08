package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"spark-mcp-gateway/internal/vault"
)

const maxResponseBodyBytes = 512 * 1024 // 512 KB

func (r *Registry) registerGitHubTools() {
	// 1. github_list_prs
	r.RegisterTool(ToolDefinition{
		Name:          "github_list_prs",
		Description:   "List pull requests for a specified GitHub repository.",
		Provider:      "github",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"owner": map[string]interface{}{
					"type":        "string",
					"description": "Repository owner or organization name",
				},
				"repo": map[string]interface{}{
					"type":        "string",
					"description": "Repository name",
				},
				"state": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"open", "closed", "all"},
					"description": "Filter by state: open, closed, or all (default: open)",
				},
			},
			"required": []string{"owner", "repo"},
		},
	}, r.handleGitHubListPRs)

	// 2. github_read_file
	r.RegisterTool(ToolDefinition{
		Name:          "github_read_file",
		Description:   "Read the raw content of a file from a GitHub repository.",
		Provider:      "github",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"owner": map[string]interface{}{
					"type":        "string",
					"description": "Repository owner or organization",
				},
				"repo": map[string]interface{}{
					"type":        "string",
					"description": "Repository name",
				},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Path to file inside the repository",
				},
				"ref": map[string]interface{}{
					"type":        "string",
					"description": "Optional branch, tag, or commit SHA (default: default branch)",
				},
			},
			"required": []string{"owner", "repo", "path"},
		},
	}, r.handleGitHubReadFile)

	// 3. github_create_issue
	r.RegisterTool(ToolDefinition{
		Name:          "github_create_issue",
		Description:   "Create a new issue in a GitHub repository.",
		Provider:      "github",
		RequiredScope: "full_access",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"owner": map[string]interface{}{
					"type":        "string",
					"description": "Repository owner",
				},
				"repo": map[string]interface{}{
					"type":        "string",
					"description": "Repository name",
				},
				"title": map[string]interface{}{
					"type":        "string",
					"description": "Issue title",
				},
				"body": map[string]interface{}{
					"type":        "string",
					"description": "Issue body markdown text",
				},
				"labels": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "List of label names",
				},
			},
			"required": []string{"owner", "repo", "title"},
		},
	}, r.handleGitHubCreateIssue)
}

func (r *Registry) handleGitHubListPRs(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	if token == nil || token.AccessToken == "" {
		return "", errors.New("github connection required: please connect GitHub on gateway dashboard")
	}

	owner := getStringArg(args, "owner", "")
	repo := getStringArg(args, "repo", "")
	if owner == "" || repo == "" {
		return "", errors.New("missing required arguments: owner and repo")
	}

	state := getStringArg(args, "state", "open")
	endpoint := fmt.Sprintf("%s/repos/%s/%s/pulls?per_page=20&state=%s", r.GitHubBaseURL, url.PathEscape(owner), url.PathEscape(repo), url.QueryEscape(state))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "spark-mcp-gateway/3.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var prs []struct {
		Number    int    `json:"number"`
		Title     string `json:"title"`
		State     string `json:"state"`
		HTMLURL   string `json:"html_url"`
		CreatedAt string `json:"created_at"`
		User      struct {
			Login string `json:"login"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &prs); err != nil {
		return "", err
	}

	if len(prs) == 0 {
		return fmt.Sprintf("No %s pull requests found for %s/%s.", state, owner, repo), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Pull Requests for %s/%s (%s):\n", owner, repo, state))
	for _, pr := range prs {
		sb.WriteString(fmt.Sprintf("- #%d: %s (author: @%s, status: %s) -> %s\n", pr.Number, pr.Title, pr.User.Login, pr.State, pr.HTMLURL))
	}

	return sb.String(), nil
}

func isValidRepoName(s string) bool {
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, "/\\% \t\r\n\x00") || strings.Contains(s, "..") {
		return false
	}
	return true
}

func sanitizeGitHubFilePath(rawPath string) (string, error) {
	if rawPath == "" {
		return "", errors.New("file path cannot be empty")
	}
	if strings.Contains(rawPath, "\\") || strings.Contains(rawPath, "\x00") {
		return "", errors.New("invalid path: contains forbidden characters")
	}

	// Reject URL-encoded path traversal sequences (%2e, %2f, %5c)
	lower := strings.ToLower(rawPath)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", errors.New("invalid path: contains encoded path traversal sequence")
	}

	parts := strings.Split(strings.TrimPrefix(rawPath, "/"), "/")
	escapedParts := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			return "", errors.New("invalid path: contains relative or empty traversal segment")
		}
		escapedParts = append(escapedParts, url.PathEscape(p))
	}
	if len(escapedParts) == 0 {
		return "", errors.New("invalid path: no valid segments")
	}
	return strings.Join(escapedParts, "/"), nil
}

func (r *Registry) handleGitHubReadFile(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	if token == nil || token.AccessToken == "" {
		return "", errors.New("github connection required: please connect GitHub on gateway dashboard")
	}

	owner := getStringArg(args, "owner", "")
	repo := getStringArg(args, "repo", "")
	filePath := getStringArg(args, "path", "")

	if !isValidRepoName(owner) || !isValidRepoName(repo) {
		return "", fmt.Errorf("invalid repository owner %q or repo %q", owner, repo)
	}

	safePath, err := sanitizeGitHubFilePath(filePath)
	if err != nil {
		return "", fmt.Errorf("path validation failed: %w", err)
	}

	ref := getStringArg(args, "ref", "")
	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s", r.GitHubBaseURL, url.PathEscape(owner), url.PathEscape(repo), safePath)
	if ref != "" {
		endpoint += "?ref=" + url.QueryEscape(ref)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github.raw+json")
	req.Header.Set("User-Agent", "spark-mcp-gateway/3.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

func (r *Registry) handleGitHubCreateIssue(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	if token == nil || token.AccessToken == "" {
		return "", errors.New("github connection required: please connect GitHub on gateway dashboard")
	}

	owner := getStringArg(args, "owner", "")
	repo := getStringArg(args, "repo", "")
	title := getStringArg(args, "title", "")
	if owner == "" || repo == "" || title == "" {
		return "", errors.New("missing required arguments: owner, repo, and title")
	}

	// Security Policy Check: GITHUB_ALLOWED_WRITE_REPOS allowlist
	if !r.cfg.IsRepoAllowedForWrite(owner, repo) {
		return "", fmt.Errorf("repository %s/%s is not in GITHUB_ALLOWED_WRITE_REPOS allowlist", owner, repo)
	}

	bodyText := getStringArg(args, "body", "")
	payload := map[string]interface{}{
		"title": title,
	}
	if bodyText != "" {
		payload["body"] = bodyText
	}
	if rawLabels, ok := args["labels"].([]interface{}); ok && len(rawLabels) > 0 {
		var labels []string
		for _, l := range rawLabels {
			if s, ok := l.(string); ok && s != "" {
				labels = append(labels, s)
			}
		}
		if len(labels) > 0 {
			payload["labels"] = labels
		}
	}

	reqBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s/issues", r.GitHubBaseURL, url.PathEscape(owner), url.PathEscape(repo))
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "spark-mcp-gateway/3.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var issue struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(respBody, &issue); err != nil {
		return "", err
	}

	return fmt.Sprintf("Successfully created issue #%d in %s/%s:\nTitle: %s\nURL: %s\nStatus: %s", issue.Number, owner, repo, issue.Title, issue.HTMLURL, issue.State), nil
}
