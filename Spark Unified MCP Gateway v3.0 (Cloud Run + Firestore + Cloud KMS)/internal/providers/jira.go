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

func (r *Registry) registerJiraTools() {
	// 4. jira_get_issue
	r.RegisterTool(ToolDefinition{
		Name:          "jira_get_issue",
		Description:   "Retrieve a Jira issue by key with clean plaintext ADF description.",
		Provider:      "jira",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"issue_key": map[string]interface{}{
					"type":        "string",
					"description": "Jira issue key (e.g. PROJ-123)",
				},
			},
			"required": []string{"issue_key"},
		},
	}, r.handleJiraGetIssue)

	// 5. jira_update_issue_status
	r.RegisterTool(ToolDefinition{
		Name:          "jira_update_issue_status",
		Description:   "Transition a Jira issue to a new status.",
		Provider:      "jira",
		RequiredScope: "full_access",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"issue_key": map[string]interface{}{
					"type":        "string",
					"description": "Jira issue key (e.g. PROJ-123)",
				},
				"status": map[string]interface{}{
					"type":        "string",
					"description": "Target status name (e.g. 'In Progress', 'Done', 'Resolved')",
				},
			},
			"required": []string{"issue_key", "status"},
		},
	}, r.handleJiraUpdateIssueStatus)
}

func (r *Registry) handleJiraGetIssue(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	if token == nil || token.AccessToken == "" {
		return "", errors.New("jira connection required: please connect Jira Cloud on gateway dashboard")
	}
	if token.CloudID == "" {
		return "", errors.New("jira cloudId missing from connection: please reconnect Jira")
	}

	issueKey := getStringArg(args, "issue_key", "")
	if issueKey == "" {
		return "", errors.New("missing required argument: issue_key")
	}

	endpoint := fmt.Sprintf("%s/ex/jira/%s/rest/api/3/issue/%s", r.JiraBaseURL, token.CloudID, url.PathEscape(issueKey))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
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
		return "", fmt.Errorf("jira api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var issue struct {
		Key    string `json:"key"`
		Fields struct {
			Summary string `json:"summary"`
			Status  struct {
				Name string `json:"name"`
			} `json:"status"`
			Assignee struct {
				DisplayName string `json:"displayName"`
			} `json:"assignee"`
			Priority struct {
				Name string `json:"name"`
			} `json:"priority"`
			Description interface{} `json:"description"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(body, &issue); err != nil {
		return "", err
	}

	plainDescription := FlattenADF(issue.Fields.Description)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Jira Issue: %s\n", issue.Key))
	sb.WriteString(fmt.Sprintf("Summary: %s\n", issue.Fields.Summary))
	sb.WriteString(fmt.Sprintf("Status: %s\n", issue.Fields.Status.Name))
	if issue.Fields.Priority.Name != "" {
		sb.WriteString(fmt.Sprintf("Priority: %s\n", issue.Fields.Priority.Name))
	}
	if issue.Fields.Assignee.DisplayName != "" {
		sb.WriteString(fmt.Sprintf("Assignee: %s\n", issue.Fields.Assignee.DisplayName))
	} else {
		sb.WriteString("Assignee: Unassigned\n")
	}
	sb.WriteString("\nDescription:\n")
	sb.WriteString(plainDescription)

	return sb.String(), nil
}

func (r *Registry) handleJiraUpdateIssueStatus(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	if token == nil || token.AccessToken == "" {
		return "", errors.New("jira connection required: please connect Jira Cloud on gateway dashboard")
	}
	if token.CloudID == "" {
		return "", errors.New("jira cloudId missing from connection: please reconnect Jira")
	}

	issueKey := getStringArg(args, "issue_key", "")
	targetStatus := getStringArg(args, "status", "")
	if issueKey == "" || targetStatus == "" {
		return "", errors.New("missing required arguments: issue_key and status")
	}

	// 1. Fetch available transitions
	transitionsURL := fmt.Sprintf("%s/ex/jira/%s/rest/api/3/issue/%s/transitions", r.JiraBaseURL, token.CloudID, url.PathEscape(issueKey))
	req, err := http.NewRequestWithContext(ctx, "GET", transitionsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")

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
		return "", fmt.Errorf("failed fetching transitions (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name string `json:"name"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}

	var matchedID string
	var matchedName string
	var available []string

	for _, t := range res.Transitions {
		available = append(available, t.Name)
		if strings.EqualFold(t.Name, targetStatus) || strings.EqualFold(t.To.Name, targetStatus) {
			matchedID = t.ID
			matchedName = t.Name
			break
		}
	}

	if matchedID == "" {
		return "", fmt.Errorf("target status %q is not a valid transition for %s; available transitions: %s", targetStatus, issueKey, strings.Join(available, ", "))
	}

	// 2. Execute transition POST
	transitionPayload := map[string]interface{}{
		"transition": map[string]interface{}{
			"id": matchedID,
		},
	}
	payloadBytes, err := json.Marshal(transitionPayload)
	if err != nil {
		return "", err
	}

	postReq, err := http.NewRequestWithContext(ctx, "POST", transitionsURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return "", err
	}
	postReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Accept", "application/json")

	postResp, err := r.httpClient.Do(postReq)
	if err != nil {
		return "", err
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusNoContent && postResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(postResp.Body, maxResponseBodyBytes))
		return "", fmt.Errorf("transition failed (HTTP %d): %s", postResp.StatusCode, string(respBody))
	}

	return fmt.Sprintf("Successfully transitioned %s to %q (transition: %s)", issueKey, targetStatus, matchedName), nil
}

// FlattenADF converts Atlassian Document Format (ADF) into clean readable plaintext.
func FlattenADF(adf interface{}) string {
	if adf == nil {
		return "No description provided."
	}
	if s, ok := adf.(string); ok {
		return s
	}

	m, ok := adf.(map[string]interface{})
	if !ok {
		return fmt.Sprintf("%v", adf)
	}

	var sb strings.Builder
	traverseADFNode(m, &sb)
	result := strings.TrimSpace(sb.String())
	if result == "" {
		return "No description provided."
	}
	return result
}

func traverseADFNode(node map[string]interface{}, sb *strings.Builder) {
	nodeType, _ := node["type"].(string)

	switch nodeType {
	case "text":
		if text, ok := node["text"].(string); ok {
			sb.WriteString(text)
		}
	case "paragraph", "heading":
		traverseChildren(node, sb)
		sb.WriteString("\n\n")
	case "listItem":
		sb.WriteString("- ")
		traverseChildren(node, sb)
		sb.WriteString("\n")
	case "codeBlock":
		sb.WriteString("```\n")
		traverseChildren(node, sb)
		sb.WriteString("\n```\n\n")
	default:
		traverseChildren(node, sb)
	}
}

func traverseChildren(node map[string]interface{}, sb *strings.Builder) {
	content, ok := node["content"].([]interface{})
	if !ok {
		return
	}
	for _, item := range content {
		if childMap, ok := item.(map[string]interface{}); ok {
			traverseADFNode(childMap, sb)
		}
	}
}
