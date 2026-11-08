package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"spark-mcp-gateway/internal/vault"
)

func (r *Registry) registerGDKTools() {
	// 8. gdk_search_docs
	r.RegisterTool(ToolDefinition{
		Name:            "gdk_search_docs",
		Description:     "Search Google Developer Knowledge documentation chunks via keyless ADC.",
		Provider:        "gdk",
		RequiredScope:   "read_only",
		MinimalBaseline: true,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "Search query keywords for Google Cloud / developer docs",
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of document chunks to return (default: 5, max: 20)",
				},
			},
			"required": []string{"query"},
		},
	}, r.handleGDKSearchDocs)
}

func (r *Registry) registerAllTools() {
	r.registerGitHubTools()
	r.registerJiraTools()
	r.registerGCPTools()
	r.registerGDKTools()
}

func parseJSON(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

func (r *Registry) handleGDKSearchDocs(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	query := getStringArg(args, "query", "")
	if query == "" {
		return "", errors.New("missing required argument: query")
	}

	pageSize := 5
	if ps, ok := args["page_size"]; ok {
		switch v := ps.(type) {
		case float64:
			pageSize = int(v)
		case int:
			pageSize = v
		case string:
			if parsed, err := strconv.Atoi(v); err == nil {
				pageSize = parsed
			}
		}
	}
	if pageSize <= 0 {
		pageSize = 5
	}
	if pageSize > 20 {
		pageSize = 20
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token for GDK search: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/documents:searchDocumentChunks?query=%s&pageSize=%d", r.GDKBaseURL, url.QueryEscape(query), pageSize)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if r.cfg.GCPProjectID != "" {
		req.Header.Set("X-Goog-User-Project", r.cfg.GCPProjectID)
	}

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
		return "", fmt.Errorf("gdk api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		DocumentChunks []struct {
			DocumentTitle string `json:"documentTitle"`
			DocumentURI   string `json:"documentUri"`
			ChunkContent  string `json:"chunkContent"`
			Snippet       string `json:"snippet"`
		} `json:"documentChunks"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}

	if len(res.DocumentChunks) == 0 {
		return fmt.Sprintf("No developer documentation chunks found matching %q.", query), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Google Developer Knowledge Search Results for %q:\n\n", query))
	for i, chunk := range res.DocumentChunks {
		title := chunk.DocumentTitle
		if title == "" {
			title = chunk.DocumentURI
		}
		sb.WriteString(fmt.Sprintf("### %d. %s\n", i+1, title))
		if chunk.DocumentURI != "" {
			sb.WriteString(fmt.Sprintf("Source: %s\n", chunk.DocumentURI))
		}
		content := chunk.ChunkContent
		if content == "" {
			content = chunk.Snippet
		}
		sb.WriteString(fmt.Sprintf("%s\n\n", strings.TrimSpace(content)))
	}

	return strings.TrimSpace(sb.String()), nil
}
