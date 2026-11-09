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

const notionAPIVersion = "2022-06-28"

func (r *Registry) registerNotionTools() {
	// 1. notion_search
	r.RegisterTool(ToolDefinition{
		Name:            "notion_search",
		Description:     "Search pages and databases across the connected Notion workspace.",
		Provider:        "notion",
		RequiredScope:   "read_only",
		MinimalBaseline: true,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type":        "string",
					"description": "Text query to search titles and content",
				},
				"object_type": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"page", "database"},
					"description": "Filter by object type: 'page' or 'database'",
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of results to return (default: 10, max: 50)",
				},
			},
		},
	}, r.handleNotionSearch)

	// 2. notion_get_page
	r.RegisterTool(ToolDefinition{
		Name:            "notion_get_page",
		Description:     "Get details, metadata, and properties of a Notion page by ID.",
		Provider:        "notion",
		RequiredScope:   "read_only",
		MinimalBaseline: true,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"page_id": map[string]interface{}{
					"type":        "string",
					"description": "Notion page ID (UUID format, with or without dashes)",
				},
			},
			"required": []string{"page_id"},
		},
	}, r.handleNotionGetPage)

	// 3. notion_get_block_children
	r.RegisterTool(ToolDefinition{
		Name:            "notion_get_block_children",
		Description:     "Read and render child content blocks of a page or block into clean Markdown.",
		Provider:        "notion",
		RequiredScope:   "read_only",
		MinimalBaseline: true,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"block_id": map[string]interface{}{
					"type":        "string",
					"description": "Notion page ID or parent block ID",
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of blocks to return (default: 50, max: 100)",
				},
			},
			"required": []string{"block_id"},
		},
	}, r.handleNotionGetBlockChildren)

	// 4. notion_query_database
	r.RegisterTool(ToolDefinition{
		Name:            "notion_query_database",
		Description:     "Query rows and pages within a Notion database.",
		Provider:        "notion",
		RequiredScope:   "read_only",
		MinimalBaseline: false,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"database_id": map[string]interface{}{
					"type":        "string",
					"description": "Notion database ID",
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Number of rows to return (default: 20, max: 100)",
				},
			},
			"required": []string{"database_id"},
		},
	}, r.handleNotionQueryDatabase)

	// 5. notion_get_database
	r.RegisterTool(ToolDefinition{
		Name:            "notion_get_database",
		Description:     "Get schema and properties definition of a Notion database.",
		Provider:        "notion",
		RequiredScope:   "read_only",
		MinimalBaseline: false,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"database_id": map[string]interface{}{
					"type":        "string",
					"description": "Notion database ID",
				},
			},
			"required": []string{"database_id"},
		},
	}, r.handleNotionGetDatabase)

	// 6. notion_create_page
	r.RegisterTool(ToolDefinition{
		Name:            "notion_create_page",
		Description:     "Create a new Notion page inside a parent page or database with optional content.",
		Provider:        "notion",
		RequiredScope:   "full_access",
		MinimalBaseline: false,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"title": map[string]interface{}{
					"type":        "string",
					"description": "Title of the new page",
				},
				"parent_page_id": map[string]interface{}{
					"type":        "string",
					"description": "Parent page ID (required if parent_database_id is not provided)",
				},
				"parent_database_id": map[string]interface{}{
					"type":        "string",
					"description": "Parent database ID (required if parent_page_id is not provided)",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "Initial text content to add as a paragraph block",
				},
			},
			"required": []string{"title"},
		},
	}, r.handleNotionCreatePage)

	// 7. notion_append_block_children
	r.RegisterTool(ToolDefinition{
		Name:            "notion_append_block_children",
		Description:     "Append a content block (e.g. paragraph) to a Notion page or block.",
		Provider:        "notion",
		RequiredScope:   "full_access",
		MinimalBaseline: false,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"block_id": map[string]interface{}{
					"type":        "string",
					"description": "Notion page ID or block ID to append to",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "Text content to append as a paragraph block",
				},
			},
			"required": []string{"block_id", "content"},
		},
	}, r.handleNotionAppendBlockChildren)
}

func notionSanitizeID(raw string) (string, error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", errors.New("id cannot be empty")
	}
	if strings.Contains(clean, "/") || strings.Contains(clean, "..") || strings.Contains(clean, "\\") || strings.Contains(clean, "?") || strings.Contains(clean, "#") {
		return "", errors.New("invalid id: contains forbidden path characters")
	}
	return url.PathEscape(clean), nil
}

func (r *Registry) doNotionRequest(ctx context.Context, method, path string, bodyBytes []byte, token *vault.TokenData) ([]byte, error) {
	if token == nil || token.AccessToken == "" {
		return nil, errors.New("notion access token required: provider is not connected")
	}

	endpoint := fmt.Sprintf("%s%s", strings.TrimSuffix(r.NotionBaseURL, "/"), path)
	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Notion-Version", notionAPIVersion)
	req.Header.Set("User-Agent", "Spark-Unified-MCP-Gateway/3.0")
	if len(bodyBytes) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("notion api error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func extractNotionRichText(rt interface{}) string {
	slice, ok := rt.([]interface{})
	if !ok {
		return ""
	}
	var sb strings.Builder
	for _, item := range slice {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if pt, ok := m["plain_text"].(string); ok && pt != "" {
			sb.WriteString(pt)
		} else if txt, ok := m["text"].(map[string]interface{}); ok {
			if content, ok := txt["content"].(string); ok {
				sb.WriteString(content)
			}
		}
	}
	return sb.String()
}

func extractNotionPageTitle(props map[string]interface{}) string {
	for _, prop := range props {
		pMap, ok := prop.(map[string]interface{})
		if !ok {
			continue
		}
		if pType, ok := pMap["type"].(string); ok && pType == "title" {
			t := extractNotionRichText(pMap["title"])
			if t != "" {
				return t
			}
		}
	}
	return "Untitled"
}

func extractNotionDatabaseTitle(titleArr interface{}) string {
	t := extractNotionRichText(titleArr)
	if t == "" {
		return "Untitled Database"
	}
	return t
}

func formatNotionBlock(b map[string]interface{}) string {
	bType, _ := b["type"].(string)
	data, _ := b[bType].(map[string]interface{})
	rt := ""
	if data != nil {
		rt = extractNotionRichText(data["rich_text"])
	}

	switch bType {
	case "paragraph":
		return rt + "\n\n"
	case "heading_1":
		return "# " + rt + "\n\n"
	case "heading_2":
		return "## " + rt + "\n\n"
	case "heading_3":
		return "### " + rt + "\n\n"
	case "bulleted_list_item":
		return "- " + rt + "\n"
	case "numbered_list_item":
		return "1. " + rt + "\n"
	case "to_do":
		checked, _ := data["checked"].(bool)
		box := "[ ] "
		if checked {
			box = "[x] "
		}
		return box + rt + "\n"
	case "code":
		lang, _ := data["language"].(string)
		return "```" + lang + "\n" + rt + "\n```\n\n"
	case "quote":
		return "> " + rt + "\n\n"
	case "callout":
		return "> 💡 " + rt + "\n\n"
	case "divider":
		return "---\n\n"
	default:
		if rt != "" {
			return rt + "\n\n"
		}
		return ""
	}
}

func flattenNotionProperties(props map[string]interface{}) map[string]interface{} {
	flat := make(map[string]interface{})
	for k, v := range props {
		pMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		pType, _ := pMap["type"].(string)
		switch pType {
		case "title":
			flat[k] = extractNotionRichText(pMap["title"])
		case "rich_text":
			flat[k] = extractNotionRichText(pMap["rich_text"])
		case "number":
			flat[k] = pMap["number"]
		case "select":
			if sel, ok := pMap["select"].(map[string]interface{}); ok {
				flat[k] = sel["name"]
			}
		case "multi_select":
			if ms, ok := pMap["multi_select"].([]interface{}); ok {
				var names []string
				for _, item := range ms {
					if im, ok := item.(map[string]interface{}); ok {
						if n, ok := im["name"].(string); ok {
							names = append(names, n)
						}
					}
				}
				flat[k] = names
			}
		case "status":
			if st, ok := pMap["status"].(map[string]interface{}); ok {
				flat[k] = st["name"]
			}
		case "date":
			if dt, ok := pMap["date"].(map[string]interface{}); ok {
				flat[k] = dt["start"]
			}
		case "checkbox":
			flat[k] = pMap["checkbox"]
		case "url":
			flat[k] = pMap["url"]
		case "email":
			flat[k] = pMap["email"]
		case "phone_number":
			flat[k] = pMap["phone_number"]
		case "created_time":
			flat[k] = pMap["created_time"]
		case "last_edited_time":
			flat[k] = pMap["last_edited_time"]
		default:
			flat[k] = fmt.Sprintf("[%s]", pType)
		}
	}
	return flat
}

// 1. handleNotionSearch
func (r *Registry) handleNotionSearch(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	query := getStringArg(args, "query", "")
	objectType := getStringArg(args, "object_type", "")
	pageSize := 10
	if ps, ok := args["page_size"]; ok {
		if f, ok := ps.(float64); ok && f > 0 {
			pageSize = int(f)
		} else if i, ok := ps.(int); ok && i > 0 {
			pageSize = i
		}
	}
	if pageSize > 50 {
		pageSize = 50
	}

	payload := map[string]interface{}{
		"query":     query,
		"page_size": pageSize,
	}
	if objectType == "page" || objectType == "database" {
		payload["filter"] = map[string]interface{}{
			"value":    objectType,
			"property": "object",
		}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	respBytes, err := r.doNotionRequest(ctx, "POST", "/v1/search", bodyBytes, token)
	if err != nil {
		return "", err
	}

	var raw struct {
		Results []map[string]interface{} `json:"results"`
		HasMore bool                     `json:"has_more"`
	}
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return string(respBytes), nil
	}

	type searchItem struct {
		ID             string `json:"id"`
		ObjectType     string `json:"object_type"`
		Title          string `json:"title"`
		URL            string `json:"url"`
		LastEditedTime string `json:"last_edited_time"`
	}

	items := make([]searchItem, 0, len(raw.Results))
	for _, res := range raw.Results {
		objType, _ := res["object"].(string)
		id, _ := res["id"].(string)
		urlStr, _ := res["url"].(string)
		lastEdited, _ := res["last_edited_time"].(string)

		title := "Untitled"
		if objType == "page" {
			if props, ok := res["properties"].(map[string]interface{}); ok {
				title = extractNotionPageTitle(props)
			}
		} else if objType == "database" {
			title = extractNotionDatabaseTitle(res["title"])
		}

		items = append(items, searchItem{
			ID:             id,
			ObjectType:     objType,
			Title:          title,
			URL:            urlStr,
			LastEditedTime: lastEdited,
		})
	}

	cleanJSON, err := json.MarshalIndent(map[string]interface{}{
		"results":  items,
		"total":    len(items),
		"has_more": raw.HasMore,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(cleanJSON), nil
}

// 2. handleNotionGetPage
func (r *Registry) handleNotionGetPage(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	pageID := getStringArg(args, "page_id", "")
	cleanID, err := notionSanitizeID(pageID)
	if err != nil {
		return "", fmt.Errorf("invalid page_id: %w", err)
	}

	respBytes, err := r.doNotionRequest(ctx, "GET", "/v1/pages/"+cleanID, nil, token)
	if err != nil {
		return "", err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return string(respBytes), nil
	}

	props, _ := raw["properties"].(map[string]interface{})
	flatProps := flattenNotionProperties(props)
	title := extractNotionPageTitle(props)

	result := map[string]interface{}{
		"id":               raw["id"],
		"url":              raw["url"],
		"title":            title,
		"created_time":     raw["created_time"],
		"last_edited_time": raw["last_edited_time"],
		"archived":         raw["archived"],
		"properties":       flatProps,
	}

	cleanJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(cleanJSON), nil
}

// 3. handleNotionGetBlockChildren
func (r *Registry) handleNotionGetBlockChildren(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	blockID := getStringArg(args, "block_id", "")
	cleanID, err := notionSanitizeID(blockID)
	if err != nil {
		return "", fmt.Errorf("invalid block_id: %w", err)
	}

	pageSize := 50
	if ps, ok := args["page_size"]; ok {
		if f, ok := ps.(float64); ok && f > 0 {
			pageSize = int(f)
		} else if i, ok := ps.(int); ok && i > 0 {
			pageSize = i
		}
	}
	if pageSize > 100 {
		pageSize = 100
	}

	path := fmt.Sprintf("/v1/blocks/%s/children?page_size=%d", cleanID, pageSize)
	respBytes, err := r.doNotionRequest(ctx, "GET", path, nil, token)
	if err != nil {
		return "", err
	}

	var raw struct {
		Results []map[string]interface{} `json:"results"`
		HasMore bool                     `json:"has_more"`
	}
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return string(respBytes), nil
	}

	var markdownBuilder strings.Builder
	for _, b := range raw.Results {
		markdownBuilder.WriteString(formatNotionBlock(b))
	}

	renderedMarkdown := strings.TrimSpace(markdownBuilder.String())
	if renderedMarkdown == "" {
		renderedMarkdown = "_No text content in this block/page._"
	}

	result := map[string]interface{}{
		"block_id":    blockID,
		"block_count": len(raw.Results),
		"has_more":    raw.HasMore,
		"markdown":    renderedMarkdown,
	}

	cleanJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(cleanJSON), nil
}

// 4. handleNotionQueryDatabase
func (r *Registry) handleNotionQueryDatabase(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	dbID := getStringArg(args, "database_id", "")
	cleanID, err := notionSanitizeID(dbID)
	if err != nil {
		return "", fmt.Errorf("invalid database_id: %w", err)
	}

	pageSize := 20
	if ps, ok := args["page_size"]; ok {
		if f, ok := ps.(float64); ok && f > 0 {
			pageSize = int(f)
		} else if i, ok := ps.(int); ok && i > 0 {
			pageSize = i
		}
	}
	if pageSize > 100 {
		pageSize = 100
	}

	payload := map[string]interface{}{
		"page_size": pageSize,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("/v1/databases/%s/query", cleanID)
	respBytes, err := r.doNotionRequest(ctx, "POST", path, bodyBytes, token)
	if err != nil {
		return "", err
	}

	var raw struct {
		Results []map[string]interface{} `json:"results"`
		HasMore bool                     `json:"has_more"`
	}
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return string(respBytes), nil
	}

	type dbRow struct {
		ID             string                 `json:"id"`
		Title          string                 `json:"title"`
		URL            string                 `json:"url"`
		LastEditedTime string                 `json:"last_edited_time"`
		Properties     map[string]interface{} `json:"properties"`
	}

	rows := make([]dbRow, 0, len(raw.Results))
	for _, res := range raw.Results {
		id, _ := res["id"].(string)
		urlStr, _ := res["url"].(string)
		lastEdited, _ := res["last_edited_time"].(string)
		props, _ := res["properties"].(map[string]interface{})
		title := extractNotionPageTitle(props)
		flatProps := flattenNotionProperties(props)

		rows = append(rows, dbRow{
			ID:             id,
			Title:          title,
			URL:            urlStr,
			LastEditedTime: lastEdited,
			Properties:     flatProps,
		})
	}

	cleanJSON, err := json.MarshalIndent(map[string]interface{}{
		"database_id": dbID,
		"total_rows":  len(rows),
		"has_more":    raw.HasMore,
		"rows":        rows,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(cleanJSON), nil
}

// 5. handleNotionGetDatabase
func (r *Registry) handleNotionGetDatabase(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	dbID := getStringArg(args, "database_id", "")
	cleanID, err := notionSanitizeID(dbID)
	if err != nil {
		return "", fmt.Errorf("invalid database_id: %w", err)
	}

	path := fmt.Sprintf("/v1/databases/%s", cleanID)
	respBytes, err := r.doNotionRequest(ctx, "GET", path, nil, token)
	if err != nil {
		return "", err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return string(respBytes), nil
	}

	title := extractNotionDatabaseTitle(raw["title"])
	props, _ := raw["properties"].(map[string]interface{})
	schema := make(map[string]string)
	for k, v := range props {
		if pMap, ok := v.(map[string]interface{}); ok {
			if pType, ok := pMap["type"].(string); ok {
				schema[k] = pType
			}
		}
	}

	result := map[string]interface{}{
		"id":               raw["id"],
		"title":            title,
		"url":              raw["url"],
		"created_time":     raw["created_time"],
		"last_edited_time": raw["last_edited_time"],
		"schema":           schema,
	}

	cleanJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(cleanJSON), nil
}

// 6. handleNotionCreatePage
func (r *Registry) handleNotionCreatePage(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	title := getStringArg(args, "title", "")
	if title == "" {
		return "", errors.New("missing required argument: title")
	}

	parentPageID := getStringArg(args, "parent_page_id", "")
	parentDBID := getStringArg(args, "parent_database_id", "")
	if parentPageID == "" && parentDBID == "" {
		return "", errors.New("either parent_page_id or parent_database_id is required")
	}

	parent := make(map[string]interface{})
	if parentDBID != "" {
		cleanDBID, err := notionSanitizeID(parentDBID)
		if err != nil {
			return "", fmt.Errorf("invalid parent_database_id: %w", err)
		}
		parent["database_id"] = cleanDBID
	} else {
		cleanPageID, err := notionSanitizeID(parentPageID)
		if err != nil {
			return "", fmt.Errorf("invalid parent_page_id: %w", err)
		}
		parent["page_id"] = cleanPageID
	}

	properties := map[string]interface{}{
		"title": map[string]interface{}{
			"title": []map[string]interface{}{
				{
					"type": "text",
					"text": map[string]interface{}{
						"content": title,
					},
				},
			},
		},
	}

	payload := map[string]interface{}{
		"parent":     parent,
		"properties": properties,
	}

	content := getStringArg(args, "content", "")
	if content != "" {
		payload["children"] = []map[string]interface{}{
			{
				"object": "block",
				"type":   "paragraph",
				"paragraph": map[string]interface{}{
					"rich_text": []map[string]interface{}{
						{
							"type": "text",
							"text": map[string]interface{}{
								"content": content,
							},
						},
					},
				},
			},
		}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	respBytes, err := r.doNotionRequest(ctx, "POST", "/v1/pages", bodyBytes, token)
	if err != nil {
		return "", err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return string(respBytes), nil
	}

	result := map[string]interface{}{
		"status":     "created",
		"id":         raw["id"],
		"url":        raw["url"],
		"title":      title,
		"created_at": raw["created_time"],
	}

	cleanJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(cleanJSON), nil
}

// 7. handleNotionAppendBlockChildren
func (r *Registry) handleNotionAppendBlockChildren(ctx context.Context, args map[string]interface{}, token *vault.TokenData) (string, error) {
	blockID := getStringArg(args, "block_id", "")
	cleanID, err := notionSanitizeID(blockID)
	if err != nil {
		return "", fmt.Errorf("invalid block_id: %w", err)
	}

	content := getStringArg(args, "content", "")
	if content == "" {
		return "", errors.New("missing required argument: content")
	}

	payload := map[string]interface{}{
		"children": []map[string]interface{}{
			{
				"object": "block",
				"type":   "paragraph",
				"paragraph": map[string]interface{}{
					"rich_text": []map[string]interface{}{
						{
							"type": "text",
							"text": map[string]interface{}{
								"content": content,
							},
						},
					},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("/v1/blocks/%s/children", cleanID)
	respBytes, err := r.doNotionRequest(ctx, "PATCH", path, bodyBytes, token)
	if err != nil {
		return "", err
	}

	var raw struct {
		Results []map[string]interface{} `json:"results"`
	}
	_ = json.Unmarshal(respBytes, &raw)

	result := map[string]interface{}{
		"status":          "appended",
		"block_id":        blockID,
		"appended_blocks": len(raw.Results),
	}

	cleanJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(cleanJSON), nil
}
