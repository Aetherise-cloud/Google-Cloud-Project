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

func (r *Registry) registerGCPTools() {
	// 6. gcp_list_cloudrun_services
	r.RegisterTool(ToolDefinition{
		Name:            "gcp_list_cloudrun_services",
		Description:     "List Cloud Run services in a project and region via keyless ADC.",
		Provider:        "gcp",
		RequiredScope:   "read_only",
		MinimalBaseline: true,
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "GCP Project ID (default: gateway GCP_PROJECT_ID)",
				},
				"region": map[string]interface{}{
					"type":        "string",
					"description": "GCP Region (default: gateway GCP_REGION, e.g. asia-southeast1)",
				},
			},
		},
	}, r.handleGCPListCloudRunServices)

	// 7. gcp_get_cloudrun_service
	r.RegisterTool(ToolDefinition{
		Name:          "gcp_get_cloudrun_service",
		Description:   "Get details of a Cloud Run service (with secrets and env vars strictly redacted).",
		Provider:      "gcp",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service_name": map[string]interface{}{
					"type":        "string",
					"description": "Cloud Run service name",
				},
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "GCP Project ID (optional)",
				},
				"region": map[string]interface{}{
					"type":        "string",
					"description": "GCP Region (optional)",
				},
			},
			"required": []string{"service_name"},
		},
	}, r.handleGCPGetCloudRunService)

	// 8. gcp_list_cloudrun_revisions
	r.RegisterTool(ToolDefinition{
		Name:          "gcp_list_cloudrun_revisions",
		Description:   "List Cloud Run revisions in a project and region, optionally filtered by service name.",
		Provider:      "gcp",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"service_name": map[string]interface{}{
					"type":        "string",
					"description": "Optional Cloud Run service name (default: '-' to list all revisions)",
				},
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "GCP Project ID (default: gateway GCP_PROJECT_ID)",
				},
				"region": map[string]interface{}{
					"type":        "string",
					"description": "GCP Region (default: gateway GCP_REGION)",
				},
			},
		},
	}, r.handleGCPListCloudRunRevisions)

	// 9. gcp_query_cloud_logging
	r.RegisterTool(ToolDefinition{
		Name:          "gcp_query_cloud_logging",
		Description:   "Query Cloud Logging entries using standard Cloud Logging filter syntax.",
		Provider:      "gcp",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"filter": map[string]interface{}{
					"type":        "string",
					"description": "Cloud Logging filter expression (default: resource.type=\"cloud_run_revision\")",
				},
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "GCP Project ID (default: gateway GCP_PROJECT_ID)",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"description": "Maximum entries to return (default: 20, max: 100)",
				},
			},
		},
	}, r.handleGCPQueryCloudLogging)

	// 10. gcp_list_storage_buckets
	r.RegisterTool(ToolDefinition{
		Name:          "gcp_list_storage_buckets",
		Description:   "List Cloud Storage buckets in a project via keyless ADC.",
		Provider:      "gcp",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "GCP Project ID (default: gateway GCP_PROJECT_ID)",
				},
			},
		},
	}, r.handleGCPListStorageBuckets)

	// 11. gcp_list_artifact_repositories
	r.RegisterTool(ToolDefinition{
		Name:          "gcp_list_artifact_repositories",
		Description:   "List Artifact Registry repositories in a project and region.",
		Provider:      "gcp",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "GCP Project ID (default: gateway GCP_PROJECT_ID)",
				},
				"region": map[string]interface{}{
					"type":        "string",
					"description": "GCP Region (default: gateway GCP_REGION)",
				},
			},
		},
	}, r.handleGCPListArtifactRepositories)

	// 12. gcp_list_monitoring_alerts
	r.RegisterTool(ToolDefinition{
		Name:          "gcp_list_monitoring_alerts",
		Description:   "List Cloud Monitoring alert policies in a project.",
		Provider:      "gcp",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "GCP Project ID (default: gateway GCP_PROJECT_ID)",
				},
			},
		},
	}, r.handleGCPListMonitoringAlerts)

	// 13. gcp_list_service_accounts
	r.RegisterTool(ToolDefinition{
		Name:          "gcp_list_service_accounts",
		Description:   "List IAM service accounts in a project via keyless ADC.",
		Provider:      "gcp",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"project_id": map[string]interface{}{
					"type":        "string",
					"description": "GCP Project ID (default: gateway GCP_PROJECT_ID)",
				},
			},
		},
	}, r.handleGCPListServiceAccounts)

	// 14. gcp_describe_resource
	r.RegisterTool(ToolDefinition{
		Name:          "gcp_describe_resource",
		Description:   "Describe any standard Google Cloud resource via keyless ADC using its full resource URL or path.",
		Provider:      "gcp",
		RequiredScope: "read_only",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"resource_url": map[string]interface{}{
					"type":        "string",
					"description": "Full HTTPS URL of the Google Cloud resource (e.g. https://run.googleapis.com/v2/projects/...)",
				},
			},
			"required": []string{"resource_url"},
		},
	}, r.handleGCPDescribeResource)
}

func (r *Registry) handleGCPListCloudRunServices(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	project := getStringArg(args, "project_id", r.cfg.GCPProjectID)
	region := getStringArg(args, "region", r.cfg.GCPRegion)

	if project == "" || region == "" {
		return "", errors.New("missing project_id or region")
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v2/projects/%s/locations/%s/services", r.CloudRunBaseURL, url.PathEscape(project), url.PathEscape(region))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Goog-User-Project", project)

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
		return "", fmt.Errorf("cloud run api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		Services []struct {
			Name        string `json:"name"`
			URI         string `json:"uri"`
			CreateTime  string `json:"createTime"`
			UpdateTime  string `json:"updateTime"`
			Ingress     string `json:"ingress"`
			Description string `json:"description"`
		} `json:"services"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}

	if len(res.Services) == 0 {
		return fmt.Sprintf("No Cloud Run services found in project %s (%s).", project, region), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Cloud Run Services in %s (%s):\n", project, region))
	for _, s := range res.Services {
		shortName := s.Name
		if parts := strings.Split(s.Name, "/"); len(parts) > 0 {
			shortName = parts[len(parts)-1]
		}
		sb.WriteString(fmt.Sprintf("- %s: %s (ingress: %s, updated: %s)\n", shortName, s.URI, s.Ingress, s.UpdateTime))
	}

	return sb.String(), nil
}

// SanitizedCloudRunService represents the secure, redacted view of a Cloud Run service.
// Strictly strips environment variables, secret mounts, and internal annotations (SEC-06).
type SanitizedCloudRunService struct {
	Name           string                 `json:"name"`
	URI            string                 `json:"uri"`
	Ingress        string                 `json:"ingress"`
	ServiceAccount string                 `json:"serviceAccount"`
	Scaling        map[string]interface{} `json:"scaling,omitempty"`
	Containers     []SanitizedContainer   `json:"containers"`
	Traffic        []map[string]interface{} `json:"traffic,omitempty"`
	CreateTime     string                 `json:"createTime,omitempty"`
	UpdateTime     string                 `json:"updateTime,omitempty"`
}

type SanitizedContainer struct {
	Image     string                 `json:"image"`
	Resources map[string]interface{} `json:"resources,omitempty"`
}

func (r *Registry) handleGCPGetCloudRunService(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	serviceName := getStringArg(args, "service_name", "")
	if serviceName == "" {
		return "", errors.New("missing required argument: service_name")
	}

	project := getStringArg(args, "project_id", r.cfg.GCPProjectID)
	region := getStringArg(args, "region", r.cfg.GCPRegion)

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v2/projects/%s/locations/%s/services/%s", r.CloudRunBaseURL, url.PathEscape(project), url.PathEscape(region), url.PathEscape(serviceName))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Goog-User-Project", project)

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
		return "", fmt.Errorf("cloud run api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var raw struct {
		Name       string `json:"name"`
		URI        string `json:"uri"`
		Ingress    string `json:"ingress"`
		CreateTime string `json:"createTime"`
		UpdateTime string `json:"updateTime"`
		Template   struct {
			ServiceAccount string                 `json:"serviceAccount"`
			Scaling        map[string]interface{} `json:"scaling"`
			Containers     []struct {
				Image     string                 `json:"image"`
				Resources map[string]interface{} `json:"resources"`
				Env       interface{}            `json:"env"`          // Dropped!
				Secrets   interface{}            `json:"volumeMounts"` // Dropped!
			} `json:"containers"`
		} `json:"template"`
		Traffic []map[string]interface{} `json:"traffic"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return "", err
	}

	sanitizedScaling, _ := stripSensitiveKeys(raw.Template.Scaling).(map[string]interface{})
	var sanitizedTraffic []map[string]interface{}
	for _, tr := range raw.Traffic {
		if res, ok := stripSensitiveKeys(tr).(map[string]interface{}); ok {
			sanitizedTraffic = append(sanitizedTraffic, res)
		}
	}

	sanitized := SanitizedCloudRunService{
		Name:           raw.Name,
		URI:            raw.URI,
		Ingress:        raw.Ingress,
		ServiceAccount: raw.Template.ServiceAccount,
		Scaling:        sanitizedScaling,
		Traffic:        sanitizedTraffic,
		CreateTime:     raw.CreateTime,
		UpdateTime:     raw.UpdateTime,
	}

	for _, c := range raw.Template.Containers {
		resMap, _ := stripSensitiveKeys(c.Resources).(map[string]interface{})
		sanitized.Containers = append(sanitized.Containers, SanitizedContainer{
			Image:     c.Image,
			Resources: resMap,
		})
	}

	cleanJSON, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return "", err
	}

	return string(cleanJSON), nil
}

func stripSensitiveKeys(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]interface{}:
		cleaned := make(map[string]interface{})
		for k, item := range val {
			kLower := strings.ToLower(k)
			if kLower == "env" || kLower == "secret_key_ref" || kLower == "secretkeyref" ||
				kLower == "volumemounts" || kLower == "secrets" ||
				kLower == "private_key_data" || kLower == "privatekeydata" ||
				kLower == "private_key" || kLower == "privatekey" {
				continue
			}
			cleaned[k] = stripSensitiveKeys(item)
		}
		return cleaned
	case []interface{}:
		cleaned := make([]interface{}, len(val))
		for i, item := range val {
			cleaned[i] = stripSensitiveKeys(item)
		}
		return cleaned
	case []map[string]interface{}:
		var cleaned []map[string]interface{}
		for _, item := range val {
			if res, ok := stripSensitiveKeys(item).(map[string]interface{}); ok {
				cleaned = append(cleaned, res)
			}
		}
		return cleaned
	default:
		return val
	}
}

func (r *Registry) handleGCPListCloudRunRevisions(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	project := getStringArg(args, "project_id", r.cfg.GCPProjectID)
	region := getStringArg(args, "region", r.cfg.GCPRegion)
	serviceName := getStringArg(args, "service_name", "-")
	if serviceName == "" {
		serviceName = "-"
	}

	if project == "" || region == "" {
		return "", errors.New("missing project_id or region")
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v2/projects/%s/locations/%s/services/%s/revisions",
		r.CloudRunBaseURL, url.PathEscape(project), url.PathEscape(region), url.PathEscape(serviceName))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Goog-User-Project", project)

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
		return "", fmt.Errorf("cloud run api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", err
	}

	sanitized := stripSensitiveKeys(raw)
	cleanJSON, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return "", err
	}

	return string(cleanJSON), nil
}

func (r *Registry) handleGCPQueryCloudLogging(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	project := getStringArg(args, "project_id", r.cfg.GCPProjectID)
	if project == "" {
		return "", errors.New("missing project_id")
	}

	filter := getStringArg(args, "filter", `resource.type="cloud_run_revision"`)
	limit := 20
	if l, ok := args["limit"]; ok {
		if f, ok := l.(float64); ok && f > 0 {
			limit = int(f)
		} else if i, ok := l.(int); ok && i > 0 {
			limit = i
		}
	}
	if limit > 100 {
		limit = 100
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	payload := map[string]interface{}{
		"resourceNames": []string{"projects/" + project},
		"filter":        filter,
		"orderBy":       "timestamp desc",
		"pageSize":      limit,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/v2/entries:list", r.LoggingBaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Goog-User-Project", project)

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
		return "", fmt.Errorf("cloud logging api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", err
	}

	sanitized := stripSensitiveKeys(raw)
	cleanJSON, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return "", err
	}

	return string(cleanJSON), nil
}

func (r *Registry) handleGCPListStorageBuckets(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	project := getStringArg(args, "project_id", r.cfg.GCPProjectID)
	if project == "" {
		return "", errors.New("missing project_id")
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/storage/v1/b?project=%s", r.StorageBaseURL, url.QueryEscape(project))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Goog-User-Project", project)

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
		return "", fmt.Errorf("cloud storage api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		Items []struct {
			Name         string `json:"name"`
			Location     string `json:"location"`
			StorageClass string `json:"storageClass"`
			TimeCreated  string `json:"timeCreated"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}

	if len(res.Items) == 0 {
		return fmt.Sprintf("No Cloud Storage buckets found in project %s.", project), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Cloud Storage Buckets in %s (%d total):\n", project, len(res.Items)))
	for _, b := range res.Items {
		sb.WriteString(fmt.Sprintf("- %s (location: %s, storageClass: %s)\n", b.Name, b.Location, b.StorageClass))
	}
	return sb.String(), nil
}

func (r *Registry) handleGCPListArtifactRepositories(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	project := getStringArg(args, "project_id", r.cfg.GCPProjectID)
	region := getStringArg(args, "region", r.cfg.GCPRegion)
	if project == "" || region == "" {
		return "", errors.New("missing project_id or region")
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/projects/%s/locations/%s/repositories", r.ArtifactRegistryBaseURL, url.PathEscape(project), url.PathEscape(region))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Goog-User-Project", project)

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
		return "", fmt.Errorf("artifact registry api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		Repositories []struct {
			Name        string `json:"name"`
			Format      string `json:"format"`
			Description string `json:"description"`
			UpdateTime  string `json:"updateTime"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}

	if len(res.Repositories) == 0 {
		return fmt.Sprintf("No Artifact Registry repositories found in project %s (%s).", project, region), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Artifact Registry Repositories in %s (%s):\n", project, region))
	for _, repo := range res.Repositories {
		shortName := repo.Name
		if parts := strings.Split(repo.Name, "/"); len(parts) > 0 {
			shortName = parts[len(parts)-1]
		}
		sb.WriteString(fmt.Sprintf("- %s: format=%s (updated: %s)\n", shortName, repo.Format, repo.UpdateTime))
	}
	return sb.String(), nil
}

func (r *Registry) handleGCPListMonitoringAlerts(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	project := getStringArg(args, "project_id", r.cfg.GCPProjectID)
	if project == "" {
		return "", errors.New("missing project_id")
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v3/projects/%s/alertPolicies", r.MonitoringBaseURL, url.PathEscape(project))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Goog-User-Project", project)

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
		return "", fmt.Errorf("monitoring api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", err
	}

	sanitized := stripSensitiveKeys(raw)
	cleanJSON, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return "", err
	}
	return string(cleanJSON), nil
}

func (r *Registry) handleGCPListServiceAccounts(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	project := getStringArg(args, "project_id", r.cfg.GCPProjectID)
	if project == "" {
		return "", errors.New("missing project_id")
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/v1/projects/%s/serviceAccounts", r.IAMBaseURL, url.PathEscape(project))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Goog-User-Project", project)

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
		return "", fmt.Errorf("iam api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		Accounts []struct {
			Email       string `json:"email"`
			DisplayName string `json:"displayName"`
			Disabled    bool   `json:"disabled"`
			UniqueId    string `json:"uniqueId"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}

	if len(res.Accounts) == 0 {
		return fmt.Sprintf("No IAM service accounts found in project %s.", project), nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("IAM Service Accounts in %s (%d total):\n", project, len(res.Accounts)))
	for _, sa := range res.Accounts {
		status := "enabled"
		if sa.Disabled {
			status = "disabled"
		}
		sb.WriteString(fmt.Sprintf("- %s (%s, status: %s)\n", sa.Email, sa.DisplayName, status))
	}
	return sb.String(), nil
}

func isValidGCPResourceURL(targetURL string, allowedBaseURL string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil {
		return nil, fmt.Errorf("invalid resource URL: %w", err)
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("resource URL scheme must be https or http")
	}

	host := strings.ToLower(u.Hostname())
	isGoogleAPIs := host == "googleapis.com" || strings.HasSuffix(host, ".googleapis.com")
	if !isGoogleAPIs {
		if allowedBaseURL != "" {
			if parsedBase, err := url.Parse(allowedBaseURL); err == nil && parsedBase.Hostname() == host {
				isGoogleAPIs = true
			}
		}
	}
	if !isGoogleAPIs {
		return nil, fmt.Errorf("security violation: resource host %q is not a permitted googleapis.com endpoint", host)
	}

	pathLower := strings.ToLower(u.Path)
	if strings.Contains(pathLower, ":accesssecretversion") ||
		strings.Contains(pathLower, ":signblob") ||
		strings.Contains(pathLower, ":signjwt") ||
		(strings.Contains(pathLower, "/secrets/") && strings.Contains(pathLower, "/versions/")) {
		return nil, fmt.Errorf("security violation: resource path %q attempts to access raw secrets or cryptographic signing keys", u.Path)
	}

	return u, nil
}

func (r *Registry) handleGCPDescribeResource(ctx context.Context, args map[string]interface{}, _ *vault.TokenData) (string, error) {
	rawURL := getStringArg(args, "resource_url", "")
	if rawURL == "" {
		return "", errors.New("missing required argument: resource_url")
	}

	parsedURL, err := isValidGCPResourceURL(rawURL, r.CloudRunBaseURL)
	if err != nil {
		return "", err
	}

	token, err := r.adcFunc(ctx)
	if err != nil {
		return "", fmt.Errorf("failed acquiring ADC token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
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
		return "", fmt.Errorf("gcp api error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var raw interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return string(body), nil
	}

	sanitized := stripSensitiveKeys(raw)
	cleanJSON, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return "", err
	}

	return string(cleanJSON), nil
}
