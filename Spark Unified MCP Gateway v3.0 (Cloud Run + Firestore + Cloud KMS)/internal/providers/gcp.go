package providers

import (
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

	sanitized := SanitizedCloudRunService{
		Name:           raw.Name,
		URI:            raw.URI,
		Ingress:        raw.Ingress,
		ServiceAccount: raw.Template.ServiceAccount,
		Scaling:        raw.Template.Scaling,
		Traffic:        raw.Traffic,
		CreateTime:     raw.CreateTime,
		UpdateTime:     raw.UpdateTime,
	}

	for _, c := range raw.Template.Containers {
		sanitized.Containers = append(sanitized.Containers, SanitizedContainer{
			Image:     c.Image,
			Resources: c.Resources,
		})
	}

	cleanJSON, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return "", err
	}

	return string(cleanJSON), nil
}
