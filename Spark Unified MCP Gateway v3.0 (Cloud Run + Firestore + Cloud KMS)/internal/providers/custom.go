package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var blockedCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // IPv4 link-local (Cloud metadata: GCP/AWS/Azure)
		"0.0.0.0/8",      // Current network
		"100.64.0.0/10",  // Carrier-grade NAT
		"192.0.0.0/24",   // IETF Protocol Assignments
		"198.18.0.0/15",  // Benchmark testing
		"224.0.0.0/4",    // Multicast
		"240.0.0.0/4",    // Reserved
		"::1/128",        // IPv6 loopback
		"::/128",         // IPv6 unspecified
		"fc00::/7",       // Unique local address
		"fe80::/10",      // Link-local unicast
		"ff00::/8",       // Multicast
	}
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, ipNet)
		}
	}
}

// isBlockedIP returns true if the IP belongs to any private, loopback, or cloud-metadata range.
func isBlockedIP(ip net.IP, allowLoopback bool) bool {
	if allowLoopback && ip.IsLoopback() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateUpstreamURL enforces strict SSRF validation on upstream URLs.
func ValidateUpstreamURL(rawURL string) error {
	return ValidateUpstreamURLWithTestOption(rawURL, false)
}

// ValidateUpstreamURLWithTestOption allows loopback only for unit tests when enabled.
func ValidateUpstreamURLWithTestOption(rawURL string, allowLoopback bool) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return errors.New("upstream URL cannot be empty")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}

	if allowLoopback && strings.EqualFold(u.Scheme, "http") {
		// allowed only for local test suite
	} else if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("upstream URL must use https scheme")
	}

	if u.User != nil {
		return errors.New("upstream URL must not contain userinfo credentials")
	}

	hostname := u.Hostname()
	if hostname == "" {
		return errors.New("upstream URL must contain a valid host")
	}

	// Direct IP literal check
	ip := net.ParseIP(hostname)
	if ip != nil {
		if isBlockedIP(ip, allowLoopback) {
			return fmt.Errorf("host IP %s is a private or restricted address", ip.String())
		}
		return nil
	}

	// Hostname resolution check
	if strings.EqualFold(hostname, "localhost") {
		if !allowLoopback {
			return errors.New("hostname localhost is forbidden")
		}
	}

	ips, err := net.LookupIP(hostname)
	if err == nil {
		for _, resolvedIP := range ips {
			if isBlockedIP(resolvedIP, allowLoopback) {
				return fmt.Errorf("hostname %s resolves to restricted IP %s", hostname, resolvedIP.String())
			}
		}
	}

	return nil
}

// NewSSRFSafeHTTPClient returns an HTTP client that validates every dialed IP and redirect against SSRF/downgrade attacks.
func NewSSRFSafeHTTPClient(timeout time.Duration) *http.Client {
	return NewSSRFSafeHTTPClientWithTestOption(timeout, false)
}

// NewSSRFSafeHTTPClientWithTestOption allows loopback for testing.
func NewSSRFSafeHTTPClientWithTestOption(timeout time.Duration, allowLoopback bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("SSRF DNS lookup failed for %s: %w", host, err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses resolved for %s", host)
			}

			for _, ip := range ips {
				if isBlockedIP(ip, allowLoopback) {
					return nil, fmt.Errorf("connection to %s (%s) blocked: restricted or private IP address", host, ip.String())
				}
			}

			targetAddr := net.JoinHostPort(ips[0].String(), port)
			return dialer.DialContext(ctx, network, targetAddr)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("stopped after 3 redirects")
			}
			if err := ValidateUpstreamURLWithTestOption(req.URL.String(), allowLoopback); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				return errors.New("cross-host redirect prohibited for upstream connector")
			}
			return nil
		},
	}
}

// CallRemoteMCPToolsList queries upstream JSON-RPC tools/list on a remote MCP server.
func CallRemoteMCPToolsList(ctx context.Context, client *http.Client, endpointURL, authHeader, token string) ([]ToolDefinition, error) {
	reqPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}
	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpointURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		if authHeader == "" || strings.EqualFold(authHeader, "Authorization") {
			if !strings.HasPrefix(token, "Bearer ") && !strings.HasPrefix(token, "token ") {
				req.Header.Set("Authorization", "Bearer "+token)
			} else {
				req.Header.Set("Authorization", token)
			}
		} else {
			req.Header.Set(authHeader, token)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream MCP tools/list returned HTTP %d", resp.StatusCode)
	}

	var rpcResp struct {
		Result struct {
			Tools []ToolDefinition `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&rpcResp); err != nil {
		return nil, err
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("upstream MCP error: %s", rpcResp.Error.Message)
	}

	return rpcResp.Result.Tools, nil
}

// CallRemoteMCPToolsCall dispatches an execution to upstream JSON-RPC tools/call.
func CallRemoteMCPToolsCall(ctx context.Context, client *http.Client, endpointURL, authHeader, token, toolName string, args map[string]interface{}) (string, error) {
	reqPayload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      toolName,
			"arguments": args,
		},
	}
	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpointURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		if authHeader == "" || strings.EqualFold(authHeader, "Authorization") {
			if !strings.HasPrefix(token, "Bearer ") && !strings.HasPrefix(token, "token ") {
				req.Header.Set("Authorization", "Bearer "+token)
			} else {
				req.Header.Set("Authorization", token)
			}
		} else {
			req.Header.Set(authHeader, token)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var rpcResp struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 512*1024)).Decode(&rpcResp); err != nil {
		return "", err
	}

	if rpcResp.Error != nil {
		return "", fmt.Errorf("upstream MCP error: %s", rpcResp.Error.Message)
	}

	var sb strings.Builder
	for _, c := range rpcResp.Result.Content {
		sb.WriteString(c.Text)
		sb.WriteString("\n")
	}

	return strings.TrimSpace(sb.String()), nil
}

// CallCustomRESTAPI invokes a custom REST endpoint adhering strictly to scheme/host bounds and path validation.
func CallCustomRESTAPI(ctx context.Context, client *http.Client, baseURL, authHeader, token, method, path, body string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	if strings.Contains(path, "..") {
		return "", errors.New("path traversal (..) is not permitted")
	}

	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	target := base.ResolveReference(rel)
	if !strings.EqualFold(target.Host, base.Host) {
		return "", errors.New("path cannot target a different host")
	}
	if !strings.EqualFold(target.Scheme, base.Scheme) {
		return "", errors.New("path cannot change URL scheme")
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if body != "" && method != "GET" && method != "HEAD" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, target.String(), bodyReader)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if token != "" {
		if authHeader == "" || strings.EqualFold(authHeader, "Authorization") {
			if !strings.HasPrefix(token, "Bearer ") && !strings.HasPrefix(token, "token ") {
				req.Header.Set("Authorization", "Bearer "+token)
			} else {
				req.Header.Set("Authorization", token)
			}
		} else {
			req.Header.Set(authHeader, token)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", err
	}

	return string(respBytes), nil
}
