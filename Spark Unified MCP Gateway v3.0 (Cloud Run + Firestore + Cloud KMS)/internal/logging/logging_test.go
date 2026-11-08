package logging

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	raw := "/oauth/callback/github?code=super_secret_code&state=xyz123&client_secret=topsecret"
	redacted := RedactURL(raw)

	if strings.Contains(redacted, "super_secret_code") {
		t.Errorf("expected code to be redacted, got: %s", redacted)
	}
	if strings.Contains(redacted, "topsecret") {
		t.Errorf("expected client_secret to be redacted, got: %s", redacted)
	}
	if !strings.Contains(redacted, "code=%5BREDACTED%5D") && !strings.Contains(redacted, "code=[REDACTED]") {
		t.Errorf("expected redacted code query param, got: %s", redacted)
	}
	if !strings.Contains(redacted, "state=xyz123") {
		t.Errorf("expected state to be preserved, got: %s", redacted)
	}
}

func TestRedactHeader(t *testing.T) {
	if RedactHeader("Authorization", "Bearer secret") != "[REDACTED]" {
		t.Error("expected Authorization to be redacted")
	}
	if RedactHeader("Cookie", "session=123") != "[REDACTED]" {
		t.Error("expected Cookie to be redacted")
	}
	if RedactHeader("Content-Type", "application/json") != "application/json" {
		t.Error("expected Content-Type to be preserved")
	}
}

func TestLoggerHTTPMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger("my-project", &buf)

	handler := logger.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"created": true}`))
	}))

	req := httptest.NewRequest("GET", "/test?code=secret_123&foo=bar", nil)
	req.Header.Set("Authorization", "Bearer sensitive")
	req.Header.Set("X-Cloud-Trace-Context", "trace-id-abc/span-id;o=1")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed unmarshaling log entry: %v, raw: %s", err, buf.String())
	}

	if entry.Severity != "INFO" {
		t.Errorf("expected severity INFO, got %s", entry.Severity)
	}
	if entry.Trace != "projects/my-project/traces/trace-id-abc" {
		t.Errorf("unexpected trace: %s", entry.Trace)
	}
	if entry.HTTPResponse == nil || entry.HTTPResponse.Status != 201 {
		t.Errorf("expected status 201 in http request log, got %+v", entry.HTTPResponse)
	}
	if strings.Contains(entry.HTTPResponse.RequestURL, "secret_123") {
		t.Errorf("expected secret_123 to be redacted from URL in log, got: %s", entry.HTTPResponse.RequestURL)
	}
}
