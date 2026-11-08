package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// SensitiveKeys is the list of parameters/headers that must be redacted in logs.
var SensitiveKeys = []string{
	"authorization",
	"cookie",
	"set-cookie",
	"code",
	"access_token",
	"refresh_token",
	"client_secret",
}

// Logger emits structured JSON logs compatible with Google Cloud Logging.
type Logger struct {
	mu        sync.Mutex
	out       io.Writer
	projectID string
}

// LogEntry represents a single Google Cloud Logging structured entry.
type LogEntry struct {
	Severity     string                 `json:"severity"`
	Time         string                 `json:"time"`
	Message      string                 `json:"message"`
	Trace        string                 `json:"logging.googleapis.com/trace,omitempty"`
	HTTPResponse *HTTPRequestLog        `json:"httpRequest,omitempty"`
	Fields       map[string]interface{} `json:"fields,omitempty"`
}

// HTTPRequestLog represents the Cloud Logging HTTP request payload.
type HTTPRequestLog struct {
	RequestMethod string `json:"requestMethod"`
	RequestURL    string `json:"requestURL"`
	Status        int    `json:"status"`
	UserAgent     string `json:"userAgent,omitempty"`
	RemoteIP      string `json:"remoteIp,omitempty"`
	Latency       string `json:"latency,omitempty"`
}

// NewLogger creates a new structured JSON logger.
func NewLogger(projectID string, out io.Writer) *Logger {
	if out == nil {
		out = os.Stdout
	}
	return &Logger{
		out:       out,
		projectID: projectID,
	}
}

func (l *Logger) log(severity, msg, trace string, httpReq *HTTPRequestLog, fields map[string]interface{}) {
	entry := LogEntry{
		Severity:     severity,
		Time:         time.Now().UTC().Format(time.RFC3339Nano),
		Message:      msg,
		Trace:        trace,
		HTTPResponse: httpReq,
		Fields:       fields,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(data, '\n'))
}

// Info logs an informational message.
func (l *Logger) Info(msg string, fields map[string]interface{}) {
	l.log("INFO", msg, "", nil, sanitizeFields(fields))
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string, fields map[string]interface{}) {
	l.log("WARNING", msg, "", nil, sanitizeFields(fields))
}

// Error logs an error message.
func (l *Logger) Error(msg string, fields map[string]interface{}) {
	l.log("ERROR", msg, "", nil, sanitizeFields(fields))
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, fields map[string]interface{}) {
	l.log("DEBUG", msg, "", nil, sanitizeFields(fields))
}

// RedactURL strips sensitive query parameter values.
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	modified := false
	for k := range q {
		lowerK := strings.ToLower(k)
		for _, s := range SensitiveKeys {
			if lowerK == s {
				q.Set(k, "[REDACTED]")
				modified = true
				break
			}
		}
	}
	if modified {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// RedactHeader checks if a header key is sensitive and redacts its value.
func RedactHeader(key, val string) string {
	lowerKey := strings.ToLower(key)
	for _, s := range SensitiveKeys {
		if lowerKey == s {
			return "[REDACTED]"
		}
	}
	return val
}

func sanitizeFields(fields map[string]interface{}) map[string]interface{} {
	if fields == nil {
		return nil
	}
	clean := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		lowerK := strings.ToLower(k)
		isSensitive := false
		for _, s := range SensitiveKeys {
			if lowerK == s {
				isSensitive = true
				break
			}
		}
		if isSensitive {
			clean[k] = "[REDACTED]"
		} else {
			clean[k] = v
		}
	}
	return clean
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	bytes      int64
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// HTTPMiddleware wraps an http.Handler to log each request with sensitive tokens redacted.
func (l *Logger) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rec, r)

		duration := time.Since(start)
		sanitizedURL := RedactURL(r.RequestURI)

		// Extract Cloud Trace ID if available
		var trace string
		if traceHeader := r.Header.Get("X-Cloud-Trace-Context"); traceHeader != "" {
			parts := strings.Split(traceHeader, "/")
			if len(parts) > 0 && l.projectID != "" {
				trace = fmt.Sprintf("projects/%s/traces/%s", l.projectID, parts[0])
			}
		}

		httpLog := &HTTPRequestLog{
			RequestMethod: r.Method,
			RequestURL:    sanitizedURL,
			Status:        rec.statusCode,
			UserAgent:     r.UserAgent(),
			RemoteIP:      r.RemoteAddr,
			Latency:       fmt.Sprintf("%.6fs", duration.Seconds()),
		}

		severity := "INFO"
		if rec.statusCode >= 500 {
			severity = "ERROR"
		} else if rec.statusCode >= 400 {
			severity = "WARNING"
		}

		l.log(severity, fmt.Sprintf("%s %s -> %d (%s)", r.Method, sanitizedURL, rec.statusCode, duration), trace, httpLog, nil)
	})
}
