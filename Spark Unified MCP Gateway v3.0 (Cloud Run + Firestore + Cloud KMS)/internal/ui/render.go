package ui

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

var (
	loginTmpl     *template.Template
	dashboardTmpl *template.Template
	authorizeTmpl *template.Template
	callbackTmpl  *template.Template
)

func init() {
	loginTmpl = template.Must(template.ParseFS(templateFS, "templates/common.html", "templates/login.html"))
	dashboardTmpl = template.Must(template.ParseFS(templateFS, "templates/common.html", "templates/dashboard.html"))
	authorizeTmpl = template.Must(template.ParseFS(templateFS, "templates/common.html", "templates/authorize.html"))
	callbackTmpl = template.Must(template.ParseFS(templateFS, "templates/common.html", "templates/callback.html"))
}

// setSecurityHeaders sets the strict enterprise security headers required for all UI responses.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'")
}

// renderTemplate executes the specified template into a memory buffer before writing status and headers.
func renderTemplate(w http.ResponseWriter, status int, tmpl *template.Template, templateName string, data any) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, templateName, data); err != nil {
		return err
	}

	setSecurityHeaders(w)
	w.WriteHeader(status)
	_, err := buf.WriteTo(w)
	return err
}
