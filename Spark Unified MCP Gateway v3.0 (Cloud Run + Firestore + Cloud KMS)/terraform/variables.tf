variable "project_id" {
  description = "The GCP Project ID"
  type        = string
  default     = "group-511516"
}

variable "project_number" {
  description = "The GCP Project Number"
  type        = string
  default     = "997395841168"
}

variable "region" {
  description = "The GCP region to deploy resources into"
  type        = string
  default     = "asia-southeast1"
}

variable "service_name" {
  description = "The name of the Cloud Run v2 service"
  type        = string
  default     = "spark-mcp-gateway"
}

variable "firestore_database_id" {
  description = "The dedicated named Firestore Native database ID"
  type        = string
  default     = "spark-mcp-db"
}

variable "admin_allowed_emails" {
  description = "Comma-delimited Google OIDC email addresses allowed to access the admin dashboard"
  type        = string
  default     = "brendon.ang20011007@gmail.com"
}

variable "container_image" {
  description = "Initial container image URL for Cloud Run v2 service bootstrap"
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "custom_domain" {
  description = "Optional custom domain name (e.g. mcp.example.com)"
  type        = string
  default     = ""
}

variable "enable_custom_domain_mapping" {
  description = "Enable direct Cloud Run custom domain mapping"
  type        = bool
  default     = false
}

variable "billing_account_id" {
  description = "Optional GCP Billing Account ID (e.g. 012345-6789AB-CDEF01). When set, provisions a $25/mo budget alert"
  type        = string
  default     = ""
}

variable "google_oidc_client_id" {
  description = "Google OAuth 2.0 Client ID for Admin Sign-In OIDC"
  type        = string
  default     = ""
}

variable "google_oidc_client_secret" {
  description = "Google OAuth 2.0 Client Secret for Admin Sign-In OIDC (defaults to UNCONFIGURED if empty)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_oauth_client_id" {
  description = "GitHub OAuth 2.0 App Client ID for GitHub connector"
  type        = string
  default     = ""
}

variable "github_oauth_client_secret" {
  description = "GitHub OAuth 2.0 App Client Secret (defaults to UNCONFIGURED if empty)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "github_allowed_write_repos" {
  description = "Comma-separated allowlist of repositories permitted for mutating actions (e.g. 'org/repo1,org/repo2')"
  type        = string
  default     = ""
}

variable "github_repository_id" {
  description = "The numeric GitHub repository ID for Workload Identity Federation condition pinning"
  type        = string
  default     = "1420258600"
}

variable "jira_oauth_client_id" {
  description = "Atlassian / Jira OAuth 2.0 (3LO) App Client ID"
  type        = string
  default     = ""
}

variable "jira_oauth_client_secret" {
  description = "Atlassian / Jira OAuth 2.0 (3LO) App Client Secret (defaults to UNCONFIGURED if empty)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "existing_gh_deployer_sa_email" {
  description = "Email of the existing GitHub Actions deployer service account in group-511516"
  type        = string
  default     = "gh-deployer@group-511516.iam.gserviceaccount.com"
}

variable "create_wif_pool" {
  description = "Whether to create the GitHub Workload Identity Pool (set to false when using existing 'github' pool in group-511516)"
  type        = bool
  default     = false
}
