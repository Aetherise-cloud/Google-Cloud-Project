output "service_url" {
  description = "The deterministic HTTPS endpoint of the Spark Unified MCP Gateway"
  value       = local.service_url
}

output "mcp_endpoint" {
  description = "The MCP Streamable HTTP data-plane endpoint for AI agent connections"
  value       = "${local.service_url}/mcp"
}

output "dashboard_url" {
  description = "The Admin Dashboard URL for OAuth management and tool status"
  value       = "${local.service_url}/dashboard"
}

output "google_oidc_callback_url" {
  description = "Google OAuth 2.0 authorized redirect URI to register in Google Cloud Console"
  value       = "${local.service_url}/auth/google/callback"
}

output "github_oauth_callback_url" {
  description = "GitHub OAuth App authorized callback URL to register on GitHub Developer Settings"
  value       = "${local.service_url}/oauth/callback/github"
}

output "jira_oauth_callback_url" {
  description = "Atlassian / Jira OAuth 2.0 (3LO) callback URL to register in Atlassian Developer Console"
  value       = "${local.service_url}/oauth/callback/jira"
}

output "artifact_registry_image" {
  description = "Base Artifact Registry container image path for GitHub Actions CI/CD"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.spark_gateway.name}/gateway"
}

output "firestore_database_id" {
  description = "Dedicated named Firestore Native database name"
  value       = google_firestore_database.spark_mcp_db.name
}

output "kms_key_id" {
  description = "Cloud KMS symmetric CryptoKey resource ID for TokenVault envelope encryption"
  value       = google_kms_crypto_key.mcp_token_kek.id
}

output "runtime_service_account" {
  description = "Runtime service account email used by the Cloud Run service"
  value       = google_service_account.runtime_sa.email
}

output "wif_provider_name" {
  description = "Dedicated Workload Identity Pool Provider resource name for Spark MCP Gateway GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.spark_mcp_oidc.name
}
