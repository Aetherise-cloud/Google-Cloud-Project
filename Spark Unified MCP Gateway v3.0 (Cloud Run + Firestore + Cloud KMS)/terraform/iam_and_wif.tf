# ==============================================================================
# Workload Identity Federation (WIF) & GitHub Actions Deployer Scoped Permissions
# ==============================================================================
# In GCP project group-511516, the GitHub Workload Identity Pool ('github') and
# gh-deployer service account are ALREADY provisioned and managed by Group Finance.
#
# To prevent state collisions and duplicate resource conflicts, this configuration:
# 1. Defaults create_wif_pool = false
# 2. Uses var.existing_gh_deployer_sa_email (gh-deployer@group-511516.iam.gserviceaccount.com)
# 3. Grants resource-scoped permissions strictly to the existing deployer SA:
#    - Artifact Registry writer on spark-gateway repository
#    - Cloud Run developer on spark-mcp-gateway service
#    - iam.serviceAccountUser (actAs) on mcp-spark-gateway-sa runtime SA
# ==============================================================================

locals {
  effective_deployer_sa_email = var.create_wif_pool ? google_service_account.gh_deployer[0].email : var.existing_gh_deployer_sa_email
}

# 1. Optional WIF Pool (only instantiated if create_wif_pool = true in a standalone environment)
resource "google_iam_workload_identity_pool" "github" {
  count                     = var.create_wif_pool ? 1 : 0
  project                   = var.project_id
  workload_identity_pool_id = "github"
  display_name              = "GitHub Actions"
  description               = "OIDC identities issued by GitHub Actions"

  depends_on = [google_project_service.enabled_apis]
}

resource "google_iam_workload_identity_pool_provider" "github_oidc" {
  count                              = var.create_wif_pool ? 1 : 0
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC"
  description                        = "GitHub Actions OIDC Provider for spark-mcp-gateway"

  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.repository"    = "assertion.repository"
    "attribute.repository_id" = "assertion.repository_id"
    "attribute.ref"           = "assertion.ref"
  }

  attribute_condition = "assertion.repository_id == '${var.github_repository_id}' && (assertion.ref == 'refs/heads/main' || assertion.ref == 'refs/heads/staging')"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "gh_deployer" {
  count        = var.create_wif_pool ? 1 : 0
  project      = var.project_id
  account_id   = "gh-deployer"
  display_name = "GitHub Actions deployer"
  description  = "Pushes images and deploys Cloud Run revisions from GitHub Actions"

  depends_on = [google_project_service.enabled_apis]
}

resource "google_service_account_iam_member" "gh_deployer_workload_identity_user" {
  count              = var.create_wif_pool ? 1 : 0
  service_account_id = google_service_account.gh_deployer[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.repository_id/${var.github_repository_id}"
}

# 2. Resource-Scoped Deployer Permissions (Granted to existing or created deployer SA)
# 2.1 Artifact Registry Writer (scoped to spark-gateway repository only)
resource "google_artifact_registry_repository_iam_member" "deployer_ar_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.spark_gateway.location
  repository = google_artifact_registry_repository.spark_gateway.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${local.effective_deployer_sa_email}"
}

# 2.2 Cloud Run Developer (create revisions, tag revisions, update traffic on spark-mcp-gateway)
resource "google_cloud_run_v2_service_iam_member" "deployer_run_developer" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.spark_mcp_gateway.name
  role     = "roles/run.developer"
  member   = "serviceAccount:${local.effective_deployer_sa_email}"
}

# 2.3 Service Account User (actAs permission on runtime SA for candidate deployments)
resource "google_service_account_iam_member" "deployer_act_as_runtime" {
  service_account_id = google_service_account.runtime_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${local.effective_deployer_sa_email}"
}
