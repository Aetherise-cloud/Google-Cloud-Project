locals {
  clean_domain = trim(replace(replace(var.custom_domain, "https://", ""), "http://", ""), "/")
  service_url  = local.clean_domain != "" ? "https://${local.clean_domain}" : "https://${var.service_name}-${var.project_number}.${var.region}.run.app"

  google_oidc_client_secret_val  = var.google_oidc_client_secret != "" ? var.google_oidc_client_secret : "UNCONFIGURED"
  github_oauth_client_secret_val = var.github_oauth_client_secret != "" ? var.github_oauth_client_secret : "UNCONFIGURED"
  jira_oauth_client_secret_val   = var.jira_oauth_client_secret != "" ? var.jira_oauth_client_secret : "UNCONFIGURED"

  services = [
    "run.googleapis.com",
    "firestore.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudkms.googleapis.com",
    "artifactregistry.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "serviceusage.googleapis.com",
    "developerknowledge.googleapis.com",
    "billingbudgets.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
  ]
}

# 1. Enable Required GCP APIs
resource "google_project_service" "enabled_apis" {
  for_each                   = toset(local.services)
  project                    = var.project_id
  service                    = each.key
  disable_on_destroy         = false
  disable_dependent_services = false
}

# 2. Cloud Firestore Native Database (Dedicated named database spark-mcp-db)
resource "google_firestore_database" "spark_mcp_db" {
  project                           = var.project_id
  name                              = var.firestore_database_id
  location_id                       = var.region
  type                              = "FIRESTORE_NATIVE"
  concurrency_mode                  = "OPTIMISTIC"
  app_engine_integration_mode       = "DISABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  deletion_policy                   = "ABANDON"

  depends_on = [google_project_service.enabled_apis]
}

# 3. Firestore Native TTL Policies on expires_at for ephemeral collections
resource "google_firestore_field" "oauth_states_ttl" {
  project    = var.project_id
  database   = google_firestore_database.spark_mcp_db.name
  collection = "oauth_states"
  field      = "expires_at"

  ttl_config {}

  depends_on = [google_firestore_database.spark_mcp_db]
}

resource "google_firestore_field" "auth_codes_ttl" {
  project    = var.project_id
  database   = google_firestore_database.spark_mcp_db.name
  collection = "auth_codes"
  field      = "expires_at"

  ttl_config {}

  depends_on = [google_firestore_database.spark_mcp_db]
}

resource "google_firestore_field" "oauth_clients_ttl" {
  project    = var.project_id
  database   = google_firestore_database.spark_mcp_db.name
  collection = "oauth_clients"
  field      = "expires_at"

  ttl_config {}

  depends_on = [google_firestore_database.spark_mcp_db]
}

# 4. Cloud KMS KeyRing & Symmetric Key for TokenVault Envelope Encryption
resource "google_kms_key_ring" "spark_mcp_ring" {
  project    = var.project_id
  name       = "spark-mcp-ring"
  location   = var.region
  depends_on = [google_project_service.enabled_apis]
}

resource "google_kms_crypto_key" "mcp_token_kek" {
  name            = "mcp-token-kek"
  key_ring        = google_kms_key_ring.spark_mcp_ring.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "31536000s" # 365-day automated rotation

  lifecycle {
    prevent_destroy = true
  }
}

# 5. Dedicated Runtime Service Account & Least-Privilege IAM Roles
resource "google_service_account" "runtime_sa" {
  project      = var.project_id
  account_id   = "mcp-spark-gateway-sa"
  display_name = "Spark MCP Gateway Runtime Service Account"
  description  = "Dedicated runtime service account for Spark Unified MCP Gateway Cloud Run service"

  depends_on = [google_project_service.enabled_apis]
}

# Custom IAM Role: Cloud Run Inspector for gcp_list_cloudrun_services & gcp_get_cloudrun_service tools
# Deliberately omits logging.viewer and broader administrative privileges
resource "google_project_iam_custom_role" "run_inspector" {
  project     = var.project_id
  role_id     = "sparkMcpRunInspector"
  title       = "Spark MCP Cloud Run Inspector"
  description = "Scoped read-only inspection of Cloud Run services and revisions"
  permissions = [
    "run.services.get",
    "run.services.list",
    "run.revisions.get",
    "run.revisions.list",
  ]
}

resource "google_project_iam_member" "runtime_run_inspector" {
  project = var.project_id
  role    = google_project_iam_custom_role.run_inspector.id
  member  = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# Firestore Datastore User (read/write access to Firestore collections)
resource "google_project_iam_member" "runtime_datastore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# Write-only telemetry & metrics (NO logging.viewer!)
resource "google_project_iam_member" "runtime_logging_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime_sa.email}"
}

resource "google_project_iam_member" "runtime_monitoring_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# Service Usage Consumer: grants serviceusage.services.use required for X-Goog-User-Project billing quota
# attribution when calling Google Developer Knowledge API v1 (gdk_search_docs) via keyless ADC
resource "google_project_iam_member" "runtime_service_usage_consumer" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# Key-level KMS CryptoKey Encrypter/Decrypter (scoped strictly to mcp-token-kek)
resource "google_kms_crypto_key_iam_member" "runtime_kms_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.mcp_token_kek.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# 6. Secret Manager Secrets with Auto-Bootstrapping & Per-Secret Access
# 6.1 JWT ES256 Private Key (auto-generated ECDSA P-256)
resource "tls_private_key" "jwt_signing_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "google_secret_manager_secret" "jwt_private_key" {
  project   = var.project_id
  secret_id = "spark-jwt-signing-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret_version" "jwt_private_key_version" {
  secret      = google_secret_manager_secret.jwt_private_key.id
  secret_data = tls_private_key.jwt_signing_key.private_key_pem
}

resource "google_secret_manager_secret_iam_member" "jwt_private_key_accessor" {
  secret_id = google_secret_manager_secret.jwt_private_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# 6.2 Session HMAC Key (auto-generated 32-byte hex)
resource "random_id" "session_hmac_key" {
  byte_length = 32
}

resource "google_secret_manager_secret" "session_hmac_key" {
  project   = var.project_id
  secret_id = "session-hmac-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret_version" "session_hmac_key_version" {
  secret      = google_secret_manager_secret.session_hmac_key.id
  secret_data = random_id.session_hmac_key.hex
}

resource "google_secret_manager_secret_iam_member" "session_hmac_key_accessor" {
  secret_id = google_secret_manager_secret.session_hmac_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# 6.3 Google Sign-In OIDC Client Secret
resource "google_secret_manager_secret" "google_oidc_client_secret" {
  project   = var.project_id
  secret_id = "spark-google-oidc-client-secret"

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret_version" "google_oidc_client_secret_version" {
  secret      = google_secret_manager_secret.google_oidc_client_secret.id
  secret_data = local.google_oidc_client_secret_val
}

resource "google_secret_manager_secret_iam_member" "google_oidc_client_secret_accessor" {
  secret_id = google_secret_manager_secret.google_oidc_client_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# 6.4 GitHub OAuth Client Secret
resource "google_secret_manager_secret" "github_oauth_secret" {
  project   = var.project_id
  secret_id = "spark-github-oauth-secret"

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret_version" "github_oauth_secret_version" {
  secret      = google_secret_manager_secret.github_oauth_secret.id
  secret_data = local.github_oauth_client_secret_val
}

resource "google_secret_manager_secret_iam_member" "github_oauth_secret_accessor" {
  secret_id = google_secret_manager_secret.github_oauth_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# 6.5 Jira / Atlassian OAuth Client Secret
resource "google_secret_manager_secret" "jira_oauth_secret" {
  project   = var.project_id
  secret_id = "spark-jira-oauth-secret"

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret_version" "jira_oauth_secret_version" {
  secret      = google_secret_manager_secret.jira_oauth_secret.id
  secret_data = local.jira_oauth_client_secret_val
}

resource "google_secret_manager_secret_iam_member" "jira_oauth_secret_accessor" {
  secret_id = google_secret_manager_secret.jira_oauth_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime_sa.email}"
}

# 7. Artifact Registry (asia-southeast1)
resource "google_artifact_registry_repository" "spark_gateway" {
  project       = var.project_id
  location      = var.region
  repository_id = "spark-gateway"
  description   = "Docker repository for Spark Unified MCP Gateway"
  format        = "DOCKER"

  depends_on = [google_project_service.enabled_apis]
}

# 8. Cloud Run v2 Service (spark-mcp-gateway)
resource "google_cloud_run_v2_service" "spark_mcp_gateway" {
  name     = var.service_name
  project  = var.project_id
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account                  = google_service_account.runtime_sa.email
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    timeout                          = "300s"
    max_instance_request_concurrency = 40

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }

    containers {
      image = var.container_image

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      startup_probe {
        initial_delay_seconds = 0
        timeout_seconds       = 3
        period_seconds        = 5
        failure_threshold     = 5
        http_get {
          path = "/health"
          port = 8080
        }
      }

      liveness_probe {
        timeout_seconds   = 3
        period_seconds    = 15
        failure_threshold = 3
        http_get {
          path = "/health"
          port = 8080
        }
      }

      env {
        name  = "SERVICE_URL"
        value = local.service_url
      }
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "GCP_REGION"
        value = var.region
      }
      env {
        name  = "FIRESTORE_DATABASE_ID"
        value = var.firestore_database_id
      }
      env {
        name  = "STORE_BACKEND"
        value = "firestore"
      }
      env {
        name  = "KMS_KEY_NAME"
        value = google_kms_crypto_key.mcp_token_kek.id
      }
      env {
        name  = "ADMIN_ALLOWED_EMAILS"
        value = var.admin_allowed_emails
      }
      env {
        name  = "GOOGLE_OIDC_CLIENT_ID"
        value = var.google_oidc_client_id
      }
      env {
        name  = "GITHUB_OAUTH_CLIENT_ID"
        value = var.github_oauth_client_id
      }
      env {
        name  = "GITHUB_ALLOWED_WRITE_REPOS"
        value = var.github_allowed_write_repos
      }
      env {
        name  = "JIRA_OAUTH_CLIENT_ID"
        value = var.jira_oauth_client_id
      }
      env {
        name  = "ALLOW_LOCAL_CLIENTS"
        value = "true"
      }
      env {
        name  = "DEV_MODE"
        value = "false"
      }

      # Secrets mounted from Secret Manager with explicit version pinning (NOT 'latest')
      env {
        name = "JWT_ES256_PRIVATE_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt_private_key.secret_id
            version = google_secret_manager_secret_version.jwt_private_key_version.version
          }
        }
      }

      env {
        name = "SESSION_HMAC_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.session_hmac_key.secret_id
            version = google_secret_manager_secret_version.session_hmac_key_version.version
          }
        }
      }

      env {
        name = "GOOGLE_OIDC_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.google_oidc_client_secret.secret_id
            version = google_secret_manager_secret_version.google_oidc_client_secret_version.version
          }
        }
      }

      env {
        name = "GITHUB_OAUTH_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.github_oauth_secret.secret_id
            version = google_secret_manager_secret_version.github_oauth_secret_version.version
          }
        }
      }

      env {
        name = "JIRA_OAUTH_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jira_oauth_secret.secret_id
            version = google_secret_manager_secret_version.jira_oauth_secret_version.version
          }
        }
      }
    }
  }

  # Ownership split with GitHub Actions deploy workflow.
  # CI ships container images and promotes traffic; Terraform manages infra, scaling, and secrets.
  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
      traffic,
    ]
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_firestore_database.spark_mcp_db,
    google_kms_crypto_key.mcp_token_kek,
    google_secret_manager_secret_iam_member.jwt_private_key_accessor,
    google_secret_manager_secret_version.jwt_private_key_version,
    google_secret_manager_secret_iam_member.session_hmac_key_accessor,
    google_secret_manager_secret_version.session_hmac_key_version,
    google_secret_manager_secret_iam_member.google_oidc_client_secret_accessor,
    google_secret_manager_secret_version.google_oidc_client_secret_version,
    google_secret_manager_secret_iam_member.github_oauth_secret_accessor,
    google_secret_manager_secret_version.github_oauth_secret_version,
    google_secret_manager_secret_iam_member.jira_oauth_secret_accessor,
    google_secret_manager_secret_version.jira_oauth_secret_version,
  ]
}

# Unauthenticated Ingress for OAuth 2.1 RFC 8414 endpoints & MCP Streamable HTTP data plane
resource "google_cloud_run_v2_service_iam_member" "allow_unauthenticated" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.spark_mcp_gateway.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# 9. Optional Direct Cloud Run Custom Domain Mapping (Zero Load Balancer Idle Floor)
resource "google_cloud_run_domain_mapping" "custom_domain" {
  count    = var.enable_custom_domain_mapping && local.clean_domain != "" ? 1 : 0
  location = var.region
  name     = local.clean_domain

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.spark_mcp_gateway.name
  }

  depends_on = [google_cloud_run_v2_service.spark_mcp_gateway]
}

# 10. Optional $25/mo Google Billing Budget Alert
resource "google_billing_budget" "budget" {
  count           = var.billing_account_id != "" ? 1 : 0
  billing_account = var.billing_account_id
  display_name    = "Spark MCP Gateway Monthly Budget Alert"

  budget_filter {
    projects = ["projects/${var.project_number}"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "25"
    }
  }

  threshold_rules {
    threshold_percent = 0.5
  }
  threshold_rules {
    threshold_percent = 0.8
  }
  threshold_rules {
    threshold_percent = 1.0
  }

  depends_on = [google_project_service.enabled_apis]
}