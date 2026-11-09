# ==============================================================================
# Cloud Monitoring Alert Policies & Observability SLIs (Section E.3)
# ==============================================================================
# 1. Cloud Run 5xx Response Rate Alert (SLI: 5xx Error Rate > 1% over 5m window)
# 2. Cloud KMS Decrypt Error Spike Alert (SLI: Decrypt Errors >= 1 on mcp-token-kek)
# ==============================================================================

# 1. Cloud Run 5xx Response Rate Alert
resource "google_monitoring_alert_policy" "cloudrun_5xx_rate" {
  project      = var.project_id
  display_name = "Cloud Run 5xx Response Rate Alert (> 1%) - ${var.service_name}"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Run 5xx response rate exceeds 1% over 5m window"

    condition_threshold {
      filter          = "resource.type = \"cloud_run_revision\" AND resource.labels.service_name = \"${var.service_name}\" AND metric.type = \"run.googleapis.com/request_count\" AND metric.labels.response_code_class = \"5xx\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.01

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.label.service_name"]
      }

      denominator_filter = "resource.type = \"cloud_run_revision\" AND resource.labels.service_name = \"${var.service_name}\" AND metric.type = \"run.googleapis.com/request_count\""

      denominator_aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.label.service_name"]
      }

      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Cloud Run service `${var.service_name}` 5xx response rate exceeded 1% over a 5-minute evaluation window. Possible causes: cold-start timeouts, unhandled panics, or KMS/Firestore IAM regressions. Run: `gcloud logging read 'resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${var.service_name}\" AND severity>=ERROR' --limit=50`."
    mime_type = "text/markdown"
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_cloud_run_v2_service.spark_mcp_gateway,
  ]
}

# 2. Log-Based Metric for Cloud KMS Decrypt Errors on mcp-token-kek
resource "google_logging_metric" "kms_decrypt_errors" {
  project     = var.project_id
  name        = "spark_mcp_kms_decrypt_errors"
  description = "Count of Cloud KMS Decrypt errors on mcp-token-kek"
  filter      = "protoPayload.serviceName=\"cloudkms.googleapis.com\" AND protoPayload.methodName=\"Decrypt\" AND severity>=ERROR"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }

  depends_on = [google_project_service.enabled_apis]
}

# 3. Cloud KMS Decrypt Error Spike Alert Policy
resource "google_monitoring_alert_policy" "kms_decrypt_error_spike" {
  project      = var.project_id
  display_name = "Cloud KMS Decrypt Error Spike Alert - mcp-token-kek"
  combiner     = "OR"

  conditions {
    display_name = "Cloud KMS Decrypt error spike on mcp-token-kek (>= 1 error in 5m)"

    condition_threshold {
      filter          = "resource.type = \"global\" AND metric.type = \"logging.googleapis.com/user/${google_logging_metric.kms_decrypt_errors.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Cloud KMS Decrypt error spike detected on `mcp-token-kek`. Indicates corrupted ciphertext in Firestore, key version tampering, or revoked `roles/cloudkms.cryptoKeyEncrypterDecrypter` on runtime service account `mcp-spark-gateway-sa`. Check Cloud Audit Logs: `gcloud logging read 'protoPayload.serviceName=\"cloudkms.googleapis.com\" AND protoPayload.methodName=\"Decrypt\" AND severity>=ERROR' --limit=20`."
    mime_type = "text/markdown"
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_kms_crypto_key.mcp_token_kek,
    google_logging_metric.kms_decrypt_errors,
  ]
}
