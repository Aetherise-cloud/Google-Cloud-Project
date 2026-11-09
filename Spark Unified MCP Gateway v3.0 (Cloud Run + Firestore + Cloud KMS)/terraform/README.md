# Spark Unified MCP Gateway v3.0 — Terraform Infrastructure as Code

Declarative Terraform infrastructure for **Spark Unified MCP Gateway v3.0** (`spark-mcp-gateway`), provisioning Google Cloud Run Gen2, Cloud Firestore Native, Cloud KMS envelope encryption, Secret Manager, Artifact Registry, Workload Identity Federation (WIF), and Cloud Monitoring SLI alerts in standalone GCP project `spark-mcp-gateway-v3` (folder `Aetherise`, region `asia-southeast1`).

---

## 🏛️ Architecture & Managed Resources

| Component | GCP Resource | Specifications & Settings |
|---|---|---|
| **Serverless Compute** | `google_cloud_run_v2_service` | 1 vCPU, 512 MiB, Gen2, cpu-idle=true, cpu-boost=true, max-concurrency=40, scaling 0..5, `ALLOW_LOCAL_CLIENTS="true"`, `/health` probes |
| **State Store** | `google_firestore_database` | Named database `spark-mcp-db`, `FIRESTORE_NATIVE`, PITR enabled, deletion_policy=ABANDON |
| **TTL Policies** | `google_firestore_field` | Native TTLs on `expires_at` for `oauth_states`, `auth_codes`, and `oauth_clients` |
| **Envelope Encryption** | `google_kms_key_ring` & `crypto_key` | `spark-mcp-ring` / `mcp-token-kek` (AES-256 KEK wrapping DEKs, 365-day rotation) |
| **Identity & Secrets** | `google_secret_manager_secret` | 5 regional secrets (`spark-jwt-signing-key`, `session-hmac-key`, and OAuth secrets), pinned `.version` |
| **Container Registry** | `google_artifact_registry_repository` | `spark-gateway` Docker repository in `asia-southeast1` |
| **Least-Privilege IAM** | `google_service_account` & `custom_role` | `mcp-spark-gateway-sa`, scoped custom role `sparkMcpRunInspector` (NO `logging.viewer`!) |
| **Keyless CI/CD (WIF)** | `google_iam_workload_identity_pool` | `spark-mcp-oidc` restricted strictly to `refs/heads/main` and `refs/heads/staging`; deployer SA impersonation scoped strictly to `refs/heads/main` (zero JSON keys) |
| **Observability & SLIs** | `google_monitoring_alert_policy` | Cloud Run 5xx response rate alert (> 1% over 5m window) and Cloud KMS Decrypt error spike alert |
| **Audit Log Metrics** | `google_logging_metric` | `spark_mcp_kms_decrypt_errors` on `protoPayload.methodName="Decrypt"` |
| **Cost Alerts** | `google_billing_budget` | Optional $25/mo threshold alert (50%, 80%, 100%) |

---

## 🚀 Step-by-Step Bootstrap Guide

### 1. Prerequisites
Ensure you have installed:
- Google Cloud SDK (`gcloud`) >= `500.0.0`
- Terraform >= `1.5.0` (tested with `1.9.x` / `1.15.x`)

Authenticate to GCP:
```bash
gcloud auth application-default login
gcloud config set project spark-mcp-gateway-v3
```

### 2. Configure Environment Variables
Copy `terraform.tfvars.example` to `terraform.tfvars`:
```bash
cd "Spark Unified MCP Gateway v3.0 (Cloud Run + Firestore + Cloud KMS)/terraform"
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your OAuth application credentials:
- `google_oidc_client_id` & `google_oidc_client_secret` from [Google Cloud Console Credentials](https://console.cloud.google.com/apis/credentials)
- `github_oauth_client_id` & `github_oauth_client_secret` from [GitHub Developer Settings](https://github.com/settings/developers)
- `jira_oauth_client_id` & `jira_oauth_client_secret` from [Atlassian Developer Console](https://developer.atlassian.com/console/myapps)

> [!NOTE]
> If OAuth secrets are left blank, Terraform defaults them to `UNCONFIGURED`, allowing initial infrastructure provisioning to succeed prior to external app configuration.

### 3. Initialize & Plan
Initialize the remote GCS state backend (`gs://spark-mcp-gateway-v3-tfstate`):
```bash
terraform init
```

Generate and inspect an execution plan:
```bash
terraform plan -out=tfplan
```

### 4. Apply Infrastructure
Apply the plan:
```bash
terraform apply tfplan
```

Terraform automatically:
1. Enables all required GCP APIs (including Cloud Run, Firestore, KMS, Secret Manager, Monitoring, and Logging).
2. Generates an ECDSA P-256 JWT private signing key (`tls_private_key`) and random 32-byte HMAC session secret (`random_id`).
3. Provisions the dedicated `spark-mcp-db` Firestore database and configures Native TTLs.
4. Creates the Cloud KMS `mcp-token-kek` key and grants envelope encryption roles.
5. Deploys the initial `spark-mcp-gateway` Cloud Run v2 service with strict zero-drift lifecycle rules.
6. Provisions Cloud Monitoring alert policies for Cloud Run 5xx rate and Cloud KMS Decrypt error spikes.

---

## 🔐 Section E: Hardened CI/CD, Zero-Drift & Observability

### E.1 Workload Identity Federation (WIF) Security & PR Separation
To prevent untrusted pull request code execution from gaining privileged administrative access to GCP resources:
- In `google_iam_workload_identity_pool_provider.spark_mcp_oidc`, the `attribute_condition` restricts authentication strictly to protected branches:
  ```hcl
  attribute_condition = "assertion.repository_id=='${var.github_repository_id}'&&(assertion.ref=='refs/heads/main'||assertion.ref=='refs/heads/staging')"
  ```
- Untrusted `pull_request` events are explicitly prevented from authenticating to the privileged deployer pool.
- The `gh-deployer` service account holds administrative roles (`roles/cloudkms.admin`, `roles/iam.roleAdmin`, `roles/run.developer`). Service account impersonation (`roles/iam.workloadIdentityUser`) is scoped strictly to `refs/heads/main`:
  ```hcl
  member = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.ref/refs/heads/main"
  ```
- When using a pre-existing deployer service account (`var.create_wif_pool == false`), setting `enforce_deployer_main_ref_binding = true` enables `google_service_account_iam_member.existing_gh_deployer_main_only` to enforce this policy declaratively.

### E.2 Cloud Run Zero-Drift Ownership & Secret Redaction
- **Ownership Split with GitHub Actions**:
  The Cloud Run service resource includes an explicit lifecycle ignore block:
  ```hcl
  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
      traffic,
    ]
  }
  ```
  - **Terraform owns:** Topologies, environment variables (`ALLOW_LOCAL_CLIENTS="true"`, `STORE_BACKEND="firestore"`), Secret Manager mounts with pinned `.version`, scaling limits (`0..5`), CPU/memory quotas, and health probes.
  - **GitHub Actions CI/CD owns:** Container builds (`sha256` digest on Artifact Registry), zero-downtime candidate rollouts (`--no-traffic --tag cand-<sha7>`), automated smoke tests, and 100% traffic migration (`--to-latest`).
- **Data Protection & Secret Redaction (`gcp_get_cloudrun_service`)**:
  The internal GCP provider strictly sanitizes Cloud Run service descriptions before returning them to AI clients:
  - Drops container `env` maps and Secret Manager `volumeMounts`.
  - Exposes only non-sensitive metadata (URI, service account, scaling parameters, container image digest).

### E.3 Observability, Runbook Checks & Key Alerting SLIs
Automated alerting policies in `monitoring.tf` protect production availability and cryptographic integrity:
1. **Cloud Run 5xx Response Rate Alert (`google_monitoring_alert_policy.cloudrun_5xx_rate`)**:
    - Computes the ratio of `5xx` responses over total requests on `run.googleapis.com/request_count`.
    - Triggers when 5xx errors exceed **1%** over a 5-minute (`300s`) alignment window.
    - Detects cold-start timeouts, unhandled panics, or KMS/Firestore IAM permission regressions.
2. **Cloud KMS Decrypt Error Spike Alert (`google_monitoring_alert_policy.kms_decrypt_error_spike`)**:
    - Monitors Cloud Audit Logs via log-based metric `spark_mcp_kms_decrypt_errors` (`protoPayload.serviceName="cloudkms.googleapis.com" AND protoPayload.methodName="Decrypt" AND severity>=ERROR`).
    - Triggers if **any** Decrypt errors occur within 5 minutes (`threshold_value = 0`).
    - Detects corrupted ciphertext in Firestore, revoked key permissions, or key tampering.

---

## 🔄 Gateway Protocol Flows

### Flow 1: Direct-Link Onboarding, OAuth 2.1 DCR & Interactive Scope Picker
- **OAuth 2.1 Dynamic Client Registration (RFC 7591 / RFC 8414)**:
  - Supported endpoints: `/register`, `/authorize`, `/token`, and `/.well-known/oauth-protected-resource`.
  - Configured with `ALLOW_LOCAL_CLIENTS="true"`: allows loopback redirect URIs (`http://127.0.0.1:*`, `http://localhost:*`) and dynamic AI client callback schemes (e.g., Gemini Spark, Cursor, Claude Code).
- **Interactive Workspace & Scope Picker**:
  - The admin dashboard (`/dashboard`) provides an interactive OAuth connection wizard.
  - Granular selection of GitHub Organizations, repository whitelists, and Jira Cloud sites/spaces prior to authorizing token issuance.

### Flow 2: Hot-Path Scope & Write Guardrails
- **Multi-Tenant Scope Filtering**:
  - Each issued JWT token embeds provider scopes (`read_only`, `full_access`, or `none`) for `github`, `jira`, and custom connectors.
  - Scopes are enforced before tool execution on the MCP hot-path:
    - `selected_orgs`: Restricts GitHub tool execution strictly to approved organizations.
    - `allowed_read_repos`: Restricts `github_list_prs` and `github_read_file`.
    - `allowed_write_repos`: Guardrail on mutating tools like `github_create_issue`.
    - `allowed_space_keys`: Scopes `jira_get_issue`, `jira_search_issues`, `jira_create_issue`, and `jira_update_issue_status` to authorized project spaces.
- **Fail-Closed Execution**:
  - Any attempt to access an unauthorized repository or space is immediately rejected with a structured security violation, preventing unauthorized code mutation.

### Flow 3: Anti-503 Standardized JSON-RPC 2.0 Error Envelope & Auto-Refresh
- **Standardized JSON-RPC 2.0 Error Envelope**:
  - Under traditional HTTP proxies, upstream errors produce HTTP `502 Bad Gateway` or `503 Service Unavailable`, causing AI clients to disconnect or terminate sessions.
  - The gateway encapsulates all upstream tool errors into standard JSON-RPC 2.0 responses:
    ```json
    {
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
        "content": [
          {
            "type": "text",
            "text": "Provider github is not connected or credentials expired. Re-authenticate at: https://spark-mcp-gateway.../dashboard"
          }
        ],
        "isError": true
      }
    }
    ```
- **Distributed CAS Refresh Lease**:
  - Rotating refresh tokens (e.g., Atlassian Jira 3LO) are protected against race conditions using a Firestore ACID transaction lock (`lease_expires_at = now + 15s`).
  - Concurrent requests wait or reuse refreshed tokens, eliminating token revocation from duplicate refresh requests.
- **Upstream 401 Auto-Refresh & Graceful Re-Auth**:
  - When an upstream API returns 401 Unauthorized, TokenVault automatically attempts token refresh using the stored refresh token.
  - If refresh fails, it returns a graceful re-authentication link directly to the admin dashboard instead of crashing.

---

## 🔁 Rollback & Emergency Runbook

If a broken revision is inadvertently promoted, roll back traffic instantaneously using `gcloud`:

```bash
# List recent Cloud Run revisions
gcloud run revisions list \
  --service spark-mcp-gateway \
  --region asia-southeast1 \
  --project spark-mcp-gateway-v3

# Pin 100% traffic to the known good revision (e.g., spark-mcp-gateway-00004-abc)
gcloud run services update-traffic spark-mcp-gateway \
  --to-revisions spark-mcp-gateway-00004-abc=100 \
  --region asia-southeast1 \
  --project spark-mcp-gateway-v3
```

---

## 🔐 Secret Rotation

### Rotate JWT Signing Key
```bash
# 1. Generate new P-256 private key
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/new_jwt_key.pem

# 2. Add as a new version in Secret Manager
gcloud secrets versions add spark-jwt-signing-key \
  --data-file=/tmp/new_jwt_key.pem \
  --project=spark-mcp-gateway-v3

# 3. Clean up local key file
rm -f /tmp/new_jwt_key.pem

# 4. Update the pinned version in terraform or re-apply
terraform apply
```

### Rotate KMS KEK
The Cloud KMS key `mcp-token-kek` automatically rotates its primary version every 365 days (`31536000s`). Existing envelopes remain decryptable via version-tagged wrapped DEKs.

---

## 📊 Terraform Outputs Reference

| Output Name | Description | Example Value |
|---|---|---|
| `service_url` | Root HTTPS service URL | `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app` |
| `mcp_endpoint` | MCP Streamable HTTP Data Plane | `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/mcp` |
| `dashboard_url` | Admin Control Plane Dashboard | `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/dashboard` |
| `google_oidc_callback_url` | Google OAuth Callback | `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/auth/google/callback` |
| `github_oauth_callback_url` | GitHub OAuth Callback | `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/oauth/callback/github` |
| `jira_oauth_callback_url` | Jira 3LO OAuth Callback | `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/oauth/callback/jira` |
| `artifact_registry_image` | Base Image URL for Docker CI | `asia-southeast1-docker.pkg.dev/spark-mcp-gateway-v3/spark-gateway/gateway` |
| `kms_key_id` | KMS CryptoKey Resource ID | `projects/spark-mcp-gateway-v3/locations/asia-southeast1/keyRings/spark-mcp-ring/cryptoKeys/mcp-token-kek` |
| `firestore_database_id` | Firestore Named Database | `spark-mcp-db` |
| `runtime_service_account` | Runtime SA Email | `mcp-spark-gateway-sa@spark-mcp-gateway-v3.iam.gserviceaccount.com` |
