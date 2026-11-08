# Spark Unified MCP Gateway v3.0 — Terraform Infrastructure as Code

Declarative Terraform infrastructure for **Spark Unified MCP Gateway v3.0** (`spark-mcp-gateway`), provisioning Google Cloud Run Gen2, Cloud Firestore Native, Cloud KMS envelope encryption, Secret Manager, Artifact Registry, and Workload Identity Federation (WIF) in GCP region `asia-southeast1`.

---

## 🏛️ Architecture & Managed Resources

| Component | GCP Resource | Specifications & Settings |
|---|---|---|
| **Serverless Compute** | `google_cloud_run_v2_service` | 1 vCPU, 512 MiB, Gen2, cpu-idle=true, cpu-boost=true, max-concurrency=40, scaling 0..5, `/health` probes |
| **State Store** | `google_firestore_database` | Named database `spark-mcp-db`, `FIRESTORE_NATIVE`, PITR enabled, deletion_policy=ABANDON |
| **TTL Policies** | `google_firestore_field` | Native TTLs on `expires_at` for `oauth_states`, `auth_codes`, and `oauth_clients` |
| **Envelope Encryption** | `google_kms_key_ring` & `crypto_key` | `spark-mcp-ring` / `mcp-token-kek` (AES-256 KEK wrapping DEKs, 365-day rotation) |
| **Identity & Secrets** | `google_secret_manager_secret` | 5 regional secrets (`spark-jwt-signing-key`, `session-hmac-key`, and OAuth secrets), pinned `.version` |
| **Container Registry** | `google_artifact_registry_repository` | `spark-gateway` Docker repository in `asia-southeast1` |
| **Least-Privilege IAM** | `google_service_account` & `custom_role` | `mcp-spark-gateway-sa`, scoped custom role `sparkMcpRunInspector` (NO `logging.viewer`!) |
| **Keyless CI/CD** | `google_iam_workload_identity_pool` | Scoped grants to existing `gh-deployer@group-511516.iam.gserviceaccount.com` (zero JSON keys) |
| **Cost Alerts** | `google_billing_budget` | Optional $25/mo threshold alert (50%, 80%, 100%) |

---

## 🚀 Step-by-Step Bootstrap Guide

### 1. Prerequisites
Ensure you have installed:
- Google Cloud SDK (`gcloud`) >= `500.0.0`
- Terraform >= `1.5.0` (tested with `1.15.x`)

Authenticate to GCP:
```bash
gcloud auth application-default login
gcloud config set project group-511516
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
Initialize the remote GCS state backend:
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
1. Enables all 10 required GCP APIs.
2. Generates an ECDSA P-256 JWT private signing key (`tls_private_key`) and random 32-byte HMAC session secret (`random_id`).
3. Provisions the dedicated `spark-mcp-db` Firestore database and configures Native TTLs.
4. Creates the Cloud KMS `mcp-token-kek` key and grants envelope encryption roles.
5. Deploys the initial `spark-mcp-gateway` Cloud Run v2 service with strict zero-drift lifecycle rules.

---

## 🔄 Zero-Drift Ownership Split (Terraform vs. CI/CD)

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

- **Terraform owns:** Infrastructure topologies, environment variables, Secret Manager mounts with pinned versions, scaling limits (`0..5`), memory/CPU quotas, probes, and IAM.
- **GitHub Actions owns:** Container image builds (`sha256` digest), zero-downtime candidate rollouts (`--no-traffic --tag cand-<sha7>`), health validation, and 100% traffic migration (`--to-latest`).

---

## 🔁 Rollback & Emergency Runbook

If a broken revision is inadvertently promoted, roll back traffic instantaneously using `gcloud`:

```bash
# List recent Cloud Run revisions
gcloud run revisions list \
  --service spark-mcp-gateway \
  --region asia-southeast1 \
  --project group-511516

# Pin 100% traffic to the known good revision (e.g., spark-mcp-gateway-00004-abc)
gcloud run services update-traffic spark-mcp-gateway \
  --to-revisions spark-mcp-gateway-00004-abc=100 \
  --region asia-southeast1 \
  --project group-511516
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
  --project=group-511516

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
| `service_url` | Root HTTPS service URL | `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app` |
| `mcp_endpoint` | MCP Streamable HTTP Data Plane | `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/mcp` |
| `dashboard_url` | Admin Control Plane Dashboard | `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/dashboard` |
| `google_oidc_callback_url` | Google OAuth Callback | `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/auth/google/callback` |
| `github_oauth_callback_url` | GitHub OAuth Callback | `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/oauth/callback/github` |
| `jira_oauth_callback_url` | Jira 3LO OAuth Callback | `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/oauth/callback/jira` |
| `artifact_registry_image` | Base Image URL for Docker CI | `asia-southeast1-docker.pkg.dev/group-511516/spark-gateway/gateway` |
| `kms_key_id` | KMS CryptoKey Resource ID | `projects/group-511516/locations/asia-southeast1/keyRings/spark-mcp-ring/cryptoKeys/mcp-token-kek` |
| `firestore_database_id` | Firestore Named Database | `spark-mcp-db` |
| `runtime_service_account` | Runtime SA Email | `mcp-spark-gateway-sa@group-511516.iam.gserviceaccount.com` |
