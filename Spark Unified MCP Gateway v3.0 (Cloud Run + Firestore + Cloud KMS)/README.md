# Spark Unified MCP Gateway v3.0 (`spark-mcp-gateway`)

> **Production-Grade Dual-Plane Model Context Protocol (MCP) Streamable HTTP Gateway for Google Cloud, Developer Knowledge, GitHub, and Jira**  
> Target GCP Region: `asia-southeast1` (Singapore) | Target Project: `spark-mcp-gateway-v3` (Folder: `Aetherise`) | Runtime: Go 1.23 on Distroless Linux AMD64

[![CI Status](https://github.com/Aetherise-cloud/Google-Cloud-Project/actions/workflows/spark-mcp-gateway-ci.yml/badge.svg)](https://github.com/Aetherise-cloud/Google-Cloud-Project/actions/workflows/spark-mcp-gateway-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker Image Size](https://img.shields.io/badge/image%20size-%3C%2025%20MB-brightgreen)](https://gcr.io/distroless/static-debian12)

---

## 📋 Table of Contents
1. [Overview & Value Proposition](#-overview--value-proposition)
2. [Dual-Plane Architecture](#-dual-plane-architecture)
3. [TokenVault & Cloud KMS Envelope Encryption](#-tokenvault--cloud-kms-envelope-encryption)
4. [Unified Tool Matrix (10 Tools)](#-unified-tool-matrix-10-tools)
5. [Core Gateway Protocol Flows (Flows 1, 2, 3)](#-core-gateway-protocol-flows)
6. [Local Development Quickstart](#-local-development-quickstart)
7. [Declarative Terraform Infrastructure](#-declarative-terraform-infrastructure)
8. [External OAuth Application Setup](#-external-oauth-application-setup)
9. [Connecting AI Clients (Gemini Spark & Cursor)](#-connecting-ai-clients-gemini-spark--cursor)
10. [FinOps 3-Tier Monthly Cost Breakdown](#-finops-3-tier-monthly-cost-breakdown)
11. [Section E: Hardened CI/CD, Observability & Redaction](#-section-e-hardened-cicd-observability--redaction)

---

## 🎯 Overview & Value Proposition

**Spark Unified MCP Gateway v3.0** solves the enterprise sprawl of multiple standalone Model Context Protocol servers by providing a **single, unified, secure HTTP gateway**. Instead of running individual local Node.js or Python CLI servers (`npx -y @modelcontextprotocol/server-...`, `uvx mcp-server-...`), AI desktop and cloud agents connect over **MCP Streamable HTTP (`POST /mcp`)** backed by Google Cloud Run.

### Key Capabilities
- ✅ **Single Static Binary (< 25 MB)**: Compiled with Go 1.23 on `gcr.io/distroless/static-debian12:nonroot`, eliminating container bloat, Node.js/Python runtime overhead, and shell vulnerability vectors.
- ✅ **Stateless Streamable HTTP Data Plane**: High-throughput JSON-RPC 2.0 streaming on `POST /mcp` with RFC 8707 resource-scoped Bearer token validation and sub-350ms cold starts.
- ✅ **Distributed CAS Refresh Lease**: Prevents multi-instance Atlassian 3LO rotating refresh token invalidation using a Firestore ACID transaction lock (`lease_expires_at = now + 15s`).
- ✅ **Cloud KMS Envelope Encryption**: All third-party upstream OAuth tokens in Firestore are encrypted with unique per-record AES-256-GCM Data Encryption Keys (DEKs) wrapped by a regional Cloud KMS Key Encryption Key (`mcp-token-kek`).
- ✅ **Zero Server-Side Token Cost ($0.00 AI Spend)**: Server-side LLM inference is eliminated; AI reasoning occurs inside the client (Gemini Spark / Cursor), while the gateway acts strictly as an identity and tool broker.
- ✅ **Hardened FinOps Architecture**: Keyless Google Developer Knowledge API v1 replaces sunset Custom Search JSON API, cutting Peak monthly infrastructure cost by **99.8% ($235.90 -> $0.54/mo)**.

---

## 🏛️ Dual-Plane Architecture

```mermaid
flowchart TD
    subgraph ClientLayer ["Client Layer (AI Agents & Admins)"]
        Gemini["Gemini Spark / Cursor IDE"]
        AdminUser["Admin Browser (brendon.ang20011007@gmail.com)"]
    end

    subgraph InboundGate ["Control & Data Plane Ingress (asia-southeast1)"]
        CloudRun["Cloud Run Gen2: spark-mcp-gateway<br/>(1 vCPU, 512 MiB, Concurrency: 40)"]
    end

    subgraph ControlPlane ["Control Plane (OAuth 2.1 RFC 8414 & Admin)"]
        GoogleOIDC["Google Sign-In OIDC (/auth/google/login)"]
        AdminDash["Admin Dashboard (/dashboard)"]
        DCR["Dynamic Client Reg (/api/oauth/register)"]
        AuthServer["OAuth 2.1 Auth Server (/authorize, /api/oauth/token)"]
        JWKS["JWKS Endpoint (/.well-known/jwks.json - ES256)"]
    end

    subgraph DataPlane ["Data Plane (MCP Streamable HTTP)"]
        McpRouter["MCP JSON-RPC 2.0 Router (POST /mcp)"]
        ToolRegistry["Dynamic Tool Registry & Scope Filter"]
        PromptDefense["XML Prompt-Injection Sanitizer"]
    end

    subgraph SecurityVault ["Security, State & Encryption Layer"]
        KMS["Cloud KMS (spark-mcp-ring / mcp-token-kek)"]
        Firestore[("Firestore Native: spark-mcp-db<br/>(TTL: states 10m, codes 5m, clients 30d)")]
        SecretMgr["Secret Manager (Pinned Versions)"]
    end

    subgraph UpstreamConnectors ["Outbound Upstream Connectors"]
        GCP["GCP Cloud Run API (Keyless ADC)"]
        GDK["Developer Knowledge API v1 (Keyless ADC)"]
        GitHub["GitHub REST API (OAuth 2.0 / Bearer)"]
        Jira["Atlassian Jira REST API (3LO OAuth 2.0)"]
    end

    Gemini -->|POST /mcp (Bearer ES256 JWT)| McpRouter
    Gemini -->|RFC 8414 Discovery & Token Exchange| AuthServer
    AdminUser -->|Google OIDC Login| GoogleOIDC
    GoogleOIDC --> AdminDash

    McpRouter --> ToolRegistry
    ToolRegistry --> PromptDefense
    PromptDefense --> GCP
    PromptDefense --> GDK
    PromptDefense --> GitHub
    PromptDefense --> Jira

    CloudRun -.-> KMS
    CloudRun -.-> Firestore
    CloudRun -.-> SecretMgr
```

---

## 🔒 TokenVault & Cloud KMS Envelope Encryption

Upstream access tokens and refresh tokens are protected at rest using regional Cloud KMS envelope encryption:
1. When storing credentials in Firestore (`spark-mcp-db`), a cryptographic 32-byte Data Encryption Key (DEK) is randomly generated via `crypto/rand`.
2. The payload is encrypted with AES-256-GCM using authenticated additional data (AAD) bound to the owner's Google identity (`userID:provider`).
3. The DEK is wrapped by the regional Cloud KMS Key Encryption Key (`projects/spark-mcp-gateway-v3/locations/asia-southeast1/keyRings/spark-mcp-ring/cryptoKeys/mcp-token-kek`).
4. Only the wrapped DEK and encrypted ciphertext are stored in Firestore; raw plaintext keys are never persisted to disk.

---

## 🛠️ Unified Tool Matrix (10 Tools)

| Tool Name | Provider | Scope Requirement | Minimal Preset | Description |
|---|---|---|---|---|
| `gdk_search_docs` | Google | `read_only` | ✅ Yes | Official Google Developer Knowledge search across Google Cloud documentation |
| `gdk_get_doc` | Google | `read_only` | ✅ Yes | Fetch verbatim markdown documentation by document URI |
| `gcp_list_cloudrun_services` | Google Cloud | `read_only` | ✅ Yes | Enumerate Cloud Run v2 services across project & region via keyless ADC |
| `gcp_get_cloudrun_service` | Google Cloud | `read_only` | ❌ No | Inspect Cloud Run service configuration (with secrets strictly redacted) |
| `github_list_prs` | GitHub | `read_only` | ❌ No | List pull requests for a given repository with state filtering |
| `github_read_file` | GitHub | `read_only` | ❌ No | Fetch raw file contents from a repository branch or commit |
| `github_create_issue` | GitHub | `full_access` | ❌ No | Create a new issue (guarded by `allowed_write_repos`) |
| `jira_get_issue` | Atlassian | `read_only` | ❌ No | Retrieve Jira issue details with flattened plaintext ADF descriptions |
| `jira_search_issues` | Atlassian | `read_only` | ❌ No | Query Jira Cloud issues using JQL syntax (scoped to `allowed_space_keys`) |
| `jira_create_issue` | Atlassian | `full_access` | ❌ No | Create a Jira issue in authorized project spaces |
| `jira_update_issue_status` | Atlassian | `full_access` | ❌ No | Perform workflow status transitions on Jira issues |

---

## ⚡ Core Gateway Protocol Flows

### Flow 1: Direct-Link Onboarding, OAuth 2.1 DCR & Interactive Workspace Picker
- **OAuth 2.1 RFC 8414 & RFC 7591 Dynamic Client Registration (DCR)**:
  - Endpoints: `POST /api/oauth/register` (`/register`), `GET /authorize`, `POST /api/oauth/token` (`/token`), and `GET /.well-known/oauth-protected-resource`.
  - Direct-link onboarding allows AI clients (Gemini Spark, Cursor IDE, Claude Code) to dynamically register without hardcoded pre-shared client credentials.
  - Configured with `ALLOW_LOCAL_CLIENTS="true"` in Cloud Run: permits loopback redirect URIs (`http://127.0.0.1:*`, `http://localhost:*`) and dynamic AI client callback handlers.
- **Interactive Workspace & Scope Picker**:
  - The admin dashboard (`/dashboard`) hosts an interactive wizard for managing connector authorizations.
  - Operators select target GitHub Organizations (`selected_orgs`), specific read repositories (`allowed_read_repos`), write repositories (`allowed_write_repos`), and Atlassian Jira site spaces (`allowed_space_keys`) before generating cryptographic scoped JWTs.

### Flow 2: Hot-Path Scope & Write Guardrails
- **Granular Token Scope Boundaries**:
  - Each issued ES256 Bearer JWT encapsulates provider permissions (`read_only`, `full_access`, or `none`).
  - Hot-path checks evaluate permissions before any tool invocation reaches upstream APIs.
- **Guardrail Parameter Enforcement**:
  - `selected_orgs`: Restricts GitHub tool calls strictly to approved organization boundaries.
  - `allowed_read_repos`: Allowlist for repository reads (`github_list_prs`, `github_read_file`).
  - `allowed_write_repos`: Strictly constrains mutating actions (`github_create_issue`). Unlisted repositories are blocked immediately with `Access denied`.
  - `allowed_space_keys`: Restricts Jira tools (`jira_get_issue`, `jira_search_issues`, `jira_create_issue`, and `jira_update_issue_status`) to authorized Jira project keys.

### Flow 3: Anti-503 Standardized JSON-RPC 2.0 Error Envelope & Token Auto-Refresh
- **Standardized JSON-RPC 2.0 Error Envelopes (Zero 503 HTTP Drops)**:
  - Standard HTTP reverse proxies return HTTP 502/503 on upstream failures, which causes AI IDEs to drop the MCP connection and fail the user's prompt.
  - Spark MCP Gateway intercepts all upstream network errors, expired credentials, and permission denials, returning an HTTP 200 OK with a standardized JSON-RPC 2.0 response:
    ```json
    {
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
        "content": [
          {
            "type": "text",
            "text": "Provider github is not connected or credentials expired. Re-authenticate at: https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/dashboard"
          }
        ],
        "isError": true
      }
    }
    ```
- **Distributed CAS Refresh Lease**:
  - Atlassian 3LO OAuth uses rotating refresh tokens where exchanging a token immediately revokes the old one. Under multi-instance Cloud Run concurrency, simultaneous requests would cause split-brain invalidation.
  - Firestore ACID transaction locks lease token renewal for 15 seconds (`lease_expires_at = now + 15s`). Concurrent workers wait on a singleflight channel, eliminating race conditions.
- **Upstream 401 Auto-Refresh**:
  - When an upstream API responds with HTTP 401, TokenVault attempts an automatic background refresh using the valid refresh token before reporting failure.
  - If unrecoverable, clear markdown re-authorization links are delivered directly in the tool response.

---

## 💻 Local Development Quickstart

Run the gateway locally using in-memory mock stores and loopback OAuth bypass:

```bash
cd "Spark Unified MCP Gateway v3.0 (Cloud Run + Firestore + Cloud KMS)"

# Run in mock development mode
DEV_MODE=true \
ALLOW_LOCAL_CLIENTS=true \
STORE_BACKEND=memory \
ADMIN_ALLOWED_EMAILS="brendon.ang20011007@gmail.com" \
go run ./cmd/gateway
```

---

## 🏗️ Declarative Terraform Infrastructure

Infrastructure is fully automated with Terraform in `terraform/` against remote state `gs://spark-mcp-gateway-v3-tfstate`:

```bash
cd "Spark Unified MCP Gateway v3.0 (Cloud Run + Firestore + Cloud KMS)/terraform"
terraform init
terraform plan
terraform apply
```

---

## 🔑 External OAuth Application Setup

### 1. Google Sign-In OIDC (Admin Authentication)
1. Go to [Google Cloud Console -> APIs & Services -> Credentials](https://console.cloud.google.com/apis/credentials?project=spark-mcp-gateway-v3).
2. Create an **OAuth 2.0 Client ID** of type **Web application**.
3. Set **Authorized redirect URIs**:
   `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/auth/google/callback`
4. Set `SPARK_GOOGLE_OIDC_CLIENT_ID` and `SPARK_GOOGLE_OIDC_CLIENT_SECRET` in GitHub Actions Secrets.

### 2. GitHub OAuth App
1. Go to [GitHub Developer Settings -> OAuth Apps](https://github.com/settings/developers).
2. Register a new OAuth App:
   - **Application name**: `Spark Unified MCP Gateway`
   - **Homepage URL**: `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app`
   - **Authorization callback URL**: `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/oauth/callback/github`

### 3. Atlassian Jira 3LO App
1. Go to [Atlassian Developer Console -> My Apps](https://developer.atlassian.com/console/myapps).
2. Create an **OAuth 2.0 (3LO)** integration with callback URL:
   `https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/oauth/callback/jira`

---

## 🤖 Connecting AI Clients (Gemini Spark & Cursor)

### Gemini Spark Configuration
```json
{
  "mcpServers": {
    "spark-mcp-gateway": {
      "type": "http",
      "url": "https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/mcp",
      "auth": {
        "type": "oauth2",
        "authorizationUrl": "https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/authorize",
        "tokenUrl": "https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/api/oauth/token",
        "registrationUrl": "https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/api/oauth/register",
        "scopes": ["mcp:tools"]
      }
    }
  }
}
```

### Cursor IDE Configuration
```json
{
  "mcpServers": {
    "spark-gateway": {
      "url": "https://spark-mcp-gateway-515472562394.asia-southeast1.run.app/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_GENERATED_ES256_TOKEN>"
      }
    }
  }
}
```

---

## 🛡️ Section E: Hardened CI/CD, Observability & Redaction

### E.1 Workload Identity Federation (WIF) Security & PR Separation
- **Protected Branch Scoping**:
  The GitHub Actions Workload Identity Pool Provider (`spark-mcp-oidc`) attribute condition enforces:
  ```hcl
  attribute_condition = "assertion.repository_id=='${var.github_repository_id}'&&(assertion.ref=='refs/heads/main'||assertion.ref=='refs/heads/staging')"
  ```
- **Privileged SA Impersonation Restriction**:
  Untrusted `pull_request` events cannot impersonate `gh-deployer`. Deployer impersonation (`roles/iam.workloadIdentityUser`) is strictly bound to `refs/heads/main`, ensuring that untrusted code in fork PRs cannot perform privileged operations (`roles/iam.roleAdmin`, `roles/cloudkms.admin`).

### E.2 Cloud Run Image Drift Lifecycle Protection & Secret Redaction
- **Terraform Lifecycle Protection**:
  To prevent Terraform from overwriting revision images deployed by CI/CD, the Cloud Run resource defines:
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
- **Secret & Environment Redaction (`gcp_get_cloudrun_service`)**:
  When AI clients inspect Cloud Run services, the gateway strips sensitive configuration:
  - Sanitizes container environment variables (`env`) and Secret Manager volume mounts (`volumeMounts`).
  - Returns only safe operational metrics (URI, scaling min/max, service account email, image digest).

### E.3 Observability & Key Alerting SLIs
Cloud Monitoring alert policies defined in `terraform/monitoring.tf` provide proactive incident detection:
1. **Cloud Run 5xx Response Rate Alert (`google_monitoring_alert_policy.cloudrun_5xx_rate`)**:
   - Triggers when 5xx errors exceed **1%** over a 5-minute alignment window (`run.googleapis.com/request_count`).
   - Identifies cold-start latency timeouts, container crashes, or upstream database permission regressions.
2. **Cloud KMS Decrypt Error Spike Alert (`google_monitoring_alert_policy.kms_decrypt_error_spike`)**:
   - Monitors Cloud Audit Logs via log metric `spark_mcp_kms_decrypt_errors` (`protoPayload.serviceName="cloudkms.googleapis.com" AND protoPayload.methodName="Decrypt" AND severity>=ERROR`).
   - Triggers immediately if any Decrypt error occurs on `mcp-token-kek`, catching ciphertext corruption or IAM permission loss.

### Inspecting Production Logs
```bash
gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="spark-mcp-gateway"' \
  --project=spark-mcp-gateway-v3 \
  --limit=20 \
  --format="json(severity,textPayload,jsonPayload)"
```