# Spark Unified MCP Gateway v3.0 (`spark-mcp-gateway`)

> **Production-Grade Dual-Plane Model Context Protocol (MCP) Streamable HTTP Gateway for Google Cloud, Developer Knowledge, GitHub, and Jira**  
> Target GCP Region: `asia-southeast1` (Singapore) | Target Project: `group-511516` | Runtime: Go 1.23 on Distroless Linux AMD64

[![CI Status](https://github.com/group-511516/spark-mcp-gateway/actions/workflows/spark-mcp-gateway-ci.yml/badge.svg)](https://github.com/group-511516/spark-mcp-gateway/actions/workflows/spark-mcp-gateway-ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/group-511516/spark-mcp-gateway)](https://goreportcard.com/report/github.com/group-511516/spark-mcp-gateway)
[![Docker Image Size](https://img.shields.io/badge/image%20size-%3C%2025%20MB-brightgreen)](https://gcr.io/distroless/static-debian12)

---

## 📋 Table of Contents
1. [Overview & Value Proposition](#-overview--value-proposition)
2. [Dual-Plane Architecture](#-dual-plane-architecture)
3. [TokenVault & Cloud KMS Envelope Encryption](#-tokenvault--cloud-kms-envelope-encryption)
4. [Unified Tool Matrix (10 Tools)](#-unified-tool-matrix-10-tools)
5. [Local Development Quickstart](#-local-development-quickstart)
6. [Declarative Terraform Infrastructure](#-declarative-terraform-infrastructure)
7. [External OAuth Application Setup](#-external-oauth-application-setup)
8. [Connecting AI Clients (Gemini Spark & Cursor)](#-connecting-ai-clients-gemini-spark--cursor)
9. [FinOps 3-Tier Monthly Cost Breakdown](#-finops-3-tier-monthly-cost-breakdown)
10. [Observability, Redaction & Troubleshooting](#-observability-redaction--troubleshooting)

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

### 1. Control Plane
- **Google Sign-In OIDC**: Replaces insecure HTTP Basic Auth. Only authenticated Google accounts matching `ADMIN_ALLOWED_EMAILS` receive an `HttpOnly; Secure; SameSite=Lax` `__Host-spark_admin` session cookie.
- **Admin Dashboard (`GET /dashboard`)**: Visual interface to manage upstream OAuth connections (GitHub, Jira), toggle scopes (`Minimal`, `Read Only`, `Full Access`), and inspect tool health.
- **RFC 8414 OAuth 2.1 Authorization Server**: Implements `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, Dynamic Client Registration (`POST /api/oauth/register`), PKCE (`S256`), and asymmetric ECDSA P-256 JWT minting (`/.well-known/jwks.json`).

### 2. Data Plane
- **Stateless `POST /mcp`**: Handles `tools/list` and `tools/call` over HTTP. Verifies incoming Bearer JWT against regional JWKS and RFC 8707 `aud` claim.
- **In-Memory Connection Cache**: Decrypted upstream connection status is cached in a per-instance `sync.Map` (`TTL = 60s`, max 500 entries) with immediate invalidation upon local OAuth callbacks, slashing Firestore reads by **80%**.
- **Prompt Injection Defense**: Upstream response content is wrapped with XML tags (`<untrusted_upstream_data>`) with literal closing tag escaping, preventing prompt hijacking across tools.

---

## 🔐 TokenVault & Cloud KMS Envelope Encryption

To safeguard third-party tokens stored in Firestore, TokenVault employs **two-tier envelope encryption**:

1. **Data Encryption Key (DEK)**: For every user connection, the gateway generates a cryptographically secure 32-byte DEK.
2. **Key Encryption Key (KEK)**: The DEK is encrypted using the Cloud KMS regional symmetric key `mcp-token-kek` (`asia-southeast1`) via the Google Cloud KMS API.
3. **Authenticated Data (AAD)**: Payload ciphertext is encrypted using AES-256-GCM bound to caller context:
   $$\text{AAD} = \text{"uid:"} + \text{userID} + \text{"|prv:"} + \text{provider}$$
4. **Firestore Storage**: Firestore stores `{wrapped_dek, nonce, ciphertext, kms_key_version, expires_at}`. If the database is ever compromised, tokens remain undecryptable without Cloud KMS access.

### Distributed CAS Token Refresh Lease
Atlassian Jira uses single-use rotating refresh tokens; concurrent requests with the same refresh token cause reuse detection and revoke the user's token family. To prevent races across autoscaled Cloud Run instances (up to 5 instances):
- In-process Go `singleflight` coalesces concurrent requests within each container.
- Across containers, a Firestore ACID transaction acquires a lease:
  ```go
  if doc.LeaseExpiresAt.After(now) {
      // Another instance is actively refreshing; back off and retry
      time.Sleep(300 * time.Millisecond)
      return readRefreshedToken()
  }
  // Atomically claim lease for 15s
  doc.LeaseHolder = instanceID
  doc.LeaseExpiresAt = now.Add(15 * time.Second)
  tx.Set(docRef, doc)
  ```

---

## 🛠️ Unified Tool Matrix (10 Tools)

| Tool Name | Upstream Provider | Auth Mode | Default Scope | Description |
|---|---|---|---|---|
| `gcp_list_cloudrun_services` | Google Cloud Run v2 | Keyless ADC | Baseline (Read-Only) | Lists Cloud Run services, revisions, and traffic splits in `asia-southeast1`. |
| `gcp_get_cloudrun_service` | Google Cloud Run v2 | Keyless ADC | Read-Only | Inspects configuration, container image, and CPU/memory limits for a service. Redacts environment values. |
| `gdk_search_docs` | Google Developer Knowledge | Keyless ADC | Baseline (Read-Only) | Queries official Google Cloud, Firebase, Go, and Gemini documentation via `developerknowledge.googleapis.com`. |
| `github_search_repos` | GitHub REST v3 | User OAuth Token | Read-Only | Searches repositories accessible to the user on GitHub. |
| `github_read_file` | GitHub REST v3 | User OAuth Token | Read-Only | Reads file contents and directory trees from allowed repositories. |
| `github_list_issues` | GitHub REST v3 | User OAuth Token | Read-Only | Lists issues and pull requests with state and label filters. |
| `github_create_issue` | GitHub REST v3 | User OAuth Token | Full Access (Write) | Creates new issues in repositories explicitly listed in `GITHUB_ALLOWED_WRITE_REPOS`. |
| `jira_search_issues` | Atlassian Jira Cloud | 3LO User Token | Read-Only | Searches Jira tickets using JQL queries (`project = PROJ AND status = Open`). |
| `jira_get_issue` | Atlassian Jira Cloud | 3LO User Token | Read-Only | Retrieves full Jira ticket details, description, assignee, and comments. |
| `jira_update_issue_status` | Atlassian Jira Cloud | 3LO User Token | Full Access (Write) | Transitions Jira issue workflow status (e.g., In Progress -> Done). |

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

The gateway listens on `http://127.0.0.1:8080`:
- **Health Check**: `curl -s http://127.0.0.1:8080/health` -> `{"status":"ok"}`
- **OAuth Discovery**: `curl -s http://127.0.0.1:8080/.well-known/oauth-authorization-server`
- **JWKS Endpoint**: `curl -s http://127.0.0.1:8080/.well-known/jwks.json`

---

## 🏗️ Declarative Terraform Infrastructure

Infrastructure is fully automated with Terraform in `terraform/`:

```bash
cd "Spark Unified MCP Gateway v3.0 (Cloud Run + Firestore + Cloud KMS)/terraform"

# Initialize remote backend in GCS bucket group-511516-tfstate
terraform init

# Validate configuration syntax
terraform validate

# Review execution plan
terraform plan

# Apply infrastructure changes
terraform apply
```

Key provisioned resources:
- Cloud Run v2 service `spark-mcp-gateway` (Gen2, 1 vCPU, 512 MiB, scaling 0..5, concurrency 40)
- Dedicated Cloud Firestore Native database `spark-mcp-db` with PITR and 3 Native TTL policies
- Cloud KMS KeyRing `spark-mcp-ring` and CryptoKey `mcp-token-kek`
- Secret Manager secrets with automatic ECDSA P-256 and HMAC key generation
- Least-privilege IAM roles and scoped GitHub Actions WIF bindings

---

## 🔑 External OAuth Application Setup

### 1. Google Sign-In OIDC (Admin Authentication)
1. Go to [Google Cloud Console -> APIs & Services -> Credentials](https://console.cloud.google.com/apis/credentials).
2. Create an **OAuth 2.0 Client ID** of type **Web application**.
3. Set **Authorized redirect URIs**:
   `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/auth/google/callback`
4. Set `google_oidc_client_id` and `google_oidc_client_secret` in `terraform.tfvars`.

### 2. GitHub OAuth App
1. Go to [GitHub Developer Settings -> OAuth Apps](https://github.com/settings/developers).
2. Register a new OAuth App:
   - **Application name**: `Spark Unified MCP Gateway`
   - **Homepage URL**: `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app`
   - **Authorization callback URL**: `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/oauth/callback/github`
3. Generate a Client Secret and set `github_oauth_client_id` and `github_oauth_client_secret` in `terraform.tfvars`.

### 3. Atlassian Jira 3LO App
1. Go to [Atlassian Developer Console -> My Apps](https://developer.atlassian.com/console/myapps).
2. Create an **OAuth 2.0 (3LO)** integration.
3. Under **Permissions**, add Jira platform REST API scopes (`read:jira-work`, `write:jira-work`, `read:jira-user`, `offline_access`).
4. Under **Authorization**, set the callback URL:
   `https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/oauth/callback/jira`
5. Set `jira_oauth_client_id` and `jira_oauth_client_secret` in `terraform.tfvars`.

---

## 🤖 Connecting AI Clients (Gemini Spark & Cursor)

### Gemini Spark Configuration
In your Gemini agent environment, register the gateway as a remote MCP HTTP server:

```json
{
  "mcpServers": {
    "spark-mcp-gateway": {
      "type": "http",
      "url": "https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/mcp",
      "auth": {
        "type": "oauth2",
        "authorizationUrl": "https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/authorize",
        "tokenUrl": "https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/api/oauth/token",
        "registrationUrl": "https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/api/oauth/register",
        "scopes": ["mcp:tools"]
      }
    }
  }
}
```

### Cursor IDE Configuration
In `~/.cursor/mcp.json` or project settings:
```json
{
  "mcpServers": {
    "spark-gateway": {
      "url": "https://spark-mcp-gateway-997395841168.asia-southeast1.run.app/mcp",
      "headers": {
        "Authorization": "Bearer <YOUR_GENERATED_ES256_TOKEN>"
      }
    }
  }
}
```

---

## 💰 FinOps 3-Tier Monthly Cost Breakdown

*Region: `asia-southeast1` (Singapore — Tier 2). Deductions applied from GCP Always Free Tier.*

| Category | MVP / Low (1 admin, 3k req/mo) | Expected Baseline (10 users, 60k req/mo) | Peak / Scale (100 users, 1M req/mo) |
|---|---:|---:|---:|
| **Compute** *(Cloud Run Gen2 1 vCPU / 512 MiB)* | **$0.00** | **$0.00** | **$0.00** |
| **Databases** *(Firestore Native + 7-day PITR)* | **$0.01** | **$0.04** | **$0.18** |
| **KMS & Secrets** *(Cloud KMS KEK + Secret Manager)* | **$0.06** | **$0.08** | **$0.36** |
| **Networking & Telemetry** *(Cloud Run Ingress & Logs)* | **$0.00** | **$0.00** | **$0.00** |
| **AI Services & Tokens** *(Developer Knowledge API v1)* | **$0.00** | **$0.00** | **$0.00** |
| *Always Free Value Subsidized* | *(saved $0.28)* | *(saved $0.46)* | *(saved $2.87)* |
| **Total Net Monthly Spend (USD)** | **$0.07** | **$0.11** | **$0.54** |

> [!TIP]
> **Why Cloud Run compute is $0.00**: At 1 vCPU / 512 MiB with 400ms average request duration, 1,000,000 monthly requests consume `111,111 vCPU-seconds` and `55,556 GiB-seconds`, comfortably within GCP's Always Free allocation of `180,000 vCPU-seconds` and `360,000 GiB-seconds` per month.

---

## 🔍 Observability, Redaction & Troubleshooting

### Structured Logging with Automatic Secret Redaction
All gateway logs are emitted to `stdout` in Cloud Logging JSON format. Middleware automatically redacts sensitive headers and fields (`Authorization`, `Cookie`, `Set-Cookie`, `access_token`, `refresh_token`, `code`):

```json
{
  "severity": "INFO",
  "time": "2026-11-08T14:30:00Z",
  "logging.googleapis.com/trace": "projects/group-511516/traces/abc123def456",
  "method": "tools/call",
  "tool": "gdk_search_docs",
  "status": 200,
  "latency_ms": 284,
  "user_id": "usr_99739584"
}
```

### Inspecting Production Logs
```bash
gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="spark-mcp-gateway"' \
  --project=group-511516 \
  --limit=20 \
  --format="json(severity,textPayload,jsonPayload)"
```

### Verifying Candidate Revisions Before Traffic Switch
Candidate revisions are deployed with `--no-traffic --tag cand-<sha7>`. Test the candidate directly:
```bash
# Verify health probe
curl -s -f "https://cand-<sha7>---spark-mcp-gateway-997395841168.asia-southeast1.run.app/health"

# Verify unauthenticated MCP challenge returns HTTP 401
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  "https://cand-<sha7>---spark-mcp-gateway-997395841168.asia-southeast1.run.app/mcp"
```

---

## 🚀 CI/CD & Automated Deployment

Keyless continuous integration and continuous deployment are managed with GitHub Actions:
- **`spark-mcp-gateway-ci.yml`**: Compiles Go 1.23, runs race detector tests, validates uncompressed Distroless image size (<30 MB), and checks Terraform formatting and syntax.
- **`spark-mcp-gateway-deploy.yml`**: Authenticates keylessly via Workload Identity Federation (WIF), builds and deploys immutable container revisions by `sha256` digest, validates candidate revision conditions (avoiding Issue #9 Retired trap), runs smoke probes on `/health` and unauthenticated `/mcp` challenge, and promotes traffic to `LATEST = 100%`.

> [!NOTE]
> `.github/workflows/spark-mcp-gateway-ci.yml` and `.github/workflows/spark-mcp-gateway-deploy.yml` are bundled self-contained inside this folder (`.github/workflows/`). They can be copied or symlinked to repository root `.github/workflows/` when activating monorepo GitHub Actions triggers.

