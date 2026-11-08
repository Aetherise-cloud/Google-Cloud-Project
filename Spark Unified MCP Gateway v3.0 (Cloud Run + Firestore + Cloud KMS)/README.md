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

Infrastructure is fully automated with Terraform in `terraform/` against `gs://spark-mcp-gateway-v3-tfstate`:

```bash
cd "Spark Unified MCP Gateway v3.0 (Cloud Run + Firestore + Cloud KMS)/terraform"
terraform init
terraform validate
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

## 🔍 Observability, Redaction & Troubleshooting

### Inspecting Production Logs
```bash
gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="spark-mcp-gateway"' \
  --project=spark-mcp-gateway-v3 \
  --limit=20 \
  --format="json(severity,textPayload,jsonPayload)"
```
