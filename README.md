<div align="center">

# 🛡️ CyberNova

### AI-Powered Open-Source SIEM + SOAR + EDR Security Platform

*Think like a hacker. Respond like a security chief. Built on zero-trust architecture.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.136-green.svg)](cybernova/main.py)
[![React](https://img.shields.io/badge/React-19-61dafb.svg)](cybernova-frontend/package.json)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ed.svg)](docker-compose.yml)
[![Helm](https://img.shields.io/badge/Helm-Kubernetes-0f1689.svg)](helm/)
[![Tests](https://img.shields.io/badge/Tests-886%2B-2ea44f.svg)](tests/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-441%20rules-ff4500.svg)](SECURITY.md)

**658+ detection rules · 17 protection shields · 441 Sigma rules mapped to MITRE ATT&CK · automated SOAR playbooks**

</div>

---

## ✨ What is CyberNova?

CyberNova is a **complete, production-grade security platform** that unifies three disciplines into one zero-trust system:

| Layer | What it does |
|-------|-------------|
| **🛰️ SIEM** | Ingests, normalizes, enriches and correlates security events from 40+ sources in real time |
| **🤖 SOAR** | Automates incident response with policy-driven playbooks — block, isolate, notify, investigate |
| **🖥️ EDR** | Detects and responds to endpoint threats with native Windows & Linux agents and kernel drivers |

It ships with a **3D marketing website**, a **real-time React dashboard**, a **REST + WebSocket API**, **Prometheus/Grafana monitoring**, and **Helm charts** for Kubernetes.

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CyberNova Pipeline Architecture                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INGESTION → NORMALIZATION → ENRICHMENT → DETECTION → SOAR          │
│                                                                      │
│  [syslog]     [schema map]   [geoip]      [rules engine]  [webhook] │
│  [agents]     [dedup]        [threat      [DSL rules]     [block]   │
│  [API]        [parse]        intel]       [17 shields]    [isolate] │
│  [suricata]                  [stego]      [WAF]            [log]    │
│  [filewatch]                              [correlation]             │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Option A: Docker (recommended)

```bash
# 1. Clone the repo
git clone https://github.com/Passionate-pop/CyberNova-SIEM-SOAR.git
cd CyberNova-SIEM-SOAR

# 2. Copy the example config and set real secrets
cp .env.example .env
#   edit .env — generate secrets with:  openssl rand -hex 32

# 3. Start everything
docker compose up -d --build

# 4. Open in browser
# Marketing site:  http://localhost:8080
# Dashboard:       http://localhost:8080/app/
# API docs:        http://localhost:8000/docs
# Grafana:         http://localhost:3001   (admin / GRAFANA_PASSWORD)
# MailHog (dev):   http://localhost:8025
```

### Option B: Helm (Kubernetes)

```bash
helm install cybernova ./helm/cybernova
```

### Option C: Development (without Docker)

```bash
# Backend (FastAPI)
pip install -r requirements.txt
uvicorn cybernova.main:app --host 0.0.0.0 --port 8000

# Frontend (Vite dev server)
cd cybernova-frontend && npm install && npm run dev

# Marketing site (Next.js)
cd web-page && npm install && npm run dev
```

---

## 👤 User Flow

```
1. Open browser → 3D marketing website loads
2. Click "Get Started" → redirected to /app
3. Create account → Choose Individual or Organization
4. Accept Terms & Cookies → One-time consent
5. Install agent → Copy ONE command, paste in terminal
6. Dashboard → Real-time alerts, incidents, monitoring
```

### User Roles

| Role | Access | Description |
|------|--------|-------------|
| **Individual** | Full | Personal device protection |
| **Organization Admin** | Full + Users | Manage team, devices, settings |
| **Staff** | Read + Limited Write | View alerts, respond to incidents |
| **Viewer** | Read Only | Dashboard monitoring |

---

## 🛡️ What It Does

### SIEM — Security Information & Event Management

- **40+ ingestion sources**: Syslog (UDP/TCP), REST API, file watcher, Suricata IDS, host agents
- **Real-time pipeline**: Ingest → Normalize → Enrich → Detect → Alert
- **50+ detection rules** + 17 protection modules + WAF (SQLi, XSS, CMDi, LFI, SSRF, LDAPi)
- **18 Prometheus alert rules** for infrastructure monitoring
- **Correlation engine** for multi-stage attack chains

### SOAR — Security Orchestration, Automation & Response

- **Policy-driven playbooks**: Alerts → Response actions → Dispatch
- **Built-in actions**: Webhook, firewall block (iptables/nftables/netsh), device isolation
- **WebSocket push** for real-time alert streaming
- **AI investigation** for automated threat analysis

### EDR — Endpoint Detection & Response

- **Windows agent**: Processes, files, downloads, USB, PowerShell, registry, services, security event logs
- **Linux agent**: USB monitoring, keyloggers, FIM, memory YARA scanning, stego, rootkits, cryptojacking
- **Kernel-level drivers** for both platforms (`cybernova-driver/`)

---

## 🎯 Attack Coverage (658+ Detection Rules)

CyberNova defends against **658+ attack types** across network, web, host, cloud, and data layers. See [SECURITY.md](SECURITY.md) for the complete breakdown.

| Layer | Rules | Coverage |
|-------|-------|----------|
| **WAF** | 189 | SQLi, XSS, CMDi, path traversal, SSRF, SSTI, request smuggling, protocol injection, LDAPi, NoSQLi |
| **Sigma (MITRE ATT&CK)** | 441 | Defense evasion, persistence, credential access, C2, initial access, execution, privilege escalation, lateral movement, impact, collection, exfiltration |
| **Correlation** | 6+ | Multi-stage attack chains (recon → exploit, malware → C2, credential theft → lateral) |
| **DLP** | 22 | AWS/GCP/Azure keys, SSH/PGP keys, JWT tokens, credit cards, SSNs, connection strings |
| **Shields** | 17 | Network, app, process, system, user, data, resource, self-heal, webshell, rootkit, tamper, cryptojacking, brute force, phishing |

### Top Attack Types Blocked

| Category | Examples |
|----------|----------|
| **Web** | SQLi (21 patterns), XSS (46 patterns), CMDi (37 patterns), SSRF, SSTI (Jinja2/Velocity/ERB), request smuggling |
| **Network** | Port scanning, DNS tunneling, C2 beaconing, ICMP tunneling, DGA domains, encrypted C2 |
| **Host** | Ransomware (Conti/LockBit/BlackCat), rootkits, cryptominers, credential dumping (mimikatz), keyloggers |
| **Auth** | Brute force, password spraying, credential stuffing, pass-the-hash, Kerberoasting |
| **Cloud** | K8s secrets access, pod exec, RBAC escalation, cloud metadata abuse |
| **Data** | DLP violations (22 patterns), bulk exfiltration, registry tampering, shadow copy deletion |

---

## 🏗️ Architecture

### Services

| Service | Port | Role |
|---------|------|------|
| `backend` | 8000 | FastAPI + pipeline orchestrator |
| `frontend` | 80 (internal) | React dashboard (Vite) |
| `postgres` | 5432 | Events, alerts, incidents |
| `redis` | 6379 | Streams, cache, pub/sub |
| `nginx` | 8080/443 | Reverse proxy, TLS, rate limiting |
| `pipeline-worker` | — | Redis Streams consumer |
| `prometheus` | 9090 | Metrics collection |
| `grafana` | 3001 | Dashboards & visualization |
| `alertmanager` | 9093 | Alert routing |
| `suricata` | — | Network IDS (optional) |

### Event Flow

```
Agent/Source → Ingestion → Normalization → Enrichment → Detection → Correlation → Alert → SOAR
                                                                                      ↓
                                                                              WebSocket → Dashboard
```

---

## 📡 API

Full OpenAPI docs at `http://localhost:8000/docs`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | JWT login |
| `/api/v1/setup/admin` | POST | Create first admin |
| `/api/v1/ingest/event` | POST | Ingest event |
| `/api/v1/ingest/agent` | POST | Agent event ingestion |
| `/api/v1/dashboard/summary` | GET | Dashboard summary |
| `/api/v1/devices` | GET | List devices |
| `/api/v1/alerts` | GET | List alerts |
| `/ws` | WS | Real-time updates |

---

## 🔌 Integrations (13+)

Slack · Teams · PagerDuty · Jira · Splunk · MISP · TheHive · OpenCTI · VirusTotal · AbuseIPDB · AlienVault OTX · MaxMind GeoIP

All integrations **gracefully degrade** when unconfigured.

---

## 🧪 Testing

886+ automated test functions across unit, integration, e2e, security, and chaos suites.

```bash
# Unit tests
python -m pytest tests/unit/ -v

# Integration tests
python -m pytest tests/integration/ -v

# E2E tests
python -m pytest tests/e2e/ -v

# Security tests
python -m pytest tests/security/ -v

# Chaos tests
python -m pytest tests/chaos/ -v

# Frontend tests + typecheck
cd cybernova-frontend && npm test && npx tsc --noEmit
```

---

## 📊 Monitoring & Observability

- **Prometheus** metrics at `/metrics` — pipeline throughput, latency, error rates
- **Grafana** dashboards — auto-provisioned with pre-built panels
- **Alertmanager** — email, Slack, webhook routing
- **SLA metrics** — P50/P90/P99 latency, availability, queue depths
- **OpenTelemetry tracing** across the pipeline
- **Chaos-tested** resilience (network partitions, leader election, pipeline failures)

---

## 📁 Project Structure

```
cybernova/
├── cybernova/              # Python backend (FastAPI)
│   ├── api/                # REST API routes
│   ├── auth/               # Authentication & RBAC
│   ├── detection/          # Detection engine & rules
│   ├── pipeline/           # Event processing pipeline
│   ├── response/           # SOAR response actions
│   ├── protection/         # WAF, shields, defense modules
│   ├── ingestion/          # Event ingestion (syslog, agents)
│   └── monitoring/         # Health, metrics, tracing
├── cybernova-frontend/     # React dashboard (Vite + Tailwind)
├── web-page/               # Marketing site (Next.js)
├── cybernova-driver/       # Kernel modules (Linux/Windows)
├── tests/                  # 886+ tests (unit, integration, e2e, security, chaos)
├── scripts/                # Deployment & utility scripts
├── monitoring/             # Prometheus, Grafana configs
├── nginx/                  # Reverse proxy configs
├── helm/                   # Kubernetes Helm chart
└── docker-compose.yml      # Full stack orchestration
```

---

## 📚 Documentation

| Doc | Purpose |
|-----|---------|
| [SECURITY.md](SECURITY.md) | Attack coverage & security posture |
| [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) | Production deployment checklist |
| [DEPLOYMENT_RUNBOOK.md](DEPLOYMENT_RUNBOOK.md) | Deployment runbook |
| [docs/DEVELOPER_REFERENCE.md](docs/DEVELOPER_REFERENCE.md) | Developer guide |
| [docs/RUNBOOKS.md](docs/RUNBOOKS.md) | Operational runbooks |
| [docs/PRODUCT_ROADMAP.md](docs/PRODUCT_ROADMAP.md) | Roadmap |
| [helm/](helm/) | Kubernetes deployment |

---

## 🤝 Contributing

We welcome contributions from the security community!

1. Fork the repo (`https://github.com/Passionate-pop/CyberNova-SIEM-SOAR`)
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure your changes pass the test suite before opening a PR:

```bash
python -m pytest tests/unit -v
cd cybernova-frontend && npx tsc --noEmit
```

---

## 🛡️ Security

Found a vulnerability? Please do **not** open a public issue. Report it responsibly via the [SECURITY.md](SECURITY.md) process.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⭐ Show Your Support

If CyberNova helps you, please give the repo a ⭐ — it helps the project grow and reach more defenders. 🙌

---

<div align="center">

**Built with ❤️ for the security community.**

[Report a Bug](https://github.com/Passionate-pop/CyberNova-SIEM-SOAR/issues) · [Request a Feature](https://github.com/Passionate-pop/CyberNova-SIEM-SOAR/issues) · [Star the Repo](https://github.com/Passionate-pop/CyberNova-SIEM-SOAR)

</div>
