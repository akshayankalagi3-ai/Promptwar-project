# BeSafe 🛡️ - Scam & Malicious URL Scanner

> **Explainable Scam Threat Index (0–100%)** | **50% Automated Security Heuristics + 50% Crowdsourced Consensus** | **Multi-Engine Intelligence** | **Bulk Link Auditor** | **Strict SSRF Defense**

---

## 📌 Overview

**BeSafe** is an advanced link safety and anti-scam intelligence platform engineered to protect users and organizations from phishing campaigns, credential-harvesting clones, fake job scams, fraudulent shopping portals, and crypto drainers.

Unlike legacy URL scanners that behave as opaque black boxes or rely solely on slow-updating central blocklists, BeSafe combines:
1. **Explainable Automated Security Heuristics (50% max weight)**: Instant algorithmic detection of brand typosquatting, raw IP hosts, credential-harvesting keywords, disposable TLDs, and subdomain truncation tricks.
2. **Logarithmically-Damped Community Consensus (50% max weight)**: Crowdsourced reporting calibrated with exponential saturation and salted SHA-256 IP deduplication to prevent bot manipulation and retaliatory report spam.
3. **Multi-Source Threat Cross-Referencing**: Comparative analysis across Google Safe Browsing, VirusTotal, urlscan.io, and BeSafe Local Heuristics.
4. **Google GenAI Search Grounding**: Live intelligence retrieval querying real-time cybersecurity advisories (APWG, AbuseIPDB, ICANN WHOIS, Cisco Talos) with verifiable source citations.
5. **Batch Link Inspection**: Bulk auditor allowing security teams and users to paste hundreds of links or drag-and-drop `.csv`, `.json`, or `.txt` files for rapid triage.
6. **Strict Server-Side Request Forgery (SSRF) Defense**: Pre-flight network validation blocking requests targeting private networks, loopbacks, or cloud metadata endpoints.

---

## ✨ Key Features

### 1. Dynamic Animated Circular Threat Gauge (0–100%)
- **Real-Time Visual Sweep**: SVG circular gauge powered by standard CSS keyframe animations with cubic-bezier easing.
- **Color-Coded Risk Levels**:
  - 🟢 **Safe (0–30%)**: Emerald Green gradient (`#10b981` to `#059669`) with subtle aura and ShieldCheck badge.
  - 🟡 **Suspicious (31–69%)**: Warm Amber gradient (`#f59e0b` to `#d97706`) with caution halo and AlertTriangle badge.
  - 🔴 **High Risk / Scam (70–100%)**: Crimson Red gradient (`#ef4444` to `#dc2626`) with pulsing alert glow and ShieldAlert badge.
- **Dynamic Numeric Counter**: Smoothly animates the numerical percentage counter in sync with the circular arc progression.
- **Precision Instrument Styling**: Includes perimeter tick marks, an inner track border, and a glowing endpoint tip marker.

### 2. Multi-Source Intelligence & Search Grounding
- **Security Engines Comparison**: Evaluates and displays consensus states from Google Safe Browsing, VirusTotal, urlscan.io, and BeSafe Local Engine.
- **Search-Grounded Threat Intel**: Automatically fetches external threat reports and intelligence summaries with direct citations to reputable security feeds (ICANN WHOIS, AbuseIPDB, APWG).

### 3. Bulk / Batch Link Scanner
- **Multi-Format Ingestion**: Supports `.txt` (one URL per line), `.csv` (URL columns), `.json` (arrays/objects), and direct multi-line text input.
- **High-Throughput Concurrent Processing**: Inspects batches with configurable concurrency, real-time progress bars, and execution time tracking.
- **Risk Categorization & Filtering**: Filter batch results by *All*, *Safe*, *Suspicious*, or *High Risk*.
- **Exportable Audit Reports**: Export batch inspection findings directly to JSON or CSV for security compliance logs.

### 4. Crowdsourced Intelligence & Anti-Spam Protection
- **Community Threat Feed**: Real-time stream of user-reported scam links categorized by type (Phishing, Impersonation, Crypto Scam, Fake Job, Malware).
- **Salted IP Deduplication**: Reports are hashed server-side using `SHA256(ClientIP + SecretSalt)`. Repeated submissions from the same connection for the same target are rejected with `409 Conflict`.
- **Logarithmic Saturation Curve**: Prevents single-user reporting from skewing ratings while allowing genuine crowd consensus to scale safely.

### 5. Interactive Time-Series Analytics & Heuristics
- **Interactive D3 Time-Series Chart**: Displays total scan volume alongside threats blocked over time.
- **Transparent Formula Breakdown**: Documents the exact algorithmic point system and consensus curve directly within the UI.
- **Analyst Override Controls**: Authoritative operators can set `VERIFIED_SAFE`, `CONFIRMED_SCAM`, or reset overrides back to algorithmic scoring.

---

## 🧮 Explainable Scoring Formula

The **Total Scam Threat Index** is calculated as:

$$\text{Threat Index} = \min\left(100, \text{SecurityScore}_{(0-50)} + \text{CommunityScore}_{(0-50)}\right)$$

### 1. Automated Security Signals (50% Maximum Weight)

| Heuristic Signal | Points | Detection Rationale |
|---|---|---|
| **Raw IP Host** | `+20 pts` | Direct IPv4 address used in place of a registered domain (e.g. `http://198.51.100.23`), frequently employed to bypass DNS-level security filters. |
| **Brand Impersonation & Typosquatting** | `+25 – 28 pts` | Token matching and Levenshtein string distance against monitored brands (Google, Microsoft, PayPal, Apple, Amazon, Chase, etc.). Flags deceptive domains like `google-security-portal.com` or `micros0ft.com`. |
| **Credential Harvesting Keywords** | `+8 – 18 pts` | Inspects path and query parameters for phishing triggers: `login`, `verify`, `kyc`, `banking`, `wallet`, `claim`, `telegram-task`. |
| **High-Risk TLD & Disposable Profile** | `+15 pts` | Flags cheap or disposable TLDs (`.xyz`, `.top`, `.shop`, `.buzz`) paired with security lure keywords. |
| **Subdomain Truncation Tricks** | `+8 pts` | Identifies deep subdomain nesting (3+ levels) designed to disguise malicious hostnames on mobile screens. |

### 2. Community Consensus Saturation Curve (50% Maximum Weight)

To prevent a single bad actor from falsely marking a website as a scam, community reports are mapped along an exponential saturation curve:

$$\text{CommunityScore} = \min\left(50, \text{round}\left(50 \times \left(1 - e^{-\frac{N}{3.0}}\right)\right)\right)$$

*Where $N$ is the number of distinct, verified reports from unique salted IP hashes.*

- **1 Report**: $\approx 14 \text{ pts}$ (Preserves domain in low-risk range, preventing rogue single reports from causing false alarms).
- **2 Reports**: $\approx 24 \text{ pts}$ (Approaches the suspicious threshold).
- **3 Reports**: $\approx 32 \text{ pts}$ (Confirms crowd agreement).
- **5 Reports**: $\approx 41 \text{ pts}$ (Triggers elevated threat warning).
- **8+ Reports**: $\approx 48 - 50 \text{ pts}$ (Saturates at the maximum 50% community ceiling).

---

## 🛡️ Server-Side Request Forgery (SSRF) Defense

To prevent malicious actors from using the scanner as a proxy to attack internal infrastructure, all target URLs undergo pre-flight inspection before any network interaction:

1. **Loopback Boundaries**: Rejects `127.0.0.0/8`, `localhost`, `0.0.0.0`, and IPv6 `::1`.
2. **Cloud Metadata Endpoints**: Strictly blocks link-local addresses including `169.254.169.254` (AWS, GCP, Azure metadata services).
3. **Private Subnets (RFC 1918)**: Blocks `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
4. **Allowed Protocols**: Restricts requests strictly to `http://` and `https://`. Protocol schemes such as `file://`, `ftp://`, `gopher://`, or `data:` are rejected with `400 Bad Request`.

---

## 🏗️ Project Architecture

```
besafe/
├── backend/                             # Standalone Python FastAPI + SQLite implementation
│   ├── main.py                          # FastAPI application with REST endpoints & SSRF guard
│   ├── database.py                      # SQLite database schema, connection, and seeding
│   ├── scanner.py                       # Python security heuristics and scoring engine
│   └── requirements.txt                 # Python dependencies (fastapi, uvicorn, pydantic)
├── server/                              # Node.js / Express backend service modules
│   ├── scanner.ts                       # TypeScript Security Signals & SSRF validator
│   └── store.ts                         # In-memory and persisted threat data store
├── src/                                 # Frontend Single-Page Application (React 19 + Vite)
│   ├── components/
│   │   ├── TopBar.tsx                   # Header navigation, live stats ticker, tab switcher
│   │   ├── ScannerTab.tsx               # Primary single-URL inspection interface
│   │   ├── ThreatGauge.tsx              # Dynamic animated circular threat gauge (0-100%)
│   │   ├── SecuritySourcesComparisonCard.tsx # Multi-engine security comparison card
│   │   ├── SearchGroundingIntelCard.tsx # Google GenAI search-grounded threat intelligence
│   │   ├── BatchLinkScanner.tsx         # Bulk link scanner with file import and export
│   │   ├── ReportTab.tsx                # Scam submission form with anti-spam deduplication
│   │   ├── CommunityFeedTab.tsx         # Crowdsourced scam feed with search and filters
│   │   ├── ArchitectureTab.tsx          # D3 scan velocity chart & algorithmic documentation
│   │   ├── ScansHistoryChart.tsx        # D3-rendered interactive time-series chart
│   │   ├── SearchHistoryPanel.tsx       # Local storage-backed recent scans history drawer
│   │   └── LinkVerificationAuditCard.tsx # Multi-point verification checklist component
│   ├── types.ts                         # Shared TypeScript interfaces and enums
│   ├── App.tsx                          # Root application orchestrator and state coordinator
│   ├── main.tsx                         # Client application bootstrap
│   └── index.css                        # Tailwind CSS styles and global rules
├── data/                                # Local persistence data directory
│   └── store.json                       # Seeded and cached scanner records
├── server.ts                            # Full-stack Express server + Vite middleware (Port 3000)
├── package.json                         # Project dependencies and execution scripts
├── tsconfig.json                        # TypeScript compiler configuration
├── vite.config.ts                       # Vite build and plugin configuration
├── metadata.json                        # AI Studio applet metadata and capabilities
└── README.md                            # Comprehensive project documentation
```

---

## 📡 REST API Reference

All backend endpoints are served under `/api/*`:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Analyzes a single URL, performs SSRF verification, returns 0–100% Threat Index and audit breakdown. |
| `POST` | `/api/scan-batch` | Bulk scans up to 50 URLs concurrently with individual audit flags and batch summaries. |
| `POST` | `/api/intel/search-grounding` | Queries external threat feeds and search-grounded intelligence for live reputation evidence. |
| `POST` | `/api/report` | Submits a community scam report with category tagging and salted IP anti-spam deduplication. |
| `GET` | `/api/feed` | Retrieves recent crowdsourced scam reports with category filtering. |
| `GET` | `/api/stats` | Returns real-time aggregate counters (total scanned, community reports, threats caught, verified safe). |
| `GET` | `/api/stats/history` | Delivers time-series scan activity data for the interactive D3 chart. |
| `POST` | `/api/admin/override` | Sets analyst overrides (`VERIFIED_SAFE`, `CONFIRMED_SCAM`, or `RESET`). |
| `GET` | `/api/demo-urls` | Supplies curated demonstration targets for quick evaluation. |
| `GET` | `/api/health` | Service health check returning uptime and status. |

---

## 🚀 Getting Started

### Prerequisites
- Node.js 20+ installed
- npm or bun package manager
- (Optional) Python 3.10+ for the standalone FastAPI backend

### Full-Stack Application (Node.js + React + Express)

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Start the development server**:
   ```bash
   npm run dev
   ```
   *The application starts on [http://localhost:3000](http://localhost:3000) with both Express API routes and Vite frontend.*

3. **Build for production**:
   ```bash
   npm run build
   ```

4. **Run production server**:
   ```bash
   npm start
   ```

---

### Standalone Python FastAPI Backend (Alternative)

If you wish to run the Python backend implementation with SQLite:

1. **Navigate to the backend directory**:
   ```bash
   cd backend
   ```

2. **Install requirements**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the FastAPI service**:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

4. **View interactive OpenAPI Swagger docs**:
   Visit [http://localhost:8000/docs](http://localhost:8000/docs) in your browser.

---

## 🧪 Quick Demonstration Targets

To test BeSafe's capabilities, try these sample inputs:

| Target URL | Expected Verdict | Primary Triggers |
|---|---|---|
| `http://google-security-portal.com/auth/login` | 🔴 **High Risk (80–90%)** | Brand clone ("Google"), phishing keywords (`login`, `auth`), community complaints |
| `https://github.com` | 🟢 **Safe (0%)** | Established enterprise domain, clean reputation, zero risk markers |
| `http://198.51.100.23/update-account` | 🔴 **High Risk (70–80%)** | Bare IPv4 host, credential harvesting path |
| `http://169.254.169.254/latest/meta-data/` | 🛡️ **Blocked (HTTP 400)** | SSRF prevention: Cloud metadata / link-local endpoint prohibited |
| `http://127.0.0.1:8080/admin` | 🛡️ **Blocked (HTTP 400)** | SSRF prevention: Loopback address prohibited |

---

## 🔒 Security & Privacy Practices

- **Zero Client Key Exposure**: All intelligence lookups and server-side operations are conducted behind secure `/api/*` proxies.
- **Privacy-Preserving IP Hashing**: Reporter IP addresses are transformed via one-way salted SHA-256 hashes to protect user anonymity while enforcing rate limits and anti-spam controls.
- **Robust Failover**: If external intelligence APIs are unreachable or unconfigured, the system automatically falls back gracefully to local deterministic heuristics without throwing unhandled exceptions.
