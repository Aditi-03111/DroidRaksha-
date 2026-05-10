# DroidRaksha 🛡️

**India's AI-Powered APK Threat Intelligence Platform**

DroidRaksha is an advanced, high-performance static analysis platform designed to detect Android malware, specifically tailored for the Indian cybersecurity landscape. It identifies banking trojans, UPI fraud apps, loan scams, and other mobile threats through a multi-engine analysis pipeline, leveraging YARA rules, heuristics, and AI-driven narrative generation.

## 🏗️ Architecture

DroidRaksha (Round 2) employs a scalable, microservices-based architecture designed for distributed threat analysis:

```mermaid
graph TD
    subgraph Clients ["Clients & Gateway"]
        UI[Next.js 14 Web Dashboard]
        Mobile[React Native Android App]
        Nginx[Nginx Reverse Proxy & Load Balancer]
        UI -->|HTTPS / WSS| Nginx
        Mobile -->|HTTPS| Nginx
    end

    subgraph Orchestration ["Backend & Orchestration"]
        FastAPI[FastAPI Gateway]
        RedisQueue[(Redis Cache & Queue)]
        Celery[Celery Workers]
        Nginx -->|REST / WebSocket| FastAPI
        FastAPI -->|Enqueue Jobs| RedisQueue
        RedisQueue --> Celery
    end

    subgraph Static ["Static Analysis"]
        Androguard[Androguard & APKTool]
        YARA[YARA Engine 50+ Rules]
        Obfuscation[Obfuscation & Heuristics]
        Celery --> Androguard
        Celery --> YARA
        Celery --> Obfuscation
    end

    subgraph Dynamic ["Dynamic Sandbox"]
        MobSF[MobSF + Docker]
        Frida[Frida Runtime Hooks]
        Network[PCAP & mitmproxy]
        Celery --> MobSF
        MobSF --> Frida
        MobSF --> Network
    end

    subgraph ThreatIntel ["C2 & Threat Intel"]
        IndiaIOC[India IOC DB]
        Behavior[DGA / JA3 / Beacon]
        ExtAPI[VT / AbuseIPDB / OTX]
        Claude[Claude AI + ML Classifier]
        Celery --> IndiaIOC
        Celery --> Behavior
        Celery --> ExtAPI
        Celery --> Claude
    end

    subgraph DataLayer ["Data Layer"]
        RDS[(AWS RDS PostgreSQL)]
        Mongo[(MongoDB Atlas)]
        Elastic[(Elasticsearch)]
        S3[(AWS S3 Storage)]
        Celery --> |Relational| RDS
        Celery --> |Raw JSON| Mongo
        Celery --> |Campaigns| Elastic
        FastAPI --> |APK & PCAP| S3
        Celery --> |Artifacts| S3
    end

    classDef client fill:#1e40af,stroke:#fff,stroke-width:2px,color:#fff;
    classDef orchestration fill:#047857,stroke:#fff,stroke-width:2px,color:#fff;
    classDef static fill:#b45309,stroke:#fff,stroke-width:2px,color:#fff;
    classDef dynamic fill:#dc2626,stroke:#fff,stroke-width:2px,color:#fff;
    classDef intel fill:#6d28d9,stroke:#fff,stroke-width:2px,color:#fff;
    classDef data fill:#334155,stroke:#fff,stroke-width:2px,color:#fff;

    class UI,Mobile,Nginx client;
    class FastAPI,RedisQueue,Celery orchestration;
    class Androguard,YARA,Obfuscation static;
    class MobSF,Frida,Network dynamic;
    class IndiaIOC,Behavior,ExtAPI,Claude intel;
    class RDS,Mongo,Elastic,S3 data;
```

## 🛠️ Tech Stack & Technical Decisions (Round 2)

DroidRaksha is built using a modern, scalable, and distributed technology stack, designed to handle intensive static and dynamic analysis workloads securely.

### 💻 Client & Gateway
- **Frontend:** Next.js 14 (App Router) + TypeScript, styled with Tailwind CSS and shadcn/ui. Includes interactive network graphs using D3.js.
- **Mobile App:** React Native application for Android users.
- **Gateway & Real-time:** Nginx reverse proxy with WebSockets for true live analysis progress tracking.

### ⚙️ Backend Orchestration
- **API Framework:** FastAPI (Python) for fully asynchronous endpoint handling.
- **Job Queue:** Celery with Redis as the message broker, offloading heavy static and dynamic analysis to distributed workers.
- **Caching:** Redis for fast state lookups and WebSocket state management.

### 🔍 Core Analysis & Sandbox Engines
- **Static Analysis:** Androguard, APKTool, and an extensive YARA engine (50+ comprehensive rules).
- **Dynamic Analysis:** Dockerized MobSF sandbox environment.
- **Runtime Monitoring:** Frida for API/file I/O hooking and `tcpdump`/`mitmproxy` for full PCAP network analysis.

### 🧠 Threat Intelligence & C2 Detection
- **AI & ML:** Anthropic Claude API for narrative generation with confidence scoring, paired with a custom ML classifier for malware families.
- **External Intel:** Integration with VirusTotal (Hash/URL/IP), AbuseIPDB, and AlienVault OTX.
- **Advanced C2 Detection:** Algorithms for detecting DGA (Domain Generation Algorithms) via Shannon entropy, TLS JA3 fingerprint matching, and timing variance analysis for live beacon detection.
- **India IOC Engine:** A fully managed database with an admin API for updating known fake UPI apps, fraudulent loan domains, and malicious Indian IPs.

### 🗄️ Distributed Data Layer
- **Relational DB:** AWS RDS (PostgreSQL) for metadata and structured threat metrics.
- **Document DB:** MongoDB Atlas for storing raw, unstructured JSON analysis results.
- **Search Engine:** Elasticsearch for rapid IOC searching and threat campaign clustering.
- **Storage:** AWS S3 for secure, scalable storage of raw APKs, PCAP dumps, and branded forensic PDF reports.

### 🚀 Infrastructure & DevOps
- **Deployment:** Docker Compose migrating to Kubernetes on AWS EC2.
- **CI/CD & Monitoring:** Automated deployment via GitHub Actions with Sentry and Grafana for error tracking and metrics monitoring.
- **Sharing:** Threat intelligence sharing via STIX 2.1 / TAXII exports and a rate-limited Bulk REST API.

## 🏁 Demo Round vs Final Round (Diff)

Here is a detailed breakdown of what we are building for the Hackathon Demo (Round 1) versus the Full Platform Vision (Round 2):

| Category | Technology | Round 1 (Demo Prototype) | Round 2 (Full Platform) | Change |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend** | | | | |
| Framework | Next.js 14 | App Router + TypeScript | Same + more pages | Keep |
| Styling | Tailwind + shadcn/ui | Full design system | Same | Keep |
| Charts | D3.js | Not included | Network graph + campaign map | New |
| Real-time | WebSocket | Polling every 2s (simple) | True WebSocket live progress | Upgrade |
| Mobile app | React Native | Not built | Full Android app | New |
| Deploy | Vercel | Free tier | Same (or pro if needed) | Keep |
| **Backend** | | | | |
| Framework | FastAPI | Sync (no queue) | Fully async + Celery workers | Upgrade |
| Job queue | Celery + Redis | Not used — runs inline | Full background job queue | New |
| Cache | Redis | Not used | Caching + WebSocket state | New |
| Gateway | Nginx | Not used | Reverse proxy + rate limiting | New |
| Deploy | Railway → AWS EC2 | Railway free tier | AWS EC2 t3.large | Upgrade |
| **Analysis Engines** | | | | |
| Static | Androguard + JADX | Full — androguard + YARA | Same + APKTool + deeper DEX | Upgrade |
| Dynamic | MobSF + Docker | Not built | Full Docker sandbox | New |
| Runtime hooks | Frida + strace | Not built | API call + file I/O tracing | New |
| Network capture | tcpdump + mitmproxy | Not built | Full PCAP analysis | New |
| YARA rules | yara-python | 12 rules (basic) | 50+ rules (comprehensive) | Upgrade |
| **C2 Detection** | | | | |
| String-based | Regex + IOC DB | Hardcoded IPs + domains | Same + live beacon detection | Upgrade |
| Beacon detect | Custom algorithm | Not built | Timing variance analysis | New |
| DGA detect | Entropy analysis | Not built | Shannon entropy + n-gram | New |
| TLS fingerprint| JA3 | Not built | JA3 hash matching | New |
| **Threat Intelligence** | | | | |
| VirusTotal | VT API v3 | Hash lookup only | Hash + URL + IP lookup | Upgrade |
| AbuseIPDB | AbuseIPDB API | Basic IP check | Same | Keep |
| AlienVault OTX | OTX API | Not used | Full IOC enrichment | New |
| India IOC DB | Custom | Hardcoded list (~50 entries) | Full DB + admin update API | Upgrade |
| MITRE ATT&CK | Custom mapper | Basic mapping (10 techniques)| Full matrix mapping | Upgrade |
| **AI Layer** | | | | |
| Narrative | Claude API | Single threat summary | Same + confidence scoring | Upgrade |
| Classification | ML model | Not built | Malware family classifier | New |
| **Database** | | | | |
| Primary DB | PostgreSQL | SQLite (local/demo) | AWS RDS (production) | Upgrade |
| Document DB | MongoDB | Not used (JSONB instead) | MongoDB Atlas — raw results | New |
| Cache / Queue | Redis | Not used | Upstash / AWS ElastiCache | New |
| Search | Elasticsearch | Not used | IOC search + clustering | New |
| **Storage** | | | | |
| File storage | S3 / MinIO | Local /tmp folder | AWS S3 (APK + PCAP + PDFs) | Upgrade |
| **Infrastructure** | | | | |
| Containers | Docker | Not used | Docker Compose → Kubernetes | New |
| CI/CD | GitHub Actions | Not set up | Auto deploy on push | New |
| Monitoring | Sentry / Grafana | Not set up | Error tracking + metrics | New |
| **Exports & Sharing**| | | | |
| PDF report | WeasyPrint | Basic PDF | Branded forensic PDF | Upgrade |
| Threat sharing | STIX 2.1 | Not built | STIX/TAXII export | New |
| Bulk API | REST API | Not built | API key + rate limiting | New |
| Public report | Next.js SSR | Basic shareable URL | OG tags + WhatsApp preview | Upgrade |

## 🗺️ Roadmap & Task Status

### Phase 1: Project Scaffold
- [x] Create project directory structure
- [x] `requirements.txt`
- [x] `.env.example`
- [x] `README.md`

### Phase 2: Backend — Core
- [x] `backend/models/schemas.py` (Pydantic models)
- [x] `backend/db/database.py` (SQLite + SQLAlchemy)
- [x] YARA rules: `rules/malware.yar`
- [x] YARA rules: `rules/india_patterns.yar`

### Phase 3: Backend — Analysis Engines
- [x] `backend/engines/manifest_parser.py`
- [x] `backend/engines/string_extractor.py`
- [x] `backend/engines/cert_analyzer.py`
- [x] `backend/engines/yara_scanner.py`
- [x] `backend/engines/obfuscation.py`

### Phase 4: Backend — Intel + AI
- [x] `backend/intel/india_ioc.py`
- [x] `backend/intel/virustotal.py`
- [x] `backend/intel/abuseipdb.py`
- [x] `backend/scoring/risk_scorer.py`
- [x] `backend/ai/narrative.py`
- [x] `backend/engines/static_analyzer.py` (orchestrator)

### Phase 5: Backend — API Routes
- [x] `backend/routes/upload.py`
- [x] `backend/routes/analysis.py`
- [x] `backend/routes/report.py`
- [x] `backend/routes/stats.py`
- [x] `backend/main.py`
- [x] `backend/__init__.py` (and all sub-package init files)

### Phase 6: Frontend — Foundation
- [x] Next.js 14 project init
- [x] Install tailwind and basic configuration
- [x] Install shadcn/ui defaults
- [x] Add basic shadcn components (badge, card, progress, table, tabs)
- [ ] `frontend/app/layout.tsx`
- [ ] `frontend/lib/types.ts`
- [ ] `frontend/lib/api.ts`

### Phase 7: Frontend — Components
- [ ] `frontend/components/DropZone.tsx`
- [ ] `frontend/components/AnalysisLoader.tsx`
- [ ] `frontend/components/RiskScoreCard.tsx`
- [ ] `frontend/components/AIExplanation.tsx`
- [ ] `frontend/components/PermissionTable.tsx`
- [ ] `frontend/components/StringsTable.tsx`
- [ ] `frontend/components/CertificateCard.tsx`
- [ ] `frontend/components/MitreTable.tsx`
- [ ] `frontend/components/ExportButton.tsx`

### Phase 8: Frontend — Pages
- [ ] `frontend/app/page.tsx` (landing + upload)
- [ ] `frontend/app/results/[id]/page.tsx`
- [ ] `frontend/app/report/[hash]/page.tsx` (SSR)

### Phase 9: Verification & Launch
- [ ] Backend startup test
- [ ] Frontend startup test
- [ ] End-to-end upload test
- [ ] Final UI Polish
