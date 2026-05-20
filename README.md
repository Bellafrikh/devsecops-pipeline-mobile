# Mobile DevSecOps Platform

A custom CI/CD security pipeline platform for Android apps — inspired by Jenkins Blue Ocean, built from scratch.

## 🚀 Quick Start

### 1. Clone & Configure
```bash
cd /home/iilhamm/Desktop/mobile
cp .env.example .env
# Edit .env if needed (MobSF API key, AI provider)
```

### 2. Start the Full Stack
```bash
docker-compose up -d
```

Services started:
| Service | URL |
|---|---|
| **Dashboard** | http://localhost:80 |
| **Backend API** | http://localhost:8000 |
| **MobSF** | http://localhost:8001 |
| **Ollama** | http://localhost:11434 |

### 3. Pull Ollama Model (AI Triage)
```bash
docker exec devsecops-ollama ollama pull llama3
```

### 4. Get MobSF API Key
```bash
# Open http://localhost:8001 → login (mobsf/mobsf)
# Go to Settings → API Key → copy it to .env: MOBSF_API_KEY=...
docker-compose restart backend
```

### 5. Run Your First Scan
Open http://localhost:80 → **New Scan** → paste any Android GitHub URL

---

## 🛠️ Development Mode (no Docker)

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev   # → http://localhost:5173
```

> **Note:** MobSF and Ollama still need Docker. Run just those services:
> ```bash
> docker-compose up mobsf ollama -d
> ```

---

## 🔬 Pipeline Stages

| # | Stage | Tool | Output |
|---|---|---|---|
| 1 | **Fetch & Build** | git + gradle | `app.apk` |
| 2 | **MobSF SAST** | MobSF REST API | `mobsf_report.json` |
| 3 | **SBOM** | Syft (CycloneDX) | `sbom.json` |
| 4 | **CVE Scan** | Grype | `vuln-report.json` |
| 5 | **SecretHunter** | Custom (regex + entropy) | `secrets_report.json` |
| 6 | **CryptoLint** | Custom (10 rules) | `crypto_report.json` |
| 7 | **Policy Gate** | YAML policy engine | `PASS/FAIL/WARN` |
| 8 | **AI Triage** | Ollama/OpenAI | Tickets + Release Notes |

---

## 📋 Policy-as-Code

Each project can have its own YAML policy. Edit via the UI at `/policy` or directly:

```yaml
thresholds:
  critical: 0      # 0 = any critical blocks the pipeline
  high: 5
  medium: 20

scanners:
  secret_hunter:
    block_on_any_secret: true   # Any secret = pipeline FAIL
  crypto_lint:
    severity: warn              # Weak crypto = warning only
```

---

## 🤖 AI Triage

- **Provider**: Ollama (local, free) by default
- **Deduplication**: removes duplicate findings
- **Grouping**: clusters findings by root cause (Weak Crypto, Insecure Storage, etc.)
- **Tickets**: auto-generated with title, description, remediation, CWE
- **Release Notes**: executive "go/no-go" security summary

To use OpenAI instead:
```bash
# .env
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
```
