# WebScan

**Defensive vulnerability checking web app for websites and AI endpoints.**

---
<img width="1351" height="885" alt="image" src="https://github.com/user-attachments/assets/a6ba38c7-d4a6-4dbb-98f2-1a43a3eba079" />

---
## Quick start

```bash
# 1. Install
cd webscan
pip install -e ".[dev]"

# 2. Configure
cp .env.example .env
# Edit .env as needed

# 3. Run
python -m ui.app
# Open http://localhost:8080
```

## Docker

```bash
# Standard (no LLM agents)
docker compose up webscan

# With optional Ollama LLM agents
docker compose --profile agents up
# Then pull a model: docker exec -it ollama ollama pull llama3
```

## Run tests

```bash
cd webscan
pytest                          # fast unit + integration tests
pytest --run-live               # also run tests requiring network access
pytest -m "not slow"            # skip slow tests
pytest --cov=. --cov-report=html
```

## Project structure

```
webscan/
├── config/          # Settings, defaults, logging
├── core/            # Models, interfaces, orchestrator, SSRF guard, deduplication
├── api/             # FastAPI app, routers, rate-limiter middleware
├── checks/
│   ├── website/     # 10 website security checks
│   └── ai_endpoint/ # 10 AI endpoint security checks
├── reporter/        # JSON, PDF (ReportLab), SARIF reporters
├── ui/              # NiceGUI pages and Plotly components
├── agents/          # Optional SLM-backed enrichment agents (Ollama)
└── tests/           # pytest unit + integration tests
```

## Safety design

| Layer | Mechanism |
|-------|-----------|
| Consent gate | `i_own_or_have_written_permission` must be `true` |
| SSRF guard | RFC-1918, loopback, link-local, cloud IMDS blocked |
| Allowlist | Optional `ALLOWED_TARGETS_REGEX` env var |
| Rate limiter | 20 req/min global; 5 scans/5 min per IP |
| Audit log | Append-only JSONL with fsync |
| Read-only FS | Docker container runs with `read_only: true` |
| Non-root | UID 1000 inside container |
| HTTP methods | Only `HEAD` and `GET` used (never `POST` to target) |

## Suppression

Edit `suppression.yaml` to suppress known-acceptable findings from reports.
See the file for the full format with examples.

## Optional LLM agents

Set `ENABLE_SLM_AGENTS=true` and configure `OLLAMA_BASE_URL` + `SLM_MODEL`.
Agents enrich findings with OWASP LLM Top 10 / MITRE ATLAS tags and draft
an executive summary — they never trigger additional network requests to the
scan target.
"# website_scan" 
