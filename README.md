# SAURON ASM

**External Attack Surface Management platform** — discover, monitor and assess everything your organization exposes to the internet, from a single dashboard.

Sauron maps your company's external footprint (domains, subdomains, IPs, open ports, endpoints, technologies, mobile apps, exposed files, admin panels), scans it for vulnerabilities and misconfigurations, tracks how the surface changes over time, and uses an AI layer to cut through the noise.

> 🇪🇸 [Versión en español](README.es.md)

---

## Highlights

- **Company-centric inventory** — everything hangs off a company: root domains, subdomains, IPs, neighbor hosts (reverse-IP co-hosted domains), endpoints, technologies, mobile apps. First-seen / last-seen tracking with real deltas between scans.
- **Multi-source discovery** — crt.sh (incl. O= organization match), Certificate Spotter, Wayback Machine, permutations, grep.app, GitHub, reverse IP, and optional SecurityTrails / OTX / Hunter / HIBP keys.
- **AI-assisted discovery** — an LLM brainstorms likely domains for a company and verifies them (DNS/HTTP) before they enter the inventory; mobile apps found in the App Store / Google Play are classified by the LLM as official / suspicious / unrelated.
- **Review workflow** — suspicious assets (e.g. third-party apps with colliding brand names) can be approved (become officially monitored) or rejected, individually or in bulk.
- **Real scanning tools** — nuclei, subfinder, httpx, katana, naabu and trufflehog ship inside the backend image, alongside ~34 built-in modules: TLS, headers, cookies, email security (SPF/DMARC), exposed files, admin panels, JS secret mining, cloud buckets, API/docs exposure (incl. Postman & GitHub), credential combo leaks, smart fuzzing with curated wordlists + LLM-directed paths, and more.
- **Discovery vs. vulnerability scanning are separate pipelines** — each has its own enable switch and recurrence (daily / weekly / monthly) per domain, per company and globally. Vulnerability scans can skip discovery and only assess inventoried assets.
- **Agent Scan** — an autonomous AI agent that reasons over the deterministic results, picks next steps and narrates what it's doing in real time.
- **Security rating** — Xpanse-style letter grade per domain and per company, with saturation-aware scoring, historical trend charts, and coherent badge/grade caps.
- **Remediation workflow** — persistent findings with fingerprinting (open / accepted / fixed), auto-fixed detection on subsequent full scans, and compliance mapping to NIST CSF, ISO 27001, PCI DSS and CIS Controls.
- **SauronBot** — a cheerful in-app AI assistant (floating chat or full page) that answers questions about companies, assets, scans, dates and findings, with guardrails against prompt injection and secret redaction.
- **Dashboards that match** — the global dashboard and the per-company dashboard are the same component; one is just pre-filtered. Both support date-range comparison (deltas between any two scans).
- **RBAC + edge gate** — users with viewer / operator / admin roles, plus an optional HTTP-Basic network gate with IP whitelist in front of the app login.
- **Notifications** — webhook (Slack/Discord/generic) on new assets, critical findings and grade changes.
- **Proxy pool** — optional outbound IP rotation via proxy file or rotating gateway.
- **i18n** — full English / Spanish UI, switchable at runtime.

## Stack

| Layer    | Tech                                                                 |
|----------|----------------------------------------------------------------------|
| Backend  | FastAPI · Tortoise ORM · PostgreSQL 16 · httpx · asyncio scan queue   |
| Frontend | React 18 · TypeScript · Vite · Tailwind CSS · react-router · recharts |
| Tools    | nuclei · subfinder · httpx · katana · naabu · trufflehog (in-image)  |
| AI       | Any OpenAI-compatible endpoint (Azure AI Foundry, Azure OpenAI, …)   |
| Deploy   | Docker Compose (db + backend + nginx frontend)                        |

## Quick start

```bash
# 1. Configure the backend
cp backend/.env.example backend/.env
#    REQUIRED: set POSTGRES_PASSWORD (also in a root .env for compose),
#    keep AUTH_ENABLED=true — then AI_API_KEY / AI_BASE_URL / AI_MODEL, edge gate, …

# 2. Bring the stack up
docker compose up -d --build

# 3. Open the app
open http://localhost:5173
```

With `AUTH_ENABLED=true` and zero users, the first visit offers **bootstrap**: create the first admin and you're in. Roles can then be managed from **Users**.

### Key environment variables (`backend/.env`)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Postgres DSN (inside compose it's set to the `db` service) |
| `AI_API_KEY` / `AI_BASE_URL` / `AI_MODEL` | LLM endpoint (Azure AI Foundry / Azure OpenAI / any OpenAI-compatible API) |
| `AUTH_ENABLED` | `true` enforces Bearer-token auth with RBAC (**required** for any exposed deployment; `false` is dev-only) |
| `SCAN_WORKERS` | Parallel scan workers in the asyncio queue |
| `EDGE_AUTH_ENABLED` / `EDGE_AUTH_USER` / `EDGE_AUTH_PASSWORD` / `EDGE_ALLOWED_IPS` | HTTP-Basic gate + IP whitelist (local/LAN always passes) |
| `PROXY_ENABLED` / `PROXY_FILE` / `PROXY_GATEWAY` | Outbound IP rotation |
| `NOTIFY_WEBHOOK_URL` / `NOTIFY_ON` / `DASHBOARD_URL` | Delta notifications |
| `SECURITYTRAILS_API_KEY` / `OTX_API_KEY` / `HIBP_API_KEY` / `HUNTER_API_KEY` / `GITHUB_TOKEN` | Optional discovery sources |

See [`backend/.env.example`](backend/.env.example) for the full annotated list.

## How it works

1. **Add a company** — give it a name; Sauron proposes candidate domains (crt.sh org match + LLM brainstorm), you confirm which ones are yours.
2. **Discover** — subdomains, DNS, reverse-IP neighbors, mobile apps, endpoints and technologies are inventoried as assets with first/last-seen timestamps.
3. **Scan** — deterministic modules and real tools assess every inventoried asset; findings are categorized (vulnerability / misconfiguration / exposure / info) and fingerprinted for remediation tracking.
4. **Monitor** — scheduled discovery and vulnerability scans run on their own cadences; dashboards show deltas, rating trends, compliance posture and remediation progress. SauronBot answers questions over all of it.

## License

**Apache License 2.0** — see [LICENSE](LICENSE). Copyright 2026 Carlos Ganoza.

The scanning tools bundled in the backend image keep their own licenses: nuclei, subfinder, httpx, katana and naabu are MIT (ProjectDiscovery); trufflehog is AGPL-3.0 — it is executed as an external CLI binary (mere aggregation), so its copyleft does not extend to Sauron.

## Credits

Built by **Carlos Ganoza**.
