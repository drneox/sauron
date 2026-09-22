# Sauron ASM — Roadmap

Planned features and known follow-ups. Items are roughly ordered by value/effort, not by commitment date.

## Next up

### Semantic search for the chat assistant (`search_findings` tool)
Hybrid RAG: keep tool-calling as the backbone for structured data, add one semantic-search tool over finding/report text.
- Switch Postgres image to `pgvector/pgvector:pg16`, `CREATE EXTENSION vector`
- New `finding_chunks` table (scan/domain/company, kind, text, metadata, embedding)
- Embeddings via Azure AI Foundry deployment (needs an embeddings model, e.g. `text-embedding-3-small` — **dependency: confirm the Foundry resource has one**) or local fallback via sentence-transformers
- Ingestion hook on scan completion (findings, ai_summary, agent_summary, remediation notes); keep history, filter by date at query time
- New read-only chat tool `search_findings(query, company?, domain?, days?)` with cosine search + scope filters
- Reuse existing guardrails: read-only tools, arg whitelist, output secret redaction

### Host-scan fan-out
After a full vulnerability scan, automatically enqueue per-host scans for alive inventoried hosts — capped (`host_scan_max_targets`), delta-aware (only never-scanned / changed / stale hosts), aliveness-probed first. Settings toggle, off by default.

## Security follow-ups (from the pre-release audit)

- **SSRF pinning (DNS rebinding)**: resolve-pin the validated IP through the actual connection, or verify the peer IP after connect, in `modules/common.py`
- **Rate limiting redesign**: per-account keys for login (not only `req.client.host`), progressive lockout, store outside process memory
- **Tool binary integrity**: pin + verify SHA256 for nuclei/subfinder/httpx/katana/naabu/trufflehog downloads in `backend/Dockerfile`
- **Non-root containers**: `USER` directives (backend; unprivileged nginx image for frontend), `cap_net_raw` only if SYN scanning is needed
- **Session storage**: evaluate httpOnly+SameSite cookies instead of localStorage; shorter token TTL with rotation
- **Dependency pinning**: strict pins + hashes (`pip-compile --generate-hashes`) for a reproducible public release

## Robustness

- **reverse_ip upstream quota**: hackertarget free tier rate-limits; consider a fallback source or backoff+retry window

## Later / exploratory

- Persistent chat history per user (server-side `ChatMessage` model)
- Chat over loose text (post-RAG): posture summaries, cross-company comparisons
- Additional discovery sources (SecurityTrails/OTX keys are wired; consider crt.sh OID expansion, DNSDB)
- Scheduled report delivery (PDF via webhook/email)
