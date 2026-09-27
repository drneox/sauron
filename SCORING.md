# Scoring model

How Sauron ASM turns scan results into a **0-100 score** and an **A-F letter**.
All of the logic lives in [`backend/scoring.py`](backend/scoring.py); this page
explains it and says where to change each rule. Regression tests:
`cd backend && python -m unittest discover -s tests -t .`

## Pipeline

```
each module ──► risk (low/medium/high/critical) + findings (text lines)
                     │
                     ▼
 scoring.finding_category(module, finding)  ──► category of every line
 scoring.finding_risk(module risk, category) ──► risk label of every line
                     │
                     ▼
 scoring.overall_score(results)  ──► score, grade, findings_by_severity, ...
```

## `info` is used in two places

- **As a category** (weight 0): neutral inventory that never penalizes — see §1.
- **As a risk label** on a finding line: findings whose category is `info` carry
  the risk `info` instead of inheriting their module's worst risk
  (`scoring.finding_risk`), so "Email hosted on Google Workspace" does not read as
  HIGH next to a real "No DMARC record found". It is a label for display and
  remediation tracking only: modules never return `info` as their own risk, and
  `info` findings are excluded from the score, the caps and the severity counts.
  Valid finding risks are `FINDING_RISK_LEVELS` (the four levels plus `info`).

## 1. Categories and weights

Being visible on the internet is inventory, not a defect. Every finding line gets
a category and only non-info categories can lower the score.

| Category | Weight | Meaning | Example modules |
|---|---|---|---|
| `vulnerability` | 1.0 | exploitable / confirmed problem | js_secrets, exposed, breach, blacklist, frontend_cve, cloud_storage, nuclei, kev |
| `misconfiguration` | 0.6 | hardening gap | ssl, tls, headers, cors, cookies, email, ports |
| `exposure` | 0.25 | notable attack surface | admin, robots, api_exposure, smart_fuzz, waf (only "No WAF or CDN detected"; a detected WAF is info) |
| `info` | 0 | neutral inventory, **never penalizes** | whois, dns, subdomains, tech, reverse_ip, mobile_apps |

- `CATEGORY_SCORE_WEIGHT` — the weights.
- `MODULE_FINDING_CATEGORY` — default category per module. Unknown modules default to `info`.
- `FINDING_CATEGORY_RULES` — per-module functions that reclassify individual lines
  (e.g. the `email` rule: only SPF/DMARC gaps are defects; DKIM "not detectable",
  provider detection and failed DNS lookups are `info`).

A finding dict may carry its own `category`, which wins over the rules.

## 2. Score

```
base    = 100 - average over the 29 scored modules of
          MODULE_RISK_POINTS[module risk] * category weight of the module
penalty = sum over critical/high/medium of
          max_points * (1 - exp(-weighted_count / scale))        (FINDING_PENALTY)
score   = round(clamp(base - penalty, 0, 100))
```

- `MODULE_RISK_POINTS`: low 0, medium 25, high 60, critical 100.
- `FINDING_PENALTY`: critical (25 pts, scale 2), high (12, 5), medium (4, 12) —
  diminishing returns, so repeated findings do not stack forever.
- `weighted_count` counts finding **lines** (non-info) times their category weight.
- The score is the real number: it is what ranks and charts domains.

## 3. Letter and caps

- `GRADE_THRESHOLDS`: 90 A, 75 B, 60 C, 40 D, otherwise F.
- `GRADE_CAPS`: the letter can never look better than the worst finding allows —
  any module with a **critical** finding caps at **D**, **high** at **C**,
  **medium** at **B**. Only the letter is capped, never the number; the result
  then carries `grade_capped_by` so reports can say why.
- A cap never improves a letter that is already worse.
- `findings_by_severity` counts **modules affected** per severity (a module with
  45 lines is one medium), because severity is a property of the module.

## 4. Where each rule lives

| To change… | Edit |
|---|---|
| category weights, module→category map, per-line reclassification, the risk label of a line | `backend/scoring.py` |
| score formula, penalty scale, grade thresholds, caps | `backend/scoring.py` |
| the risk level a check assigns (e.g. "port 22 open = medium") | the module itself, `backend/modules/<module>.py` — each check owns its `risk` |
| which modules are scored | `module_names` in `scoring.overall_score` |

Consumers import from `scoring`: `main.py` (scans, persistence, analytics) and
`modules/pdf_report.py` (letter). Not in Python and therefore duplicated by
necessity: the score bar colors in `frontend/src/components/sections/ScoreCard.tsx`
(thresholds 75 / 50) and the severity color maps of the frontend charts.

## 5. Pitfall: rules match text

Per-line rules read the finding **text** (`"SPF" in finding`, `"inconclusive"`,
`"reveals server technology"`…). Reformulating a message in a module can change
its category without any error. When you edit a finding message in `modules/`,
check the matching rule in `scoring.py` and the tests in `backend/tests/`.
