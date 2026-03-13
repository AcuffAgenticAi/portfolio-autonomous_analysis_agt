# ◈ Enterprise Data Insight Agent

> Upload any dataset. Get board-ready intelligence in seconds.

A production-hardened AI agent that connects to your data, performs autonomous exploratory analysis, and surfaces executive summaries, ranked insights, and operational recommendations — powered by GPT-4o and built on a secure Streamlit dashboard.

---

## What It Does

| Step | What Happens |
|------|-------------|
| **1. Upload** | Drop any CSV or Excel file into the sidebar |
| **2. Profile** | Pandas profiles shape, dtypes, distributions, missing values |
| **3. Analyze** | GPT-4o receives a sanitized statistical profile and generates intelligence |
| **4. Render** | Dashboard displays executive summary, KPIs, insights, and risk flags |
| **5. Export** | Download a plain-text report for stakeholder distribution |

---

## Output: What the Agent Produces

- **Executive Summary** — 3–5 sentence board-level narrative, ready to copy-paste
- **Key Metrics** — auto-detected KPIs with sentiment scoring (positive / neutral / negative)
- **Ranked Insights** — findings sorted by priority: 🔴 High · 🟡 Medium · 🟢 Low
- **Data Quality Score** — 0–100 score with specific issues and fix recommendations
- **Recommended Actions** — concrete next steps grounded in the data
- **Risk Flags** — anomalies, outliers, and structural concerns
- **Downloadable Report** — timestamped `.txt` export for email or documentation

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend | Streamlit + custom CSS | Dashboard UI |
| AI Engine | OpenAI GPT-4o (JSON mode) | Insight generation |
| Data Layer | Pandas | Profiling and EDA |
| Schema Validation | Pydantic v2 | LLM output sanitization |
| Output Sanitization | Python `html` stdlib | XSS prevention |
| File Support | CSV, XLSX, XLS | Upload formats |
| Logging | Python `logging` + UUID correlation IDs | Secure error handling |

---

## Security Posture

This build was red-team reviewed and remediated from **20 findings → 4 accepted residuals**.

| Severity | Before | After |
|----------|--------|-------|
| Critical | 2 | 0 ✅ |
| High | 5 | 0 ✅ |
| Medium | 6 | 0 ✅ |
| Low / Info | 7 | 4 (accepted, documented) |

Key mitigations applied:

- **No XSS** — all LLM output validated through Pydantic and `html.escape()` before any HTML render
- **No credential exposure** — API key loaded from environment variable only; never stored in session state
- **No raw data to OpenAI** — `sample_rows` removed; categorical values sanitized; column names stripped of injection characters
- **No path traversal** — CSS loaded via absolute path anchored to `__file__`; content scanned for `<script>` / `url()` before injection
- **No verbose errors** — all exceptions logged server-side with UUID correlation IDs; users see only the reference code
- **No DoS** — 50MB file size limit and 500K row cap enforced server-side
- **No prompt injection** — column names and filenames sanitized before LLM prompt construction; system prompt includes explicit untrusted-data guardrails

Full findings and remediation rationale: see [`SECURITY_CHANGELOG.md`](./SECURITY_CHANGELOG.md)

---

## Project Structure

```
enterprise_insight_agent/
├── app.py                  # Main Streamlit application (remediated v2.0)
├── style.css               # Custom dark-theme stylesheet
├── requirements.txt        # Python dependencies
├── sample_data.csv         # Demo dataset (Q1–Q2 sales data, 48 rows)
├── SECURITY_CHANGELOG.md   # Red team findings → remediation log
└── README.md               # This file
```

---

## Setup & Run

### Prerequisites

- Python 3.11+
- An OpenAI API key with GPT-4o access

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note:** `python-magic` requires `libmagic` on the system:
> ```bash
> # macOS
> brew install libmagic
>
> # Ubuntu / Debian
> sudo apt-get install libmagic1
> ```

### 2. Set your API key

```bash
export OPENAI_API_KEY="sk-..."
```

For persistent configuration, add to your `.env` file and load with `python-dotenv`, or use your deployment platform's secrets manager (Streamlit Cloud → Secrets, AWS → Secrets Manager, etc.).

> **Security:** The API key is **never** accepted via the UI. It must be injected at deploy time via environment variable. This is intentional and not configurable.

### 3. Run

```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

### 4. Demo

Upload `sample_data.csv` (included) to see the agent in action immediately — no real data required.

---

## Configuration

| Setting | Where | Default | Notes |
|---------|-------|---------|-------|
| Max file size | `app.py → MAX_FILE_MB` | 50 MB | Enforced server-side |
| Max rows | `app.py → MAX_ROWS` | 500,000 | Truncates with warning |
| LLM model | `app.py → run_agent()` | `gpt-4o` | Change to `gpt-4o-mini` to reduce cost |
| Max output tokens | `app.py → run_agent()` | 2,000 | Increase for larger datasets |
| Upload size limit | `.streamlit/config.toml` | Streamlit default | Override with `[server] maxUploadSize = 50` |

---

## Limitations & Accepted Residuals

| ID | Issue | Status | Mitigation |
|----|-------|--------|-----------|
| LOW-01 | No authentication layer | Accepted | Deploy behind VPN / IP allowlist until SSO (Okta/Azure AD) is integrated |
| LOW-02 | No explicit API call timeout | Accepted | OpenAI SDK default 600s; add `timeout=30.0` before multi-tenant deployment |
| LOW-05 | f-string HTML pattern for static strings | Accepted | All dynamic values wrapped in `sanitize_text()`; enforced via code review |
| INFO-01 | Downloaded report may reach downstream AI | Accepted | AI-GENERATED header added; escalate if PDF/HTML export is added |

---

## What This Demonstrates

- **Agentic AI design** — autonomous dataset profiling with LLM-generated actionable output
- **Secure LLM integration** — prompt injection defense, output schema validation, and XSS prevention in a full pipeline
- **Enterprise data engineering** — Pandas EDA, dtype inference, statistical profiling at scale
- **Production security practices** — OWASP-aware code, Pydantic validation, structured logging, correlation ID error handling
- **Full-stack ownership** — from raw file upload through sanitized insight delivery and secure export

---

## License

MIT — free to use, fork, and build on.
