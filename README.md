# PhishScope · Phishing Detection

A runnable URL investigation workspace alongside the original phishing-detection research notebooks. The demo uses **transparent local rules**, optional VirusTotal and Google Safe Browsing agents, an evidence ledger, a unified decision, and a persisted human-review decision.

**This demo does not load the notebook models, use an LLM, or claim their accuracy.** Its score is an uncalibrated rule total, not a probability or a guarantee that a URL is safe.

![PhishScope investigation workspace](docs/demo-desktop.png)

## Run the demo

```bash
docker compose up -d --build
# Open http://localhost:3102
```

The service restarts automatically with Docker and saves cases in the `phishscope-data` named volume. It binds to `127.0.0.1` on the host. The container runs as a non-root user with a read-only root filesystem. Check `docker compose ps` for health. Stop with `docker compose down`; this preserves saved cases.

Or use Python 3.10+ with no runtime dependencies:

```bash
python3 -m app.server
```

Configuration: `HOST` (default `127.0.0.1`), `PORT` (default `3102`), and `DATA_DIR` (default `data`). No API key, model download, or account is needed for the offline workflow. Optional Node dependencies are used only for browser tests.

## Explore the workflow

1. Choose an example or enter an HTTP(S) URL.
2. **Intake** validates syntax, rejects explicit private/local addresses and embedded credentials, and removes query values and fragments from saved results.
3. **Plan** selects transport, hostname, and path checks; query and internationalized-hostname checks run only when relevant.
4. **Investigate** collects explanations with visible weights. If you supply credentials in the optional panel, separate agents retrieve an existing [VirusTotal URL report](https://docs.virustotal.com/reference/url-info), [VirusTotal domain report](https://docs.virustotal.com/reference/domain-info), and/or [Google Safe Browsing match](https://developers.google.com/safe-browsing/v4/reference/rest/v4/threatMatches/find). The app never submits a URL for a new scan.
5. **Evaluate** combines those signals into an explained policy decision. The local score remains a separate, uncalibrated rule total: low `<20`, moderate `20–49`, high `≥50`.
6. Moderate/high concern or any positive reputation result pauses at **Human review**. An operator records a decision and reasoning. Low-concern cases can also be reviewed. Decisions are persisted once; further investigation is an explicit escalation state.
7. Open the case again from history or export its JSON audit record.

The agent-style architecture is **deterministic orchestration**, not an autonomous LLM agent. Each enabled provider is a real, independently reported signal; failures degrade to an `unavailable` result. The unified decision is a transparent policy call. There are no simulated model calls or fabricated threat-intelligence results.

```mermaid
flowchart LR
  A[URL intake] --> B[Conditional tool plan]
  B --> C[Local evidence tools]
  B --> I[Optional reputation agents]
  C --> D[Unified decision policy]
  I --> D
  D -->|Score at least 20| E[Await human review]
  D -->|Score below 20| F[Analysis complete]
  F -->|Optional review| E
  E --> G[Reviewed or escalated]
  G --> H[SQLite audit and JSON export]
```

## Boundaries and data handling

- PhishScope never fetches, resolves, renders, or executes a submitted website. When explicitly enabled, it sends the submitted URL only to fixed VirusTotal and/or Google Safe Browsing HTTPS API endpoints. It does not follow provider redirects. Certificates, page content, and website redirects are not checked.
- Explicit private, reserved, multicast, loopback, local-hostname, and ambiguous numeric targets are rejected. Public-looking hostnames are not resolved, so the demo does not establish whether their DNS points to a public address. There is no URL-fetching path that could use them for SSRF.
- Query **values** and fragments are removed before persistence; hostname, path, query names, evidence, bounded provider summaries, and review notes remain in the local database. Provider lookup may require the full query-bearing URL, so do not enable live checks for URLs containing secrets. HTTP request logging is disabled.
- API keys live only in the current page DOM and one request body. The server validates them, uses them for that request, and never puts them in results, SQLite, exports, logs, cookies, local storage, session storage, environment variables, or URLs, except that Google v4 itself requires its key in the fixed provider request query string. Reloading the page clears the fields.
- HTTPS, brand terms, Unicode names, long URLs, and login language can appear on legitimate and malicious sites. These rules have false positives and false negatives and have not been evaluated as a production classifier.
- This is a single-operator local demonstration. Reviewer identity is labeled “local demo operator”; it is not authenticated or a tamper-proof audit. Public deployment requires authentication, storage access controls, rate limits, and a production HTTP server.
- Provider results can be stale, incomplete, rate-limited, or unavailable. A clean response is supporting evidence, not proof that a URL is benign. No live blocking, reporting, email sending, or automated remediation occurs.

See [security and provider design](docs/SECURITY.md) for endpoint allowlisting, credential handling, failure behavior, and the model boundary.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Version, mode, health |
| POST | `/api/analyze` | `{"url":"https://example.com","providers":{"virustotal":"optional","google_safe_browsing":"optional"}}` creates a case |
| GET | `/api/cases` | Latest 30 cases |
| GET | `/api/cases/{id}` | Full case evidence and state |
| POST | `/api/cases/{id}/review` | `{"decision":"suspicious","note":"Reasoning"}` records one review |

Review decisions: `likely_legitimate`, `suspicious`, `needs_investigation`. Notes are required and limited to 500 characters; duplicate reviews return HTTP 409. The browser exports the case response as JSON.

## Verification

```bash
python3 -m unittest discover -s tests -v
# With the app running on localhost:3102:
npm ci
npx playwright install chromium
npm run test:e2e
```

Unit/integration tests cover offline isolation, private and ambiguous targets, credential rejection, redaction, fixed provider endpoints, mocked provider responses and failures, unified policy, persisted reviews, key non-persistence, invalid payloads, cross-origin requests, and response security headers. Tests never call a paid provider. Browser checks exercise the optional-key UI, high/low results, the five-stage trail, review persistence after reload, JSON export, rejected private input, mobile overflow, and JavaScript errors. See [validation record](docs/VALIDATION.md) and [mobile screenshot](docs/demo-mobile.png). CI runs both suites; local results do not imply a completed remote CI run.

## Original research

The root notebooks are preserved unchanged: EDA, classical classifiers, URL embeddings, neural networks, and Captum/SHAP/LIME explainability. The original project description is archived in [docs/RESEARCH.md](docs/RESEARCH.md). Any research results belong to the original experimental setup and are not measurements of this web demo. No compatible trained artifact, preprocessing bundle, class mapping, or inference contract is present, so the app labels its local signal as a deterministic scorer instead of pretending to call the research model.
