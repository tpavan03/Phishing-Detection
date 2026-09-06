# Demo validation · 2026-09-06

Validated locally before the demo prerelease:

- Python 3.10.12: `python3 -m unittest discover -s tests -v` — 11 tests passed.
- Docker: Python 3.12 slim image built, non-root service started, health endpoint returned `status: ok`; host binding `127.0.0.1:3102`.
- Playwright 1.63.0 Chromium: optional-key fields cleared on reload with no web-storage entry; high-concern and low-concern unified decisions; five workflow stages; review saved and recovered after reload; exported JSON download; private address error; 390px mobile layout without horizontal overflow; no browser JavaScript errors.
- Reputation agents: VirusTotal URL/domain and Google Safe Browsing HTTP interactions were mocked. Tests verified fixed endpoints, unpadded URL-safe Base64, request-only credentials, redacted persistence, positive-signal fusion, and graceful provider failure. No real provider or paid API was contacted.
- Screenshots: `docs/demo-desktop.png` at 1440px wide and `docs/demo-mobile.png` at 390px wide. They show actual local demo results, not an image mockup.
- Notebook changes: none.

These checks establish the documented demo behavior only. No phishing accuracy, live provider coverage, latency benchmark, production load test, penetration test, or trained-model equivalence is claimed. The public CI workflow is included separately; this record describes local validation.
