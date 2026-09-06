# Security and provider design

PhishScope is local-first. With no keys supplied, URL analysis performs no DNS resolution or outbound request. The input validator rejects credentials, non-HTTP(S) schemes, explicit private/non-public IPs, local hostname suffixes, ambiguous numeric hosts, controls, whitespace, and backslashes.

Live reputation is opt-in per browser tab and per request. The browser keeps keys only in password input elements; it does not use cookies, `localStorage`, or `sessionStorage`. The backend accepts keys only in `POST /api/analyze`, limits each to 512 non-whitespace characters, and passes them directly to the selected provider call. Keys are excluded from the result before SQLite persistence and JSON export. Request logging is disabled.

The outbound allowlist is implemented as code constants, with no user-controlled host, scheme, port, or redirect:

| Agent | Fixed endpoint | Credential placement | Data sent |
| --- | --- | --- | --- |
| VirusTotal URL | `https://www.virustotal.com/api/v3/urls/{base64-id}` | `x-apikey` header | Full submitted URL encoded as documented, excluding fragment |
| VirusTotal domain | `https://www.virustotal.com/api/v3/domains/{host}` | `x-apikey` header | Validated ASCII hostname |
| Google Safe Browsing | `https://safebrowsing.googleapis.com/v4/threatMatches:find` | Provider-required `key` query parameter | Full submitted URL excluding fragment |

PhishScope retrieves existing VirusTotal reports; it never requests a scan and never contacts the submitted host. Provider redirects are disabled, responses are capped at 1 MB, and calls time out after five seconds. Authentication errors, missing reports, rate limits, timeouts, malformed responses, and other provider failures become sanitized `unavailable` evidence. Local analysis still completes.

Provider output is treated as one signal. Any provider malicious/suspicious match yields a `Likely malicious` policy decision. Without a provider flag, high local scores yield `Likely malicious`, moderate scores yield `Needs review`, and low local scores plus completed clean checks yield `Likely benign` with an explicit non-guarantee. The policy does not convert engine counts into a probability.

The research notebooks do not ship a deployable model artifact. Reproducing their preprocessing and architecture from notebook fragments would not establish compatible inference. Consequently, the live application uses a labeled deterministic lexical scorer and does not simulate an ML/LLM agent. A future model adapter should require a versioned model artifact, exact preprocessing contract, class mapping, validation record, bounded inference resources, and a separate evidence field so its output remains one signal in the same policy.
