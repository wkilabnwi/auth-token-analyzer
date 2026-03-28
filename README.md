# auth-token-analyzer

A dynamic web security auditing tool that detects exposed secrets, tokens, and sensitive credentials in live web applications — including those only revealed at runtime.

Unlike static scanners that analyze source files, `auth-token-analyzer` actually **executes** the target page in a headless browser, intercepting runtime storage writes and scanning real HTTP responses as they happen.

---

## How It Works

The tool runs three detection layers in parallel for every URL it visits:

**1. Runtime Storage Hooks**
Intercepts `localStorage`, `sessionStorage`, and `document.cookie` write operations at the JavaScript level using injected init scripts. If a token is only set after the page loads and runs its JS — this catches it.

**2. HTTP Response Header Scanning**
Inspects every response header for sensitive patterns (JWT tokens, API keys, bearer tokens, etc.), skipping known-safe headers like `cache-control` and `etag` to reduce noise.

**3. Response Body Analysis**
- For JavaScript and JSON responses: runs full secret extraction across the entire body
- For HTML responses: extracts and scans only inline `<script>` blocks, avoiding false positives from markup

All findings are deduplicated using SHA-256 hashing before being written to the output file.

---

## Detected Secret Types

| Pattern | Example |
|---|---|
| JWT Token | `eyJ...` (validated by decoding payload) |
| Google API Key | `AIza...` |
| AWS Access Key | `AKIA...` |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| Bearer Token | `Authorization: Bearer ...` |
| Slack Token | `xoxb-...`, `xoxp-...` |
| High-Entropy Strings | Any 32+ char string with Shannon entropy > 4.5 |

---

## Installation

**Prerequisites:** Go 1.21+, Node.js (required by Playwright)

```bash
git clone https://github.com/wkilabnwi/auth-token-analyzer
cd auth-token-analyzer
go mod tidy
go run github.com/playwright-community/playwright-go/cmd/playwright install chromium
```

---

## Usage

**Basic scan (unauthenticated):**
```bash
go run main.go -url https://target.com
```

**Authenticated scan with credentials:**
```bash
go run main.go -url https://target.com -u admin -p secret123
```

**Authenticated scan with wordlist:**
```bash
go run main.go -url https://target.com -u admin -p secret123 -w wordlist.txt -t 10 -o results.json
```

**Custom login selectors (for non-standard login forms):**
```bash
go run main.go -url https://target.com -u admin -p secret123 \
  --user-sel "#email-input" \
  --pass-sel "#password-input" \
  --submit-sel ".signin-button"
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-url` | *(required)* | Base URL of the target |
| `-u` | | Username for login |
| `-p` | | Password for login |
| `-w` | | Path to wordlist file (one path per line) |
| `-t` | `5` | Number of concurrent worker threads |
| `-o` | `findings.json` | Output file path |
| `--user-sel` | | CSS selector for username field |
| `--pass-sel` | | CSS selector for password field |
| `--submit-sel` | | CSS selector for submit button |

---

## Output

Findings are written to a JSON file (default: `findings.json`):

```json
[
  {
    "type": "STORAGE_HOOK",
    "location": "https://target.com/dashboard",
    "key": "localStorage:auth_token",
    "payload": "eyJhbGciOiJIUzI1NiJ9..."
  },
  {
    "type": "SOURCE",
    "location": "https://target.com/static/app.js",
    "key": "AWS_ACCESS_KEY",
    "payload": "AKIA4EXAMPLE..."
  }
]
```

**Finding types:**

- `STORAGE_HOOK` — Secret intercepted at runtime during a storage write
- `HEADER` — Secret found in an HTTP response header
- `SOURCE` — Secret found in a JS or JSON response body
- `INLINE_SCRIPT` — Secret found inside an inline `<script>` block in HTML

---

## Architecture

```
auth-token-analyzer/
├── main.go          # CLI, worker pool, URL feeding
├── engine/
│   ├── browser.go   # Page scanning, JS hooks, response interception
│   └── auth.go      # Login flow with selector fallback chain
├── parser/
│   └── regex.go     # Regex patterns + Shannon entropy analysis
└── models/
    └── results.go   # Finding type, dedup logic, async JSON writer
```

Each worker gets its own isolated browser context. When credentials are provided, the authenticated session state is captured after login and shared across all workers via Playwright's storage state API.

---

## Legal

This tool is intended for use on systems you own or have explicit written permission to test. Unauthorized use against third-party systems may violate computer fraud laws in your jurisdiction. The author is not responsible for misuse.

---

## Author

Built by [@wkilabnwi](https://github.com/wkilabnwi)