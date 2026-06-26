# CyberShield SOC — Enterprise Security Platform

**Version 7.0** — 120+ Features Across 12 Integrated Modules

A single-server Flask SOC platform with 90+ API endpoints and a dark-themed frontend covering Email Security, Mobile Security, Threat Intelligence, AI Engine, Sandbox, APK Analyzer, YARA Rules, Third-Party Integrations, Encryption, UEBA, Auth & IAM, and Reporting.

---

## Quick Start

```bash
pip install flask flask-cors pyjwt fpdf2 openpyxl cryptography python-magic-bin phonenumbers

# Windows
python backend\app.py

# Linux/Mac
python backend/app.py
```

**Open:** http://localhost:5000

**Login:** `admin@cybershield.com` / `admin123`

**Mobile Login:** Any phone + PIN `123456` / OTP `123456`

---

## 12 Modules — 90+ API Endpoints

### 1. Email Security (15 endpoints)

Frontend: `email-security.html`

| Feature | Endpoint | Description |
|---|---|---|
| SPF Checker | `POST /api/email/check-spf` | Real DNS SPF record validation |
| DKIM Checker | `POST /api/email/check-dkim` | Real DNS DKIM signature verification |
| DMARC Checker | `POST /api/email/check-dmarc` | Real DNS DMARC policy check |
| Header Analyzer | `POST /api/email/analyze-header` | Deep email header analysis (hops, spoof) |
| Phishing Detection | `POST /api/email/bec-scan` | BEC/impersonation scan |
| URL Scanner | `POST /api/email/url-analysis` | Real URL fetch + VirusTotal (optional) |
| Attachment Sandbox | `POST /api/email/sandbox-analysis` | Simulated sandbox detonation |
| Lookalike Domain | `POST /api/email/lookalike-domain` | Typosquatting/homograph detection |
| Heuristic Scan | `POST /api/email/heuristic-scan` | Content-based heuristics |
| Attachment Block | `POST /api/email/attachment-block` | Real MIME detection via python-magic-bin |
| Outbound Encrypt | `POST /api/email/outbound-encrypt` | Real AES-256-GCM encryption |
| Sender Reputation | `POST /api/email/sender-scan` | Sender reputation + AbuseIPDB (optional) |
| EML File Analysis | `POST /api/email/analyze-eml-file` | Parses .eml files for phishing |
| EML PDF Report | `GET /api/email/eml-report/pdf` | Professional PDF from EML analysis |
| EML Excel Report | `GET /api/email/eml-report/xlsx` | Structured XLSX from EML analysis |

### 2. Mobile Security (12 endpoints)

Frontend: `mobile-security.html`

| Feature | Endpoint | Description |
|---|---|---|
| Device List | `GET /api/mobile/devices` | All monitored devices |
| Device Details | `GET /api/mobile/devices/<id>` | Single device info |
| App Scanner | `GET /api/mobile/scan-apps` | Installed app permissions audit |
| SMS Analyzer | `POST /api/mobile/analyze-sms` | Phishing/smishing detection |
| Malware Scan | `GET /api/mobile/malware-scan` | Malware signature matching |
| SMS Logs | `GET /api/mobile/sms-logs` | SMS history with classification |
| Call Logs | `GET /api/mobile/call-logs` | Call history with blocked calls |
| Device Health | `GET /api/mobile/device-health` | OS patches, root, encryption, VPN |
| Dashboard Stats | `GET /api/mobile/dashboard-stats` | Aggregate security metrics |
| App Reputation | `POST /api/mobile/app-reputation` | Package name reputation lookup |
| Caller Scanner | `POST /api/mobile/caller-scan` | Real phone validation via phonenumbers |
| SMS Threat Scan | `POST /api/mobile/sms-threat-scan` | SMS threat analysis |
| Live Caller Feed | `GET /api/mobile/caller-feed` | Real-time call event simulation |

### 3. Threat Intelligence (5 endpoints)

Frontend: `threat-intel.html`

| Feature | Endpoint | Description |
|---|---|---|
| IOC Feeds | `GET /api/threat-intel/feeds` | AlienVault, VirusTotal, AbuseIPDB, MISP, GreyNoise |
| IOC Lookup | `POST /api/threat-intel/ioc-lookup` | Auto-detect IP/domain/email/hash |
| Alerts | `GET /api/threat-intel/alerts` | Severity-filtered alerts |
| Generate Alert | `POST /api/threat-intel/alerts/generate` | Create security alert |
| Hash Scan | `POST /api/threat-intel/scan-hash` | VirusTotal + 72 engine scan |

### 4. AI Engine (6 endpoints)

Frontend: `ai-engine.html`

| Feature | Endpoint | Description |
|---|---|---|
| IOC Analysis | `POST /api/ai/analyze-ioc` | LLM-powered IOC analysis (Ollama Llama 3) |
| Email Analysis | `POST /api/ai/analyze-email` | AI phishing/BEC detection (Phi 3) |
| AI Search | `POST /api/ai/search` | AI security search engine |
| Models | `GET /api/ai/models` | Available Ollama models |
| History | `GET /api/ai/history` | AI analysis history |
| Report Gen | `POST /api/ai/generate-report` | AI-generated security report |

### 5. Sandbox (4 endpoints)

Frontend: `sandbox.html`

| Feature | Endpoint | Description |
|---|---|---|
| Create Session | `POST /api/sandbox/create` | Isolated Windows 11 sandbox |
| Upload File | `POST /api/sandbox/upload` | File detonation + behavioral analysis |
| Status | `GET /api/sandbox/status` | Active session status |
| Destroy | `POST /api/sandbox/destroy` | Terminate sandbox session |

### 6. APK Analyzer (5 endpoints)

Frontend: `apk-analyzer.html`

| Feature | Endpoint | Description |
|---|---|---|
| Decompile | `POST /api/apk/decompile` | JADX + APKTool decompilation |
| Static Analysis | `POST /api/apk/static-analysis` | Dangerous patterns, secrets, network |
| Malware Scan | `POST /api/apk/malware-scan` | 72-engine detection |
| History | `GET /api/apk/analyses` | Last 20 analyses |
| Tools Status | `GET /api/apk/tools-status` | APKTool/JADX/dex2jar/aapt2 status |

### 7. YARA Rules (6 endpoints)

Frontend: `yara-rules.html`

| Feature | Endpoint | Description |
|---|---|---|
| Scan IP | `POST /api/yara/scan-ip` | IP vs C2/brute/Tor/VPN rules |
| List Rules | `GET /api/yara/rules` | All rules with status |
| Create Rule | `POST /api/yara/rules` | Custom YARA rule creation |
| Toggle Rule | `POST /api/yara/rules/toggle` | Enable/disable by ID |
| Delete Rule | `POST /api/yara/rules/delete` | Remove rule by ID |
| Scan History | `GET /api/yara/history` | Recent YARA scans |

### 8. Integrations (9 endpoints)

Frontend: `integrations.html`

| Feature | Endpoint | Description |
|---|---|---|
| Gmail Connect | `POST /api/integration/gmail/connect` | OAuth Gmail API connection |
| Gmail Scan | `POST /api/integration/gmail/scan` | Inbox threat scan |
| Gmail Search | `POST /api/integration/gmail/search` | Query Gmail inbox |
| Gmail Disconnect | `POST /api/integration/gmail/disconnect` | Revoke tokens |
| Graph Connect | `POST /api/integration/graph/connect` | OAuth Microsoft Graph |
| Graph Users | `POST /api/integration/graph/users` | List Microsoft 365 users |
| Graph Mail Scan | `POST /api/integration/graph/scan-mail` | Mailbox threat scan |
| Graph Audit Logs | `POST /api/integration/graph/audit-logs` | M365 audit retrieval |
| Graph Disconnect | `POST /api/integration/graph/disconnect` | Revoke tokens |

### 9. Encryption (5 endpoints)

Frontend: `encryption.html`

| Feature | Endpoint | Description |
|---|---|---|
| Encrypt | `POST /api/encryption/encrypt` | AES-256-GCM encryption |
| Decrypt | `POST /api/encryption/decrypt` | AES-256-GCM decryption |
| Key Management | `GET /api/encryption/keys` | List/rotate encryption keys |
| TLS Status | `GET /api/encryption/tls-status` | TLS 1.3 config + cert status |
| PGP Encrypt | `POST /api/encryption/pgp-encrypt` | RSA-2048 / AES-256 PGP |

### 10. UEBA (4 endpoints)

Frontend: `ueba.html`

| Feature | Endpoint | Description |
|---|---|---|
| Behavior Analysis | `POST /api/ueba/analyze-behavior` | Anomaly detection on events |
| User Profile | `POST /api/ueba/user-profile` | Behavioral baseline |
| Login Anomaly | `POST /api/ueba/login-anomaly` | Impossible travel, brute force |
| Risk Score | `POST /api/ueba/risk-score` | Multi-signal risk calculation |

### 11. Auth & IAM (12 endpoints)

Frontend: `login.html` + `auth-enhanced.html`

| Feature | Endpoint | Description |
|---|---|---|
| Email Login | `POST /api/auth/login` | Standard auth with lockout |
| Mobile Login | `POST /api/auth/mobile-login` | Phone + PIN auth |
| OTP Verify | `POST /api/auth/verify-otp` | One-time passcode |
| MFA Verify | `POST /api/auth/verify-mfa` | MFA OTP verification |
| SSO Login | `POST /api/auth/sso-login` | SAML/OIDC providers |
| OAuth Authorize | `POST /api/auth/oauth/authorize` | OAuth 2.0 code generation |
| OAuth Token | `POST /api/auth/oauth/token` | Token exchange |
| Recovery | `POST /api/auth/recovery` | Account recovery |
| Double Auth | `POST /api/auth-enhanced/double-auth` | Password + TOTP |
| Password Reset | `POST /api/auth-enhanced/password-reset` | Token-based reset |
| Session Management | `POST /api/auth-enhanced/session-*` | Create/validate/revoke/list |
| Argon2 Status | `GET /api/auth-enhanced/argon2-status` | Hashing config status |
| OAuth Initiate/Callback | `POST /api/auth-enhanced/oauth-*` | Google/Microsoft OAuth |

### 12. Reports (7 endpoints)

Frontend: `reports.html`

| Feature | Endpoint | Description |
|---|---|---|
| PDF Report | `GET /api/reports/download-pdf` | Professional SOC PDF |
| CSV Export | `GET /api/reports/download-csv` | Structured CSV |
| JSON Export | `GET /api/reports/download-json` | Structured JSON |
| Comprehensive | `GET /api/reports/comprehensive` | Full module status JSON |
| Threat Report | `GET /api/reports/threat-report` | Threat landscape JSON |
| Encryption Report | `GET /api/reports/encryption` | Encryption status JSON |
| UEBA Risk Report | `GET /api/reports/ueba-risk` | Risk assessment JSON |

---

## Frontend Pages

| Page | File | Purpose |
|---|---|---|
| Home/Landing | `index.html` | Marketing, live threat ticker |
| Login | `login.html` | Email + Mobile auth, OTP, SSO |
| Dashboard | `dashboard.html` | Stats, live threat monitor |
| Email Security | `email-security.html` | 15 tool cards, header analyzer, EML parser |
| Mobile Security | `mobile-security.html` | 12 scanners + caller/sms analysis |
| Threat Intel | `threat-intel.html` | IOC lookup, feeds, hash scan, alerts |
| AI Engine | `ai-engine.html` | AI IOC/email/search, models, report |
| Sandbox | `sandbox.html` | Create/upload/status/destroy sessions |
| APK Analyzer | `apk-analyzer.html` | Decompile, static, malware, history |
| YARA Rules | `yara-rules.html` | IP scan, rules CRUD, history |
| Integrations | `integrations.html` | Gmail + Microsoft Graph tools |
| Encryption | `encryption.html` | Encrypt/decrypt, TLS, PGP, keys |
| UEBA | `ueba.html` | Behavior, profile, anomaly, risk |
| Auth Enhanced | `auth-enhanced.html` | Double auth, password reset, OAuth, session |
| Reports | `reports.html` | 7 report types, charts, alerts |

---

## Architecture

```
Forntend1/
├── index.html              # Landing page
├── *.html                  # 15 frontend pages
├── js/
│   └── script.js           # All frontend logic (~925 lines)
├── backend/
│   ├── app.py              # Flask app + blueprint registration
│   ├── config/
│   │   └── settings.py     # Config constants
│   ├── middleware/
│   │   └── auth.py         # JWT decorator
│   ├── controllers/        # 12 controller modules
│   ├── routes/             # 13 route blueprints
│   └── services/           # Gmail + Graph integration services
└── requirements.txt
```

**Tech Stack:** Python Flask, JWT auth, fpdf2 (PDF), openpyxl (XLSX), AES-256-GCM (cryptography), python-magic-bin (MIME), phonenumbers, argon2-cffi, Ollama (optional AI).

---

## Credentials

| Method | Credentials |
|---|---|
| Email Login | `admin@cybershield.com` / `admin123` |
| Mobile Login | Any phone number (e.g. `+91 9876543210`) + PIN `123456` |
| OTP (any user) | `123456` |

---

## API Keys (optional — app falls back to simulated data)

Set environment variables for real API lookups:

- `VIRUSTOTAL_API_KEY` — VirusTotal hash/URL scanning
- `ABUSEIPDB_API_KEY` — AbuseIPDB IP reputation
- `GMAIL_CREDENTIALS_JSON` — Gmail API OAuth credentials
- `GMAIL_TOKEN_JSON` — Gmail API OAuth token
- `GRAPH_TENANT_ID` / `GRAPH_CLIENT_ID` / `GRAPH_CLIENT_SECRET` — Microsoft Graph API

---

## License

Internal SOC tool. All rights reserved.
