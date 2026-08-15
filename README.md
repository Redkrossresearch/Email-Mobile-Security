# CyberShield SOC — Enterprise Security Platform

**Version 6.0** — Email, Mobile, Auth & IAM, Reporting, and SIEM in one unified platform

A single-server Flask SOC platform with 60+ API endpoints and a dark-themed frontend covering Email Security, Mobile Security, Authentication & IAM, Reporting, and SIEM eventing.

---

## Quick Start

```bash
pip install flask flask-cors pyjwt fpdf2 openpyxl cryptography python-magic-bin phonenumbers pyotp argon2-cffi

# Windows
python backend\app.py

# Linux/Mac
python backend/app.py
```

**Open:** http://localhost:5000

**Email Login:** `admin@cybershield.com` / `admin123`

**Mobile Login:** Any phone + a security PIN set at registration. The SMS/email OTP is printed to the server console in demo mode (SMTP not configured).

---

## 5 Modules — 60+ API Endpoints

### 1. Email Security (20 endpoints)

Frontend: `email-security.html`

| Feature | Endpoint | Description |
|---|---|---|
| SPF Checker | `POST /api/email/check-spf` | Real DNS SPF record validation |
| DKIM Checker | `POST /api/email/check-dkim` | Real DNS DKIM signature verification |
| DMARC Checker | `POST /api/email/check-dmarc` | Real DNS DMARC policy check |
| Header Analyzer | `POST /api/email/analyze-header` | Deep email header analysis (hops, spoof) |
| Phishing Scan | `POST /api/email/phishing-scan` | Content-based phishing detection |
| BEC Scan | `POST /api/email/bec-scan` | BEC/impersonation scan |
| URL Scanner | `POST /api/email/url-analysis` | Real URL fetch + VirusTotal (optional) |
| Attachment Sandbox | `POST /api/email/sandbox-analysis` | Simulated sandbox detonation |
| Lookalike Domain | `POST /api/email/lookalike-domain` | Typosquatting/homograph detection |
| Heuristic Scan | `POST /api/email/heuristic-scan` | Content-based heuristics |
| Attachment Block | `POST /api/email/attachment-block` | Real MIME detection via python-magic-bin |
| Content Disarm | `POST /api/email/content-disarm` | CDR simulation for attachments |
| Outbound Encrypt | `POST /api/email/outbound-encrypt` | Real AES-256-GCM encryption |
| Sender Reputation | `POST /api/email/sender-scan` | Sender reputation + AbuseIPDB (optional) |
| EML File Analysis | `POST /api/email/analyze-eml-file` | Parses .eml files for phishing |
| EML PDF Report | `GET /api/email/eml-report/pdf` | Professional PDF from EML analysis |
| EML Excel Report | `GET /api/email/eml-report/xlsx` | Structured XLSX from EML analysis |
| Allow-List | `POST /api/email/allow-list` | Manage trusted senders |
| Block-List | `POST /api/email/block-list` | Manage blocked senders |
| Auto-Remediate | `POST /api/email/auto-remediate` | Automatic email remediation |

### 2. Mobile Security (15 endpoints)

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
| Device Health | `GET /api/mobile/device-health` | OS patches, root, VPN, firmware integrity |
| Dashboard Stats | `GET /api/mobile/dashboard-stats` | Aggregate security metrics |
| App Reputation | `POST /api/mobile/app-reputation` | Package name reputation lookup |
| Caller Scanner | `POST /api/mobile/caller-scan` | Real phone validation via phonenumbers |
| Live Caller Feed | `GET /api/mobile/caller-feed` | Real-time call event simulation |
| Report Caller | `POST /api/mobile/report-caller` | Report spam/scam numbers |
| Battery Check | `GET /api/mobile/check-battery` | Battery health anomaly check |
| VoLTE Status | `GET /api/mobile/volte-status` | VoLTE/VoWiFi encryption status |

### 3. Auth & IAM (22 endpoints)

Frontend: `login.html` + `register.html`

| Feature | Endpoint | Description |
|---|---|---|
| Email Login | `POST /api/auth/login` | Standard auth with lockout + email OTP |
| Email Register | `POST /api/auth/register` | Self-service account registration |
| Mobile Login | `POST /api/auth/mobile-login` | Phone + security PIN auth |
| Mobile Register | `POST /api/auth/mobile-register` | Set phone + security PIN |
| Send OTP | `POST /api/auth/send-otp` | Generic OTP dispatch |
| Verify OTP | `POST /api/auth/verify-otp` | One-time passcode check |
| Send Email OTP | `POST /api/auth/send-email-otp` | Email OTP delivery |
| Verify Email OTP | `POST /api/auth/verify-email-otp` | Email OTP verification |
| Send Mobile OTP | `POST /api/auth/send-mobile-otp` | SMS OTP delivery (console in demo mode) |
| Verify Mobile OTP | `POST /api/auth/verify-mobile-otp` | SMS OTP verification |
| MFA Verify | `POST /api/auth/verify-2fa` | MFA OTP verification |
| Refresh | `POST /api/auth/refresh` | Token refresh |
| Logout | `POST /api/auth/logout` | Session revocation |
| Me | `GET /api/auth/me` | Current user profile |
| Users | `GET /api/auth/users` | User directory (admin) |
| TOTP Setup | `POST /api/auth/totp/generate` | TOTP secret + QR provisioning |
| OAuth Authorize | `POST /api/auth/oauth/authorize` | OAuth 2.0 code generation |
| OAuth Token | `POST /api/auth/oauth/token` | Token exchange |
| SSO OIDC | `POST /api/auth/sso/oidc` | OIDC SSO login |
| SSO SAML | `POST /api/auth/sso/saml` | SAML SSO login |
| Password Reset | `POST /api/auth/password-reset` | Request password reset |
| Password Reset Confirm | `POST /api/auth/password-reset/confirm` | Apply password reset |

### 4. Reports (5 endpoints)

Frontend: `reports.html`

| Feature | Endpoint | Description |
|---|---|---|
| PDF Report | `GET /api/reports/download-pdf` | Professional SOC PDF |
| CSV Export | `GET /api/reports/download-csv` | Structured CSV |
| JSON Export | `GET /api/reports/download-json` | Structured JSON |
| Comprehensive | `GET /api/reports/comprehensive` | Full module status JSON |
| Threat Report | `GET /api/reports/threat-report` | Threat landscape JSON |

### 5. SIEM (1 endpoint)

| Feature | Endpoint | Description |
|---|---|---|
| Event Feed | `GET /api/siem/events` | Security event log (severity/type filters) |

---

## Frontend Pages

| Page | File | Purpose |
|---|---|---|
| Home/Landing | `index.html` | Marketing, live threat ticker |
| Login | `login.html` | Email + Mobile auth, OTP, PIN setup |
| Register | `register.html` | New account registration |
| Dashboard | `dashboard.html` | Stats, live threat monitor |
| Email Security | `email-security.html` | 20 tool cards, header analyzer, EML parser |
| Mobile Security | `mobile-security.html` | 15 scanners + caller/sms analysis |
| Reports | `reports.html` | 5 report types, charts, alerts |

---

## Architecture

```
Forntend1/
├── index.html              # Landing page
├── *.html                  # 7 frontend pages
├── js/
│   └── script.js           # All frontend logic
├── backend/
│   ├── app.py              # Flask app + blueprint registration
│   ├── config/
│   │   └── settings.py     # Config constants
│   ├── middleware/
│   │   └── auth.py         # JWT decorator + rate limiting
│   ├── controllers/        # auth, email, mobile, reports
│   ├── routes/             # auth, email, mobile, reports
│   ├── services/
│   │   ├── auth/           # Login, OTP, mobile PIN, MFA
│   │   ├── email_security/ # SPF/DKIM/DMARC + scanners
│   │   ├── mobile_security # Devices, SMS, caller analysis
│   │   └── _shared/        # JWT, SIEM logger
│   └── data/               # JSON data stores
└── requirements.txt
```

**Tech Stack:** Python Flask, JWT (RS256) auth, argon2-cffi (password hashing), pyotp (TOTP), fpdf2 (PDF), openpyxl (XLSX), AES-256-GCM (cryptography), python-magic-bin (MIME), phonenumbers.

---

## Credentials

| Method | Credentials |
|---|---|
| Email Login | `admin@cybershield.com` / `admin123` |
| Mobile Login | Any phone number + security PIN (set via "Set your security PIN" on the login page) |
| OTP Delivery | Printed to the server console when SMTP is not configured |

---

## API Keys (optional — app falls back to simulated data)

Set environment variables in `backend/.env` for real behavior:

- `EMAIL_USER` / `EMAIL_APP_PASSWORD` — Gmail App Password for real OTP email delivery
- `VIRUSTOTAL_API_KEY` — VirusTotal URL/hash scanning
- `ABUSEIPDB_API_KEY` — AbuseIPDB IP reputation

---

## License

Internal SOC tool. All rights reserved.
