# Web Recon & Analysis Tool

A terminal-based passive reconnaissance tool written in Python.
Analyzes a target domain across 9 dimensions and produces a security score.

---

## What It Does

Given a domain or URL, the tool runs 9 sequential checks:

### 1. HTTP Response & Headers
- Fetches the target with a real browser User-Agent
- Reports: status code, final URL (after redirects), response time, content size
- Checks for 7 critical security headers and flags missing ones:
  - `X-Frame-Options` — prevents clickjacking
  - `X-Content-Type-Options` — blocks MIME sniffing
  - `Strict-Transport-Security` — enforces HTTPS
  - `Content-Security-Policy` — controls resource loading
  - `Referrer-Policy` — controls referrer leakage
  - `Permissions-Policy` — restricts browser APIs
  - `X-XSS-Protection` — legacy XSS filter
- Lists cookies and checks for missing `Secure` / `HttpOnly` flags

### 2. Technology Detection
- Scans HTML body and response headers for 17 tech fingerprints:
  WordPress, Joomla, Drupal, Laravel, Django, React, Vue.js,
  Angular, jQuery, Bootstrap, Next.js, Shopify, Cloudflare,
  Google Analytics, ASP.NET, PHP, Ruby on Rails
- Extracts `<title>`, `<meta description>`, and `<meta generator>` tags

### 3. DNS Records
- Queries all major record types: `A, AAAA, MX, NS, TXT, CNAME, SOA`
- Uses `dnspython` for direct resolver queries (not OS-level)
- Useful for finding mail servers, SPF/DMARC policies, nameservers

### 4. SSL/TLS Certificate
- Opens a direct TLS socket to port 443
- Reports: Common Name, Issuer, expiry date, days remaining
- Warns if certificate expires within 30 days, fails if already expired
- Shows active cipher suite and TLS protocol version
- Lists all Subject Alternative Names (SANs)

### 5. Open Port Scan
- Scans 20 commonly abused ports using 50 parallel threads
- Ports checked:
  21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS),
  80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 465 (SMTPS),
  587 (SMTP/TLS), 993 (IMAPS), 995 (POP3S), 3306 (MySQL),
  3389 (RDP), 5432 (PostgreSQL), 6379 (Redis),
  8080 (HTTP-Alt), 8443 (HTTPS-Alt), 27017 (MongoDB)
- Timeout per connection: 1.5 seconds

### 6. Sensitive File & Path Discovery
- Sends HTTP requests to 30+ known sensitive paths in parallel
- Flags by response code:
  - `200` → Accessible (critical)
  - `403` → Exists but forbidden (notable)
  - `301/302` → Redirect (notable)
- Paths checked include:
  `.env`, `.git/HEAD`, `wp-config.php`, `phpinfo.php`,
  `admin/`, `backup.zip`, `backup.sql`, `config.json`,
  `swagger-ui.html`, `graphql`, `server-status`, and more

### 7. Subdomain Enumeration
- Resolves 50+ common subdomains via DNS lookup
- Uses 50 parallel threads for speed
- Wordlist covers: www, mail, api, dev, staging, admin, cdn,
  git, jenkins, ci, vpn, portal, db, app, mobile, and more
- Reports discovered subdomain + resolved IP

### 8. IP & Geo Information
- Resolves domain to IP via `socket.gethostbyname()`
- Queries `ipapi.co` for:
  Organization/ISP, Country, Region, City,
  Timezone, Latitude, Longitude, ASN

### 9. Security Score
- Aggregates findings into a score out of 100
- Deductions:
  | Finding                        | Penalty |
  |-------------------------------|---------|
  | Each missing security header  | −5 pts  |
  | Cookie without Secure flag    | −5 pts  |
  | SSL expiring within 30 days   | −20 pts |
  | Each sensitive file exposed   | −10 pts |
  | Each dangerous port open      | −10 pts |
- Score thresholds:
  - `80–100` → Green (Good)
  - `50–79`  → Yellow (Review needed)
  - `0–49`   → Red (Critical issues)
- Prints a numbered list of all issues found

### Output
- All results optionally saved to a timestamped JSON file:
  `recon_example.com_20260613_142300.json`

---

## Requirements
```bash
pip install requests dnspython

| Package     | Purpose                  |
|-------------|--------------------------|
| `requests`  | HTTP fetching            |
| `dnspython` | DNS record queries       |
| `socket`    | Port scanning, IP lookup |
| `ssl`       | TLS certificate parsing  |
| `concurrent.futures` | Parallel threads |

Python 3.8+ required.

---

## Usage

bash
python recon_tool.py

Enter a domain or URL when prompted:


Target (domain or URL): example.com

Both formats work:

example.com
https://example.com
http://example.com/path

---

## Build as Standalone Executable

bash
pip install pyinstaller
pyinstaller --onefile recon_tool.py

Output: `dist/recon_tool.exe` (Windows) or `dist/recon_tool` (Linux/macOS)
No Python installation needed on the target machine.

---

## Legal Notice

This tool performs **passive and semi-active reconnaissance**.
The subdomain enumeration and port scanning modules send direct
network traffic to the target.

**Only use against domains you own or have explicit written permission to test.**
Unauthorized scanning may violate local laws.

---

## Output Example


═══════════════════════════════════════════════════════
  1. HTTP Response & Headers
═══════════════════════════════════════════════════════
  ✔ Status Code: 200 (OK)
  ✔ Response Time: 312 ms
  ✘ Content-Security-Policy: MISSING
  ✘ Permissions-Policy: MISSING

═══════════════════════════════════════════════════════
  9. Security Summary
═══════════════════════════════════════════════════════

  Security Score: 65/100

  Issues Found:
  ✘  Missing header: Content-Security-Policy
  ✘  Missing header: Permissions-Policy
  ✘  Sensitive file exposed: /.env
  ✘  Dangerous port open: 3306 (MySQL)

---

## File Structure


recon_tool.py          # Main script (single file)
README.md              # This file
recon_*.json           # Output files (generated at runtime)
