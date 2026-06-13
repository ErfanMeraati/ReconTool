import socket
import ssl
import requests
import dns.resolver
import concurrent.futures
import json
import re
import datetime
from urllib.parse import urljoin, urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ─────────────────────────────────────────────
COLORS = {
    "green":  "\033[92m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "blue":   "\033[94m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def c(text, color):
    return f"{COLORS[color]}{text}{COLORS['reset']}"

def section(title):
    print(f"\n{c('═' * 55, 'cyan')}")
    print(f"{c(f'  {title}', 'bold')}")
    print(c('═' * 55, 'cyan'))

def ok(label, value):
    print(f"  {c('✔', 'green')} {c(label, 'yellow')}: {value}")

def warn(label, value):
    print(f"  {c('⚠', 'yellow')} {c(label, 'yellow')}: {value}")

def fail(label, value):
    print(f"  {c('✘', 'red')} {c(label, 'yellow')}: {value}")

# ─────────────────────────────────────────────
results = {}

def normalize_url(target):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")

def get_domain(url):
    return urlparse(url).hostname

# ══════════════════════════════════════════════
# 1. HTTP Response & Headers
# ══════════════════════════════════════════════
def check_http(url):
    section("1. HTTP Response & Headers")
    data = {}
    headers_to_check = [
        "Server", "X-Powered-By", "X-Generator", "Via",
        "X-Frame-Options", "X-Content-Type-Options",
        "Strict-Transport-Security", "Content-Security-Policy",
        "Referrer-Policy", "Permissions-Policy",
        "X-XSS-Protection", "Access-Control-Allow-Origin",
        "Cache-Control", "Content-Type", "ETag", "Last-Modified",
    ]
    security_headers = {
        "X-Frame-Options", "X-Content-Type-Options",
        "Strict-Transport-Security", "Content-Security-Policy",
        "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"
    }
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0"})
        ok("Status Code", f"{resp.status_code} ({resp.reason})")
        ok("Final URL", resp.url)
        ok("Response Time", f"{resp.elapsed.total_seconds() * 1000:.0f} ms")
        ok("Content Length", f"{len(resp.content):,} bytes")

        data["status"] = resp.status_code
        data["headers"] = {}

        print(f"\n  {c('── Headers ──', 'blue')}")
        for h in headers_to_check:
            val = resp.headers.get(h)
            if val:
                if h in security_headers:
                    ok(h, val)
                else:
                    ok(h, val)
                data["headers"][h] = val
            else:
                if h in security_headers:
                    fail(h, "MISSING")
                    data["headers"][h] = None

        # Cookies
        if resp.cookies:
            print(f"\n  {c('── Cookies ──', 'blue')}")
            data["cookies"] = []
            for cookie in resp.cookies:
                flags = []
                if cookie.secure: flags.append("Secure")
                if cookie.has_nonstandard_attr("HttpOnly"): flags.append("HttpOnly")
                flag_str = ", ".join(flags) if flags else c("No Secure/HttpOnly!", "red")
                ok(cookie.name, flag_str)
                data["cookies"].append({"name": cookie.name, "flags": flags})

        data["response"] = resp.text[:5000]
        results["http"] = data

    except requests.exceptions.SSLError:
        fail("SSL", "Certificate error")
    except requests.exceptions.ConnectionError:
        fail("Connection", "Failed to connect")
    except Exception as e:
        fail("Error", str(e))

# ══════════════════════════════════════════════
# 2. Technology Detection
# ══════════════════════════════════════════════
def detect_tech(url):
    section("2. Technology Detection")
    data = {}
    tech_signatures = {
        "WordPress":    [r"wp-content", r"wp-includes", r"WordPress"],
        "Joomla":       [r"Joomla!", r"/components/com_"],
        "Drupal":       [r"Drupal", r"/sites/default/"],
        "Laravel":      [r"laravel_session", r"Laravel"],
        "Django":       [r"csrfmiddlewaretoken", r"Django"],
        "React":        [r"react", r"__REACT"],
        "Vue.js":       [r"vue\.js", r"Vue\."],
        "Angular":      [r"ng-version", r"angular"],
        "jQuery":       [r"jquery"],
        "Bootstrap":    [r"bootstrap"],
        "Next.js":      [r"__NEXT_DATA__", r"_next/static"],
        "Shopify":      [r"Shopify\.theme", r"cdn\.shopify"],
        "Cloudflare":   [r"cloudflare", r"__cf_bm"],
        "Google Analytics": [r"google-analytics\.com", r"gtag\("],
        "ASP.NET":      [r"__VIEWSTATE", r"ASP\.NET"],
        "PHP":          [r"\.php", r"PHPSESSID"],
        "Ruby on Rails":[r"authenticity_token"],
    }
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        body = resp.text
        server_header = resp.headers.get("Server", "")
        powered_by = resp.headers.get("X-Powered-By", "")

        found = []
        for tech, patterns in tech_signatures.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE) or \
                   re.search(pattern, server_header, re.IGNORECASE) or \
                   re.search(pattern, powered_by, re.IGNORECASE):
                    found.append(tech)
                    break

        if found:
            for t in found:
                ok("Detected", t)
        else:
            warn("Tech", "Nothing obvious detected")

        # Meta tags
        title = re.findall(r"<title>(.*?)</title>", body, re.IGNORECASE)
        desc  = re.findall(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', body, re.IGNORECASE)
        generator = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', body, re.IGNORECASE)

        if title:    ok("Title", title[0])
        if desc:     ok("Description", desc[0][:100])
        if generator: ok("Generator", generator[0])

        data["technologies"] = found
        results["tech"] = data

    except Exception as e:
        fail("Error", str(e))

# ══════════════════════════════════════════════
# 3. DNS Records
# ══════════════════════════════════════════════
def dns_lookup(domain):
    section("3. DNS Records")
    if not DNS_AVAILABLE:
        warn("dnspython", "Not installed — pip install dnspython")
        return
    data = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            vals = []
            for r in answers:
                vals.append(r.to_text())
                ok(rtype, r.to_text())
            data[rtype] = vals
        except Exception:
            pass
    results["dns"] = data

# ══════════════════════════════════════════════
# 4. SSL/TLS Certificate
# ══════════════════════════════════════════════
def check_ssl(domain):
    section("4. SSL/TLS Certificate")
    data = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            cipher = s.cipher()

        subject = dict(x[0] for x in cert["subject"])
        issuer  = dict(x[0] for x in cert["issuer"])
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days

        ok("Common Name",   subject.get("commonName", "?"))
        ok("Issuer",        issuer.get("organizationName", "?"))
        ok("Valid Until",   cert["notAfter"])

        if days_left > 30:
            ok("Days Left", str(days_left))
        elif days_left > 0:
            warn("Days Left", f"{days_left} (expiring soon!)")
        else:
            fail("Days Left", "EXPIRED!")

        ok("Cipher Suite",  cipher[0])
        ok("TLS Version",   cipher[1])

        # SANs
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if sans:
            ok("SANs", ", ".join(sans[:5]) + ("..." if len(sans) > 5 else ""))

        data = {"issuer": issuer, "days_left": days_left,
                "cipher": cipher[0], "tls": cipher[1], "sans": sans}
        results["ssl"] = data

    except ssl.SSLError as e:
        fail("SSL Error", str(e))
    except Exception as e:
        fail("Error", str(e))

# ══════════════════════════════════════════════
# 5. Open Ports
# ══════════════════════════════════════════════
def scan_ports(domain):
    section("5. Open Ports (Common)")
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 465: "SMTPS", 587: "SMTP/TLS",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    open_ports = []

    def scan(port):
        try:
            s = socket.socket()
            s.settimeout(1.5)
            if s.connect_ex((domain, port)) == 0:
                return port
            s.close()
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan, p): p for p in common_ports}
        for f in concurrent.futures.as_completed(futures):
            port = f.result()
            if port:
                name = common_ports.get(port, "Unknown")
                ok(f"Port {port}", f"{name} — OPEN")
                open_ports.append(port)

    if not open_ports:
        warn("Ports", "No common ports open / filtered")

    results["ports"] = open_ports

# ══════════════════════════════════════════════
# 6. Sensitive Files & Paths
# ══════════════════════════════════════════════
def check_sensitive(url):
    section("6. Sensitive Files & Exposed Paths")
    paths = [
        "robots.txt", "sitemap.xml", ".git/HEAD", ".env",
        "wp-config.php", "phpinfo.php", "info.php",
        "admin/", "administrator/", "wp-admin/",
        "backup/", "backup.zip", "backup.sql",
        "config.php", "config.json", "database.yml",
        ".htaccess", "web.config", "crossdomain.xml",
        "api/", "api/v1/", "swagger/", "swagger-ui.html",
        "graphql", ".well-known/security.txt",
        "server-status", "server-info",
    ]
    found = []

    def check(path):
        try:
            full = urljoin(url + "/", path)
            r = requests.get(full, timeout=5,
                             headers={"User-Agent": "Mozilla/5.0"},
                             allow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                return (path, r.status_code)
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(check, p) for p in paths]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                path, code = res
                if code == 200:
                    fail(f"/{path}", f"HTTP {code} — Accessible!")
                elif code == 403:
                    warn(f"/{path}", f"HTTP {code} — Exists but Forbidden")
                else:
                    ok(f"/{path}", f"HTTP {code}")
                found.append(res)

    if not found:
        ok("Sensitive", "Nothing obvious found")

    results["sensitive"] = found

# ══════════════════════════════════════════════
# 7. Subdomain Enumeration
# ══════════════════════════════════════════════
def enum_subdomains(domain):
    section("7. Subdomain Enumeration")
    wordlist = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "admin", "cpanel", "whm", "panel", "dashboard",
        "api", "api2", "dev", "staging", "test", "beta",
        "shop", "store", "blog", "forum", "m", "mobile",
        "cdn", "static", "assets", "media", "img",
        "vpn", "remote", "portal", "auth", "sso",
        "ns1", "ns2", "mx", "mx1", "mail2",
        "git", "gitlab", "jenkins", "ci", "jira", "confluence",
        "db", "database", "mysql", "redis", "elastic",
        "app", "app2", "web", "web2", "old", "new",
    ]
    found = []

    def check_sub(sub):
        full = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(2)
            ip = socket.gethostbyname(full)
            return (full, ip)
        except:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(check_sub, s) for s in wordlist]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                sub, ip = res
                ok(sub, ip)
                found.append(res)

    if not found:
        warn("Subdomains", "None found in wordlist")

    results["subdomains"] = found

# ══════════════════════════════════════════════
# 8. IP & Geo Info
# ══════════════════════════════════════════════
def ip_geo(domain):
    section("8. IP & Geo Information")
    try:
        ip = socket.gethostbyname(domain)
        ok("Resolved IP", ip)

        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
        data = r.json()

        fields = [
            ("org",          "Organization / ISP"),
            ("country_name", "Country"),
            ("region",       "Region"),
            ("city",         "City"),
            ("timezone",     "Timezone"),
            ("latitude",     "Latitude"),
            ("longitude",    "Longitude"),
            ("asn",          "ASN"),
        ]
        for key, label in fields:
            val = data.get(key)
            if val:
                ok(label, str(val))

        results["geo"] = data
    except Exception as e:
        fail("Error", str(e))

# ══════════════════════════════════════════════
# 9. Security Summary
# ══════════════════════════════════════════════
def security_summary():
    section("9. Security Summary")
    score = 100
    issues = []

    http_data = results.get("http", {})
    headers   = http_data.get("headers", {})

    security_headers = [
        "X-Frame-Options", "X-Content-Type-Options",
        "Strict-Transport-Security", "Content-Security-Policy",
        "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection"
    ]
    for h in security_headers:
        if not headers.get(h):
            score -= 5
            issues.append(f"Missing header: {h}")

    # Cookie flags
    for cookie in http_data.get("cookies", []):
        if "Secure" not in cookie.get("flags", []):
            score -= 5
            issues.append(f"Cookie '{cookie['name']}' missing Secure flag")

    # SSL
    ssl_data = results.get("ssl", {})
    days = ssl_data.get("days_left", 999)
    if days < 30:
        score -= 20
        issues.append(f"SSL expires in {days} days")

    # Sensitive files
    for path, code in results.get("sensitive", []):
        if code == 200:
            score -= 10
            issues.append(f"Sensitive file exposed: /{path}")

    # Dangerous ports
    dangerous = {21: "FTP", 23: "Telnet", 3306: "MySQL",
                 3389: "RDP", 27017: "MongoDB", 6379: "Redis"}
    for port in results.get("ports", []):
        if port in dangerous:
            score -= 10
            issues.append(f"Dangerous port open: {port} ({dangerous[port]})")

    score = max(0, score)

    if score >= 80:
        color = "green"
    elif score >= 50:
        color = "yellow"
    else:
        color = "red"

    print(f"\n  Security Score: {c(str(score) + '/100', color)}\n")

    if issues:
        print(f"  {c('Issues Found:', 'yellow')}")
        for i in issues:
            fail("", i)
    else:
        ok("Status", "No major issues detected")

# ══════════════════════════════════════════════
# Save Results
# ══════════════════════════════════════════════
def save_results(domain):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"recon_{domain}_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    print(f"\n  {c('Results saved to:', 'cyan')} {filename}")

# ══════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════
def main():
    print(c("""
╔═══════════════════════════════════════════════════════╗
║          Web Recon & Analysis Tool  v1.0              ║
║         Passive reconnaissance — ethical use          ║
╚═══════════════════════════════════════════════════════╝""", "cyan"))

    target = input(c("\n  Target (domain or URL): ", "bold")).strip()
    if not target:
        return

    url    = normalize_url(target)
    domain = get_domain(url)

    print(f"\n  {c('Target:', 'yellow')} {url}")
    print(f"  {c('Domain:', 'yellow')} {domain}")
    print(f"  {c('Time:',   'yellow')} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    check_http(url)
    detect_tech(url)
    dns_lookup(domain)
    check_ssl(domain)
    scan_ports(domain)
    check_sensitive(url)
    enum_subdomains(domain)
    ip_geo(domain)
    security_summary()

    save = input(c("\n  Save results to JSON? (y/n): ", "bold")).strip().lower()
    if save == "y":
        save_results(domain)

    print(c("\n  Done.\n", "green"))

if __name__ == "__main__":
    main()
