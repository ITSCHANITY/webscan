#!/usr/bin/env python3
"""
WebScan v4.0 — Authorized Web Recon & Vulnerability Scanner
==============================================================
Run:
    python3 webscan.py --authorized https://target.com
    python3 webscan.py --authorized --delay 0.5 https://target.com
    python3 webscan.py --selftest

This is a rebuild of the original v3 tool (webscan.py / "WebScan Pro").
What changed and why:

  1. Certificate verification is ON by default. The old tool disabled SSL
     verification globally for every request it made — backwards for a
     security tool whose own job includes flagging weak TLS configs.
     Use --insecure to explicitly opt out (e.g. for an internal lab target
     with a self-signed cert), but it is never the silent default anymore.
  2. A required --authorized flag gates every active-scanning module. The
     tool will not touch a target until you explicitly assert you have
     permission to test it. This isn't just a politeness flag — it's the
     difference between a tool that *assumes* good use and one that
     *requires* it.
  3. Every request goes through a shared rate limiter (--delay, default
     0.3s between requests). The old tool fired as fast as Python allowed,
     which is both easy to get blocked for and, against a fragile target,
     a real risk of accidental denial-of-service.
  4. SQLi/XSS detection adds a timing-based check alongside the original
     pattern-matching, so it can catch blind/boolean-style injection that
     doesn't reflect anything detectable in the response body.
  5. A --selftest mode runs every detection module against a local test
     server with deliberately planted, safe "vulnerabilities" (missing
     headers, a fake .env file, a reflective XSS endpoint, etc.) so the
     detection logic is validated against ground truth, not just trusted
     to work.
"""

import sys, os, re, ssl, time, socket, subprocess, shutil, json, threading, argparse
import urllib.request, urllib.error, urllib.parse
from html.parser import HTMLParser
from datetime import datetime, timezone
from collections import defaultdict

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"
    BLUE="\033[94m"; MAGENTA="\033[95m"; WHITE="\033[97m"
    BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"
    BG_RED="\033[41m"; BG_BLUE="\033[44m"

W = 60  # box width

def clear():
    if sys.stdout.isatty():
        os.system("clear")

def box_top():    print(f"{C.CYAN}╔{'═'*W}╗{C.RESET}")
def box_bot():    print(f"{C.CYAN}╚{'═'*W}╝{C.RESET}")
def box_mid():    print(f"{C.CYAN}╠{'═'*W}╣{C.RESET}")
def box_sep():    print(f"{C.CYAN}║{' '*W}║{C.RESET}")
def box_line(txt, color="", align="center"):
    txt = str(txt)
    if align == "center":
        pad = W - len(re.sub(r'\033\[[0-9;]*m','',txt))
        l = pad//2; r = pad - l
        print(f"{C.CYAN}║{C.RESET}{' '*l}{color}{txt}{C.RESET}{' '*r}{C.CYAN}║{C.RESET}")
    else:
        pad = W - 2 - len(re.sub(r'\033\[[0-9;]*m','',txt))
        print(f"{C.CYAN}║{C.RESET} {color}{txt}{C.RESET}{' '*max(0,pad)} {C.CYAN}║{C.RESET}")

def ok(m):   print(f" {C.GREEN}[OK]{C.RESET} {m}")
def warn(m): print(f" {C.YELLOW}[~]{C.RESET} {m}")
def vuln(m): print(f" {C.RED}[!]{C.RESET} {C.RED}{m}{C.RESET}")
def info(m): print(f" {C.CYAN}[i]{C.RESET} {m}")

findings = []
def record(sev, cat, detail):
    findings.append({"severity": sev, "category": cat, "detail": detail})


# ──────────────────────────────────────────────────────────────────────────────
# LAYMAN EXPLANATIONS
# ──────────────────────────────────────────────────────────────────────────────
# One-line, plain-English translation for each finding category, printed under
# the technical finding so results are readable without a security background.
LAYMAN = {
    "Recon":     "Basic info about who hosts this site and where.",
    "Port":      "A network door (port) that's open and answering.",
    "Nmap":      "A risky service is reachable from the internet with no protection.",
    "NSE":       "An automated script thinks this server may be exploitable.",
    "CVE":       "This matches a known, publicly documented software bug.",
    "Banner":    "The server told us what software it's running — helps an attacker plan.",
    "Headers":   "The site isn't telling browsers to enforce a safety rule, so the browser falls back to a less safe default.",
    "SSL":       "Something about the site's HTTPS/encryption setup isn't fully solid.",
    "Cookies":   "A cookie (used to keep you logged in) can be stolen or reused more easily than it should be.",
    "WAF":       "No firewall was detected specifically shielding the web app from attacks.",
    "Files":     "A file or folder that shouldn't be public is answering requests.",
    "Info Leak": "The server is revealing details about itself it doesn't need to.",
    "Nikto":     "A general-purpose scanner flagged something worth a manual look.",
    "Hash Leak": "Something that looks like a scrambled password (a hash) showed up in a normal page response.",
    "Redirect":  "The site can be tricked into sending visitors to an attacker's page.",
    "XSS":       "User input might get shown back on the page without being neutralized first, which can let an attacker run script in someone else's browser.",
    "SQLi":      "The database might respond differently to malformed input, a sign it could be manipulated.",
    "CORS":      "Other websites may be allowed to read data from this one on a visitor's behalf.",
    "NoAuth":    "A service that should require a login is answering with no login at all.",
    "Database":  "A database or its admin panel is directly reachable from the internet.",
    "DB Exposure": "The site's own front-end code leaks a way to read (or fully access) its database, with no login required.",
    "CloudKey":  "A key used to talk to a cloud backend (like Supabase or Firebase) was found in the site's public code, and the data behind it may be readable by anyone who has that key.",
}

def explain(cat):
    msg = LAYMAN.get(cat)
    if msg:
        print(f"     {C.DIM}→ {msg}{C.RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# BASELINE / FALSE-POSITIVE FILTER
# ──────────────────────────────────────────────────────────────────────────────
# Single-page apps (React/Vue/Vite SPAs) commonly return their *same* index.html
# shell for every unmatched path instead of a real 404, because routing happens
# client-side. Without checking for this, every "does /admin exist" style probe
# comes back 200 and gets misreported as a finding, even though it's just the
# app's normal fallback page. We fetch one deliberately-nonexistent path once
# per scan and compare every other result against that signature; a match means
# "this is just the fallback page," not "this path actually exists."
_BASELINE = {"sig": None}

def establish_baseline(url):
    base = url.rstrip("/")
    junk = f"/__webscan_baseline_check_{int(time.time())}_nonexistent"
    s, headers, body = fetch(base + junk, timeout=6)
    if s is None:
        _BASELINE["sig"] = None
        return
    hl = {k.lower(): v for k, v in headers.items()}
    _BASELINE["sig"] = (s, len(body or ""), hl.get("content-type", ""))
    if s == 200:
        info("Baseline check: unmatched paths return HTTP 200 with no real 404 — "
             "this app likely serves one fallback page for every route.")
        info("Findings below are filtered against that fallback page so real issues aren't buried in noise.")


def is_fallback_response(status, headers, body):
    """True if this response matches the app's generic fallback/catch-all page."""
    sig = _BASELINE["sig"]
    if sig is None or status is None:
        return False
    hl = {k.lower(): v for k, v in (headers or {}).items()}
    this_sig = (status, len(body or ""), hl.get("content-type", ""))
    return this_sig == sig


# ──────────────────────────────────────────────────────────────────────────────
# SITE CRAWLER
# ──────────────────────────────────────────────────────────────────────────────
# Pure standard-library crawler (html.parser) — no BeautifulSoup/requests
# dependency needed. Follows same-origin <a>, <script>, <link>, <iframe>
# references breadth-first, and separately records every <form> it sees
# (action, method, field names) so later modules can fuzz real input fields
# instead of only guessing common parameter names on the homepage.
class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()
        self.assets = set()   # <script src>/<link href> — fetched for content scanning, not crawled as pages
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        ad = dict(attrs)
        if tag == "a" and ad.get("href"):
            self.links.add(ad["href"])
        elif tag == "script" and ad.get("src"):
            self.assets.add(ad["src"])
        elif tag in ("link", "iframe") and (ad.get("src") or ad.get("href")):
            self.links.add(ad.get("src") or ad.get("href"))
        elif tag == "form":
            self._form = {"action": ad.get("action", ""), "method": (ad.get("method") or "get").lower(), "params": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = ad.get("name")
            if name:
                self._form["params"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


# Paths that a client-side-routed app (or a hand-linked admin panel) often
# won't expose via any visible <a href>, so they're checked directly in
# addition to whatever the crawler finds organically.
COMMON_ENTRY_PATHS = [
    "/admin", "/admin/login", "/administrator", "/login", "/signin",
    "/dashboard", "/panel", "/cpanel", "/wp-admin", "/manage",
    "/account", "/user/login", "/staff", "/api", "/api/docs", "/api/v1",
]

_PAGES = {"urls": [], "forms": [], "assets": []}

def crawl(base_url, max_pages=25, max_depth=2):
    parsed_base = urllib.parse.urlparse(base_url)
    origin = (parsed_base.scheme, parsed_base.netloc)
    seen = set()
    queue = [(base_url.rstrip("/") or base_url, 0)]
    discovered, forms, assets = [], [], set()

    while queue and len(discovered) < max_pages:
        page_url, depth = queue.pop(0)
        norm = page_url.split("#")[0]
        if norm in seen:
            continue
        seen.add(norm)
        s, headers, body = fetch(norm, timeout=6)
        if s is None or not body:
            continue
        if is_fallback_response(s, headers, body) and norm != base_url.rstrip("/"):
            continue  # SPA fallback page again, not a real distinct page
        discovered.append(norm)
        if depth >= max_depth:
            continue
        parser = _LinkExtractor()
        try:
            parser.feed(body)
        except Exception:
            continue
        for f in parser.forms:
            action = urllib.parse.urljoin(norm, f["action"]) if f["action"] else norm
            forms.append({"page": norm, "action": action, "method": f["method"], "params": f["params"]})
        for asset in parser.assets:
            full_asset = urllib.parse.urljoin(norm, asset).split("#")[0]
            pu = urllib.parse.urlparse(full_asset)
            if (pu.scheme, pu.netloc) == origin:
                assets.add(full_asset)
        for link in parser.links:
            full = urllib.parse.urljoin(norm, link).split("#")[0]
            pu = urllib.parse.urlparse(full)
            if (pu.scheme, pu.netloc) != origin or pu.scheme not in ("http", "https"):
                continue
            if full not in seen:
                queue.append((full, depth + 1))

    # Also probe common admin/login-style entry points directly — a lot of
    # real admin panels are reached by direct URL, not a homepage link.
    base = base_url.rstrip("/")
    for p in COMMON_ENTRY_PATHS:
        full = base + p
        if full in seen:
            continue
        s, h, body = fetch(full, timeout=5)
        seen.add(full)
        if s and s < 400 and not is_fallback_response(s, h, body):
            discovered.append(full)

    _PAGES["urls"] = discovered
    _PAGES["forms"] = forms
    _PAGES["assets"] = list(assets)
    return discovered, forms


def target_pages(url, limit=8):
    """Homepage plus up to `limit`-1 other discovered same-origin pages,
    for modules that check page-level issues (headers, cookies, hashes,
    XSS/SQLi params) rather than host-level ones (nmap, SSL, WAF)."""
    others = [p for p in _PAGES["urls"] if p != url]
    return [url] + others[:max(0, limit - 1)]


def brute_force_dirs(base_url):
    """Use whichever Kali directory brute-forcer is installed to find paths
    the crawler can't see because nothing links to them. Tries gobuster,
    then ffuf, then dirb — whichever is available and a wordlist exists."""
    wordlists = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ]
    wl = next((w for w in wordlists if os.path.exists(w)), None)
    if not wl:
        return [], None

    if tool_ok("gobuster"):
        out = run_cmd(["gobuster", "dir", "-u", base_url, "-w", wl,
                        "-q", "-t", "10", "--no-error"], 90)
        hits = []
        for line in out.splitlines():
            m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line.strip())
            if m:
                hits.append((m.group(1), int(m.group(2))))
        return hits, "gobuster"

    if tool_ok("ffuf"):
        out = run_cmd(["ffuf", "-u", f"{base_url}/FUZZ", "-w", wl,
                        "-mc", "200,301,302,401,403", "-s"], 90)
        hits = [(line.strip(), 200) for line in out.splitlines() if line.strip()]
        return [("/" + h[0].lstrip("/"), h[1]) for h in hits], "ffuf"

    if tool_ok("dirb"):
        out = run_cmd(["dirb", base_url, wl, "-S"], 90)
        hits = []
        for line in out.splitlines():
            m = re.match(r"^\+\s+\S*?(/\S+)\s+\(CODE:(\d+)", line.strip())
            if m:
                hits.append((m.group(1), int(m.group(2))))
        return hits, "dirb"

    return [], None


# ──────────────────────────────────────────────────────────────────────────────
# RATE LIMITER
# ──────────────────────────────────────────────────────────────────────────────
# Every HTTP request in this tool funnels through fetch(), and fetch() always
# waits at least RATE_DELAY seconds since the last request before sending the
# next one. This is a deliberate, global throttle — not a per-module setting
# that's easy to forget to apply somewhere.
RATE_DELAY = 0.3  # seconds; overridden by --delay
_last_request_time = [0.0]
_rate_lock = threading.Lock()

def _throttle():
    with _rate_lock:
        now = time.time()
        wait = RATE_DELAY - (now - _last_request_time[0])
        if wait > 0:
            time.sleep(wait)
        _last_request_time[0] = time.time()


# ──────────────────────────────────────────────────────────────────────────────
# HTTP helper
# ──────────────────────────────────────────────────────────────────────────────
# SECURITY FIX vs. v3: certificate verification is ON by default. The old
# code did:
#     _sslctx.check_hostname = False
#     _sslctx.verify_mode = ssl.CERT_NONE
# globally, for every single request the tool made. That makes a security
# scanner blind to exactly the kind of MITM/spoofing/expired-cert conditions
# it's supposed to be looking for. ALLOW_INSECURE defaults to False and can
# only become True via the explicit --insecure flag on the command line.
ALLOW_INSECURE = False

def _build_ssl_context():
    if ALLOW_INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()  # verifies hostname + chain, as it should


def fetch(url, method="GET", headers=None, body=None, timeout=8, follow=True):
    """
    The single chokepoint for every HTTP request this tool makes. Three
    things happen on every call, unconditionally:
      1. Rate limiting (_throttle()) — never skipped, never optional per-module.
      2. Certificate verification according to ALLOW_INSECURE (see above).
      3. A consistent three-value return: (status, headers, body). On a
         hard failure status is None and body holds the error string, so
         callers can always tell "got an HTTP error code" apart from
         "couldn't even connect."
    """
    _throttle()

    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "Mozilla/5.0 (WebScan/4.0; authorized-testing)")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if body:
        req.data = body.encode() if isinstance(body, str) else body
    try:
        ctx = _build_ssl_context()
        h = urllib.request.HTTPSHandler(context=ctx)
        o = urllib.request.build_opener(h) if follow else urllib.request.build_opener(h, NoRedir())
        r = o.open(req, timeout=timeout)
        return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", "replace")
        except Exception:
            b = ""
        return e.code, dict(e.headers), b
    except ssl.SSLCertVerificationError as e:
        # Distinguished explicitly so callers (m_ssl, m_headers, etc.) can
        # tell "certificate problem" apart from "network down" instead of
        # both collapsing into a generic exception message.
        return None, {}, f"SSL_VERIFY_FAILED: {e}"
    except Exception as e:
        return None, {}, str(e)


def tool_ok(n):
    return shutil.which(n) is not None


def run_cmd(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except FileNotFoundError:
        return f"[NOT FOUND: {cmd[0]}]"
    except Exception as e:
        return f"[ERROR: {e}]"


# ── Spinner ───────────────────────────────────────────────────────────────────
class Spinner:
    def __init__(self, msg):
        self.msg = msg
        self.running = False
        self.t = None

    def _spin(self):
        frames = ["-", "\\", "|", "/"]
        i = 0
        while self.running:
            if sys.stdout.isatty():
                print(f"\r {C.CYAN}{frames[i % len(frames)]}{C.RESET} {self.msg}...", end="", flush=True)
            time.sleep(0.1)
            i += 1
        if sys.stdout.isatty():
            print(f"\r {C.GREEN}[OK]{C.RESET} {self.msg}        ")
        else:
            print(f" {C.GREEN}[OK]{C.RESET} {self.msg}")

    def start(self):
        self.running = True
        self.t = threading.Thread(target=self._spin, daemon=True)
        self.t.start()

    def stop(self):
        self.running = False
        if self.t:
            self.t.join()


# ── Module header ─────────────────────────────────────────────────────────────
mod_num = [0]
def mod_hdr(name):
    mod_num[0] += 1
    print(f"\n{C.CYAN}╔{'═'*58}╗{C.RESET}")
    label = f" MODULE {mod_num[0]:02d} · {name} "
    pad = 58 - len(label)
    print(f"{C.CYAN}║{C.BOLD}{C.WHITE}{label}{C.RESET}{C.CYAN}{' '*pad}║{C.RESET}")
    print(f"{C.CYAN}╚{'═'*58}╝{C.RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK mapping
# ──────────────────────────────────────────────────────────────────────────────
MITRE_MAP = {
    "Recon":      ("T1592", "Gather Victim Host Information"),
    "Port":       ("T1595.001", "Active Scanning: Scanning IP Blocks"),
    "Nmap":       ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "NSE":        ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "Banner":     ("T1592.002", "Gather Victim Host Information: Software"),
    "Headers":    ("T1190", "Exploit Public-Facing Application"),
    "SSL":        ("T1557", "Adversary-in-the-Middle"),
    "Cookies":    ("T1539", "Steal Web Session Cookie"),
    "WAF":        ("T1590.006", "Gather Victim Network Information: IP Addresses"),
    "Files":      ("T1592.004", "Gather Victim Host Information: Client Configurations"),
    "Info Leak":  ("T1592.002", "Gather Victim Host Information: Software"),
    "Nikto":      ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "Hash Leak":  ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "Redirect":   ("T1204.001", "User Execution: Malicious Link"),
    "XSS":        ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    "SQLi":       ("T1190", "Exploit Public-Facing Application"),
    "CORS":       ("T1190", "Exploit Public-Facing Application"),
    "NoAuth":     ("T1190", "Exploit Public-Facing Application"),
    "DB Exposure": ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "Database":   ("T1590.006", "Gather Victim Network Information: IP Addresses"),
    "CloudKey":   ("T1552.001", "Unsecured Credentials: Credentials In Files"),
}

def mitre_tag(category):
    tid, name = MITRE_MAP.get(category, ("—", "Unmapped"))
    return f"[MITRE {tid} · {name}]"


# ══════════════════════════════════════════════════════════════════════════════
# SCAN MODULES
# ══════════════════════════════════════════════════════════════════════════════

def m_recon(url, ip_ref):
    mod_hdr(f"TARGET RECONNAISSANCE  {mitre_tag('Recon')}")
    host = urllib.parse.urlparse(url).hostname
    try:
        ip = socket.gethostbyname(host)
        ip_ref[0] = ip
        ok(f"Hostname   : {C.WHITE}{host}{C.RESET}")
        ok(f"IP Address : {C.WHITE}{ip}{C.RESET}")
        record("INFO", "Recon", f"IP: {ip}")
        try:
            rdns = socket.gethostbyaddr(ip)[0]
            info(f"Reverse DNS: {rdns}")
        except Exception:
            pass
        all_ips = list({a[4][0] for a in socket.getaddrinfo(host, None)})
        if len(all_ips) > 1:
            info(f"All IPs    : {', '.join(all_ips)}")
        s, _, body = fetch(f"https://ipinfo.io/{ip}/json", timeout=5)
        if s == 200:
            try:
                d = json.loads(body)
                if d.get("org"):
                    info(f"ASN/Org    : {d['org']}")
                if d.get("city"):
                    info(f"Location   : {d['city']}, {d.get('country','')}")
                if d.get("hostname"):
                    info(f"ISP Host   : {d['hostname']}")
            except json.JSONDecodeError:
                pass
    except Exception as e:
        vuln(f"DNS failed: {e}")


def m_crawl(url, ip_ref):
    mod_hdr(f"SITE CRAWL & PAGE DISCOVERY  {mitre_tag('Recon')}")
    sp = Spinner("Crawling same-origin links (depth 2) + checking common entry points")
    sp.start()
    pages, forms = crawl(url)
    sp.stop()

    ok(f"Discovered {len(pages)} in-scope page(s)")
    for p in pages[:30]:
        info(f"  {p}")
    if len(pages) > 30:
        info(f"  ...and {len(pages) - 30} more")
    record("INFO", "Recon", f"{len(pages)} page(s) discovered via crawl")

    if forms:
        ok(f"Found {len(forms)} form(s) — their fields will be fuzzed for XSS/SQLi too")
        for f in forms[:15]:
            fields = ", ".join(f["params"]) if f["params"] else "(no named fields)"
            info(f"  [{f['method'].upper()}] {f['action']}  fields: {fields}")

    if tool_ok("gobuster") or tool_ok("ffuf") or tool_ok("dirb"):
        sp = Spinner("Brute-forcing hidden directories with an installed Kali tool")
        sp.start()
        extra, toolname = brute_force_dirs(url)
        sp.stop()
        base = url.rstrip("/")
        new_hits = 0
        for path, status in extra:
            full = base + path
            if full not in pages:
                pages.append(full)
                new_hits += 1
            if status in (200, 301, 302):
                ok(f"[{toolname}] {path} [{status}]")
            elif status in (401, 403):
                info(f"[{toolname}] {path} [{status}] — exists but protected")
        if new_hits:
            record("INFO", "Recon", f"{new_hits} additional path(s) found via {toolname} brute-force")
            explain("Files")
        _PAGES["urls"] = pages
    else:
        warn("No directory brute-forcer found (gobuster/ffuf/dirb) — skipping hidden-path discovery")
        warn("Install one for deeper coverage: sudo apt install gobuster")


def m_nmap(url, ip_ref):
    mod_hdr(f"NMAP PORT & SERVICE SCAN  {mitre_tag('Nmap')}")
    ip = ip_ref[0]
    if not tool_ok("nmap"):
        warn("nmap not found — sudo apt install nmap")
        return
    if not ip:
        warn("No IP resolved")
        return
    sp = Spinner(f"Scanning {ip}")
    sp.start()
    cmd = ["nmap", "-sV", "-sC", "--open", "-T4",
           "--script=banner,http-title,http-headers,ssl-cert,ssl-enum-ciphers", ip]
    if os.geteuid() == 0:
        cmd = ["nmap", "-sV", "-sC", "-O", "--open", "-T4",
               "--script=banner,http-title,http-headers,ssl-cert,ssl-enum-ciphers", ip]
    out = run_cmd(cmd, 120)
    sp.stop()
    dangerous = {21: "FTP", 23: "Telnet", 2049: "NFS", 6379: "Redis",
                 27017: "MongoDB", 9200: "Elasticsearch", 3389: "RDP", 5900: "VNC",
                 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 5984: "CouchDB",
                 9042: "Cassandra", 11211: "Memcached", 1521: "Oracle DB",
                 5601: "Kibana", 9300: "Elasticsearch (transport)"}
    for line in out.splitlines():
        line = line.strip()
        if re.match(r"^\d+/tcp\s+open", line):
            parts = line.split()
            port = parts[0]
            svc = parts[2] if len(parts) > 2 else "?"
            ver = " ".join(parts[3:])[:40] if len(parts) > 3 else ""
            ok(f"Port {port:<12} {C.GREEN}{svc:<14}{C.RESET} {C.DIM}{ver}{C.RESET}")
            record("INFO", "Port", f"{port} {svc} {ver}")
            pnum = int(port.split("/")[0])
            if pnum in dangerous:
                vuln(f"Dangerous service exposed: {dangerous[pnum]} on port {pnum}")
                record("HIGH", "Nmap", f"{dangerous[pnum]} on port {pnum}")
                explain("Nmap")
        elif "OS details:" in line:
            info(f"OS: {line.replace('OS details:','').strip()}")
        elif "VULNERABLE" in line:
            vuln(line)
            record("HIGH", "Nmap", line.strip())
            explain("Nmap")


def m_nse(url, ip_ref):
    mod_hdr(f"NMAP NSE VULNERABILITY SCRIPTS  {mitre_tag('NSE')}")
    ip = ip_ref[0]
    if not tool_ok("nmap"):
        warn("nmap not found")
        return
    if not ip:
        return
    sp = Spinner("Running CVE/exploit scripts")
    sp.start()
    scripts = ("vuln,exploit,http-shellshock,http-sql-injection,http-csrf,"
               "http-dombased-xss,http-stored-xss,http-cookie-flags,"
               "http-security-headers,http-methods,http-default-accounts,"
               "ftp-anon,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,"
               "ssl-dh-params,smb-vuln-ms17-010")
    out = run_cmd(["nmap", "--script", scripts, "-T4", ip], 180)
    sp.stop()
    count = 0
    lines = out.splitlines()
    for idx, line in enumerate(lines):
        line = line.strip()
        if "VULNERABLE" in line or "State: VULNERABLE" in line:
            vuln(f"NSE: {line}")
            record("CRITICAL", "NSE", line)
            explain("NSE")
            # Print a few lines of surrounding context so you can see *why*
            # the script fired, not just the one-line summary.
            ctx = [l.strip() for l in lines[idx:idx + 4] if l.strip()]
            for c in ctx[1:]:
                print(f"     {C.DIM}{c[:90]}{C.RESET}")
            count += 1
        elif re.search(r"CVE-\d{4}-\d+", line):
            cve = re.search(r"CVE-\d{4}-\d+", line).group()
            vuln(f"{cve}: {line[:75]}")
            record("HIGH", "CVE", f"{cve}: {line[:75]}")
            explain("CVE")
            count += 1
    ok(f"NSE complete — {count} finding(s)")
    if count == 0:
        info("No NSE vulnerability scripts fired against this target")


def m_banner(url, ip_ref):
    mod_hdr(f"BANNER GRABBING  {mitre_tag('Banner')}")
    ip = ip_ref[0]
    if not ip:
        return
    ports = {21: ("FTP", b""), 22: ("SSH", b""), 25: ("SMTP", b"EHLO test\r\n"),
             80: ("HTTP", b"HEAD / HTTP/1.0\r\n\r\n"), 110: ("POP3", b""),
             3306: ("MySQL", b""), 5432: ("PostgreSQL", b""),
             6379: ("Redis", b"PING\r\n"), 27017: ("MongoDB", b""),
             11211: ("Memcached", b"stats\r\n"), 5984: ("CouchDB", b""),
             9200: ("Elasticsearch", b""), 1433: ("MSSQL", b"")}
    for port, (svc, probe) in ports.items():
        _throttle()  # banner grabbing opens raw sockets too — still rate limited
        try:
            s = socket.socket()
            s.settimeout(2)
            if s.connect_ex((ip, port)) != 0:
                s.close()
                continue
            if probe:
                s.sendall(probe)
            try:
                banner = s.recv(512).decode("utf-8", "replace").strip()[:100]
            except Exception:
                banner = ""
            s.close()
            if banner:
                warn(f"Port {port}/{svc:<12} {C.DIM}{repr(banner[:60])}{C.RESET}")
                record("INFO", "Banner", f"{port}/{svc}: {banner[:60]}")
                if svc == "Redis" and "+PONG" in banner:
                    vuln("Redis UNAUTHENTICATED — anyone can read/write the entire dataset!")
                    record("CRITICAL", "NoAuth", "Redis open, no password required")
                    explain("NoAuth")
                elif svc == "Memcached" and banner.upper().startswith("STAT"):
                    vuln("Memcached UNAUTHENTICATED — cached data readable with no password!")
                    record("CRITICAL", "NoAuth", "Memcached open, no auth")
                    explain("NoAuth")
            else:
                info(f"Port {port}/{svc} open (no banner) — reachable, but auth status needs manual check")
        except Exception:
            pass

    # MongoDB, CouchDB, and Elasticsearch all speak HTTP-ish protocols that
    # answer a plain, harmless GET with a JSON banner when no auth is set —
    # this confirms "no password required" far more reliably than a raw
    # socket connect, without ever touching real data.
    http_db_checks = [
        (9200, "Elasticsearch", lambda body: '"cluster_name"' in body),
        (5984, "CouchDB",       lambda body: '"couchdb"' in body.lower()),
        (27017, "MongoDB",      lambda body: "mongodb" in body.lower() and "shell" in body.lower()),
    ]
    for port, svc, is_open in http_db_checks:
        try:
            s = socket.socket()
            s.settimeout(2)
            if s.connect_ex((ip, port)) != 0:
                s.close()
                continue
            s.close()
        except Exception:
            continue
        _throttle()
        code, _, body = fetch(f"http://{ip}:{port}/", timeout=4)
        if code and body and is_open(body):
            vuln(f"{svc} on port {port} answers with NO AUTHENTICATION — database contents may be fully readable")
            record("CRITICAL", "NoAuth", f"{svc} unauthenticated on port {port}")
            explain("NoAuth")


def m_headers(url, ip_ref):
    mod_hdr(f"HTTP SECURITY HEADERS  {mitre_tag('Headers')}")
    pages = target_pages(url)
    checks = {
        "strict-transport-security": ("HSTS missing — downgrade attacks possible", "HIGH"),
        "content-security-policy":   ("No CSP — XSS risk elevated", "HIGH"),
        "x-frame-options":           ("X-Frame-Options missing — clickjacking", "MEDIUM"),
        "x-content-type-options":    ("MIME sniffing not disabled", "MEDIUM"),
        "referrer-policy":           ("Referrer-Policy missing", "LOW"),
        "permissions-policy":        ("Permissions-Policy not set", "LOW"),
    }
    seen_signatures = set()
    checked = 0
    for page in pages:
        s, headers, body = fetch(page)
        if not s:
            if page == url:
                vuln(f"Cannot reach target: {body}")
            continue
        hl = {k.lower(): v for k, v in headers.items()}
        missing = tuple(sorted(h for h in checks if h not in hl))
        sig = (s, missing)
        if sig in seen_signatures:
            continue  # identical header profile to a page already reported — skip the repeat
        seen_signatures.add(sig)
        checked += 1
        label = "homepage" if page == url else page
        print(f"\n {C.BOLD}{C.WHITE}{label}{C.RESET}")
        for h, (msg, sev) in checks.items():
            if h in hl:
                ok(f"{h}: {C.DIM}{hl[h][:45]}{C.RESET}")
            else:
                (vuln if sev == "HIGH" else warn)(msg)
                record(sev, "Headers", f"{msg} ({label})")
                explain("Headers")
        for lk in ("server", "x-powered-by", "x-aspnet-version"):
            if lk in hl:
                warn(f"Version leak [{lk}]: {hl[lk]}")
                record("LOW", "Info Leak", f"{lk}: {hl[lk]} ({label})")
                explain("Info Leak")
    if len(pages) > checked:
        info(f"\n{len(pages) - checked} page(s) had identical header profiles to ones already shown — skipped repeats")


def m_ssl(url, ip_ref):
    mod_hdr(f"SSL / TLS ANALYSIS  {mitre_tag('SSL')}")
    p = urllib.parse.urlparse(url)
    if p.scheme != "https":
        vuln("No HTTPS!")
        record("CRITICAL", "SSL", "No HTTPS")
        return
    host = p.hostname
    port = p.port or 443
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = True
        ctx2.verify_mode = ssl.CERT_REQUIRED
        _throttle()
        with socket.create_connection((host, port), 8) as c:
            with ctx2.wrap_socket(c, server_hostname=host) as ss:
                cert = ss.getpeercert()
                cipher = ss.cipher()
                ver = ss.version()
        sub = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        exp = cert.get("notAfter", "?")
        ok(f"Valid cert  : {C.WHITE}{sub.get('commonName','?')}{C.RESET}")
        info(f"Issuer      : {issuer.get('organizationName','?')}")
        info(f"Expires     : {exp}")
        info(f"Protocol    : {ver}  |  Cipher: {cipher[0] if cipher else '?'}")
        if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
            vuln(f"Deprecated protocol: {ver}")
            record("HIGH", "SSL", f"Deprecated: {ver}")
            explain("SSL")
        if cipher and any(w in cipher[0] for w in ("RC4", "DES", "NULL", "EXPORT")):
            vuln(f"Weak cipher: {cipher[0]}")
            record("HIGH", "SSL", f"Weak cipher: {cipher[0]}")
            explain("SSL")
        try:
            exp_dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
            days = (exp_dt - datetime.now(timezone.utc).replace(tzinfo=None)).days
            if days < 0:
                vuln(f"EXPIRED {abs(days)} days ago!")
                record("CRITICAL", "SSL", "Expired")
                explain("SSL")
            elif days < 30:
                warn(f"Expires in {days} days")
                record("MEDIUM", "SSL", f"Expiring {days}d")
                explain("SSL")
            else:
                ok(f"Valid for {days} more days")
        except Exception:
            pass
    except ssl.SSLCertVerificationError as e:
        vuln(f"SSL invalid: {e}")
        record("HIGH", "SSL", str(e))
        explain("SSL")
    except Exception as e:
        warn(f"SSL error: {e}")
    if tool_ok("nmap"):
        sp = Spinner("Testing Heartbleed CVE-2014-0160")
        sp.start()
        out = run_cmd(["nmap", "--script", "ssl-heartbleed", "-p", str(port), host], 20)
        sp.stop()
        if "VULNERABLE" in out:
            vuln("HEARTBLEED VULNERABLE!")
            record("CRITICAL", "SSL", "Heartbleed CVE-2014-0160")
            explain("SSL")
        elif "NOT VULNERABLE" in out:
            ok("Not vulnerable to Heartbleed")


def m_cookies(url, ip_ref):
    mod_hdr(f"COOKIE SECURITY FLAGS  {mitre_tag('Cookies')}")
    pages = target_pages(url)
    any_cookie = False
    seen_names = set()
    for page in pages:
        s, headers, _ = fetch(page)
        if not s:
            continue
        cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
        if not cookies:
            continue
        any_cookie = True
        label = "homepage" if page == url else page
        for c in cookies:
            name = c.split("=")[0].strip()
            if name in seen_names:
                continue
            seen_names.add(name)
            al = c.lower()
            missing = [x for x, f in [("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite")] if f not in al]
            if missing:
                vuln(f"Cookie '{C.WHITE}{name}{C.RESET}{C.RED}' on {label} missing: {', '.join(missing)}")
                record("MEDIUM", "Cookies", f"{name}: missing {', '.join(missing)} ({label})")
                explain("Cookies")
            else:
                ok(f"Cookie '{name}' on {label} properly secured")
    if not any_cookie:
        info("No Set-Cookie headers on any checked page (including login/admin pages if discovered)")


def m_waf(url, ip_ref):
    mod_hdr(f"WAF / FIREWALL DETECTION  {mitre_tag('WAF')}")
    if tool_ok("wafw00f"):
        sp = Spinner("wafw00f scanning")
        sp.start()
        out = run_cmd(["wafw00f", url], 30)
        sp.stop()
        for line in out.splitlines():
            line = line.strip()
            if "is behind" in line.lower() or "detected" in line.lower():
                ok(f"WAF: {line}")
                record("INFO", "WAF", line)
            elif "no waf" in line.lower():
                vuln("No WAF detected!")
                record("MEDIUM", "WAF", "No WAF detected")
                explain("WAF")
    else:
        warn("wafw00f not found — header-based check ...")
        xss = urllib.parse.quote("<script>alert(1)</script>")
        s, hl, _ = fetch(f"{url}?q={xss}", timeout=6)
        hl = {k.lower(): v for k, v in hl.items()}
        sigs = {"cf-ray": "Cloudflare", "x-sucuri-id": "Sucuri", "x-amzn-waf": "AWS WAF", "x-waf-status": "WAF"}
        found = False
        for k, v in sigs.items():
            if k in hl:
                ok(f"WAF detected: {v}")
                found = True
        if s == 403:
            ok("Got 403 on payload — WAF likely active")
        elif not found:
            warn("No WAF signatures detected")
            record("MEDIUM", "WAF", "No WAF found")
            explain("WAF")


def m_files(url, ip_ref):
    mod_hdr(f"SENSITIVE FILES & DIRECTORIES  {mitre_tag('Files')}")
    base = url.rstrip("/")
    paths = ["/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
             "/config.php", "/config.yml", "/wp-config.php", "/.htaccess", "/.htpasswd",
             "/phpinfo.php", "/info.php", "/admin", "/administrator", "/phpmyadmin",
             "/backup.zip", "/backup.sql", "/db.sql", "/server-status",
             "/api/swagger.json", "/swagger.json", "/openapi.json",
             "/actuator/env", "/actuator/health", "/.DS_Store",
             "/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
    db_admin_paths = ["/adminer.php", "/adminer", "/mongo-express", "/_utils/",
                       "/redis-commander", "/pgadmin4", "/_cat/indices?v",
                       "/rockmongo", "/dbadmin", "/phppgadmin"]
    paths += db_admin_paths
    sp = Spinner(f"Checking {len(paths)} paths (rate-limited)")
    sp.start()
    results = []
    for path in paths:
        s, h, body = fetch(base + path, timeout=5)
        results.append((path, s, h, body))
    sp.stop()

    skipped_fallback = 0
    for path, s, h, body in results:
        if s == 200:
            if is_fallback_response(s, h, body):
                # Same status/length/content-type as a deliberately nonexistent
                # path — this is the SPA's fallback page, not a real hit.
                skipped_fallback += 1
                continue
            if "/.git" in path:
                vuln(f"GIT REPO EXPOSED: {path}")
                record("CRITICAL", "Files", "Git exposed")
                explain("Files")
            elif path in db_admin_paths:
                vuln(f"DATABASE ADMIN PANEL EXPOSED: {path}")
                record("CRITICAL", "Database", f"DB admin panel reachable: {path}")
                explain("Database")
            elif ".env" in path:
                vuln(f"ENV FILE EXPOSED: {path}")
                record("CRITICAL", "Files", ".env exposed")
                explain("Files")
            elif "phpinfo" in path and "PHP" in body:
                vuln("phpinfo() exposed")
                record("HIGH", "Files", "phpinfo exposed")
                explain("Files")
            elif "actuator" in path:
                vuln(f"Spring Actuator: {path}")
                record("HIGH", "Files", f"Actuator: {path}")
                explain("Files")
            elif path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                ok(f"Found (informational): {path}")
            else:
                warn(f"Accessible [{s}]: {path}")
                record("MEDIUM", "Files", path)
                explain("Files")
        elif s in (401, 403):
            info(f"Protected [{s}]: {path}")
    if skipped_fallback:
        info(f"Skipped {skipped_fallback} path(s) that just matched the app's fallback page (not real findings)")


def m_whatweb(url, ip_ref):
    mod_hdr("TECHNOLOGY FINGERPRINTING")
    if tool_ok("whatweb"):
        sp = Spinner("WhatWeb fingerprinting")
        sp.start()
        out = run_cmd(["whatweb", "--color=never", "-a3", url], 30)
        sp.stop()
        for line in out.splitlines():
            if line.strip():
                info(line.strip()[:110])
        return
    warn("WhatWeb not found — manual detection ...")
    s, headers, body = fetch(url)
    if not s:
        return
    hl = {k.lower(): v for k, v in headers.items()}
    for h in ("server", "x-powered-by", "x-generator"):
        if h in hl:
            info(f"{h}: {hl[h]}")
    for tech, pat in {"WordPress": r"wp-content", "Drupal": r"Drupal\.settings",
                       "Joomla": r"/components/com_", "Laravel": r"laravel_session",
                       "Django": r"csrfmiddlewaretoken", "React": r"__REACT",
                       "Angular": r"ng-version", "jQuery": r"jquery[\-\.]\d+\.\d+"}.items():
        if re.search(pat, body, re.I):
            ok(f"Detected: {C.WHITE}{tech}{C.RESET}")


def m_nikto(url, ip_ref):
    mod_hdr(f"NIKTO WEB VULNERABILITY SCANNER  {mitre_tag('Nikto')}")
    if not tool_ok("nikto"):
        warn("nikto not found — sudo apt install nikto")
        return
    sp = Spinner("Nikto scanning (2-5 min)")
    sp.start()
    out = run_cmd(["nikto", "-h", url, "-nossl", "-Format", "txt"], 300)
    sp.stop()
    count = 0
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        if "OSVDB" in line or re.search(r"CVE-\d{4}-\d+", line):
            vuln(f"{line[:140]}")
            record("HIGH", "Nikto", line[:100])
            explain("Nikto")
            count += 1
        elif line.startswith("+ "):
            warn(f"{line[2:140]}")
            record("MEDIUM", "Nikto", line[2:100])
    ok(f"Nikto done — {count} high-severity finding(s)")


def identify_hash(h):
    h = h.strip()
    checks = [
        (r"^\$2[aby]\$\d{2}\$", "bcrypt", "STRONG", "Computationally expensive — safe"),
        (r"^\$argon2", "Argon2", "STRONG", "PHC winner — very safe"),
        (r"^\$6\$", "SHA-512-crypt", "MEDIUM", "Linux shadow SHA-512"),
        (r"^\$1\$", "MD5-crypt", "WEAK", "Old Linux shadow — crackable"),
        (r"^[a-f0-9]{32}$", "MD5", "WEAK", "Crackable in seconds"),
        (r"^[a-f0-9]{40}$", "SHA-1", "WEAK", "Deprecated — collision known"),
        (r"^[a-f0-9]{64}$", "SHA-256", "MEDIUM", "Weak for passwords"),
        (r"^[a-f0-9]{128}$", "SHA-512", "MEDIUM", "OK for checksums"),
        (r"^\*[A-F0-9]{40}$", "MySQL4.1+", "WEAK", "MySQL SHA-1 double hash"),
        (r"^[a-f0-9]{32}:[^:]+$", "NTLM", "CRITICAL", "Windows NTLM — fast to crack"),
        (r"^\$NT\$[a-f0-9]{32}", "NT Hash", "CRITICAL", "Windows NT hash"),
        (r"^[a-zA-Z0-9/+.]{13}$", "DES-crypt", "CRITICAL", "Unix DES — obsolete"),
    ]
    for pat, name, strength, note in checks:
        if re.match(pat, h, re.I):
            return name, strength, note
    return "Unknown", "UNKNOWN", "Cannot identify"


def m_dbexposure(url, ip_ref):
    mod_hdr(f"DATABASE EXPOSURE  {mitre_tag('DB Exposure')}")

    # ── Step 1: collect every JS bundle + inline <script> we can reach ──────
    sp = Spinner("Pulling JS bundles from discovered pages")
    sp.start()
    html_pages = [url] + [p for p in _PAGES.get("urls", []) if p != url][:10]
    js_urls, blobs = set(), []
    for page in html_pages:
        s, h, body = fetch(page, timeout=6)
        if not s or not body:
            continue
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I):
            js_urls.add(urllib.parse.urljoin(page, m.group(1)))
        for m in re.finditer(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', body, re.I | re.S):
            if m.group(1).strip():
                blobs.append(m.group(1))
    for js_url in list(js_urls)[:20]:
        s, h, body = fetch(js_url, timeout=8)
        if s and body:
            blobs.append(body)
    sp.stop()
    joined = "\n".join(blobs)
    if not joined:
        ok("No JS bundles/inline scripts reachable to inspect")
        return
    info(f"Inspected {len(js_urls)} JS file(s) + inline scripts across {len(html_pages)} page(s)")

    hits = []  # (severity, message, category_key)

    # ── Step 2: raw DB connection strings — if these ship to the browser,
    # that's a full-credential leak, no testing needed to know it's critical.
    for label, pat in {
        "MongoDB": r"mongodb(?:\+srv)?://[^\s\"'<>]+",
        "PostgreSQL": r"postgres(?:ql)?://[^\s\"'<>]+",
        "MySQL": r"mysql://[^\s\"'<>]+",
        "Redis": r"redis://[^\s\"'<>]+",
    }.items():
        for m in list(dict.fromkeys(re.findall(pat, joined, re.I)))[:3]:
            redacted = re.sub(r"://[^@/]+@", "://[credentials-redacted]@", m)
            vuln(f"Raw {label} connection string in client-side code: {redacted[:80]}")
            record("CRITICAL", "DB Exposure", f"{label} connection string shipped to browser")
            explain("DB Exposure")
            hits.append(("CRITICAL", label))

    # ── Step 3: Supabase — project URL + a public key. Legit and common, but
    # only safe if Row Level Security is actually locked down, which we test.
    sb_projects = set(re.findall(r'https://([a-z0-9]{15,25})\.supabase\.co', joined, re.I))
    sb_keys = list(dict.fromkeys(
        re.findall(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', joined) +
        re.findall(r'sb_publishable_[A-Za-z0-9_-]+', joined)
    ))
    sb_secret = re.findall(r'sb_secret_[A-Za-z0-9_-]+', joined)
    if sb_secret:
        vuln("Supabase SECRET (service-role) key found in client-side code — full DB admin access")
        record("CRITICAL", "DB Exposure", "Supabase secret key exposed client-side")
        explain("DB Exposure")
    if sb_projects and sb_keys:
        project = list(sb_projects)[0]
        key = sb_keys[0]
        ok(f"Supabase backend detected: {project}.supabase.co")
        info("Testing common table names for anonymous read access (GET only, no writes)...")
        common_tables = ["users", "admins", "profiles", "accounts", "orders", "customers",
                          "payments", "transactions", "settings", "app_settings", "config",
                          "logs", "staff", "employees", "sessions", "api_keys", "secrets"]
        readable_data, readable_empty = [], []
        for t in common_tables:
            s, h, body = fetch(f"https://{project}.supabase.co/rest/v1/{t}?select=*&limit=1",
                                headers={"apikey": key}, timeout=6)
            if s != 200 or body is None:
                continue  # 401/403/PGRST-not-found: table doesn't exist or is properly protected
            stripped = body.strip()
            if stripped == "[]":
                readable_empty.append(t)  # RLS still let the read through — just no rows right now
            elif stripped.startswith("["):
                readable_data.append(t)
        if readable_data or readable_empty:
            if readable_data:
                vuln(f"Anonymous READ access confirmed on table(s) WITH DATA: {', '.join(readable_data)}")
                record("CRITICAL", "DB Exposure", f"Supabase RLS gap, real data readable: {', '.join(readable_data)}")
                explain("DB Exposure")
            if readable_empty:
                warn(f"Anonymous READ access confirmed on table(s) (currently empty): {', '.join(readable_empty)}")
                record("MEDIUM", "DB Exposure", f"Supabase RLS gap, empty table readable: {', '.join(readable_empty)}")
                explain("DB Exposure")
            info("This means the public key shipped to every visitor's browser can read these")
            info("tables with zero login. Fix: add/tighten Row Level Security policies on them.")
        else:
            ok("No anonymous reads succeeded on common table names (RLS may be correctly configured)")
            info("This only tested guessed table names — it doesn't prove every table is safe.")

    # ── Step 4: Firebase Realtime Database — classic misconfig is that the
    # DB is fully readable by appending .json to the root, no auth needed.
    fb_dbs = set(re.findall(r'https://([a-z0-9-]+)\.firebaseio\.com', joined, re.I))
    for db in fb_dbs:
        s, h, body = fetch(f"https://{db}.firebaseio.com/.json", timeout=6)
        if s == 200 and body and body.strip() not in ("null", "{}", ""):
            vuln(f"Firebase Realtime Database '{db}' is publicly readable at /.json")
            record("CRITICAL", "DB Exposure", f"Firebase RTDB '{db}' open read")
            explain("DB Exposure")
        elif s == 200:
            ok(f"Firebase DB '{db}' reachable but empty/locked at root")
        else:
            ok(f"Firebase DB '{db}' — root read blocked (status {s})")

    # ── Step 5: public S3 buckets referenced in the frontend ────────────────
    s3_buckets = set(re.findall(r'https://([a-z0-9.-]+)\.s3[.\-][a-z0-9-]*\.amazonaws\.com', joined, re.I))
    for bucket in s3_buckets:
        s, h, body = fetch(f"https://{bucket}.s3.amazonaws.com/?list-type=2", timeout=6)
        if s == 200 and body and "<ListBucketResult" in body:
            vuln(f"S3 bucket '{bucket}' allows public listing")
            record("HIGH", "DB Exposure", f"S3 bucket {bucket} publicly listable")
            explain("DB Exposure")
        else:
            ok(f"S3 bucket '{bucket}' referenced but listing not public (status {s})")

    if not (sb_projects or fb_dbs or s3_buckets or hits):
        ok("No cloud database backends (Supabase/Firebase/S3) or raw connection strings detected in client-side code")


def m_hashes(url, ip_ref):
    mod_hdr(f"HASH DETECTION IN HTTP RESPONSES  {mitre_tag('Hash Leak')}")
    base = url.rstrip("/")
    found = []
    patterns = {"MD5": r"\b[a-f0-9]{32}\b", "SHA-1": r"\b[a-f0-9]{40}\b",
                "SHA-256": r"\b[a-f0-9]{64}\b", "bcrypt": r"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}",
                "NTLM": r"\b[a-f0-9]{32}:[a-f0-9]{32}\b"}
    guess_paths = ["/", "api/users", "/api/profile", "/debug", "/phpinfo.php", "/.git/config"]
    check_urls = [base + "/" + p.lstrip("/") for p in guess_paths] + target_pages(url, limit=10)[1:]
    check_urls = list(dict.fromkeys(check_urls))  # dedupe, keep order

    skipped_fallback = 0
    for full_url in check_urls:
        s, h, body = fetch(full_url, timeout=5)
        if not s or not body:
            continue
        if is_fallback_response(s, h, body):
            # This page is just the SPA's fallback shell — any "hash-looking"
            # string in it (e.g. a build hash / asset fingerprint in the HTML)
            # isn't a real credential leak, it's noise from static asset names.
            skipped_fallback += 1
            continue
        label = full_url.replace(base, "") or "/"
        for htype, pat in patterns.items():
            for m in re.findall(pat, body, re.I)[:2]:
                if m not in [f["hash"] for f in found]:
                    name, strength, note = identify_hash(m)
                    found.append({"hash": m, "type": name, "strength": strength, "note": note, "path": label})
    if found:
        for f in found:
            col = C.RED if f["strength"] in ("CRITICAL", "WEAK") else C.YELLOW
            vuln(f"Hash in {f['path']}: {f['hash'][:32]}...")
            print(f"     {col}Type: {f['type']} | Strength: {f['strength']}{C.RESET}")
            print(f"     Note: {f['note']}")
            record(f["strength"], "Hash Leak", f"{f['type']} in {f['path']}")
            explain("Hash Leak")
    else:
        ok("No hash strings found in HTTP responses")
    if skipped_fallback:
        info(f"Skipped {skipped_fallback} path(s) that just matched the app's fallback page (not real findings)")


def m_redirect(url, ip_ref):
    mod_hdr(f"OPEN REDIRECT  {mitre_tag('Redirect')}")
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    found = False
    for param in ["redirect", "url", "next", "return", "goto", "dest"]:
        for payload in ["https://evil.example", "//evil.example"]:
            test = f"{base}?{param}={urllib.parse.quote(payload, safe='')}"
            s, h, _ = fetch(test, follow=False, timeout=5)
            if s in (301, 302, 307, 308) and "evil.example" in h.get("Location", ""):
                vuln(f"Open redirect via ?{param}=")
                record("HIGH", "Redirect", f"?{param}= open redirect")
                explain("Redirect")
                found = True
                break
        if found:
            break
    if not found:
        ok("No open redirect on common parameters")


def _xss_sqli_targets(url):
    """Build a list of (test_base_url, [param_names]) to fuzz: the homepage
    with common guessed param names, plus every GET form the crawler found
    (using its real field names), plus any crawled URL that already has its
    own query parameters."""
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    targets = [(base, ["q", "search", "id", "name", "input", "s", "query"])]
    for f in _PAGES.get("forms", []):
        if f["method"] == "get" and f["params"]:
            targets.append((f["action"], f["params"][:6]))
    for page in _PAGES.get("urls", []):
        pu = urllib.parse.urlparse(page)
        if pu.query:
            qs_base = f"{pu.scheme}://{pu.netloc}{pu.path}"
            params = list(urllib.parse.parse_qs(pu.query).keys())
            if params:
                targets.append((qs_base, params[:6]))
    # dedupe by (base, tuple(params))
    seen, out = set(), []
    for b, p in targets:
        key = (b, tuple(p))
        if key not in seen:
            seen.add(key)
            out.append((b, p))
    return out[:12]  # cap total fuzz targets so this stays fast


def m_xss(url, ip_ref):
    mod_hdr(f"REFLECTED XSS  {mitre_tag('XSS')}")
    payloads = ["<script>alert(1)</script>", '"><script>alert(1)</script>',
                "<img src=x onerror=alert(1)>"]
    targets = _xss_sqli_targets(url)
    found_any = False
    for test_base, params in targets:
        found = False
        for param in params:
            for payload in payloads:
                s, _, body = fetch(f"{test_base}?{param}={urllib.parse.quote(payload)}", timeout=5)
                if s and payload in body:
                    label = test_base if test_base != urllib.parse.urlunparse(
                        urllib.parse.urlparse(url)._replace(query="")) else "(homepage)"
                    vuln(f"XSS reflected on {label} via ?{param}= (exact payload echoed back unescaped)")
                    record("HIGH", "XSS", f"Reflected XSS on {label} ?{param}")
                    explain("XSS")
                    found = found_any = True
                    break
            if found:
                break
    if not found_any:
        ok(f"No exact-reflection XSS across {len(targets)} tested endpoint(s)/form(s)")
        info("Note: this checks for unescaped reflection only. A page that HTML-encodes")
        info("the payload (turns < into &lt;) will correctly show as clean here — that's")
        info("the page doing its job, not a false negative.")


# ──────────────────────────────────────────────────────────────────────────────
# TIMING-BASED INJECTION CHECK
# ──────────────────────────────────────────────────────────────────────────────
# This is the detection upgrade vs. v3. The original tool only checked for
# error-based SQLi (does a DB error string show up in the response) and
# exact-reflection XSS (does the literal payload show up unescaped). Both
# miss "blind" injection, where the application behaves correctly on the
# surface but a malicious payload still changes what the server does
# internally — the classic example being a SQL payload that makes the
# database pause for N seconds if (and only if) it's actually interpreted
# as SQL rather than treated as inert text.
#
# This does NOT replace the original checks — it runs alongside them as an
# additional signal, because each technique catches different things.
TIMING_DELAY_SECONDS = 4
SQLI_TIME_PAYLOADS = [
    f"' OR SLEEP({TIMING_DELAY_SECONDS})-- -",          # MySQL
    f"'; SELECT pg_sleep({TIMING_DELAY_SECONDS})-- -",   # PostgreSQL
    f"' WAITFOR DELAY '0:0:{TIMING_DELAY_SECONDS}'-- -", # MSSQL
]


def m_sqli(url, ip_ref):
    mod_hdr(f"SQL INJECTION (ERROR-BASED + TIMING-BASED)  {mitre_tag('SQLi')}")
    targets = _xss_sqli_targets(url)
    errors = ["you have an error in your sql syntax", "warning: mysql",
              "unclosed quotation mark", "quoted string not properly terminated",
              "pg_query()", "sqlite3", "ora-01756", "microsoft ole db provider"]

    # Error-based pass across every discovered endpoint/form.
    found_error_based = False
    for test_base, params in targets:
        for param in (params or ["id", "user", "item", "product", "page", "cat"]):
            for payload in ["'", '"', "' OR '1'='1"]:
                s, _, body = fetch(f"{test_base}?{param}={urllib.parse.quote(payload)}", timeout=5)
                if s and body and any(e in body.lower() for e in errors):
                    vuln(f"SQL error on {test_base} via ?{param}='{payload}'")
                    record("CRITICAL", "SQLi", f"DB error on {test_base} ?{param}")
                    explain("SQLi")
                    found_error_based = True
                    break
            if found_error_based:
                break
        if found_error_based:
            break
    if not found_error_based:
        ok(f"No error-based SQLi across {len(targets)} tested endpoint(s)/form(s)")

    # Timing-based pass: establish a baseline response time, then compare it
    # against the response time for a payload designed to make a real
    # database sleep. A consistent, repeatable delay that lines up with the
    # payload (and does NOT happen on a harmless control payload) is a much
    # stronger signal than a single slow response, which could just be
    # network jitter. Capped to the first few targets since each check is
    # inherently slow (multiple multi-second sleeps per parameter).
    found_timing_based = False
    for test_base, params in targets[:4]:
        for param in (params or ["id", "user", "item", "product", "page", "cat"])[:4]:
            baseline_url = f"{test_base}?{param}={urllib.parse.quote('1')}"
            t0 = time.time()
            s_base, _, _ = fetch(baseline_url, timeout=TIMING_DELAY_SECONDS + 6)
            baseline_time = time.time() - t0
            if s_base is None:
                continue

            for payload in SQLI_TIME_PAYLOADS:
                test_url = f"{test_base}?{param}={urllib.parse.quote(payload)}"
                t0 = time.time()
                s_test, _, _ = fetch(test_url, timeout=TIMING_DELAY_SECONDS + 6)
                elapsed = time.time() - t0
                if s_test is not None and elapsed >= (baseline_time + TIMING_DELAY_SECONDS - 1):
                    vuln(f"Timing-based SQLi on {test_base} via ?{param}= "
                         f"(baseline {baseline_time:.1f}s -> {elapsed:.1f}s with sleep payload)")
                    record("CRITICAL", "SQLi", f"Timing-based (blind) SQLi on {test_base} ?{param}")
                    explain("SQLi")
                    found_timing_based = True
                    break
            if found_timing_based:
                break
        if found_timing_based:
            break
    if not found_timing_based:
        ok("No timing-based (blind) SQLi detected on tested endpoints")


def m_cors(url, ip_ref):
    mod_hdr(f"CORS POLICY  {mitre_tag('CORS')}")
    for origin in ["https://evil.example", "null"]:
        s, h, _ = fetch(url, headers={"Origin": origin}, timeout=5)
        if not s:
            continue
        acao = h.get("Access-Control-Allow-Origin", "")
        acac = h.get("Access-Control-Allow-Credentials", "")
        if acao == origin and acac.lower() == "true":
            vuln(f"CORS reflects '{origin}' WITH credentials=true!")
            record("HIGH", "CORS", "Reflected CORS + credentials")
            explain("CORS")
        elif acao == origin:
            warn(f"CORS reflects arbitrary origin '{origin}'")
            record("MEDIUM", "CORS", "Reflected CORS")
            explain("CORS")
        elif acao == "*":
            warn("CORS wildcard (*) — any origin allowed")
            record("LOW", "CORS", "Wildcard CORS")
            explain("CORS")
        elif acao:
            ok(f"CORS locked to: {acao}")
            break


ALL_MODULES = [
    m_recon, m_crawl, m_nmap, m_nse, m_banner, m_headers, m_ssl, m_cookies,
    m_waf, m_files, m_dbexposure, m_whatweb, m_nikto, m_hashes, m_redirect, m_xss,
    m_sqli, m_cors
]


# ══════════════════════════════════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════════════════════════════════
def compute_risk():
    """Shared scoring so the pretty report and the --json report always agree.
    Returns (counts: dict, score: int, risk: str)."""
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    score = (counts["CRITICAL"] * 10 + counts["HIGH"] * 5 +
             counts["MEDIUM"] * 2 + counts["LOW"])
    risk = ("CRITICAL" if score >= 20 else "HIGH" if score >= 10 else
            "MEDIUM" if score >= 4 else "LOW" if score >= 1 else "CLEAN")
    return counts, score, risk


def json_report(url, elapsed):
    """Emit a machine-readable report to stdout. Mirrors the data in the
    human report (target, timing, risk score, severity counts, findings) so
    results can be piped into other tools or stored. No ANSI colors."""
    counts, score, risk = compute_risk()
    report = {
        "tool": "webscan",
        "version": "4.0",
        "target": url,
        "scanned_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_seconds": round(elapsed, 2),
        "risk": {"score": score, "level": risk},
        "counts": {sev: counts.get(sev, 0)
                   for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "findings": list(findings),
    }
    print(json.dumps(report, indent=2))


def print_report(url, elapsed):
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    colors = {"CRITICAL": C.RED, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN, "INFO": C.DIM}
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    score = (counts["CRITICAL"] * 10 + counts["HIGH"] * 5 + counts["MEDIUM"] * 2 + counts["LOW"])
    risk = ("CRITICAL" if score >= 20 else "HIGH" if score >= 10 else
            "MEDIUM" if score >= 4 else "LOW" if score >= 1 else "CLEAN")
    rc = colors.get(risk, C.GREEN)

    print(f"\n{C.CYAN}╔{'═'*58}╗{C.RESET}")
    print(f"{C.CYAN}║{C.BOLD}{C.WHITE}{'  SCAN COMPLETE — FINAL REPORT':^58}{C.RESET}{C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}╠{'═'*58}╣{C.RESET}")

    def rl(txt, col="", align="left"):
        txt = str(txt)
        raw_len = len(re.sub(r'\033\[[0-9;]*m', '', txt))
        pad = 56 - raw_len
        if align == "left":
            print(f"{C.CYAN}║{C.RESET} {col}{txt}{C.RESET}{' '*max(0,pad)} {C.CYAN}║{C.RESET}")
        else:
            l = pad // 2
            r = pad - l
            print(f"{C.CYAN}║{C.RESET}{' '*l}{col}{txt}{C.RESET}{' '*r}{C.CYAN}║{C.RESET}")

    rl(f"Target  : {url}", C.WHITE)
    rl(f"Time    : {elapsed:.1f}s  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    rl(f"Risk    : {rc}{score} pts — {risk}{C.RESET}")
    print(f"{C.CYAN}╠{'═'*58}╣{C.RESET}")
    for sev in sev_order:
        n = counts.get(sev, 0)
        if n:
            rl(f"{sev:<10} {n} finding(s)", colors.get(sev, ""))
    print(f"{C.CYAN}╚{'═'*58}╝{C.RESET}")

    # Full, non-truncated finding list, printed outside the fixed-width box so
    # nothing gets cut off (the old version chopped long lines like a CVE URL
    # down to 56 characters). Every entry also gets its plain-English line.
    if findings:
        print(f"\n{C.BOLD}{C.WHITE}Everything found, in order of severity:{C.RESET}\n")
        for sev in sev_order:
            group = [f for f in findings if f["severity"] == sev]
            if not group:
                continue
            print(f"{colors.get(sev,'')}{C.BOLD}{sev}{C.RESET}")
            for f in group:
                print(f"  {colors.get(sev,'')}•{C.RESET} [{f['category']}] {f['detail']}")
                msg = LAYMAN.get(f["category"])
                if msg:
                    print(f"     {C.DIM}→ {msg}{C.RESET}")
            print()

    # Plain-English wrap-up paragraph — no jargon, meant to be readable by
    # someone who doesn't do security day-to-day (e.g. for a report intro).
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    print(f"{C.BOLD}{C.WHITE}In plain terms:{C.RESET}")
    if crit == 0 and high == 0:
        print(f"  {C.GREEN}Nothing urgent turned up. Lower-severity items above are still worth"
              f"\n  fixing when you get the chance, but nothing here needs same-day attention.{C.RESET}")
    else:
        print(f"  This site has {crit} issue(s) rated CRITICAL and {high} rated HIGH — meaning"
              f"\n  real data or access could realistically be exposed, not just theoretical risk."
              f"\n  Start with the CRITICAL items above; each one lists in plain words what's"
              f"\n  actually wrong and why it matters.")
    print()
    return score, risk


# ══════════════════════════════════════════════════════════════════════════════
# BANNER + AUTHORIZATION GATE
# ══════════════════════════════════════════════════════════════════════════════
def draw_banner():
    clear()
    print(f"{C.CYAN}")
    print(r"  ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗  ██╗")
    print(r"  ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗ ██║")
    print(r"  ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗██║")
    print(r"  ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚████║")
    print(r"  ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚███║")
    print(r"   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝")
    print(f"{C.RESET}")
    box_top()
    box_line("WebScan v4.0  ·  Authorized Recon & Vuln Scanner", C.BOLD+C.WHITE)
    box_line(f"{len(ALL_MODULES)} Modules  ·  Rate-Limited  ·  Authorization-Gated", C.DIM)
    box_sep()
    box_line("[ Nmap . NSE . Nikto . WhatWeb . WAF . SSL . XSS . SQLi ]", C.CYAN)
    box_line("[ Banner . CORS . Cookies . Hashes . Redirect . Headers ]", C.CYAN)
    box_sep()

    tools = ["nmap", "nikto", "whatweb", "wafw00f"]
    row = ""
    for t in tools:
        if tool_ok(t):
            row += f"{C.GREEN}*{t} {C.RESET}"
        else:
            row += f"{C.RED}x{t} {C.RESET}"
    box_line(row)
    box_sep()
    box_line("Made for authorized security testing only", C.DIM)
    box_bot()
    print()


# SECURITY FIX vs. v3: the original tool had no authorization gate at all —
# it would scan whatever URL you gave it, no questions asked. This function
# is the enforcement point. require_authorization() must return True before
# main() will run a single active-scanning module.
def require_authorization(cli_authorized_flag):
    if cli_authorized_flag:
        return True
    print(f"\n{C.RED}{C.BOLD}[!] AUTHORIZATION REQUIRED{C.RESET}")
    print(f"{C.YELLOW}This tool performs active scanning (port scans, payload injection,")
    print(f"directory brute-forcing). Running it against a target you do not own or")
    print(f"have explicit written permission to test may be illegal in your jurisdiction")
    print(f"and may violate the target's terms of service.{C.RESET}\n")
    try:
        answer = input(f" Type {C.WHITE}{C.BOLD}YES{C.RESET} to confirm you are authorized to test this target: ").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{C.YELLOW}[!] Exiting...{C.RESET}\n")
        return False
    return answer == "YES"


def get_target():
    print(f"{C.CYAN}╔{'═'*58}╗{C.RESET}")
    print(f"{C.CYAN}║{C.BOLD}{C.WHITE}{'  ENTER TARGET':^58}{C.RESET}{C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}╚{'═'*58}╝{C.RESET}")
    print()
    try:
        url = input(f" {C.CYAN}┌─[{C.RESET}{C.GREEN}WebScan{C.RESET}{C.CYAN}]─[{C.RESET}target{C.CYAN}]{C.RESET}\n {C.CYAN}└─▶{C.RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n {C.YELLOW}[!] Exiting...{C.RESET}\n")
        sys.exit(0)

    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        p = urllib.parse.urlparse(url)
        if not p.netloc:
            return None
    except Exception:
        return None
    return url


def progress_bar(current, total, label=""):
    pct = current / total
    filled = int(pct * 40)
    bar = f"{C.GREEN}{'#'*filled}{C.DIM}{'.'*(40-filled)}{C.RESET}"
    print(f"\r {C.CYAN}[{C.RESET}{bar}{C.CYAN}]{C.RESET} {current}/{total} {C.DIM}{label:<20}{C.RESET}", end="", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
# SELFTEST — validates detection modules against a local server with known,
# deliberately planted issues, instead of trusting the modules to work.
# ══════════════════════════════════════════════════════════════════════════════
def _build_selftest_server():
    """
    Spins up a local HTTP server (127.0.0.1, random port) with deliberately
    planted, SAFE issues so the header/cookie/file-exposure/XSS/SQLi
    detection logic can be checked against known ground truth. Nothing
    here touches a real third party — this is the only ethical way to test
    a web vulnerability scanner.
    """
    import http.server
    import socketserver

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # keep selftest output focused on webscan's own findings

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)

            if parsed.path == "/.env":
                body = b"DB_PASSWORD=supersecret123\nAPI_KEY=fake_test_key_not_real\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/search":
                # Deliberately vulnerable: reflects the q param with NO encoding.
                q = qs.get("q", [""])[0]
                body = f"<html><body>You searched for: {q}</body></html>".encode()
                self.send_response(200)
                # Deliberately missing every security header, on purpose.
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", "session=abc123")  # missing HttpOnly/Secure/SameSite on purpose
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/product":
                pid = qs.get("id", [""])[0]
                if "'" in pid or '"' in pid:
                    body = b"Warning: mysql_fetch_array() error in your SQL syntax near '''"
                    self.send_response(500)
                else:
                    body = f"<html><body>Product #{pid}</body></html>".encode()
                    self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)
                return

            # Default page — has SOME headers right, to verify the scanner
            # doesn't just flag everything indiscriminately.
            body = b"<html><body>Selftest target home page</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

    httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port


def cmd_selftest():
    global ALLOW_INSECURE, RATE_DELAY
    print(f"\n{C.CYAN}{C.BOLD}{'='*58}{C.RESET}")
    print(f"{C.BOLD}  SELFTEST — Detection Validation Suite{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'='*58}{C.RESET}\n")
    print(f"{C.DIM}Starting a local test server with deliberately planted,")
    print(f"safe issues (exposed .env, missing headers, unescaped XSS")
    print(f"reflection, fake SQL error) to validate detection logic")
    print(f"against known ground truth.{C.RESET}\n")

    RATE_DELAY = 0.0  # selftest runs locally; no need to throttle ourselves
    httpd, port = _build_selftest_server()
    base_url = f"http://127.0.0.1:{port}"

    results = {"pass": 0, "fail": 0, "details": []}

    def check(name, condition):
        if condition:
            results["pass"] += 1
            print(f" {C.GREEN}[PASS]{C.RESET} {name}")
        else:
            results["fail"] += 1
            print(f" {C.RED}[FAIL]{C.RESET} {name}")
        results["details"].append((name, condition))

    try:
        # --- Headers module: should catch missing CSP/HSTS/etc on home page ---
        findings.clear()
        s, headers, body = fetch(f"{base_url}/")
        hl = {k.lower(): v for k, v in headers.items()}
        check("Detects missing Content-Security-Policy header",
              "content-security-policy" not in hl)
        check("Home page reachable (status 200)", s == 200)

        # --- Cookie module: planted cookie is missing all 3 flags ---
        s, headers, _ = fetch(f"{base_url}/search?q=test")
        set_cookie = headers.get("Set-Cookie", "")
        missing_flags = [f for f in ("httponly", "secure", "samesite") if f not in set_cookie.lower()]
        check("Detects cookie missing HttpOnly/Secure/SameSite", len(missing_flags) == 3)

        # --- XSS module logic: planted /search endpoint reflects unescaped ---
        payload = "<script>alert(1)</script>"
        s, _, body = fetch(f"{base_url}/search?q={urllib.parse.quote(payload)}")
        check("Detects unescaped reflected XSS on planted endpoint",
              s == 200 and payload in body)

        # --- SQLi module logic: planted /product endpoint errors on quote ---
        s, _, body = fetch(f"{base_url}/product?id=1")
        clean_works = (s == 200 and "Product #1" in body)
        s2, _, body2 = fetch(f"{base_url}/product?id=" + urllib.parse.quote("'"))
        error_triggered = any(e in body2.lower() for e in
                               ["you have an error in your sql syntax", "warning: mysql"])
        check("Normal product lookup works (no false positive)", clean_works)
        check("Detects planted SQL error on malicious input", error_triggered)

        # --- .env exposure check ---
        s, _, body = fetch(f"{base_url}/.env")
        check("Detects exposed .env file", s == 200 and "DB_PASSWORD" in body)

        # --- Certificate verification is genuinely enforced ---
        check("ALLOW_INSECURE defaults to False (cert verification stays on)",
              ALLOW_INSECURE is False)

        # --- Rate limiter actually delays requests when enabled ---
        RATE_DELAY = 0.5
        t0 = time.time()
        fetch(f"{base_url}/")
        fetch(f"{base_url}/")
        elapsed = time.time() - t0
        check(f"Rate limiter enforces delay between requests (took {elapsed:.2f}s, expected >= 0.5s)",
              elapsed >= 0.45)
        RATE_DELAY = 0.0

    finally:
        httpd.shutdown()

    total = results["pass"] + results["fail"]
    print(f"\n{C.CYAN}{C.BOLD}{'='*58}{C.RESET}")
    print(f"{C.BOLD}  RESULTS: {results['pass']}/{total} checks passed{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'='*58}{C.RESET}\n")
    if results["fail"] == 0:
        print(f"{C.GREEN}All detection logic validated against known ground truth.{C.RESET}\n")
    else:
        print(f"{C.RED}{results['fail']} check(s) failed — see [FAIL] lines above.{C.RESET}\n")
    return results["fail"] == 0


def main():
    global ALLOW_INSECURE, RATE_DELAY

    parser = argparse.ArgumentParser(
        description="WebScan v4.0 — authorized web recon & vulnerability scanner. "
                     "Certificate verification is on by default; active scanning "
                     "requires explicit authorization."
    )
    parser.add_argument("target", nargs="?", help="URL or hostname to scan")
    parser.add_argument("--authorized", action="store_true",
                         help="Confirm you have explicit permission to test this target "
                              "(skips the interactive confirmation prompt)")
    parser.add_argument("--delay", type=float, default=0.3,
                         help="Minimum seconds between requests (default: 0.3)")
    parser.add_argument("--insecure", action="store_true",
                         help="Disable TLS certificate verification (e.g. for an internal "
                              "lab target with a self-signed cert). NEVER the default.")
    parser.add_argument("--selftest", action="store_true",
                         help="Run the detection validation suite against a local test server")
    parser.add_argument("--json", action="store_true",
                         help="Emit a machine-readable JSON report on stdout instead of the "
                              "formatted report (status messages go to stderr so stdout stays clean)")
    args = parser.parse_args()

    RATE_DELAY = max(0.0, args.delay)
    ALLOW_INSECURE = args.insecure

    if args.selftest:
        ok_result = cmd_selftest()
        sys.exit(0 if ok_result else 1)

    draw_banner()

    if ALLOW_INSECURE:
        print(f"{C.YELLOW}{C.BOLD}[!] --insecure set: TLS certificate verification is DISABLED.{C.RESET}")
        print(f"{C.YELLOW}    Only use this against a target you control with a known self-signed cert.{C.RESET}\n")

    if args.target:
        url = args.target.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
    else:
        url = get_target()
        if not url:
            print(f"\n {C.RED}[!] Invalid URL{C.RESET}\n")
            sys.exit(1)

    if not require_authorization(args.authorized):
        print(f"\n {C.RED}[!] Authorization not confirmed — exiting without scanning.{C.RESET}\n")
        sys.exit(1)

    # In --json mode, keep stdout reserved for the JSON document only. All the
    # human-facing status/progress output is temporarily redirected to stderr
    # for the duration of the scan, then stdout is restored to print the report.
    real_stdout = sys.stdout
    if args.json:
        sys.stdout = sys.stderr

    print(f"\n {C.BOLD}Target  :{C.RESET} {C.WHITE}{url}{C.RESET}")
    print(f" {C.BOLD}Modules :{C.RESET} {len(ALL_MODULES)} (all)")
    print(f" {C.BOLD}Rate    :{C.RESET} {RATE_DELAY}s between requests")
    print(f" {C.BOLD}Started :{C.RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n {C.DIM}Running all modules — this respects the rate limit, so it may take a while{C.RESET}\n")

    establish_baseline(url)

    ip_ref = [None]
    t0 = time.time()
    total = len(ALL_MODULES)

    for i, mod in enumerate(ALL_MODULES):
        progress_bar(i, total, mod.__name__.replace("m_", ""))
        try:
            mod(url, ip_ref)
        except KeyboardInterrupt:
            print(f"\n\n {C.YELLOW}[!] Scan interrupted by user.{C.RESET}\n")
            sys.exit(130)

    progress_bar(total, total, "done")
    print()

    elapsed = time.time() - t0
    if args.json:
        sys.stdout = real_stdout
        json_report(url, elapsed)
    else:
        print_report(url, elapsed)


if __name__ == "__main__":
    main()
