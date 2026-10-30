"""
CyberShield - Phishing URL Analyzer & Security Awareness Platform
-----------------------------------------------------------------
Security features:
  * Static URL analysis only (the server NEVER connects to the submitted URL -> no SSRF)
  * CSRF protection (session token validated on every POST)
  * Rate limiting per client IP (sliding window)
  * Strict input validation + length limits
  * Output escaping (Jinja2 autoescape) + defanged URLs  -> XSS protection
  * Parameterised SQL queries only                       -> SQL injection protection
  * Security headers: CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS
  * Only the hostname + score is stored (no full URLs, no personal data)
"""
import os
import re
import time
import hmac
import secrets
import sqlite3
import ipaddress
from collections import deque, Counter
from urllib.parse import urlparse

from flask import (Flask, render_template, request, session, g, abort,
                   make_response)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cybershield.db")
KEY_PATH = os.path.join(BASE_DIR, ".secret_key")

app = Flask(__name__)



def load_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    try:
        with open(KEY_PATH, "w") as f:
            f.write(key)
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass
    return key


app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # set CYBERSHIELD_ENV=production on the server so cookies are HTTPS-only
    SESSION_COOKIE_SECURE=os.environ.get("CYBERSHIELD_ENV") == "production",
    MAX_CONTENT_LENGTH=16 * 1024,  # reject big request bodies
)

MAX_URL_LENGTH = 2048
RATE_LIMIT = 10          # scans ...
RATE_WINDOW = 60         # ... per 60 seconds per IP


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   host TEXT NOT NULL,
                   score INTEGER NOT NULL,
                   level TEXT NOT NULL,
                   flags TEXT NOT NULL,
                   created INTEGER NOT NULL
               )"""
        )


init_db()


# ---------------------------------------------------------------- analyzer
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "bank",
    "password", "confirm", "wallet", "billing", "suspend", "unlock",
    "recover", "validate", "authenticate", "invoice", "payment",
]
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "mov",
    "work", "support", "country", "kim", "loan", "rest",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}
BRANDS = [
    "paypal", "google", "facebook", "microsoft", "apple", "amazon", "netflix",
    "instagram", "whatsapp", "binance", "linkedin", "dropbox", "outlook",
    "banquemisr", "nbe", "vodafone", "etisalat",
]

# (code, human readable title, explanation, points)
FLAG_INFO = {
    "no_https": ("No HTTPS", "The link uses plain HTTP, so traffic is not encrypted.", 15),
    "ip_host": ("IP address as host", "Legitimate sites use domain names, not raw IP addresses.", 30),
    "at_symbol": ("'@' symbol in URL", "Everything before '@' is ignored by browsers - a classic trick to hide the real destination.", 20),
    "long_url": ("Very long URL", "Long URLs are often used to hide the real domain.", 10),
    "many_subdomains": ("Too many subdomains", "Attackers stack subdomains (e.g. paypal.com.evil.site) to look legitimate.", 15),
    "many_hyphens": ("Many hyphens in domain", "Domains like secure-login-bank-update.com are typical for phishing.", 10),
    "keywords": ("Suspicious keywords", "Words like login / verify / update push the victim to act fast.", 0),
    "bad_tld": ("Risky top-level domain", "This TLD is heavily abused for cheap or free throw-away domains.", 15),
    "shortener": ("URL shortener", "The real destination is hidden behind a short link.", 15),
    "punycode": ("Punycode / look-alike characters", "xn-- domains can imitate real brands using similar-looking characters.", 25),
    "brand_spoof": ("Brand impersonation", "A famous brand name appears in the host, but the domain does not belong to it.", 35),
    "odd_port": ("Non-standard port", "Normal websites rarely use unusual ports.", 10),
    "encoded": ("Heavy percent-encoding", "Lots of %XX characters can hide malicious content.", 10),
    "redirect_param": ("Redirect inside URL", "A second URL is embedded in the link (open redirect trick).", 10),
    "bad_scheme": ("Unsupported scheme", "Only http:// and https:// links are analysed; others (javascript:, data:) are dangerous.", 40),
}

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f\s]")


def registered_domain(host):
    """Very small heuristic for the registrable domain (last 2 labels)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def defang(url):
    """Make a URL harmless to display: hxxp://example[.]com"""
    out = url.replace("http", "hxxp", 1) if url.lower().startswith("http") else url
    return out.replace(".", "[.]")


def analyze_url(raw):
    """Return (result_dict, error_message). Pure static analysis - no network access."""
    raw = (raw or "").strip()
    if not raw:
        return None, "Please enter a URL."
    if len(raw) > MAX_URL_LENGTH:
        return None, "URL is too long (max %d characters)." % MAX_URL_LENGTH
    if CONTROL_CHARS.search(raw):
        return None, "URL must not contain spaces or control characters."

    flags = []          # list of (code, extra_text, points)

    # dangerous non-web schemes are reported directly (never executed or opened)
    m = re.match(r"^(javascript|data|vbscript|file|blob):", raw, re.I)
    if m:
        flags.append(("bad_scheme", m.group(1).lower() + ":", FLAG_INFO["bad_scheme"][2] + 40))
        return {
            "host": m.group(1).lower() + ":", "defanged": defang(raw), "score": 80,
            "level": "high", "label": "Likely phishing", "scheme": m.group(1).lower(),
            "findings": [{"title": FLAG_INFO["bad_scheme"][0], "text": FLAG_INFO["bad_scheme"][1],
                          "extra": flags[0][1], "points": 80}],
            "codes": ["bad_scheme"],
        }, None

    has_scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", raw) and "://" in raw
    candidate = raw if has_scheme else "http://" + raw
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return None, "That does not look like a valid URL."

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        flags.append(("bad_scheme", scheme + ":", FLAG_INFO["bad_scheme"][2]))
    if not host:
        return None, "That does not look like a valid URL."
    if not re.match(r"^[a-z0-9.\-:\[\]_]+$|^xn--", host) and "xn--" not in host:
        flags.append(("punycode", "non-ASCII characters in host", FLAG_INFO["punycode"][2]))

    # 1. HTTPS
    if scheme == "http" and not has_scheme:
        flags.append(("no_https", "no scheme given, assumed http://", FLAG_INFO["no_https"][2]))
    elif scheme == "http":
        flags.append(("no_https", "", FLAG_INFO["no_https"][2]))

    # 2. IP address host
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        if re.match(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", host):
            is_ip = True  # decimal / hex obfuscated IPs
    if is_ip:
        flags.append(("ip_host", host, FLAG_INFO["ip_host"][2]))

    # 3. '@' trick
    if "@" in parsed.netloc:
        flags.append(("at_symbol", "", FLAG_INFO["at_symbol"][2]))

    # 4. length
    if len(raw) > 100:
        flags.append(("long_url", "%d characters" % len(raw), 15))
    elif len(raw) > 75:
        flags.append(("long_url", "%d characters" % len(raw), FLAG_INFO["long_url"][2]))

    if not is_ip:
        labels = host.split(".")
        # 5. subdomains
        if len(labels) > 4:
            flags.append(("many_subdomains", "%d labels" % len(labels), FLAG_INFO["many_subdomains"][2]))
        # 6. hyphens
        if host.count("-") >= 3:
            flags.append(("many_hyphens", "%d hyphens" % host.count("-"), FLAG_INFO["many_hyphens"][2]))
        # 7. TLD
        if labels[-1] in SUSPICIOUS_TLDS:
            flags.append(("bad_tld", "." + labels[-1], FLAG_INFO["bad_tld"][2]))
        # 8. shortener
        if registered_domain(host) in SHORTENERS or host in SHORTENERS:
            flags.append(("shortener", host, FLAG_INFO["shortener"][2]))
        # 9. punycode
        if "xn--" in host:
            flags.append(("punycode", "", FLAG_INFO["punycode"][2]))
        # 10. brand impersonation
        reg = registered_domain(host)
        for brand in BRANDS:
            if brand in host and not reg.split(".")[0] == brand:
                flags.append(("brand_spoof", brand, FLAG_INFO["brand_spoof"][2]))
                break

    # 11. suspicious words (cap 25)
    haystack = (host + parsed.path + parsed.query).lower()
    found = [w for w in SUSPICIOUS_WORDS if w in haystack]
    if found:
        flags.append(("keywords", ", ".join(found[:5]), min(25, 8 * len(found))))

    # 12. port
    if port and port not in (80, 443):
        flags.append(("odd_port", str(port), FLAG_INFO["odd_port"][2]))

    # 13. encoding
    if len(re.findall(r"%[0-9a-fA-F]{2}", raw)) >= 5:
        flags.append(("encoded", "", FLAG_INFO["encoded"][2]))

    # 14. redirect inside the URL
    if re.search(r"(url|redirect|next|goto|continue|return)=https?", parsed.query, re.I) or "//" in parsed.path:
        flags.append(("redirect_param", "", FLAG_INFO["redirect_param"][2]))

    score = min(100, sum(f[2] for f in flags))
    if score < 25:
        level, label = "low", "Low risk"
    elif score < 55:
        level, label = "medium", "Suspicious"
    else:
        level, label = "high", "Likely phishing"

    result = {
        "host": host,
        "defanged": defang(raw),
        "score": score,
        "level": level,
        "label": label,
        "scheme": scheme,
        "findings": [
            {"title": FLAG_INFO[c][0], "text": FLAG_INFO[c][1], "extra": extra, "points": pts}
            for c, extra, pts in flags
        ],
        "codes": [c for c, _e, _p in flags],
    }
    return result, None


# ---------------------------------------------------------------- security helpers
_hits = {}  # ip -> deque of timestamps


def client_ip():
    # PythonAnywhere / nginx put the real address in X-Real-IP
    return request.headers.get("X-Real-IP") or request.remote_addr or "unknown"


def rate_limited(ip):
    now = time.time()
    q = _hits.setdefault(ip, deque())
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    # keep memory bounded
    if len(_hits) > 5000:
        for k in [k for k, v in _hits.items() if not v or now - v[-1] > RATE_WINDOW]:
            _hits.pop(k, None)
    return False


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_ok():
    sent = request.form.get("csrf_token", "")
    return bool(sent) and hmac.compare_digest(sent, session.get("csrf", ""))


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path in ("/scanner", "/dashboard"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- routes
@app.route("/")
def index():
    row = get_db().execute("SELECT COUNT(*) c, COALESCE(SUM(level='high'),0) h FROM scans").fetchone()
    return render_template("index.html", total=row["c"], high=row["h"])


@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    result = error = None
    submitted = ""
    if request.method == "POST":
        if not csrf_ok():
            abort(400)
        if rate_limited(client_ip()):
            abort(429)
        submitted = request.form.get("url", "")[:MAX_URL_LENGTH]
        result, error = analyze_url(submitted)
        if result:
            db = get_db()
            db.execute(
                "INSERT INTO scans (host, score, level, flags, created) VALUES (?,?,?,?,?)",
                (result["host"][:100], result["score"], result["level"],
                 ",".join(result["codes"]), int(time.time())),
            )
            db.commit()
    return render_template("scanner.html", result=result, error=error, submitted=submitted)


@app.route("/dashboard")
def dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    levels = {r["level"]: r["c"] for r in db.execute("SELECT level, COUNT(*) c FROM scans GROUP BY level")}
    avg = db.execute("SELECT COALESCE(AVG(score),0) FROM scans").fetchone()[0]
    recent = db.execute("SELECT host, score, level, created FROM scans ORDER BY id DESC LIMIT 10").fetchall()
    counter = Counter()
    for r in db.execute("SELECT flags FROM scans"):
        counter.update([f for f in r["flags"].split(",") if f])
    top = [(FLAG_INFO[c][0], n) for c, n in counter.most_common(6) if c in FLAG_INFO]
    top_max = top[0][1] if top else 1
    recent_fmt = [
        {"host": r["host"], "score": r["score"], "level": r["level"],
         "time": time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["created"]))}
        for r in recent
    ]
    return render_template(
        "dashboard.html", total=total, avg=round(avg), recent=recent_fmt,
        low=levels.get("low", 0), medium=levels.get("medium", 0), high=levels.get("high", 0),
        top=top, top_max=top_max,
    )


@app.route("/guide")
def guide():
    return render_template("guide.html")


# ---------------------------------------------------------------- errors
ERRORS = {
    400: ("Bad request", "The security token is missing or expired. Go back, reload the page and try again."),
    404: ("Page not found", "The page you are looking for does not exist."),
    405: ("Method not allowed", "This action is not allowed on this page."),
    413: ("Request too large", "The data you sent is too large."),
    429: ("Too many requests", "Rate limit reached: %d scans per minute. Please wait a moment." % RATE_LIMIT),
    500: ("Server error", "Something went wrong on our side."),
}


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
@app.errorhandler(429)
@app.errorhandler(500)
def handle_error(e):
    code = getattr(e, "code", 500)
    title, text = ERRORS.get(code, ERRORS[500])
    return make_response(render_template("error.html", code=code, title=title, text=text), code)


if __name__ == "__main__":
    app.run(debug=False)
