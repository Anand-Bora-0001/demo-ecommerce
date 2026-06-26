"""
Demo E-Commerce Website with HoneyCloud Security Integration
============================================================
Professional demo showing how real applications integrate
with external security / SIEM systems like HoneyCloud.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, abort, session
from datetime import datetime
import logging
from honeycloud_client import HoneyCloudClient

# -----------------------------------------------------------------------------
# APP SETUP
# -----------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = "demo-secret-key-for-testing-only"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Config from environment variables or secure defaults
import os
API_KEY = os.environ.get("HONEYCLOUD_API_KEY") or os.environ.get("API_KEY") or "hc_live_fsj-onia9stXSc2HgIuUDqfwR_f5Oe0Q4sTZTMhBku0"
HONEYCLOUD_URL = os.environ.get("HONEYCLOUD_URL") or os.environ.get("VITE_API_URL") or "https://honeycloud-backend.onrender.com"

honeycloud = HoneyCloudClient(api_key=API_KEY, base_url=HONEYCLOUD_URL)

# -----------------------------------------------------------------------------
# SECURITY HELPERS
# -----------------------------------------------------------------------------
import re

def get_client_ip():
    """Extract real client IP from headers or remote_addr"""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("X-Real-IP")
    if xri:
        return xri
    return request.remote_addr

def detect_sqli(value: str) -> bool:
    """Detect common SQL Injection patterns"""
    if not value or not isinstance(value, str):
        return False
    sqli_patterns = [
        r"'\s*or\s*",
        r"'\s*and\s*",
        r"union\s+select",
        r"select\s+.*\s+from",
        r"insert\s+into",
        r"delete\s+from",
        r"drop\s+table",
        r"--",
        r"/\*",
        r"\*/",
        r"'\s*#",
        r"admin'\s*--"
    ]
    for pattern in sqli_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False

def detect_xss(value: str) -> bool:
    """Detect common Cross-Site Scripting patterns"""
    if not value or not isinstance(value, str):
        return False
    xss_patterns = [
        r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
        r"javascript\s*:",
        r"onload\s*=",
        r"onerror\s*=",
        r"onmouseover\s*=",
        r"<img\s+[^>]*src",
        r"<iframe\b",
        r"alert\s*\(",
        r"confirm\s*\(",
        r"prompt\s*\("
    ]
    for pattern in xss_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    return False

# -----------------------------------------------------------------------------
# DATA (IN-MEMORY)
# -----------------------------------------------------------------------------

DEMO_PRODUCTS = [
    {"id": 1, "name": "Wireless Headphones", "price": 2999, "stock": 50, "description": "High-fidelity Bluetooth headphones with active noise cancellation."},
    {"id": 2, "name": "Smart Watch", "price": 8999, "stock": 30, "description": "Fitness tracking, heart rate monitor, and built-in GPS."},
    {"id": 3, "name": "Laptop Backpack", "price": 1499, "stock": 100, "description": "Waterproof, multi-compartment backpack with USB charging port."},
    {"id": 4, "name": "USB-C Hub", "price": 1999, "stock": 75, "description": "8-in-1 adapter with HDMI, USB 3.0, SD card reader, and power delivery."},
    {"id": 5, "name": "Wireless Mouse", "price": 799, "stock": 120, "description": "Ergonomic 2.4GHz wireless optical mouse with adjustable DPI."},
    {"id": 6, "name": "Mechanical Keyboard", "price": 4999, "stock": 45, "description": "Tactile mechanical keyboard with customizable RGB backlighting."},
]

DEMO_USERS = {
    "demo@example.com": "password123",
    "user@test.com": "test123"
}

# Per-IP failed login tracker
# Format: { "ip": { "count": int, "usernames": set() } }
# Resets on app restart (in production, use Redis or persistent store)
login_attempts = {}


# -----------------------------------------------------------------------------
# ACTIVE REDIRECTION (PHASE 2)
# -----------------------------------------------------------------------------

@app.before_request
def check_deception_routing():
    """
    If the session is flagged for deception, redirect ALL their traffic to the fake environment.
    """
    if session.get("deception_trapped"):
        if request.path == "/reset-demo":
            return None # Allow the reset to go through
        
        # Use the dynamic redirect URL stored in session, or fallback
        deception_url = session.get("deception_redirect_url", f"{HONEYCLOUD_URL.rstrip('/')}/deception/fake-admin")
        logger.info(f"🔄 Redirection Engine: Routing trapped attacker to {deception_url}")
        return redirect(deception_url)

def handle_routing_decision(response: dict, default_abort=404):
    """
    Inspects HoneyCloud's routing decision. If DECEPTION, traps the user.
    """
    if response and response.get("recommended_route") == "DECEPTION":
        session["deception_trapped"] = True
        session["deception_session_id"] = response.get("session_id")
        
        redirect_url = response.get("redirect_url")
        if redirect_url:
            # The URL might be relative (e.g. /deception/wp-admin)
            if redirect_url.startswith("/"):
                deception_url = f"{HONEYCLOUD_URL.rstrip('/')}{redirect_url}"
            else:
                deception_url = redirect_url
        else:
            deception_url = f"{HONEYCLOUD_URL.rstrip('/')}/deception/fake-admin"
            
        session["deception_redirect_url"] = deception_url
        logger.warning(f"🪤 TRAPPED! Redirecting attacker to Deception Environment: {deception_url}")
        return redirect(deception_url)
        
    abort(default_abort)

# -----------------------------------------------------------------------------
# NORMAL ROUTES (NO ALERTS)


@app.route("/reset-demo")
def reset_demo():
    """Clear session to escape deception trap during testing"""
    session.clear()
    logger.info("♻️ Session cleared. Escaped deception environment.")
    return redirect(url_for("home"))

@app.route("/")
def home():
    logger.info(f"✅ Normal traffic: Home from {request.remote_addr}")
    return render_template("index.html")

@app.route("/products")
def products():
    logger.info(f"✅ Normal traffic: Products from {request.remote_addr}")
    return render_template("products.html", products=DEMO_PRODUCTS)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        client_ip = get_client_ip()
        user_agent = request.headers.get("User-Agent", "")

        # --- Check for SQL Injection Attack ---
        if detect_sqli(email) or detect_sqli(password):
            logger.warning(f"🔥 SQL Injection attempt detected from {client_ip}!")
            res = honeycloud.send_event(
                service="DEMO_ECOMMERCE",
                source_ip=client_ip,
                endpoint="/login",
                method="POST",
                severity="CRITICAL",
                description=f"SQL Injection attack attempt in login credentials. Input email: '{email}', password: '{password}'",
                additional_data={
                    "event_type": "SQL_INJECTION",
                    "payload_email": email,
                    "payload_password": password,
                    "user_agent": user_agent
                }
            )
            return handle_routing_decision(res, default_abort=403)

        # --- Check for Scripting Attack (XSS) ---
        if detect_xss(email) or detect_xss(password):
            logger.warning(f"🔥 Cross-Site Scripting (XSS) attempt detected from {client_ip}!")
            res = honeycloud.send_event(
                service="DEMO_ECOMMERCE",
                source_ip=client_ip,
                endpoint="/login",
                method="POST",
                severity="CRITICAL",
                description=f"Cross-Site Scripting (XSS) attack attempt in login credentials. Input email: '{email}', password: '{password}'",
                additional_data={
                    "event_type": "XSS_ATTACK",
                    "payload_email": email,
                    "payload_password": password,
                    "user_agent": user_agent
                }
            )
            return handle_routing_decision(res, default_abort=403)

        # --- Successful Login ---
        if DEMO_USERS.get(email) == password:
            logger.info(f"✅ Successful login: {email}")

            # Clear failed attempt counter for this IP
            login_attempts.pop(client_ip, None)

            # Send audit telemetry to HoneyCloud
            honeycloud.send_successful_login(
                source_ip=client_ip,
                username=email,
                user_agent=user_agent
            )

            return redirect(url_for("products"))

        # --- Failed Login ---
        # Track cumulative failures per IP
        if client_ip not in login_attempts:
            login_attempts[client_ip] = {"count": 0, "usernames": set()}
        login_attempts[client_ip]["count"] += 1
        login_attempts[client_ip]["usernames"].add(email)
        attempt_count = login_attempts[client_ip]["count"]
        unique_usernames = len(login_attempts[client_ip]["usernames"])

        logger.warning(
            f"⚠️ Failed login attempt #{attempt_count}: {email} from {client_ip}"
        )

        # Account Enumeration Detection:
        # If the username doesn't exist at all, this is enumeration probing
        if email not in DEMO_USERS:
            res = honeycloud.send_account_enumeration(
                source_ip=client_ip,
                username=email,
                user_agent=user_agent
            )
            logger.warning(f"🔍 Account enumeration probe: '{email}' does not exist")
        else:
            # Send failed login telemetry to HoneyCloud
            # Severity auto-escalates: MEDIUM → HIGH → CRITICAL based on attempt_count
            res = honeycloud.send_failed_login(
                source_ip=client_ip,
                username=email,
                attempt_count=attempt_count,
                user_agent=user_agent,
                referer=request.headers.get("Referer", ""),
                username_exists=True
            )

        # --- Deception Routing for Brute Force ---
        # After 5+ failures, check if HoneyCloud recommends deception
        if attempt_count >= 5:
            logger.warning(
                f"🚨 Brute force detected: {attempt_count} attempts, "
                f"{unique_usernames} unique usernames from {client_ip}"
            )

            if res and res.get("recommended_route") == "DECEPTION":
                # Trap the attacker: fake "success" then redirect to deception
                session["deception_trapped"] = True
                redirect_url = res.get("redirect_url")
                if redirect_url:
                    if redirect_url.startswith("/"):
                        deception_url = f"{HONEYCLOUD_URL.rstrip('/')}{redirect_url}"
                    else:
                        deception_url = redirect_url
                else:
                    deception_url = f"{HONEYCLOUD_URL.rstrip('/')}/deception/fake-admin"

                session["deception_redirect_url"] = deception_url
                logger.warning(
                    f"🪤 TRAPPED! Credential hunter routed to deception: {deception_url}"
                )
                return redirect(deception_url)

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")

@app.route("/api/products")
def api_products():
    return jsonify({"products": DEMO_PRODUCTS, "total": len(DEMO_PRODUCTS)})

# -----------------------------------------------------------------------------
# HONEYPOT ROUTES (SECURITY EVENTS)
# -----------------------------------------------------------------------------

@app.route("/admin", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/admin/<path:path>", methods=["GET", "POST"])
def honeypot_admin(path):
    """Admin panel honeypot - Most common attack target"""
    logger.warning(f"🚨 HONEYPOT HIT: /admin from {request.remote_addr}")
    
    # Send to HoneyCloud
    res = honeycloud.send_honeypot_hit(
        endpoint=request.path,
        source_ip=request.remote_addr,
        method=request.method,
        severity="CRITICAL",
        user_agent=request.headers.get("User-Agent", ""),
        referer=request.headers.get("Referer", "")
    )
    return handle_routing_decision(res)  # ✅ Return 404 to attacker

@app.route("/wp-admin", methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
def honeypot_wordpress():
    """WordPress admin honeypot"""
    logger.warning(f"🚨 HONEYPOT HIT: WordPress scan from {request.remote_addr}")
    
    res = honeycloud.send_honeypot_hit(
        endpoint=request.path,
        source_ip=request.remote_addr,
        method=request.method,
        severity="HIGH",
        user_agent=request.headers.get("User-Agent", "")
    )
    return handle_routing_decision(res)

@app.route("/.env", methods=["GET"])
@app.route("/.env.backup", methods=["GET"])
@app.route("/.env.prod", methods=["GET"])
def honeypot_env():
    """Environment file honeypot - Critical security risk"""
    logger.warning(f"🚨 HONEYPOT HIT: .env file probe from {request.remote_addr}")
    
    res = honeycloud.send_honeypot_hit(
        endpoint=request.path,
        source_ip=request.remote_addr,
        method=request.method,
        severity="CRITICAL",
        user_agent=request.headers.get("User-Agent", "")
    )
    return handle_routing_decision(res)

@app.route("/api/debug", methods=["GET", "POST"])
@app.route("/api/v1/debug", methods=["GET", "POST"])
def honeypot_debug():
    """Debug API honeypot"""
    logger.warning(f"🚨 HONEYPOT HIT: Debug API probe from {request.remote_addr}")
    
    res = honeycloud.send_honeypot_hit(
        endpoint=request.path,
        source_ip=request.remote_addr,
        method=request.method,
        severity="HIGH",
        user_agent=request.headers.get("User-Agent", "")
    )
    return handle_routing_decision(res)

@app.route("/phpmyadmin", methods=["GET", "POST"])
@app.route("/pma", methods=["GET", "POST"])
@app.route("/phpMyAdmin", methods=["GET", "POST"])
def honeypot_phpmyadmin():
    """phpMyAdmin honeypot"""
    logger.warning(f"🚨 HONEYPOT HIT: phpMyAdmin scan from {request.remote_addr}")
    
    res = honeycloud.send_honeypot_hit(
        endpoint=request.path,
        source_ip=request.remote_addr,
        method=request.method,
        severity="HIGH",
        user_agent=request.headers.get("User-Agent", "")
    )
    return handle_routing_decision(res)

@app.route("/.git/config", methods=["GET"])
@app.route("/.git/HEAD", methods=["GET"])
def honeypot_git():
    """Git repository exposure honeypot"""
    logger.warning(f"🚨 HONEYPOT HIT: Git repo probe from {request.remote_addr}")
    
    res = honeycloud.send_honeypot_hit(
        endpoint=request.path,
        source_ip=request.remote_addr,
        method=request.method,
        severity="CRITICAL",
        user_agent=request.headers.get("User-Agent", "")
    )
    return handle_routing_decision(res)

@app.route("/backup.sql", methods=["GET"])
@app.route("/database.sql", methods=["GET"])
@app.route("/dump.sql", methods=["GET"])
def honeypot_sql_backup():
    """SQL backup file honeypot"""
    logger.warning(f"🚨 HONEYPOT HIT: SQL backup probe from {request.remote_addr}")
    
    res = honeycloud.send_honeypot_hit(
        endpoint=request.path,
        source_ip=request.remote_addr,
        method=request.method,
        severity="CRITICAL",
        user_agent=request.headers.get("User-Agent", "")
    )
    return handle_routing_decision(res)

# -----------------------------------------------------------------------------
# HEALTH CHECK
# -----------------------------------------------------------------------------

@app.route("/health")
def health():
    """Health check endpoint"""
    honeycloud_status = "connected" if honeycloud.health_check() else "disconnected"
    
    return jsonify({
        "status": "healthy",
        "service": "demo-ecommerce",
        "timestamp": datetime.utcnow().isoformat(),
        "honeycloud": honeycloud_status
    })

# -----------------------------------------------------------------------------
# ERROR HANDLERS
# -----------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    """Custom 404 handler"""
    return "Not Found", 404


# -----------------------------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 Demo E-Commerce running on http://localhost:5000")
    print("="*70)
    print("\n📋 Legitimate Routes:")
    print("   • http://localhost:5000/          - Home page")
    print("   • http://localhost:5000/products  - Product catalog")
    print("   • http://localhost:5000/login     - Login page")
    print("\n🍯 Active Honeypots (will trigger alerts):")
    print("   • /admin              - Admin panel probe")
    print("   • /wp-admin           - WordPress scan")
    print("   • /.env               - Environment file leak")
    print("   • /api/debug          - Debug API probe")
    print("   • /phpmyadmin         - Database panel scan")
    print("   • /.git/config        - Source code disclosure")
    print("   • /backup.sql         - Database backup probe")
    print("\n🔐 Login Telemetry (sends events to HoneyCloud):")
    print("   • Failed login        - Sends FAILED_LOGIN event")
    print("   • Wrong username      - Sends ACCOUNT_ENUMERATION event")
    print("   • 5+ failures/IP      - Triggers brute force detection")
    print("   • Deception routing   - Credential hunters get trapped")
    print("   • Successful login    - Sends audit trail event")
    print("\n🔗 HoneyCloud Dashboard: http://localhost:8000/docs")
    print("="*70 + "\n")
    
    # Check HoneyCloud connection
    if honeycloud.health_check():
        print("✅ HoneyCloud connection: OK\n")
    else:
        print("⚠️  HoneyCloud connection: FAILED")
        print("   Make sure HoneyCloud is running: docker-compose up\n")
    
    # Run Flask app
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True  # ✅ Enable debug mode for development
    )
