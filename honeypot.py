from flask import Flask, request, redirect, render_template_string, abort
import time
from datetime import datetime
import os
import ipaddress

app = Flask(__name__)

# Security Configuration
REDIRECT_KEY = "SECURE_KEY_123"
REAL_SITE_URL = "https://my-real-website-b3cg.onrender.com"
MAX_REQUESTS_PER_MIN = 100  # Increased to avoid false positives
WHITELISTED_PATHS = ['/', '/favicon.ico', '/static/*']
SAFE_USER_AGENTS = ['mozilla', 'chrome', 'safari', 'firefox', 'edge']

# Cloudflare and Render IP ranges (CIDR notation)
TRUSTED_NETWORKS = [
    '104.16.0.0/13',    # Cloudflare
    '216.24.57.0/24',   # Render
    '172.16.0.0/12'     # Private network
]

# IP Management
BLOCKED_IPS_FILE = "blocked_ips.txt"
blocked_ips = set()
request_counts = {}

def is_trusted_ip(ip):
    """Check if IP belongs to Cloudflare, Render, or private networks"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in TRUSTED_NETWORKS:
            if ip_obj in ipaddress.ip_network(network):
                return True
    except ValueError:
        pass
    return False

def get_real_ip():
    """Get the real client IP when behind Cloudflare"""
    if 'CF-Connecting-IP' in request.headers:
        return request.headers['CF-Connecting-IP']
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

# Load blocked IPs
if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        blocked_ips.update(line.split(' - ')[0] for line in f.read().splitlines() if line.strip())

def block_ip(ip):
    """Block an IP and log it"""
    if is_trusted_ip(ip):
        print(f"⚠️ Not blocking trusted IP: {ip}")
        return
        
    blocked_ips.add(ip)
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(f"{ip} - {datetime.now()}\n")
    print(f"🚨 BLOCKED ATTACKER: {ip} at {datetime.now()}")

def is_attacker(ip, path, user_agent):
    """Enhanced attack detection that won't block legitimate users"""
    if is_trusted_ip(ip):
        return False
        
    user_agent = user_agent.lower()
    
    # Always allow whitelisted paths
    if path in WHITELISTED_PATHS:
        return False
        
    # Never block browser traffic
    if any(agent in user_agent for agent in SAFE_USER_AGENTS):
        return False
        
    # Rate limiting (only applies to non-browser traffic)
    current_time = time.time()
    if ip not in request_counts:
        request_counts[ip] = {'count': 1, 'time': current_time}
    else:
        request_counts[ip]['count'] += 1
    
    if current_time - request_counts[ip]['time'] > 60:
        request_counts[ip] = {'count': 1, 'time': current_time}
    elif request_counts[ip]['count'] > MAX_REQUESTS_PER_MIN:
        print(f"🚨 Blocked {ip} for excessive requests ({request_counts[ip]['count']}/min)")
        return True
    
    # Detect known bad tools
    bad_agents = ['sqlmap', 'nikto', 'metasploit', 'hydra', 'wpscan', 'zap']
    if any(bot in user_agent for bot in bad_agents):
        print(f"🚨 Blocked {ip} for malicious User-Agent: {user_agent[:50]}")
        return True
    
    # Path probing detection (only for non-whitelisted paths)
    print(f"🚨 Blocked {ip} for probing restricted path: {path}")
    return True

@app.before_request
def protect():
    ip = get_real_ip()
    path = request.path
    user_agent = request.headers.get('User-Agent', '')
    
    # Skip protection for whitelisted paths
    if path.startswith('/static/'):
        return
    
    if ip in blocked_ips:
        abort(403, description="IP blocked due to malicious activity")
    
    if is_attacker(ip, path, user_agent):
        block_ip(ip)
        abort(429, description="Suspicious activity detected")

@app.route('/')
def home():
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Modern browser detection
    if any(x in user_agent for x in SAFE_USER_AGENTS):
        return render_template_string(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting...</title>
            <meta http-equiv="refresh" content="3;url={REAL_SITE_URL}?key={REDIRECT_KEY}">
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .box {{ background: white; padding: 30px; border-radius: 8px; max-width: 500px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            </style>
        </head>
        <body>
            <div class="box">
                <h2>Welcome to our site</h2>
                <p>Redirecting you to our secure portal...</p>
                <p><small>If not redirected, <a href="{REAL_SITE_URL}?key={REDIRECT_KEY}">click here</a>.</small></p>
            </div>
        </body>
        </html>
        """)
    
    # Show honeypot page to non-browser requests
    return render_template_string("""
    <h1>Wikipedia</h1>
    <p>Free Encyclopedia</p>
    <form action="/search">
        <input type="text" name="q" placeholder="Search...">
        <button>Search</button>
    </form>
    """)
# [Keep all your existing code above this]

# ===== DASHBOARD ROUTES =====
@app.route('/dashboard')
def dashboard():
    return send_from_directory('.', 'dashboard.html')

@app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    ip = request.form.get('ip', '').strip()
    if not ip:
        return "IP required", 400
    
    blocked_ips.discard(ip)
    
    # Update the blocked_ips file
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'w') as f:
            f.write('\n'.join(f"{ip} - {datetime.now()}" for ip in blocked_ips))
    
    return f"Unblocked {ip}", 200

# ===== LAUNCH APP =====
if __name__ == '__main__':
    print("🔥 Honeypot active - Legitimate users will be redirected")
    print(f"Blocked IPs: {len(blocked_ips)}")
    app.run(port=8080, host='0.0.0.0')
