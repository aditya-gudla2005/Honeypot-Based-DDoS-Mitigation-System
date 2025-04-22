from flask import Flask, request, redirect, render_template_string, abort
import time
from datetime import datetime
import os

app = Flask(__name__)

# Security Configuration
REDIRECT_KEY = "SECURE_KEY_123"
REAL_SITE_URL = "https://my-real-website-b3cg.onrender.com"
MAX_REQUESTS_PER_MIN = 100  # Increased to avoid false positives
WHITELISTED_PATHS = ['/', '/favicon.ico', '/static/*']
SAFE_USER_AGENTS = ['mozilla', 'chrome', 'safari', 'firefox', 'edge']

# IP Management
BLOCKED_IPS_FILE = "blocked_ips.txt"
blocked_ips = set()
request_counts = {}

# Load blocked IPs
if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        blocked_ips.update(line.split(' - ')[0] for line in f.read().splitlines() if line.strip())

def block_ip(ip):
    """Block an IP and log it"""
    blocked_ips.add(ip)
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(f"{ip} - {datetime.now()}\n")
    print(f"🚨 BLOCKED ATTACKER: {ip} at {datetime.now()}")

def is_attacker(ip, path, user_agent):
    """Enhanced attack detection that won't block legitimate users"""
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
    ip = request.remote_addr
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

if __name__ == '__main__':
    print("🔥 Honeypot active - Legitimate users will be redirected")
    print(f"Blocked IPs: {len(blocked_ips)}")
    app.run(port=8080, host='0.0.0.0')
