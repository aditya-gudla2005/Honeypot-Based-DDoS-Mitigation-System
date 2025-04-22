from flask import Flask, request, redirect, render_template_string, abort
import time
from datetime import datetime
import os

app = Flask(__name__)

# Security Configuration
REDIRECT_KEY = "SECURE_KEY_123"  # Must match real_website.py
REAL_SITE_URL = "https://my-real-website-b3cg.onrender.com"  # Add `:10000`!
MAX_REQUESTS_PER_MIN = 30  # Lowered for stricter blocking
WHITELISTED_PATHS = ['/', '/favicon.ico']

# IP Management
BLOCKED_IPS_FILE = "blocked_ips.txt"
blocked_ips = set()
request_counts = {}

# Load blocked IPs
if os.path.exists(BLOCKED_IPS_FILE):
    with open(BLOCKED_IPS_FILE, "r") as f:
        blocked_ips.update(f.read().splitlines())

def block_ip(ip):
    """Permanently block an IP and log it"""
    blocked_ips.add(ip)
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(f"{ip} - {datetime.now()}\n")
    print(f"🚨 BLOCKED ATTACKER: {ip} at {datetime.now()}")

def is_attacker(ip, path, user_agent):
    """Enhanced attack detection with real-time logging"""
    # Path probing detection
    if path not in WHITELISTED_PATHS:
        print(f"🚨 Blocked {ip} for path probing: {path}")
        return True
        
    # Rate limiting
    current_time = time.time()
    if ip not in request_counts:
        request_counts[ip] = {'count': 1, 'time': current_time}
    else:
        request_counts[ip]['count'] += 1
    
    # Reset counter if minute passed
    if current_time - request_counts[ip]['time'] > 60:
        request_counts[ip] = {'count': 1, 'time': current_time}
    elif request_counts[ip]['count'] > MAX_REQUESTS_PER_MIN:
        print(f"🚨 Blocked {ip} for exceeding rate limit ({request_counts[ip]['count']} requests/min)")
        return True
    
    # Bot/Scanner detection
    bad_agents = ['bot', 'spider', 'scan', 'crawl', 'sqlmap', 'nikto', 'metasploit']
    if any(bot in user_agent.lower() for bot in bad_agents):
        print(f"🚨 Blocked {ip} for bot User-Agent: {user_agent}")
        return True
    
    return False

@app.before_request
def protect():
    ip = request.remote_addr
    path = request.path
    user_agent = request.headers.get('User-Agent', '')
    
    if ip in blocked_ips:
        abort(403, description="IP permanently blocked")
    
    if is_attacker(ip, path, user_agent):
        block_ip(ip)
        abort(429, description="Too many requests")

@app.route('/')
def home():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Legitimate user detection (modern browsers)
    if any(x in user_agent for x in ['mozilla', 'chrome', 'safari', 'edge', 'firefox']):
        return render_template_string(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting...</title>
            <meta http-equiv="refresh" content="3;url={REAL_SITE_URL}?key={REDIRECT_KEY}">
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f5f5f5; }}
                .message {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; margin: 0 auto; }}
            </style>
        </head>
        <body>
            <div class="message">
                <h2>Please wait...</h2>
                <p>You are a legitimate user. You will be redirected to our real site in 3 seconds.</p>
                <p>If not redirected automatically, <a href="{REAL_SITE_URL}?key={REDIRECT_KEY}">click here</a>.</p>
            </div>
        </body>
        </html>
        """)
    
    # Show fake page to attackers
    return render_template_string("""
    <h1>Welcome to Wikipedia</h1>
    <p>This is a honeypot page.</p>
    """)

if __name__ == '__main__':
    print("🔥 Honeypot running - Attackers will be auto-blocked!")
    app.run(port=8080, host='0.0.0.0')
