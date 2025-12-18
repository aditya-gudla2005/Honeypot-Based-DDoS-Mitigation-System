import os  
from flask import Flask, render_template, request

app = Flask(__name__)

REDIRECT_KEY = "SECURE_KEY_123"  

articles = {
    "Programming": "Real programming content here...",
    "Security": "Real security content here..."
}

@app.route('/')
def home():
    if request.args.get('key') == REDIRECT_KEY:
        return render_template("wiki_home.html")
    return "Direct access forbidden", 403

@app.route('/article/<title>')
def article(title):
    if request.args.get('key') == REDIRECT_KEY:
        return render_template("wiki_article.html", title=title)
    return "Direct access forbidden", 403

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  
    app.run(host='0.0.0.0', port=port)


