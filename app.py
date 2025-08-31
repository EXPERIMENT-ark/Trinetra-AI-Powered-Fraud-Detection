# app.py
from flask import Flask, request, jsonify, render_template
import requests
from urllib.parse import urlparse
import datetime
import imagehash
from PIL import Image
import io

app = Flask(__name__)

# A simple dictionary of suspicious keywords
SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "urgent action required",
    "claim your prize",
    "winner",
    "congratulations",
    "free money",
    "click here to login",
    "security alert"
]

# A small dictionary of known brand image hashes (in a real scenario, this would be a larger database)
KNOWN_BRAND_HASHES = {
    "google": "3f3f3f3f3f3f3f3f",  # A sample hash
    "paypal": "f3f3f3f3f3f3f3f3"   # Another sample hash
}

def get_domain_age(url):
    """
    A placeholder function to simulate a WHOIS lookup.
    In a real app, you would use an API like whois-api.com.
    """
    # Simulate a new domain for demonstration
    return (datetime.date.today() - datetime.date(2025, 7, 1)).days

def check_suspicious_keywords(text):
    """Checks if the text contains suspicious keywords."""
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in text.lower()]
    return found_keywords

def check_visual_similarity(url):
    """Simulates UI similarity check using image hashing."""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            img = Image.open(io.BytesIO(response.content))
            page_hash = str(imagehash.phash(img))
            
            # Compare with known brand hashes
            for brand, brand_hash in KNOWN_BRAND_HASHES.items():
                if imagehash.hex_to_hash(page_hash) - imagehash.hex_to_hash(brand_hash) < 5: # Threshold
                    return f"UI is visually similar to {brand}"
    except Exception as e:
        print(f"Image hashing error: {e}")
    return None

def analyze_url(url):
    """The main function to analyze the URL and provide a risk score."""
    risk_score = 0
    reasons = []

    # 1. URL Analysis
    parsed_url = urlparse(url)
    domain_age = get_domain_age(url)
    if domain_age < 90:
        risk_score += 5
        reasons.append(f"Domain is new (registered {domain_age} days ago).")
    
    # Check for TLD
    tld = parsed_url.netloc.split('.')[-1]
    if tld in ['xyz', 'club', 'gq', 'pw']:
        risk_score += 2
        reasons.append(f"Using a suspicious Top-Level Domain (.{tld}).")

    # 2. Content Analysis (NLP rules)
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text
            keywords = check_suspicious_keywords(content)
            if keywords:
                risk_score += 4
                reasons.append(f"Found suspicious keywords: {', '.join(keywords)}.")
    except Exception as e:
        reasons.append(f"Could not retrieve website content: {e}.")

    # 3. Visual Similarity
    ui_reason = check_visual_similarity(url)
    if ui_reason:
        risk_score += 5
        reasons.append(ui_reason)

    # 4. Final Classification
    if risk_score > 10:
        status = "🔴 High Risk (Scam/Phishing)"
    elif risk_score >= 5:
        status = "🟡 Medium Risk (Suspicious)"
    else:
        status = "🟢 Low Risk (Likely Safe)"

    return {
        "status": status,
        "score": risk_score,
        "reasons": reasons
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL is missing."}), 400
    
    result = analyze_url(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
