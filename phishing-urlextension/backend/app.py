from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re
import math
import os
import whois
from datetime import datetime

app = Flask(__name__)

# ✅ FIXED CORS (important)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Load Models ─────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(BASE, "phishing_models")

url_model  = joblib.load(os.path.join(MODELS, "url_model.pkl"))
url_scaler = joblib.load(os.path.join(MODELS, "url_scaler.pkl"))

print("✅ Models Loaded")

# ── Feature Functions ───────────────────────
def calculate_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return round(-sum((c/n) * math.log2(c/n) for c in freq.values()), 4)

def extract_url_features(url):
    url = str(url).lower()

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_https": int(url.startswith("https")),
        "has_ip_address": int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        "suspicious_keywords": sum(k in url for k in ["login","verify","bank","secure"]),
        "num_subdomains": max(0, url.count(".") - 1),
        "path_length": len(url.split("/")[-1]),
        "entropy": calculate_entropy(url)
    }

# ── WHOIS + Domain Info ─────────────────────
def get_domain_info(url):
    try:
        domain = url.split("//")[-1].split("/")[0]

        w = whois.whois(domain)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        age_days = None
        if creation:
            age_days = (datetime.now() - creation).days

        return {
            "domain": domain,
            "age_days": age_days,
            "country": str(w.country)
        }

    except Exception as e:
        return {
            "domain": domain,
            "error": "WHOIS lookup failed"
        }

# ── API Route ───────────────────────────────
@app.route("/predict/url", methods=["POST"])
def predict_url():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL missing"}), 400

    url = data["url"]

    features = extract_url_features(url)
    df = pd.DataFrame([features])
    scaled = url_scaler.transform(df)

    pred = int(url_model.predict(scaled)[0])
    prob = url_model.predict_proba(scaled)[0]
    confidence = round(float(prob[pred]) * 100, 2)

    domain_info = get_domain_info(url)

    return jsonify({
        "prediction": "phishing" if pred == 1 else "safe",
        "confidence": confidence,
        "features": features,
        "domain_info": domain_info
    })

# ── Test Route (IMPORTANT FOR BROWSER CHECK) ──
@app.route("/")
def home():
    return "🚀 Phishing Detection API is Running!"

# ── Run ─────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)