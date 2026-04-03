from flask import Flask, request, jsonify, send_from_directory
import joblib
import pandas as pd
import numpy as np
import re
import math
import string
import os

app = Flask(__name__, static_folder="static")

# ── Load models ──────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(BASE, "models")

url_model  = joblib.load(os.path.join(MODELS, "url_model.pkl"))
url_scaler = joblib.load(os.path.join(MODELS, "url_scaler.pkl"))
text_model = joblib.load(os.path.join(MODELS, "text_model.pkl"))
tfidf      = joblib.load(os.path.join(MODELS, "tfidf.pkl"))

print("✅ All 4 models loaded successfully.")

# ── Helpers ───────────────────────────────────────────────────────
def calculate_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return round(-sum((c/n) * math.log2(c/n) for c in freq.values()), 4)


def extract_url_features(url):
    url = str(url).strip().lower()
    url_no_proto = re.sub(r"^https?://", "", url)
    suspicious_kw = ["login","verify","secure","update","account",
                     "banking","confirm","password","signin","ebayisapi",
                     "webscr","paypal","free","prize","winner"]
    ip_pattern = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )
    try:
        hostname = url_no_proto.split("/")[0].split(":")[0]
        num_subdomains = max(0, hostname.count(".") - 1)
    except Exception:
        hostname = ""; num_subdomains = 0
    try:
        path_length = len("/" + "/".join(url_no_proto.split("/")[1:]))
    except Exception:
        path_length = 0

    return {
        "url_length":          len(url),
        "num_dots":            url.count("."),
        "num_hyphens":         url.count("-"),
        "num_digits":          sum(c.isdigit() for c in url),
        "has_https":           int(url.startswith("https")),
        "has_ip_address":      int(bool(ip_pattern.search(url))),
        "suspicious_keywords": sum(kw in url for kw in suspicious_kw),
        "num_subdomains":      num_subdomains,
        "path_length":         path_length,
        "entropy":             calculate_entropy(url),
    }


def preprocess_text(text):
    text = str(text).lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    return re.sub(r"\s+", " ", text).strip()


# ── Routes ────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/predict/url", methods=["POST"])
def predict_url():
    data = request.get_json()
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features    = extract_url_features(url)
    feat_df     = pd.DataFrame([features])
    feat_scaled = url_scaler.transform(feat_df)
    pred        = int(url_model.predict(feat_scaled)[0])
    proba       = url_model.predict_proba(feat_scaled)[0]
    confidence  = round(float(proba[pred]) * 100, 2)

    return jsonify({
        "prediction": "phishing" if pred == 1 else "safe",
        "confidence": confidence,
        "features":   features
    })


@app.route("/predict/text", methods=["POST"])
def predict_text():
    data = request.get_json()
    text = data.get("text", "").strip()

    if not text:
        return jsonify({"error": "No text provided"}), 400

    clean      = preprocess_text(text)
    vec        = tfidf.transform([clean])
    pred       = int(text_model.predict(vec)[0])
    proba      = text_model.predict_proba(vec)[0]
    confidence = round(float(proba[pred]) * 100, 2)

    return jsonify({
        "prediction": "phishing" if pred == 1 else "safe",
        "confidence": confidence
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)