import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# ✅ FIXED CORS (important)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── API Route ───────────────────────────────
@app.route("/predict/url", methods=["POST"])
def predict_url():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL missing"}), 400

    url = data["url"]

    try:
        # Proxy the request to the new phishing_models backend running on port 5000
        response = requests.post("http://127.0.0.1:5000/predict/url", json={"url": url}, timeout=10)
        response.raise_for_status()
        main_data = response.json()
        
        # phishing_models returns "prediction": "phishing" | "legitimate"
        is_phishing = (main_data.get("prediction") == "phishing")
        prediction = "phishing" if is_phishing else "safe"
        
        # phishing_models returns "phishing_prob": float (0.0 to 1.0)
        confidence = round(main_data.get("phishing_prob", 0) * 100, 2)
        
        # Support both old and new response spec for backward compatibility
        return jsonify({
            "prediction": prediction,
            "confidence": confidence,
            "features": {},      # Extension might expect these keys
            "domain_info": {},
            
            # New Pre-Load Real-Time Detection fields
            "is_phishing": is_phishing,
            "risk_score": confidence,
            "reasons": main_data.get("top_signals", main_data.get("signals", []))
        })

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to call phishing-models backend: {str(e)}"}), 500

# ── Test Route (IMPORTANT FOR BROWSER CHECK) ──
@app.route("/")
def home():
    return "🚀 Phishing Detection Proxy API is Running!"

# ── Run ─────────────────────────────────────
if __name__ == "__main__":
    # Running on 5001 so it doesn't conflict with phishing_models on 5000
    app.run(port=5001, debug=True)