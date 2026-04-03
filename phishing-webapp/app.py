from flask import (
    Flask, request, jsonify, send_from_directory,
    redirect, session, render_template
)
import joblib, pandas as pd, numpy as np
import re, math, string, os, base64, io, json

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import google.auth.transport.requests

try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = False
app.secret_key = os.environ.get("FLASK_SECRET", "CHANGE_ME_IN_PRODUCTION_abc123xyz")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

BASE   = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(BASE, "models")

# ---------------- Load Models ----------------

def load_models():
    try:
        um  = joblib.load(os.path.join(MODELS, "url_model.pkl"))
        us  = joblib.load(os.path.join(MODELS, "url_scaler.pkl"))
        tm  = joblib.load(os.path.join(MODELS, "text_model.pkl"))
        tf_ = joblib.load(os.path.join(MODELS, "tfidf.pkl"))
        print("✅ All 4 models loaded successfully.")
        return um, us, tm, tf_
    except FileNotFoundError:
        print("⚠️  Model files not found. Analysis endpoints will be unavailable.")
        return None, None, None, None

url_model, url_scaler, text_model, tfidf = load_models()

CLIENT_SECRETS_FILE = os.path.join(BASE, "client_secret.json")
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]
REDIRECT_URI = "http://localhost:5000/oauth2callback"


# ---------------- Helper: Build Credentials ----------------

def get_credentials():
    creds_data = session.get("credentials")
    if not creds_data:
        return None
    creds = Credentials(
        token=creds_data["token"],
        refresh_token=creds_data.get("refresh_token"),
        token_uri=creds_data["token_uri"],
        client_id=creds_data["client_id"],
        client_secret=creds_data["client_secret"],
        scopes=creds_data["scopes"],
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(google.auth.transport.requests.Request())
        session["credentials"]["token"] = creds.token
    return creds


# ---------------- Static Route ----------------

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# ---------------- OAuth Routes ----------------

@app.route("/login")
def login():
    if not os.path.exists(CLIENT_SECRETS_FILE):
        return jsonify({"error": "client_secret.json not found"}), 503

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )

    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )

    session["state"] = state
    return redirect(auth_url)


@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session.get("state"),
        redirect_uri=REDIRECT_URI,
    )

    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    session["credentials"] = {
        "token":         creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri":     creds.token_uri,
        "client_id":     creds.client_id,
        "client_secret": creds.client_secret,
        "scopes":        list(creds.scopes),
    }

    return redirect("/?gmail=1")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- Auth Status ----------------

@app.route("/auth/status")
def auth_status():
    creds = get_credentials()
    if not creds:
        return jsonify({"logged_in": False})
    try:
        service   = build("oauth2", "v2", credentials=creds)
        user_info = service.userinfo().get().execute()
        return jsonify({
            "logged_in": True,
            "email":     user_info.get("email"),
            "name":      user_info.get("name"),
            "picture":   user_info.get("picture"),
        })
    except Exception as e:
        return jsonify({"logged_in": False, "error": str(e)})


# ---------------- Gmail Routes ----------------

@app.route("/gmail/emails")
def gmail_emails():
    creds = get_credentials()
    if not creds:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(
            userId="me", maxResults=20, labelIds=["INBOX"]
        ).execute()

        messages = results.get("messages", [])
        emails   = []

        for msg in messages:
            msg_data = service.users().messages().get(
                userId="me", id=msg["id"], format="full"
            ).execute()

            headers = {
                h["name"]: h["value"]
                for h in msg_data["payload"].get("headers", [])
            }

            # Extract body text
            body    = ""
            payload = msg_data.get("payload", {})
            if "parts" in payload:
                for part in payload["parts"]:
                    if part.get("mimeType") == "text/plain":
                        data = part.get("body", {}).get("data", "")
                        if data:
                            body = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                            break
            else:
                data = payload.get("body", {}).get("data", "")
                if data:
                    body = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

            emails.append({
                "id":      msg["id"],
                "subject": headers.get("Subject", "(No Subject)"),
                "from":    headers.get("From", "Unknown"),
                "date":    headers.get("Date", ""),
                "snippet": msg_data.get("snippet", ""),
                "body":    body[:500],
            })

        return jsonify({"emails": emails})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/gmail/analyze/<msg_id>")
def gmail_analyze(msg_id):
    """Fetch a single Gmail message and run phishing analysis on it."""
    creds = get_credentials()
    if not creds:
        return jsonify({"error": "Not authenticated"}), 401

    if text_model is None or tfidf is None:
        return jsonify({"error": "Text model not loaded"}), 503

    try:
        service  = build("gmail", "v1", credentials=creds)
        msg_data = service.users().messages().get(
            userId="me", id=msg_id, format="full"
        ).execute()

        headers = {
            h["name"]: h["value"]
            for h in msg_data["payload"].get("headers", [])
        }

        body    = ""
        payload = msg_data.get("payload", {})
        if "parts" in payload:
            for part in payload["parts"]:
                if part.get("mimeType") == "text/plain":
                    data = part.get("body", {}).get("data", "")
                    if data:
                        body = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                        break
        else:
            data = payload.get("body", {}).get("data", "")
            if data:
                body = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

        text_to_analyze = body or msg_data.get("snippet", "")

        features    = tfidf.transform([text_to_analyze])
        prediction  = text_model.predict(features)[0]
        probability = text_model.predict_proba(features)[0]

        return jsonify({
            "id":         msg_id,
            "subject":    headers.get("Subject", "(No Subject)"),
            "from":       headers.get("From", "Unknown"),
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(float(max(probability)) * 100, 2),
            "phishing_probability": round(float(probability[1]) * 100, 2),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- URL Analysis ----------------

@app.route("/analyze/url", methods=["POST"])
def analyze_url():
    if url_model is None or url_scaler is None:
        return jsonify({"error": "URL model not loaded"}), 503

    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        features        = extract_url_features(url)
        features_scaled = url_scaler.transform([features])
        prediction      = url_model.predict(features_scaled)[0]
        probability     = url_model.predict_proba(features_scaled)[0]

        return jsonify({
            "url":        url,
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(float(max(probability)) * 100, 2),
            "phishing_probability": round(float(probability[1]) * 100, 2),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Text Analysis ----------------

@app.route("/analyze/text", methods=["POST"])
def analyze_text():
    if text_model is None or tfidf is None:
        return jsonify({"error": "Text model not loaded"}), 503

    data = request.get_json()
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    try:
        features    = tfidf.transform([text])
        prediction  = text_model.predict(features)[0]
        probability = text_model.predict_proba(features)[0]

        return jsonify({
            "prediction": "phishing" if prediction == 1 else "legitimate",
            "confidence": round(float(max(probability)) * 100, 2),
            "phishing_probability": round(float(probability[1]) * 100, 2),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Image / OCR Analysis ----------------

@app.route("/analyze/image", methods=["POST"])
def analyze_image():
    if not OCR_AVAILABLE:
        return jsonify({"error": "OCR not available (Pillow/pytesseract not installed)"}), 503

    data       = request.get_json()
    image_data = data.get("image", "")

    if not image_data:
        return jsonify({"error": "No image data provided"}), 400

    try:
        if "," in image_data:
            image_data = image_data.split(",")[1]

        image_bytes    = base64.b64decode(image_data)
        image          = Image.open(io.BytesIO(image_bytes))
        extracted_text = pytesseract.image_to_string(image)

        if not extracted_text.strip():
            return jsonify({"error": "No text could be extracted from the image"}), 400

        if text_model and tfidf:
            features    = tfidf.transform([extracted_text])
            prediction  = text_model.predict(features)[0]
            probability = text_model.predict_proba(features)[0]

            return jsonify({
                "extracted_text": extracted_text,
                "prediction":     "phishing" if prediction == 1 else "legitimate",
                "confidence":     round(float(max(probability)) * 100, 2),
                "phishing_probability": round(float(probability[1]) * 100, 2),
            })
        else:
            return jsonify({
                "extracted_text": extracted_text,
                "error": "Text model not loaded"
            })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- URL Feature Extraction ----------------

def extract_url_features(url: str) -> list:
    features = []

    features.append(len(url))
    features.append(len(url.split("//")[-1].split("/")[0]))  # domain length
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("_"))
    features.append(url.count("/"))
    features.append(url.count("?"))
    features.append(url.count("="))
    features.append(url.count("@"))
    features.append(url.count("&"))
    features.append(url.count("!"))
    features.append(url.count(" "))
    features.append(url.count("~"))
    features.append(url.count(","))
    features.append(url.count("+"))
    features.append(url.count("*"))
    features.append(url.count("#"))
    features.append(url.count("$"))
    features.append(url.count("%"))
    features.append(1 if "https" in url else 0)
    features.append(1 if "http"  in url else 0)
    features.append(1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0)

    digits  = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    features.append(digits)
    features.append(letters)
    features.append(round(digits / max(len(url), 1), 4))

    return features


# ---------------- Run ----------------

if __name__ == "__main__":
    print("\n🛡️  PhishGuard starting...")
    print("   Open: http://localhost:5000")
    app.run(debug=True, port=5000, use_reloader=False)