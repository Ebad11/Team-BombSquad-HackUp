from flask import (
    Flask, request, jsonify, send_from_directory,
    redirect, session
)
import joblib, pandas as pd, numpy as np
import re, math, string, os, base64, io, json, traceback

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import google.auth.transport.requests

# ── OCR: Pillow + Tesseract ──────────────────────────────────────
try:
    from PIL import Image
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__, static_folder="static")
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE']   = False
app.secret_key = os.environ.get("FLASK_SECRET", "CHANGE_ME_IN_PRODUCTION_abc123xyz")

BASE   = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(BASE, "models")

# ════════════════════════════════════════════════════════════════
#  LOAD MODELS
# ════════════════════════════════════════════════════════════════

def load_models():
    try:
        um  = joblib.load(os.path.join(MODELS, "url_model.pkl"))
        us  = joblib.load(os.path.join(MODELS, "url_scaler.pkl"))
        tm  = joblib.load(os.path.join(MODELS, "text_model.pkl"))
        tf_ = joblib.load(os.path.join(MODELS, "tfidf.pkl"))
        print("✅ All 4 models loaded successfully.")
        return um, us, tm, tf_
    except FileNotFoundError as e:
        print(f"⚠️  Model files not found: {e}")
        return None, None, None, None

url_model, url_scaler, text_model, tfidf = load_models()

# ════════════════════════════════════════════════════════════════
#  OAUTH CONFIG
# ════════════════════════════════════════════════════════════════

CLIENT_SECRETS_FILE = os.path.join(BASE, "client_secret.json")
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]
REDIRECT_URI = "http://localhost:5000/oauth2callback"

# ════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════

def get_credentials():
    creds_data = session.get("credentials")
    if not creds_data:
        return None
    creds = Credentials(
        token         = creds_data["token"],
        refresh_token = creds_data.get("refresh_token"),
        token_uri     = creds_data["token_uri"],
        client_id     = creds_data["client_id"],
        client_secret = creds_data["client_secret"],
        scopes        = creds_data["scopes"],
    )
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(google.auth.transport.requests.Request())
            session["credentials"]["token"] = creds.token
            print("🔄 Token refreshed.")
        except Exception as e:
            print(f"❌ Token refresh failed: {e}")
            return None
    return creds


# ── Used ONLY for manual /analyze/url endpoint ──────────────────
# Exactly 10 features to match the trained MinMaxScaler
def extract_url_features(url: str) -> list:
    digits = sum(c.isdigit() for c in url)
    return [
        len(url),                                                      # 1. URL length
        url.count("."),                                                # 2. dots
        url.count("-"),                                                # 3. hyphens
        url.count("/"),                                                # 4. slashes
        url.count("@"),                                                # 5. @ symbol
        url.count("?"),                                                # 6. question marks
        url.count("="),                                                # 7. equals signs
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,          # 8. has IP address
        1 if url.lower().startswith("https") else 0,                  # 9. uses HTTPS
        round(digits / max(len(url), 1), 4),                          # 10. digit ratio
    ]


def decode_body(payload):
    """Recursively extract plain-text body from a Gmail payload."""
    if "parts" in payload:
        for part in payload["parts"]:
            if part.get("mimeType") == "text/plain":
                data = part.get("body", {}).get("data", "")
                if data:
                    return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
        for part in payload["parts"]:
            result = decode_body(part)
            if result:
                return result
    else:
        data = payload.get("body", {}).get("data", "")
        if data:
            return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
    return ""


# ════════════════════════════════════════════════════════════════
#  STATIC
# ════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# ════════════════════════════════════════════════════════════════
#  OAUTH ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/login")
def login():
    if not os.path.exists(CLIENT_SECRETS_FILE):
        return jsonify({"error": "client_secret.json not found."}), 503

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent"
    )
    session["state"] = state
    return redirect(auth_url)


@app.route("/oauth2callback")
def oauth2callback():
    print("OAuth callback received")
    if "error" in request.args:
        return f"OAuth error: {request.args['error']}", 400

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session.get("state"),
        redirect_uri=REDIRECT_URI,
    )
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        print(f"❌ fetch_token failed: {e}\n{traceback.format_exc()}")
        return f"Token error: {e}", 500

    creds = flow.credentials
    session["credentials"] = {
        "token":         creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri":     creds.token_uri,
        "client_id":     creds.client_id,
        "client_secret": creds.client_secret,
        "scopes":        list(creds.scopes),
    }
    print(f"✅ OAuth complete. Refresh token present: {bool(creds.refresh_token)}")
    return redirect("/?gmail=1")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ════════════════════════════════════════════════════════════════
#  AUTH STATUS
# ════════════════════════════════════════════════════════════════

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


# ════════════════════════════════════════════════════════════════
#  GMAIL — SCAN
#  ✅ Uses TEXT MODEL ONLY for verdict (no URL model in scan)
#     URL model is reserved for manual /analyze/url tab only
# ════════════════════════════════════════════════════════════════

@app.route("/gmail/scan")
def gmail_scan():
    creds = get_credentials()
    if not creds:
        return jsonify({"error": "Not authenticated"}), 401

    if text_model is None or tfidf is None:
        return jsonify({"error": "Models not loaded"}), 503

    max_emails  = min(int(request.args.get("max", 30)), 100)
    inbox_quota = max_emails // 2
    spam_quota  = max_emails - inbox_quota
    print(f"📬 Gmail scan: {inbox_quota} inbox + {spam_quota} spam")

    try:
        service = build("gmail", "v1", credentials=creds)

        inbox_resp = service.users().messages().list(
            userId="me", maxResults=inbox_quota, labelIds=["INBOX"]
        ).execute()
        inbox_msgs = [(m, "INBOX") for m in inbox_resp.get("messages", [])]

        spam_resp = service.users().messages().list(
            userId="me", maxResults=spam_quota, labelIds=["SPAM"]
        ).execute()
        spam_msgs = [(m, "SPAM") for m in spam_resp.get("messages", [])]

        all_messages = spam_msgs + inbox_msgs
        print(f"   Got {len(inbox_msgs)} inbox + {len(spam_msgs)} spam = {len(all_messages)} total")

    except Exception as e:
        print(f"❌ Gmail list failed: {e}\n{traceback.format_exc()}")
        return jsonify({"error": f"Gmail API error: {str(e)}"}), 500

    if not all_messages:
        return jsonify({
            "total": 0, "phishing_count": 0,
            "safe_count": 0, "phishing_rate": 0, "emails": []
        })

    emails         = []
    phishing_count = 0

    for msg_meta, folder in all_messages:
        try:
            msg_data = service.users().messages().get(
                userId="me", id=msg_meta["id"], format="full"
            ).execute()
        except Exception as e:
            print(f"   skip {msg_meta['id']}: {e}")
            continue

        headers = {
            h["name"]: h["value"]
            for h in msg_data.get("payload", {}).get("headers", [])
        }
        subject = headers.get("Subject", "(No Subject)")
        sender  = headers.get("From",    "Unknown")
        date    = headers.get("Date",    "")
        snippet = msg_data.get("snippet", "")

        body            = decode_body(msg_data.get("payload", {}))
        text_to_analyze = (body or snippet or subject)[:1000]

        # ── Text model verdict (only model used for Gmail scan) ──
        try:
            vec        = tfidf.transform([text_to_analyze])
            pred_text  = int(text_model.predict(vec)[0])
            proba_text = text_model.predict_proba(vec)[0]
            text_conf  = round(float(max(proba_text)) * 100, 2)
        except Exception:
            pred_text = 0; text_conf = 0.0

        # ── Collect URLs for display only (not used for verdict) ──
        urls_found = re.findall(r'https?://[^\s<>"\']+', snippet + " " + body)
        urls_found = list(set(urls_found))[:5]

        # ── Verdict: text model + SPAM folder only ──
        in_spam     = (folder == "SPAM")
        is_phishing = (pred_text == 1) or in_spam
        if is_phishing:
            phishing_count += 1

        emails.append({
            "id":          msg_meta["id"],
            "subject":     subject,
            "sender":      sender,
            "date":        date,
            "snippet":     snippet[:200],
            "folder":      folder,
            "is_phishing": is_phishing,
            "urls_found":  urls_found,
            "text_result": {"confidence": text_conf},
        })

    safe_count    = len(emails) - phishing_count
    phishing_rate = round(phishing_count / max(len(emails), 1) * 100, 1)
    print(f"✅ Scan done: {phishing_count} phishing / {safe_count} safe")

    return jsonify({
        "total":          len(emails),
        "phishing_count": phishing_count,
        "safe_count":     safe_count,
        "phishing_rate":  phishing_rate,
        "emails":         emails,
    })


# ════════════════════════════════════════════════════════════════
#  MANUAL — URL  (URL model used here only)
# ════════════════════════════════════════════════════════════════

@app.route("/analyze/url", methods=["POST"])
def analyze_url():
    if url_model is None or url_scaler is None:
        return jsonify({"error": "URL model not loaded"}), 503

    data = request.get_json()
    url  = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        features  = extract_url_features(url)
        scaled    = url_scaler.transform([features])
        pred      = int(url_model.predict(scaled)[0])
        proba     = url_model.predict_proba(scaled)[0]
        return jsonify({
            "url":        url,
            "prediction": "phishing" if pred == 1 else "safe",
            "confidence": round(float(max(proba)) * 100, 2),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ════════════════════════════════════════════════════════════════
#  MANUAL — TEXT
# ════════════════════════════════════════════════════════════════

@app.route("/analyze/text", methods=["POST"])
def analyze_text():
    if text_model is None or tfidf is None:
        return jsonify({"error": "Text model not loaded"}), 503

    data = request.get_json()
    text = (data or {}).get("text", "").strip()
    if not text:
        return jsonify({"error": "No text provided"}), 400

    try:
        vec   = tfidf.transform([text])
        pred  = int(text_model.predict(vec)[0])
        proba = text_model.predict_proba(vec)[0]
        return jsonify({
            "prediction": "phishing" if pred == 1 else "safe",
            "confidence": round(float(max(proba)) * 100, 2),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ════════════════════════════════════════════════════════════════
#  SCREENSHOT / OCR
# ════════════════════════════════════════════════════════════════

@app.route("/predict/screenshot", methods=["POST"])
def predict_screenshot():
    if not OCR_AVAILABLE:
        return jsonify({"error": "OCR not available — install Pillow and pytesseract, then install Tesseract from https://github.com/UB-Mannheim/tesseract/wiki"}), 503
    if text_model is None or tfidf is None:
        return jsonify({"error": "Text model not loaded"}), 503

    if "image" not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    try:
        file           = request.files["image"]
        image          = Image.open(io.BytesIO(file.read()))
        extracted_text = pytesseract.image_to_string(image).strip()
    except Exception as e:
        return jsonify({"error": f"OCR error: {str(e)}"}), 500

    if not extracted_text:
        return jsonify({"error": "No text found in image"}), 422

    try:
        vec   = tfidf.transform([extracted_text])
        pred  = int(text_model.predict(vec)[0])
        proba = text_model.predict_proba(vec)[0]
        return jsonify({
            "prediction": "phishing" if pred == 1 else "safe",
            "confidence": round(float(max(proba)) * 100, 2),
            "ocr_text":   extracted_text[:500],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ════════════════════════════════════════════════════════════════
#  RUN
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n🛡️  PhishGuard starting on http://localhost:5000")
    app.run(debug=True, port=5000, use_reloader=False)