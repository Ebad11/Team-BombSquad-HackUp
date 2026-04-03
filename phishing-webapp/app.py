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
import urllib.request

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
#  GEMINI CONFIG
# ════════════════════════════════════════════════════════════════

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyBqAS17MfHWaSNC1uSvNlE89YSlLk_7EHA")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

def call_gemini(prompt: str) -> str:
    """Call Gemini API and return text response."""
    try:
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 1024,
            }
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())
            return result["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        print(f"❌ Gemini API error: {e}")
        return None


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


def extract_url_features(url: str) -> list:
    digits = sum(c.isdigit() for c in url)
    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("/"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        1 if url.lower().startswith("https") else 0,
        round(digits / max(len(url), 1), 4),
    ]


def get_url_red_flags(url: str) -> list:
    """Extract human-readable red flags from a URL."""
    flags = []
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        flags.append("Uses raw IP address instead of domain name")
    if not url.lower().startswith("https"):
        flags.append("Not using HTTPS (insecure connection)")
    if url.count("-") > 3:
        flags.append(f"Excessive hyphens ({url.count('-')}) in URL — common phishing tactic")
    if len(url) > 75:
        flags.append(f"Unusually long URL ({len(url)} characters)")
    if url.count(".") > 4:
        flags.append(f"Too many subdomains ({url.count('.')} dots)")
    if "@" in url:
        flags.append("Contains @ symbol — hides the real destination")
    suspicious_words = ["login", "verify", "secure", "update", "confirm", "account", "bank", "paypal", "amazon"]
    found = [w for w in suspicious_words if w in url.lower()]
    if found:
        flags.append(f"Contains urgency/trust keywords: {', '.join(found)}")
    digit_ratio = sum(c.isdigit() for c in url) / max(len(url), 1)
    if digit_ratio > 0.2:
        flags.append(f"High digit ratio ({round(digit_ratio*100)}%) — typical of auto-generated phishing domains")
    return flags


def decode_body(payload):
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

        try:
            vec        = tfidf.transform([text_to_analyze])
            pred_text  = int(text_model.predict(vec)[0])
            proba_text = text_model.predict_proba(vec)[0]
            text_conf  = round(float(max(proba_text)) * 100, 2)
        except Exception:
            pred_text = 0; text_conf = 0.0

        urls_found = re.findall(r'https?://[^\s<>"\']+', snippet + " " + body)
        urls_found = list(set(urls_found))[:5]

        in_spam     = (folder == "SPAM")
        is_phishing = (pred_text == 1) or in_spam
        if is_phishing:
            phishing_count += 1

        emails.append({
            "id":             msg_meta["id"],
            "subject":        subject,
            "sender":         sender,
            "date":           date,
            "snippet":        snippet[:200],
            "body_preview":   text_to_analyze[:500],
            "folder":         folder,
            "is_phishing":    is_phishing,
            "urls_found":     urls_found,
            "text_result":    {"confidence": text_conf},
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
#  EXPLAIN — EMAIL (Gemini powered)
# ════════════════════════════════════════════════════════════════

@app.route("/explain/email", methods=["POST"])
def explain_email():
    data    = request.get_json()
    subject = (data or {}).get("subject", "")
    sender  = (data or {}).get("sender", "")
    snippet = (data or {}).get("snippet", "")
    body    = (data or {}).get("body_preview", "")
    urls    = (data or {}).get("urls_found", [])
    conf    = (data or {}).get("confidence", 0)
    folder  = (data or {}).get("folder", "INBOX")

    prompt = f"""You are a cybersecurity expert and educator helping regular users understand phishing threats.

Analyze this email and provide a clear, educational explanation for a non-technical person.

EMAIL DETAILS:
- Subject: {subject}
- Sender: {sender}
- Folder: {folder}
- AI Confidence it's phishing: {conf}%
- URLs found: {', '.join(urls) if urls else 'None'}
- Content preview: {(body or snippet)[:400]}

Respond ONLY with a valid JSON object in this exact format (no markdown, no extra text):
{{
  "verdict_summary": "One punchy sentence explaining why this is phishing",
  "red_flags": [
    "Specific red flag 1 found in this email",
    "Specific red flag 2 found in this email",
    "Specific red flag 3 found in this email"
  ],
  "what_attacker_wants": "What the attacker is trying to steal or achieve",
  "what_to_do": "Specific action the user should take right now",
  "how_to_spot_next_time": "One key lesson to remember for future emails",
  "danger_level": "HIGH" or "MEDIUM" or "LOW",
  "danger_reason": "Brief reason for the danger level"
}}"""

    ai_text = call_gemini(prompt)

    if not ai_text:
        # Fallback rule-based explanation
        flags = []
        if "urgent" in (subject + snippet).lower() or "immediately" in (subject + snippet).lower():
            flags.append("Uses urgency language to pressure you into acting fast")
        if urls:
            flags.append(f"Contains {len(urls)} suspicious link(s)")
        if folder == "SPAM":
            flags.append("Gmail's own filters marked this as spam")
        if conf > 80:
            flags.append(f"AI model is {conf}% confident this is phishing")

        return jsonify({
            "verdict_summary": "This email shows multiple signs of a phishing attempt.",
            "red_flags": flags or ["Suspicious content pattern detected by AI", "Unusual sender behavior", "Content matches known phishing templates"],
            "what_attacker_wants": "Likely trying to steal your login credentials or personal information.",
            "what_to_do": "Do not click any links. Mark as spam and delete immediately.",
            "how_to_spot_next_time": "Legitimate companies never ask for sensitive info via email urgently.",
            "danger_level": "HIGH" if conf > 80 else "MEDIUM",
            "danger_reason": "High AI confidence score with suspicious content patterns."
        })

    try:
        # Strip any markdown fencing if present
        clean = ai_text.strip()
        if clean.startswith("```"):
            clean = re.sub(r"```[a-z]*\n?", "", clean).strip().rstrip("`").strip()
        result = json.loads(clean)
        return jsonify(result)
    except Exception as e:
        print(f"❌ Gemini JSON parse error: {e}\nRaw: {ai_text}")
        return jsonify({
            "verdict_summary": "This email shows signs of a phishing attempt.",
            "red_flags": ["Suspicious sender pattern", "Content matches phishing templates", "Unusual link structure"],
            "what_attacker_wants": "Trying to steal credentials or personal data.",
            "what_to_do": "Do not click any links. Delete this email immediately.",
            "how_to_spot_next_time": "Always verify sender identity through official channels.",
            "danger_level": "HIGH",
            "danger_reason": "Multiple phishing indicators detected."
        })


# ════════════════════════════════════════════════════════════════
#  EXPLAIN — URL (Gemini powered)
# ════════════════════════════════════════════════════════════════

@app.route("/explain/url", methods=["POST"])
def explain_url():
    data       = request.get_json()
    url        = (data or {}).get("url", "")
    prediction = (data or {}).get("prediction", "phishing")
    confidence = (data or {}).get("confidence", 0)

    features   = extract_url_features(url)
    red_flags  = get_url_red_flags(url)

    feature_desc = f"""URL Analysis Features:
- Length: {features[0]} chars
- Dots: {features[1]}
- Hyphens: {features[2]}
- Slashes: {features[3]}
- @ symbols: {features[4]}
- Has IP address: {'Yes' if features[7] else 'No'}
- Uses HTTPS: {'Yes' if features[8] else 'No'}
- Digit ratio: {features[9]}"""

    prompt = f"""You are a cybersecurity educator explaining phishing URLs to everyday users.

URL: {url}
AI Verdict: {prediction.upper()} ({confidence}% confidence)
{feature_desc}
Pre-detected red flags: {', '.join(red_flags) if red_flags else 'None obvious'}

Respond ONLY with a valid JSON object (no markdown):
{{
  "verdict_summary": "Plain English explanation of why this URL is {'dangerous' if prediction == 'phishing' else 'safe'}",
  "red_flags": ["Specific red flag 1", "Specific red flag 2", "Specific red flag 3"],
  "what_happens_if_clicked": "Exactly what could happen if someone visits this URL",
  "how_to_verify": "How a user can verify if a URL is safe before clicking",
  "safe_alternative": "What the legitimate version of this URL might look like (if phishing)",
  "danger_level": "HIGH" or "MEDIUM" or "LOW",
  "tip_for_future": "One memorable tip to identify similar URLs"
}}"""

    ai_text = call_gemini(prompt)

    if not ai_text:
        return jsonify({
            "verdict_summary": f"This URL appears {'dangerous' if prediction == 'phishing' else 'safe'} with {confidence}% confidence.",
            "red_flags": red_flags or ["No obvious red flags detected"],
            "what_happens_if_clicked": "Could lead to credential theft or malware installation.",
            "how_to_verify": "Hover over the link to preview the URL. Use Google Safe Browsing to check.",
            "safe_alternative": "Always type URLs directly into your browser instead of clicking links.",
            "danger_level": "HIGH" if confidence > 80 else "MEDIUM",
            "tip_for_future": "Real banks and services never use IP addresses or excessive hyphens in URLs."
        })

    try:
        clean = ai_text.strip()
        if clean.startswith("```"):
            clean = re.sub(r"```[a-z]*\n?", "", clean).strip().rstrip("`").strip()
        return jsonify(json.loads(clean))
    except Exception as e:
        print(f"❌ Gemini JSON parse error: {e}")
        return jsonify({
            "verdict_summary": f"URL classified as {prediction} with {confidence}% confidence.",
            "red_flags": red_flags or ["Suspicious URL pattern"],
            "what_happens_if_clicked": "May lead to credential theft.",
            "how_to_verify": "Check with Google Safe Browsing.",
            "safe_alternative": "Navigate directly to official websites.",
            "danger_level": "HIGH" if confidence > 80 else "MEDIUM",
            "tip_for_future": "Look for HTTPS and recognize the official domain."
        })


# ════════════════════════════════════════════════════════════════
#  EXPLAIN — TEXT / OCR (Gemini powered)
# ════════════════════════════════════════════════════════════════

@app.route("/explain/text", methods=["POST"])
def explain_text():
    data       = request.get_json()
    text       = (data or {}).get("text", "")
    prediction = (data or {}).get("prediction", "phishing")
    confidence = (data or {}).get("confidence", 0)
    source     = (data or {}).get("source", "email/sms")  # 'email/sms' or 'screenshot'

    prompt = f"""You are a cybersecurity educator. A user submitted a {source} for phishing analysis.

Content: {text[:500]}
AI Verdict: {prediction.upper()} ({confidence}% confidence)

Respond ONLY with a valid JSON object (no markdown):
{{
  "verdict_summary": "Plain English summary of the verdict",
  "red_flags": ["Specific red flag 1 from the actual content", "Specific red flag 2", "Specific red flag 3"],
  "psychological_tricks": ["Trick 1 the attacker uses (e.g., urgency, fear, greed)", "Trick 2"],
  "what_attacker_wants": "Specific goal of this phishing attempt",
  "what_to_do": "Exactly what the user should do right now",
  "how_to_verify_legitimacy": "How to check if this message is actually from a real organization",
  "danger_level": "HIGH" or "MEDIUM" or "LOW",
  "educational_insight": "One important cybersecurity lesson from this example"
}}"""

    ai_text = call_gemini(prompt)

    if not ai_text:
        return jsonify({
            "verdict_summary": f"This {source} appears {'dangerous' if prediction == 'phishing' else 'safe'}.",
            "red_flags": ["Suspicious language pattern", "Pressure tactics detected", "Unusual request"],
            "psychological_tricks": ["Creates urgency to prevent careful thinking", "Impersonates trusted authority"],
            "what_attacker_wants": "Steal personal information or account credentials.",
            "what_to_do": "Do not respond or click any links. Report and delete.",
            "how_to_verify_legitimacy": "Contact the organization directly through their official website.",
            "danger_level": "HIGH" if confidence > 80 else "MEDIUM",
            "educational_insight": "Legitimate organizations never request sensitive data via unsolicited messages."
        })

    try:
        clean = ai_text.strip()
        if clean.startswith("```"):
            clean = re.sub(r"```[a-z]*\n?", "", clean).strip().rstrip("`").strip()
        return jsonify(json.loads(clean))
    except Exception as e:
        print(f"❌ Gemini JSON parse error: {e}")
        return jsonify({
            "verdict_summary": f"Content classified as {prediction}.",
            "red_flags": ["Suspicious content detected"],
            "psychological_tricks": ["Urgency manipulation"],
            "what_attacker_wants": "Personal information theft.",
            "what_to_do": "Delete and report.",
            "how_to_verify_legitimacy": "Contact organization via official channels.",
            "danger_level": "HIGH",
            "educational_insight": "Always verify unexpected urgent requests."
        })


# ════════════════════════════════════════════════════════════════
#  MANUAL — URL
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
        red_flags = get_url_red_flags(url)
        return jsonify({
            "url":        url,
            "prediction": "phishing" if pred == 1 else "safe",
            "confidence": round(float(max(proba)) * 100, 2),
            "red_flags":  red_flags,
            "features": {
                "length":      features[0],
                "dots":        features[1],
                "hyphens":     features[2],
                "has_ip":      bool(features[7]),
                "uses_https":  bool(features[8]),
                "digit_ratio": features[9],
            }
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
        return jsonify({"error": "OCR not available — install Pillow and pytesseract"}), 503
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