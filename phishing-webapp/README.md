# 🛡️ PhishGuard – AI Phishing Detection System
### Features Added (Group Extension)
- ✅ **Gmail OAuth Login** → auto-scan inbox → phishing statistics dashboard
- ✅ **Manual paste** of URL or email/SMS text
- ✅ **Screenshot OCR** → upload email image → extract text → analyze

---

## 📁 Project Structure

```
phishing_app/
├── app.py                  ← Flask server (all routes)
├── requirements.txt        ← Python dependencies
├── client_secret.json      ← ⚠️ YOU CREATE THIS (Google Cloud)
├── models/
│   ├── url_model.pkl       ← copy from your Colab output
│   ├── url_scaler.pkl
│   ├── text_model.pkl
│   └── tfidf.pkl
└── static/
    └── index.html          ← full frontend UI
```

---

## ⚙️ Setup — Step by Step

### STEP 1 — Copy your trained model files
After training in Colab, download these 4 files from Google Drive:
```
url_model.pkl
url_scaler.pkl
text_model.pkl
tfidf.pkl
```
Place them in the `models/` folder.

---

### STEP 2 — Install Python dependencies
```bash
pip install -r requirements.txt
```

#### Also install Tesseract OCR (for screenshot feature):
- **Windows**: Download from https://github.com/UB-Mannheim/tesseract/wiki
  Then add to PATH or set in code: `pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'`
- **Mac**: `brew install tesseract`
- **Linux/Ubuntu**: `sudo apt install tesseract-ocr`

---

### STEP 3 — Set up Google OAuth (for Gmail scanning)

1. Go to https://console.cloud.google.com
2. Create a new project (e.g. "PhishGuard")
3. Go to **APIs & Services → Enable APIs**
   - Enable: **Gmail API**
   - Enable: **Google People API** (for user info)
4. Go to **APIs & Services → OAuth consent screen**
   - User Type: External
   - App name: PhishGuard
   - Add scopes: `gmail.readonly`, `userinfo.email`, `userinfo.profile`
   - Add your email as a test user
5. Go to **APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client ID**
   - Application type: **Web application**
   - Authorized redirect URIs: `http://localhost:5000/oauth2callback`
6. Click **Download JSON** → rename to `client_secret.json`
7. Place `client_secret.json` in the project root folder

---

### STEP 4 — Run the app
```bash
python app.py
```
Open browser: http://localhost:5000

---

## 🔑 How Each Feature Works

### Gmail Scan
1. User clicks "Login with Google"
2. Google OAuth redirects back to `/oauth2callback`
3. Credentials stored in session
4. `/gmail/scan` fetches latest N emails via Gmail API
5. Each email body + URLs are run through both ML models
6. Dashboard shows total scanned, phishing count, rate, email list

### Manual URL / Text Analysis
- POST to `/predict/url` with `{"url": "..."}`
- POST to `/predict/text` with `{"text": "..."}`
- Returns `{prediction, confidence, features}`

### Screenshot OCR
1. User uploads image (PNG/JPG) of email screenshot
2. POST to `/predict/screenshot` with multipart form
3. Tesseract OCR extracts text from image
4. Extracted text sent through text phishing model
5. Returns prediction + shows extracted text for transparency

---

## 🛡️ Privacy Note
- Emails are **never stored** to disk
- Analysis happens entirely on your local server
- OAuth tokens are session-only (cleared on logout)
- We request `gmail.readonly` scope only

---

## 🚀 Demo for Presentation

**Scenario 1 — Gmail Scan:**
Login → Scan 30 emails → Show stats (e.g. "3/30 flagged as phishing")

**Scenario 2 — Paste test:**
Paste: `WINNER! You've been selected for a £1000 prize. Call 08712300150 NOW!`
→ Shows PHISHING DETECTED, 97% confidence

**Scenario 3 — OCR Screenshot:**
Take a screenshot of a spam email → Upload → Shows extracted text + phishing verdict

---

## ⚠️ Troubleshooting

| Problem | Fix |
|---|---|
| `FileNotFoundError: url_model.pkl` | Copy .pkl files to `/models/` folder |
| `client_secret.json not found` | Download from Google Cloud Console |
| OCR returns empty text | Install Tesseract, check PATH |
| `redirect_uri_mismatch` | Add `http://localhost:5000/oauth2callback` in Google Cloud Console |
| Gmail scan fails after login | Check you added your email as test user in OAuth consent screen |
