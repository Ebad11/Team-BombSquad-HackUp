"""
=============================================================================
  Phishing Detection API — Flask Backend
=============================================================================
  Accepts:
    • A single URL           → URL feature model (XGBoost + LR)
    • Full email content     → Splits into URL(s) + Body text + Attachments
                               Runs each through its specialist model
                               Combines scores via Risk Engine

  Models expected (set paths via env or defaults below):
    URL_MODEL_DIR    → folder with xgb_model.pkl, lr_model.pkl, scaler.pkl,
                       feature_cols.json
    TEXT_MODEL_DIR   → folder with tfidf_vectorizer.pkl, lr_model.pkl,
                       signal_cols.json, distilbert_model/

  Risk Tier:
    score >= 0.70  →  PHISHING  🔴
    score <  0.70  →  SAFE      🟢
=============================================================================
"""

import os, re, io, math, json, pickle, logging, warnings, hashlib
from collections import deque
from pathlib import Path
from typing import Optional

import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)

# ── Optional heavy imports (graceful degradation if GPU unavailable) ──────────
try:
    import torch
    from transformers import (
        DistilBertTokenizerFast,
        DistilBertForSequenceClassification,
    )
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    log.warning("PyTorch/Transformers not installed — DistilBERT disabled.")

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    log.warning("XGBoost not installed — URL XGB model disabled.")

try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.stem import WordNetLemmatizer
    from nltk.tokenize import word_tokenize
    for r in ["punkt", "punkt_tab", "stopwords", "wordnet", "omw-1.4",
              "averaged_perceptron_tagger", "averaged_perceptron_tagger_eng"]:
        nltk.download(r, quiet=True)
    NLTK_AVAILABLE = True
    _lemmatizer = WordNetLemmatizer()
    _stop_words = set(stopwords.words("english"))
except Exception:
    NLTK_AVAILABLE = False
    log.warning("NLTK not fully available — basic text cleaning only.")

try:
    import tldextract
    TLD_AVAILABLE = True
except ImportError:
    TLD_AVAILABLE = False

from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix

# =============================================================================
#  CONFIG — override via environment variables
# =============================================================================
URL_MODEL_DIR  = Path(os.getenv("URL_MODEL_DIR",  "models/url_model"))
TEXT_MODEL_DIR = Path(os.getenv("TEXT_MODEL_DIR", "models/text_model"))
BERT_MODEL_DIR = TEXT_MODEL_DIR / "distilbert_model"
MAX_UPLOAD_MB  = int(os.getenv("MAX_UPLOAD_MB", 10))
ALLOWED_ATTACH = {".txt", ".eml", ".msg", ".pdf", ".html", ".htm"}
DEVICE = "cuda" if (TORCH_AVAILABLE and torch.cuda.is_available()) else "cpu"

# =============================================================================
#  RISK THRESHOLD  — single cutoff: >= 0.70 → PHISHING, else → SAFE
# =============================================================================
PHISHING_THRESHOLD = 0.70

def risk_tier(score: float) -> dict:
    """
    Binary classification:
      score >= 0.70  →  PHISHING  (red)
      score <  0.70  →  SAFE      (green)
    """
    if score >= PHISHING_THRESHOLD:
        return {"label": "PHISHING", "color": "#FF2D2D", "score": round(score, 4)}
    return {"label": "SAFE", "color": "#00C853", "score": round(score, 4)}

# =============================================================================
#  MODEL REGISTRY  (lazy-loaded singletons)
# =============================================================================
_registry: dict = {}

def _load_pickle(path: Path):
    with open(path, "rb") as f:
        return pickle.load(f)

def get_url_models():
    if "url" not in _registry:
        try:
            xgb_model = _load_pickle(URL_MODEL_DIR / "xgb_model.pkl")
            lr_model  = _load_pickle(URL_MODEL_DIR / "lr_model.pkl")
            scaler    = _load_pickle(URL_MODEL_DIR / "scaler.pkl")
            with open(URL_MODEL_DIR / "feature_cols.json") as f:
                feature_cols = json.load(f)
            _registry["url"] = dict(xgb=xgb_model, lr=lr_model,
                                    scaler=scaler, cols=feature_cols)
            log.info("✅ URL models loaded.")
        except Exception as e:
            log.error(f"URL model load failed: {e}")
            _registry["url"] = None
    return _registry["url"]

def get_text_models():
    if "text" not in _registry:
        try:
            tfidf    = _load_pickle(TEXT_MODEL_DIR / "tfidf_vectorizer.pkl")
            lr_model = _load_pickle(TEXT_MODEL_DIR / "lr_model.pkl")
            with open(TEXT_MODEL_DIR / "signal_cols.json") as f:
                signal_cols = json.load(f)
            _registry["text"] = dict(tfidf=tfidf, lr=lr_model,
                                     signal_cols=signal_cols)
            log.info("✅ Text (TF-IDF+LR) models loaded.")
        except Exception as e:
            log.error(f"Text model load failed: {e}")
            _registry["text"] = None
    return _registry["text"]

def get_bert_model():
    if "bert" not in _registry:
        if not TORCH_AVAILABLE:
            _registry["bert"] = None
        else:
            try:
                tokenizer = DistilBertTokenizerFast.from_pretrained(str(BERT_MODEL_DIR))
                model     = DistilBertForSequenceClassification.from_pretrained(
                    str(BERT_MODEL_DIR)
                ).to(DEVICE)
                model.eval()
                _registry["bert"] = dict(tokenizer=tokenizer, model=model)
                log.info(f"✅ DistilBERT loaded on {DEVICE}.")
            except Exception as e:
                log.error(f"DistilBERT load failed: {e}")
                _registry["bert"] = None
    return _registry["bert"]

# =============================================================================
#  URL FEATURE EXTRACTION  (mirrors training notebook exactly)
# =============================================================================
IP_RE       = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
URL_RE_FIND = re.compile(r"https?://\S+|www\.\S+", re.I)

SUSPICIOUS_TLD = {"tk","ml","ga","cf","gq","xyz","top","pw","click","link"}
SUSPICIOUS_KW  = [
    "login","signin","verify","update","secure","bank","account","password",
    "confirm","webscr","ebayisapi","wp-admin","phish","free","lucky","bonus",
    "paypal","appleid","support","service","checkout",
]

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def extract_url_features(url: str) -> dict:
    url = str(url).strip()
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
    except Exception:
        parsed = urlparse("")

    if TLD_AVAILABLE:
        ext    = tldextract.extract(url)
        domain = ext.domain
        suffix = ext.suffix
        sub    = ext.subdomain
    else:
        domain = parsed.netloc.split(".")[0] if parsed.netloc else ""
        suffix = ".".join(parsed.netloc.split(".")[-2:]) if parsed.netloc else ""
        sub    = ""

    path  = parsed.path
    query = parsed.query
    full  = url

    subdomains = [s for s in sub.split(".") if s] if sub else []
    digits  = sum(c.isdigit() for c in full)
    letters = sum(c.isalpha() for c in full)

    kw_feats = {f"has_{kw}": int(kw in full.lower()) for kw in SUSPICIOUS_KW}

    return {
        "url_length":           len(full),
        "num_dots":             full.count("."),
        "num_hyphens":          full.count("-"),
        "num_underscores":      full.count("_"),
        "num_slashes":          full.count("/"),
        "num_at":               full.count("@"),
        "num_eq":               full.count("="),
        "num_question":         full.count("?"),
        "num_ampersand":        full.count("&"),
        "num_percent":          full.count("%"),
        "num_hash":             full.count("#"),
        "has_https":            int(parsed.scheme == "https"),
        "has_ip":               int(bool(IP_RE.search(full))),
        "domain_length":        len(domain),
        "path_length":          len(path),
        "query_length":         len(query),
        "path_segments":        len([p for p in path.split("/") if p]),
        "num_params":           len(query.split("&")) if query else 0,
        "num_subdomains":       len(subdomains),
        "subdomain_length":     len(sub),
        "digit_count":          digits,
        "letter_count":         letters,
        "digit_letter_ratio":   digits / (letters + 1e-6),
        "url_entropy":          _entropy(full),
        "domain_entropy":       _entropy(domain),
        "is_suspicious_tld":    int(suffix.split(".")[-1].lower() in SUSPICIOUS_TLD),
        "mock_domain_age_flag": int(len(domain) <= 4),
        **kw_feats,
    }

def predict_url(url: str) -> dict:
    """Run a single URL through XGBoost (+ LR fallback). Returns score dict."""
    models = get_url_models()
    if models is None:
        return {"error": "URL models not loaded", "phishing_prob": 0.5}

    feats = extract_url_features(url)
    vec   = np.array([feats.get(c, 0) for c in models["cols"]],
                     dtype=np.float32).reshape(1, -1)

    # XGBoost
    xgb_prob = float(models["xgb"].predict_proba(vec)[0][1]) if XGB_AVAILABLE else None

    # LR (scaled)
    vec_scaled = models["scaler"].transform(vec)
    lr_prob    = float(models["lr"].predict_proba(vec_scaled)[0][1])

    # Ensemble
    prob = (xgb_prob * 0.65 + lr_prob * 0.35) if xgb_prob is not None else lr_prob

    signals = []
    if feats["has_ip"]:             signals.append("IP address used instead of domain")
    if feats["is_suspicious_tld"]:  signals.append("Suspicious TLD detected")
    if feats["num_at"] > 0:         signals.append("@ symbol in URL (credential bypass)")
    if feats["num_subdomains"] > 2: signals.append("Excessive subdomains")
    if not feats["has_https"]:      signals.append("No HTTPS")
    for kw in SUSPICIOUS_KW:
        if feats.get(f"has_{kw}"):
            signals.append(f"Suspicious keyword: '{kw}'")
            break

    return {
        "url":           url,
        "xgb_prob":      round(xgb_prob, 4) if xgb_prob is not None else None,
        "lr_prob":       round(lr_prob, 4),
        "phishing_prob": round(prob, 4),
        # Binary label using shared threshold
        "prediction":    "phishing" if prob >= PHISHING_THRESHOLD else "legitimate",
        "signals":       signals,
    }

# =============================================================================
#  TEXT FEATURE EXTRACTION  (mirrors training notebook)
# =============================================================================
HTML_RE    = re.compile(r"<[^>]+>")
URL_RE_SUB = re.compile(r"https?://\S+|www\.\S+", re.I)
SPEC_RE    = re.compile(r"[^a-z\s]")

URGENCY_KW    = ["urgent","immediately","act now","action required","asap",
                 "limited time","expires","deadline","final notice","last chance",
                 "hurry","today only","within 24","do not ignore"]
FINANCIAL_KW  = ["bank","account","verify","credit card","debit","billing",
                 "payment","paypal","transfer","ssn","social security","tax",
                 "refund","invoice","wire","irs","subscription"]
SUSPICIOUS_PH = ["click here","login now","confirm your","update your","verify your",
                 "won a prize","free gift","you have been selected","claim now",
                 "suspended","unusual activity","locked out","password expired",
                 "security alert","reset your password"]

def _clean_text(text: str) -> str:
    text = HTML_RE.sub(" ", text)
    text = URL_RE_SUB.sub(" urltoken ", text)
    text = text.lower()
    text = SPEC_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()

def _nlp_process(text: str) -> str:
    if not NLTK_AVAILABLE:
        return text
    tokens = word_tokenize(text)
    tokens = [_lemmatizer.lemmatize(t) for t in tokens
              if t not in _stop_words and len(t) > 1]
    return " ".join(tokens)

def full_preprocess(text: str) -> str:
    return _nlp_process(_clean_text(text))

def extract_text_signals(text: str) -> dict:
    t     = text.lower()
    alpha = [c for c in text if c.isalpha()]
    caps  = sum(1 for c in alpha if c.isupper()) / max(len(alpha), 1)
    return {
        "has_urgency":       int(any(w in t for w in URGENCY_KW)),
        "has_financial":     int(any(w in t for w in FINANCIAL_KW)),
        "has_suspicious":    int(any(p in t for p in SUSPICIOUS_PH)),
        "has_url":           int(bool(URL_RE_SUB.search(text))),
        "exclamation_count": text.count("!"),
        "caps_ratio":        round(caps, 4),
        "text_length":       len(text),
        "word_count":        len(text.split()),
    }

def predict_text_lr(text: str) -> dict:
    """TF-IDF + LR prediction on body text."""
    models = get_text_models()
    if models is None:
        return {"error": "Text models not loaded", "phishing_prob": 0.5}

    proc     = full_preprocess(text)
    tfidf_v  = models["tfidf"].transform([proc])
    sigs     = extract_text_signals(text)
    sig_v    = csr_matrix(np.array([[sigs[c] for c in models["signal_cols"]]],
                                    dtype=np.float32))
    combined = hstack([tfidf_v, sig_v])
    prob     = float(models["lr"].predict_proba(combined)[0][1])

    signals = []
    if sigs["has_urgency"]:           signals.append("Urgency language detected")
    if sigs["has_financial"]:         signals.append("Financial keywords present")
    if sigs["has_suspicious"]:        signals.append("Suspicious phrases found")
    if sigs["has_url"]:               signals.append("URL(s) embedded in text body")
    if sigs["caps_ratio"] > 0.3:      signals.append(f"High CAPS ratio ({sigs['caps_ratio']:.0%})")
    if sigs["exclamation_count"] > 1: signals.append(f"{sigs['exclamation_count']} exclamation marks")

    return {
        "phishing_prob":   round(prob, 4),
        # Binary label using shared threshold
        "prediction":      "phishing" if prob >= PHISHING_THRESHOLD else "legitimate",
        "signals":         signals,
        "signal_features": sigs,
    }

def predict_text_bert(text: str) -> dict:
    """DistilBERT prediction on body text."""
    bert = get_bert_model()
    if bert is None:
        return {"phishing_prob": None, "prediction": "unavailable", "signals": []}

    enc = bert["tokenizer"](
        text, truncation=True, padding="max_length",
        max_length=128, return_tensors="pt"
    )
    with torch.no_grad():
        out  = bert["model"](
            input_ids      = enc["input_ids"].to(DEVICE),
            attention_mask = enc["attention_mask"].to(DEVICE),
        )
        prob = float(torch.softmax(out.logits, dim=1)[0][1].cpu())

    return {
        "phishing_prob": round(prob, 4),
        # Binary label using shared threshold
        "prediction":    "phishing" if prob >= PHISHING_THRESHOLD else "legitimate",
        "signals":       [],
    }

# =============================================================================
#  EMAIL PARSER  — extract URLs, body text, attachment text
# =============================================================================
def extract_urls_from_text(text: str) -> list[str]:
    return list(set(URL_RE_FIND.findall(text)))

def read_attachment_text(file_bytes: bytes, filename: str) -> str:
    """Extract readable text from common attachment types."""
    ext = Path(filename).suffix.lower()
    try:
        if ext in (".txt", ".eml", ".msg", ".html", ".htm"):
            return file_bytes.decode("utf-8", errors="ignore")
        if ext == ".pdf":
            try:
                import pypdf
                reader = pypdf.PdfReader(io.BytesIO(file_bytes))
                return " ".join(p.extract_text() or "" for p in reader.pages)
            except Exception:
                return ""
    except Exception:
        pass
    return ""

def parse_email(subject: str, body: str, attachments: list[dict]) -> dict:
    """
    Decompose an email into:
      - all_text    : subject + body (for text model)
      - urls        : every URL found across subject, body, attachments
      - attach_texts: readable text extracted from attachments
    """
    combined_text = f"{subject}\n{body}"
    urls          = extract_urls_from_text(combined_text)

    attach_texts = []
    for att in attachments:
        att_text = read_attachment_text(att["bytes"], att["name"])
        if att_text.strip():
            attach_texts.append({"name": att["name"], "text": att_text})
            urls += extract_urls_from_text(att_text)

    return {
        "body_text":    body,
        "subject":      subject,
        "all_text":     combined_text,
        "urls":         list(set(urls)),
        "attach_texts": attach_texts,
    }

# =============================================================================
#  RISK ENGINE
# =============================================================================
W_URL        = 0.40
W_TEXT_LR    = 0.30
W_TEXT_BERT  = 0.25
W_ATTACHMENT = 0.05

def run_risk_engine(
    url_results:    list[dict],
    lr_result:      Optional[dict],
    bert_result:    Optional[dict],
    attach_results: list[dict],
) -> dict:
    components = {}

    # URL component — worst URL wins
    url_probs = [r["phishing_prob"] for r in url_results if "phishing_prob" in r]
    url_score = max(url_probs) if url_probs else 0.0
    components["url"] = round(url_score, 4)

    # Text LR component
    lr_score = lr_result["phishing_prob"] if (lr_result and "phishing_prob" in lr_result) else 0.0
    components["text_lr"] = round(lr_score, 4)

    # Text BERT component
    bert_available = bert_result and bert_result.get("phishing_prob") is not None
    bert_score     = bert_result["phishing_prob"] if bert_available else None
    components["text_bert"] = round(bert_score, 4) if bert_score is not None else None

    # Attachment component
    att_scores = [r["phishing_prob"] for r in attach_results if "phishing_prob" in r]
    att_score  = max(att_scores) if att_scores else 0.0
    components["attachment"] = round(att_score, 4)

    # Weighted sum
    if bert_available:
        final = (
            W_URL        * url_score  +
            W_TEXT_LR    * lr_score   +
            W_TEXT_BERT  * bert_score +
            W_ATTACHMENT * att_score
        )
    else:
        # Redistribute BERT weight evenly to URL and LR
        w_url_adj = W_URL      + W_TEXT_BERT * 0.5
        w_lr_adj  = W_TEXT_LR  + W_TEXT_BERT * 0.5
        final = (
            w_url_adj    * url_score +
            w_lr_adj     * lr_score  +
            W_ATTACHMENT * att_score
        )

    # Boost when multiple sources agree strongly
    high_signals = sum([
        url_score        > 0.7,
        lr_score         > 0.7,
        (bert_score or 0) > 0.7,
        att_score        > 0.7,
    ])
    if high_signals >= 2:
        final = min(final * 1.15, 1.0)

    tier = risk_tier(final)

    # Collect all signals
    all_signals = []
    for r in url_results:
        all_signals += [f"[URL] {s}" for s in r.get("signals", [])]
    if lr_result:
        all_signals += [f"[TEXT] {s}" for s in lr_result.get("signals", [])]

    return {
        "risk_score":     round(final, 4),
        "risk_tier":      tier["label"],
        "risk_color":     tier["color"],
        "components":     components,
        "all_signals":    list(dict.fromkeys(all_signals)),  # preserve order + dedup
        "bert_available": bert_available,
    }

# =============================================================================
#  CAMPAIGN DETECTION  — rolling in-memory fingerprint store
# =============================================================================
_CAMPAIGN_HASHES: deque = deque(maxlen=500)

def _hash_email(text: str) -> str:
    """SHA-256 of the first 500 characters of email text."""
    return hashlib.sha256(text[:500].encode("utf-8", errors="ignore")).hexdigest()

def detect_campaign(text: str) -> bool:
    """Returns True if this fingerprint was seen before; always records it."""
    h    = _hash_email(text)
    seen = h in _CAMPAIGN_HASHES
    _CAMPAIGN_HASHES.append(h)
    return seen

# =============================================================================
#  RESPONSE HELPERS
# =============================================================================

def classify_attack_type(
    url_score: float,
    text_score: float,
    attachment_score: float,
) -> str:
    """
    Classifies dominant attack vector (most severe first):
      multi-stage          → URL  high AND text high
      malicious-link       → URL  high
      phishing-content     → text high
      malicious-attachment → attachment high
      safe                 → nothing crosses threshold
    """
    if url_score > 0.7 and text_score > 0.7:
        return "multi-stage"
    if url_score > 0.7:
        return "malicious-link"
    if text_score > 0.7:
        return "phishing-content"
    if attachment_score > 0.7:
        return "malicious-attachment"
    return "safe"


def generate_attack_story(
    url_score: float,
    text_score: float,
    bert_score: Optional[float],
    attack_type: str,
    signals: list[str],
) -> str:
    """Human-readable paragraph explaining what the analysis found."""
    leads = {
        "multi-stage": (
            "This email shows hallmarks of a coordinated multi-stage phishing "
            "attack: both the embedded links and the message body carry strong "
            "deceptive signals."
        ),
        "malicious-link": (
            "The primary threat originates from one or more embedded URLs "
            "that exhibit high phishing confidence."
        ),
        "phishing-content": (
            "The body text contains language patterns strongly associated "
            "with social-engineering and phishing campaigns."
        ),
        "malicious-attachment": (
            "A suspicious attachment was detected that may carry malicious "
            "content or links designed to compromise the recipient."
        ),
        "safe": (
            "No significant phishing indicators were detected in this email."
        ),
    }

    parts = [leads.get(attack_type, leads["safe"])]

    if url_score > 0.0:
        level = "high-risk" if url_score >= PHISHING_THRESHOLD else "low-risk"
        parts.append(
            f"URL analysis returned a phishing probability of "
            f"{url_score:.0%} ({level})."
        )

    if text_score > 0.0:
        bert_note = (
            f", corroborated by the neural model at {bert_score:.0%}"
            if bert_score is not None else ""
        )
        parts.append(
            f"The text classifier scored the body at "
            f"{text_score:.0%}{bert_note}."
        )

    clean_sigs = [s.split("] ", 1)[-1] for s in signals if s.strip()]
    if clean_sigs:
        parts.append("Key indicators: " + "; ".join(clean_sigs[:3]) + ".")

    return " ".join(parts)


def generate_impact(signals: list[str]) -> str:
    """Maps signal keywords to a business-impact statement."""
    combined = " ".join(signals).lower()

    financial_triggers  = ["financial","bank","credit card","billing","payment",
                           "paypal","transfer","ssn","tax","refund","invoice"]
    credential_triggers = ["login","password","credential","signin","verify your",
                           "reset your password","account","confirm your"]

    if any(t in combined for t in financial_triggers):
        return "Financial fraud risk detected"
    if any(t in combined for t in credential_triggers):
        return "Credential theft attempt likely"
    return "Potential phishing attempt"


def select_top_signals(all_signals: list[str], n: int = 3) -> list[str]:
    """
    Returns top-n signals ordered by priority [URL] > [TEXT] > other.
    Strips the category prefix before returning.
    """
    url_sigs  = [s for s in all_signals if s.startswith("[URL]")]
    text_sigs = [s for s in all_signals if s.startswith("[TEXT]")]
    other     = [s for s in all_signals if not s.startswith(("[URL]", "[TEXT]"))]

    ordered = (url_sigs + text_sigs + other)[:n]
    return [s.split("] ", 1)[-1] if "] " in s else s for s in ordered]


def build_final_response(
    risk:           dict,
    url_results:    list[dict],
    lr_result:      Optional[dict],
    bert_result:    Optional[dict],
    attach_results: list[dict],
    parsed:         dict,
    subject:        str,
) -> dict:
    """
    Assembles the standardised, frontend-ready JSON response for the
    Gmail add-on.  All raw technical data is preserved under
    'technical_details' for debugging / advanced views.
    """
    components       = risk.get("components", {})
    url_score        = components.get("url",        0.0)
    text_lr_score    = components.get("text_lr",    0.0)
    bert_score_raw   = components.get("text_bert")          # may be None
    attachment_score = components.get("attachment", 0.0)

    # Use the higher of LR / BERT as representative text score
    text_score = max(
        text_lr_score,
        bert_score_raw if bert_score_raw is not None else 0.0,
    )

    all_signals  = risk.get("all_signals", [])
    attack_type  = classify_attack_type(url_score, text_score, attachment_score)
    attack_story = generate_attack_story(
        url_score, text_lr_score, bert_score_raw, attack_type, all_signals
    )
    impact      = generate_impact(all_signals)
    top_signals = select_top_signals(all_signals, n=3)

    # Campaign detection — fingerprint on subject + first 500 chars of body
    fingerprint_text  = subject + "\n" + parsed.get("body_text", "")
    campaign_detected = detect_campaign(fingerprint_text)

    return {
        # ── Top-level verdict ──────────────────────────────────────────────────
        "risk_score": risk["risk_score"],
        "risk_tier":  risk["risk_tier"],          # "PHISHING" | "SAFE"

        # ── Attack classification ──────────────────────────────────────────────
        "attack_type":  attack_type,
        "attack_story": attack_story,

        # ── Per-component breakdown ────────────────────────────────────────────
        "risk_breakdown": {
            "url":        url_score,
            "text":       round(text_score, 4),
            "attachment": attachment_score,
        },

        # ── Human-readable signals (top 3) ────────────────────────────────────
        "top_signals": top_signals,

        # ── Impact assessment ─────────────────────────────────────────────────
        "impact": impact,

        # ── Campaign / repeat-sender detection ────────────────────────────────
        "campaign_detected": campaign_detected,

        # ── Raw technical details (for debugging / advanced frontend views) ────
        "technical_details": {
            "urls_found":         parsed.get("urls", []),
            "url_results":        url_results,
            "text_lr":            lr_result,
            "text_bert":          bert_result,
            "attachment_results": attach_results,
        },
    }

# =============================================================================
#  FLASK APP
# =============================================================================
app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":      "ok",
        "url_models":  get_url_models()  is not None,
        "text_models": get_text_models() is not None,
        "bert_model":  get_bert_model()  is not None,
        "device":      DEVICE,
        "threshold":   PHISHING_THRESHOLD,
    })


@app.route("/predict/url", methods=["POST"])
def predict_url_endpoint():
    """
    Input  (JSON): { "url": "https://..." }
    Output (JSON): URL phishing analysis + binary risk tier
    """
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = predict_url(url)
    tier   = risk_tier(result["phishing_prob"])
    result["risk_tier"]  = tier["label"]
    result["risk_color"] = tier["color"]
    return jsonify(result)


@app.route("/predict/email", methods=["POST"])
def predict_email_endpoint():
    """
    Input  (multipart/form-data):
      - subject        : str  (optional)
      - body           : str
      - attachments[]  : files (optional, multiple)

    Output (JSON): standardised frontend-ready phishing analysis.
      risk_tier is always "PHISHING" or "SAFE" (threshold = 0.70).
    """
    subject = request.form.get("subject", "").strip()
    body    = request.form.get("body",    "").strip()

    if not body and not subject:
        return jsonify({"error": "No email content provided"}), 400

    # ── Parse attachments ──────────────────────────────────────────────────────
    attachments = []
    for f in request.files.getlist("attachments[]"):
        fname = secure_filename(f.filename or "attachment")
        if Path(fname).suffix.lower() in ALLOWED_ATTACH:
            attachments.append({"name": fname, "bytes": f.read()})

    # ── Decompose email ───────────────────────────────────────────────────────
    parsed = parse_email(subject, body, attachments)

    # ── Run URL model on every extracted URL (cap at 20) ──────────────────────
    url_results = [predict_url(u) for u in parsed["urls"][:20]]

    # ── Run text models on combined subject + body ─────────────────────────────
    combined_text = parsed["all_text"]
    lr_result   = predict_text_lr(combined_text)   if combined_text.strip() else None
    bert_result = predict_text_bert(combined_text) if combined_text.strip() else None

    # ── Run text model on each attachment ──────────────────────────────────────
    attach_results = []
    for att in parsed["attach_texts"]:
        att_lr = predict_text_lr(att["text"])
        attach_results.append({
            "filename":      att["name"],
            "phishing_prob": att_lr["phishing_prob"],
            "prediction":    att_lr["prediction"],
            "signals":       att_lr["signals"],
        })

    # ── Risk Engine ───────────────────────────────────────────────────────────
    risk = run_risk_engine(url_results, lr_result, bert_result, attach_results)

    # ── Build standardised response ───────────────────────────────────────────
    return jsonify(build_final_response(
        risk           = risk,
        url_results    = url_results,
        lr_result      = lr_result,
        bert_result    = bert_result,
        attach_results = attach_results,
        parsed         = parsed,
        subject        = subject,
    ))


if __name__ == "__main__":
    log.info("Pre-loading models...")
    get_url_models()
    get_text_models()
    get_bert_model()
    log.info("Starting Flask server on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)