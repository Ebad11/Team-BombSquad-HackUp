"""
PhishGuard v3 — Production-Ready Hybrid Detection Pipeline
==========================================================
8-Stage Architecture:
  Stage 1: URL ML Model (35-feature stacked ensemble)
  Stage 2: Text ML Model (TF-IDF stacked ensemble + transactional fix)
  Stage 3: Rule-Based Engine (deterministic risk scoring)
  Stage 4: Reputation Layer (whitelist / blacklist)
  Stage 5: Anomaly Detection (Isolation Forest on safe URLs)
  Stage 6: Ensemble Decision Engine (weighted combination)
  Stage 7: Confidence & Uncertainty Estimation
  Stage 8: Final Classification with Explainability
"""

from flask import Flask, request, jsonify, send_from_directory
import joblib, os, re, math, string, warnings
import numpy as np
import pandas as pd
from datetime import datetime
from collections import deque
from sklearn.ensemble import IsolationForest

warnings.filterwarnings("ignore")

app = Flask(__name__, static_folder="static", template_folder="templates")

# ══════════════════════════════════════════════════════════════════
#  CONSTANTS  (exact copies from V3 notebook)
# ══════════════════════════════════════════════════════════════════
TOP_BRANDS = [
    'google','microsoft','apple','amazon','paypal','facebook','instagram',
    'twitter','netflix','linkedin','dropbox','adobe','yahoo','outlook',
    'office365','onedrive','sharepoint','github','stackoverflow','reddit',
    'whatsapp','telegram','discord','zoom','slack','chase','wellsfargo',
    'bankofamerica','citibank','barclays','hsbc','dhl','fedex','ups',
    'usps','ebay','walmart','target','steam','epicgames'
]

TRUSTED_DOMAINS = {
    'google.com','googleapis.com','google.co.in','youtube.com',
    'microsoft.com','live.com','outlook.com','office.com',
    'apple.com','icloud.com',
    'amazon.com','amazon.in','amazonaws.com',
    'github.com','githubusercontent.com',
    'stackoverflow.com','stackexchange.com',
    'linkedin.com','facebook.com','instagram.com','twitter.com','x.com',
    'paypal.com','ebay.com','reddit.com','wikipedia.org',
    'netflix.com','zoom.us','slack.com','discord.com',
    'dropbox.com','adobe.com','yahoo.com','bing.com',
    'cloudflare.com','akamai.com','fastly.com',
    'npmjs.com','pypi.org','docker.com','kubernetes.io',
    'notion.so','figma.com','canva.com','vercel.com','netlify.com',
    'heroku.com','railway.app','render.com'
}

BLACKLISTED_DOMAINS = {
    'login-secure.tk','paypa1-account.com','fakebank.login-secure.tk',
    'apple-id-verify.com','secure-login-verify.paypa1-account.com',
}

SUSPICIOUS_TLD = {
    'tk','ml','ga','cf','gq','xyz','top','click','link',
    'work','loan','win','download','zip','review','country',
    'kim','science','party','trade','date','faith','racing'
}

SUSPICIOUS_KW = [
    'login','verify','secure','update','account','banking',
    'confirm','password','signin','webscr','paypal','free',
    'prize','winner','ebayisapi','suspended','alert','urgent',
    'validate','authenticate','reactivate','recover','unlock'
]

TRANSACTIONAL_KW = [
    'your order','has shipped','delivery','tracking number',
    'otp','one-time','verification code','valid for',
    'receipt','invoice','your account statement',
    'thank you for your purchase','booking confirmation',
    'will arrive','order #','order number','shipment',
    'check-in','check in','reservation confirmed'
]

URGENCY_KW = [
    'urgent','immediately','suspended','expires','act now',
    'verify now','click here','limited time','your account has been',
    'unusual activity','security alert','confirm your identity',
    'update your information','will be terminated'
]

HOMOGLYPHS = {
    '0':'o','1':'l','3':'e','4':'a','5':'s',
    '6':'g','7':'t','8':'b','@':'a','$':'s'
}

# ══════════════════════════════════════════════════════════════════
#  MODEL LOADING
# ══════════════════════════════════════════════════════════════════
BASE   = os.path.dirname(os.path.abspath(__file__))
MDIR   = os.path.join(BASE, "models")

print("🔄 Loading models...")
url_model  = joblib.load(os.path.join(MDIR, "url_model.pkl"))
url_scaler = joblib.load(os.path.join(MDIR, "url_scaler.pkl"))
text_model = joblib.load(os.path.join(MDIR, "text_model.pkl"))
tfidf      = joblib.load(os.path.join(MDIR, "tfidf.pkl"))

try:
    URL_THRESH  = float(joblib.load(os.path.join(MDIR, "url_threshold.pkl")))
    TEXT_THRESH = float(joblib.load(os.path.join(MDIR, "text_threshold.pkl")))
except:
    URL_THRESH, TEXT_THRESH = 0.4336, 0.4324

print(f"✅ Models loaded | URL thresh={URL_THRESH:.4f} | Text thresh={TEXT_THRESH:.4f}")

# ══════════════════════════════════════════════════════════════════
#  ISOLATION FOREST — train on safe URL features at startup
# ══════════════════════════════════════════════════════════════════
print("🔄 Training Isolation Forest on safe URL profiles...")

_safe_url_profiles = [
    # Typical safe URL feature vectors [url_len, dots, hyphens, digits, https,
    # ip, kw, subs, path_len, entropy, at, depth, query_len, special, susp_tld]
    [20, 2, 0, 0, 1, 0, 0, 0, 1,  3.2, 0, 2, 0,  0, 0],
    [25, 2, 0, 0, 1, 0, 0, 0, 5,  3.5, 0, 3, 0,  0, 0],
    [30, 2, 0, 0, 1, 0, 0, 1, 10, 3.8, 0, 4, 0,  0, 0],
    [35, 3, 0, 2, 1, 0, 0, 1, 15, 3.9, 0, 5, 10, 2, 0],
    [18, 1, 0, 0, 1, 0, 0, 0, 1,  3.0, 0, 1, 0,  0, 0],
    [22, 2, 0, 0, 1, 0, 0, 0, 3,  3.3, 0, 2, 0,  0, 0],
    [40, 3, 0, 3, 1, 0, 0, 1, 20, 4.0, 0, 6, 15, 3, 0],
    [28, 2, 1, 1, 1, 0, 0, 0, 8,  3.6, 0, 3, 0,  0, 0],
    [15, 1, 0, 0, 1, 0, 0, 0, 0,  2.9, 0, 1, 0,  0, 0],
    [50, 3, 0, 4, 1, 0, 0, 2, 25, 4.1, 0, 7, 20, 4, 0],
]
_iso_forest = IsolationForest(
    n_estimators=100, contamination=0.05, random_state=42
)
_iso_forest.fit(np.array(_safe_url_profiles, dtype=float))
print("✅ Isolation Forest ready!")

# ══════════════════════════════════════════════════════════════════
#  IN-MEMORY STATS & HISTORY
# ══════════════════════════════════════════════════════════════════
stats = dict(total=0, phishing=0, suspicious=0, safe=0,
             url_scans=0, text_scans=0)
history = deque(maxlen=50)

# ══════════════════════════════════════════════════════════════════
#  FEATURE HELPERS  (exact V3 logic)
# ══════════════════════════════════════════════════════════════════
def calculate_entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return round(-sum((v/n)*math.log2(v/n) for v in freq.values()), 4)

def normalize_for_homoglyph(text):
    return ''.join(HOMOGLYPHS.get(c, c) for c in text.lower())

def get_brand_features(hostname, registered_domain, subdomain, url):
    hostname_norm = normalize_for_homoglyph(hostname)
    reg_norm      = normalize_for_homoglyph(registered_domain)
    brand_in_subdomain = brand_not_in_reg = num_brands = 0

    for brand in TOP_BRANDS:
        in_host = brand in hostname_norm
        in_reg  = brand in reg_norm
        if in_host:
            num_brands += 1
            if subdomain and brand in normalize_for_homoglyph(subdomain) and not in_reg:
                brand_in_subdomain = 1
            if in_host and not in_reg:
                brand_not_in_reg = 1

    reg_clean = reg_norm.split('.')[0] if '.' in reg_norm else reg_norm
    try:
        import Levenshtein as lev
        min_lev = min(
            (lev.distance(reg_clean, brand) for brand in TOP_BRANDS
             if abs(len(reg_clean)-len(brand)) <= 3),
            default=99
        )
    except ImportError:
        # fallback without Levenshtein library
        min_lev = 0 if reg_clean in TOP_BRANDS else 99

    is_lookalike  = int(0 < min_lev <= 2 and len(reg_clean) >= 4)
    has_digit_sub = int(any(c in registered_domain for c in '013456789'
                            if c in HOMOGLYPHS))
    path_has_brand = 0
    if brand_not_in_reg:
        path_has_brand = int(any(b in normalize_for_homoglyph(url) for b in TOP_BRANDS))

    return {
        'brand_in_subdomain'  : brand_in_subdomain,
        'brand_not_in_reg'    : brand_not_in_reg,
        'num_brands_mentioned': min(num_brands, 5),
        'is_lookalike_domain' : is_lookalike,
        'min_brand_lev_dist'  : min(min_lev, 10),
        'has_digit_sub'       : has_digit_sub,
        'path_has_brand'      : path_has_brand,
    }

def extract_url_features(url):
    """Extract all 34 V3 features."""
    try:
        import tldextract
        url_raw = str(url).strip()
        url_low = url_raw.lower()
        ext = tldextract.extract(url_low)
        registered_domain = f'{ext.domain}.{ext.suffix}' if ext.suffix else ext.domain
        subdomain = ext.subdomain
        hostname  = f'{ext.subdomain}.{ext.domain}.{ext.suffix}'.strip('.')
        tld       = ext.suffix.lower() if ext.suffix else ''
    except Exception:
        url_low = str(url).strip().lower()
        registered_domain = subdomain = hostname = ''
        tld = ''

    is_trusted = int(registered_domain in TRUSTED_DOMAINS)
    url_no_proto = re.sub(r'^https?://', '', url_low)

    try:
        path_part  = '/' + '/'.join(url_no_proto.split('/')[1:])
        query_part = url_low.split('?')[1] if '?' in url_low else ''
    except:
        path_part = query_part = ''

    ip_pat  = re.compile(
        r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)')
    digits  = sum(c.isdigit() for c in url_low)
    letters = sum(c.isalpha() for c in url_low)
    d2l     = round(digits / (letters + 1e-5), 4)
    num_sub = max(0, url_low.count('.') - 1)

    path_kw_hits = sum(kw in path_part for kw in SUSPICIOUS_KW)
    path_kw_dens = round(path_kw_hits / (len(path_part.split('/')) + 1e-5), 4)

    try:
        import tldextract as _tld
        _e = _tld.extract(url_low)
        reg_entropy = calculate_entropy(_e.domain)
        reg_length  = len(_e.domain)
    except:
        reg_entropy = calculate_entropy(registered_domain.split('.')[0])
        reg_length  = len(registered_domain.split('.')[0])

    brand_feats = get_brand_features(hostname, registered_domain, subdomain, url_low)

    base = {
        'url_length'               : len(url_low),
        'num_dots'                 : url_low.count('.'),
        'num_hyphens'              : url_low.count('-'),
        'num_digits'               : digits,
        'has_https'                : int(url_low.startswith('https')),
        'has_ip_address'           : int(bool(ip_pat.search(url_low))),
        'suspicious_keywords'      : sum(kw in url_low for kw in SUSPICIOUS_KW),
        'num_subdomains'           : num_sub,
        'path_length'              : len(path_part),
        'entropy'                  : calculate_entropy(url_low),
        'has_at_symbol'            : int('@' in url_low),
        'url_depth'                : url_low.count('/'),
        'query_length'             : len(query_part),
        'num_special_chars'        : sum(url_low.count(c) for c in ['=','&','%','~','+']),
        'suspicious_tld'           : int(tld in SUSPICIOUS_TLD),
        'digit_letter_ratio'       : d2l,
        'has_double_slash'         : int('//' in url_no_proto),
        'has_port'                 : int(bool(re.search(r':\d{2,5}/', url_low))),
        'has_fragment'             : int('#' in url_low),
        'has_hex_encoding'         : int('%' in url_low),
        'has_punycode'             : int('xn--' in url_low),
        'excessive_subdomains'     : int(num_sub > 3),
        'is_trusted_domain'        : is_trusted,
        'registered_domain_entropy': reg_entropy,
        'registered_domain_len'    : reg_length,
        'path_keyword_density'     : path_kw_dens,
        'tld_mismatch'             : int(
            any(b in hostname for b in TOP_BRANDS) and
            tld not in ['com','org','net','edu','gov'] and
            not is_trusted
        ),
    }
    base.update(brand_feats)
    return base

def preprocess_text(txt):
    txt = str(txt).lower()
    txt = txt.translate(str.maketrans('', '', string.punctuation))
    return re.sub(r'\s+', ' ', txt).strip()

def has_transactional_context(txt):
    txt_low = str(txt).lower()
    return int(any(kw in txt_low for kw in TRANSACTIONAL_KW))

def has_urgency_context(txt):
    txt_low = str(txt).lower()
    return int(any(kw in txt_low for kw in URGENCY_KW))

# ══════════════════════════════════════════════════════════════════
#  STAGE 1: URL ML MODEL
# ══════════════════════════════════════════════════════════════════
def stage1_url_ml(url: str) -> tuple:
    """Returns (p_url, features_dict, raw_feature_values_for_iso)"""
    feats   = extract_url_features(url)
    feat_df = pd.DataFrame([feats])
    scaled  = url_scaler.transform(feat_df)
    p_url   = float(url_model.predict_proba(scaled)[0][1])

    # 15-dim vector for Isolation Forest
    iso_vec = [
        feats['url_length'], feats['num_dots'], feats['num_hyphens'],
        feats['num_digits'], feats['has_https'], feats['has_ip_address'],
        feats['suspicious_keywords'], feats['num_subdomains'],
        feats['path_length'], feats['entropy'], feats['has_at_symbol'],
        feats['url_depth'], feats['query_length'], feats['num_special_chars'],
        feats['suspicious_tld']
    ]
    return p_url, feats, iso_vec

# ══════════════════════════════════════════════════════════════════
#  STAGE 2: TEXT ML MODEL + TRANSACTIONAL FIX
# ══════════════════════════════════════════════════════════════════
def stage2_text_ml(text: str) -> tuple:
    """Returns (p_text, is_transactional, has_urgency)"""
    if not text or not text.strip():
        return None, False, False

    clean      = preprocess_text(text)
    vec        = tfidf.transform([clean])
    p_text_raw = float(text_model.predict_proba(vec)[0][1])
    is_txn     = bool(has_transactional_context(text))
    is_urgent  = bool(has_urgency_context(text))

    # ── Transactional override ──────────────────────────────────────
    # If clearly transactional AND no urgency signals → reduce score
    if is_txn and not is_urgent:
        p_text = max(0.0, p_text_raw - 0.30)
    # If transactional but also has urgency (phishing mimics transactions)
    elif is_txn and is_urgent:
        p_text = p_text_raw  # trust the model
    else:
        p_text = p_text_raw

    return p_text, is_txn, is_urgent

# ══════════════════════════════════════════════════════════════════
#  STAGE 3: RULE-BASED ENGINE
# ══════════════════════════════════════════════════════════════════
def stage3_rule_engine(url: str, feats: dict) -> tuple:
    """Returns (p_rule, triggered_rules)"""
    score   = 0.0
    rules   = []
    url_low = url.lower()

    # IP address in URL → very suspicious
    if feats.get('has_ip_address'):
        score += 0.35; rules.append("IP address used instead of domain")

    # Suspicious TLD
    if feats.get('suspicious_tld'):
        score += 0.20; rules.append("Suspicious TLD detected (.tk/.xyz/.top etc.)")

    # Brand impersonation (brand in subdomain, not registered domain)
    if feats.get('brand_in_subdomain'):
        score += 0.30; rules.append("Brand name in subdomain — likely impersonation")

    # Brand keyword not in registered domain
    if feats.get('brand_not_in_reg'):
        score += 0.25; rules.append("Brand keyword not owned by registered domain")

    # Lookalike domain (Levenshtein ≤ 2)
    if feats.get('is_lookalike_domain'):
        score += 0.25; rules.append(f"Lookalike domain (edit distance={feats.get('min_brand_lev_dist')} from known brand)")

    # High entropy (randomness in URL)
    if feats.get('entropy', 0) > 4.2:
        score += 0.15; rules.append(f"High URL entropy ({feats['entropy']:.2f}) — likely generated")

    # Too many subdomains
    if feats.get('excessive_subdomains'):
        score += 0.10; rules.append("Excessive subdomains (>3)")

    # Login keyword without HTTPS
    if 'login' in url_low and not feats.get('has_https'):
        score += 0.20; rules.append("Login page without HTTPS")

    # @ symbol in URL (classic trick)
    if feats.get('has_at_symbol'):
        score += 0.25; rules.append("@ symbol in URL (browser ignores everything before @)")

    # Punycode / homoglyph
    if feats.get('has_punycode') or feats.get('has_digit_sub'):
        score += 0.20; rules.append("Punycode or digit-substitution in domain")

    # Multiple suspicious keywords in URL
    kw_count = feats.get('suspicious_keywords', 0)
    if kw_count >= 2:
        score += 0.15; rules.append(f"{kw_count} suspicious keywords in URL")
    elif kw_count == 1:
        score += 0.07

    # TLD mismatch (brand name + non-standard TLD)
    if feats.get('tld_mismatch'):
        score += 0.20; rules.append("Brand name present but TLD is non-standard")

    # High path keyword density
    if feats.get('path_keyword_density', 0) > 0.4:
        score += 0.10; rules.append("High density of phishing keywords in URL path")

    # Very long URL
    if feats.get('url_length', 0) > 100:
        score += 0.08; rules.append(f"Unusually long URL ({feats['url_length']} chars)")

    # Normalize to [0, 1]
    p_rule = min(score / 1.5, 1.0)
    return round(p_rule, 4), rules

# ══════════════════════════════════════════════════════════════════
#  STAGE 4: REPUTATION LAYER
# ══════════════════════════════════════════════════════════════════
def stage4_reputation(url: str, feats: dict) -> tuple:
    """Returns (p_rep, force_safe, force_phishing, rep_reason)"""
    try:
        import tldextract
        ext = tldextract.extract(url.lower())
        registered_domain = f'{ext.domain}.{ext.suffix}' if ext.suffix else ext.domain
    except:
        registered_domain = ''

    # Whitelist check
    if feats.get('is_trusted_domain') and not feats.get('brand_not_in_reg'):
        return 0.0, True, False, f"Trusted domain: {registered_domain}"

    # Blacklist check
    if registered_domain in BLACKLISTED_DOMAINS or \
       any(b in url.lower() for b in BLACKLISTED_DOMAINS):
        return 1.0, False, True, "Known malicious domain"

    # Domain looks very clean (trusted TLD + no suspicious signals)
    if feats.get('has_https') and \
       not feats.get('suspicious_tld') and \
       not feats.get('has_ip_address') and \
       feats.get('suspicious_keywords', 0) == 0:
        return 0.1, False, False, "Clean domain profile"

    return 0.5, False, False, "Neutral reputation"

# ══════════════════════════════════════════════════════════════════
#  STAGE 5: ANOMALY DETECTION
# ══════════════════════════════════════════════════════════════════
def stage5_anomaly(iso_vec: list) -> tuple:
    """Returns (anomaly_flag, anomaly_score)"""
    X = np.array([iso_vec], dtype=float)
    pred  = _iso_forest.predict(X)[0]       # -1 = anomaly, 1 = normal
    score = float(_iso_forest.score_samples(X)[0])
    # score_samples returns negative values; more negative = more anomalous
    anomaly_flag  = int(pred == -1)
    # Normalize: typical range is [-0.7, 0.1], map to [0,1] risk
    anomaly_risk  = round(max(0.0, min(1.0, (-score - 0.1) / 0.6)), 4)
    return anomaly_flag, anomaly_risk

# ══════════════════════════════════════════════════════════════════
#  STAGE 6: ENSEMBLE DECISION ENGINE
# ══════════════════════════════════════════════════════════════════
def stage6_ensemble(p_url, p_text, p_rule, p_rep,
                    anomaly_flag, has_text,
                    force_safe, force_phishing) -> tuple:
    """Returns (final_score, weight_breakdown)"""

    # ── Hard overrides ───────────────────────────────────────────
    if force_safe:
        return 0.02, {"override": "whitelist_safe"}
    if force_phishing:
        return 0.98, {"override": "blacklist_phishing"}

    # ── Dynamic weights depending on text availability ───────────
    if has_text:
        w_url  = 0.45
        w_text = 0.25
        w_rule = 0.20
        w_rep  = 0.10
    else:
        w_url  = 0.55
        w_text = 0.00
        w_rule = 0.30
        w_rep  = 0.15

    p_text_val = p_text if has_text else 0.0

    final = (w_url  * p_url  +
             w_text * p_text_val +
             w_rule * p_rule +
             w_rep  * p_rep)

    # ── Anomaly boost ────────────────────────────────────────────
    if anomaly_flag and final < 0.75:
        final = max(final, 0.65)

    final = round(min(max(final, 0.0), 1.0), 4)
    weights = {
        "url_model"   : round(w_url * p_url, 4),
        "text_model"  : round(w_text * p_text_val, 4),
        "rule_engine" : round(w_rule * p_rule, 4),
        "reputation"  : round(w_rep * p_rep, 4),
    }
    return final, weights

# ══════════════════════════════════════════════════════════════════
#  STAGE 7: CONFIDENCE & UNCERTAINTY
# ══════════════════════════════════════════════════════════════════
def stage7_confidence(final_score: float) -> tuple:
    """Returns (confidence_pct, confidence_label, is_uncertain)"""
    distance    = abs(final_score - 0.5)
    confidence  = round(distance * 200, 1)   # 0-100%
    is_uncertain = distance < 0.15

    if confidence >= 75:
        label = "High"
    elif confidence >= 40:
        label = "Medium"
    else:
        label = "Low"

    return confidence, label, is_uncertain

# ══════════════════════════════════════════════════════════════════
#  STAGE 8: FINAL CLASSIFICATION
# ══════════════════════════════════════════════════════════════════
def stage8_classify(final_score: float, is_uncertain: bool) -> str:
    if is_uncertain:
        return "Suspicious"
    if final_score < 0.25:
        return "Safe"
    elif final_score <= 0.75:
        return "Suspicious"
    else:
        return "Phishing"

# ══════════════════════════════════════════════════════════════════
#  MASTER PIPELINE
# ══════════════════════════════════════════════════════════════════
def run_pipeline(url: str, text: str = "") -> dict:
    url      = (url or "").strip()
    text     = (text or "").strip()
    has_text = len(text) > 3

    if not url:
        return {"error": "No URL provided"}

    reasons  = []
    signals  = {}

    # ── Stage 1: URL ML ──────────────────────────────────────────
    p_url, feats, iso_vec = stage1_url_ml(url)
    signals["url_model"] = round(p_url, 4)

    # ── Stage 2: Text ML ─────────────────────────────────────────
    p_text = None
    is_txn = is_urgent = False
    if has_text:
        p_text, is_txn, is_urgent = stage2_text_ml(text)
        signals["text_model"] = round(p_text, 4)
        if is_txn and not is_urgent:
            reasons.append("Transactional context detected — score reduced")
        if is_urgent:
            reasons.append("Urgency language detected in message")
    else:
        signals["text_model"] = None

    # ── Stage 3: Rule Engine ─────────────────────────────────────
    p_rule, rule_reasons = stage3_rule_engine(url, feats)
    signals["rule_engine"] = p_rule
    reasons.extend(rule_reasons[:5])   # top 5 rule triggers

    # ── Stage 4: Reputation ──────────────────────────────────────
    p_rep, force_safe, force_phishing, rep_reason = stage4_reputation(url, feats)
    signals["reputation"] = p_rep
    if force_safe or force_phishing:
        reasons.insert(0, rep_reason)

    # ── Stage 5: Anomaly Detection ───────────────────────────────
    anomaly_flag, anomaly_risk = stage5_anomaly(iso_vec)
    signals["anomaly_risk"] = anomaly_risk
    if anomaly_flag:
        reasons.append(f"URL structure anomaly detected (risk={anomaly_risk:.2f})")

    # ── Stage 6: Ensemble ────────────────────────────────────────
    final_score, weights = stage6_ensemble(
        p_url, p_text if has_text else 0.5,
        p_rule, p_rep,
        anomaly_flag, has_text,
        force_safe, force_phishing
    )

    # ── Stage 7: Confidence ──────────────────────────────────────
    conf_pct, conf_label, is_uncertain = stage7_confidence(final_score)
    if is_uncertain:
        reasons.append("Low confidence — borderline case, treat with caution")

    # ── Stage 8: Classification ──────────────────────────────────
    label = stage8_classify(final_score, is_uncertain)

    # ── Dominant stage ───────────────────────────────────────────
    if force_safe or force_phishing:
        dominant = "Reputation Layer"
    elif p_rule > 0.6 and p_rule > p_url:
        dominant = "Rule Engine"
    elif anomaly_flag:
        dominant = "Anomaly Detection"
    else:
        dominant = "URL ML Model"

    return {
        "url"           : url[:120],
        "probability"   : final_score,
        "label"         : label,
        "confidence"    : conf_label,
        "confidence_pct": conf_pct,
        "signals"       : {
            "url_model"  : round(p_url * 100, 1),
            "text_model" : round((p_text or 0) * 100, 1) if has_text else None,
            "rule_engine": round(p_rule * 100, 1),
            "reputation" : round(p_rep * 100, 1),
            "anomaly"    : round(anomaly_risk * 100, 1),
        },
        "reasons"       : reasons[:6] if reasons else ["No strong indicators detected"],
        "dominant_stage": dominant,
        "is_transactional": is_txn,
        "anomaly_flag"  : bool(anomaly_flag),
        "weights_used"  : weights,
        "features"      : {
            # ── Trust & Reputation ──────────────────────────────
            "is_trusted_domain"     : bool(feats.get('is_trusted_domain')),
            "has_https"             : bool(feats.get('has_https')),
            "suspicious_tld"        : bool(feats.get('suspicious_tld')),
            "has_ip_address"        : bool(feats.get('has_ip_address')),

            # ── Brand Impersonation ─────────────────────────────
            "brand_in_subdomain"    : bool(feats.get('brand_in_subdomain')),
            "brand_not_in_reg"      : bool(feats.get('brand_not_in_reg')),
            "is_lookalike_domain"   : bool(feats.get('is_lookalike_domain')),
            "min_brand_lev_dist"    : int(feats.get('min_brand_lev_dist', 99)),
            "num_brands_mentioned"  : int(feats.get('num_brands_mentioned', 0)),
            "has_digit_sub"         : bool(feats.get('has_digit_sub')),
            "has_punycode"          : bool(feats.get('has_punycode')),
            "tld_mismatch"          : bool(feats.get('tld_mismatch')),
            "path_has_brand"        : bool(feats.get('path_has_brand')),

            # ── URL Structure ───────────────────────────────────
            "url_length"            : int(feats.get('url_length', 0)),
            "num_dots"              : int(feats.get('num_dots', 0)),
            "num_hyphens"           : int(feats.get('num_hyphens', 0)),
            "num_subdomains"        : int(feats.get('num_subdomains', 0)),
            "excessive_subdomains"  : bool(feats.get('excessive_subdomains')),
            "url_depth"             : int(feats.get('url_depth', 0)),
            "path_length"           : int(feats.get('path_length', 0)),
            "has_at_symbol"         : bool(feats.get('has_at_symbol')),
            "has_double_slash"      : bool(feats.get('has_double_slash')),
            "has_port"              : bool(feats.get('has_port')),
            "has_fragment"          : bool(feats.get('has_fragment')),
            "has_hex_encoding"      : bool(feats.get('has_hex_encoding')),

            # ── Content & Entropy ───────────────────────────────
            "entropy"               : round(float(feats.get('entropy', 0)), 4),
            "registered_domain_entropy": round(float(feats.get('registered_domain_entropy', 0)), 4),
            "registered_domain_len" : int(feats.get('registered_domain_len', 0)),
            "suspicious_keywords"   : int(feats.get('suspicious_keywords', 0)),
            "path_keyword_density"  : round(float(feats.get('path_keyword_density', 0)), 4),
            "num_digits"            : int(feats.get('num_digits', 0)),
            "digit_letter_ratio"    : round(float(feats.get('digit_letter_ratio', 0)), 4),
            "num_special_chars"     : int(feats.get('num_special_chars', 0)),
            "query_length"          : int(feats.get('query_length', 0)),
        }
    }

# ══════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/about")
def about():
    return send_from_directory("static", "about.html")

@app.route("/stats")
def get_stats():
    return jsonify({**stats, "history": list(history)})

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url  = (data.get("url") or "").strip()
    text = (data.get("text") or "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = run_pipeline(url, text)
    if "error" in result:
        return jsonify(result), 400

    # ── Update stats ─────────────────────────────────────────────
    label = result["label"].lower()
    stats["total"]    += 1
    stats[label]      += 1
    if text: stats["text_scans"] += 1
    else:    stats["url_scans"]  += 1

    history.appendleft({
        "url"       : url[:70],
        "label"     : result["label"],
        "prob"      : result["probability"],
        "conf"      : result["confidence"],
        "time"      : datetime.now().strftime("%H:%M:%S"),
        "has_text"  : bool(text),
    })

    prediction = result["label"].lower()   # "safe" | "suspicious" | "phishing"
    confidence = result["confidence_pct"]  # numeric 0-100

    return jsonify({
        "prediction": prediction,
        "confidence": confidence,
        "features":   result["features"],
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)