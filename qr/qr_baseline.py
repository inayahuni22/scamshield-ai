"""
QR Baseline
-----------
Reference characteristics used by ScamShield AI to classify QR codes.

The baseline contains:
1. Known-safe examples
2. Suspicious characteristics
3. High-risk/malicious characteristics

This is a reference baseline, not a machine-learning model.
"""

# ============================================================
# 1. KNOWN SAFE QR EXAMPLES
# ============================================================

SAFE_BASELINE = {

    # Demo domains, kept for the test suite in agents.py's __main__ block.
    # Real, well-known domains added below so genuine safe merchant/service
    # QR codes get recognized as explicitly trusted, not just "no risk found."
    "trusted_domains": [
        "example.com",
        "example.org",
        "example.net",
        "wikipedia.org",

        # Major global payment/tech providers commonly embedded in
        # legitimate payment QR codes.
        "paypal.com",
        "google.com",
        "apple.com",
        "microsoft.com",
        "visa.com",
        "mastercard.com",
        "stripe.com",

        # UAE government and major service providers (adjust/add real
        # merchants you'll use in your actual demo QR codes).
        "dewa.gov.ae",
        "adnoc.ae",
        "etisalat.ae",
        "du.ae",
        "emirates.com",
        "dubaipolice.gov.ae",
        "u.ae",
        "uowdubai.ac.ae",
    ],

    # Safe QR codes normally use HTTPS.
    "allowed_protocols": [
        "https",
    ],

    # Characteristics we expect from a normal QR URL.
    "normal_characteristics": {
        "uses_https": True,
        "has_ip_address": False,
        "uses_url_shortener": False,
        "contains_credential_request": False,
        "contains_payment_request": False,
    },
}


# ============================================================
# 2. SUSPICIOUS QR BASELINE
# ============================================================

SUSPICIOUS_BASELINE = {

    # These do NOT automatically mean the QR is malicious.
    # They increase the risk and may result in Verify First.
    "suspicious_keywords": [
        "verify",
        "verification",
        "login",
        "signin",
        "sign-in",
        "password",
        "credential",
        "otp",
        "payment",
        "pay",
        "refund",
        "claim",
        "reward",
        "prize",
        "confirm",
        "update",
        "secure",
        "account",
    ],

    # Suspicious URL structures.
    "suspicious_url_patterns": [
        "verify-account",
        "verify-login",
        "confirm-account",
        "update-account",
        "secure-login",
        "login-account",
        "pay-now",
        "claim-reward",
        "claim-prize",
    ],

    # URL shorteners hide the final destination.
    "url_shorteners": [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "shorturl.at",
    ],

    # Characteristics that deserve additional verification.
    "suspicious_characteristics": {
        "uses_http": True,
        "has_ip_address": True,
        "uses_url_shortener": True,
        "very_long_url": True,
        "many_subdomains": True,
    },
}


# ============================================================
# 3. HIGH-RISK / MALICIOUS QR BASELINE
# ============================================================

MALICIOUS_BASELINE = {

    # These are strong indicators of phishing/scam behavior.
    "high_risk_keywords": [
        "verify-account",
        "verify login",
        "confirm-account",
        "secure-login",
        "password",
        "enter-password",
        "enter-otp",
        "otp-code",
        "one-time-password",
        "pay-now",
        "send-money",
        "transfer-money",
        "claim-reward",
        "claim-prize",
        "free-money",
        "winner",
        "you-have-won",
    ],

    # Strongly suspicious URL patterns.
    "high_risk_patterns": [
        "login",
        "signin",
        "verify-account",
        "confirm-account",
        "update-account",
        "secure-login",
        "password",
        "otp",
        "pay-now",
        "claim-reward",
        "claim-prize",
    ],

    # Exact malicious/demo URLs can be added here later.
    "known_malicious_urls": [

    ],

    # Known malicious/demo domains can be added here later.
    "known_malicious_domains": [

    ],
}


# ============================================================
# 4. BASELINE SCORING WEIGHTS
# ============================================================

RISK_WEIGHTS = {

    # Low/medium risk indicators
    "unknown_domain": 2,
    "http": 2,
    "url_shortener": 2,
    "ip_address": 3,
    "long_url": 1,
    "many_subdomains": 1,

    # Strong indicators
    "suspicious_keyword": 2,
    "suspicious_pattern": 3,

    # Very strong indicators
    "credential_request": 5,
    "payment_request": 5,
    "known_malicious_domain": 10,
    "known_malicious_url": 10,
}


# ============================================================
# 5. VERDICT THRESHOLDS
# ============================================================

VERDICT_THRESHOLDS = {

    # 0–2 → Safe, assuming no strong indicators
    "safe_max": 2,

    # 3–6 → needs additional verification
    "verify_first_max": 6,

    # 7+ → high risk
    # Do Not Proceed
}