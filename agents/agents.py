"""
ScamShield AI — CrewAI analysis pipeline.

Responsibilities:
1. Analyze suspicious text / social-engineering tactics.
2. Analyze decoded QR content.
3. Compare QR content against the QR baseline.
4. Collect CAMARA/Nokia signals.
5. Produce a deterministic verdict.
6. Use CrewAI/Groq to generate a user-friendly explanation.
"""

import os
import re
from urllib.parse import urlparse

from dotenv import load_dotenv

from crewai import Agent, Task, Crew, Process
from crewai.llm import LLM

from camara.camara_apis import (
    check_sim_swap,
    check_number_verification,
    check_device_status,
    check_location,
)

from camara.mock_camara import (
    check_sim_swap as mock_check_sim_swap,
    check_number_verification as mock_check_number_verification,
    check_device_status as mock_check_device_status,
    check_location as mock_check_location,
)

# ============================================================
# QR BASELINE
# ============================================================

from qr.qr_baseline import (
    SAFE_BASELINE,
    SUSPICIOUS_BASELINE,
    MALICIOUS_BASELINE,
    RISK_WEIGHTS,
    VERDICT_THRESHOLDS,
)


load_dotenv()


# ============================================================
# CONFIGURATION
# ============================================================

USE_MOCK_CAMARA = os.getenv(
    "USE_MOCK_CAMARA",
    "false"
).lower() == "true"

GROQ_API_KEY = os.getenv("GROQ_API_KEY")


# ============================================================
# LLM
# ============================================================

llm = LLM(
    model="groq/openai/gpt-oss-120b",
    api_key=GROQ_API_KEY,
)


# ============================================================
# SOCIAL ENGINEERING ANALYZER
# ============================================================

def analyze_social_engineering(text: str) -> dict:
    """
    Detect common social-engineering indicators in text.
    """

    if not text:
        return {
            "analyzed": False,
            "risk_score": 0,
            "tactics": {},
            "matches": [],
        }

    lower_text = text.lower()

    tactics = {
    "urgency": [
        "immediately",
        "urgent",
        "urgently",
        "right away",
        "within 24 hours",
        "within 2 hours",
        "act now",
        "take action",
        "last chance",
        "as soon as possible",
        "today",
        "expires today",
        "deadline",
    ],

    "authority": [
        "microsoft",
        "security team",
        "bank",
        "police",
        "government",
        "administrator",
        "it department",
        "support team",
        "official",
    ],

    "fear": [
        "suspended",
        "blocked",
        "locked",
        "terminated",
        "legal action",
        "security breach",
        "unauthorized access",
        "account will be closed",
    ],

    "reward": [
        "congratulations",
        "winner",
        "selected",
        "reward",
        "prize",
        "gift",
        "$500",
        "$1000",
        "free money",
        "cash prize",
    ],

    "credential_harvesting": [
        "verify your account",
        "verify account",
        "confirm your account",
        "login",
        "sign in",
        "signin",
        "password",
        "one-time password",
        "otp",
        "credentials",
        "enter your details",
        "confirm your details",
    ],

    "financial_pressure": [
        "payment",
        "pay now",
        "transfer money",
        "send money",
        "bank transfer",
        "credit card",
        "debit card",
        "refund",
        "invoice",
    ],

    "impersonation": [
        "this is microsoft",
        "this is your bank",
        "this is support",
        "i am from microsoft",
        "i'm from microsoft",
        "security department",
        "account manager",
    ],

    "account_threat": [
        "account compromised",
        "account has been compromised",
        "account suspended",
        "account will be suspended",
        "account locked",
        "account has been locked",
        "unauthorized access",
        "suspicious activity",
    ],

    "credential_request": [
        "verify your account",
        "verify your details",
        "confirm your account",
        "confirm your identity",
        "enter your login details",
        "enter your password",
        "enter your security code",
    ],
}

    detected = {}
    all_matches = []

    for tactic, keywords in tactics.items():

        matches = [
            keyword
            for keyword in keywords
            if _keyword_present(keyword, lower_text)
        ]

        detected[tactic] = {
            "detected": bool(matches),
            "matches": matches,
        }

        all_matches.extend(matches)

    # --------------------------------------------------------
    # Risk scoring
    # --------------------------------------------------------

    risk_score = 0

    if detected["urgency"]["detected"]:
        risk_score += 2

    if detected["authority"]["detected"]:
        risk_score += 1

    if detected["fear"]["detected"]:
        risk_score += 2

    if detected["reward"]["detected"]:
        risk_score += 2

    if detected["credential_harvesting"]["detected"]:
        risk_score += 3

    if detected["financial_pressure"]["detected"]:
        risk_score += 3

    if detected["impersonation"]["detected"]:
        risk_score += 2

    return {
        "analyzed": True,
        "risk_score": risk_score,
        "tactics": detected,
        "matches": list(dict.fromkeys(all_matches)),
    }


# ============================================================
# URL HELPERS
# ============================================================

def _extract_domain(url: str) -> str:
    """
    Extract the hostname/domain from a URL.
    """

    try:

        # urlparse() only populates .netloc when the string has "://" —
        # a bare "www.paypal.com/signin" (no http/https prefix) parses
        # with an EMPTY netloc and the whole thing lands in .path, so
        # it silently fails to match anything in the trusted-domain
        # list. Add a scheme first when one isn't present.
        parsed = urlparse(
            url if "://" in url else "https://" + url
        )

        domain = parsed.netloc.lower()

        # Remove username/password if present.
        if "@" in domain:
            domain = domain.split("@")[-1]

        # Remove port.
        domain = domain.split(":")[0]

        # Remove www.
        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except Exception:
        return ""


def _has_ip_address(domain: str) -> bool:
    """
    Check whether a domain is an IPv4 address.
    """

    if not domain:
        return False

    return bool(
        re.fullmatch(
            r"\d{1,3}(\.\d{1,3}){3}",
            domain,
        )
    )


def _count_subdomains(domain: str) -> int:
    """
    Count subdomain levels.

    example.com -> 0
    shop.example.com -> 1
    login.secure.example.com -> 2
    """

    if not domain:
        return 0

    parts = domain.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def _keyword_present(keyword: str, text: str) -> bool:
    """
    Whole-word keyword match, not substring match.

    Plain "in" substring checks cause false positives — e.g. the
    keyword "pay" matching inside "payload" or "display", or "account"
    matching inside "accountant". \\b word-boundary regex avoids this
    while still matching the keyword regardless of surrounding
    punctuation or case.
    """

    return bool(
        re.search(
            r"\b" + re.escape(keyword.lower()) + r"\b",
            text,
        )
    )


# ============================================================
# URL EXTRACTION (for free-text messages)
# ============================================================
#
# A pasted link like "www.paypal.com/signin" or "g00gle-login.com"
# was previously scanned as plain prose in analyze_social_engineering,
# so words that happen to appear inside the URL itself (e.g. "signin",
# "payment") got counted as narrative social-engineering language, and
# the URL never got the domain-trust / brand-impersonation / baseline
# checks that analyze_qr_content() already does correctly for QR
# codes. This regex pulls URL-looking tokens out of the message so
# they can be run through analyze_qr_content() instead, and removed
# from the text before keyword scoring runs.

_URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s'\"<>]+"
    r"|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}(?:/[^\s'\"<>]*)?"
)


def _extract_urls(text: str) -> list[str]:
    """
    Find URL-looking substrings in free text, e.g. embedded in a
    Telegram message alongside a sentence.
    """

    if not text:
        return []

    candidates = _URL_PATTERN.findall(text)

    cleaned = []

    for candidate in candidates:

        trimmed = candidate.strip().strip("'\").,;:!?")

        # Require an actual dot so we don't match plain words.
        if "." in trimmed:
            cleaned.append(trimmed)

    # De-duplicate while preserving order.
    return list(dict.fromkeys(cleaned))


def _strip_urls(text: str, urls: list[str]) -> str:
    """
    Remove already-extracted URL substrings from the text before it
    goes through narrative keyword scoring, so words inside the URL
    (like "signin" or "payment") aren't double-counted as if they were
    part of the sender's sentence.
    """

    stripped = text

    for url in urls:
        stripped = stripped.replace(url, " ")

    return stripped


# ============================================================
# QR BASELINE ANALYZER
# ============================================================

def analyze_qr_content(qr_content: str) -> dict:
    """
    Analyze decoded QR content against the QR baseline.

    The analyzer does NOT simply assume that a working website
    is safe.

    It checks:
    - trusted baseline domains
    - malicious baseline domains
    - exact malicious URLs
    - HTTPS/HTTP
    - IP addresses
    - URL shorteners
    - URL length
    - subdomains
    - suspicious keywords
    - suspicious URL patterns
    - high-risk credential/payment indicators
    """

    if not qr_content:

        return {
            "analyzed": False,
            "is_url": False,
            "domain": "",
            "risk_score": 0,
            "classification": "unknown",
            "matches": [],
            "reasons": [],
            "content": "",
        }

    content = qr_content.strip()
    lower_content = content.lower()

    # --------------------------------------------------------
    # Detect URL
    # --------------------------------------------------------

    is_url = lower_content.startswith(
        (
            "http://",
            "https://",
            "www.",
        )
    )

    # --------------------------------------------------------
    # Non-URL QR
    # --------------------------------------------------------

    if not is_url:

        suspicious_matches = [
            keyword
            for keyword in (
                SUSPICIOUS_BASELINE.get(
                    "suspicious_keywords",
                    [],
                )
            )
            if _keyword_present(keyword, lower_content)
        ]

        high_risk_matches = [
            keyword
            for keyword in (
                MALICIOUS_BASELINE.get(
                    "high_risk_keywords",
                    [],
                )
            )
            if _keyword_present(keyword, lower_content)
        ]

        all_matches = list(
            dict.fromkeys(
                suspicious_matches
                + high_risk_matches
            )
        )

        if high_risk_matches:

            return {
                "analyzed": True,
                "is_url": False,
                "domain": "",
                "risk_score": RISK_WEIGHTS.get(
                    "credential_request",
                    5,
                ),
                "classification": "high_risk",
                "matches": all_matches,
                "reasons": [
                    "High-risk content detected in QR payload."
                ],
                "content": content,
            }

        if suspicious_matches:

            return {
                "analyzed": True,
                "is_url": False,
                "domain": "",
                "risk_score": RISK_WEIGHTS.get(
                    "suspicious_keyword",
                    2,
                ),
                "classification": "suspicious",
                "matches": all_matches,
                "reasons": [
                    "Suspicious content detected in QR payload."
                ],
                "content": content,
            }

        return {
            "analyzed": True,
            "is_url": False,
            "domain": "",
            "risk_score": 0,
            "classification": "safe",
            "matches": [],
            "reasons": [
                "No suspicious indicators detected in QR payload."
            ],
            "content": content,
        }

    # ========================================================
    # URL ANALYSIS
    # ========================================================

    domain = _extract_domain(content)

    parsed_url = urlparse(
        content if "://" in content else "https://" + content
    )

    scheme = parsed_url.scheme.lower()

    risk_score = 0
    matches = []
    reasons = []

    # --------------------------------------------------------
    # Known malicious URL
    # --------------------------------------------------------

    known_malicious_urls = [
        url.lower().strip()
        for url in MALICIOUS_BASELINE.get(
            "known_malicious_urls",
            [],
        )
    ]

    if lower_content in known_malicious_urls:

        return {
            "analyzed": True,
            "is_url": True,
            "domain": domain,
            "risk_score": RISK_WEIGHTS.get(
                "known_malicious_url",
                10,
            ),
            "classification": "high_risk",
            "matches": ["known_malicious_url"],
            "reasons": [
                "URL exactly matches a known malicious URL in the baseline."
            ],
            "content": content,
        }

    # --------------------------------------------------------
    # Known malicious domain
    # --------------------------------------------------------

    known_malicious_domains = [
        d.lower().strip()
        for d in MALICIOUS_BASELINE.get(
            "known_malicious_domains",
            [],
        )
    ]

    if domain in known_malicious_domains:

        return {
            "analyzed": True,
            "is_url": True,
            "domain": domain,
            "risk_score": RISK_WEIGHTS.get(
                "known_malicious_domain",
                10,
            ),
            "classification": "high_risk",
            "matches": ["known_malicious_domain"],
            "reasons": [
                "Domain matches a known malicious domain in the baseline."
            ],
            "content": content,
        }

    # --------------------------------------------------------
    # Trusted domain
    # --------------------------------------------------------

    trusted_domains = [
        d.lower().strip()
        for d in SAFE_BASELINE.get(
            "trusted_domains",
            [],
        )
    ]

    is_trusted_domain = (
        domain in trusted_domains
        or any(
            domain.endswith("." + trusted)
            for trusted in trusted_domains
        )
    )

    if is_trusted_domain:

        return {
            "analyzed": True,
            "is_url": True,
            "domain": domain,
            "risk_score": 0,
            "classification": "safe",
            "matches": [],
            "reasons": [
                "Domain matches the trusted-domain baseline."
            ],
            "content": content,
        }

    # --------------------------------------------------------
    # Brand impersonation (lookalike domain)
    # --------------------------------------------------------
    # A domain that contains a well-known trusted brand name (e.g.
    # "paypal") but is NOT that brand's actual domain is a classic
    # phishing pattern — e.g. "paypal-secure-verify.com" is not
    # paypal.com and should never be treated as merely "suspicious".
    # This has to run after the exact-trusted-domain check above
    # (which already returned) and before general keyword scoring,
    # since it's a strong signal on its own regardless of risk_score.

    # Exclude generic placeholder/demo domains from the trusted list —
    # "example" and "wikipedia" are common enough words/substrings that
    # checking for them as "brands" produces false positives (e.g.
    # "random-shop-example.net" contains "example" but isn't
    # impersonating anyone). Only real, distinctive commercial/
    # government brand names belong in impersonation matching.
    _generic_placeholder_domains = {
        "example.com", "example.org", "example.net", "wikipedia.org",
    }

    # --------------------------------------------------------
    # Brand impersonation / lookalike domain detection
    # --------------------------------------------------------
    #
    # Detect both:
    #   microsoft-secure.com
    #   micr0s0ft.com
    #
    # The second case uses common digit substitutions such as:
    #   0 -> o
    #   1 -> i/l
    #   3 -> e
    #   4 -> a
    #   5 -> s
    #   7 -> t
    #
    # This prevents typosquatting/lookalike domains from being
    # treated as safe simply because the exact brand string isn't
    # present.

    _generic_placeholder_domains = {
        "example.com",
        "example.org",
        "example.net",
        "wikipedia.org",
    }

    brand_names = [
        trusted.split(".")[0]
        for trusted in trusted_domains
        if trusted not in _generic_placeholder_domains
        and len(trusted.split(".")[0]) >= 4
    ]

    def _normalize_lookalike(value: str) -> str:
        """
        Normalize common digit substitutions used in phishing
        lookalike domains.
        """
        translation = str.maketrans({
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "6": "g",
            "7": "t",
            "8": "b",
            "9": "g",
        })

        return value.lower().translate(translation)

    normalized_domain = _normalize_lookalike(domain)

    impersonated_brand = None

    for brand in brand_names:

        normalized_brand = _normalize_lookalike(
            brand
        )

        # Exact brand or obvious brand substring.
        if brand in domain:
            impersonated_brand = brand
            break

        # Detect digit-substitution lookalikes such as:
        # micr0s0ft -> microsoft
        if normalized_brand in normalized_domain:
            impersonated_brand = brand
            break

    if impersonated_brand:
        return {
            "analyzed": True,
            "is_url": True,
            "domain": domain,
            "risk_score": RISK_WEIGHTS.get(
                "known_malicious_domain",
                10,
            ),
            "classification": "high_risk",
            "matches": [
                "brand_impersonation"
            ],
            "reasons": [
                f"The domain '{domain}' resembles the trusted "
                f"{impersonated_brand} brand but is not the real "
                f"{impersonated_brand} domain — a classic phishing "
                "lookalike pattern."
            ],
            "content": content,
        }

    if impersonated_brand:

        return {
            "analyzed": True,
            "is_url": True,
            "domain": domain,
            "risk_score": RISK_WEIGHTS.get(
                "known_malicious_domain",
                10,
            ),
            "classification": "high_risk",
            "matches": ["brand_impersonation"],
            "reasons": [
                f"The domain contains '{impersonated_brand}' but is not "
                f"the real {impersonated_brand} domain — a classic "
                "phishing lookalike pattern."
            ],
            "content": content,
        }

    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    if scheme == "http":

        risk_score += RISK_WEIGHTS.get(
            "http",
            2,
        )

        matches.append("http")

        reasons.append(
            "The URL does not use HTTPS."
        )

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    if _has_ip_address(domain):

        risk_score += RISK_WEIGHTS.get(
            "ip_address",
            3,
        )

        matches.append("ip_address")

        reasons.append(
            "The URL uses an IP address instead of a normal domain."
        )

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    url_shorteners = [
        d.lower().strip()
        for d in SUSPICIOUS_BASELINE.get(
            "url_shorteners",
            [],
        )
    ]

    if domain in url_shorteners:

        risk_score += RISK_WEIGHTS.get(
            "url_shortener",
            2,
        )

        matches.append("url_shortener")

        reasons.append(
            "The URL uses a shortened link that hides its final destination."
        )

    # --------------------------------------------------------
    # Long URL
    # --------------------------------------------------------

    if len(content) > 150:

        risk_score += RISK_WEIGHTS.get(
            "long_url",
            1,
        )

        matches.append("long_url")

        reasons.append(
            "The URL is unusually long."
        )

    # --------------------------------------------------------
    # Many subdomains
    # --------------------------------------------------------

    subdomain_count = _count_subdomains(domain)

    if subdomain_count >= 3:

        risk_score += RISK_WEIGHTS.get(
            "many_subdomains",
            1,
        )

        matches.append("many_subdomains")

        reasons.append(
            "The URL contains an unusually large number of subdomains."
        )

    # --------------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------------

    suspicious_keywords = SUSPICIOUS_BASELINE.get(
        "suspicious_keywords",
        [],
    )

    keyword_matches = [
        keyword
        for keyword in suspicious_keywords
        if _keyword_present(keyword, lower_content)
    ]

    if keyword_matches:

        risk_score += (
            RISK_WEIGHTS.get(
                "suspicious_keyword",
                2,
            )
            * min(len(keyword_matches), 3)
        )

        matches.extend(keyword_matches)

        reasons.append(
            "The URL contains suspicious security, payment, "
            "verification, or account-related terms."
        )

    # --------------------------------------------------------
    # Suspicious URL patterns
    # --------------------------------------------------------

    suspicious_patterns = SUSPICIOUS_BASELINE.get(
        "suspicious_url_patterns",
        [],
    )

    pattern_matches = [
        pattern
        for pattern in suspicious_patterns
        if pattern.lower() in lower_content
    ]

    if pattern_matches:

        risk_score += (
            RISK_WEIGHTS.get(
                "suspicious_pattern",
                3,
            )
            * min(len(pattern_matches), 2)
        )

        matches.extend(pattern_matches)

        reasons.append(
            "The URL structure matches suspicious patterns in the baseline."
        )

    # --------------------------------------------------------
    # High-risk keywords
    # --------------------------------------------------------

    high_risk_keywords = MALICIOUS_BASELINE.get(
        "high_risk_keywords",
        [],
    )

    high_risk_matches = [
        keyword
        for keyword in high_risk_keywords
        if _keyword_present(keyword, lower_content)
    ]

    if high_risk_matches:

        risk_score += RISK_WEIGHTS.get(
            "credential_request",
            5,
        )

        matches.extend(
            high_risk_matches
        )

        reasons.append(
            "The URL contains high-risk phishing, credential, "
            "payment, or scam indicators."
        )

    # --------------------------------------------------------
    # Remove duplicate matches
    # --------------------------------------------------------

    matches = list(
        dict.fromkeys(matches)
    )

    # --------------------------------------------------------
    # Determine classification
    # --------------------------------------------------------

    if high_risk_matches:

        classification = "high_risk"

    elif risk_score >= VERDICT_THRESHOLDS.get(
        "verify_first_max",
        6,
    ) + 1:

        classification = "high_risk"

    elif risk_score > 0:

        classification = "suspicious"

    else:
        # No risk signals detected (no HTTP, no IP address, no
        # shortener, no suspicious keywords/patterns, reasonable
        # length/subdomains) — treat as safe even though the domain
        # isn't on the explicit trusted list. A hardcoded whitelist
        # can never cover every legitimate merchant, so "no red flags"
        # should mean Safe, not an automatic Verify First.
        classification = "safe"

        reasons.append(
            "No risk indicators detected, though this domain is not "
            "on the explicit trusted-domain list."
        )

    return {
        "analyzed": True,
        "is_url": True,
        "domain": domain,
        "risk_score": risk_score,
        "classification": classification,
        "matches": matches,
        "reasons": reasons,
        "trusted_domain": is_trusted_domain,
        "content": content,
    }


# ============================================================
# CAMARA SIGNAL COLLECTION
# ============================================================

def get_camara_signals(
    phone_number: str,
    claimed_location: str = "Unknown",
) -> dict:
    """
    Collect telecom signals using either mock or real CAMARA APIs.
    """

    if USE_MOCK_CAMARA:

        sim_swap = mock_check_sim_swap(
            phone_number
        )

        number_verification = (
            mock_check_number_verification(
                phone_number
            )
        )

        device_status = mock_check_device_status(
            phone_number
        )

        location = mock_check_location(
            phone_number,
            claimed_location,
        )

    else:

        sim_swap = check_sim_swap(
            phone_number
        )

        number_verification = (
            check_number_verification(
                phone_number
            )
        )

        device_status = check_device_status(
            phone_number
        )

        location = check_location(
            phone_number,
            claimed_location,
        )

    return {
        "sim_swap": sim_swap,
        "number_verification": number_verification,
        "device_status": device_status,
        "location": location,
    }


# ============================================================
# CAMARA RED FLAGS
# ============================================================

def count_camara_red_flags(
    camara_signals: dict,
) -> int:
    """
    Count suspicious telecom signals.
    """

    count = 0

    sim_swap = camara_signals.get(
        "sim_swap",
        {},
    )

    if sim_swap.get("swapped") is True:
        count += 1

    number_verification = camara_signals.get(
        "number_verification",
        {},
    )

    if number_verification.get("verified") is False:
        count += 1

    device_status = camara_signals.get(
        "device_status",
        {},
    )

    if device_status.get("active") is False:
        count += 1

    location = camara_signals.get(
        "location",
        {},
    )

    if location.get("match") is False:
        count += 1

    return count


# ============================================================
# DETERMINISTIC VERDICT
# ============================================================

def determine_verdict(
    signal_data: dict,
) -> tuple[str, list[str]]:
    """
    Determine the verdict BEFORE asking the LLM.

    QR baseline analysis has priority for QR inputs.
    CAMARA signals are supporting evidence and cannot downgrade
    a clearly high-risk QR.
    """

    red_flags = []

    input_type = signal_data.get(
        "input_type",
        "text",
    )

    # ========================================================
    # QR VERDICT
    # ========================================================

    if input_type == "qr":

        qr_analysis = signal_data.get(
            "qr_analysis",
            {},
        )

        classification = qr_analysis.get(
            "classification",
            "unknown",
        )

        qr_risk_score = qr_analysis.get(
            "risk_score",
            0,
        )

        matches = qr_analysis.get(
            "matches",
            [],
        )

        reasons = qr_analysis.get(
            "reasons",
            [],
        )

        # CAMARA signals (SIM Swap, Number Verification, Device Status,
        # Location Verification) are computed as supporting evidence.
        # They can ESCALATE risk (e.g. a location mismatch on an
        # otherwise-clean QR is a strong spoofing signal) but can never
        # downgrade an already high-risk QR baseline verdict.
        camara_signals = signal_data.get(
            "camara_signals",
            {},
        )

        camara_count = count_camara_red_flags(
            camara_signals
        )

        location = camara_signals.get("location", {})
        location_mismatch = location.get("match") is False

        if camara_count > 0:

            if location_mismatch:

                red_flags.append(
                    "The QR code's claimed merchant location does not "
                    "match the actual device location."
                )

            if camara_count == 1:

                red_flags.append(
                    "One telecom verification signal requires attention."
                )

            elif camara_count >= 2:

                red_flags.append(
                    f"{camara_count} telecom verification signals "
                    "require attention."
                )

        # ----------------------------------------------------
        # High-risk QR — CAMARA cannot downgrade this
        # ----------------------------------------------------

        if classification == "high_risk":

            if matches:

                red_flags.append(
                    "QR baseline detected high-risk indicators: "
                    + ", ".join(matches)
                )

            red_flags.extend(
                reasons[:3]
            )

            return "Do Not Proceed", red_flags

        # ----------------------------------------------------
        # Suspicious QR — CAMARA can escalate to Do Not Proceed
        # ----------------------------------------------------

        if classification == "suspicious":

            red_flags.extend(
                reasons[:3]
            )

            if location_mismatch or camara_count >= 2:

                return "Do Not Proceed", red_flags

            return "Verify First", red_flags

        # ----------------------------------------------------
        # Baseline-safe QR — CAMARA can still downgrade this,
        # since a location mismatch on an otherwise-clean QR is
        # exactly the spoofing scenario this feature exists to catch
        # ----------------------------------------------------

        if classification == "safe":

            # Only a location mismatch justifies downgrading an
            # otherwise-clean, trusted-domain QR — that's the specific
            # spoofing scenario this branch exists to catch. Do NOT
            # downgrade on camara_count alone: Number Verification is
            # currently a random mock (see check_number_verification's
            # docstring) with a ~15% false-flag rate, so treating any
            # single red flag as disqualifying was intermittently
            # downgrading genuinely safe QRs (e.g. paypal.com) to
            # "Verify First" for no real reason.

            if location_mismatch:

                if camara_count >= 2:

                    return "Do Not Proceed", red_flags

                return "Verify First", red_flags

            red_flags.append(
                "QR baseline and telecom signals both check out."
            )

            return "Safe", red_flags

        # ----------------------------------------------------
        # Fallback (unreachable under current analyze_qr_content
        # logic, kept as a safety net)
        # ----------------------------------------------------

        return "Verify First", red_flags

    # ========================================================
    # TEXT VERDICT
    # ========================================================

    social_analysis = signal_data.get(
        "social_analysis",
        {},
    )

    risk_score = social_analysis.get(
        "risk_score",
        0,
    )

    tactics = social_analysis.get(
        "tactics",
        {},
    )

    # --------------------------------------------------------
    # Social engineering red flags
    # --------------------------------------------------------

    if risk_score >= 6:

        red_flags.append(
            "Multiple high-risk social-engineering indicators detected."
        )

    elif risk_score >= 3:

        red_flags.append(
            "Potential social-engineering tactics detected."
        )

    # --------------------------------------------------------
    # Embedded URL red flags (links pasted inside the message)
    # --------------------------------------------------------

    url_analysis = signal_data.get(
        "url_analysis",
        [],
    )

    url_high_risk = [
        u for u in url_analysis
        if u.get("classification") == "high_risk"
    ]

    url_suspicious = [
        u for u in url_analysis
        if u.get("classification") == "suspicious"
    ]

    for u in url_high_risk:

        red_flags.append(
            "The link to "
            f"{u.get('domain') or u.get('content')} "
            "matches high-risk phishing indicators."
        )

    for u in url_suspicious:

        red_flags.append(
            "The link to "
            f"{u.get('domain') or u.get('content')} "
            "could not be verified as safe."
        )

    has_url_signal = bool(url_high_risk) or bool(url_suspicious)
    has_text_signal = risk_score > 0

    # A high-risk link on its own is enough — same as QR handling,
    # CAMARA signals below can only escalate, never downgrade this.
    if url_high_risk:

        return "Do Not Proceed", red_flags

    # --------------------------------------------------------
    # CAMARA signals
    # --------------------------------------------------------
    #
    # The mock CAMARA responses are per-phone-number telecom checks —
    # they say nothing about what the message actually says. They must
    # never be the SOLE reason a plain, benign message ("hello world",
    # "are we still on for lunch?") gets flagged "Do Not Proceed" or
    # even "Verify First". They only count once there's already some
    # real signal in the message itself (a detected social-engineering
    # tactic, or a risky/unverified link) for them to reinforce.

    camara_signals = signal_data.get(
        "camara_signals",
        {},
    )

    camara_count = count_camara_red_flags(
        camara_signals
    )

    camara_is_grounded = has_text_signal or has_url_signal

    if camara_count > 0 and camara_is_grounded:

        if camara_count == 1:

            red_flags.append(
                "One telecom verification signal requires attention."
            )

        else:

            red_flags.append(
                f"{camara_count} telecom verification signals "
                "require attention."
            )

    # --------------------------------------------------------
    # Strong text-based threats
    # --------------------------------------------------------

    credential_detected = tactics.get(
        "credential_harvesting",
        {},
    ).get(
        "detected",
        False,
    )

    financial_detected = tactics.get(
        "financial_pressure",
        {},
    ).get(
        "detected",
        False,
    )

    fear_detected = tactics.get(
        "fear",
        {},
    ).get(
        "detected",
        False,
    )

    # --------------------------------------------------------
    # Final text verdict
    # --------------------------------------------------------

    if risk_score >= 6:

        return "Do Not Proceed", red_flags

    if credential_detected and (
        (camara_count >= 1 and camara_is_grounded)
        or risk_score >= 4
    ):

        return "Do Not Proceed", red_flags

    if financial_detected and risk_score >= 4:

        return "Do Not Proceed", red_flags

    if url_suspicious and (
        risk_score >= 3
        or (camara_count >= 2 and camara_is_grounded)
    ):

        return "Do Not Proceed", red_flags

    if camara_count >= 2 and camara_is_grounded:

        return "Do Not Proceed", red_flags

    if risk_score >= 3:

        return "Verify First", red_flags

    if fear_detected:

        return "Verify First", red_flags

    if url_suspicious:

        return "Verify First", red_flags

    if camara_count >= 1 and camara_is_grounded:

        return "Verify First", red_flags

    return "Safe", red_flags


# ============================================================
# EXPLANATION GENERATOR
# ============================================================

def generate_explanation(
    signal_data: dict,
    verdict: str,
    red_flags: list[str],
) -> str:
    """
    Generate a user-friendly explanation.

    QR explanations are deterministic so the LLM cannot
    contradict the QR baseline verdict.
    """

    input_type = signal_data.get(
        "input_type",
        "text",
    )

    # ========================================================
    # QR EXPLANATION
    # ========================================================

    if input_type == "qr":

        qr_analysis = signal_data.get(
            "qr_analysis",
            {},
        )

        domain = qr_analysis.get(
            "domain",
            "",
        )

        matches = qr_analysis.get(
            "matches",
            [],
        )

        reasons = qr_analysis.get(
            "reasons",
            [],
        )

        classification = qr_analysis.get(
            "classification",
            "unknown",
        )

        # ----------------------------------------------------
        # High-risk
        # ----------------------------------------------------

        if verdict == "Do Not Proceed":

            if matches:

                return (
                    "🚨 Do Not Proceed. "
                    "The QR code matches high-risk patterns in the "
                    "ScamShield baseline: "
                    + ", ".join(matches[:4])
                    + ". Do not open the link, enter credentials, "
                    "share OTPs, or make a payment."
                )

            return (
                "🚨 Do Not Proceed. "
                "The QR code shows high-risk characteristics "
                "consistent with phishing or scam activity."
            )

        # ----------------------------------------------------
        # Suspicious
        # ----------------------------------------------------

        if verdict == "Verify First":

            if domain:

                return (
                    "⚠️ Verify First. "
                    f"The QR points to {domain}, but it does not "
                    "match the trusted baseline or contains "
                    "characteristics that require additional verification. "
                    "Check the destination before proceeding."
                )

            return (
                "⚠️ Verify First. "
                "The QR code could not be confidently matched "
                "to the trusted baseline."
            )

        # ----------------------------------------------------
        # Safe
        # ----------------------------------------------------

        if verdict == "Safe":

            if domain:

                return (
                    "✅ Safe based on the current baseline. "
                    f"The QR points to {domain}, which matches "
                    "a trusted baseline domain and has no detected "
                    "high-risk indicators."
                )

            return (
                "✅ No significant risk indicators were detected "
                "in the QR content."
            )

    # ========================================================
    # TEXT EXPLANATION
    # ========================================================

    social_analysis = signal_data.get(
        "social_analysis",
        {},
    )

    # Safe is fully deterministic. This prevents an LLM from inventing
    # telecom or other red flags when the classifier found none.
    if verdict == "Safe":
        return (
            "✅ No significant risk indicators were detected. "
            "The message appears safe based on the available signals."
        )

    prompt = f"""
You are the explanation agent for ScamShield AI.

The deterministic analysis has already produced the final verdict.
You are ONLY allowed to explain the approved findings below.

VERDICT:
{verdict}

APPROVED RED FLAGS:
{red_flags}

Rules:
- Do not change or contradict the verdict.
- Only mention facts explicitly contained in APPROVED RED FLAGS.
- Do not infer additional facts from the original message or hidden data.
- Never claim a SIM swap, location mismatch, device problem, or failed
  number verification unless that exact finding appears in APPROVED RED FLAGS.
- If the verdict is "Do Not Proceed", clearly tell the user not to continue.
- If the verdict is "Verify First", tell the user to verify independently.
- Do not mention CrewAI, agents, prompts, models, or internal implementation.
- Keep the response under 80 words.
"""

    try:

        explainer_agent = Agent(
            role="ScamShield Security Explainer",
            goal=(
                "Explain the already-determined scam risk clearly "
                "without changing the verdict."
            ),
            backstory=(
                "You are a cybersecurity assistant helping users "
                "understand suspicious messages."
            ),
            llm=llm,
            verbose=False,
        )

        task = Task(
            description=prompt,
            expected_output=(
                "A concise explanation under 80 words that "
                "strictly follows the supplied verdict."
            ),
            agent=explainer_agent,
        )

        crew = Crew(
            agents=[explainer_agent],
            tasks=[task],
            process=Process.sequential,
            verbose=False,
        )

        result = crew.kickoff()

        explanation = str(
            result
        ).strip()

        if explanation:

            return explanation

    except Exception as e:

        print(
            f"[agents] LLM explanation failed: {e}"
        )

    # ========================================================
    # FALLBACK
    # ========================================================

    if verdict == "Do Not Proceed":

        return (
            "🚨 Multiple risk indicators were detected. "
            "Do not continue, click links, share credentials, "
            "or make payments."
        )

    if verdict == "Verify First":

        return (
            "⚠️ Some risk indicators were detected. "
            "Verify the sender and destination independently "
            "before taking any action."
        )

    return (
        "✅ No significant risk indicators were detected. "
        "The message appears safe based on the available signals."
    )


# ============================================================
# MAIN PROCESS FUNCTION
# ============================================================

def process(
    input_type: str,
    phone_number: str,
    message_text: str = "",
    claimed_location: str = "Unknown",
) -> dict:
    """
    Main ScamShield analysis pipeline.

    Returns:

        {
            "verdict": "...",
            "explanation": "...",
            "raw_signals": {...}
        }
    """

    # ========================================================
    # TEXT
    # ========================================================

    if input_type == "text":

        urls_found = _extract_urls(
            message_text
        )

        text_without_urls = _strip_urls(
            message_text,
            urls_found,
        )

        social_analysis = analyze_social_engineering(
            text_without_urls
        )

        # Run any pasted links through the same domain-trust /
        # brand-impersonation / baseline logic used for QR codes,
        # instead of letting words inside the URL leak into the
        # narrative keyword scan above.
        url_analysis = [
            analyze_qr_content(url)
            for url in urls_found
        ]

        camara_signals = get_camara_signals(
            phone_number,
            claimed_location,
        )

        signal_data = {
            "input_type": "text",
            "message_text": message_text,
            "social_analysis": social_analysis,
            "url_analysis": url_analysis,
            "camara_signals": camara_signals,
        }

    # ========================================================
    # QR
    # ========================================================

    elif input_type == "qr":

        qr_analysis = analyze_qr_content(
            message_text
        )

        camara_signals = get_camara_signals(
            phone_number,
            claimed_location,
        )

        signal_data = {
            "input_type": "qr",
            "message_text": message_text,
            "qr_analysis": qr_analysis,
            "camara_signals": camara_signals,
        }

    # ========================================================
    # UNKNOWN
    # ========================================================

    else:

        signal_data = {
            "input_type": input_type,
            "message_text": message_text,
            "camara_signals": {},
        }

    # ========================================================
    # VERDICT
    # ========================================================

    verdict, red_flags = determine_verdict(
        signal_data
    )

    # ========================================================
    # EXPLANATION
    # ========================================================

    explanation = generate_explanation(
        signal_data,
        verdict,
        red_flags,
    )

    # ========================================================
    # RETURN
    # ========================================================

    return {
        "verdict": verdict,
        "explanation": explanation,
        "raw_signals": {
            **signal_data,
            "red_flags": red_flags,
        },
    }


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("SCAMSHIELD AI — BASELINE QR TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # TEST 1: Known safe QR
    # --------------------------------------------------------

    test_qr_safe = "https://example.com"

    result = process(
        input_type="qr",
        phone_number="+000000000000",
        message_text=test_qr_safe,
    )

    print("\nSAFE QR TEST")
    print("-" * 60)
    print("QR:", test_qr_safe)
    print("Verdict:", result["verdict"])
    print("Explanation:", result["explanation"])
    print(
        "QR Analysis:",
        result["raw_signals"]["qr_analysis"],
    )

    # --------------------------------------------------------
    # TEST 2: Unknown website
    # --------------------------------------------------------

    test_qr_unknown = "https://random-business-example.com"

    result = process(
        input_type="qr",
        phone_number="+000000000000",
        message_text=test_qr_unknown,
    )

    print("\nUNKNOWN QR TEST")
    print("-" * 60)
    print("QR:", test_qr_unknown)
    print("Verdict:", result["verdict"])
    print("Explanation:", result["explanation"])
    print(
        "QR Analysis:",
        result["raw_signals"]["qr_analysis"],
    )

    # --------------------------------------------------------
    # TEST 3: Harmful QR
    # --------------------------------------------------------

    test_qr_harmful = (
        "https://pay-now-example.net/verify-account"
    )

    result = process(
        input_type="qr",
        phone_number="+000000000000",
        message_text=test_qr_harmful,
    )

    print("\nHARMFUL QR TEST")
    print("-" * 60)
    print("QR:", test_qr_harmful)
    print("Verdict:", result["verdict"])
    print("Explanation:", result["explanation"])
    print(
        "QR Analysis:",
        result["raw_signals"]["qr_analysis"],
    )

    # --------------------------------------------------------
    # TEST 4: Suspicious text
    # --------------------------------------------------------

    test_text = (
        "Congratulations! You have been selected to receive "
        "a $500 reward. Confirm your details within 2 hours "
        "to claim your prize."
    )

    result = process(
        input_type="text",
        phone_number="+000000000000",
        message_text=test_text,
    )

    print("\nSUSPICIOUS TEXT TEST")
    print("-" * 60)
    print("Message:", test_text)
    print("Verdict:", result["verdict"])
    print("Explanation:", result["explanation"])

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)