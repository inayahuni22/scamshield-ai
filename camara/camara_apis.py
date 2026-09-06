"""
Real CAMARA API wrappers via Nokia Network-as-Code (NaC) sandbox.

AUTH: confirmed via RapidAPI Application Key, same host header for every
API: network-as-code.nokia.rapidapi.com

URL STRUCTURE — confirmed individually per API from each one's own Code
Snippets panel in the Playground. Turns out the structure is NOT uniform:
  - Number Verification & SIM Swap:  .../passthrough/camara/v1/{name}/{name}/{version}/{action}
  - Device Status & Location Verification: .../{name}/{version}/{action}  (no passthrough/camara/v1 prefix, no doubled name)
Don't assume one pattern applies to an API you haven't personally checked —
confirm each new endpoint's own snippet before trusting a path below.

Same function signatures as mock_camara.py, so main.py can swap the import
with no other code changes.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("NOKIA_API_KEY")
RAPIDAPI_HOST = "network-as-code.nokia.rapidapi.com"

# Full URLs, confirmed individually — see module docstring for why these
# aren't built from one shared BASE_URL pattern.
# ─────────────────────────────────────────────────────────────────────────
# KNOWN SIMULATOR TEST NUMBERS (from Nokia's official docs) — deterministic
# outcomes for demo scripting. Use these instead of random-looking +9999...
# numbers so your live demo produces the SAME verdict every rehearsal.
#
#   SIM Swap:
#     +99999991000  -> swapped = True
#     +99999991001  -> swapped = False
#
#   Device Roaming Status:
#     +99999991000  -> roaming = True
#     +99999991001  -> roaming = False
#     +99999990400/404/422/500/502/503/504 -> simulates that HTTP error
#
#   Location Verification (paired with check_location's own area/radius):
#     +99999991000  -> device NOT in the given area   (verificationResult=FALSE)
#     +99999991001  -> device IS in the given area     (verificationResult=TRUE)
#     +99999991002  -> partially within the area       (verificationResult=PARTIAL)
#     +99999991003  -> location unknown                (verificationResult=UNKNOWN)
#     +99999990400/404/422/500/502/503/504 -> simulates that HTTP error
#
# Suggested demo script:
#   "Safe" verdict      -> use +99999991001 for every check (no swap, not
#                          roaming, device in claimed area)
#   "Do Not Proceed"    -> use +99999991000 for every check (swap detected,
#                          roaming, device NOT in claimed area)
# ─────────────────────────────────────────────────────────────────────────

URLS = {
    # Confirmed exact via retrieveSimSwapDate's snippet; "check" action
    # inferred from the same versioned folder — verify before relying on it.
    "sim_swap_check": "https://network-as-code.p-eu.apihub.nokia.io/passthrough/camara/v1/sim-swap/sim-swap/v0/check",
    "sim_swap_retrieve_date": "https://network-as-code.p-eu.apihub.nokia.io/passthrough/camara/v1/sim-swap/sim-swap/v0/retrieve-date",
    # Confirmed exact via phoneNumberVerify-NV-V2's snippet.
    "number_verification": "https://network-as-code.p-eu.apihub.nokia.io/passthrough/camara/v1/number-verification/number-verification/v2/verify",
    # Confirmed exact via getRoamingStatus-DS-V0's snippet. Using roaming
    # rather than connectivity as the "device status" signal since it's the
    # one actually confirmed working — a device roaming when a message
    # claims a local sender is itself a useful fraud signal.
    "device_roaming": "https://network-as-code.p-eu.apihub.nokia.io/device-status/v0/roaming",
    # Confirmed exact via verifyLocation-LocV-V0's snippet.
    "location_verification": "https://network-as-code.p-eu.apihub.nokia.io/location-verification/v0/verify",
}


def _headers() -> dict:
    return {
        "x-rapidapi-key": API_KEY,
        "x-rapidapi-host": RAPIDAPI_HOST,
        "Content-Type": "application/json",
    }


def check_sim_swap(phone_number: str) -> dict:
    """
    Both response shapes confirmed via the Playground's Example Responses:
      checkSimSwap        -> {"swapped": true}
      retrieveSimSwapDate -> {"latestSimChange": "2023-07-03T14:27:08.312+02:00"}
    These are separate endpoints with separate response shapes — only call
    retrieve-date when a swap was actually found, to save an API call.
    """
    resp = requests.post(
        URLS["sim_swap_check"],
        headers=_headers(),
        json={"phoneNumber": phone_number, "maxAge": 240},
        timeout=10,
    )
    resp.raise_for_status()
    swapped = resp.json().get("swapped", False)

    swap_date = None
    if swapped:
        date_resp = requests.post(
            URLS["sim_swap_retrieve_date"],
            headers=_headers(),
            json={"phoneNumber": phone_number},
            timeout=10,
        )
        date_resp.raise_for_status()
        swap_date = date_resp.json().get("latestSimChange")

    return {"swapped": swapped, "swap_date": swap_date}


def check_number_verification(phone_number: str) -> dict:
    """
    KNOWN LIMITATION: Number Verification requires a second auth layer beyond
    the RapidAPI key — a Bearer token representing device/subscriber consent
    (CAMARA's standard 3-legged OAuth flow for this specific API). Confirmed
    this isn't a code bug: calling this same endpoint directly in Nokia's own
    Playground UI fails identically with "Authorization header is missing."

    Setting up that consent flow is out of scope for hackathon time, so this
    falls back to a mocked response so the rest of the pipeline (Verifier +
    Explainer agents) still runs end to end. SIM Swap, Device Status, and
    Location Verification are unaffected — they only needed the RapidAPI key.

    To make this real: obtain a Bearer token via Number Verification's OAuth2
    flow (see Nokia's "Consent and Identity Management" docs), then add
    "Authorization": f"Bearer {token}" to the headers below.
    """
    import random
    return {"verified": random.random() > 0.15}


def check_device_status(phone_number: str) -> dict:
    """
    Uses the Roaming Status endpoint. Response shape confirmed via Playground
    Example Responses: {"roaming": true, "countryCode": 901, "countryName": []}

    "active" here means "not roaming" — i.e. behaving like a normal local
    device, which is what you'd expect from a legitimate local sender.
    """
    resp = requests.post(
        URLS["device_roaming"],
        headers=_headers(),
        json={"device": {"phoneNumber": phone_number}},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    is_roaming = data.get("roaming", False)
    return {"active": not is_roaming}


# Simple in-memory cache so repeated checks against the same claimed location
# (e.g. re-testing the same demo QR code) don't hit the geocoder every time.
_geocode_cache: dict[str, dict] = {}

# Fallback coordinates for locations you know you'll use in the demo — add to
# this if the geocoder is down or rate-limited right before you present.
KNOWN_LOCATIONS = {
    "dubai, uae": {"latitude": 25.2048, "longitude": 55.2708},
    "abu dhabi, uae": {"latitude": 24.4539, "longitude": 54.3773},
}


def _geocode_location(location_name: str) -> dict | None:
    """
    Turns a place name (e.g. "Dubai, UAE") into {"latitude": ..., "longitude": ...}
    using OpenStreetMap's free Nominatim API — no key required, but keep calls
    light (max ~1/sec) and cache results.

    Returns None if the location can't be resolved, so callers can decide how
    to handle that instead of silently sending a bad request.
    """
    key = location_name.strip().lower()

    if key in _geocode_cache:
        return _geocode_cache[key]
    if key in KNOWN_LOCATIONS:
        _geocode_cache[key] = KNOWN_LOCATIONS[key]
        return KNOWN_LOCATIONS[key]

    try:
        resp = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": location_name, "format": "json", "limit": 1},
            headers={"User-Agent": "ScamShieldAI-Hackathon/1.0"},
            timeout=5,
        )
        resp.raise_for_status()
        results = resp.json()
        if not results:
            return None
        coords = {
            "latitude": float(results[0]["lat"]),
            "longitude": float(results[0]["lon"]),
        }
        _geocode_cache[key] = coords
        return coords
    except Exception as e:
        print(f"[camara_apis] geocoding failed for '{location_name}': {e}")
        return None


def check_location(phone_number: str, claimed_location: str) -> dict:
    coords = _geocode_location(claimed_location)

    if coords is None:
        # Can't verify without coordinates — fail safe rather than sending a
        # bad request to the API. Treat as a mismatch so the user is warned
        # instead of getting a false "Safe".
        return {
            "match": False,
            "claimed_location": claimed_location,
            "actual_location": "Could not resolve claimed location",
        }

    resp = requests.post(
        URLS["location_verification"],
        headers=_headers(),
        json={
            "device": {"phoneNumber": phone_number},
            "area": {
                "areaType": "CIRCLE",
                "center": {"latitude": coords["latitude"], "longitude": coords["longitude"]},
                "radius": 5000,
            },
        },
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    result = data.get("verificationResult")  # "TRUE" | "FALSE" | "PARTIAL" | "UNKNOWN"
    match = result == "TRUE"

    if result == "PARTIAL":
        actual = f"Partial match (match_rate: {data.get('matchRate', 'n/a')})"
    elif result == "UNKNOWN":
        actual = "Location unknown — too old or unavailable"
    elif match:
        actual = claimed_location
    else:
        actual = "Mismatch detected"

    return {
        "match": match,
        "claimed_location": claimed_location,
        "actual_location": actual,
    }


if __name__ == "__main__":
    # Manual smoke test — using Nokia's confirmed simulator test numbers.
    # +99999991000 always returns swapped=True / roaming=True / NOT in area —
    # use +99999991001 instead to see the opposite ("Safe") outcomes.
    print(check_sim_swap("+99999991000"))
    print(check_number_verification("+99999991001"))
    print(check_device_status("+99999991001"))
    print(check_location("+99999991001", "Dubai, UAE"))
