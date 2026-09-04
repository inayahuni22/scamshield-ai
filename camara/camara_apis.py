"""
Real CAMARA API wrappers via Nokia Network-as-Code (NaC) sandbox.

IMPORTANT: Nokia's exact endpoint paths, auth flow, and response schemas can
differ from what's below — this follows the standard CAMARA OAuth2
client-credentials pattern, but Person C should confirm every URL/field
against the live NaC sandbox docs (https://network-as-code.nokia.dev/) and
adjust before the demo. Don't trust this file blindly; test each function
against the real sandbox the moment credentials are issued.

Same function signatures as mock_camara.py, so main.py can swap the import
with no other code changes.
"""

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv("NOKIA_BASE_URL", "https://network-as-code.p-eu.rapidapi.com")
CLIENT_ID = os.getenv("NOKIA_CLIENT_ID")
CLIENT_SECRET = os.getenv("NOKIA_CLIENT_SECRET")

_token_cache = {"access_token": None, "expires_at": 0}


def _get_access_token() -> str:
    """OAuth2 client-credentials token, cached until near expiry."""
    if _token_cache["access_token"] and time.time() < _token_cache["expires_at"] - 30:
        return _token_cache["access_token"]

    resp = requests.post(
        f"{BASE_URL}/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    _token_cache["access_token"] = data["access_token"]
    _token_cache["expires_at"] = time.time() + data.get("expires_in", 3600)
    return _token_cache["access_token"]


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {_get_access_token()}",
        "Content-Type": "application/json",
    }


def check_sim_swap(phone_number: str) -> dict:
    resp = requests.post(
        f"{BASE_URL}/sim-swap/v0/check",
        headers=_headers(),
        json={"phoneNumber": phone_number, "maxAge": 240},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "swapped": data.get("swapped", False),
        "swap_date": data.get("latestSimChange"),
    }


def check_number_verification(phone_number: str) -> dict:
    resp = requests.post(
        f"{BASE_URL}/number-verification/v0/verify",
        headers=_headers(),
        json={"phoneNumber": phone_number},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    return {"verified": data.get("devicePhoneNumberVerified", False)}


def check_device_status(phone_number: str) -> dict:
    resp = requests.post(
        f"{BASE_URL}/device-status/v0/connectivity",
        headers=_headers(),
        json={"device": {"phoneNumber": phone_number}},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    return {"active": data.get("connectivityStatus") == "CONNECTED_DATA"}


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
        f"{BASE_URL}/location-verification/v0/verify",
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
    match = data.get("verificationResult") == "TRUE"
    return {
        "match": match,
        "claimed_location": claimed_location,
        "actual_location": claimed_location if match else "Mismatch detected",
    }


if __name__ == "__main__":
    # Manual smoke test — run this file directly once credentials are set
    print(check_sim_swap("+971500000000"))
