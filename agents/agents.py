"""
CrewAI agents: Verifier (decides which CAMARA checks to run) and Explainer
(reasons over signals, writes the plain-language verdict).

Built against camara/mock_camara.py by default so this can be developed and
tested without real Nokia sandbox access. main.py switches the import to the
real camara_apis module for the live demo.
"""

import os
import json
from dotenv import load_dotenv
from crewai import Agent, Task, Crew

load_dotenv()

USE_MOCK = os.getenv("USE_MOCK_CAMARA", "true").lower() == "true"

if USE_MOCK:
    from camara.mock_camara import (
        check_sim_swap,
        check_number_verification,
        check_device_status,
        check_location,
    )
else:
    from camara.camara_apis import (
        check_sim_swap,
        check_number_verification,
        check_device_status,
        check_location,
    )


def run_verifier(input_type: str, phone_number: str | None, claimed_location: str | None) -> dict:
    checks_run = []
    results = {}

    if input_type == "text":
        checks_run = ["sim_swap", "number_verification", "device_status"]
        results["sim_swap"] = check_sim_swap(phone_number)
        results["number_verification"] = check_number_verification(phone_number)
        results["device_status"] = check_device_status(phone_number)
    elif input_type == "qr":
        checks_run = ["location_verification", "device_status"]
        results["location_verification"] = check_location(phone_number, claimed_location)
        results["device_status"] = check_device_status(phone_number)

    return {
        "input_type": input_type,
        "checks_run": checks_run,
        "results": results,
    }


def run_explainer(signal_data: dict) -> dict:
    return _fallback_verdict(signal_data)


def _fallback_verdict(signal_data: dict) -> dict:
    results = signal_data.get("results", {})
    red_flags = []

    if results.get("sim_swap", {}).get("swapped"):
        red_flags.append("this number's SIM was recently swapped")
    if results.get("number_verification", {}).get("verified") is False:
        red_flags.append("the sender's number couldn't be verified")
    if results.get("device_status", {}).get("active") is False:
        red_flags.append("the sender's device appears inactive")
    if results.get("location_verification", {}).get("match") is False:
        red_flags.append("the QR code's location doesn't match the merchant's actual location")

    if len(red_flags) >= 2:
        verdict = "Do Not Proceed"
    elif len(red_flags) == 1:
        verdict = "Verify First"
    else:
        verdict = "Safe"

    explanation = (
        "No red flags found — this looks legitimate, but always stay cautious."
        if not red_flags
        else "We found a concern: " + "; ".join(red_flags) + "."
    )

    return {"verdict": verdict, "explanation": explanation, "raw_signals": signal_data}


def process(input_type: str, phone_number: str | None = None,
            claimed_location: str | None = None) -> dict:
    signal_data = run_verifier(input_type, phone_number, claimed_location)
    return run_explainer(signal_data)


if __name__ == "__main__":
    result = process(input_type="text", phone_number="+971500000000")
    print(json.dumps(result, indent=2))
