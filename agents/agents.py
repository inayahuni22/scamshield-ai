"""
CrewAI agents: Verifier (decides which CAMARA checks to run) and Explainer
(reasons over signals, writes the plain-language verdict).

Built against camara/mock_camara.py by default so this can be developed and
tested without real Nokia sandbox access. main.py switches the import to the
real camara_apis module for the live demo.
"""

import os
import sys
import json
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from langchain_groq import ChatGroq
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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

GROQ_MODEL = "openai/gpt-oss-120b"


def run_verifier(input_type: str, phone_number: str | None, claimed_location: str | None) -> dict:
    """
    Decides which CAMARA checks matter for this input type and runs them.
    Text/SMS -> sender identity checks. QR -> location match check.
    """
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
    """
    Feeds the signal results to a CrewAI agent backed by Groq, gets back a
    plain-language verdict. Falls back to a rule-based verdict if the LLM
    call fails, so the demo never breaks on an API hiccup.
    """
    explainer = Agent(
        role="Fraud Signal Explainer",
        goal=(
            "Read raw telecom fraud-detection signals and produce one of "
            "exactly three verdicts: 'Safe', 'Verify First', or 'Do Not Proceed', "
            "with a short plain-language explanation a non-technical person can "
            "understand in 2-3 sentences."
        ),
        backstory=(
            "You explain fraud risk to everyday consumers — parents, "
            "grandparents, first-time smartphone users. No jargon, no risk "
            "scores, just a clear verdict and why."
        ),
        llm=ChatGroq(model=GROQ_MODEL, temperature=0.2),
        verbose=False,
    )

    task = Task(
        description=(
            "Here are the raw signal results from CAMARA fraud-detection APIs:\n"
            f"{json.dumps(signal_data, indent=2)}\n\n"
            "Return ONLY a JSON object with exactly two keys: 'verdict' "
            "(one of 'Safe', 'Verify First', 'Do Not Proceed') and "
            "'explanation' (a short plain-language string). No other text."
        ),
        expected_output="A JSON object with 'verdict' and 'explanation' keys.",
        agent=explainer,
    )

    crew = Crew(agents=[explainer], tasks=[task], verbose=False)

    try:
        raw = crew.kickoff()
        print(f"[DEBUG] raw kickoff result: {repr(raw)}")
        text = str(raw).strip().strip("```json").strip("```").strip()
        parsed = json.loads(text)
        return {
            "verdict": parsed["verdict"],
            "explanation": parsed["explanation"],
            "raw_signals": signal_data,
        }
    except Exception as e:
        print(f"[DEBUG] LLM call failed: {e}")
        return _fallback_verdict(signal_data)


def _fallback_verdict(signal_data: dict) -> dict:
    """Simple rule-based backup if the LLM call fails or returns bad JSON."""
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
    """Full pipeline: Verifier -> Explainer. This is what main.py calls."""
    signal_data = run_verifier(input_type, phone_number, claimed_location)
    return run_explainer(signal_data)


if __name__ == "__main__":
    # Standalone test using mock signals
    result = process(input_type="text", phone_number="+99999991000")
    print(json.dumps(result, indent=2))
