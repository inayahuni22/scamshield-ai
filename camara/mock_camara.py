"""Deterministic mock CAMARA responses for ScamShield AI demos."""

RISKY_DEMO_NUMBER = "+99999991000"


def check_sim_swap(phone_number: str) -> dict:
    risky = phone_number == RISKY_DEMO_NUMBER
    return {"swapped": risky, "swap_date": "2026-08-30" if risky else None}


def check_number_verification(phone_number: str) -> dict:
    return {"verified": phone_number != RISKY_DEMO_NUMBER}


def check_device_status(phone_number: str) -> dict:
    return {"active": phone_number != RISKY_DEMO_NUMBER}


def check_location(phone_number: str, claimed_location: str) -> dict:
    risky = phone_number == RISKY_DEMO_NUMBER
    return {
        "match": False if risky else True,
        "claimed_location": claimed_location,
        "actual_location": (
            "Unknown / mismatched region" if risky else claimed_location
        ),
    }


if __name__ == "__main__":
    print(check_sim_swap(RISKY_DEMO_NUMBER))
    print(check_number_verification(RISKY_DEMO_NUMBER))
    print(check_device_status(RISKY_DEMO_NUMBER))
    print(check_location(RISKY_DEMO_NUMBER, "Dubai, UAE"))
