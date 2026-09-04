"""
Mock CAMARA API responses.

Same function names/signatures as camara_apis.py (the real Nokia NaC wrappers).
Everyone else (bot, agents) imports from here until camara_apis.py is ready,
then main.py swaps the import — no other code needs to change.
"""

import random


def check_sim_swap(phone_number: str) -> dict:
    swapped = random.random() < 0.2  # 20% of test calls flag a swap
    return {
        "swapped": swapped,
        "swap_date": "2026-08-30" if swapped else None,
    }


def check_number_verification(phone_number: str) -> dict:
    return {
        "verified": random.random() > 0.15,
    }


def check_device_status(phone_number: str) -> dict:
    return {
        "active": random.random() > 0.1,
    }


def check_location(phone_number: str, claimed_location: str) -> dict:
    match = random.random() > 0.25
    return {
        "match": match,
        "claimed_location": claimed_location,
        "actual_location": claimed_location if match else "Unknown / mismatched region",
    }


if __name__ == "__main__":
    # quick sanity check
    print(check_sim_swap("+971500000000"))
    print(check_number_verification("+971500000000"))
    print(check_device_status("+971500000000"))
    print(check_location("+971500000000", "Dubai, UAE"))
