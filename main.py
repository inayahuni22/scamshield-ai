"""
Integration entry point: Telegram -> (QR decode if needed) -> Verifier Agent
-> Explainer Agent -> reply to user -> log to Supabase.

Run this (not bot/telegram_bot.py directly) to run the full pipeline.
"""

import re
import sys
import os

sys.path.append(os.path.dirname(__file__))

from bot import telegram_bot
from qr.qr_decoder import decode_qr
from agents.agents import process
from logging_module.supabase_logger import log_check

PHONE_REGEX = re.compile(r"(\+?\d[\d\s\-]{7,}\d)")


def _extract_phone(text: str) -> str | None:
    match = PHONE_REGEX.search(text)
    return match.group(1).replace(" ", "").replace("-", "") if match else None


async def process_check(input_type: str, content: str) -> dict:
    """
    input_type: "text" or "qr"
    content: the raw message text, or a local image path for QR
    """
    if input_type == "text":
        phone_number = _extract_phone(content) or "+000000000000"
        result = process(input_type="text", phone_number=phone_number)

    elif input_type == "qr":
        qr_data = decode_qr(content)
        if not qr_data.get("found"):
            result = {
                "verdict": "Verify First",
                "explanation": "Couldn't read that QR code clearly — try a clearer photo, "
                                "or don't scan it if you're unsure.",
                "raw_signals": {},
            }
        else:
            claimed_location = qr_data.get("claimed_sender", "Unknown")
            # Demo note: a real merchant phone/device identifier would come
            # from the decoded QR payload's payment info; using a placeholder
            # here since sandbox test QR codes won't encode a real number.
            phone_number = "+000000000000"
            result = process(
                input_type="qr",
                phone_number=phone_number,
                claimed_location=claimed_location,
            )
    else:
        result = {
            "verdict": "Verify First",
            "explanation": "Unrecognized input type.",
            "raw_signals": {},
        }

    log_check(
        input_type=input_type,
        verdict=result["verdict"],
        explanation=result["explanation"],
        raw_signals=result.get("raw_signals", {}),
    )

    return result


def main():
    telegram_bot.process_check = process_check
    app = telegram_bot.build_app()
    print("ScamShield AI is live. Forward a suspicious message or QR photo to test it.")
    app.run_polling()


if __name__ == "__main__":
    main()
