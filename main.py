
"""
Integration entry point:

Telegram
    -> text / QR
    -> social-engineering analysis
    -> CAMARA verification
    -> CrewAI Explainer
    -> Telegram reply
    -> Supabase logging

Run this file (not bot/telegram_bot.py directly) to run the full pipeline.
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

    return (
        match.group(1).replace(" ", "").replace("-", "")
        if match
        else None
    )


async def process_check(input_type: str, content: str) -> dict:
    """
    input_type:
        "text" -> raw Telegram message text
        "qr"   -> local image path

    content:
        Raw message text for text input,
        or local image path for QR input.
    """

    # ============================================================
    # TEXT INPUT
    # ============================================================

    if input_type == "text":

        phone_number = _extract_phone(content) or "+000000000000"

        result = process(
            input_type="text",
            phone_number=phone_number,
            message_text=content,
        )

    # ============================================================
    # QR INPUT
    # ============================================================

    elif input_type == "qr":

        qr_data = decode_qr(content)

        if not qr_data.get("found"):

            result = {
                "verdict": "Verify First",
                "explanation": (
                    "Couldn't read that QR code clearly — try a clearer "
                    "photo, or don't scan it if you're unsure."
                ),
                "raw_signals": {},
            }

        else:

            # ----------------------------------------------------
            # IMPORTANT:
            # Keep the actual decoded QR content.
            # ----------------------------------------------------

            raw_qr_data = qr_data.get("raw_data", "")

            claimed_location = qr_data.get(
                "claimed_sender",
                "Unknown"
            )

            # Demo note:
            # A real merchant phone/device identifier would come
            # from the decoded QR payment payload. Sandbox/demo
            # QR codes may not contain a real number.
            phone_number = "+000000000000"

            result = process(
                input_type="qr",
                phone_number=phone_number,
                claimed_location=claimed_location,

                # Pass the actual QR content to the analyzer.
                message_text=raw_qr_data,
            )

    # ============================================================
    # UNKNOWN INPUT
    # ============================================================

    else:

        result = {
            "verdict": "Verify First",
            "explanation": "Unrecognized input type.",
            "raw_signals": {},
        }

    # ============================================================
    # SUPABASE LOGGING
    # ============================================================

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

    print(
        "ScamShield AI is live. "
        "Forward a suspicious message or QR photo to test it."
    )

    app.run_polling()


if __name__ == "__main__":
    main()
