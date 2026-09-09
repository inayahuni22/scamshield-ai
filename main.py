
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

        # Fallback uses a real Nokia simulator test number rather than
        # an all-zero placeholder, which isn't valid and would just
        # 404 against the real sandbox — see the QR branch below for
        # the same fix and full reasoning.
        phone_number = _extract_phone(content) or "+99999991001"

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
            # Real merchant/payment QR payloads sometimes embed a phone
            # number (e.g. UPI-style "pa=" fields, contact QR codes).
            # Try to extract one first; only fall back to a placeholder
            # if the QR genuinely doesn't contain one.
            #
            # The fallback uses a real Nokia simulator test number
            # (+99999991001, documented as the "safe" outcome number)
            # rather than +000000000000 — an all-zero number isn't a
            # valid simulator identifier and would just 404 against the
            # real sandbox, making Location Verification silently
            # meaningless for every demo QR that lacks an embedded number.
            phone_number = _extract_phone(raw_qr_data) or "+99999991001"

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
