"""
Telegram bot — entry point. Routes text vs photo input, replies with the
verdict from the agent pipeline. Import target for main.py.
"""

import os
import tempfile
import logging
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# process_check is injected by main.py so this file has no direct dependency
# on agents/camara — keeps it testable standalone with a stub function.
process_check = None


async def handle_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 I'm ScamShield AI.\n\n"
        "Forward me a suspicious text/SMS, or send a photo of a QR code "
        "(e.g. a payment QR), and I'll check it against telecom signals "
        "and give you a verdict: ✅ Safe / ⚠️ Verify First / 🚫 Do Not Proceed."
    )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    await update.message.reply_text("Checking that message, one moment...")

    if process_check is None:
        await update.message.reply_text(f"[stub] received text: {text}")
        return

    result = await process_check(input_type="text", content=text)
    await update.message.reply_text(_format_reply(result))


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Checking that QR code, one moment...")

    local_path = os.path.join(tempfile.gettempdir(), f"{update.message.message_id}.jpg")
    try:
        photo_file = await update.message.photo[-1].get_file()
        await photo_file.download_to_drive(local_path)
    except Exception:
        logger.exception("Failed to download photo for message %s", update.message.message_id)
        await update.message.reply_text(
            "⚠️ I couldn't download that photo — try sending it again."
        )
        return

    if process_check is None:
        await update.message.reply_text(f"[stub] received photo, saved to {local_path}")
        return

    result = await process_check(input_type="qr", content=local_path)
    await update.message.reply_text(_format_reply(result))


def _format_reply(result: dict) -> str:
    verdict = result.get("verdict", "Unknown")
    explanation = result.get("explanation", "No explanation available.")
    emoji = {"Safe": "✅", "Verify First": "⚠️", "Do Not Proceed": "🚫"}.get(verdict, "❓")
    return f"{emoji} Verdict: {verdict}\n\n{explanation}"


async def handle_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Unhandled exception while processing update: %s", update, exc_info=context.error)
    if isinstance(update, Update) and update.message:
        await update.message.reply_text(
            "⚠️ Something went wrong on my end handling that — please try again."
        )


def build_app():
    if not BOT_TOKEN:
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN is not set. Copy .env.example to .env and add your "
            "bot token from @BotFather."
        )
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", handle_start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.add_error_handler(handle_error)
    return app


if __name__ == "__main__":
    # Standalone test run — replies "[stub] received ..." since process_check
    # isn't wired in yet. Confirms the bot itself works before integration.
    application = build_app()
    print("ScamShield AI bot running (stub mode)...")
    application.run_polling()
