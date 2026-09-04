"""
Supabase logging — writes every check + verdict as an audit row.
Fully standalone: test with fake dicts matching the contract, no dependency
on any other module.

Expected Supabase table `checks` columns:
  id            uuid, default gen_random_uuid(), primary key
  created_at    timestamptz, default now()
  input_type    text
  verdict       text
  explanation   text
  raw_signals   jsonb
"""

import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

_client: Client | None = None


def _get_client() -> Client:
    global _client
    if _client is None:
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _client


def log_check(input_type: str, verdict: str, explanation: str, raw_signals: dict) -> bool:
    """Returns True on success, False on failure (never raises — logging
    should never crash the bot's main flow)."""
    try:
        client = _get_client()
        client.table("checks").insert({
            "input_type": input_type,
            "verdict": verdict,
            "explanation": explanation,
            "raw_signals": raw_signals,
        }).execute()
        return True
    except Exception as e:
        print(f"[supabase_logger] failed to log check: {e}")
        return False


if __name__ == "__main__":
    # Standalone test with a fake record
    ok = log_check(
        input_type="text",
        verdict="Verify First",
        explanation="Test log entry.",
        raw_signals={"sim_swap": {"swapped": True}},
    )
    print("Logged successfully" if ok else "Logging failed")
