# ScamShield AI

AI agent behind a Telegram bot that checks forwarded scam messages, SMS, and
QR codes against CAMARA telecom signals (Nokia Network-as-Code) and returns
a plain-language verdict: **Safe / Verify First / Do Not Proceed**.

## JSON contracts (source of truth — don't deviate without updating this doc)

**Verifier Agent output -> Explainer Agent input:**
```json
{
  "input_type": "text",
  "checks_run": ["sim_swap", "number_verification", "device_status"],
  "results": {
    "sim_swap": {"swapped": false, "swap_date": null},
    "number_verification": {"verified": true},
    "device_status": {"active": true}
  }
}
```

**Explainer Agent output -> sent to user + logged:**
```json
{
  "verdict": "Safe",
  "explanation": "This number checks out — no recent SIM swap and it's verified.",
  "raw_signals": { "...same shape as above..." }
}
```

## Setup

```bash
git clone <repo-url>
cd scamshield-ai
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then fill in your keys
```

Fill in `.env`:
- `TELEGRAM_BOT_TOKEN` — from @BotFather
- `GROQ_API_KEY` — https://console.groq.com/keys
- `NOKIA_CLIENT_ID` / `NOKIA_CLIENT_SECRET` — Nokia NaC sandbox
- `SUPABASE_URL` / `SUPABASE_KEY` — Supabase project settings
- `USE_MOCK_CAMARA=true` while developing; set to `false` for the real sandbox

Run `logging_module/schema.sql` in the Supabase SQL editor once, to create the `checks` table.

## Run each piece standalone (while developing)

```bash
python bot/telegram_bot.py          # bot in stub mode, replies "[stub] received..."
python qr/qr_decoder.py             # needs a local test_qr.png
python camara/mock_camara.py        # prints fake signal results
python agents/agents.py             # runs Verifier + Explainer against mocks
python logging_module/supabase_logger.py   # writes one test row to Supabase
```

## Run the full integrated app

```bash
python main.py
```

Then message your bot on Telegram with a suspicious text or a photo of a QR code.

## Folder ownership (5-way split)

| Folder | Owner |
|---|---|
| `bot/` | Person A |
| `qr/` | Person B |
| `camara/` | Person C |
| `agents/` | Person D |
| `logging_module/` | Person E |

Everyone builds against the JSON contracts above and against
`camara/mock_camara.py`. `main.py` is the integration point, built once
individual pieces work standalone. Switch `USE_MOCK_CAMARA=false` in `.env`
once `camara/camara_apis.py` is confirmed working against the real sandbox.

## Known things to verify before the demo

- Nokia NaC's exact endpoint paths/auth flow in `camara/camara_apis.py` are
  written from the standard CAMARA pattern — confirm against the live sandbox
  docs and adjust before relying on it.
- QR decoding assumes a phone-number-bearing payload isn't always present;
  `main.py` uses a placeholder number for the location check in that case —
  fine for a demo with pre-generated test QR codes, not for production.
