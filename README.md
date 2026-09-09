# 🛡️ ScamShield AI

### AI-Powered Consumer Fraud Defense Agent

**ScamShield AI** is an AI-powered fraud detection assistant that helps users identify suspicious messages, phishing attempts, and malicious QR codes before they interact with them.

Built by **Team ZeroDay** for the hackathon.

---

## 🚨 Problem

Online scams are becoming increasingly sophisticated. Attackers use social engineering techniques such as:

* Urgency and time pressure
* Impersonation of trusted organizations
* Fake rewards and prizes
* Account verification requests
* Credential and OTP harvesting
* Payment requests
* Malicious or deceptive QR codes
* Suspicious links and shortened URLs

Traditional security tools often focus on known malicious URLs or malware signatures. ScamShield AI instead combines **social engineering analysis, QR analysis, network intelligence, and AI reasoning** to provide a user-friendly risk assessment.

---

## 💡 Our Solution

ScamShield AI acts as a **consumer fraud-defense AI agent**.

Users can forward:

* 💬 Suspicious text messages
* 🔗 Suspicious URLs
* 📱 QR-code images

The system analyzes the input and returns one of three simple verdicts:

| Verdict               | Meaning                                                                   |
| --------------------- | ------------------------------------------------------------------------- |
| ✅ **Safe**            | No significant risk indicators were detected                              |
| ⚠️ **Verify First**   | Some suspicious indicators were detected; verify independently            |
| 🚫 **Do Not Proceed** | Strong indicators of fraud, phishing, or malicious activity were detected |

The goal is to turn complex security signals into a decision that an everyday user can understand.

---

## 🧠 How It Works

```text
                    ┌──────────────────┐
                    │   Telegram User  │
                    └────────┬─────────┘
                             │
                    Text / URL / QR Image
                             │
                             ▼
                    ┌──────────────────┐
                    │   Input Handler  │
                    └────────┬─────────┘
                             │
                 ┌───────────┴───────────┐
                 │                       │
                 ▼                       ▼
          Text / URL Analysis        QR Decoder
                 │                       │
                 └───────────┬───────────┘
                             │
                             ▼
                  ┌────────────────────┐
                  │ Social Engineering │
                  │     Analysis       │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │   QR / URL Baseline│
                  │   Risk Analysis    │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ CAMARA / Nokia     │
                  │ Network Signals    │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │     AI Reasoning   │
                  │  & Risk Assessment │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │ ScamShield Verdict │
                  └─────────┬──────────┘
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
          Telegram Response       Supabase Log
```

---

## 🔍 Key Features

### 1. Social Engineering Detection

ScamShield analyzes messages for common manipulation techniques, including:

* Urgency
* Authority pressure
* Fear and threats
* Rewards and incentives
* Impersonation
* Credential harvesting
* Payment requests
* Account verification requests

Example:

> "Your account will be suspended within 24 hours. Verify your account immediately."

The system can identify the urgency, authority, fear, and credential-harvesting indicators in the message.

---

### 2. QR Code Analysis

Users can send a QR-code image to ScamShield AI.

The QR module:

1. Decodes the QR code
2. Extracts the embedded data or URL
3. Analyzes the destination
4. Checks suspicious characteristics
5. Assigns risk indicators
6. Produces a final verdict

The system also handles cases where a QR code cannot be decoded successfully.

---

### 3. URL & QR Baseline Detection

ScamShield uses a rule-based security baseline to identify suspicious URL characteristics.

Indicators include:

* Unknown domains
* HTTP instead of HTTPS
* URL shorteners
* IP-address-based URLs
* Excessively long URLs
* Multiple subdomains
* Suspicious URL patterns
* Credential-related keywords
* Payment-related keywords
* Reward/prize-related keywords

Risk indicators are combined into a weighted score to help determine the final verdict.

> **Note:** Reserved domains such as `example.com` are used for testing and demonstration purposes. A trusted-domain match is not intended to represent a real-world guarantee of safety.

---

### 4. CAMARA / Nokia Network Intelligence

ScamShield AI integrates with network intelligence APIs based on the **CAMARA / Nokia Network-as-Code ecosystem**.

The system can work with signals such as:

* SIM swap status
* Number verification
* Device status
* Location verification

These signals can provide additional context when assessing suspicious activity.

For development and testing, ScamShield supports a mock CAMARA mode.

---

### 5. AI-Powered Explanation

Instead of simply returning a risk score, ScamShield generates a human-readable explanation of **why** an input was classified as suspicious.

This makes the system more useful for everyday consumers who may not understand cybersecurity terminology.

---

### 6. Supabase Logging

Security checks are logged to a Supabase PostgreSQL database.

Each check can contain:

* Input type
* Verdict
* Explanation
* Raw security signals
* Timestamp

This provides a foundation for future analytics, monitoring, and fraud-pattern analysis.

---

## 🏗️ Technology Stack

| Component            | Technology                     |
| -------------------- | ------------------------------ |
| Interface            | Telegram Bot                   |
| Programming Language | Python                         |
| AI / Agent Framework | CrewAI                         |
| LLM                  | Groq                           |
| Network Intelligence | Nokia Network-as-Code / CAMARA |
|Image & QR Processing | OpenCV + Pyzbar                |
| Database             | Supabase PostgreSQL            |
| Environment          | Python Virtual Environment     |
| Version Control      | Git / GitHub                   |

---

## 📁 Project Structure

```text
scamshield-ai/
│
├── agents/
│   ├── agents.py
│   └── __init__.py
│
├── bot/
│   ├── telegram_bot.py
│   └── __init__.py
│
├── camara/
│   ├── camara_apis.py
│   ├── mock_camara.py
│   └── __init__.py
│
├── logging_module/
│   ├── schema.sql
│   ├── supabase_logger.py
│   └── __init__.py
│
├── qr/
│   ├── qr_baseline.py
│   ├── qr_decoder.py
│   ├── test_qr.png
│   ├── no_qr.png
│   └── __init__.py
│
├── main.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/inayahuni22/scamshield-ai.git
cd scamshield-ai
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file based on `.env.example`.

Add the required credentials for:

* Telegram Bot API
* Groq
* Supabase
* Nokia Network-as-Code / CAMARA

**Never commit `.env` or API keys to GitHub.**

---

## 🧪 Development Mode

ScamShield supports mock CAMARA responses for development.

Set:

```env
USE_MOCK_CAMARA=true
```

This allows the application to be tested without depending on live network API responses.

---

## ▶️ Running ScamShield AI

Start the complete application with:

```bash
python main.py
```

The Telegram bot will begin polling for incoming messages and QR images.

Users can then send suspicious content directly to the Telegram bot.

---

## 🧪 Example Tests

### Safe Input

```text
Check this website: https://example.com
```

Expected:

```text
✅ Safe
```

### Suspicious Input

```text
Your Microsoft account needs verification at microsoft-login.example.com
```

Expected:

```text
⚠️ Verify First
```

### High-Risk Input

```text
Congratulations! You won a $500 reward.
Confirm your account and enter your password and OTP
immediately to claim your prize.
```

Expected:

```text
🚫 Do Not Proceed
```

---

## 🔐 Security & Privacy

ScamShield AI is designed as a defensive cybersecurity tool.

Important security practices:

* API credentials are stored in environment variables.
* `.env` is excluded from version control.
* No API secrets should be included in the source repository.
* Mock APIs are available for development.
* The system provides risk guidance rather than guaranteeing that a website or message is safe.

Users should still independently verify important requests, particularly those involving payments, passwords, OTPs, or account recovery.

---

## 🚀 Future Improvements

Potential future development includes:

* 🔎 Following QR-code URL redirects before analysis
* 🌐 Real-time malicious URL reputation checking
* 🤖 Improved machine-learning-based scam classification
* 📊 Fraud analytics dashboard
* 🧠 Personalized risk explanations
* 🔐 Additional CAMARA network signals
* 📈 Historical risk and scam-pattern analysis
* 🌍 Multi-language scam detection
* 📱 Support for additional messaging platforms

---

## 👥 Team ZeroDay

**Team ZeroDay**

* Inayah Imran
* Warisha Faisal
* Debjani Bagchi
* Giselle Telles
* Valliammai Palaniappan

---

## 🎯 Hackathon Project

**ScamShield AI** was developed as a cybersecurity-focused AI solution designed to help consumers make safer decisions when interacting with suspicious digital content.

### Core Idea

> **Don't let urgency make the decision for you. Let ScamShield analyze it first.**

---

## 📄 License

This project is intended for educational, research, and hackathon purposes.
