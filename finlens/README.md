# FinLens — AI-Powered Financial Safety Net 🛡️

> **Track 04: AI for Finance** | ForgeAI Hackathon @ graVITas'26, VIT Vellore
> Observed by **PRISM by Block Convey**

---

## What is FinLens?

FinLens is an AI-powered platform that protects Indians from the ₹10,000 crore financial scam epidemic while building long-term financial literacy. It combines three tools in one:

| Feature | What it does |
|---------|-------------|
| 🔍 **Scam Analyzer** | Paste any suspicious message (WhatsApp, SMS, email) → instant risk assessment with red flags, scam type identification, and actionable advice |
| 📊 **Financial Health Check** | Describe your income and expenses → get a health grade, spending breakdown, budget recommendations, and tax-saving tips |
| 🧠 **Learn Finance** | Ask anything about SIPs, mutual funds, credit scores, taxes → get clear, India-specific answers with key takeaways |

## The PRISM Story

Every AI interaction is traced to **PRISM by Block Convey** for observability:

1. **Observe** → PRISM captures all scam analyses, health checks, and Q&A interactions
2. **Identify** → PRISM's Agent Intelligence clusters failures and finds patterns (e.g., "AI misclassifies 38% of sophisticated investment scams")
3. **Improve** → We tune prompts and add knowledge base entries for weak categories
4. **Prove** → Before/after evidence: "Investment scam detection improved from 62% → 93% accuracy"

This is the **Build → Observe → Improve → Prove** cycle that ForgeAI demands.

---

## Quick Start

On Windows, zip this folder, send it, and **double-click `FinLens.bat`**.

The launcher installs Python packages on first run, starts the live Gemini app, and opens your browser. The other computer needs **Python 3.11+** with **Add python.exe to PATH** checked, plus internet on the first launch.

If `backend/.env` has no Gemini key, the launcher will ask for one.

### Manual start (optional)

```bash
cd finlens/backend
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

You need:
- **Google Gemini API key** (required): create one at [Google AI Studio](https://aistudio.google.com/apikey) and set `GOOGLE_API_KEY` in `backend/.env`
- **PRISM credentials** (optional locally): [prism.blockconvey.com](https://prism.blockconvey.com/signup)

Paste the key like this:

```
GOOGLE_API_KEY=AIza...your-key
FINLENS_MODEL=gemini-3.6-flash
```

### 3. Run the Server

```bash
cd finlens/backend
python main.py
```

The app starts at **http://localhost:8000**

### 4. Open FinLens

Navigate to `http://localhost:8000` in your browser. You'll see the FinLens UI.

---

## Architecture

```
finlens/
├── backend/
│   ├── main.py              # FastAPI app (API + serves frontend)
│   ├── llm.py               # Google Gemini client (live calls only)
│   ├── prism_config.py      # PRISM observability (traces every interaction)
│   ├── guardrails.py        # Safety filters for financial advice
│   ├── agents/
│   │   ├── scam_analyzer.py # AI scam detection with Indian fraud patterns
│   │   ├── finance_health.py# Financial health assessment
│   │   └── literacy_chat.py # Financial literacy Q&A
│   ├── knowledge/
│   │   └── scam_patterns.json # Indian scam pattern database (8 categories)
│   └── requirements.txt
├── frontend/
│   └── index.html           # Single-page app (dark cybersecurity theme)
├── .env.example             # Environment template
└── README.md
```

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, httpx
- **AI Model**: Google Gemini (`gemini-3.6-flash` by default, override with `FINLENS_MODEL`)
- **Observability**: PRISM by Block Convey (Python SDK + HTTP API)
- **Frontend**: Vanilla HTML/CSS/JS (no framework needed)
- **Design**: Dark cybersecurity theme, animated risk meters, glassmorphism

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analyze-scam` | POST | Analyze suspicious message for scams |
| `/api/finance-health` | POST | Get financial health assessment |
| `/api/financial-qa` | POST | Ask financial literacy questions |
| `/api/prism-status` | GET | Check PRISM connection status |
| `/api/health` | GET | Health check |

## PRISM Integration

Every API call automatically sends a trace to PRISM with:
- Input messages and AI output
- Model name and latency
- Session ID (conversation continuity)
- Agent ID (scam-analyzer, finance-health, literacy-chat)
- Metadata (risk scores, health grades, guardrail violations)

View your traces at: `https://prism.blockconvey.com` → Your Project → Traces

---

## Hackathon Presentation (5 minutes)

1. **Problem** (30s): ₹10,000 crore scam epidemic, no real-time protection tool
2. **Demo** (2 min): Live scam analysis → paste a real scam message → watch it detect and explain
3. **PRISM Story** (1.5 min): Show PRISM dashboard → identify a failure → show before/after improvement
4. **Impact** (1 min): Scalable, addresses financial literacy gap

---

*Built with ❤️ for ForgeAI Hackathon @ graVITas'26*
