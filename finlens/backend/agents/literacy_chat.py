"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Financial Literacy Chat Agent
═══════════════════════════════════════════════════════════════════════════════

India's friendliest financial literacy assistant covering:
- Personal finance fundamentals (budgeting, saving, emergency funds)
- Investing basics (SIP, mutual funds, stocks, bonds, gold)
- Tax planning (old vs new regime, 80C, 80D, GST, capital gains)
- Insurance (health, life, motor, term vs endowment)
- Loans and credit (EMI, credit score, home loan, personal loan)
- UPI and digital payments safety
- Retirement planning (PPF, NPS, EPF, SCSS)
- Estate planning basics (will, nominees, succession)
- Government schemes (PM Kisan, PMJJBY, PMSBY, Atal Pension)
- Stock market fundamentals (Nifty, Sensex, PE ratio, dividends)

Features:
- Topic classification for analytics
- Difficulty-level adaptation (beginner/intermediate/advanced)
- India-specific examples and calculations
- Q&A history for conversation continuity
- Related question suggestions
- Quiz generation from any topic
"""

import re
import json
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger("finlens.literacy_chat")


# ═══════════════════════════════════════════════════════════════════════════════
# Topic Classification
# ═══════════════════════════════════════════════════════════════════════════════

TOPIC_KEYWORDS = {
    "investing": {
        "keywords": [
            "invest", "sip", "mutual fund", "stock", "nifty", "sensex",
            "etf", "index fund", "dividend", "portfolio", "asset",
            "equity", "debt", "gold", "real estate", "reit",
        ],
        "subtopics": ["sip", "mutual_funds", "stocks", "etf", "bonds", "gold", "reits"],
        "display_name": "Investing & Wealth Building",
        "icon": "📈",
    },
    "budgeting": {
        "keywords": [
            "budget", "save", "savings", "spend", "expense", "income",
            "50/30/20", "track", "money management", "cash flow",
        ],
        "subtopics": ["50_30_20", "expense_tracking", "saving_strategies", "income_management"],
        "display_name": "Budgeting & Saving",
        "icon": "💰",
    },
    "taxes": {
        "keywords": [
            "tax", "gst", "income tax", "80c", "80d", "deduction",
            "itr", "form 16", "tds", "capital gains", "stcg", "ltcg",
            "old regime", "new regime", "pan", "tax slab",
        ],
        "subtopics": ["income_tax", "gst", "tax_planning", "tax_filing", "deductions"],
        "display_name": "Tax Planning",
        "icon": "🧾",
    },
    "insurance": {
        "keywords": [
            "insurance", "health insurance", "life insurance", "term plan",
            "motor insurance", "claim", "premium", "coverage", "policy",
            "endowment", "ulip", "uld",
        ],
        "subtopics": ["health", "life", "motor", "term_vs_endowment", "claim_process"],
        "display_name": "Insurance",
        "icon": "🛡️",
    },
    "loans_credit": {
        "keywords": [
            "loan", "emi", "credit", "credit score", "credit card",
            "home loan", "personal loan", "car loan", "education loan",
            "interest rate", "prepayment", "balance transfer", "cibil",
        ],
        "subtopics": ["emi_calculation", "credit_score", "loan_types", "credit_cards"],
        "display_name": "Loans & Credit",
        "icon": "🏦",
    },
    "upi_payments": {
        "keywords": [
            "upi", "gpay", "phonepe", "paytm", "qr code", "upi pin",
            "digital payment", "net banking", "neft", "imps", "rtgs",
        ],
        "subtopics": ["upi_safety", "digital_payments", "scam_prevention"],
        "display_name": "UPI & Digital Payments",
        "icon": "📱",
    },
    "retirement": {
        "keywords": [
            "retire", "retirement", "ppf", "nps", "epf", "pension",
            "annuity", "scss", "old age", "financial freedom", "fire",
        ],
        "subtopics": ["ppf", "nps", "epf", "retirement_planning", "fire"],
        "display_name": "Retirement Planning",
        "icon": "🏖️",
    },
    "estate_planning": {
        "keywords": [
            "will", "nominee", "succession", "estate", "inheritance",
            "legal heir", "trust", "property transfer", "probate",
        ],
        "subtopics": ["will_basics", "nominee_basics", "succession_planning"],
        "display_name": "Estate Planning",
        "icon": "📜",
    },
    "government_schemes": {
        "keywords": [
            "pm kisan", "pmjjby", "pmsby", "atal pension", "pm vaya",
            "sukanya", "pm awas", "mudra", "stand up india",
        ],
        "subtopics": ["pm_kisan", "pmjjby", "pmsby", "atal_pension"],
        "display_name": "Government Schemes",
        "icon": "🏛️",
    },
    "stock_market": {
        "keywords": [
            "stock market", "share market", "ipo", "demat", "broker",
            "trading", "intraday", "fno", "option", "futures",
            "pe ratio", "market cap", "fundamental", "technical",
        ],
        "subtopics": ["getting_started", "analysis_basics", "ipo", "trading"],
        "display_name": "Stock Market",
        "icon": "📊",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Topic Classifier
# ═══════════════════════════════════════════════════════════════════════════════

class TopicClassifier:
    """Classifies financial questions into topics using keyword matching."""

    def classify(self, question: str) -> Tuple[str, float, List[str]]:
        """
        Classify a question into a topic.

        Returns:
            (topic_id, confidence, matched_keywords)
        """
        question_lower = question.lower().strip()
        scores = {}

        for topic_id, topic_data in TOPIC_KEYWORDS.items():
            score = 0
            matched = []
            for keyword in topic_data["keywords"]:
                if keyword in question_lower:
                    score += len(keyword)  # Longer matches = higher confidence
                    matched.append(keyword)
            if score > 0:
                scores[topic_id] = (score, matched)

        if not scores:
            return "general", 0.3, []

        best_topic = max(scores.keys(), key=lambda k: scores[k][0])
        max_score = scores[best_topic][0]
        total_score = sum(v[0] for v in scores.values())
        confidence = min(0.95, max_score / total_score) if total_score > 0 else 0.3

        return best_topic, confidence, scores[best_topic][1]


# ═══════════════════════════════════════════════════════════════════════════════
# Knowledge Base
# ═══════════════════════════════════════════════════════════════════════════════

FINANCIAL_KNOWLEDGE_BASE = {
    "sip": {
        "key_facts": [
            "SIP (Systematic Investment Plan) lets you invest a fixed amount monthly in mutual funds",
            "Minimum SIP amount: ₹100-500 depending on the fund",
            "Best time to start: Today! Time in market beats timing the market",
            "Average equity mutual fund returns: 12-15% over 5+ years",
            "Step-up SIP: Increase SIP by 10% every year for dramatically higher returns",
        ],
        "common_mistakes": [
            "Stopping SIP during market dips — that's when you get more units cheaper",
            "Checking returns daily — SIPs are meant for long-term (5+ years)",
            "Choosing funds based on 1-year returns — look at 5+ year track record",
            "Not increasing SIP with salary hikes — step up every year",
        ],
        "practical_example": (
            "A ₹5,000/month SIP in a Nifty 50 index fund started at age 25 "
            "can grow to ₹1.03 Crore by age 40 (assuming 12% average returns). "
            "Starting at 30 instead would yield only ₹53 Lakhs — "
            "that 5-year delay costs you ₹50 Lakhs!"
        ),
    },
    "credit_score": {
        "key_facts": [
            "CIBIL score ranges from 300 to 900",
            "Score above 750 is considered good — most banks prefer this",
            "You can check your free credit report once a year at CIBIL.com",
            "Factors: Payment history (35%), Credit utilization (30%), Credit age (15%), Credit mix (10%), Inquiries (10%)",
            "Missing even one EMI or credit card payment can drop your score by 50-100 points",
        ],
        "common_mistakes": [
            "Maxing out credit cards — keep utilization below 30%",
            "Applying for too many loans at once — each application lowers your score",
            "Not checking credit report for errors",
            "Closing old credit cards — this reduces your credit age",
        ],
        "practical_example": (
            "Rahul (age 28) had a 720 CIBIL score. He applied for 4 credit cards in "
            "one month and his score dropped to 680. After 6 months of paying all bills "
            "on time, it recovered to 735. Lesson: Don't apply for credit you don't need."
        ),
    },
    "ppf": {
        "key_facts": [
            "Public Provident Fund: 15-year lock-in, currently 7.1% interest",
            "Investment limit: ₹500 to ₹1,50,000 per year",
            "Triple tax exempt (EEE): No tax on deposit, interest, or maturity",
            "Partial withdrawal allowed after 7 years",
            "Loan against PPF available between Year 3-6",
            "Can be opened at any bank or post office",
        ],
        "common_mistakes": [
            "Not investing the full ₹1.5L limit — you lose tax-free compounding",
            "Withdrawing too early — let it compound for the full 15 years",
            "Not adding a nominee — PPF has no automatic succession",
        ],
        "practical_example": (
            "If you invest ₹12,500/month (₹1.5L/year) in PPF for 15 years at 7.1%, "
            "your maturity value will be ₹40.7 Lakhs. Total invested: ₹22.5L. "
            "Interest earned: ₹18.2L — ALL TAX FREE."
        ),
    },
    "health_insurance": {
        "key_facts": [
            "A basic surgery in India costs ₹2-5L, heart surgery ₹5-15L",
            "Average hospitalization cost is rising 15-20% annually",
            "Minimum recommended cover: ₹5L individual, ₹10L family",
            "Buy before age 35 for significantly lower premiums",
            "Always take a super top-up after your base policy",
        ],
        "common_mistakes": [
            "Relying only on employer health insurance — it ends when you leave the job",
            "Not reading policy exclusions — many policies don't cover pre-existing conditions for 2-4 years",
            "Choosing cheapest policy over comprehensive coverage",
            "Not declaring pre-existing conditions — leads to claim rejection",
        ],
        "practical_example": (
            "Priya (age 30) pays ₹8,000/year for ₹10L health cover. "
            "After a scooter accident requiring ₹4L surgery, her insurance covered everything. "
            "Without insurance, this would have wiped out 6 months of savings."
        ),
    },
    "nps": {
        "key_facts": [
            "National Pension System: Government-backed retirement savings scheme",
            "Additional ₹50,000 tax deduction under Section 80CCD(1B)",
            "Returns: 8-14% depending on fund manager and allocation",
            "60% of corpus is tax-free at maturity (40% must be used for annuity)",
            "Can start with as little as ₹1,000/year",
        ],
        "common_mistakes": [
            "Not choosing the right asset allocation — young investors should go equity-heavy",
            "Not maxing out the ₹50K additional deduction",
            "Waiting until 50 to start — every year of delay reduces retirement corpus significantly",
        ],
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Response Enhancement
# ═══════════════════════════════════════════════════════════════════════════════

class ResponseEnhancer:
    """Enhances LLM responses with structured data and educational content."""

    def enhance(
        self,
        question: str,
        llm_response: str,
        topic: str,
        confidence: float,
    ) -> Dict[str, Any]:
        """
        Enhance an LLM response with topic data, key takeaways,
        related questions, and disclaimers.
        """
        topic_data = TOPIC_KEYWORDS.get(topic, {})
        knowledge = FINANCIAL_KNOWLEDGE_BASE.get(topic, {})

        # Extract key takeaways from knowledge base
        key_takeaways = knowledge.get("key_facts", [])[:3]

        # Generate related questions
        related = self._generate_related_questions(topic, topic_data)

        # Generate India-specific tips
        india_tips = self._get_india_specific_tips(topic)

        # Format response
        enhanced = {
            "response": llm_response,
            "topic": topic,
            "topic_display": topic_data.get("display_name", "General Finance"),
            "topic_icon": topic_data.get("icon", "💰"),
            "confidence": round(confidence, 2),
            "subtopics": topic_data.get("subtopics", []),
            "key_takeaways": key_takeaways,
            "related_questions": related,
            "india_specific_tips": india_tips,
            "sources": self._get_sources(topic),
            "disclaimer": (
                "This is AI-generated educational information for general awareness only. "
                "It is not personalized financial advice. Please consult a SEBI-registered "
                "investment advisor or certified financial planner before making financial decisions."
            ),
        }

        # Add practical example if available
        if knowledge.get("practical_example"):
            enhanced["practical_example"] = knowledge["practical_example"]

        # Add common mistakes if available
        if knowledge.get("common_mistakes"):
            enhanced["common_mistakes_to_avoid"] = knowledge["common_mistakes"][:3]

        return enhanced

    def _generate_related_questions(self, topic: str, topic_data: dict) -> List[str]:
        """Generate related questions the user might want to ask."""
        question_bank = {
            "investing": [
                "How do I start SIP with just ₹500?",
                "Which is better: Nifty 50 or Flexi Cap fund?",
                "What is the difference between ELSS and regular mutual fund?",
                "How do I read a mutual fund fact sheet?",
            ],
            "taxes": [
                "Old regime vs new regime — which saves more tax for me?",
                "How do I save ₹1.5L under Section 80C?",
                "What is LTCG tax on mutual funds?",
                "Do I need to file ITR if my income is below ₹7L?",
            ],
            "budgeting": [
                "How do I create a monthly budget?",
                "What is the 50/30/20 rule?",
                "How much should I save from my first salary?",
                "Best apps to track expenses in India?",
            ],
            "insurance": [
                "Term insurance vs endowment — which is better?",
                "How much health insurance do I need?",
                "Does my employer health insurance cover my family?",
                "How to claim health insurance?",
            ],
            "upi_payments": [
                "How do I stay safe from UPI scams?",
                "What to do if I shared my UPI PIN?",
                "Can someone hack my bank account through UPI?",
                "Which UPI app is safest?",
            ],
            "retirement": [
                "How much do I need to retire in India?",
                "PPF vs NPS — which is better?",
                "What is FIRE movement?",
                "When should I start planning for retirement?",
            ],
        }
        return question_bank.get(topic, [
            "Tell me more about " + (topic_data.get("display_name", "this topic")),
            "What are the best practices?",
            "What mistakes should I avoid?",
        ])

    def _get_india_specific_tips(self, topic: str) -> List[str]:
        """Get India-specific tips for the topic."""
        tips = {
            "investing": [
                "Start with Index Funds — lowest cost, no fund manager risk",
                "ELSS gives tax savings + equity returns — best of both worlds",
                "Sovereign Gold Bonds (SGB) pay 2.5% interest over gold price returns",
            ],
            "taxes": [
                "New regime is default from FY 2023-24 — opt for old only if deductions > ₹2L",
                "Section 80C limit of ₹1.5L can be split across PPF, EPF, ELSS, insurance",
                "Health insurance premium up to ₹25K (self) + ₹25K (parents) under 80D",
            ],
            "budgeting": [
                "In India, housing should ideally be <30% of take-home salary",
                "Cook at home 5 days/week to save ₹5,000-8,000/month vs food delivery",
                "Use CRED or similar apps to pay credit card bills on time",
            ],
            "upi_payments": [
                "NEVER share your UPI PIN with anyone — no bank or company will ask for it",
                "Set UPI transaction limit to ₹5,000 for daily use",
                "Use UPI Lite for small transactions (<₹500) without entering PIN each time",
            ],
        }
        return tips.get(topic, [
            "India has one of the highest savings rates in the world — use this cultural advantage",
            "Start investing early — even ₹500/month matters more than you think",
        ])

    def _get_sources(self, topic: str) -> List[str]:
        """Get authoritative sources for the topic."""
        common = [
            "SEBI (Securities and Exchange Board of India)",
            "AMFI (Association of Mutual Funds in India)",
            "IRDAI (Insurance Regulatory and Development Authority)",
        ]
        topic_sources = {
            "taxes": ["Income Tax Department (incometax.gov.in)", "CBDT Notifications"],
            "government_schemes": ["PMIndia.gov.in", "NSDL", "CDSL"],
            "upi_payments": ["NPCI (National Payments Corporation of India)"],
            "retirement": ["PFRDA (Pension Fund Regulatory Authority)", "EPFO"],
        }
        return common + topic_sources.get(topic, [])


# ═══════════════════════════════════════════════════════════════════════════════
# Quiz Generator
# ═══════════════════════════════════════════════════════════════════════════════

class QuizGenerator:
    """Generates financial literacy quizzes from topics."""

    QUIZ_QUESTIONS = {
        "investing": [
            {
                "question": "What is the minimum SIP amount for most mutual funds in India?",
                "options": ["₹10,000", "₹1,000", "₹500", "₹50"],
                "correct": "₹500",
                "explanation": "Many mutual funds allow SIP starting from just ₹100-500. This makes investing accessible to everyone.",
            },
            {
                "question": "Which type of mutual fund is generally recommended for beginners?",
                "options": ["Sectoral Fund", "Index Fund", "ELSS", "Liquid Fund"],
                "correct": "Index Fund",
                "explanation": "Index funds have the lowest fees, no fund manager risk, and have historically outperformed most actively managed funds.",
            },
            {
                "question": "What is the ideal minimum time horizon for equity mutual fund investments?",
                "options": ["6 months", "1 year", "5 years", "10 years"],
                "correct": "5 years",
                "explanation": "Equity markets can be volatile in the short term but tend to deliver 12-15% annual returns over 5+ year periods.",
            },
            {
                "question": "What happens to your SIP returns if you stop investing during a market crash?",
                "options": ["Nothing changes", "You lose money", "You miss buying more units cheaply", "Your fund closes"],
                "correct": "You miss buying more units cheaply",
                "explanation": "Market crashes are actually the BEST time for SIP investors — you get more units for the same amount (rupee cost averaging).",
            },
            {
                "question": "ELSS mutual funds have a mandatory lock-in period of:",
                "options": ["1 year", "3 years", "5 years", "No lock-in"],
                "correct": "3 years",
                "explanation": "ELSS (Equity Linked Savings Scheme) has the shortest lock-in among all 80C investment options — just 3 years.",
            },
        ],
        "taxes": [
            {
                "question": "Under Section 80C, what is the maximum tax deduction available?",
                "options": ["₹50,000", "₹1,00,000", "₹1,50,000", "₹2,00,000"],
                "correct": "₹1,50,000",
                "explanation": "Section 80C allows deduction up to ₹1.5L through PPF, ELSS, EPF, life insurance, home loan principal, etc.",
            },
            {
                "question": "What is the LTCG tax rate on equity mutual fund gains above ₹1.25L?",
                "options": ["0%", "10%", "12%", "20%"],
                "correct": "12%",
                "explanation": "Long-term capital gains on equity above ₹1.25L are taxed at 12% (as per FY 2024-25 rules).",
            },
            {
                "question": "Which tax regime is the default from FY 2023-24?",
                "options": ["Old Regime", "New Regime", "Both are equal", "No default"],
                "correct": "New Regime",
                "explanation": "New tax regime is now the default. You must actively opt for the old regime if you want to claim deductions like 80C.",
            },
            {
                "question": "HRA exemption is calculated based on:",
                "options": ["Only basic salary", "Basic + DA", "Basic salary, rent paid, and city type", "Gross salary only"],
                "correct": "Basic salary, rent paid, and city type",
                "explanation": "HRA exemption is the minimum of: actual HRA received, 50%/40% of basic (metro/non-metro), or rent paid minus 10% of basic.",
            },
        ],
        "upi_payments": [
            {
                "question": "Should you ever share your UPI PIN with anyone?",
                "options": ["Yes, with family", "Yes, with bank", "Never", "Only with merchant"],
                "correct": "Never",
                "explanation": "NO bank, merchant, or government official will EVER ask for your UPI PIN. Sharing it gives complete access to your account.",
            },
            {
                "question": "What should you do if you receive a suspicious UPI collect request?",
                "options": ["Accept it", "Decline and block", "Ask for details", "Forward to friends"],
                "correct": "Decline and block",
                "explanation": "Never accept unknown UPI collect requests. Decline immediately and block the sender. Report to your bank.",
            },
            {
                "question": "UPI Lite is best used for:",
                "options": ["Large transactions", "Small transactions under ₹500", "International transfers", "Business payments"],
                "correct": "Small transactions under ₹500",
                "explanation": "UPI Lite allows fast payments under ₹500 without entering PIN each time, making daily small payments quicker.",
            },
        ],
    }

    def generate_quiz(
        self, topic: str, difficulty: str = "beginner", num_questions: int = 5
    ) -> Dict[str, Any]:
        """Generate a quiz for the given topic."""
        questions = self.QUIZ_QUESTIONS.get(topic, self.QUIZ_QUESTIONS.get("investing", []))

        # Filter by difficulty if available
        selected = questions[:num_questions]

        import uuid
        quiz_id = f"quiz-{uuid.uuid4().hex[:8]}"

        return {
            "quiz_id": quiz_id,
            "topic": topic,
            "difficulty": difficulty,
            "questions": [
                {
                    "id": f"q{i+1}",
                    "question": q["question"],
                    "options": q["options"],
                    "explanation": q["explanation"],
                    "difficulty": difficulty,
                    "topic": topic,
                }
                for i, q in enumerate(selected)
            ],
            "total_questions": len(selected),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Main Orchestration
# ═══════════════════════════════════════════════════════════════════════════════

_topic_classifier = TopicClassifier()
_response_enhancer = ResponseEnhancer()
_quiz_generator = QuizGenerator()


# ═══════════════════════════════════════════════════════════════════════════════
# LLM Integration
# ═══════════════════════════════════════════════════════════════════════════════

LITERACY_SYSTEM_PROMPT = """You are FinLens, India's friendliest and most knowledgeable financial literacy assistant.

Your mission: Make personal finance simple, accessible, and actionable for every Indian.

TOPICS YOU COVER EXCELLENTLY:
- Budgeting (50/30/20 rule adapted for India)
- SIP and Mutual Funds (how to start, best practices, common mistakes)
- Stocks and Stock Market basics (NSE, BSE, how to invest)
- Tax Planning (old vs new regime, 80C, 80D, GST, ITR filing)
- Insurance (health, life, term, motor — what you actually need)
- UPI and Digital Payments (safety, scam prevention)
- Credit Score (CIBIL, how to improve, common mistakes)
- Loans and EMIs (home loan, personal loan, when to prepay)
- Retirement Planning (PPF, NPS, EPF, SCSS)
- Government Schemes (PM Kisan, PMJJBY, PMSBY, Atal Pension)
- Gold Investing (SGB, Gold ETF vs physical gold)
- Estate Planning (will, nominees, succession)

YOUR STYLE:
1. Use simple, conversational language — no jargon without explanation
2. Always give India-specific examples (₹ amounts, Indian institutions)
3. Include concrete numbers and calculations when possible
4. Mention relevant government bodies (SEBI, RBI, IRDAI)
5. Share common mistakes to avoid
6. Be encouraging — personal finance can feel overwhelming for beginners
7. Use examples from real Indian scenarios (metro vs small city, student vs professional)

IMPORTANT RULES:
1. Never guarantee investment returns
2. Always mention risks alongside benefits
3. Never recommend specific stocks or funds by name (use categories)
4. Always include a disclaimer that this is educational, not financial advice
5. If unsure about something, say so honestly
6. Direct users to SEBI-registered advisors for personalized advice

RESPOND IN VALID JSON:
{
  "response": "your detailed response to the question (3-5 paragraphs)",
  "topic": "detected topic",
  "key_points": ["3-5 key takeaways as bullet points"],
  "practical_tip": "one actionable tip the user can do today",
  "common_mistake": "one common mistake to avoid",
  "disclaimer": "standard financial disclaimer",
  "follow_up_questions": ["2-3 related questions the user might want to ask"]
}"""


async def financial_qa(question: str, llm_call) -> dict:
    """
    Answer a financial literacy question with LLM + local knowledge.

    Args:
        question: User's financial question
        llm_call: Async function (system_prompt, user_prompt) -> str

    Returns:
        Enhanced response with topic classification, key takeaways, etc.
    """
    # Classify topic
    topic, confidence, matched_keywords = _topic_classifier.classify(question)

    # Build context-aware prompt
    topic_context = ""
    knowledge = FINANCIAL_KNOWLEDGE_BASE.get(topic, {})
    if knowledge.get("key_facts"):
        topic_context = "\n\nRelevant facts from our knowledge base:\n"
        for fact in knowledge["key_facts"][:3]:
            topic_context += f"- {fact}\n"

    user_prompt = f"""Question: {question}

{topic_context}

Provide your response as JSON with the exact structure specified.
Be comprehensive, practical, and India-specific."""

    raw_response = await llm_call(LITERACY_SYSTEM_PROMPT, user_prompt)
    if not raw_response:
        raise RuntimeError("Gemini returned no answer text")

    # Parse JSON response
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError:
        json_match = re.search(r'\{[\s\S]*\}', cleaned)
        if json_match:
            try:
                result = json.loads(json_match.group())
            except json.JSONDecodeError:
                result = {"response": raw_response}
        else:
            result = {"response": raw_response}

    # Enhance response with local data
    enhanced = _response_enhancer.enhance(
        question=question,
        llm_response=result.get("response", raw_response),
        topic=topic,
        confidence=confidence,
    )

    # Merge LLM-provided fields
    enhanced["key_points"] = result.get("key_points", enhanced.get("key_takeaways", []))
    enhanced["practical_tip"] = result.get("practical_tip", "")
    enhanced["common_mistake"] = result.get("common_mistake", "")

    return enhanced


def generate_quiz(topic: str, difficulty: str = "beginner", num_questions: int = 5) -> dict:
    """Generate a financial literacy quiz."""
    return _quiz_generator.generate_quiz(topic, difficulty, num_questions)


def get_topic_info() -> dict:
    """Get information about all available topics."""
    return {
        topic_id: {
            "display_name": data["display_name"],
            "icon": data["icon"],
            "subtopics": data["subtopics"],
            "question_count": len(FINANCIAL_KNOWLEDGE_BASE.get(topic_id, {}).get("key_facts", [])),
        }
        for topic_id, data in TOPIC_KEYWORDS.items()
    }
