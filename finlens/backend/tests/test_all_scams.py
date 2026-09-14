import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.scam_analyzer import analyze_scam
from main import llm_call

SCAMS = [
    ("UPI PIN Scam", "Congratulations! You won 1 lakh cashback! Share your UPI PIN to claim. Your account will be blocked in 30 minutes."),
    ("Fake Investment", "Guaranteed 5% daily returns! Our AI trading bot never lost money. Invest 5000, double in 7 days. Risk free!"),
    ("Phishing/KYC", "URGENT: Your SBI account suspended! KYC expired. Click http://sbi-verify-update.com/kyc to update NOW."),
    ("OTP Fraud", "I accidentally sent an OTP to your number. Can you share the code? Just tell me the 6 digits."),
    ("Job Scam", "Work from home! Earn 50000/month with 2 hours work. No experience. Register with fee 999."),
    ("Digital Arrest", "This is Inspector from CBI. Your Aadhaar linked to money laundering. Transfer 2 lakh to safe account. Tell no one."),
    ("Social Engineering", "My phone broke, at hospital with mom. Need 6800 for emergency surgery. Please help, return tomorrow."),
    ("Lottery Scam", "Selected for Samsung Galaxy S24! Pay courier charge 500 to claim. Last date today!"),
    ("Loan Scam", "Instant personal loan 5 lakh! No documents! Pay processing fee 2000 via UPI. Credited in 1 hour."),
    ("Tax Refund", "Income Tax Dept: You have refund of 15400. Click http://taxrefund-gov.in/refund. Verify with PAN."),
]

async def test():
    print()
    print("=" * 110)
    print(f"{'SCAM TYPE':20s} | SCORE | LEVEL           | GEMINI CLASSIFICATION")
    print("=" * 110)
    for name, msg in SCAMS:
        try:
            result = await analyze_scam(msg, llm_call)
            score = result["risk_score"]
            level = result["risk_level"]
            scam_type = result.get("scam_type") or "N/A"
            flag = "PASS" if score >= 50 else "WEAK" if score >= 30 else "FAIL"
            print(f"  {flag} {name:18s} | {score:3d}/100 | {level:15s} | {scam_type}")
        except Exception as e:
            print(f"  ERR {name:18s} | ERROR: {str(e)[:70]}")
    print("=" * 110)

asyncio.run(test())
