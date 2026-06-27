"""AI Analysis — generates personalized security report from scan findings."""

import json
import os
from http.server import BaseHTTPRequestHandler
import httpx

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

SYSTEM_PROMPT = """You are a cybersecurity expert helping individuals understand their digital exposure.
Given scan findings, generate a brief, actionable report in this format:

1. Risk Score (1-10) with one-line summary
2. Top 3 priority actions (specific, actionable)
3. Quick wins (things they can fix in 5 minutes)

Be direct, no fluff. Use bullet points. If findings are minimal, say so and congratulate them."""


async def analyze_with_ai(findings: list) -> str:
    """Send findings to Groq (free Llama 3) for analysis."""
    if not GROQ_API_KEY:
        return _fallback_analysis(findings)

    findings_text = json.dumps(findings[:15], indent=2)

    async with httpx.AsyncClient(timeout=30) as c:
        try:
            r = await c.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Analyze these digital exposure findings:\n\n{findings_text}"}
                    ],
                    "max_tokens": 500,
                    "temperature": 0.3,
                }
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass

    return _fallback_analysis(findings)


def _fallback_analysis(findings: list) -> str:
    """Simple rule-based analysis when AI is unavailable."""
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    info = sum(1 for f in findings if f.get("severity") == "info")

    score = min(10, critical * 3 + high * 2 + medium * 1 + info * 0.2)

    report = f"## Risk Score: {score:.1f}/10\n\n"

    if critical > 0:
        report += "⚠️ **CRITICAL**: Your passwords have been found in data breaches.\n\n"
        report += "### Priority Actions:\n"
        report += "1. Change passwords on ALL accounts immediately\n"
        report += "2. Enable 2FA on email, banking, and social accounts\n"
        report += "3. Use a password manager (Bitwarden, 1Password)\n\n"

    if high > 0:
        report += f"### Data Breaches ({high} found):\n"
        report += "- Check each breach at haveibeenpwned.com\n"
        report += "- Change passwords for breached services\n"
        report += "- Watch for phishing emails targeting these accounts\n\n"

    if info > 0:
        report += f"### Accounts Found ({info} platforms):\n"
        report += "- Deactivate accounts you no longer use\n"
        report += "- Review privacy settings on active accounts\n"
        report += "- Remove personal info from public profiles\n\n"

    if score < 3:
        report += "✅ **Good news**: Your digital exposure is relatively low. Keep it up!"

    return report


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        import asyncio
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode())

        findings = body.get("findings", [])
        report = asyncio.run(analyze_with_ai(findings))

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({"report": report}).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
