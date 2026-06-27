"""Exposure Scanner API — Vercel serverless."""

import asyncio
import hashlib
import json
import os
from urllib.parse import unquote_plus

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from pathlib import Path

app = FastAPI()

SOCIAL_PLATFORMS = {
    "github": "https://github.com/{u}",
    "twitter": "https://x.com/{u}",
    "instagram": "https://www.instagram.com/{u}/",
    "linkedin": "https://www.linkedin.com/in/{u}/",
    "reddit": "https://www.reddit.com/user/{u}",
    "tiktok": "https://www.tiktok.com/@{u}",
    "youtube": "https://www.youtube.com/@{u}",
    "medium": "https://medium.com/@{u}",
    "dev.to": "https://dev.to/{u}",
    "gitlab": "https://gitlab.com/{u}",
    "bitbucket": "https://bitbucket.org/{u}/",
    "npm": "https://www.npmjs.com/~{u}",
    "pypi": "https://pypi.org/user/{u}/",
    "dockerhub": "https://hub.docker.com/u/{u}",
    "keybase": "https://keybase.io/{u}",
    "hackernews": "https://news.ycombinator.com/user?id={u}",
    "twitch": "https://www.twitch.tv/{u}",
    "pinterest": "https://www.pinterest.com/{u}/",
    "soundcloud": "https://soundcloud.com/{u}",
    "spotify": "https://open.spotify.com/user/{u}",
}

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")


async def check_hibp(email):
    findings = []
    sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    async with httpx.AsyncClient(timeout=10) as c:
        try:
            r = await c.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if suffix in r.text:
                findings.append({"source": "HaveIBeenPwned", "severity": "critical",
                    "title": "Password found in data breaches",
                    "detail": "A password associated with this email appears in known breach databases.",
                    "url": "", "action": "Change passwords on all accounts. Enable 2FA everywhere."})
        except Exception:
            pass
        try:
            r = await c.get(f"https://haveibeenpwned.com/unifiedsearch/{email}",
                           headers={"User-Agent": "ExposureScanner"})
            if r.status_code == 200:
                breaches = r.json().get("Breaches", [])
                for b in breaches[:5]:
                    findings.append({"source": "HaveIBeenPwned", "severity": "high",
                        "title": f"Data breach: {b.get('Name', '?')}",
                        "detail": f"Breached {b.get('BreachDate', '?')}. Data: {', '.join(b.get('DataClasses', [])[:4])}",
                        "url": "https://haveibeenpwned.com/", "action": "Change password for this service."})
                if len(breaches) > 5:
                    findings.append({"source": "HaveIBeenPwned", "severity": "high",
                        "title": f"+{len(breaches)-5} more breaches", "detail": f"Total: {len(breaches)} breaches.",
                        "url": "https://haveibeenpwned.com/", "action": "Review all breaches."})
        except Exception:
            pass
    return findings


async def check_username(username):
    findings = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=8) as c:
        tasks = []
        for platform, url_t in SOCIAL_PLATFORMS.items():
            url = url_t.format(u=username)
            tasks.append((platform, url, c.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible)"})))
        results = await asyncio.gather(*[t[2] for t in tasks], return_exceptions=True)
        for (platform, url, _), result in zip(tasks, results):
            if isinstance(result, Exception):
                continue
            if result.status_code == 200:
                findings.append({"source": platform, "severity": "info",
                    "title": f"Account found: {platform}",
                    "detail": f"Username '{username}' exists on {platform}.",
                    "url": url, "action": "If unused, consider deactivating."})
    return findings


async def check_github_email(email):
    findings = []
    async with httpx.AsyncClient(timeout=10) as c:
        try:
            r = await c.get(f"https://api.github.com/search/commits?q=author-email:{email}",
                           headers={"Accept": "application/vnd.github.cloak-preview+json", "User-Agent": "ExposureScanner"})
            if r.status_code == 200:
                count = r.json().get("total_count", 0)
                if count > 0:
                    findings.append({"source": "GitHub", "severity": "medium",
                        "title": f"Email in {count} public commit(s)",
                        "detail": f"Email '{email}' visible in public git history.",
                        "url": f"https://github.com/search?q=author-email%3A{email}&type=commits",
                        "action": "Use noreply email: git config user.email 'user@users.noreply.github.com'"})
        except Exception:
            pass
    return findings


async def check_gravatar(email):
    """Check if Gravatar profile exists (reveals linked accounts + photo)."""
    findings = []
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    async with httpx.AsyncClient(timeout=8) as c:
        try:
            r = await c.get(f"https://en.gravatar.com/{email_hash}.json")
            if r.status_code == 200:
                data = r.json()
                profile = data.get("entry", [{}])[0]
                name = profile.get("displayName", "")
                accounts = profile.get("accounts", [])
                photos = profile.get("photos", [])
                detail = f"Profile found with display name '{name}'." if name else "Profile found."
                if accounts:
                    detail += f" Linked accounts: {', '.join(a.get('shortname', '') for a in accounts[:5])}"
                findings.append({"source": "Gravatar", "severity": "medium",
                    "title": "Gravatar profile exposes identity",
                    "detail": detail,
                    "url": f"https://gravatar.com/{email_hash}",
                    "action": "Review gravatar.com profile. Remove linked accounts or use a different email for public services."})
        except Exception:
            pass
    return findings


async def check_wayback(email, username):
    """Check Wayback Machine for cached pages mentioning the person."""
    findings = []
    query = username or email.split("@")[0]
    async with httpx.AsyncClient(timeout=10) as c:
        try:
            r = await c.get(f"https://web.archive.org/cdx/search/cdx?url=*{query}*&output=json&limit=5")
            if r.status_code == 200 and r.text.strip() and r.text.strip() != "[]":
                rows = r.json()
                if len(rows) > 1:  # first row is header
                    count = len(rows) - 1
                    findings.append({"source": "Wayback Machine", "severity": "low",
                        "title": f"{count} archived page(s) found",
                        "detail": f"The Wayback Machine has cached pages related to '{query}'.",
                        "url": f"https://web.archive.org/web/*/{'*' + query + '*'}",
                        "action": "Review cached pages. Request removal at web.archive.org if sensitive content found."})
        except Exception:
            pass
    return findings


async def check_pgp_keys(email):
    """Check if PGP public keys exist (reveals name, email associations)."""
    findings = []
    async with httpx.AsyncClient(timeout=8) as c:
        try:
            r = await c.get(f"https://keys.openpgp.org/vks/v1/by-email/{email}")
            if r.status_code == 200 and len(r.text) > 50:
                findings.append({"source": "OpenPGP", "severity": "info",
                    "title": "PGP public key found",
                    "detail": f"A PGP key associated with '{email}' is published on keys.openpgp.org.",
                    "url": f"https://keys.openpgp.org/search?q={email}",
                    "action": "PGP keys often contain full name. Revoke if no longer used."})
        except Exception:
            pass
    return findings


async def check_whois(domain):
    """Check WHOIS/RDAP for domain registration info."""
    findings = []
    if not domain:
        return findings
    async with httpx.AsyncClient(timeout=10) as c:
        try:
            r = await c.get(f"https://rdap.org/domain/{domain}")
            if r.status_code == 200:
                data = r.json()
                for entity in data.get("entities", []):
                    vcards = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
                    for vcard in vcards:
                        if isinstance(vcard, list) and vcard[0] == "fn" and vcard[3]:
                            findings.append({"source": "WHOIS/RDAP", "severity": "medium",
                                "title": f"Personal info in domain WHOIS: {vcard[3]}",
                                "detail": f"Domain '{domain}' registration exposes registrant identity.",
                                "url": f"https://rdap.org/domain/{domain}",
                                "action": "Enable WHOIS privacy through your domain registrar."})
                            break
        except Exception:
            pass
    return findings


async def ai_analyze(findings):
    if not GROQ_API_KEY or not findings:
        return _fallback(findings)
    async with httpx.AsyncClient(timeout=30) as c:
        try:
            r = await c.post("https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={"model": "llama-3.3-70b-versatile", "max_tokens": 500, "temperature": 0.3,
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert. Given scan findings, provide: 1) Risk score 1-10, 2) Top 3 priority actions, 3) Quick wins. Be direct, use bullet points."},
                        {"role": "user", "content": f"Findings:\n{json.dumps(findings[:10], indent=2)}"}
                    ]})
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
        except Exception:
            pass
    return _fallback(findings)


def _fallback(findings):
    c = sum(1 for f in findings if f["severity"] == "critical")
    h = sum(1 for f in findings if f["severity"] == "high")
    i = sum(1 for f in findings if f["severity"] == "info")
    score = min(10, c * 3 + h * 2 + i * 0.2)
    r = f"Risk Score: {score:.1f}/10\n\n"
    if c: r += "CRITICAL: Passwords in breaches. Change all passwords + enable 2FA.\n\n"
    if h: r += f"{h} breaches found. Rotate credentials on affected services.\n\n"
    if i: r += f"{i} accounts found. Deactivate unused ones.\n"
    return r


@app.get("/")
async def home():
    return FileResponse(Path(__file__).parent.parent / "index.html")


@app.post("/api/scan")
async def scan(email: str = Form(""), username: str = Form(""), domain: str = Form("")):
    tasks = []
    if email:
        tasks.append(check_hibp(email))
        tasks.append(check_github_email(email))
        tasks.append(check_gravatar(email))
        tasks.append(check_pgp_keys(email))
    if username:
        tasks.append(check_username(username))
    if email or username:
        tasks.append(check_wayback(email, username))
    if domain:
        tasks.append(check_whois(domain))
    elif email and "." in email.split("@")[-1]:
        # Auto-check domain from email
        email_domain = email.split("@")[-1]
        if email_domain not in ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com"):
            tasks.append(check_whois(email_domain))

    all_findings = await asyncio.gather(*tasks)
    findings = []
    for f in all_findings:
        findings.extend(f)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))
    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {"findings": findings, "summary": summary}


@app.post("/api/analyze")
async def analyze(request: Request):
    body = await request.json()
    report = await ai_analyze(body.get("findings", []))
    return {"report": report}
