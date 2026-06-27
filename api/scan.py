"""Scan API — serverless function for Vercel."""

import asyncio
import hashlib
import json
from http.server import BaseHTTPRequestHandler
import httpx

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


async def check_hibp(email):
    findings = []
    sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    async with httpx.AsyncClient(timeout=10) as c:
        try:
            r = await c.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if suffix in r.text:
                findings.append({
                    "source": "HaveIBeenPwned", "severity": "critical",
                    "title": "Password found in data breaches",
                    "detail": "A password associated with this email appears in known breach databases.",
                    "url": "", "action": "Change passwords on all accounts. Enable 2FA everywhere."
                })
        except Exception:
            pass

        try:
            r = await c.get(f"https://haveibeenpwned.com/unifiedsearch/{email}",
                           headers={"User-Agent": "ExposureScanner"})
            if r.status_code == 200:
                breaches = r.json().get("Breaches", [])
                for b in breaches[:5]:
                    findings.append({
                        "source": "HaveIBeenPwned", "severity": "high",
                        "title": f"Data breach: {b.get('Name', '?')}",
                        "detail": f"Breached {b.get('BreachDate', '?')}. Data: {', '.join(b.get('DataClasses', [])[:4])}",
                        "url": f"https://haveibeenpwned.com/", "action": "Change password for this service."
                    })
                if len(breaches) > 5:
                    findings.append({
                        "source": "HaveIBeenPwned", "severity": "high",
                        "title": f"+{len(breaches)-5} more breaches",
                        "detail": f"Total: {len(breaches)} breaches found.",
                        "url": "https://haveibeenpwned.com/", "action": "Review all at haveibeenpwned.com"
                    })
        except Exception:
            pass
    return findings


async def check_username(username):
    findings = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=8) as c:
        tasks = {}
        for platform, url_t in SOCIAL_PLATFORMS.items():
            url = url_t.format(u=username)
            tasks[platform] = (url, c.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible)"}))

        results = await asyncio.gather(*[t[1] for t in tasks.values()], return_exceptions=True)

        for (platform, (url, _)), result in zip(tasks.items(), results):
            if isinstance(result, Exception):
                continue
            if result.status_code == 200:
                findings.append({
                    "source": platform, "severity": "info",
                    "title": f"Account found: {platform}",
                    "detail": f"Username '{username}' exists on {platform}.",
                    "url": url, "action": "If unused, consider deactivating to reduce exposure."
                })
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
                    findings.append({
                        "source": "GitHub", "severity": "medium",
                        "title": f"Email in {count} public commit(s)",
                        "detail": f"Email '{email}' visible in public git history.",
                        "url": f"https://github.com/search?q=author-email%3A{email}&type=commits",
                        "action": "Use noreply email: git config user.email 'user@users.noreply.github.com'"
                    })
        except Exception:
            pass
    return findings


async def run_scan(email, username):
    tasks = []
    if email:
        tasks.append(check_hibp(email))
        tasks.append(check_github_email(email))
    if username:
        tasks.append(check_username(username))

    all_findings = await asyncio.gather(*tasks)
    findings = []
    for f_list in all_findings:
        findings.extend(f_list)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {"findings": findings, "summary": summary}


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()

        # Parse form data
        params = {}
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                from urllib.parse import unquote_plus
                params[k] = unquote_plus(v)

        email = params.get("email", "")
        username = params.get("username", "")

        result = asyncio.run(run_scan(email, username))

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
