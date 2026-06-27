# 🔍 Exposure Scanner

Digital footprint audit tool. Check what's publicly exposed about you and get AI-powered security recommendations.

## What it checks

- **Data breaches** (HaveIBeenPwned) — is your email in leaked databases?
- **Username enumeration** (20+ platforms) — where do your accounts exist?
- **Git email exposure** (GitHub) — is your email in public commits?
- **AI analysis** (Groq/Llama 3) — personalized risk report with priorities

## Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/subzone/exposure-scanner)

Or manually:

```bash
npm i -g vercel
vercel --prod
```

## Environment Variables (optional)

| Variable | Purpose | Where to get |
|---|---|---|
| `GROQ_API_KEY` | AI analysis (free) | https://console.groq.com/keys |

Without the API key, the tool uses rule-based analysis (still useful, just less personalized).

## Privacy

- No data stored — scans are ephemeral
- No accounts needed to use
- Checks only public sources
- Open source — verify the code yourself

## License

MIT
