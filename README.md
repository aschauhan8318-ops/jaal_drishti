# JaalDrishti — See the trap before you click

An explainable, AI-based phishing email detection system. JaalDrishti combines a
rule-based link scanner with Google Gemini to classify emails as **Safe**,
**Suspicious** or **Phishing**, explains every red flag, and shows verified Indian
cyber-crime helplines when a threat is found. No training dataset is required.

## How it works

1. **Sender analysis** (`sender_checks.py`) – checks the sender address (entered, or
   taken from a `From:` line): look-alike domains (`paypa1.com`, `micros0ft-support.com`),
   brand names on unofficial domains, display-name/domain mismatch, free or disposable
   accounts posing as organisations or executives, risky TLDs, random-looking addresses,
   a different `Reply-To`, and links that point away from the sender's domain.
2. **Link scanner** (`url_checks.py`) – rule-based checks on every URL: raw IP hosts,
   risky TLDs, link shorteners, punycode, `@` tricks and look-alike brand domains.
3. **Gemini analysis × 3** (`detector.py`) – the email and link findings are sent to
   Gemini three times in parallel with a fixed JSON schema. The scores are averaged
   (self-consistency) and the agreement between runs is shown.
4. **Verdict** – Safe (< 30), Suspicious (30–69), Phishing (≥ 70).
5. **Explainable report** – phishing probability gauge, attack type, red flags with
   the exact phrases highlighted in the email, Cialdini persuasion techniques,
   recommended next steps, and a "Report & get help" panel (1930,
   cybercrime.gov.in, Sanchar Saathi Chakshu, 112, CERT-In).

## Tech stack

Python · Flask · Google Gemini API (`google-genai`) · Pydantic · HTML/CSS/JS

## Project structure

```
app.py                    Flask app: routes, sample emails, phrase highlighting
detector.py               Gemini prompt, response schema, 3-run self-consistency
url_checks.py             Rule-based URL checks
sender_checks.py          Rule-based sender address checks
templates/index.html      Web page
public/static/            CSS (served by Vercel's CDN)
phishing_test_emails.md   80 phishing test emails (8 attack types × 10)
vercel.json               Vercel function settings
.env.example              Template for your API key
```

## Run locally

```bash
python -m venv venv
venv\Scripts\activate          # Windows  (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env         # macOS/Linux: cp .env.example .env
```

Open `.env` and set `GEMINI_API_KEY=your-key`
(get one at https://aistudio.google.com/apikey), then:

```bash
python app.py
```

Open http://127.0.0.1:5000

## Deploy on Vercel

1. Push this repository to GitHub (`.env` is git-ignored, so your key is never uploaded).
2. In Vercel, **Add New → Project** and import the repository. Vercel detects the
   Flask app in `app.py` automatically.
3. Under **Settings → Environment Variables**, add:
   - `GEMINI_API_KEY` = your key
   - `GEMINI_MODEL` = `gemini-3.5-flash-lite` (optional)
4. Deploy. Static files in `public/` are served from Vercel's CDN.

## Testing

`phishing_test_emails.md` contains 80 fictional phishing emails across 8 attack
types (credential harvesting, account suspension, payment fraud, prize scams,
business email compromise, malware lures, fake jobs, tech-support scams) at
Easy / Medium / Hard difficulty. Every email should be rated Suspicious or Phishing.

## Disclaimer

Results are AI estimates. Always verify through official channels.
