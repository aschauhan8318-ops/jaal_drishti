import os

from dotenv import load_dotenv
from flask import Flask, render_template, request
from google import genai
from markupsafe import Markup, escape

from detector import PERSUASION_PRINCIPLES, RUNS, analyze_email
from sender_checks import analyze_sender
from url_checks import analyze_urls


# Load GEMINI_API_KEY (and optional GEMINI_MODEL) from .env
load_dotenv()

api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("WARNING: GEMINI_API_KEY is not set. Copy .env.example to .env (or set it in Vercel) and add your key.")

client = genai.Client(api_key=api_key) if api_key else None
model_name = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")

MAX_EMAIL_CHARS = 20000
MAX_SENDER_CHARS = 320

SAMPLES = [
    {
        "name": "Bank account alert",
        "sender": "SBI Security Team <alerts@sbi-secure-verify.xyz>",
        "text": "Dear Customer,\n\nYour SBI account has been temporarily suspended due to unusual activity. "
                "To avoid permanent closure, verify your details within 24 hours:\n\n"
                "http://sbi-secure-verify.xyz/login\n\n"
                "Enter your account number, ATM PIN and the OTP you receive.\n\nSBI Security Team",
    },
    {
        "name": "Prize winner",
        "sender": "Apple Rewards <winner.2026.draw@gmail.com>",
        "text": "CONGRATULATIONS!!! You have been selected as the lucky winner of an Apple iPhone 17 Pro "
                "in our anniversary draw. To claim your prize, pay a small shipping fee of Rs. 99 here: "
                "https://bit.ly/claim-iphone-now\n\nOffer expires in 2 hours!",
    },
    {
        "name": "CEO gift card request",
        "sender": "Rajesh Kumar CEO <rajesh.kumar.ceo@outlook.com>",
        "text": "Hi,\n\nAre you at your desk? I need you to handle something quickly and discreetly. "
                "Please buy 5 Amazon gift cards of Rs. 10,000 each for a client and send me the codes. "
                "I'm in a meeting and can't take calls. I'll reimburse you today.\n\nRegards,\nRajesh Kumar\nCEO",
    },
    {
        "name": "Project meeting",
        "sender": "Priya Sharma <priya.sharma@university.edu>",
        "text": "Hi team,\n\nThe project review meeting has been moved to Thursday at 3 PM in Room 204. "
                "Please bring your progress slides. The agenda is attached.\n\nThanks,\nPriya",
    },
    {
        "name": "Order shipped",
        "sender": "Amazon.in <shipment-tracking@amazon.in>",
        "text": "Hello Harsh,\n\nYour order #402-1187733 has shipped and will arrive by Monday. "
                "You can track it anytime in Your Orders on amazon.in.\n\nThank you for shopping with us.",
    },
]


# Static files live in public/static so Vercel can serve them from its CDN;
# Flask serves the same folder when running locally.
app = Flask(__name__, static_folder="public/static", static_url_path="/static")


def highlight(text, red_flags):
    """Escape the email and wrap each red-flag quote in <mark data-flag="n">."""
    lower = text.lower()
    spans = []
    for number, flag in enumerate(red_flags, start=1):
        quote = flag.quote.strip()
        start = lower.find(quote.lower()) if quote else -1
        if start != -1:
            spans.append((start, start + len(quote), number, flag.category))
    spans.sort()

    parts = []
    pos = 0
    for start, end, number, category in spans:
        if start < pos:
            continue
        parts.append(escape(text[pos:start]))
        parts.append(
            Markup('<mark data-flag="{}" title="{}">{}</mark>').format(number, category, text[start:end])
        )
        pos = end
    parts.append(escape(text[pos:]))
    return Markup("").join(parts)


def render_page(**context):
    return render_template(
        "index.html",
        samples=SAMPLES,
        model=model_name,
        runs=RUNS,
        principles=PERSUASION_PRINCIPLES,
        **context
    )


@app.route("/")
def home():
    return render_page()


@app.route("/predict", methods=["POST"])
def predict():

    email_text = request.form["email"][:MAX_EMAIL_CHARS]
    sender_input = request.form.get("sender", "")[:MAX_SENDER_CHARS]
    url_results = analyze_urls(email_text)
    sender_result = analyze_sender(email_text, sender_input, url_results)

    if client is None:
        return render_page(error="GEMINI_API_KEY is not set on the server.", email=email_text, sender=sender_input)

    try:
        analysis = analyze_email(client, model_name, email_text, url_results, sender_result)
    except Exception:
        app.logger.exception("Gemini request failed")
        return render_page(
            error="Could not get a result from Gemini. Check your API key and the terminal for details.",
            email=email_text,
            sender=sender_input
        )

    return render_page(
        analysis=analysis,
        verdict=analysis.verdict,
        urls=url_results,
        sender_result=sender_result,
        highlighted=highlight(email_text, analysis.verdict.red_flags),
        email=email_text,
        sender=sender_input
    )


if __name__ == "__main__":
    app.run(debug=True)
