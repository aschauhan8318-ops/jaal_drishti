import ipaddress
import re
from urllib.parse import urlparse


URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

# Top-level domains that show up disproportionately in phishing reports
RISKY_TLDS = {
    "xyz", "top", "click", "link", "zip", "mov", "tk", "ml", "ga", "cf", "gq",
    "work", "support", "rest", "country", "loan", "live", "icu", "buzz",
}

BRANDS = {
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook",
    "instagram", "whatsapp", "sbi", "hdfc", "icici", "axis", "paytm", "flipkart",
}

BAIT_WORDS = {"verify", "login", "signin", "secure", "update", "account", "wallet", "confirm"}

# Second-level labels used under country domains, e.g. sbi.co.in
COUNTRY_SLDS = {"co", "com", "org", "net", "gov", "ac", "edu"}


def registered_domain(host):
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in COUNTRY_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def check_url(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    domain = registered_domain(host)
    issues = []

    if url.lower().startswith("http://"):
        issues.append("Not encrypted (uses http instead of https)")

    try:
        ipaddress.ip_address(host)
        issues.append("Uses a raw IP address instead of a domain name")
    except ValueError:
        pass

    if "@" in parsed.netloc:
        issues.append("Contains '@', which hides the real destination")

    if host in SHORTENERS:
        issues.append("Link shortener hides the real destination")

    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        issues.append(f".{tld} domains are often used in scams")

    if "xn--" in host:
        issues.append("Punycode domain (may use look-alike characters)")

    if host.count(".") >= 4:
        issues.append("Unusually many subdomains")

    for brand in BRANDS:
        if brand in host and not domain.startswith(brand + "."):
            issues.append(f"Mentions '{brand}' but the real domain is {domain}")
            break

    if any(word in host for word in BAIT_WORDS):
        issues.append("Domain contains bait words like 'verify', 'secure' or 'login'")

    return {"url": url, "domain": domain, "issues": issues}


def analyze_urls(text):
    results = []
    seen = set()
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            results.append(check_url(url))
    return results
