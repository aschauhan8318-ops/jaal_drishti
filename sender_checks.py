import re
from email.utils import parseaddr

from url_checks import RISKY_TLDS, registered_domain


# Official sending domains of commonly impersonated organisations
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "office.com", "outlook.com"},
    "google": {"google.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "linkedin": {"linkedin.com"},
    "flipkart": {"flipkart.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "zoom": {"zoom.us"},
    "dhl": {"dhl.com"},
    "sbi": {"sbi.co.in"},
    "hdfc": {"hdfcbank.com", "hdfcbank.net"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "lic": {"licindia.in"},
    "income tax": {"incometax.gov.in"},
    "india post": {"indiapost.gov.in"},
}
OFFICIAL_DOMAINS = {d: brand for brand, domains in BRAND_DOMAINS.items() for d in domains}

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "rediffmail.com", "aol.com", "icloud.com", "me.com",
    "protonmail.com", "proton.me", "zoho.com", "gmx.com", "mail.com", "yandex.com",
}

DISPOSABLE_PROVIDERS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com", "temp-mail.org",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com",
}

# Words that suggest the sender claims to be an organisation rather than a person
ORG_WORDS = {
    "bank", "support", "security", "team", "department", "service", "services", "helpdesk",
    "admin", "administrator", "official", "billing", "account", "accounts", "hr", "customer",
    "care", "noreply", "no-reply", "alert", "alerts", "verification", "rewards", "claims",
}

# Job titles often faked in CEO / boss fraud (business email compromise)
EXEC_WORDS = {
    "ceo", "cfo", "coo", "md", "director", "manager", "president", "chairman",
    "principal", "dean", "professor", "prof", "hod",
}

# Character swaps used in look-alike domains, e.g. paypa1 -> paypal
LOOKALIKE_SWAPS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("$", "s")]

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
HEADER_RE = r"^\s*{}\s*:\s*(.+)$"


def edit_distance(a, b):
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def brand_in_text(brand, text):
    """Match short brand names as whole words to avoid false hits (e.g. 'lic' in 'Alice')."""
    if len(brand) <= 4:
        return re.search(rf"\b{re.escape(brand)}\b", text) is not None
    return brand in text


def brand_in_domain(brand, domain):
    tokens = re.split(r"[.-]", domain)
    return any(t == brand or (len(brand) >= 4 and brand in t) for t in tokens)


def find_lookalike(domain):
    """Return the official domain this one imitates, if any."""
    if domain in OFFICIAL_DOMAINS:
        return None
    normalised = domain
    for fake, real in LOOKALIKE_SWAPS:
        normalised = normalised.replace(fake, real)
    if normalised != domain:
        for brand, official in BRAND_DOMAINS.items():
            brand = brand.replace(" ", "")
            if brand_in_domain(brand, normalised) and not brand_in_domain(brand, domain):
                # Prefer the official domain with the same ending, e.g. arnazon.in -> amazon.in
                same_tld = [d for d in official if d.rsplit(".", 1)[-1] == domain.rsplit(".", 1)[-1]]
                return sorted(same_tld or official)[0]
    for official in OFFICIAL_DOMAINS:
        if len(official) >= 7 and 0 < edit_distance(domain, official) <= 2:
            return official
    return None


def find_header(text, name):
    match = re.search(HEADER_RE.format(re.escape(name)), text, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else ""


def analyze_sender(email_text, sender_input="", url_results=()):
    """Run rule-based checks on the sender. Returns None when no sender is known."""
    source = "entered"
    raw = sender_input.strip()
    if not raw:
        raw = find_header(email_text, "From")
        source = "found in the email"
    if not raw:
        return None

    display_name, address = parseaddr(raw)
    address = address.strip().lower()
    issues = []  # (severity, message)
    notes = []

    if not EMAIL_RE.match(address):
        return {
            "raw": raw, "address": address or raw, "display_name": display_name, "domain": "",
            "provider": "Unknown", "source": source, "risk": "high", "notes": [],
            "issues": [("high", "Not a valid email address")],
        }

    local, domain = address.rsplit("@", 1)
    reg_domain = registered_domain(domain)
    name_text = f"{display_name} {local}".lower()
    name_words = set(re.split(r"[^a-z-]+", name_text)) | set(re.split(r"[^a-z]+", name_text))
    claims_org = bool(name_words & ORG_WORDS)
    exec_titles = sorted(name_words & EXEC_WORDS)
    claimed_brands = [b for b in BRAND_DOMAINS if brand_in_text(b, display_name.lower())]

    # Provider type
    if reg_domain in DISPOSABLE_PROVIDERS:
        provider = "Disposable email"
        issues.append(("high", f"{reg_domain} is a throwaway (disposable) email service"))
    elif reg_domain in FREE_PROVIDERS:
        provider = "Free email provider"
    elif reg_domain in OFFICIAL_DOMAINS:
        provider = f"Official {OFFICIAL_DOMAINS[reg_domain].upper()} domain"
        notes.append("Domain belongs to the real organisation, but sender addresses can be forged; "
                     "be careful if the message asks for money or passwords.")
    else:
        provider = "Custom domain"

    if "xn--" in domain:
        issues.append(("high", "Punycode domain (may use look-alike characters)"))

    lookalike = find_lookalike(reg_domain)
    if lookalike:
        issues.append(("high", f"Look-alike domain: {reg_domain} imitates {lookalike}"))

    for brand, official in BRAND_DOMAINS.items():
        if reg_domain not in official and brand_in_domain(brand.replace(" ", ""), domain) and not lookalike:
            issues.append(("high", f"Uses '{brand}' in the domain, but the real domain is {' / '.join(sorted(official))}"))
            break

    for brand in claimed_brands:
        if reg_domain not in BRAND_DOMAINS[brand]:
            issues.append(("high", f"Display name claims to be {brand.upper()}, but the email comes from {reg_domain}"))
            break

    if reg_domain in FREE_PROVIDERS and (claims_org or claimed_brands):
        issues.append(("medium", f"Claims to be an organisation but uses a free {reg_domain} account"))

    if reg_domain in FREE_PROVIDERS and exec_titles:
        issues.append(("medium", f"Uses an executive title ({exec_titles[0].upper()}) on a personal {reg_domain} "
                                 "account, a common sign of CEO fraud"))

    tld = domain.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        issues.append(("medium", f".{tld} domains are often used in scams"))

    if domain.count("-") >= 2 or domain.count(".") >= 4:
        issues.append(("medium", "Unusually long or hyphenated domain"))

    if sum(c.isdigit() for c in local) >= 4:
        issues.append(("low", "Random-looking address with many digits"))

    reply_to = parseaddr(find_header(email_text, "Reply-To"))[1].lower()
    if reply_to and "@" in reply_to and registered_domain(reply_to.rsplit("@", 1)[1]) != reg_domain:
        issues.append(("high", f"Replies go to a different address: {reply_to}"))

    link_domains = sorted({u["domain"] for u in url_results if u["domain"]})
    if link_domains and reg_domain not in link_domains and reg_domain not in FREE_PROVIDERS:
        issues.append(("medium", f"Links point to {', '.join(link_domains)}, not the sender's domain {reg_domain}"))

    severities = {s for s, _ in issues}
    risk = "high" if "high" in severities else "medium" if "medium" in severities else "low"

    return {
        "raw": raw, "address": address, "display_name": display_name, "domain": reg_domain,
        "provider": provider, "source": source, "risk": risk, "issues": issues, "notes": notes,
    }
