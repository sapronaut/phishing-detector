import re
import tldextract
from whois_lookup import get_domain_info

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "password", "wallet", "signin", "confirm",
    "paypal", "ebay", "amazon", "apple", "microsoft",
    "support", "service", "security", "alert", "urgent",
]

IP_PATTERN = re.compile(
    r"(https?://)?"
    r"(\d{1,3}\.){3}\d{1,3}"
)


def analyze_url(url: str) -> dict:
    url = url.strip()
    score = 0
    flags = []

    # 1. IP address used instead of domain
    if IP_PATTERN.match(url):
        score += 3
        flags.append(("IP address used instead of domain", 3))

    # 2. No HTTPS
    if not url.startswith("https://"):
        score += 2
        flags.append(("No HTTPS", 2))

    # 3. Contains @ symbol
    if "@" in url:
        score += 3
        flags.append(("Contains @ symbol (can redirect to attacker)", 3))

    # 4. Excessive subdomains (too many dots in host)
    extracted = None
    try:
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
        dot_count = subdomain.count(".") + 1 if subdomain else 0
        if dot_count >= 3:
            score += 2
            flags.append((f"Excessive subdomains ({dot_count})", 2))
    except Exception:
        pass

    # 5. Suspicious keywords in URL
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found_keywords:
        score += min(len(found_keywords), 3)
        flags.append((f"Suspicious keywords: {', '.join(found_keywords)}", len(found_keywords)))

    # 6. Long URL
    if len(url) > 75:
        score += 1
        flags.append((f"Long URL ({len(url)} chars)", 1))

    # 7. Hyphen abuse in domain
    try:
        domain = extracted.domain
        if domain.count("-") >= 2:
            score += 1
            flags.append((f"Hyphen-heavy domain ({domain})", 1))
    except Exception:
        pass

    # 8. Digit substitution (e.g. paypa1, g00gle)
    digit_sub = re.search(r"(pay|pal|google|apple|amazon|bank|secure)[a-z]*\d[a-z]*", url_lower)
    if digit_sub:
        score += 2
        flags.append(("Digit substitution detected (e.g. paypa1)", 2))

    # 9. WHOIS lookup
    is_ip = bool(IP_PATTERN.match(url))
    whois_data = {}
    if not is_ip:
        whois_data = get_domain_info(url)
        if whois_data.get("age_flag"):
            score += whois_data["score_delta"]
            flags.append((whois_data["age_flag"], whois_data["score_delta"]))

    # Verdict
    if score <= 2:
        verdict = "legitimate"
    elif score <= 5:
        verdict = "suspicious"
    else:
        verdict = "phishing"

    return {
        "url":     url,
        "score":   score,
        "verdict": verdict,
        "flags":   flags,
        "whois":   whois_data,
    }