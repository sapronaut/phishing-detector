import whois
import tldextract
from datetime import datetime, timezone


def get_domain_info(url: str) -> dict:
    """
    Perform a WHOIS lookup on the domain extracted from the URL.
    Returns a dict with domain age, creation date, registrar, and a risk score delta.
    Never raises — returns an error key on failure.
    """
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if not extracted.domain or not extracted.suffix:
            return {"error": "Could not extract domain"}

        w = whois.whois(domain)

        # creation_date can be a list or a single datetime
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        registrar = w.registrar or "Unknown"

        now = datetime.now(timezone.utc)

        # Normalise to UTC-aware
        if creation_date and creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        if expiration_date and expiration_date.tzinfo is None:
            expiration_date = expiration_date.replace(tzinfo=timezone.utc)

        age_days = (now - creation_date).days if creation_date else None
        age_str  = _format_age(age_days)

        # Risk scoring: very new domains are suspicious
        score_delta = 0
        age_flag = None
        if age_days is not None:
            if age_days < 30:
                score_delta = 3
                age_flag = "Domain registered <30 days ago — very high risk"
            elif age_days < 180:
                score_delta = 2
                age_flag = "Domain registered <6 months ago — elevated risk"
            elif age_days < 365:
                score_delta = 1
                age_flag = "Domain registered <1 year ago — minor risk"

        return {
            "domain":          domain,
            "registrar":       registrar,
            "creation_date":   creation_date.strftime("%Y-%m-%d") if creation_date else "Unknown",
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else "Unknown",
            "age_days":        age_days,
            "age_str":         age_str,
            "score_delta":     score_delta,
            "age_flag":        age_flag,
            "error":           None,
        }

    except Exception as e:
        return {"error": str(e), "score_delta": 0, "age_flag": None}


def _format_age(days: int | None) -> str:
    if days is None:
        return "Unknown"
    if days < 1:
        return "Registered today"
    if days < 30:
        return f"{days} day{'s' if days != 1 else ''} old"
    if days < 365:
        months = days // 30
        return f"~{months} month{'s' if months != 1 else ''} old"
    years = days // 365
    rem   = (days % 365) // 30
    parts = [f"{years} yr{'s' if years != 1 else ''}"]
    if rem:
        parts.append(f"{rem} mo")
    return ", ".join(parts)