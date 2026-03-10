from urllib.parse import urlparse
import whois
from datetime import datetime


# threshold for considering a domain suspiciously young (in days)
SUSPICIOUS_DOMAIN_AGE_DAYS = 180


def extract_domain(url: str) -> str:
    """Extract and return the domain from the URL."""
    parsed = urlparse(url)
    return parsed.netloc


def get_domain_info(domain: str) -> object | None:
    """Fetch WHOIS information for the domain.

    Returns the WHOIS object if successful, None otherwise.
    """
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        print(f"Error fetching domain info: {e}")
        return None


def calculate_domain_age(domain_info: object) -> int | None:
    """Calculate the age of the domain in days from creation date.

    Returns None if creation date is unavailable.
    """
    creation_date = domain_info.creation_date

    if not creation_date:
        return None

    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    # remove timezone info if present
    if creation_date.tzinfo is not None:
        creation_date = creation_date.replace(tzinfo=None)

    today = datetime.now()
    age = (today - creation_date).days

    return age


def analyze_domain(url: str) -> list[str]:
    """Analyze the domain for potential phishing indicators.

    Checks various attributes like age, registrar, name servers, and TLD.
    Returns a list of indicator messages.
    """
    indicators = []
    domain = extract_domain(url)
    info = get_domain_info(domain)

    if not info:
        indicators.append("Domain info not found")
        return indicators

    age = calculate_domain_age(info)

    # check domain age
    if age is not None and age < SUSPICIOUS_DOMAIN_AGE_DAYS:
        indicators.append(f"Domain age is {age} days, which is suspiciously young")
    elif age is not None and age > SUSPICIOUS_DOMAIN_AGE_DAYS:
        indicators.append(f"Domain age is {age} days, which is relatively old")

    # check registrar
    if not info.registrar:
        indicators.append("No registrar information found")

    # check name servers
    if info.name_servers:
        indicators.append(f"Domain has {len(info.name_servers)} name servers")
        if len(info.name_servers) < 2:
            indicators.append("Domain has less than 2 name servers, which is suspicious")
        # check for suspicious name server patterns
        suspicious_ns = ['cheap', '.ru', '.cn', '.tk']
        if any(ns in suspicious_ns for ns in info.name_servers):
            indicators.append("Domain has an unusual name server configuration")

    # check TLD
    if info.tld:
        indicators.append(f"Domain TLD is {info.tld}")
        suspicious_tlds = ['xyz', 'top', 'club', 'online', 'site']
        if info.tld in suspicious_tlds:
            indicators.append(f"Domain uses a less common TLD: {info.tld}, possibly phishing")

    return indicators
