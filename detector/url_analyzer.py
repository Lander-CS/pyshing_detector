import re
from urllib.parse import urlparse

from .models import Indicator, IndicatorCategory, Severity


def analyze_url_indicators(url: str) -> list[Indicator]:
    """Analyze the given URL for potential phishing indicators.

    This function computes a list of indicators based on several heuristics:
    - URL length exceeding 75 characters.
    - Use of IP address instead of domain name.
    - Excessive number of subdomains (more than 3 dots).
    - Presence of suspicious keywords in the URL.

    Parameters
    ----------
    url : str
        The URL string to analyze.

    Returns
    -------
    list[Indicator]
        A list of structured indicators describing the potential phishing indicators found.
    """

    indicators: list[Indicator] = []

    # penalize URLs longer than 75 characters as they may hide malicious content
    if len(url) > 75:
        indicators.append(
            Indicator(
                category=IndicatorCategory.URL_STRUCTURE,
                message="URL length is unusually long ({} characters)".format(len(url)),
                severity=Severity.MEDIUM,
            )
        )

    # check for IP address usage, which is uncommon for legitimate sites
    ip_pattern = r"(http|https)://\d+\.\d+\.\d+\.\d+"
    if re.match(ip_pattern, url):
        indicators.append(
            Indicator(
                category=IndicatorCategory.URL_STRUCTURE,
                message="URL uses IP address instead of domain name",
                severity=Severity.MEDIUM,
            )
        )

    #return indicators

    # count subdomains; too many may indicate obfuscation
    domain = urlparse(url).netloc
    if domain.count(".") > 3:
        indicators.append(
            Indicator(
                category=IndicatorCategory.URL_STRUCTURE,
                message="URL has excessive number of subdomains ({} dots)".format(
                    domain.count(".")
                ),
                severity=Severity.MEDIUM,
            )
        )

    # list of keywords often associated with phishing attempts
    suspicious_keywords = [
        "login",
        "secure",
        "account",
        "update",
        "free",
        "verify",
        "password",
        "bank",
        "confirm",
        "security",
    ]

    # increment indicators if any suspicious keyword is found
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            indicators.append(
                Indicator(
                    category=IndicatorCategory.URL_KEYWORD,
                    message=f"URL contains suspicious keyword: '{keyword}'",
                    severity=Severity.MEDIUM,
                )
            )
            break  # stop after first match to avoid over-penalizing

    return indicators


"""def analyze_url(url: str) -> list[str]:
   
    Backwards-compatible wrapper returning only indicator messages.

    Prefer usar analyze_url_indicators para obter objetos estruturados.
 
    return [indicator.message for indicator in analyze_url_indicators(url)]
    """


def classify(indicators: list) -> str:
    """Classify the URL based on the computed indicators.

    Parameters
    ----------
    indicators : list
        A list of strings describing the potential phishing indicators found.

    Returns
    -------
    str
        A classification string: "Possibly phishing" or "Possibly legitimate".
    """
    if  len(indicators) >= 3:
        return "Possibly phishing"
    else:
        return "Possibly legitimate"


# example usage: prompt user for a URL and display analysis
if __name__ == "__main__":
    url = input("Enter a URL to analyze: ")
    indicators = analyze_url_indicators(url)
    classification = classify(indicators)
    print(f"URL: {url}")
    print(f"Classification: {classification}")