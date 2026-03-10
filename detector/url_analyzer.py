import re
from urllib.parse import urlparse


def analyze_url(url: str) -> int:
    """Analyze the given URL for potential phishing indicators.

    This function computes a risk score based on several heuristics:
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
    int
        A numeric score indicating the level of suspicion (higher is riskier).
    """
    score = 0

    # penalize URLs longer than 75 characters as they may hide malicious content
    if len(url) > 75:
        score += 1

    # check for IP address usage, which is uncommon for legitimate sites
    ip_pattern = r"(http|https)://\d+\.\d+\.\d+\.\d+"
    if re.match(ip_pattern, url):
        score += 2

    # count subdomains; too many may indicate obfuscation
    domain = urlparse(url).netloc
    if domain.count('.') > 3:
        score += 1

    # list of keywords often associated with phishing attempts
    suspicious_keywords = [
        'login',
        'secure',
        'account',
        'update',
        'free',
        'verify',
        'password',
        'bank',
        'confirm',
        'security'
    ]

    # increment score if any suspicious keyword is found
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            score += 1
            break  # stop after first match to avoid over-penalizing

    return score


def classify(score: int) -> str:
    """Classify the URL based on the computed score.

    Parameters
    ----------
    score : int
        The risk score from analyze_url.

    Returns
    -------
    str
        A classification string: "Possibly phishing" or "Possibly legitimate".
    """
    if score >= 3:
        return "Possibly phishing"
    else:
        return "Possibly legitimate"


# example usage: prompt user for a URL and display analysis
if __name__ == "__main__":
    url = input("Enter a URL to analyze: ")
    score = analyze_url(url)
    classification = classify(score)
    print(f"URL: {url}")
    print(f"Score: {score}")
    print(f"Classification: {classification}")