from urllib.parse import urlparse
import Levenshtein


# list of well-known domains attackers often mimic via typosquatting
TARGET_DOMAINS = [
    "google.com",
    "facebook.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "instagram.com",
    "twitter.com",
    "linkedin.com",
    "netflix.com",
]


def extract_domain(url: str) -> str:
    """Return a normalized domain name for the given URL.

    The function uses :mod:`urllib.parse` to parse the URL and then
    lower-cases the network location.  A leading ``www.`` prefix is removed
    so that ``www.google.com`` and ``google.com`` are treated equivalently.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def find_closest_domain(domain: str, targets: list[str]) -> tuple[str | None, int]:
    """Find the target domain with the smallest Levenshtein distance.

    Parameters
    ----------
    domain : str
        The domain name to compare.
    targets : list[str]
        A list of candidate domains to measure against.

    Returns
    -------
    (closest_domain, distance)
        ``closest_domain`` is ``None`` if ``targets`` is empty, otherwise the
        target with the lowest edit distance.  ``distance`` is the numeric
        Levenshtein distance.
    """
    closest_domain = None
    smallest_distance = float("inf")

    for target in targets:
        distance = Levenshtein.distance(domain, target)
        if distance < smallest_distance:
            smallest_distance = distance
            closest_domain = target

    return closest_domain, smallest_distance


def detect_typosquatting(url: str) -> dict:
    """Analyze ``url`` for possible typosquatting.

    The function returns a dictionary containing a ``suspicious`` flag and an
    optional ``indicator`` message describing the reason.  A domain is marked
    suspicious if it is within an edit distance of 2 from a known target but
    not identical.
    """
    domain = extract_domain(url)
    closest, distance = find_closest_domain(domain, TARGET_DOMAINS)

    result = {"suspicious": False, "indicator": None}

    # edit distance cutoff chosen heuristically; adjust as needed
    if closest and distance <= 2 and domain != closest:
        result["suspicious"] = True
        result["indicator"] = (
            f"Domain '{domain}' is very similar to '{closest}' (distance {distance}), "
            "which may indicate typosquatting."
        )

    return result
