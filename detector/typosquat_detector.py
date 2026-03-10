from urllib.parse import urlparse
import Levenshtein


TARGET_DOMAINS = [
    "google.com",
    "facebook.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
]

BRANDS = [
    "google",
    "paypal",
    "facebook",
    "amazon",
    "microsoft",
    "apple",
]


HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "@": "a"
}


def normalize(text: str):

    for fake, real in HOMOGLYPHS.items():
        text = text.replace(fake, real)

    return text


def extract_domain(url: str):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def get_sld(domain: str):

    return domain.split(".")[0]


def find_closest_domain(domain: str, targets):

    closest_domain = None
    smallest_distance = float("inf")

    domain_sld = normalize(get_sld(domain))

    for target in targets:

        target_sld = normalize(get_sld(target))

        distance = Levenshtein.distance(domain_sld, target_sld)

        if distance < smallest_distance:

            smallest_distance = distance
            closest_domain = target

    return closest_domain, smallest_distance


def contains_brand(domain):

    indicators = []

    domain_sld = normalize(get_sld(domain))

    for brand in BRANDS:

        if brand in domain_sld:
            indicators.append(
                f"Brand name '{brand}' detected inside domain"
            )

    return indicators


def detect_typosquatting(url: str):

    domain = extract_domain(url)

    indicators = []

    closest, distance = find_closest_domain(domain, TARGET_DOMAINS)

    if closest and distance <= 3 and domain != closest:

        indicators.append(
            f"Domain '{domain}' similar to '{closest}' (distance {distance})"
        )

    brand_hits = contains_brand(domain)

    indicators.extend(brand_hits)

    return {
        "suspicious": len(indicators) > 0,
        "indicators": indicators
    }