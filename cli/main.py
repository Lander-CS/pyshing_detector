import argparse

from detector import analyze_url
from detector import analyze_domain
from detector import analyze_html
from detector import detect_typosquatting


# Peso de risco para cada tipo de indicador
RISK_WEIGHTS = {
    "keyword": 1,
    "domain_missing": 2,
    "html_issue": 1,
    "brand": 4,
    "typosquat": 5
}


def calculate_risk(indicators):

    score = 0

    for indicator in indicators:

        indicator = indicator.lower()

        if "keyword" in indicator:
            score += RISK_WEIGHTS["keyword"]

        elif "domain info not found" in indicator:
            score += RISK_WEIGHTS["domain_missing"]

        elif "brand name" in indicator:
            score += RISK_WEIGHTS["brand"]

        elif "similar to" in indicator:
            score += RISK_WEIGHTS["typosquat"]

        elif "html" in indicator:
            score += RISK_WEIGHTS["html_issue"]

    return min(score, 10)  # limite máximo 10


def run_analysis(url):

    print("\nAnalyzing URL...\n")

    indicators = []

    # URL analysis
    url_results = analyze_url(url)
    indicators.extend(url_results)

    # Domain analysis
    domain_results = analyze_domain(url)
    indicators.extend(domain_results)

    # HTML analysis
    html_results = analyze_html(url)
    indicators.extend(html_results)

    # Typosquatting analysis
    typo_results = detect_typosquatting(url)

    if typo_results["suspicious"]:
        indicators.extend(typo_results["indicators"])

    # calcular risco
    risk_score = calculate_risk(indicators)

    # mostrar resultados
    if indicators:

        print("[!] Potential phishing indicators found:\n")

        for i in indicators:
            print(f" - {i}")

    else:
        print("No obvious phishing indicators found.")

    print(f"\nAnalysis complete, total indicators found: {len(indicators)}")
    print(f"\nRisk level: {risk_score}/10")
    

def main():

    parser = argparse.ArgumentParser(description="Phishing URL Analyzer")

    parser.add_argument(
        "url",
        help="URL to analyze"
    )

    args = parser.parse_args()

    run_analysis(args.url)


if __name__ == "__main__":
    main()