import argparse


from detector import analyze_url
from detector import analyze_domain
from detector import analyze_html
from detector import detect_typosquatting

def run_analysis(url):
    print("\n Analyzing URL...\n")

    indicators = []
    risk_score = len(indicators)

    #URL analysis
    url_results = analyze_url(url)
    indicators.extend(url_results)

    #Domain analysis
    domain_results = analyze_domain(url)
    indicators.extend(domain_results)
    # HTML analysis
    html_results = analyze_html(url)
    indicators.extend(html_results)

    # Typosquatting
    typo_results = detect_typosquatting(url)
    if typo_results.get("suspicious"):
        indicators.append(
            f"Typosquatting detected (similar to {typo_results['closest_match']})"
        )
    
    # Print results
    if indicators:
        print("\n[!] Potential phishing indicators found:")
        for i in indicators:
            print(f" - {i}")
            print("\n Risk level: {}/10".format(risk_score))
    else:
        print("\nNo obvious phishing indicators found.")
    print("\nAnalysis complete, total indicators found: {}\n".format(len(indicators)))

def main():

    parser = argparse.ArgumentParser( description="Phishing URL Analyzer" )
    parser.add_argument( "url", help="URL to analyze" )
    args = parser.parse_args()
    run_analysis(args.url)
if __name__ == "__main__":
    main()
