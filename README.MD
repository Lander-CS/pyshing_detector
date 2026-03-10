
# Phishing URL Analyzer

![Cybersecurity](https://img.shields.io/badge/domain-cybersecurity-red)![Python](https://img.shields.io/badge/python-3.10+-blue)

A Python-based tool for detecting potential phishing websites by analyzing URLs, domains, HTML content, and typosquatting patterns.

This project simulates techniques used in real phishing detection engines and security tools.

## Features

- URL analysis
- Domain analysis
- HTML content inspection
- Typosquatting detection
- Brand name detection inside domains
- Risk scoring system (0–10)

## Detection Techniques

The analyzer searches for multiple phishing indicators such as:

- Suspicious keywords in URLs (login, verify, secure, update)
- Typosquatting domains similar to well-known services
- Brand names embedded inside domains
- Missing or suspicious domain information
- Suspicious HTML structures

Each indicator contributes to a weighted **risk score**.

## Example

Running the analyzer:

```bash
python -m cli.main http://g00glelogin.com
 ``` 
 [!] Potential phishing indicators found:

 - URL contains suspicious keyword: 'login'
 - Brand name 'google' detected inside domain
 - Domain 'g00glelogin.com' similar to 'google.com'

Analysis complete, total indicators found: 3

Risk level: 7/10
## Project Structure
```phishing-detector
│
├ detectors
│  ├ url_analyzer.py
│  ├ domain_analyzer.py
│  ├ html_analyzer.py
│  └ typosquatting.py
│
├ cli
│  └ main.py
│
├ README.md
└ requirements.txt
```
## InstalLation
Clone the repository
```
    git clone https://github.com/yourusername/phishing-analyzer
    
    cd phishing-analyzer
```


Install dependencies
```
pip install -r requirements.txt
```
## Usage
Run the detector from the command line
`python -m cli.main <url>`
Example:
`python -m cli.main https://paypal-login-security.xyz`


## Risk Score
The analyzer assigns a risk score from 0 to 10.
---
Score |	Risk Level|
0–2	  = Low|
3–5	  = Medium|
6–8	  = High|
9–10  = Critical|
---

## Educational Purpose

This tool was created for learning and research purposes in cybersecurity.
It demonstrates how phishing detection systems analyze:

- URL patterns
- domain characteristics
- HTML structure
- brand impersonation

## Future Improvements
Possible improvements include:

- Domain age detection via WHOIS
- Screenshot capture of analyzed pages
- Machine learning phishing classification
- Integration with threat intelligence feeds
- Web dashboard interface

### License
MIT License