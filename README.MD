# Phishing URL Analyzer

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