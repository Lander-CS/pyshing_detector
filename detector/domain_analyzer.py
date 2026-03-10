from urllib.parse import urlparse
import whois
from datetime import datetime

SUSPICIOUS_DOMAIN_AGE_DAYS = 180


def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc


def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
       print(f"Error fetching domain info: {e}")
       return None


def calculate_domain_age(domain_info):

    creation_date = domain_info.creation_date

    if not creation_date:
        return None

    if isinstance(creation_date, list):
        creation_date = creation_date[0]
#remove timezone info if exists
    if creation_date.tzinfo is not None:
        creation_date = creation_date.replace(tzinfo=None)
    today = datetime.now()

    age = (today - creation_date).days

    return age


def analyze_domain(url):
  
    indicators = []

    domain = extract_domain(url)

    info = get_domain_info(domain)



    if not info:
        indicators.append("Domain info not found")
        return indicators
   

    age = calculate_domain_age(info)

    if age is not None and age < SUSPICIOUS_DOMAIN_AGE_DAYS:
        indicators.append(f"Domain age is {age} days, which is suspiciously young")

    elif not info.registrar:
        indicators.append("No registrar information found")
    elif age > SUSPICIOUS_DOMAIN_AGE_DAYS:
        indicators.append(f"Domain age is {age} days, which is relatively old")
    elif info.name_servers:
        indicators.append(f"Domain has {len(info.name_servers)} name servers")
    elif info.name_servers in ['cheap', '.ru', '.cn', '.tk']:
        indicators.append("Domain has an unusual name server configuration")
    elif len(info.name_servers) < 2:
        indicators.append("Domain has less than 2 name servers, which is suspicious")
    elif info.tld:
        indicators.append(f"Domain TLD is {info.tld}")
    elif info.tld in ['xyz', 'top', 'club', 'online', 'site']:
        indicators.append(f"Domain uses a less common TLD: {info.tld}, possibly phishing")

    return indicators
