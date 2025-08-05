from urllib.parse import urlparse
import re
import pandas as pd

# Optional: Load CSV dataset if exists
try:
    phishing_urls = pd.read_csv("phishing_url_detector/phishing_data.csv")['url'].tolist()
except:
    phishing_urls = []

def is_phishing(url):
    score = 0

    if url in phishing_urls:
        return True

    if '@' in url:
        score += 1

    if url.count('-') > 3:
        score += 1

    if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url):
        score += 1

    if not url.startswith("https://"):
        score += 1

    if url.count('.') > 5:
        score += 1

    bad_keywords = ['login', 'verify', 'secure', 'account', 'bank', 'confirm']
    if any(word in url.lower() for word in bad_keywords):
        score += 1

    return score >= 2