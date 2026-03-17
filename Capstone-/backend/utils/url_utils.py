from urllib.parse import urlparse

def normalize_url(url: str):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    return parsed.geturl()