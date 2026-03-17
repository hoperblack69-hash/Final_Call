import re
from typing import List, Tuple


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance (edit distance) between two strings."""
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, start=1):
        curr_row = [i]
        for j, c2 in enumerate(s2, start=1):
            insert_cost = curr_row[j - 1] + 1
            delete_cost = prev_row[j] + 1
            replace_cost = prev_row[j - 1] + (0 if c1 == c2 else 1)
            curr_row.append(min(insert_cost, delete_cost, replace_cost))
        prev_row = curr_row
    return prev_row[-1]


def is_lookalike_domain(domain: str, known_brands: List[str]) -> Tuple[bool, str, int]:
    """Detect if a domain is a lookalike of a known brand using edit distance."""
    # Normalize domain to base label (remove subdomains and tld)
    parts = domain.lower().split('.')
    if len(parts) == 0:
        return False, "", 0

    base = parts[0]
    best_brand = ""
    # use a large int to match return type expectations
    best_dist = 10**6

    for brand in known_brands:
        dist = levenshtein_distance(base, brand.lower())
        if dist < best_dist:
            best_dist = dist
            best_brand = brand

    is_lookalike = best_dist <= 2 and best_brand != ""
    return is_lookalike, best_brand, best_dist


def extract_urls(text: str, max_urls: int = 10) -> List[str]:
    """Extract URLs from arbitrary email body text (plain or HTML)."""
    if not text:
        return []

    # Find href links in HTML
    href_pattern = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)
    urls = href_pattern.findall(text)

    # Find plain URLs
    url_pattern = re.compile(r'(https?://[^\s"\'>]+|www\.[^\s"\'>]+)', re.IGNORECASE)
    urls += url_pattern.findall(text)

    # Normalize and dedupe while preserving order
    seen = set()
    results = []
    for u in urls:
        normalized = u.strip()
        if normalized.lower().startswith('www.'):
            normalized = 'http://' + normalized
        if normalized not in seen:
            seen.add(normalized)
            results.append(normalized)
        if len(results) >= max_urls:
            break

    return results


def normalize_email(raw_email: str) -> dict:
    """Extract sender, subject, and body from a raw email string."""
    if not raw_email:
        return {"sender": "", "subject": "", "body": ""}

    sender = ""
    subject = ""
    body = raw_email

    # Simple parsing for common headers
    sender_match = re.search(r"^From:\s*(.+)$", raw_email, re.IGNORECASE | re.MULTILINE)
    subject_match = re.search(r"^Subject:\s*(.+)$", raw_email, re.IGNORECASE | re.MULTILINE)

    if sender_match:
        sender = sender_match.group(1).strip()
    if subject_match:
        subject = subject_match.group(1).strip()

    # Attempt to isolate body past the first blank line
    parts = re.split(r"\r?\n\r?\n", raw_email, maxsplit=1)
    if len(parts) > 1:
        body = parts[1]

    return {"sender": sender, "subject": subject, "body": body}
