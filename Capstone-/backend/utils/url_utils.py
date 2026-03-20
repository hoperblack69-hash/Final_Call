from urllib.parse import urlparse
import unicodedata

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "bitly.com",
}

SCRIPT_RANGES = [
    (0x0041, 0x007A, "Latin"),        # Basic Latin + Latin-1 Supplement subset
    (0x00C0, 0x00FF, "Latin"),        # Latin-1 Supplement
    (0x0100, 0x017F, "Latin"),        # Latin Extended-A
    (0x0180, 0x024F, "Latin"),        # Latin Extended-B
    (0x0370, 0x03FF, "Greek"),        # Greek
    (0x0400, 0x04FF, "Cyrillic"),     # Cyrillic
    (0x0530, 0x058F, "Armenian"),     # Armenian
    (0x0590, 0x05FF, "Hebrew"),       # Hebrew
    (0x0600, 0x06FF, "Arabic"),       # Arabic
    (0x0900, 0x097F, "Devanagari"),   # Devanagari
    (0x3040, 0x30FF, "Kana"),         # Hiragana + Katakana
    (0x4E00, 0x9FFF, "Han"),          # CJK Unified Ideographs
    (0xAC00, 0xD7AF, "Hangul"),       # Hangul Syllables
]


def _extract_hostname(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _extract_root_domain(hostname: str) -> str:
    if not hostname:
        return ""

    parts = hostname.split('.')
    if len(parts) < 2:
        return hostname

    tld = parts[-1]
    if tld in {"uk", "au", "in"} and len(parts) >= 3 and parts[-2] in {"co", "ac", "gov", "edu"}:
        return '.'.join(parts[-3:])

    return '.'.join(parts[-2:])


def _decode_idna(hostname: str) -> str:
    if not hostname:
        return ""

    try:
        labels = hostname.split('.')
        decoded_labels = []

        for label in labels:
            if label.startswith('xn--'):
                decoded_labels.append(label.encode('ascii').decode('idna'))
            else:
                decoded_labels.append(label)

        return '.'.join(decoded_labels)

    except Exception:
        try:
            return hostname.encode('ascii', errors='ignore').decode('idna')
        except Exception:
            return hostname


def _char_script(char: str) -> str:
    if not char or char == '-' or char == '.':
        return 'Common'

    try:
        cp = ord(char)
    except TypeError:
        return 'Unknown'

    for start, end, label in SCRIPT_RANGES:
        if start <= cp <= end:
            return label

    category = unicodedata.category(char)
    if category.startswith('L'):
        return 'OtherLetter'
    if category.startswith('N'):
        return 'Number'

    return 'Common'


def _is_homograph_label(label: str) -> bool:
    scripts = set()
    for ch in label:
        script = _char_script(ch)
        if script in {'Common', 'Number'}:
            continue
        scripts.add(script)

        if len(scripts) > 1:
            return True

    return False


def is_shortener_domain(hostname: str) -> bool:
    if not hostname:
        return False

    root = _extract_root_domain(hostname)
    return root in SHORTENER_DOMAINS


def is_punycode_domain(hostname: str) -> bool:
    if not hostname:
        return False

    if 'xn--' in hostname:
        return True

    decoded = _decode_idna(hostname)
    return decoded != hostname


def is_homograph_domain(hostname: str) -> bool:
    if not hostname:
        return False

    decoded = _decode_idna(hostname)
    for label in decoded.split('.'):
        if _is_homograph_label(label):
            return True

    return False


def url_threat_flags(url: str) -> dict:
    hostname = _extract_hostname(url)
    decoded_hostname = _decode_idna(hostname)

    flags = {
        'punycode': is_punycode_domain(hostname),
        'homograph': is_homograph_domain(hostname),
        'shortener': is_shortener_domain(hostname),
    }

    return {
        'normalized_url': normalize_url(url),
        'hostname': hostname,
        'decoded_hostname': decoded_hostname,
        'flags': flags,
    }


def compute_url_heuristic_score(url: str) -> float:
    flags = url_threat_flags(url)['flags']

    score = 0.0
    if flags['punycode']:
        score += 0.15
    if flags['homograph']:
        score += 0.25
    if flags['shortener']:
        score += 0.2

    return min(score, 1.0)


def normalize_url(url: str, return_flags: bool = False):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    normalized_url = parsed.geturl()

    if return_flags:
        # Only compute flags if explicitly requested
        normalized_url_flags = url_threat_flags(normalized_url)['flags']
        return normalized_url, normalized_url_flags
    return normalized_url