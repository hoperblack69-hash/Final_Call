import os

import httpx

GOOGLE_API_KEY = os.environ.get(
    'GOOGLE_API_KEY',
    'AIzaSyAb4dcChWkY2eUJRCEvrkqw6MDh-F8fOhA',
)
API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'


async def check(url: str) -> dict:
    payload = {
        'client': {
            'clientId': 'phishing-detector',
            'clientVersion': '1.0'
        },
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }

    params = {'key': GOOGLE_API_KEY}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(API_URL, json=payload, params=params)
        response.raise_for_status()
        data = response.json()

    if 'matches' in data:
        threat_types = [match['threatType'] for match in data['matches']]
        return {
            'is_safe': False,
            'threat_types': threat_types,
            'platform_types': []
        }

    return {
        'is_safe': True,
        'threat_types': [],
        'platform_types': []
    }
