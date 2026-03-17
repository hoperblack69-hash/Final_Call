import os
import asyncio

import httpx

VT_API_KEY = os.environ.get(
    'VT_API_KEY',
    '83b57f6c4a3c1eb88cf2ad2761d7912519d108f63d553e87b923699db94eee98',
)
BASE_URL = 'https://www.virustotal.com/api/v3/'


async def submit_url(url: str) -> str:
    headers = {'x-apikey': VT_API_KEY}
    data = {'url': url}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(BASE_URL + 'urls', headers=headers, data=data)
        response.raise_for_status()
        return response.json()['data']['id']


async def get_analysis(analysis_id: str) -> dict:
    headers = {'x-apikey': VT_API_KEY}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(BASE_URL + f'analyses/{analysis_id}', headers=headers)
        response.raise_for_status()
        return response.json()


async def scan(url: str) -> dict:
    analysis_id = await submit_url(url)

    # Poll for completion
    for _ in range(30):
        analysis = await get_analysis(analysis_id)
        status = analysis.get('data', {}).get('attributes', {}).get('status')
        if status == 'completed':
            break
        await asyncio.sleep(2)
    else:
        raise Exception('VirusTotal scan timeout')

    stats = analysis.get('data', {}).get('attributes', {}).get('stats', {})
    malicious = stats.get('malicious', 0)
    total = sum(stats.values())

    return {
        'malicious': malicious,
        'suspicious': stats.get('suspicious', 0),
        'harmless': stats.get('harmless', 0),
        'undetected': stats.get('undetected', 0),
        'total_engines': total,
        'scan_url': f'https://www.virustotal.com/gui/url/{analysis_id}/detection',
        'threat_names': [],
    }
