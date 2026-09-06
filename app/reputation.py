"""Optional reputation agents with fixed provider endpoints and bounded responses."""
import base64
import json
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

VT_ROOT = 'https://www.virustotal.com/api/v3'
GSB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 1_000_000


class ProviderError(Exception):
    """A safe, user-facing provider failure without response or credential details."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_json(request, timeout=TIMEOUT_SECONDS):
    """Network transport isolated for tests; callers only construct fixed endpoints."""
    try:
        with build_opener(_NoRedirect).open(request, timeout=timeout) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                raise ProviderError('Provider response exceeded the 1 MB safety limit.')
            return json.loads(payload)
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise ProviderError('Provider rejected the API key.') from None
        if exc.code == 404:
            raise ProviderError('No existing provider report was found.') from None
        if exc.code == 429:
            raise ProviderError('Provider rate limit reached; offline analysis is still available.') from None
        raise ProviderError(f'Provider returned HTTP {exc.code}.') from None
    except (URLError, TimeoutError, OSError):
        raise ProviderError('Provider was unavailable or timed out; offline analysis is still available.') from None
    except (json.JSONDecodeError, UnicodeError):
        raise ProviderError('Provider returned an unreadable response.') from None


def _stats(payload):
    attributes = payload.get('data', {}).get('attributes', {})
    values = attributes.get('last_analysis_stats', {})
    try:
        return {name: max(0, int(values.get(name, 0))) for name in ('malicious', 'suspicious', 'harmless', 'undetected')}
    except (AttributeError, TypeError, ValueError):
        raise ProviderError('Provider returned an unexpected report format.') from None


def virustotal_url(url, api_key, transport=_read_json):
    identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    endpoint = VT_ROOT + '/urls/' + identifier
    request = Request(endpoint, headers={'Accept': 'application/json', 'x-apikey': api_key})
    stats = _stats(transport(request))
    return {'agent': 'VirusTotal URL', 'status': 'completed', 'kind': 'url_reputation', 'stats': stats,
            'malicious': stats['malicious'] > 0 or stats['suspicious'] > 0,
            'summary': f"{stats['malicious']} malicious and {stats['suspicious']} suspicious engine verdicts."}


def virustotal_domain(host, api_key, transport=_read_json):
    endpoint = VT_ROOT + '/domains/' + quote(host, safe='')
    request = Request(endpoint, headers={'Accept': 'application/json', 'x-apikey': api_key})
    payload = transport(request)
    stats = _stats(payload)
    try:
        reputation = int(payload.get('data', {}).get('attributes', {}).get('reputation', 0))
    except (AttributeError, TypeError, ValueError):
        raise ProviderError('Provider returned an unexpected report format.') from None
    return {'agent': 'VirusTotal domain', 'status': 'completed', 'kind': 'domain_reputation', 'stats': stats,
            'reputation': reputation,
            'malicious': stats['malicious'] > 0 or stats['suspicious'] > 0 or reputation < 0,
            'summary': f"{stats['malicious']} malicious, {stats['suspicious']} suspicious; community reputation {reputation}."}


def google_safe_browsing(url, api_key, transport=_read_json):
    # Google v4 requires the key as a query parameter. It is never returned or persisted here.
    endpoint = GSB_ENDPOINT + '?' + urlencode({'key': api_key})
    body = json.dumps({'client': {'clientId': 'phishscope-local-demo', 'clientVersion': '2.1.0'},
                       'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                                      'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'],
                                      'threatEntries': [{'url': url}]}}).encode()
    request = Request(endpoint, data=body, method='POST', headers={'Accept': 'application/json', 'Content-Type': 'application/json'})
    matches = transport(request).get('matches', [])
    types = sorted({str(match.get('threatType', 'UNKNOWN')) for match in matches if isinstance(match, dict)})
    return {'agent': 'Google Safe Browsing', 'status': 'completed', 'kind': 'safe_browsing',
            'malicious': bool(matches), 'matches': types,
            'summary': ('Matched threat lists: ' + ', '.join(types) + '.') if types else 'No matching threat list entry was returned.'}


def run_agents(url, host, credentials, transport=_read_json):
    """Run only explicitly credentialed agents. Failures become bounded status objects."""
    specs = []
    if credentials.get('virustotal'):
        specs += [(virustotal_url, (url, credentials['virustotal'])),
                  (virustotal_domain, (host, credentials['virustotal']))]
    if credentials.get('google_safe_browsing'):
        specs.append((google_safe_browsing, (url, credentials['google_safe_browsing'])))
    results = []
    for agent, args in specs:
        try:
            results.append(agent(*args, transport=transport))
        except (ProviderError, AttributeError, KeyError, TypeError, ValueError) as exc:
            name = {'virustotal_url': 'VirusTotal URL', 'virustotal_domain': 'VirusTotal domain',
                    'google_safe_browsing': 'Google Safe Browsing'}[agent.__name__]
            summary = str(exc) if isinstance(exc, ProviderError) else 'Provider returned an unexpected report format.'
            results.append({'agent': name, 'status': 'unavailable', 'malicious': False, 'summary': summary})
    return results
