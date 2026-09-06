"""URL triage with offline rules and explicitly enabled reputation agents."""
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, unquote
from app.reputation import run_agents

VERSION = '2.1.0'
LIMITATIONS = [
    'The local scorer is deterministic lexical logic, not the trained model from the research notebooks.',
    'Submitted websites are never fetched. DNS, content, redirects, and certificates are not inspected.',
    'Optional reputation providers return third-party observations, which may be stale, incomplete, or unavailable.',
    'The score is a transparent rule total, not a probability. Low concern does not establish safety.',
]


def normalize(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError('Enter a URL to analyze.')
    raw = raw.strip()
    if len(raw) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in raw) or '\\' in raw:
        raise ValueError('Use a URL under 2,048 characters without whitespace, controls, or backslashes.')
    if '://' not in raw:
        raw = 'https://' + raw
    try:
        parts = urlsplit(raw)
        if parts.scheme.lower() not in ('http', 'https'):
            raise ValueError('Only HTTP and HTTPS URLs are supported.')
        if parts.username is not None or parts.password is not None:
            raise ValueError('Remove embedded credentials before submitting the URL.')
        if not parts.hostname:
            raise ValueError('A public hostname is required.')
        host = parts.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        port = parts.port
    except (UnicodeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address:
        if not address.is_global or address.is_multicast or (address.version == 6 and address.ipv4_mapped and not address.ipv4_mapped.is_global):
            raise ValueError('Private, reserved, loopback, and non-public IP addresses are not supported.')
    else:
        labels = host.split('.')
        if len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels):
            raise ValueError('Enter a valid public hostname.')
        if labels[-1] in ('localhost', 'local', 'internal', 'lan', 'home', 'invalid', 'test') or host.endswith('.home.arpa'):
            raise ValueError('Local and internal hostnames are not supported.')
        if labels[-1].isdigit() or re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*', host):
            raise ValueError('Alternative numeric IP formats are not supported.')
    authority = '[' + host + ']' if ':' in host else host
    if port:
        authority += ':' + str(port)
    # Values and fragments may contain tokens. They are never persisted or returned.
    keys = [k[:80] for k, _ in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=100)]
    query = urlencode([(k, '[redacted]') for k in keys])
    normalized = urlunsplit((parts.scheme.lower(), authority, parts.path or '/', query, ''))
    return {'url': normalized, 'host': host, 'scheme': parts.scheme.lower(), 'port': port,
            'path': parts.path, 'query_keys': keys, 'is_ip': address is not None,
            'original_length': len(raw), 'has_fragment': bool(parts.fragment)}


def _lookup_url(raw, target):
    """Validated URL for opt-in reputation APIs; this value is never returned or persisted."""
    candidate = raw.strip()
    if '://' not in candidate:
        candidate = 'https://' + candidate
    parts = urlsplit(candidate)
    saved = urlsplit(target['url'])
    return urlunsplit((target['scheme'], saved.netloc, parts.path or '/', parts.query, ''))


def _unified_decision(score, provider_results):
    completed = [item for item in provider_results if item['status'] == 'completed']
    positives = [item['agent'] for item in completed if item.get('malicious')]
    if positives:
        return {'label': 'likely_malicious', 'title': 'Likely malicious',
                'explanation': 'Threat intelligence flagged this target: ' + ', '.join(positives) + '.'}
    if score >= 50:
        return {'label': 'likely_malicious', 'title': 'Likely malicious',
                'explanation': 'The local deterministic scorer found a high concentration of phishing-like URL signals.'}
    if score >= 20:
        return {'label': 'needs_review', 'title': 'Needs review',
                'explanation': 'The local scorer found warning signals, but available evidence is not decisive.'}
    if completed:
        return {'label': 'likely_benign', 'title': 'Likely benign',
                'explanation': 'The local score is low and the completed reputation agents returned no malicious match. This is not a safety guarantee.'}
    return {'label': 'low_concern', 'title': 'Low concern',
            'explanation': 'Only the deterministic local scorer ran and found few lexical warning signals; no reputation verdict is available.'}


def analyze(raw, credentials=None, reputation_transport=None):
    target = normalize(raw)
    lookup_url = _lookup_url(raw, target)
    findings = []
    def evidence(code, title, detail, weight):
        findings.append({'id': code, 'title': title, 'detail': detail, 'weight': weight,
                         'severity': 'high' if weight >= 25 else 'medium' if weight else 'info'})

    plan = ['transport', 'host_structure', 'path_intent']
    if target['query_keys']:
        plan.append('query_inspection')
    if 'xn--' in target['host']:
        plan.append('internationalized_hostname')
    stage = lambda name, detail: {'name': name, 'status': 'completed', 'detail': detail}
    stages = [stage('Intake', 'Validated syntax and rejected explicit local/private targets. The submitted website is never fetched.'),
              stage('Plan', 'Selected local tools from URL features: ' + ', '.join(plan) + '. Reputation agents run only when keys are supplied.')]
    if target['scheme'] == 'http':
        evidence('transport.http', 'Unencrypted URL scheme', 'HTTP does not provide transport encryption. This alone does not establish phishing.', 15)
    else:
        evidence('transport.https', 'HTTPS scheme present', 'HTTPS is present in the URL text; the certificate has not been checked. Phishing sites can use HTTPS.', 0)
    host = target['host']
    if target['is_ip']:
        evidence('host.ip', 'IP address used as host', 'A numeric public address replaces a readable domain. This warrants context, but can be legitimate.', 20)
    if not target['is_ip'] and len(host.split('.')) >= 5:
        evidence('host.depth', 'Deeply nested hostname', 'The hostname has at least five labels, which can make the actual destination harder to read.', 15)
    if host.count('-') >= 3:
        evidence('host.hyphens', 'Many hostname separators', 'Three or more hyphens are present. Campaign URLs sometimes use this pattern; legitimate names can too.', 10)
    if len(host) > 60:
        evidence('host.length', 'Long hostname', 'The hostname exceeds 60 characters and deserves closer inspection.', 10)
    words = set(re.findall(r'[a-z]+', unquote(host + '/' + target['path']).lower()))
    intent = sorted(words & {'login', 'signin', 'verify', 'password', 'account', 'secure', 'update', 'wallet', 'payment'})
    if intent:
        evidence('path.intent', 'Account or payment language', 'Observed terms: ' + ', '.join(intent) + '. These are common on both real and deceptive pages.', min(25, len(intent) * 5))
    brands = sorted(words & {'paypal', 'microsoft', 'apple', 'google', 'amazon', 'netflix'})
    # Conservative exact-domain checks, not an inferred public-suffix implementation.
    for brand in brands:
        if host != brand + '.com' and not host.endswith('.' + brand + '.com'):
            evidence('host.brand.' + brand, 'Brand term outside its common .com domain',
                     f'The URL contains “{brand}” but the host is not {brand}.com or its subdomain. Regional and partner domains can produce false positives.', 25)
    if target['original_length'] > 180:
        evidence('url.length', 'Long URL', 'The supplied URL is over 180 characters. Long URLs can obscure a destination but are often legitimate.', 5)
    if target['port'] and target['port'] not in (80, 443):
        evidence('transport.port', 'Nonstandard web port', 'The URL specifies a port other than 80 or 443.', 10)
    if 'query_inspection' in plan:
        redirect = sorted(set(k.lower() for k in target['query_keys']) & {'redirect', 'url', 'next', 'return', 'continue', 'redirect_uri'})
        if redirect:
            evidence('query.redirect', 'Navigation parameter present', 'Potential destination keys: ' + ', '.join(redirect) + '. Values are redacted and redirects are not followed.', 10)
        else:
            evidence('query.redacted', 'Query values redacted', 'Only parameter names were inspected; query values are not stored.', 0)
    if 'internationalized_hostname' in plan:
        evidence('host.idn', 'Internationalized hostname', 'Punycode labels are present. Internationalized names are legitimate but can sometimes resemble other domains.', 15)
    score = min(100, sum(x['weight'] for x in findings))
    level = 'high' if score >= 50 else 'moderate' if score >= 20 else 'low'
    required = level != 'low'
    credentials = credentials or {}
    providers = run_agents(lookup_url, host, credentials, reputation_transport) if reputation_transport else run_agents(lookup_url, host, credentials)
    for item in providers:
        findings.append({'id': 'provider.' + item['agent'].lower().replace(' ', '_'), 'title': item['agent'],
                         'detail': item['summary'], 'weight': 0,
                         'severity': 'high' if item.get('malicious') else ('info' if item['status'] == 'completed' else 'medium'),
                         'source': 'external_reputation', 'status': item['status']})
    unified = _unified_decision(score, providers)
    if unified['label'] == 'likely_malicious':
        level = 'high'
        required = True
    elif unified['label'] == 'needs_review':
        level = 'moderate'
        required = True
    agent_count = len(plan) + len(providers)
    stages += [stage('Investigate', f'Executed {len(plan)} local tools and {len(providers)} optional reputation agents; collected {len(findings)} evidence items.'),
               stage('Evaluate', f'Unified decision: {unified["title"]}. Local rule total {score}/100; provider results are separate signals.'),
               {'name': 'Human review', 'status': 'waiting' if required else 'optional',
                'detail': 'A person must assess context before resolving this case.' if required else 'Optional review; limited lexical evidence cannot establish safety.'}]
    return {'id': str(uuid.uuid4()), 'created_at': datetime.now(timezone.utc).isoformat(),
            'url': target['url'], 'host': host, 'mode': 'local rules + optional reputation', 'workflow_version': VERSION,
            'score': score, 'risk': level, 'review_required': required,
            'status': 'awaiting_review' if required else 'analysis_complete', 'review': None,
            'tools': plan, 'agent_count': agent_count, 'provider_results': providers,
            'unified_decision': unified, 'stages': stages, 'evidence': findings, 'limitations': LIMITATIONS}
