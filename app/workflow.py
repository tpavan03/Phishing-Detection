"""Offline, tool-selecting URL triage. No DNS, network requests, or model weights."""
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, unquote

VERSION = '1.0.0'
LIMITATIONS = [
    'Offline lexical heuristics; this is not the trained model from the research notebooks.',
    'No DNS, website content, redirects, reputation feeds, or certificate verification are performed.',
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


def analyze(raw):
    target = normalize(raw)
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
    stages = [stage('Intake', 'Validated syntax and rejected explicit local/private targets. No network access.'),
              stage('Plan', 'Selected tools from URL features: ' + ', '.join(plan) + '.')]
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
    stages += [stage('Investigate', f'Executed {len(plan)} offline tools; collected {len(findings)} evidence items.'),
               stage('Evaluate', f'Rule total {score}/100 → {level} concern. Thresholds: moderate ≥20; high ≥50.'),
               {'name': 'Human review', 'status': 'waiting' if required else 'optional',
                'detail': 'A person must assess context before resolving this case.' if required else 'Optional review; limited lexical evidence cannot establish safety.'}]
    return {'id': str(uuid.uuid4()), 'created_at': datetime.now(timezone.utc).isoformat(),
            'url': target['url'], 'host': host, 'mode': 'offline rules', 'workflow_version': VERSION,
            'score': score, 'risk': level, 'review_required': required,
            'status': 'awaiting_review' if required else 'analysis_complete', 'review': None,
            'tools': plan, 'stages': stages, 'evidence': findings, 'limitations': LIMITATIONS}
