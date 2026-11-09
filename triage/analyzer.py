
"""Static email inspection: no link visits or attachment execution."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[^\s<>\"'()]+", re.I)

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
}

URGENT = (
    'urgent', 'immediately', 'act now',
    'within 24 hours', 'verify your account',
    'password expires', 'suspended'
)

CREDENTIAL = (
    'password', 'login', 'sign in',
    'verify your account', 'credentials', 'otp'
)

DANGEROUS_EXT = (
    '.exe', '.scr', '.js', '.vbs', '.hta',
    '.ps1', '.bat', '.cmd', '.iso', '.lnk'
)


def _auth_status(value: str, mechanism: str) -> str:
    match = re.search(
        r'(?<![a-z])' + re.escape(mechanism)
        + r'\s*=\s*([a-z]+)',
        value.lower()
    )
    return match.group(1) if match else 'unknown'


def analyze_email(data: bytes) -> dict:

    if len(data) > 10_000_000:
        raise ValueError('File exceeds the 10 MB safety limit.')

    msg = BytesParser(
        policy=policy.default
    ).parsebytes(data)

    sender = str(msg.get('From', ''))
    sender_address = parseaddr(sender)[1]

    reply_address = parseaddr(
        str(msg.get('Reply-To', ''))
    )[1]

    subject = str(msg.get('Subject', ''))

    auth = ' '.join(
        str(x) for x in msg.get_all(
            'Authentication-Results', []
        )
    )

    auth_results = {
        m: _auth_status(auth, m)
        for m in ('spf', 'dkim', 'dmarc')
    }

    plain_parts = []
    html_parts = []
    attachments = []

    parts = msg.walk() if msg.is_multipart() else [msg]

    for part in parts:

        if part.is_multipart():
            continue

        filename = part.get_filename()
        content_type = part.get_content_type()

        if filename or part.get_content_disposition() == 'attachment':

            payload = part.get_payload(decode=True) or b''

            attachments.append({
                'filename': filename or '(unnamed)',
                'content_type': content_type,
                'size_bytes': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest()
            })

        elif content_type in ('text/plain', 'text/html'):

            try:
                content = part.get_content()

            except (UnicodeError, LookupError, ValueError):
                content = (
                    part.get_payload(decode=True) or b''
                ).decode('utf-8', errors='replace')

            if content_type == 'text/html':
                html_parts.append(str(content))
            else:
                plain_parts.append(str(content))

    body = '\n'.join(plain_parts or html_parts)

    urls = sorted({
        u.rstrip('.,;!?]')
        for u in URL_RE.findall(
            '\n'.join(plain_parts + html_parts)
        )
    })

    indicators = []
    score = 0

    def flag(reason: str, points: int, detail: str) -> None:

        nonlocal score

        score += points

        indicators.append({
            'reason': reason,
            'points': points,
            'detail': detail
        })

    # Email authentication checks
    for mechanism, status in auth_results.items():

        if status in ('fail', 'softfail', 'temperror', 'permerror'):

            points = 14 if mechanism == 'dmarc' else 8

            flag(
                f'{mechanism.upper()} result',
                points,
                status
            )

    # Reply-To mismatch
    if (
        reply_address
        and sender_address
        and reply_address.lower() != sender_address.lower()
    ):
        flag(
            'Reply-To differs from sender',
            12,
            'Verify whether the difference is legitimate.'
        )

    combined = (subject + ' ' + body).lower()

    # Social engineering language
    if any(term in combined for term in URGENT):
        flag(
            'Urgency or pressure language',
            12,
            'Possible social engineering.'
        )

    # Credential harvesting language
    if any(term in combined for term in CREDENTIAL):
        flag(
            'Credential-related language',
            12,
            'Email references sign-in, password, or account verification.'
        )

    # URL analysis
    for url in urls[:30]:

        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname or ''

            # New rule 1: URL shorteners
            if hostname.lower() in URL_SHORTENERS:
                flag(
                    'Shortened URL',
                    10,
                    url
                )

            # New rule 2: HTTP URL
            if parsed.scheme.lower() == 'http':
                flag(
                    'Insecure HTTP URL',
                    8,
                    url
                )

            # New rule 3: Long URLs
            if len(url) > 200:
                flag(
                    'Excessively long URL',
                    8,
                    url
                )

            # Embedded username or password
            if parsed.username or parsed.password:
                flag(
                    'URL embeds user information',
                    20,
                    url
                )

            # IP-based URL
            try:
                ipaddress.ip_address(hostname)

                flag(
                    'URL uses IP address',
                    18,
                    url
                )

            except ValueError:
                pass

            # Punycode domain
            if hostname.startswith('xn--') or '.xn--' in hostname:
                flag(
                    'Punycode domain',
                    14,
                    url
                )

            # Excessive subdomains
            if len(hostname.split('.')) >= 5:
                flag(
                    'Deeply nested subdomain',
                    8,
                    url
                )

        except ValueError:
            flag(
                'Malformed URL',
                8,
                url
            )

    # Many links
    if len(urls) > 5:
        flag(
            'Many URLs',
            6,
            f'{len(urls)} unique URLs'
        )

    # Suspicious attachment extensions
    for attachment in attachments:

        if attachment['filename'].lower().endswith(DANGEROUS_EXT):

            flag(
                'Potentially executable attachment',
                25,
                attachment['filename']
            )

    # Final risk score
    score = min(100, score)

    if score >= 60:
        classification = 'High'

    elif score >= 30:
        classification = 'Medium'

    else:
        classification = 'Low'

    # SOC recommendation
    if classification == 'High':
        disposition = (
            'Escalate for analyst review; '
            'do not interact with content.'
        )

    elif classification == 'Medium':
        disposition = (
            'Review indicators and validate sender context.'
        )

    else:
        disposition = (
            'No strong static indicators; '
            'continue routine verification.'
        )

    return {
        'subject': subject,
        'sender': sender,
        'sender_address': sender_address,
        'reply_to': reply_address,
        'date': str(msg.get('Date', '')),
        'authentication': auth_results,
        'urls': urls,
        'attachments': attachments,
        'indicators': indicators,
        'score': score,
        'classification': classification,
        'recommendation': disposition,
        'sha256_email': hashlib.sha256(data).hexdigest(),
        'body_preview': body[:1200]
    }
