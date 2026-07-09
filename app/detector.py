"""
Phishing URL Detector - URL String Analysis Only
Performs static analysis on URL structure without fetching remote content.
Aggressive scoring - prefers false positives over false negatives.
"""

import re
from urllib.parse import urlparse, unquote
from typing import TypedDict, Optional
import tldextract
import validators


class DetectionResult(TypedDict):
    score: int
    risk: str
    reasons: list[str]
    normalized_url: str
    signals_checked: list[str]


class FullDetectionResult(TypedDict):
    score: int
    risk: str
    reasons: list[str]
    normalized_url: str
    signals_checked: list[str]
    intel: dict


# Configurable suspicious TLDs (easily editable)
SUSPICIOUS_TLDS = frozenset([
    '.zip', '.mov', '.tk', '.ga', '.cf', '.gq', '.ml',
    '.top', '.work', '.click', '.link', '.win', '.racing',
    '.buzz', '.surf', '.monster', '.xyz', '.icu', '.cam'
])

# TLDs commonly abused when combined with brand impersonation
BRAND_IMPERSONATION_TLDS = frozenset([
    '.net', '.org', '.info', '.co', '.io', '.app', '.site', '.online',
    '.live', '.tech', '.cloud', '.digital', '.services', '.support'
])

# Brand keywords for impersonation detection
BRAND_KEYWORDS = frozenset([
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'capitalone',
    'venmo', 'zelle', 'coinbase', 'binance', 'stripe', 'steam', 'ebay',
    'github', 'gitlab', 'bitbucket', 'slack', 'zoom', 'docusign',
    'adobe', 'oracle', 'salesforce', 'intuit', 'quickbooks', 'turbotax'
])

# Financial/security keywords that are suspicious in hostnames
SECURITY_KEYWORDS = frozenset([
    'secure', 'security', 'bank', 'banking', 'update', 'verify',
    'verification', 'confirm', 'validate', 'authenticate', 'wallet',
    'payment', 'billing', 'invoice', 'refund', 'transfer', 'wire'
])

# Suspicious keywords in path/query - auth related
AUTH_PATH_KEYWORDS = frozenset([
    'login', 'signin', 'sign-in', 'sign_in', 'logon', 'signon',
    'password', 'passwd', 'pwd', 'auth', 'authenticate', 'oauth',
    'credential', 'credentials', 'reset', 'recover', 'recovery'
])

# Suspicious keywords in path/query - urgency/action
ACTION_PATH_KEYWORDS = frozenset([
    'verify', 'verification', 'confirm', 'validate', 'update',
    'suspend', 'suspended', 'locked', 'unlock', 'urgent', 'expire',
    'expired', 'expiring', 'alert', 'warning', 'action', 'required',
    'immediately', 'limited', 'restrict', 'restricted', 'unusual'
])

# Account-related keywords
ACCOUNT_KEYWORDS = frozenset([
    'account', 'accounts', 'myaccount', 'my-account', 'user', 'users',
    'profile', 'settings', 'billing', 'payment', 'invoice', 'order'
])


def normalize_url(url: str) -> str:
    """Normalize URL for consistent analysis."""
    url = url.strip()
    # Decode percent-encoded characters for analysis
    try:
        url = unquote(url)
    except Exception:
        pass
    return url


def analyze_url(url: str) -> DetectionResult:
    """
    Analyze a URL string for phishing indicators.
    Returns a deterministic, explainable risk assessment.
    Does NOT fetch remote content (SSRF prevention).
    
    Scoring is aggressive - prefers false positives over false negatives.
    """
    reasons: list[str] = []
    signals_checked: list[str] = []
    score = 0
    
    # Normalize the URL
    normalized = normalize_url(url)
    
    # Cap URL length for processing (defense in depth)
    if len(normalized) > 2048:
        normalized = normalized[:2048]
    
    # Check for valid URL format
    signals_checked.append('url_format')
    if not validators.url(normalized):
        # Try adding https:// if no scheme
        if not normalized.startswith(('http://', 'https://', 'ftp://')):
            test_url = 'https://' + normalized
            if validators.url(test_url):
                normalized = test_url
            else:
                return DetectionResult(
                    score=100,
                    risk='High',
                    reasons=['Invalid URL format - cannot parse'],
                    normalized_url=normalized,
                    signals_checked=['url_format']
                )
        else:
            return DetectionResult(
                score=100,
                risk='High',
                reasons=['Invalid URL format - malformed structure'],
                normalized_url=normalized,
                signals_checked=['url_format']
            )
    
    # Parse the URL
    try:
        parsed = urlparse(normalized)
    except Exception:
        return DetectionResult(
            score=100,
            risk='High',
            reasons=['URL parsing failed - potentially malicious encoding'],
            normalized_url=normalized,
            signals_checked=['url_format']
        )
    
    # Extract TLD information
    extracted = tldextract.extract(normalized)
    hostname = parsed.netloc.lower()
    path_and_query = (parsed.path + '?' + parsed.query if parsed.query else parsed.path).lower()
    domain_part = extracted.domain.lower() if extracted.domain else ''
    subdomain_lower = extracted.subdomain.lower() if extracted.subdomain else ''
    full_hostname = f'{subdomain_lower}.{domain_part}' if subdomain_lower else domain_part
    registrable_domain = f'{domain_part}.{extracted.suffix}'.lower() if domain_part and extracted.suffix else ''
    tld = '.' + extracted.suffix.lower() if extracted.suffix else ''
    
    # === DETECTION RULES ===
    
    # Rule 1: Host is an IP address (+30)
    signals_checked.append('ip_in_host')
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$|'  # IPv4
        r'^\[([a-fA-F0-9:]+)\](:\d+)?$'      # IPv6
    )
    host_no_port = hostname.split(':')[0] if ':' in hostname and not hostname.startswith('[') else hostname
    if ip_pattern.match(hostname) or re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host_no_port):
        score += 30
        reasons.append('Host is an IP address instead of domain name')
    
    # Rule 2: "@" in URL - credential injection attempt (+35)
    signals_checked.append('at_symbol')
    if '@' in parsed.netloc:
        score += 35
        reasons.append('URL contains @ symbol (potential credential obfuscation)')
    
    # Rule 3: Excessive subdomains >= 3 (+15)
    signals_checked.append('many_subdomains')
    subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
    subdomains = [s for s in subdomains if s]
    if len(subdomains) >= 3:
        score += 15
        reasons.append(f'Excessive subdomains ({len(subdomains)} levels) - may obscure true domain')
    
    # Rule 4: Very long URL >= 75 chars (+10)
    signals_checked.append('url_length')
    if len(normalized) >= 75:
        score += 10
        reasons.append(f'URL is unusually long ({len(normalized)} characters)')
    
    # Rule 5: Non-HTTPS scheme (+20)
    signals_checked.append('non_https')
    if parsed.scheme.lower() != 'https':
        score += 20
        reasons.append(f'Non-HTTPS scheme ({parsed.scheme}) - connection not encrypted')
    
    # Rule 6: Punycode / IDN domain (+30)
    signals_checked.append('punycode')
    if 'xn--' in hostname.lower():
        score += 30
        reasons.append('Internationalized domain (Punycode) - potential homograph attack')
    
    # Rule 7: Hyphens in domain or subdomain >= 2 (+15)
    signals_checked.append('hyphen_spam')
    domain_hyphen_count = domain_part.count('-')
    subdomain_hyphen_count = subdomain_lower.count('-')
    if domain_hyphen_count >= 2:
        score += 15
        reasons.append(f'Multiple hyphens in domain ({domain_hyphen_count}) - commonly used in phishing')
    elif subdomain_hyphen_count >= 1 and subdomain_lower:
        score += 10
        reasons.append(f'Hyphenated subdomain pattern - commonly used in phishing')
    
    # Rule 8: Security/financial keywords in hostname (+20 each, max 40)
    signals_checked.append('security_keywords_hostname')
    hostname_security_keywords = []
    for keyword in SECURITY_KEYWORDS:
        if keyword in full_hostname:
            hostname_security_keywords.append(keyword)
    if hostname_security_keywords:
        kw_score = min(len(hostname_security_keywords) * 20, 40)
        score += kw_score
        reasons.append(f'Security/financial keywords in hostname: {", ".join(hostname_security_keywords[:3])}')
    
    # Rule 9: Auth-related keywords in path (+20 each, max 40)
    signals_checked.append('auth_keywords_path')
    auth_keywords_found = []
    for keyword in AUTH_PATH_KEYWORDS:
        if keyword in path_and_query:
            auth_keywords_found.append(keyword)
    if auth_keywords_found:
        auth_score = min(len(auth_keywords_found) * 20, 40)
        score += auth_score
        reasons.append(f'Authentication keywords in path: {", ".join(auth_keywords_found[:3])}')
    
    # Rule 10: Urgency/action keywords in path (+15 each, max 30)
    signals_checked.append('urgency_keywords_path')
    action_keywords_found = []
    for keyword in ACTION_PATH_KEYWORDS:
        if keyword in path_and_query:
            action_keywords_found.append(keyword)
    if action_keywords_found:
        action_score = min(len(action_keywords_found) * 15, 30)
        score += action_score
        reasons.append(f'Urgency/action keywords in path: {", ".join(action_keywords_found[:3])}')
    
    # Rule 11: Keyword spam - multiple suspicious words in hostname (+25)
    signals_checked.append('keyword_spam_hostname')
    all_hostname_keywords = []
    for kw_set in [SECURITY_KEYWORDS, AUTH_PATH_KEYWORDS, ACCOUNT_KEYWORDS]:
        for keyword in kw_set:
            if keyword in full_hostname and keyword not in all_hostname_keywords:
                all_hostname_keywords.append(keyword)
    if len(all_hostname_keywords) >= 2:
        score += 25
        reasons.append(f'Multiple suspicious keywords in hostname ({len(all_hostname_keywords)}): {", ".join(all_hostname_keywords[:4])}')
    
    # Rule 12: Suspicious TLD (+20)
    signals_checked.append('suspicious_tld')
    if tld in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f'Suspicious top-level domain ({tld})')
    
    # Rule 13: Brand impersonation - brand in subdomain/hostname but not the real domain (+35)
    signals_checked.append('brand_mismatch')
    brand_found = None
    brand_location = None
    for brand in BRAND_KEYWORDS:
        brand_in_subdomain = brand in subdomain_lower
        brand_in_domain = brand in domain_part
        brand_in_path = brand in path_and_query
        
        # Check if this is the actual brand's domain
        is_real_brand = (brand == domain_part) or (domain_part.startswith(brand) and len(domain_part) <= len(brand) + 3)
        
        if (brand_in_subdomain or brand_in_domain or brand_in_path) and not is_real_brand:
            brand_found = brand
            if brand_in_subdomain:
                brand_location = 'subdomain'
            elif brand_in_domain:
                brand_location = 'domain'
            else:
                brand_location = 'path'
            break
    
    if brand_found:
        score += 35
        reasons.append(f'Brand impersonation: "{brand_found}" in {brand_location}, but domain is "{registrable_domain}"')
        
        # Additional penalty if using a commonly abused TLD with brand impersonation
        signals_checked.append('brand_tld_combo')
        if tld in BRAND_IMPERSONATION_TLDS:
            score += 15
            reasons.append(f'Brand impersonation combined with commonly abused TLD ({tld})')
    
    # Rule 14: URL contains double slashes in path (+10)
    signals_checked.append('double_slash_path')
    if '//' in parsed.path:
        score += 10
        reasons.append('Double slashes in URL path - potential obfuscation')
    
    # Rule 15: Unusual port number (+15)
    signals_checked.append('unusual_port')
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        score += 15
        reasons.append(f'Unusual port number ({parsed.port})')
    
    # Rule 16: Numbers mixed with text in domain (common in phishing) (+10)
    signals_checked.append('mixed_numbers_domain')
    if domain_part and re.search(r'[a-z]+\d+[a-z]+|\d+[a-z]+\d+', domain_part):
        score += 10
        reasons.append('Numbers mixed with text in domain - common phishing pattern')
    
    # Rule 17: Very short domain with suspicious path (+10)
    signals_checked.append('short_domain_suspicious_path')
    if domain_part and len(domain_part) <= 4 and (auth_keywords_found or action_keywords_found):
        score += 10
        reasons.append('Short domain combined with suspicious path keywords')
    
    # Cap score at 100
    score = min(score, 100)
    
    # Determine risk level with new thresholds
    # 0-29 = Low, 30-59 = Medium, 60-100 = High
    if score >= 60:
        risk = 'High'
    elif score >= 30:
        risk = 'Medium'
    else:
        risk = 'Low'
    
    # If no issues found, provide a positive reason
    if not reasons:
        reasons.append('No obvious phishing indicators detected')
    
    return DetectionResult(
        score=score,
        risk=risk,
        reasons=reasons,
        normalized_url=normalized,
        signals_checked=signals_checked
    )


def analyze_url_with_intel(url: str, intel_result: Optional[dict] = None) -> FullDetectionResult:
    """
    Analyze URL with both heuristics and threat intelligence.
    
    Scoring enforcement:
    - If intel.sources contains any result == "hit", force score >= 90 and risk="High"
    - Add reason: "Matched known malicious source: <source>"
    """
    # Get heuristic analysis
    heuristic = analyze_url(url)
    
    score = heuristic['score']
    risk = heuristic['risk']
    reasons = list(heuristic['reasons'])
    
    # Check for any intel source hits
    if intel_result:
        sources = intel_result.get('sources', [])
        hit_sources = [s['name'] for s in sources if s.get('result') == 'hit']
        
        if hit_sources:
            # Add reason for each hit source
            for source_name in hit_sources:
                reasons.insert(0, f'Matched known malicious source: {source_name}')
            
            # Force high risk with score >= 90
            score = max(score, 90)
            risk = 'High'
    
    # Cap at 100
    score = min(score, 100)
    
    return FullDetectionResult(
        score=score,
        risk=risk,
        reasons=reasons,
        normalized_url=heuristic['normalized_url'],
        signals_checked=heuristic['signals_checked'],
        intel=intel_result or {
            'known_bad': False,
            'feed_hits': [],
            'sources': [],
            'details': {}
        }
    )
