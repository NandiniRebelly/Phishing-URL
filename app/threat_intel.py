"""
Threat Intelligence Module - External Feed Integration
Integrates with PhishTank, URLhaus, and Scamwave (if permitted).

SAFETY RULES:
- Never fetch the user-submitted URL content
- Respect robots.txt and Terms of Service
- All network calls have strict timeouts (<= 3s)
- Caching to prevent spamming sources
- Never log submitted URLs
"""

import os
import json
import time
import hashlib
import threading
from pathlib import Path
from typing import TypedDict, Optional
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
import requests

# Constants
DEFAULT_TIMEOUT = 3  # seconds
DATA_DIR = Path(__file__).parent.parent / "data"
USER_AGENT = "PhishDetector-Educational/0.2.0 (+https://github.com/educational-security-tool)"


class SourceResult(TypedDict):
    name: str
    result: str  # "hit" | "clear" | "unavailable" | "disabled" | "blocked_by_robots"
    note: str    # Short explanation of the result


class IntelDetails(TypedDict):
    phishtank: dict
    urlhaus: dict
    scamwave: dict


class IntelResult(TypedDict):
    known_bad: bool
    feed_hits: list[str]
    sources: list[SourceResult]
    details: IntelDetails


# In-memory cache with TTL
class TTLCache:
    """Thread-safe in-memory cache with TTL."""
    
    def __init__(self, default_ttl: int = 300):  # 5 minutes default
        self._cache: dict = {}
        self._lock = threading.Lock()
        self._default_ttl = default_ttl
    
    def _hash_key(self, key: str) -> str:
        """Hash key to avoid storing actual URLs."""
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def get(self, key: str) -> Optional[dict]:
        hashed = self._hash_key(key)
        with self._lock:
            if hashed in self._cache:
                entry = self._cache[hashed]
                if time.time() < entry['expires']:
                    return entry['value']
                else:
                    del self._cache[hashed]
        return None
    
    def set(self, key: str, value: dict, ttl: Optional[int] = None):
        hashed = self._hash_key(key)
        ttl = ttl or self._default_ttl
        with self._lock:
            self._cache[hashed] = {
                'value': value,
                'expires': time.time() + ttl
            }
    
    def clear(self):
        with self._lock:
            self._cache.clear()


# Global caches
_phishtank_cache = TTLCache(default_ttl=300)  # 5 min
_urlhaus_hosts: set = set()
_urlhaus_last_refresh: Optional[datetime] = None
_urlhaus_lock = threading.Lock()
_scamwave_hosts: set = set()
_scamwave_policy: str = "unknown"  # "allowed" | "disallowed" | "unknown"
_scamwave_last_refresh: Optional[datetime] = None
_scamwave_lock = threading.Lock()


def _get_env_bool(key: str, default: bool) -> bool:
    """Get boolean from environment variable."""
    val = os.environ.get(key, str(default)).lower()
    return val in ('true', '1', 'yes', 'on')


def _get_env_int(key: str, default: int) -> int:
    """Get integer from environment variable."""
    try:
        return int(os.environ.get(key, default))
    except ValueError:
        return default


# ============================================================================
# PhishTank Integration
# ============================================================================

def check_phishtank(url: str) -> dict:
    """
    Check URL against PhishTank database.
    Uses their checkurl API endpoint.
    
    Returns:
        {"in_database": bool, "verified": bool, "result": str, "note": str}
    """
    if not _get_env_bool("PHISHTANK_ENABLED", True):
        return {"in_database": False, "verified": False, "result": "disabled", "note": "PHISHTANK_ENABLED is false"}
    
    # Check cache first
    cached = _phishtank_cache.get(f"phishtank:{url}")
    if cached:
        return cached
    
    try:
        api_key = os.environ.get("PHISHTANK_APP_KEY", "")
        
        # PhishTank API endpoint
        api_url = "https://checkurl.phishtank.com/checkurl/"
        
        data = {
            "url": url,
            "format": "json"
        }
        if api_key:
            data["app_key"] = api_key
        
        headers = {
            "User-Agent": USER_AGENT
        }
        
        response = requests.post(
            api_url,
            data=data,
            headers=headers,
            timeout=DEFAULT_TIMEOUT
        )
        
        if response.status_code == 200:
            result_data = response.json()
            results = result_data.get("results", {})
            
            in_database = results.get("in_database", False)
            verified = results.get("verified", False) if in_database else False
            
            if in_database:
                note = "Verified phish" if verified else "In database (unverified)"
                result = {
                    "in_database": in_database,
                    "verified": verified,
                    "result": "hit",
                    "note": note
                }
            else:
                result = {
                    "in_database": False,
                    "verified": False,
                    "result": "clear",
                    "note": "Not in PhishTank database"
                }
        else:
            result = {"in_database": False, "verified": False, "result": "unavailable", "note": f"API returned {response.status_code}"}
        
        # Cache the result
        _phishtank_cache.set(f"phishtank:{url}", result, ttl=300)
        return result
        
    except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
        return {"in_database": False, "verified": False, "result": "unavailable", "note": "Network error or timeout"}


# ============================================================================
# URLhaus Integration
# ============================================================================

def _refresh_urlhaus_hostfile():
    """
    Download and parse URLhaus hostfile.
    Cached on disk with refresh interval.
    """
    global _urlhaus_hosts, _urlhaus_last_refresh
    
    if not _get_env_bool("URLHAUS_ENABLED", True):
        return
    
    refresh_hours = _get_env_int("URLHAUS_REFRESH_HOURS", 24)
    
    with _urlhaus_lock:
        # Check if refresh is needed
        if _urlhaus_last_refresh:
            if datetime.now() - _urlhaus_last_refresh < timedelta(hours=refresh_hours):
                return
        
        # Ensure data directory exists
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        hostfile_path = DATA_DIR / "urlhaus_hostfile.txt"
        timestamp_path = DATA_DIR / "urlhaus_timestamp.txt"
        
        # Check disk cache
        if hostfile_path.exists() and timestamp_path.exists():
            try:
                timestamp_str = timestamp_path.read_text().strip()
                cached_time = datetime.fromisoformat(timestamp_str)
                if datetime.now() - cached_time < timedelta(hours=refresh_hours):
                    # Load from disk cache
                    _urlhaus_hosts = set(
                        line.strip().lower()
                        for line in hostfile_path.read_text().splitlines()
                        if line.strip() and not line.startswith('#')
                    )
                    _urlhaus_last_refresh = cached_time
                    return
            except (ValueError, IOError):
                pass
        
        # Download fresh hostfile
        try:
            response = requests.get(
                "https://urlhaus.abuse.ch/downloads/hostfile/",
                headers={"User-Agent": USER_AGENT},
                timeout=DEFAULT_TIMEOUT
            )
            
            if response.status_code == 200:
                lines = response.text.splitlines()
                hosts = set()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Hostfile format: "127.0.0.1 malicious.domain.com"
                        parts = line.split()
                        if len(parts) >= 2:
                            hosts.add(parts[1].lower())
                
                _urlhaus_hosts = hosts
                _urlhaus_last_refresh = datetime.now()
                
                # Save to disk cache
                hostfile_path.write_text('\n'.join(sorted(hosts)))
                timestamp_path.write_text(_urlhaus_last_refresh.isoformat())
                
        except requests.RequestException:
            # If download fails, try to use existing cache
            if hostfile_path.exists():
                _urlhaus_hosts = set(
                    line.strip().lower()
                    for line in hostfile_path.read_text().splitlines()
                    if line.strip() and not line.startswith('#')
                )


def check_urlhaus(url: str) -> dict:
    """
    Check if URL's host is in URLhaus hostfile.
    
    Returns:
        {"host_hit": bool, "result": str, "note": str}
    """
    if not _get_env_bool("URLHAUS_ENABLED", True):
        return {"host_hit": False, "result": "disabled", "note": "URLHAUS_ENABLED is false"}
    
    # Ensure hostfile is loaded
    _refresh_urlhaus_hostfile()
    
    if not _urlhaus_hosts:
        return {"host_hit": False, "result": "unavailable", "note": "Hostfile not loaded"}
    
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        hostname = parsed.netloc.lower().split(':')[0]  # Remove port
        
        # Check exact match and parent domains
        parts = hostname.split('.')
        for i in range(len(parts)):
            check_host = '.'.join(parts[i:])
            if check_host in _urlhaus_hosts:
                return {"host_hit": True, "result": "hit", "note": f"Host matched: {check_host}"}
        
        return {"host_hit": False, "result": "clear", "note": "Not in URLhaus blocklist"}
        
    except Exception:
        return {"host_hit": False, "result": "unavailable", "note": "Error parsing URL"}


# ============================================================================
# Scamwave Integration (Ethical/Policy-Compliant)
# ============================================================================

def _check_scamwave_robots() -> bool:
    """
    Check if Scamwave robots.txt allows scraping /scammers/.
    Returns True if allowed, False otherwise.
    """
    try:
        response = requests.get(
            "https://scamwave.com/robots.txt",
            headers={"User-Agent": USER_AGENT},
            timeout=DEFAULT_TIMEOUT
        )
        
        if response.status_code != 200:
            return False  # Assume disallowed if can't check
        
        robots_txt = response.text.lower()
        
        # Simple robots.txt parser
        # Check for disallow rules that would block /scammers/
        current_agent_applies = False
        
        for line in robots_txt.splitlines():
            line = line.strip()
            if line.startswith('user-agent:'):
                agent = line.split(':', 1)[1].strip()
                current_agent_applies = (agent == '*' or 'phish' in agent.lower())
            elif current_agent_applies and line.startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path == '/' or path == '/scammers' or path == '/scammers/':
                    return False
        
        return True
        
    except requests.RequestException:
        return False  # Assume disallowed on error


def _refresh_scamwave_cache():
    """
    Refresh Scamwave cache if policy allows.
    Only scrapes if robots.txt permits.
    """
    global _scamwave_hosts, _scamwave_policy, _scamwave_last_refresh
    
    if not _get_env_bool("SCAMWAVE_ENABLED", False):
        _scamwave_policy = "disabled_by_config"
        return
    
    refresh_hours = _get_env_int("SCAMWAVE_REFRESH_HOURS", 24)
    
    with _scamwave_lock:
        # Check if refresh is needed
        if _scamwave_last_refresh:
            if datetime.now() - _scamwave_last_refresh < timedelta(hours=refresh_hours):
                return
        
        # Ensure data directory exists
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        cache_path = DATA_DIR / "scamwave_cache.json"
        
        # Check disk cache first
        if cache_path.exists():
            try:
                cache_data = json.loads(cache_path.read_text())
                cached_time = datetime.fromisoformat(cache_data.get("timestamp", ""))
                if datetime.now() - cached_time < timedelta(hours=refresh_hours):
                    _scamwave_hosts = set(cache_data.get("hosts", []))
                    _scamwave_policy = cache_data.get("policy", "unknown")
                    _scamwave_last_refresh = cached_time
                    
                    # If policy was disallowed, don't retry
                    if _scamwave_policy == "disallowed":
                        return
                    return
            except (json.JSONDecodeError, ValueError, IOError):
                pass
        
        # Check robots.txt compliance
        if not _check_scamwave_robots():
            _scamwave_policy = "disallowed"
            _scamwave_hosts = set()
            _scamwave_last_refresh = datetime.now()
            
            # Save policy decision to cache
            cache_path.write_text(json.dumps({
                "timestamp": _scamwave_last_refresh.isoformat(),
                "policy": "disallowed",
                "hosts": []
            }))
            return
        
        # Policy allows - attempt to fetch
        # First check if there's an API or downloadable dataset
        try:
            # Check for API endpoint or data download
            response = requests.get(
                "https://scamwave.com/api/",
                headers={"User-Agent": USER_AGENT},
                timeout=DEFAULT_TIMEOUT
            )
            
            if response.status_code == 200:
                # API exists, try to use it
                try:
                    api_data = response.json()
                    if isinstance(api_data, list):
                        hosts = set()
                        for entry in api_data:
                            if isinstance(entry, dict):
                                domain = entry.get("domain", "")
                                if domain:
                                    hosts.add(domain.lower())
                        _scamwave_hosts = hosts
                        _scamwave_policy = "allowed"
                        _scamwave_last_refresh = datetime.now()
                        
                        cache_path.write_text(json.dumps({
                            "timestamp": _scamwave_last_refresh.isoformat(),
                            "policy": "allowed",
                            "hosts": list(hosts)
                        }))
                        return
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            pass
        
        # No API available, try minimal page scrape with polite behavior
        try:
            response = requests.get(
                "https://scamwave.com/scammers/",
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html"
                },
                timeout=DEFAULT_TIMEOUT
            )
            
            if response.status_code == 200:
                # Extract domains using simple regex (no heavy parsing)
                import re
                # Look for domain patterns in the page
                domain_pattern = re.compile(
                    r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}',
                    re.IGNORECASE
                )
                
                found_domains = set()
                for match in domain_pattern.finditer(response.text):
                    domain = match.group(0).lower()
                    # Clean up the domain
                    if domain.startswith('http://'):
                        domain = domain[7:]
                    elif domain.startswith('https://'):
                        domain = domain[8:]
                    domain = domain.split('/')[0]
                    
                    # Filter out common non-scam domains
                    if not any(safe in domain for safe in [
                        'scamwave.com', 'google.com', 'facebook.com',
                        'twitter.com', 'youtube.com', 'github.com'
                    ]):
                        found_domains.add(domain)
                
                _scamwave_hosts = found_domains
                _scamwave_policy = "allowed"
                _scamwave_last_refresh = datetime.now()
                
                cache_path.write_text(json.dumps({
                    "timestamp": _scamwave_last_refresh.isoformat(),
                    "policy": "allowed",
                    "hosts": list(found_domains)
                }))
            else:
                _scamwave_policy = "unavailable"
                
        except requests.RequestException:
            _scamwave_policy = "unavailable"


def check_scamwave(url: str) -> dict:
    """
    Check if URL's host is in Scamwave scammer list.
    Respects robots.txt and site policies.
    
    Returns:
        {"host_hit": bool, "policy": str, "result": str, "note": str}
        
    Result values:
        - "disabled": SCAMWAVE_ENABLED is false
        - "blocked_by_robots": robots.txt disallows /scammers/
        - "unavailable": network/timeout/error
        - "clear": checked, no match
        - "hit": match found
    """
    if not _get_env_bool("SCAMWAVE_ENABLED", False):
        return {
            "host_hit": False,
            "policy": "disabled_by_config",
            "result": "disabled",
            "note": "SCAMWAVE_ENABLED is false"
        }
    
    # Ensure cache is loaded
    _refresh_scamwave_cache()
    
    if _scamwave_policy == "disallowed":
        return {
            "host_hit": False,
            "policy": "disallowed",
            "result": "blocked_by_robots",
            "note": "robots.txt disallows /scammers/"
        }
    
    if _scamwave_policy in ("unavailable", "unknown") or not _scamwave_hosts:
        return {
            "host_hit": False,
            "policy": _scamwave_policy,
            "result": "unavailable",
            "note": "Network error or timeout"
        }
    
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        hostname = parsed.netloc.lower().split(':')[0]
        
        # Check exact match and parent domains
        parts = hostname.split('.')
        for i in range(len(parts)):
            check_host = '.'.join(parts[i:])
            if check_host in _scamwave_hosts:
                return {
                    "host_hit": True,
                    "policy": "allowed",
                    "result": "hit",
                    "note": f"Host matched: {check_host}"
                }
        
        return {
            "host_hit": False,
            "policy": "allowed",
            "result": "clear",
            "note": "Checked, no match found"
        }
        
    except Exception:
        return {
            "host_hit": False,
            "policy": _scamwave_policy,
            "result": "unavailable",
            "note": "Error parsing URL"
        }


# ============================================================================
# Main Intel Check Function
# ============================================================================

def check_threat_intel(url: str) -> IntelResult:
    """
    Check URL against all enabled threat intelligence sources.
    
    Returns comprehensive intel result with source details.
    """
    # Run all checks
    phishtank_result = check_phishtank(url)
    urlhaus_result = check_urlhaus(url)
    scamwave_result = check_scamwave(url)
    
    # Compile results with notes
    sources: list[SourceResult] = [
        {
            "name": "PhishTank",
            "result": phishtank_result.get("result", "unavailable"),
            "note": phishtank_result.get("note", "")
        },
        {
            "name": "URLhaus",
            "result": urlhaus_result.get("result", "unavailable"),
            "note": urlhaus_result.get("note", "")
        },
        {
            "name": "Scamwave",
            "result": scamwave_result.get("result", "unavailable"),
            "note": scamwave_result.get("note", "")
        }
    ]
    
    # Determine hits
    feed_hits = []
    known_bad = False
    
    if phishtank_result.get("result") == "hit":
        feed_hits.append("PhishTank")
        known_bad = True
    
    if urlhaus_result.get("result") == "hit":
        feed_hits.append("URLhaus")
        known_bad = True
    
    if scamwave_result.get("result") == "hit":
        feed_hits.append("Scamwave")
        known_bad = True
    
    return IntelResult(
        known_bad=known_bad,
        feed_hits=feed_hits,
        sources=sources,
        details=IntelDetails(
            phishtank={
                "in_database": phishtank_result.get("in_database", False),
                "verified": phishtank_result.get("verified", False)
            },
            urlhaus={
                "host_hit": urlhaus_result.get("host_hit", False)
            },
            scamwave={
                "host_hit": scamwave_result.get("host_hit", False),
                "policy": scamwave_result.get("policy", "unknown")
            }
        )
    )


def clear_caches():
    """Clear all in-memory caches. Useful for testing."""
    global _urlhaus_hosts, _urlhaus_last_refresh
    global _scamwave_hosts, _scamwave_policy, _scamwave_last_refresh
    
    _phishtank_cache.clear()
    
    with _urlhaus_lock:
        _urlhaus_hosts = set()
        _urlhaus_last_refresh = None
    
    with _scamwave_lock:
        _scamwave_hosts = set()
        _scamwave_policy = "unknown"
        _scamwave_last_refresh = None
