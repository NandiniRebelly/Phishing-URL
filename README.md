# Phishing URL Detector

A defensive, educational web application that analyzes URLs for potential phishing indicators. This tool performs **static URL string analysis only** - it does NOT fetch remote content (SSRF prevention).


## Features

- **URL Structure Analysis**: Examines URL components for common phishing patterns
- **Threat Intelligence Integration**: Checks against PhishTank, URLhaus, and Scamwave feeds
- **Risk Scoring**: Returns a 0-100 score with Low/Medium/High risk classification
- **Explainable Results**: Provides clear, human-readable reasons for each detection
- **Security Hardened**: Rate limiting, request size limits, security headers, JSON-only API
- **Clean UI**: Dark "cyber" themed interface for easy use

## Detection Rules

The detector checks for the following indicators:

| Indicator | Description |
|-----------|-------------|
| IP Address Host | Domain is an IP address instead of hostname |
| @ Symbol | URL contains @ (credential obfuscation) |
| Excessive Subdomains | 3+ subdomain levels |
| Long URL | 75+ characters |
| Non-HTTPS | Connection not encrypted |
| Punycode/IDN | Internationalized domain (homograph attack risk) |
| Excessive Hyphens | 3+ hyphens in domain name |
| Suspicious Keywords | login, verify, secure, account, bank, password, etc. |
| Suspicious TLDs | .zip, .mov, .tk, .ga, .cf, .gq, .ml, etc. |
| Brand Impersonation | Brand keyword in subdomain/path with different domain |

## Threat Intelligence Feeds

The detector integrates with external threat intelligence feeds to enhance detection. All feed integrations are optional and can be enabled/disabled via environment variables.

### Supported Feeds

| Feed | Description | Default |
|------|-------------|---------|
| **PhishTank** | Community-driven phishing URL database | Enabled |
| **URLhaus** | Malware URL blocklist from abuse.ch | Enabled |
| **Scamwave** | Scam domain database (if robots.txt permits) | Disabled |

### Environment Variables

```bash
# PhishTank
PHISHTANK_ENABLED=true          # Enable/disable PhishTank lookups
PHISHTANK_APP_KEY=your_key      # Optional: API key for higher rate limits

# URLhaus
URLHAUS_ENABLED=true            # Enable/disable URLhaus lookups
URLHAUS_REFRESH_HOURS=24        # How often to refresh the hostfile (default: 24h)

# Scamwave
SCAMWAVE_ENABLED=false          # Enable/disable Scamwave lookups (disabled by default)
SCAMWAVE_REFRESH_HOURS=24       # How often to refresh the cache (default: 24h)
```

### Privacy & Safety

- **URLs are never fetched**: Only URL strings are analyzed, never the content
- **URLs are never logged**: User-submitted URLs are not stored or logged
- **Caching prevents spam**: Results are cached to avoid spamming external feeds
- **Timeouts enforced**: All network calls have a 3-second timeout
- **robots.txt respected**: Scamwave integration checks robots.txt before scraping
- **Thread-safe**: All feed operations are thread-safe for concurrent requests

## Installation

```bash
# Clone or navigate to the project
cd phish-detector

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=term-missing
```

## Running the Application

```bash
# Start the Flask development server
flask --app app run --host 127.0.0.1 --port 5001

# The application will be available at:
# http://127.0.0.1:5001
```

## API Endpoints

### GET /
Serves the web UI.

### GET /healthz
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

### POST /check
Analyze a URL for phishing indicators.

**Request:**
```json
{
  "url": "https://example.com/path"
}
```

**Response:**
```json
{
  "score": 25,
  "risk": "Medium",
  "reasons": [
    "Non-HTTPS scheme (http) - connection not encrypted",
    "Suspicious keywords in URL path: login, verify"
  ],
  "normalized_url": "http://example.com/login/verify",
  "signals_checked": ["url_format", "ip_in_host", "at_symbol", "..."],
  "intel": {
    "known_bad": false,
    "feed_hits": [],
    "sources": [
      {"name": "PhishTank", "result": "no_hit"},
      {"name": "URLhaus Hostfile", "result": "no_hit"},
      {"name": "Scamwave", "result": "unavailable"}
    ],
    "details": {}
  }
}
```

**Error Response:**
```json
{
  "error": "bad_request",
  "message": "Missing required field: url",
  "status": 400
}
```

## Security Features

- **JSON-only API**: POST /check requires `Content-Type: application/json`
- **Request Size Limit**: Maximum 2KB request body
- **URL Length Cap**: Maximum 2048 characters
- **Rate Limiting**: 10 requests/minute per IP
- **Security Headers**: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- **No CORS Wildcards**: Strict same-origin policy
- **No Content Fetching**: URL string analysis only (SSRF prevention)
- **No Logging of URLs**: User input is never logged

## Project Structure

```
phish-detector/
├── app/
│   ├── __init__.py      # Flask app factory
│   ├── routes.py        # API endpoints
│   ├── detector.py      # URL analysis logic
│   ├── threat_intel.py  # Threat intelligence integrations
│   ├── templates/
│   │   └── index.html   # Web UI
│   └── static/
│       ├── style.css    # Dark cyber theme
│       └── app.js       # Frontend logic
├── data/                # Cached threat intel data (auto-created)
├── tests/
│   ├── conftest.py      # Pytest fixtures
│   ├── test_detector.py # Unit tests for detector
│   ├── test_routes.py   # Integration tests for API
│   └── test_threat_intel.py # Tests for threat intel module
├── requirements.txt
└── README.md
```

## Disclaimer

This is an **educational phishing awareness tool**. It is designed to help users understand URL-based phishing indicators and should NOT be used as the sole means of determining URL safety. The tool:

- Does NOT guarantee detection of all phishing attempts
- Does NOT fetch or analyze page content
- Is for educational purposes only
- Should be used responsibly and ethically

## License

MIT License - For educational purposes only.
