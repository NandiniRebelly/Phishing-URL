"""
Phishing URL Detector - Flask Routes
"""

from flask import Blueprint, request, render_template, abort, current_app
from flask_limiter import Limiter
from app.detector import analyze_url_with_intel
from app.threat_intel import check_threat_intel

bp = Blueprint('main', __name__)


def get_limiter() -> Limiter:
    """Get the limiter instance from the current app."""
    return current_app.limiter


@bp.route('/')
def index():
    """Serve the main UI."""
    return render_template('index.html')


@bp.route('/healthz')
def healthz():
    """Health check endpoint."""
    return {'status': 'ok', 'version': '0.1.0'}


@bp.route('/check', methods=['POST'])
def check_url():
    """
    Analyze a URL for phishing indicators.
    Accepts JSON: {"url": "..."}
    Returns JSON with score, risk level, and reasons.
    """
    # Get limiter and apply rate limit
    limiter = get_limiter()
    
    # Apply rate limit decorator dynamically
    @limiter.limit("10/minute")
    def rate_limited_check():
        # Require JSON content type
        if not request.is_json:
            abort(415)
        
        # Parse JSON body
        try:
            data = request.get_json(force=False, silent=False)
        except Exception:
            abort(400, description='Invalid JSON payload')
        
        if not data or not isinstance(data, dict):
            abort(400, description='Request body must be a JSON object')
        
        # Extract and validate URL
        url = data.get('url')
        if not url:
            abort(400, description='Missing required field: url')
        
        if not isinstance(url, str):
            abort(400, description='Field "url" must be a string')
        
        # URL length limit (defense against DoS)
        if len(url) > 2048:
            abort(400, description='URL exceeds maximum length of 2048 characters')
        
        # Get threat intelligence (cached, no SSRF - never fetches URL content)
        intel_result = check_threat_intel(url)
        
        # Analyze the URL with heuristics + threat intel
        result = analyze_url_with_intel(url, intel_result)
        
        return {
            'score': result['score'],
            'risk': result['risk'],
            'reasons': result['reasons'],
            'normalized_url': result['normalized_url'],
            'signals_checked': result['signals_checked'],
            'intel': result['intel']
        }
    
    return rate_limited_check()
