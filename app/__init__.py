"""
Phishing URL Detector - Flask Application Factory
"""

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def create_app(testing: bool = False) -> Flask:
    """Application factory for Flask app."""
    app = Flask(__name__)
    
    # Configuration
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024  # 2KB request size limit
    app.config['TESTING'] = testing
    
    # Rate limiting configuration
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[],
        storage_uri="memory://",
    )
    
    # Store limiter on app for access in routes
    app.limiter = limiter
    
    # Register blueprints/routes
    from app.routes import bp
    app.register_blueprint(bp)
    
    # Security headers middleware
    @app.after_request
    def add_security_headers(response):
        # Content Security Policy - strict same-origin
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self';"
        )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # No CORS headers = strict same-origin (no wildcard)
        return response
    
    # Global JSON error handlers
    @app.errorhandler(400)
    def bad_request(e):
        return {
            'error': 'bad_request',
            'message': str(e.description) if hasattr(e, 'description') else 'Bad request',
            'status': 400
        }, 400
    
    @app.errorhandler(404)
    def not_found(e):
        return {
            'error': 'not_found',
            'message': 'The requested resource was not found',
            'status': 404
        }, 404
    
    @app.errorhandler(405)
    def method_not_allowed(e):
        return {
            'error': 'method_not_allowed',
            'message': 'The method is not allowed for the requested URL',
            'status': 405
        }, 405
    
    @app.errorhandler(413)
    def request_entity_too_large(e):
        return {
            'error': 'payload_too_large',
            'message': 'Request payload exceeds the 2KB limit',
            'status': 413
        }, 413
    
    @app.errorhandler(415)
    def unsupported_media_type(e):
        return {
            'error': 'unsupported_media_type',
            'message': 'Content-Type must be application/json',
            'status': 415
        }, 415
    
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return {
            'error': 'rate_limit_exceeded',
            'message': 'Rate limit exceeded. Maximum 10 requests per minute.',
            'status': 429
        }, 429
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return {
            'error': 'internal_server_error',
            'message': 'An internal server error occurred',
            'status': 500
        }, 500
    
    return app
