"""
Pytest fixtures for Phishing URL Detector tests.
"""

import pytest
from app import create_app


@pytest.fixture
def app():
    """Create application for testing."""
    app = create_app(testing=True)
    app.config['TESTING'] = True
    yield app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create test CLI runner."""
    return app.test_cli_runner()
