"""
Unit tests for the Threat Intelligence module.
Uses mocking to avoid actual network calls.
"""

import pytest
from unittest.mock import patch, MagicMock
import json
import os


class TestPhishTank:
    """Tests for PhishTank integration."""

    def test_phishtank_disabled_returns_disabled(self):
        """When PHISHTANK_ENABLED=false, should return disabled."""
        with patch.dict(os.environ, {"PHISHTANK_ENABLED": "false"}):
            from app.threat_intel import check_phishtank, clear_caches
            clear_caches()
            
            result = check_phishtank("https://example.com")
            assert result["result"] == "disabled"
            assert result["in_database"] == False
            assert "note" in result

    @patch("app.threat_intel.requests.post")
    def test_phishtank_hit_returns_hit(self, mock_post):
        """When PhishTank returns in_database=true, should return hit."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {
                "in_database": True,
                "verified": True
            }
        }
        mock_post.return_value = mock_response
        
        with patch.dict(os.environ, {"PHISHTANK_ENABLED": "true"}):
            from app.threat_intel import check_phishtank, clear_caches
            clear_caches()
            
            result = check_phishtank("https://malicious.com/phish")
            assert result["result"] == "hit"
            assert result["in_database"] == True
            assert result["verified"] == True
            assert "note" in result

    @patch("app.threat_intel.requests.post")
    def test_phishtank_no_hit_returns_clear(self, mock_post):
        """When PhishTank returns in_database=false, should return clear."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {
                "in_database": False,
                "verified": False
            }
        }
        mock_post.return_value = mock_response
        
        with patch.dict(os.environ, {"PHISHTANK_ENABLED": "true"}):
            from app.threat_intel import check_phishtank, clear_caches
            clear_caches()
            
            result = check_phishtank("https://example.com")
            assert result["result"] == "clear"
            assert result["in_database"] == False

    @patch("app.threat_intel.requests.post")
    def test_phishtank_network_error_returns_unavailable(self, mock_post):
        """When network error occurs, should return unavailable."""
        import requests
        mock_post.side_effect = requests.RequestException("Network error")
        
        with patch.dict(os.environ, {"PHISHTANK_ENABLED": "true"}):
            from app.threat_intel import check_phishtank, clear_caches
            clear_caches()
            
            result = check_phishtank("https://example.com")
            assert result["result"] == "unavailable"

    @patch("app.threat_intel.requests.post")
    def test_phishtank_caches_results(self, mock_post):
        """Results should be cached to avoid repeated API calls."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": {
                "in_database": False,
                "verified": False
            }
        }
        mock_post.return_value = mock_response
        
        with patch.dict(os.environ, {"PHISHTANK_ENABLED": "true"}):
            from app.threat_intel import check_phishtank, clear_caches
            clear_caches()
            
            # First call
            result1 = check_phishtank("https://example.com")
            # Second call should use cache
            result2 = check_phishtank("https://example.com")
            
            # Should only call API once
            assert mock_post.call_count == 1
            assert result1 == result2


class TestURLhaus:
    """Tests for URLhaus integration."""

    def test_urlhaus_disabled_returns_disabled(self):
        """When URLHAUS_ENABLED=false, should return disabled."""
        with patch.dict(os.environ, {"URLHAUS_ENABLED": "false"}):
            from app.threat_intel import check_urlhaus, clear_caches
            clear_caches()
            
            result = check_urlhaus("https://example.com")
            assert result["result"] == "disabled"
            assert "note" in result

    @patch("app.threat_intel._refresh_urlhaus_hostfile")
    def test_urlhaus_host_match_returns_hit(self, mock_refresh):
        """When host is in URLhaus list, should return hit."""
        import app.threat_intel as ti
        
        # Manually set the hosts for testing
        with ti._urlhaus_lock:
            ti._urlhaus_hosts = {"malicious.com", "evil.net"}
        
        with patch.dict(os.environ, {"URLHAUS_ENABLED": "true"}):
            result = ti.check_urlhaus("https://malicious.com/path")
            assert result["result"] == "hit"
            assert result["host_hit"] == True
            assert "note" in result
        
        # Cleanup
        ti.clear_caches()

    @patch("app.threat_intel._refresh_urlhaus_hostfile")
    def test_urlhaus_no_match_returns_clear(self, mock_refresh):
        """When host is not in URLhaus list, should return clear."""
        import app.threat_intel as ti
        
        # Manually set the hosts for testing
        with ti._urlhaus_lock:
            ti._urlhaus_hosts = {"malicious.com"}
        
        with patch.dict(os.environ, {"URLHAUS_ENABLED": "true"}):
            result = ti.check_urlhaus("https://example.com/path")
            assert result["result"] == "clear"
            assert result["host_hit"] == False
        
        # Cleanup
        ti.clear_caches()

    @patch("app.threat_intel._refresh_urlhaus_hostfile")
    def test_urlhaus_subdomain_match_returns_hit(self, mock_refresh):
        """Subdomain of malicious host should also return hit."""
        import app.threat_intel as ti
        
        # Manually set the hosts for testing
        with ti._urlhaus_lock:
            ti._urlhaus_hosts = {"malicious.com"}
        
        with patch.dict(os.environ, {"URLHAUS_ENABLED": "true"}):
            result = ti.check_urlhaus("https://sub.malicious.com/path")
            assert result["result"] == "hit"
        
        # Cleanup
        ti.clear_caches()


class TestScamwave:
    """Tests for Scamwave integration."""

    def test_scamwave_disabled_returns_disabled(self):
        """Scamwave should return disabled when SCAMWAVE_ENABLED is false."""
        with patch.dict(os.environ, {"SCAMWAVE_ENABLED": "false"}):
            from app.threat_intel import check_scamwave, clear_caches
            clear_caches()
            
            result = check_scamwave("https://example.com")
            assert result["result"] == "disabled"
            assert result["policy"] == "disabled_by_config"
            assert "note" in result
            assert "SCAMWAVE_ENABLED" in result["note"]

    def test_scamwave_disabled_by_default(self):
        """Scamwave should be disabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove SCAMWAVE_ENABLED if set
            os.environ.pop("SCAMWAVE_ENABLED", None)
            
            from app.threat_intel import check_scamwave, clear_caches
            clear_caches()
            
            result = check_scamwave("https://example.com")
            assert result["result"] == "disabled"
            assert result["policy"] == "disabled_by_config"

    @patch("app.threat_intel._check_scamwave_robots")
    @patch("app.threat_intel._refresh_scamwave_cache")
    def test_scamwave_blocked_by_robots_returns_blocked_by_robots(self, mock_refresh, mock_robots):
        """When robots.txt disallows, should return blocked_by_robots."""
        import app.threat_intel as ti
        
        # Set the policy to disallowed
        with ti._scamwave_lock:
            ti._scamwave_policy = "disallowed"
            ti._scamwave_hosts = set()
        
        with patch.dict(os.environ, {"SCAMWAVE_ENABLED": "true"}):
            result = ti.check_scamwave("https://example.com")
            assert result["result"] == "blocked_by_robots"
            assert result["policy"] == "disallowed"
            assert "note" in result
            assert "robots.txt" in result["note"]
        
        # Cleanup
        ti.clear_caches()

    @patch("app.threat_intel._refresh_scamwave_cache")
    def test_scamwave_hit_forces_high_risk(self, mock_refresh):
        """Scamwave hit should result in High risk with score >= 90."""
        import app.threat_intel as ti
        from app.detector import analyze_url_with_intel
        
        # Set up Scamwave to return hit
        with ti._scamwave_lock:
            ti._scamwave_policy = "allowed"
            ti._scamwave_hosts = {"scam-domain.com"}
        
        with patch.dict(os.environ, {"SCAMWAVE_ENABLED": "true"}):
            scamwave_result = ti.check_scamwave("https://scam-domain.com/path")
            assert scamwave_result["result"] == "hit"
            
            # Now test with analyze_url_with_intel
            intel_result = {
                "known_bad": True,
                "feed_hits": ["Scamwave"],
                "sources": [
                    {"name": "PhishTank", "result": "clear", "note": ""},
                    {"name": "URLhaus", "result": "clear", "note": ""},
                    {"name": "Scamwave", "result": "hit", "note": "Host matched"}
                ],
                "details": {}
            }
            
            result = analyze_url_with_intel("https://scam-domain.com/path", intel_result)
            assert result["risk"] == "High"
            assert result["score"] >= 90
            assert any("Scamwave" in r for r in result["reasons"])
        
        # Cleanup
        ti.clear_caches()

    @patch("app.threat_intel._refresh_scamwave_cache")
    def test_scamwave_clear_returns_clear(self, mock_refresh):
        """When host is not in Scamwave list, should return clear."""
        import app.threat_intel as ti
        
        # Set up Scamwave with some hosts
        with ti._scamwave_lock:
            ti._scamwave_policy = "allowed"
            ti._scamwave_hosts = {"other-scam.com"}
        
        with patch.dict(os.environ, {"SCAMWAVE_ENABLED": "true"}):
            result = ti.check_scamwave("https://example.com/path")
            assert result["result"] == "clear"
            assert result["host_hit"] == False
            assert "note" in result
        
        # Cleanup
        ti.clear_caches()

    def test_scamwave_disabled_does_not_affect_risk(self):
        """When Scamwave is disabled, it should not affect the risk score."""
        from app.detector import analyze_url_with_intel
        
        intel_result = {
            "known_bad": False,
            "feed_hits": [],
            "sources": [
                {"name": "PhishTank", "result": "clear", "note": ""},
                {"name": "URLhaus", "result": "clear", "note": ""},
                {"name": "Scamwave", "result": "disabled", "note": "SCAMWAVE_ENABLED is false"}
            ],
            "details": {}
        }
        
        result = analyze_url_with_intel("https://example.com", intel_result)
        
        # Disabled source should not affect risk
        assert result["risk"] == "Low"
        assert result["score"] < 30
        assert not any("Scamwave" in r for r in result["reasons"])


class TestCheckThreatIntel:
    """Tests for the combined threat intel check."""

    @patch("app.threat_intel.check_phishtank")
    @patch("app.threat_intel.check_urlhaus")
    @patch("app.threat_intel.check_scamwave")
    def test_combined_check_aggregates_sources(self, mock_scamwave, mock_urlhaus, mock_phishtank):
        """Combined check should aggregate all source results."""
        mock_phishtank.return_value = {"result": "clear", "in_database": False, "verified": False, "note": ""}
        mock_urlhaus.return_value = {"result": "clear", "host_hit": False, "note": ""}
        mock_scamwave.return_value = {"result": "disabled", "host_hit": False, "policy": "disabled_by_config", "note": ""}
        
        from app.threat_intel import check_threat_intel
        
        result = check_threat_intel("https://example.com")
        
        assert result["known_bad"] == False
        assert len(result["feed_hits"]) == 0
        assert len(result["sources"]) == 3
        # Check that notes are included
        for source in result["sources"]:
            assert "note" in source

    @patch("app.threat_intel.check_phishtank")
    @patch("app.threat_intel.check_urlhaus")
    @patch("app.threat_intel.check_scamwave")
    def test_any_hit_sets_known_bad(self, mock_scamwave, mock_urlhaus, mock_phishtank):
        """If any source returns hit, known_bad should be True."""
        mock_phishtank.return_value = {"result": "hit", "in_database": True, "verified": True, "note": "In database"}
        mock_urlhaus.return_value = {"result": "clear", "host_hit": False, "note": ""}
        mock_scamwave.return_value = {"result": "disabled", "host_hit": False, "policy": "disabled_by_config", "note": ""}
        
        from app.threat_intel import check_threat_intel
        
        result = check_threat_intel("https://malicious.com")
        
        assert result["known_bad"] == True
        assert "PhishTank" in result["feed_hits"]

    @patch("app.threat_intel.check_phishtank")
    @patch("app.threat_intel.check_urlhaus")
    @patch("app.threat_intel.check_scamwave")
    def test_multiple_hits_aggregates_feed_hits(self, mock_scamwave, mock_urlhaus, mock_phishtank):
        """Multiple hits should all appear in feed_hits."""
        mock_phishtank.return_value = {"result": "hit", "in_database": True, "verified": True, "note": ""}
        mock_urlhaus.return_value = {"result": "hit", "host_hit": True, "note": ""}
        mock_scamwave.return_value = {"result": "clear", "host_hit": False, "policy": "allowed", "note": ""}
        
        from app.threat_intel import check_threat_intel
        
        result = check_threat_intel("https://malicious.com")
        
        assert result["known_bad"] == True
        assert "PhishTank" in result["feed_hits"]
        assert "URLhaus" in result["feed_hits"]
        assert "Scamwave" not in result["feed_hits"]


class TestAnalyzeUrlWithIntel:
    """Tests for combined heuristic + intel analysis."""

    def test_intel_hit_forces_high_risk(self):
        """When intel shows known_bad, should force High risk with score >= 90."""
        from app.detector import analyze_url_with_intel
        
        intel_result = {
            "known_bad": True,
            "feed_hits": ["PhishTank"],
            "sources": [{"name": "PhishTank", "result": "hit", "note": "In database"}],
            "details": {"phishtank": {"in_database": True, "verified": True}}
        }
        
        # Even a clean-looking URL should be High risk if in intel feeds
        result = analyze_url_with_intel("https://example.com", intel_result)
        
        assert result["risk"] == "High"
        assert result["score"] >= 90
        assert any("Matched known malicious source" in r for r in result["reasons"])

    def test_no_intel_hit_uses_heuristics(self):
        """When no intel hit, should use heuristic score only."""
        from app.detector import analyze_url_with_intel
        
        intel_result = {
            "known_bad": False,
            "feed_hits": [],
            "sources": [{"name": "PhishTank", "result": "clear", "note": ""}],
            "details": {}
        }
        
        result = analyze_url_with_intel("https://example.com", intel_result)
        
        # Clean URL should be Low risk
        assert result["risk"] == "Low"
        assert result["score"] < 30
        assert not any("Matched known malicious source" in r for r in result["reasons"])

    def test_none_intel_result_handled(self):
        """When intel_result is None, should use defaults."""
        from app.detector import analyze_url_with_intel
        
        result = analyze_url_with_intel("https://example.com", None)
        
        assert "intel" in result
        assert result["intel"]["known_bad"] == False
        assert result["intel"]["feed_hits"] == []

    def test_signals_checked_included(self):
        """Result should include signals_checked list."""
        from app.detector import analyze_url_with_intel
        
        result = analyze_url_with_intel("https://example.com", None)
        
        assert "signals_checked" in result
        assert isinstance(result["signals_checked"], list)
        assert len(result["signals_checked"]) > 0


class TestTTLCache:
    """Tests for the TTL cache implementation."""

    def test_cache_stores_and_retrieves(self):
        """Cache should store and retrieve values."""
        from app.threat_intel import TTLCache
        
        cache = TTLCache(default_ttl=60)
        cache.set("test_key", {"value": "test"})
        
        result = cache.get("test_key")
        assert result == {"value": "test"}

    def test_cache_returns_none_for_missing(self):
        """Cache should return None for missing keys."""
        from app.threat_intel import TTLCache
        
        cache = TTLCache(default_ttl=60)
        
        result = cache.get("nonexistent")
        assert result is None

    def test_cache_hashes_keys(self):
        """Cache should hash keys to avoid storing actual URLs."""
        from app.threat_intel import TTLCache
        
        cache = TTLCache(default_ttl=60)
        url = "https://sensitive-url.com/path"
        cache.set(url, {"value": "test"})
        
        # The actual URL should not be stored as a key
        assert url not in cache._cache

    def test_cache_clear(self):
        """Cache clear should remove all entries."""
        from app.threat_intel import TTLCache
        
        cache = TTLCache(default_ttl=60)
        cache.set("key1", {"value": "1"})
        cache.set("key2", {"value": "2"})
        
        cache.clear()
        
        assert cache.get("key1") is None
        assert cache.get("key2") is None
