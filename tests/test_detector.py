"""
Unit tests for the URL detector module.
Tests cover all major detection rules.
"""

import pytest
from app.detector import analyze_url, normalize_url


class TestNormalizeUrl:
    """Tests for URL normalization."""

    def test_strips_whitespace(self):
        result = normalize_url("  https://example.com  ")
        assert result == "https://example.com"

    def test_decodes_percent_encoding(self):
        result = normalize_url("https://example.com/%2Fpath")
        assert "/path" in result


class TestAnalyzeUrl:
    """Tests for URL analysis and detection rules."""

    # Rule: Invalid URL format
    def test_invalid_url_returns_high_risk(self):
        result = analyze_url("not a valid url !!!")
        assert result['score'] == 100
        assert result['risk'] == 'High'
        assert any('Invalid URL' in r for r in result['reasons'])

    def test_valid_url_without_scheme_gets_normalized(self):
        result = analyze_url("example.com")
        assert result['normalized_url'].startswith('https://')

    # Rule: IP address host
    def test_ip_address_host_detected(self):
        result = analyze_url("http://192.168.1.1/path")
        assert result['score'] > 0
        assert any('IP address' in r for r in result['reasons'])

    def test_ip_address_with_port_detected(self):
        result = analyze_url("http://192.168.1.1:8080/path")
        assert any('IP address' in r for r in result['reasons'])

    # Rule: @ symbol in URL
    def test_at_symbol_detected(self):
        result = analyze_url("https://user@evil.com/path")
        assert result['score'] > 0
        assert any('@' in r for r in result['reasons'])

    # Rule: Excessive subdomains
    def test_excessive_subdomains_detected(self):
        result = analyze_url("https://a.b.c.example.com/path")
        assert result['score'] > 0
        assert any('subdomain' in r.lower() for r in result['reasons'])

    def test_two_subdomains_not_flagged(self):
        result = analyze_url("https://www.mail.example.com")
        # Two subdomains should not trigger excessive subdomains
        assert not any('Excessive subdomains' in r for r in result['reasons'])

    # Rule: Long URL
    def test_long_url_detected(self):
        long_path = "a" * 80
        result = analyze_url(f"https://example.com/{long_path}")
        assert result['score'] > 0
        assert any('long' in r.lower() for r in result['reasons'])

    def test_short_url_not_flagged_for_length(self):
        result = analyze_url("https://example.com/")
        assert not any('long' in r.lower() for r in result['reasons'])

    # Rule: Non-HTTPS scheme
    def test_http_scheme_detected(self):
        result = analyze_url("http://example.com/path")
        assert result['score'] > 0
        assert any('Non-HTTPS' in r or 'not encrypted' in r.lower() for r in result['reasons'])

    def test_https_not_flagged(self):
        result = analyze_url("https://example.com/path")
        assert not any('Non-HTTPS' in r for r in result['reasons'])

    # Rule: Punycode / IDN
    def test_punycode_detected(self):
        result = analyze_url("https://xn--80ak6aa92e.com/path")
        assert result['score'] > 0
        assert any('Punycode' in r or 'Internationalized' in r for r in result['reasons'])

    # Rule: Hyphens in domain (>=2 now triggers)
    def test_multiple_hyphens_detected(self):
        result = analyze_url("https://my-super-long-domain-name.com/path")
        assert result['score'] > 0
        assert any('hyphen' in r.lower() for r in result['reasons'])

    def test_single_hyphen_not_flagged(self):
        result = analyze_url("https://my-site.com/path")
        assert not any('hyphen' in r.lower() for r in result['reasons'])

    # Rule: Suspicious keywords
    def test_login_keyword_detected(self):
        result = analyze_url("https://example.com/login/user")
        assert result['score'] > 0
        assert any('keyword' in r.lower() or 'authentication' in r.lower() for r in result['reasons'])

    def test_multiple_keywords_detected(self):
        result = analyze_url("https://example.com/login/verify/account")
        assert result['score'] > 0
        reasons_text = ' '.join(result['reasons']).lower()
        assert 'keyword' in reasons_text or 'authentication' in reasons_text or 'urgency' in reasons_text

    def test_verify_keyword_detected(self):
        result = analyze_url("https://example.com/verify-account")
        assert any('keyword' in r.lower() or 'urgency' in r.lower() for r in result['reasons'])

    # Rule: Suspicious TLD
    def test_suspicious_tld_detected(self):
        result = analyze_url("https://example.tk/path")
        assert result['score'] > 0
        assert any('.tk' in r for r in result['reasons'])

    def test_zip_tld_detected(self):
        result = analyze_url("https://download.zip/malware")
        assert result['score'] > 0
        assert any('.zip' in r for r in result['reasons'])

    def test_common_tld_not_flagged(self):
        result = analyze_url("https://example.com/path")
        assert not any('Suspicious top-level domain' in r for r in result['reasons'])

    # Rule: Brand impersonation
    def test_brand_impersonation_subdomain(self):
        result = analyze_url("https://paypal-login.evil.com/path")
        assert result['score'] > 0
        assert any('paypal' in r.lower() and 'impersonation' in r.lower() for r in result['reasons'])

    def test_brand_impersonation_path(self):
        result = analyze_url("https://evil.com/paypal/login")
        assert result['score'] > 0
        reasons_text = ' '.join(result['reasons']).lower()
        # Should detect either brand impersonation or suspicious keyword
        assert 'paypal' in reasons_text or 'keyword' in reasons_text or 'authentication' in reasons_text

    def test_legitimate_brand_domain_not_flagged(self):
        result = analyze_url("https://paypal.com/login")
        # Should not flag brand impersonation when domain is the brand
        assert not any('impersonation' in r.lower() for r in result['reasons'])

    # Rule: Security keywords in hostname
    def test_security_keywords_in_hostname(self):
        result = analyze_url("https://secure-bank-update.example.com/")
        assert result['score'] > 0
        assert any('security' in r.lower() or 'financial' in r.lower() or 'hostname' in r.lower() for r in result['reasons'])

    # Rule: Keyword spam in hostname
    def test_keyword_spam_in_hostname(self):
        result = analyze_url("https://secure-login-verify.example.com/")
        assert result['score'] >= 30
        reasons_text = ' '.join(result['reasons']).lower()
        assert 'keyword' in reasons_text or 'suspicious' in reasons_text


class TestRiskLevels:
    """Tests for risk level classification with new thresholds."""

    def test_low_risk_threshold(self):
        # Clean URL should be Low risk (score < 30)
        result = analyze_url("https://example.com/page")
        assert result['risk'] == 'Low'
        assert result['score'] < 30

    def test_medium_risk_threshold(self):
        # HTTP (15) + auth keyword (15) = 30, should be Medium
        result = analyze_url("http://example.com/login")
        assert result['risk'] == 'Medium'
        assert 30 <= result['score'] < 60

    def test_high_risk_threshold(self):
        # Combine multiple factors to exceed 60
        result = analyze_url("http://192.168.1.1/login/verify?account=update")
        assert result['risk'] == 'High'
        assert result['score'] >= 60


class TestScoreCapping:
    """Tests for score bounds."""

    def test_score_never_exceeds_100(self):
        # Create a very malicious-looking URL
        url = "http://xn--user@paypal-login.a.b.c.d.evil.tk:9999/login/verify/account/password/signin/auth/update?secure=1"
        result = analyze_url(url)
        assert result['score'] <= 100

    def test_score_never_below_zero(self):
        result = analyze_url("https://example.com")
        assert result['score'] >= 0


class TestOutputFormat:
    """Tests for output structure."""

    def test_returns_all_required_fields(self):
        result = analyze_url("https://example.com")
        assert 'score' in result
        assert 'risk' in result
        assert 'reasons' in result
        assert 'normalized_url' in result
        assert 'signals_checked' in result

    def test_reasons_is_list(self):
        result = analyze_url("https://example.com")
        assert isinstance(result['reasons'], list)

    def test_signals_checked_is_list(self):
        result = analyze_url("https://example.com")
        assert isinstance(result['signals_checked'], list)

    def test_signals_checked_contains_expected_signals(self):
        result = analyze_url("https://example.com")
        # Should contain at least url_format signal
        assert 'url_format' in result['signals_checked']

    def test_reasons_always_has_content(self):
        result = analyze_url("https://example.com")
        assert len(result['reasons']) > 0

    def test_clean_url_has_no_obvious_indicators_message(self):
        result = analyze_url("https://example.com/page")
        if result['score'] == 0:
            assert any('no obvious' in r.lower() for r in result['reasons'])


class TestRegressionCases:
    """Regression tests for specific phishing URL patterns."""

    def test_target_case_secure_bank_update(self):
        """TARGET TEST: https://secure-bank-update.example.net/login must be HIGH risk >= 70"""
        result = analyze_url("https://secure-bank-update.example.net/login")
        assert result['risk'] == 'High', f"Expected High risk, got {result['risk']} with score {result['score']}"
        assert result['score'] >= 70, f"Expected score >= 70, got {result['score']}"
        # Should have multiple reasons
        assert len(result['reasons']) >= 2, f"Expected multiple reasons, got {result['reasons']}"

    def test_paypal_impersonation_high_risk(self):
        """http://paypal-login.example.com/verify must be HIGH risk"""
        result = analyze_url("http://paypal-login.example.com/verify")
        assert result['risk'] == 'High', f"Expected High risk, got {result['risk']} with score {result['score']}"
        assert result['score'] >= 60
        # Should detect brand impersonation
        reasons_text = ' '.join(result['reasons']).lower()
        assert 'paypal' in reasons_text or 'impersonation' in reasons_text

    def test_github_legitimate_low_risk(self):
        """https://github.com must be LOW risk"""
        result = analyze_url("https://github.com")
        assert result['risk'] == 'Low', f"Expected Low risk, got {result['risk']} with score {result['score']}"
        assert result['score'] < 30

    def test_queensu_legitimate_low_risk(self):
        """https://queensu.ca must be LOW risk"""
        result = analyze_url("https://queensu.ca")
        assert result['risk'] == 'Low', f"Expected Low risk, got {result['risk']} with score {result['score']}"
        assert result['score'] < 30

    def test_google_login_legitimate_low_risk(self):
        """https://accounts.google.com/login should be Low risk (real Google)"""
        result = analyze_url("https://accounts.google.com/signin")
        # This is the real Google domain, should not be flagged as impersonation
        assert not any('impersonation' in r.lower() for r in result['reasons'])
        # May have some score for auth keywords but should still be Low/Medium
        assert result['risk'] in ('Low', 'Medium')

    def test_fake_google_high_risk(self):
        """https://google-login.fakesite.com/signin should be HIGH risk"""
        result = analyze_url("https://google-login.fakesite.com/signin")
        assert result['risk'] == 'High', f"Expected High risk, got {result['risk']}"
        assert result['score'] >= 60

    def test_microsoft_phishing_high_risk(self):
        """https://microsoft-secure-update.evil.net/auth should be HIGH risk"""
        result = analyze_url("https://microsoft-secure-update.evil.net/auth")
        assert result['risk'] == 'High', f"Expected High risk, got {result['risk']}"
        assert result['score'] >= 60

    def test_ip_with_login_high_risk(self):
        """http://192.168.1.1/signin should be HIGH risk"""
        result = analyze_url("http://192.168.1.1/signin")
        assert result['risk'] == 'High', f"Expected High risk, got {result['risk']}"
        assert result['score'] >= 60

    def test_suspicious_tld_with_brand(self):
        """https://amazon-verify.site.tk/account should be HIGH risk"""
        result = analyze_url("https://amazon-verify.site.tk/account")
        assert result['risk'] == 'High', f"Expected High risk, got {result['risk']}"
        assert result['score'] >= 60
