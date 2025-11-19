# -*- coding: utf-8 -*-
"""
Tests for CORS Security Configuration
Task 2.1 - Sprint 2: Restrict CORS Wildcards
"""

import pytest
from fastapi.testclient import TestClient
from main import app, ALLOWED_CORS_METHODS, ALLOWED_CORS_HEADERS

client = TestClient(app)


def test_cors_methods_not_wildcard():
    """Verify CORS methods are explicit (no wildcard)"""
    assert "*" not in ALLOWED_CORS_METHODS, "CORS methods should not contain wildcard"
    assert "GET" in ALLOWED_CORS_METHODS, "GET method should be allowed"
    assert "POST" in ALLOWED_CORS_METHODS, "POST method should be allowed"
    assert "OPTIONS" in ALLOWED_CORS_METHODS, "OPTIONS method should be allowed"


def test_cors_headers_not_wildcard():
    """Verify CORS headers are explicit (no wildcard)"""
    assert "*" not in ALLOWED_CORS_HEADERS, "CORS headers should not contain wildcard"
    assert "Authorization" in ALLOWED_CORS_HEADERS, "Authorization header should be allowed"
    assert "Content-Type" in ALLOWED_CORS_HEADERS, "Content-Type header should be allowed"


def test_cors_preflight_request():
    """Test CORS preflight (OPTIONS) request"""
    response = client.options(
        "/api/ai/validate",
        headers={
            "Origin": "http://odoo:8069",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization"
        }
    )
    
    # Should allow configured methods
    assert response.status_code in [200, 204], f"Preflight should succeed, got {response.status_code}"
    
    # Verify no wildcard in response headers
    allowed_methods = response.headers.get("Access-Control-Allow-Methods", "")
    assert "*" not in allowed_methods, "Response should not contain wildcard methods"


def test_cors_disallows_dangerous_methods():
    """Verify dangerous HTTP methods are not allowed"""
    assert "DELETE" not in ALLOWED_CORS_METHODS, "DELETE method should not be allowed"
    assert "PUT" not in ALLOWED_CORS_METHODS, "PUT method should not be allowed"
    assert "PATCH" not in ALLOWED_CORS_METHODS, "PATCH method should not be allowed"


def test_cors_config_validator():
    """Test CORS origins validator in config"""
    from config import Settings
    
    # Test valid origins
    try:
        settings = Settings(
            allowed_origins=["http://localhost:8069", "http://odoo:8069"],
            api_key="a" * 32,  # Valid 32-char key
            anthropic_api_key="sk-ant-" + "x" * 40,  # Valid Anthropic key
            odoo_api_key="b" * 32  # Valid 32-char key
        )
        assert settings.allowed_origins == ["http://localhost:8069", "http://odoo:8069"]
    except Exception as e:
        pytest.fail(f"Valid origins rejected: {e}")


def test_cors_validator_rejects_wildcard_in_production():
    """Test that wildcard origins are rejected in non-debug mode"""
    from config import Settings
    
    with pytest.raises(ValueError, match="Wildcard CORS not allowed"):
        Settings(
            allowed_origins=["*"],
            debug=False,  # Production mode
            api_key="a" * 32,
            anthropic_api_key="sk-ant-" + "x" * 40,
            odoo_api_key="b" * 32
        )


def test_cors_validator_accepts_valid_urls():
    """Test that valid URL formats are accepted"""
    from config import Settings
    
    valid_origins = [
        "http://localhost:8069",
        "https://production.example.com",
        "http://odoo:8069",
        "https://secure-site.com:8443"
    ]
    
    try:
        settings = Settings(
            allowed_origins=valid_origins,
            api_key="a" * 32,
            anthropic_api_key="sk-ant-" + "x" * 40,
            odoo_api_key="b" * 32
        )
        assert len(settings.allowed_origins) == len(valid_origins)
    except Exception as e:
        pytest.fail(f"Valid URLs rejected: {e}")


def test_cors_validator_rejects_invalid_urls():
    """Test that invalid URL formats are rejected"""
    from config import Settings
    
    invalid_origins = [
        "not-a-url",  # Missing scheme
        "ftp://invalid-scheme.com",  # Wrong scheme
        "http://",  # Incomplete URL
    ]
    
    for invalid_origin in invalid_origins:
        with pytest.raises(ValueError, match="Invalid CORS origin format"):
            Settings(
                allowed_origins=[invalid_origin],
                api_key="a" * 32,
                anthropic_api_key="sk-ant-" + "x" * 40,
                odoo_api_key="b" * 32
            )


def test_cors_only_necessary_headers_allowed():
    """Verify only necessary headers are in the allowlist"""
    # Expected headers for AI service functionality
    expected_headers = {
        "Authorization",  # API key authentication
        "Content-Type",   # JSON payloads
        "Accept",         # Response format negotiation
        "X-Request-ID",   # Request tracing
        "X-API-Key"       # Alternative auth header
    }
    
    assert set(ALLOWED_CORS_HEADERS) == expected_headers, \
        f"Only necessary headers should be allowed. Got: {ALLOWED_CORS_HEADERS}"


def test_cors_max_age_configured():
    """Verify CORS max_age is configured for preflight caching"""
    # This test verifies that the middleware configuration includes max_age
    # by checking the actual middleware in the app stack
    from starlette.middleware.cors import CORSMiddleware
    
    cors_middleware = None
    for middleware in app.user_middleware:
        if middleware.cls == CORSMiddleware:
            cors_middleware = middleware
            break
    
    assert cors_middleware is not None, "CORS middleware should be configured"
    # The max_age parameter should be in the options
    assert 'max_age' in str(cors_middleware.options), "max_age should be configured for CORS"
