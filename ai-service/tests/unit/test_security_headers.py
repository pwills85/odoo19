# -*- coding: utf-8 -*-
"""
Security Headers Middleware Tests
Unit tests for OWASP security headers implementation
"""

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_security_headers_present():
    """
    Test that all required security headers are present in responses.
    
    Validates OWASP recommended headers:
    - X-Content-Type-Options
    - X-Frame-Options
    - X-XSS-Protection
    - Strict-Transport-Security
    - Referrer-Policy
    """
    response = client.get('/health')
    
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['X-XSS-Protection'] == '1; mode=block'
    assert 'Strict-Transport-Security' in response.headers
    assert 'Referrer-Policy' in response.headers


def test_security_headers_on_all_endpoints():
    """
    Test that security headers are applied to all endpoints.
    
    Validates middleware is correctly registered and applies
    headers universally across different routes.
    """
    response = client.get('/ready')
    assert 'X-Content-Type-Options' in response.headers
    
    # Test another endpoint
    response = client.get('/health')
    assert 'X-Content-Type-Options' in response.headers


def test_middleware_doesnt_break_existing_endpoints():
    """
    Test that security headers middleware doesn't break existing functionality.
    
    Validates that adding security headers doesn't interfere with
    normal endpoint operation and status codes.
    """
    response = client.get('/health')
    assert response.status_code == 200


def test_hsts_header_value():
    """
    Test that HSTS header has correct value for production security.
    
    Validates:
    - 1 year max-age (31536000 seconds)
    - includeSubDomains directive present
    """
    response = client.get('/health')
    hsts = response.headers.get('Strict-Transport-Security', '')
    
    assert 'max-age=31536000' in hsts
    assert 'includeSubDomains' in hsts


def test_referrer_policy_value():
    """
    Test that Referrer-Policy header has appropriate value.
    
    Validates strict-origin-when-cross-origin policy to balance
    security and functionality.
    """
    response = client.get('/health')
    referrer_policy = response.headers.get('Referrer-Policy', '')
    
    assert referrer_policy == 'strict-origin-when-cross-origin'


def test_x_frame_options_denies_embedding():
    """
    Test that X-Frame-Options is set to DENY to prevent clickjacking.
    
    Validates DENY policy to completely prevent iframe embedding
    of the application.
    """
    response = client.get('/health')
    assert response.headers['X-Frame-Options'] == 'DENY'
