# -*- coding: utf-8 -*-
"""
Security Headers Middleware
Implements OWASP best practices for HTTP security headers
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.
    
    Implements OWASP recommended security headers:
    - X-Content-Type-Options: Prevents MIME type sniffing
    - X-Frame-Options: Prevents clickjacking attacks
    - X-XSS-Protection: Enables browser XSS filters
    - Strict-Transport-Security: Enforces HTTPS connections
    - Referrer-Policy: Controls referrer information leakage
    
    References:
    - OWASP Secure Headers Project
    - https://owasp.org/www-project-secure-headers/
    """
    
    async def dispatch(self, request: Request, call_next):
        """
        Add security headers to all responses.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in chain
            
        Returns:
            Response with security headers added
        """
        response = await call_next(request)
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Prevent clickjacking by denying iframe embedding
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Enable browser XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Enforce HTTPS for 1 year including subdomains
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Control referrer information leakage
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response
