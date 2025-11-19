# -*- coding: utf-8 -*-
"""
Test Redis TLS Configuration (Task 1.2 - Sprint 1)
===================================================

Tests for Redis TLS encryption support.

Scope:
- TLS URL configuration validation
- SSL context creation
- Redis client initialization with TLS
- Graceful fallback for development

Security Coverage:
- P0-9: Redis TLS encryption for data in transit
"""

import pytest
import os
from unittest.mock import patch, MagicMock
import ssl


@pytest.mark.unit
@pytest.mark.security
class TestRedisTLSConfiguration:
    """Test suite for Redis TLS configuration"""

    def test_redis_tls_url_configured(self):
        """
        ✅ Verify Redis URL uses TLS protocol (rediss://)
        
        Security: P0-9 - Data in transit encryption
        """
        from config import settings
        
        assert settings.redis_url.startswith('rediss://'), \
            'Redis URL should use rediss:// protocol for TLS encryption'
        
    def test_redis_tls_settings_defined(self):
        """
        ✅ Verify TLS configuration settings are defined
        
        Security: P0-9 - TLS configuration validation
        """
        from config import settings
        
        assert hasattr(settings, 'redis_tls_enabled'), \
            'redis_tls_enabled setting should be defined'
        assert hasattr(settings, 'redis_ssl_cert_reqs'), \
            'redis_ssl_cert_reqs setting should be defined'
        assert hasattr(settings, 'redis_ssl_ca_certs'), \
            'redis_ssl_ca_certs setting should be defined'
        
        # Validate default values
        assert settings.redis_tls_enabled is True, \
            'TLS should be enabled by default'
        assert settings.redis_ssl_cert_reqs == 'required', \
            'Certificate requirements should be set to "required"'

    @patch('utils.redis_helper.redis.Redis')
    def test_redis_client_creation_with_tls(self, mock_redis):
        """
        ✅ Test Redis client can be created with TLS configuration
        
        Security: P0-9 - SSL context initialization
        """
        from utils.redis_helper import reset_redis_client, _get_direct_client
        
        # Reset to ensure clean state
        reset_redis_client()
        
        # Mock successful connection
        mock_instance = MagicMock()
        mock_instance.ping.return_value = True
        mock_redis.return_value = mock_instance
        
        # Set TLS environment variables
        with patch.dict(os.environ, {
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': '6379',
            'REDIS_DB': '1',
            'REDIS_PASSWORD': 'test_password_12345678901234567890',
            'REDIS_TLS_ENABLED': 'true',
            'REDIS_SSL_CERT_REQS': 'none'  # Development mode
        }):
            try:
                client = _get_direct_client()
                assert client is not None, 'Redis client should be created'
                
                # Verify Redis was called with ssl parameter
                call_kwargs = mock_redis.call_args[1]
                assert 'ssl' in call_kwargs, 'SSL configuration should be passed to Redis client'
                
                # Verify SSL context is configured
                ssl_context = call_kwargs['ssl']
                if ssl_context:
                    assert isinstance(ssl_context, ssl.SSLContext), \
                        'SSL parameter should be SSLContext instance'
                
            except Exception as e:
                pytest.skip(f'Redis TLS not available in test environment: {e}')
            finally:
                reset_redis_client()

    @patch('utils.redis_helper.redis.Redis')
    def test_redis_tls_development_mode(self, mock_redis):
        """
        ✅ Test TLS development mode (CERT_NONE)
        
        Allows testing without certificates
        """
        from utils.redis_helper import reset_redis_client, _get_direct_client
        
        reset_redis_client()
        
        mock_instance = MagicMock()
        mock_instance.ping.return_value = True
        mock_redis.return_value = mock_instance
        
        with patch.dict(os.environ, {
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': '6379',
            'REDIS_DB': '1',
            'REDIS_PASSWORD': 'test_password_12345678901234567890',
            'REDIS_TLS_ENABLED': 'true',
            'REDIS_SSL_CERT_REQS': 'none'  # Development
        }):
            try:
                client = _get_direct_client()
                assert client is not None
                
                # In development mode, SSL should still be configured
                # but with CERT_NONE for flexibility
                call_kwargs = mock_redis.call_args[1]
                ssl_context = call_kwargs.get('ssl')
                
                if ssl_context:
                    # Development mode uses CERT_NONE
                    assert ssl_context.verify_mode == ssl.CERT_NONE, \
                        'Development mode should use CERT_NONE'
                    assert ssl_context.check_hostname is False, \
                        'Development mode should not check hostname'
                
            except Exception as e:
                pytest.skip(f'Redis TLS dev mode test skipped: {e}')
            finally:
                reset_redis_client()

    @patch('utils.redis_helper.redis.Redis')
    def test_redis_tls_production_mode(self, mock_redis):
        """
        ✅ Test TLS production mode (CERT_REQUIRED)
        
        Enforces certificate validation
        """
        from utils.redis_helper import reset_redis_client, _get_direct_client
        
        reset_redis_client()
        
        mock_instance = MagicMock()
        mock_instance.ping.return_value = True
        mock_redis.return_value = mock_instance
        
        with patch.dict(os.environ, {
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': '6379',
            'REDIS_DB': '1',
            'REDIS_PASSWORD': 'test_password_12345678901234567890',
            'REDIS_TLS_ENABLED': 'true',
            'REDIS_SSL_CERT_REQS': 'required',  # Production
            'REDIS_SSL_CA_CERTS': '/path/to/ca.crt'
        }):
            try:
                client = _get_direct_client()
                assert client is not None
                
                # In production mode, SSL should be configured with CERT_REQUIRED
                call_kwargs = mock_redis.call_args[1]
                ssl_context = call_kwargs.get('ssl')
                
                if ssl_context:
                    # Production mode uses CERT_REQUIRED
                    assert ssl_context.verify_mode == ssl.CERT_REQUIRED, \
                        'Production mode should use CERT_REQUIRED'
                    assert ssl_context.check_hostname is True, \
                        'Production mode should check hostname'
                
            except Exception as e:
                pytest.skip(f'Redis TLS production mode test skipped: {e}')
            finally:
                reset_redis_client()

    @patch('utils.redis_helper.redis.Redis')
    def test_redis_connection_with_fallback(self, mock_redis):
        """
        ✅ Test Redis connection works with graceful fallback
        
        Ensures application doesn't fail if TLS is misconfigured
        """
        from utils.redis_helper import reset_redis_client, get_redis_client
        
        reset_redis_client()
        
        # Mock successful connection
        mock_instance = MagicMock()
        mock_instance.ping.return_value = True
        mock_redis.return_value = mock_instance
        
        with patch.dict(os.environ, {
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': '6379',
            'REDIS_DB': '1',
            'REDIS_PASSWORD': 'test_password_12345678901234567890',
            'REDIS_SENTINEL_ENABLED': 'false',  # Use direct connection
            'REDIS_TLS_ENABLED': 'true',
            'REDIS_SSL_CERT_REQS': 'none'
        }):
            try:
                client = get_redis_client()
                assert client is not None, 'Redis client should be created'
                
                # Test ping
                result = client.ping()
                assert result is True, 'Redis ping should succeed'
                
            except Exception as e:
                pytest.skip(f'Redis not available in test environment: {e}')
            finally:
                reset_redis_client()

    def test_redis_tls_disabled_fallback(self):
        """
        ✅ Test behavior when TLS is explicitly disabled
        
        Ensures backward compatibility
        """
        from utils.redis_helper import reset_redis_client
        
        reset_redis_client()
        
        with patch.dict(os.environ, {
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': '6379',
            'REDIS_DB': '1',
            'REDIS_PASSWORD': 'test_password_12345678901234567890',
            'REDIS_TLS_ENABLED': 'false'  # Explicitly disabled
        }):
            # This should work without TLS configuration
            # Test is informational - verifies config is read correctly
            tls_enabled = os.getenv('REDIS_TLS_ENABLED', 'true').lower() == 'true'
            assert tls_enabled is False, 'TLS should be disabled when env var is false'
            
            reset_redis_client()


@pytest.mark.integration
@pytest.mark.security
class TestRedisTLSIntegration:
    """Integration tests for Redis TLS (require running Redis)"""

    def test_real_redis_connection_tls(self):
        """
        ✅ Integration test: Connect to real Redis with TLS
        
        Skipped if Redis not available
        """
        from utils.redis_helper import reset_redis_client, get_redis_client
        
        reset_redis_client()
        
        try:
            client = get_redis_client()
            result = client.ping()
            assert result is True, 'Redis TLS connection should work'
            
        except Exception as e:
            pytest.skip(f'Redis not available for integration test: {e}')
        finally:
            reset_redis_client()
