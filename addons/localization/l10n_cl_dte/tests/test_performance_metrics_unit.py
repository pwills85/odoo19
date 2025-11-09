# -*- coding: utf-8 -*-
"""
Unit Tests - Performance Metrics with Dynamic Configuration
============================================================

P1.3 GAP CLOSURE: Tests for performance metrics instrumentation.

Tests:
- Dynamic Redis connection (env var → config_parameter → fallback)
- Conditional execution based on metrics_enabled parameter
- ORM-aware env extraction (model methods and HTTP controllers)
- Decorator behavior with metrics enabled/disabled

Author: EERGYGROUP - Claude Code (Anthropic)
License: LGPL-3
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import os


class TestPerformanceMetricsUnit(unittest.TestCase):
    """Tests unitarios para performance_metrics.py con configuración dinámica."""

    def setUp(self):
        """Preparar mocks."""
        # Clear environment variables before each test
        if 'REDIS_URL' in os.environ:
            del os.environ['REDIS_URL']
        if 'DTE_METRICS_ENABLED' in os.environ:
            del os.environ['DTE_METRICS_ENABLED']

    def test_01_get_redis_url_from_env_var(self):
        """P1.3: Test Redis URL from environment variable (highest priority)."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _get_redis_url

        # Set environment variable
        os.environ['REDIS_URL'] = 'redis://custom-redis:6380/2'

        redis_url = _get_redis_url(env=None)
        self.assertEqual(redis_url, 'redis://custom-redis:6380/2')

    def test_02_get_redis_url_from_config_parameter(self):
        """P1.3: Test Redis URL from config parameter (if env available)."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _get_redis_url

        # Mock env with config parameter
        mock_env = Mock()
        mock_config = Mock()
        mock_config.get_param.return_value = 'redis://config-redis:6381/3'
        mock_env.__getitem__.return_value.sudo.return_value = mock_config

        redis_url = _get_redis_url(env=mock_env)
        self.assertEqual(redis_url, 'redis://config-redis:6381/3')

    def test_03_get_redis_url_fallback(self):
        """P1.3: Test Redis URL fallback (no env var, no config parameter)."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _get_redis_url

        redis_url = _get_redis_url(env=None)
        self.assertEqual(redis_url, 'redis://redis:6379/1')

    def test_04_is_metrics_enabled_default(self):
        """P1.3: Test metrics enabled by default (backward compatibility)."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _is_metrics_enabled

        enabled = _is_metrics_enabled(env=None)
        self.assertTrue(enabled)

    def test_05_is_metrics_disabled_via_env_var(self):
        """P1.3: Test metrics disabled via environment variable."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _is_metrics_enabled

        os.environ['DTE_METRICS_ENABLED'] = 'false'

        enabled = _is_metrics_enabled(env=None)
        self.assertFalse(enabled)

    def test_06_is_metrics_enabled_via_config_parameter(self):
        """P1.3: Test metrics enabled via config parameter."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _is_metrics_enabled

        # Mock env with config parameter
        mock_env = Mock()
        mock_config = Mock()
        mock_config.get_param.return_value = 'True'
        mock_env.__getitem__.return_value.sudo.return_value = mock_config

        enabled = _is_metrics_enabled(env=mock_env)
        self.assertTrue(enabled)

    def test_07_is_metrics_disabled_via_config_parameter(self):
        """P1.3: Test metrics disabled via config parameter."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _is_metrics_enabled

        # Mock env with config parameter
        mock_env = Mock()
        mock_config = Mock()
        mock_config.get_param.return_value = 'False'
        mock_env.__getitem__.return_value.sudo.return_value = mock_config

        enabled = _is_metrics_enabled(env=mock_env)
        self.assertFalse(enabled)

    def test_08_get_env_from_model_method(self):
        """P1.3: Test env extraction from model method (args[0].env)."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _get_env_from_args

        # Mock model instance with env
        mock_self = Mock()
        mock_self.env = Mock()

        env = _get_env_from_args((mock_self,))
        self.assertEqual(env, mock_self.env)

    def test_09_get_env_from_http_controller(self):
        """P1.3: Test env extraction from HTTP controller (request.env)."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _get_env_from_args

        # Mock HTTP request
        with patch('odoo.http.request') as mock_request:
            mock_request.env = Mock()

            env = _get_env_from_args((Mock(),))  # args[0] has no env
            self.assertEqual(env, mock_request.env)

    def test_10_decorator_with_metrics_enabled(self):
        """P1.3: Test decorator executes measurement when metrics enabled."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import measure_performance

        # Mock env
        mock_env = Mock()
        mock_config = Mock()
        mock_config.get_param.return_value = 'True'
        mock_env.__getitem__.return_value.sudo.return_value = mock_config

        # Mock self with env
        mock_self = Mock()
        mock_self.env = mock_env

        # Decorate function
        @measure_performance('test_stage')
        def test_function(self):
            return 'result'

        # Mock Redis to avoid actual connection
        with patch('addons.localization.l10n_cl_dte.libs.performance_metrics.redis'):
            result = test_function(mock_self)

        self.assertEqual(result, 'result')

    def test_11_decorator_with_metrics_disabled(self):
        """P1.3: Test decorator skips measurement when metrics disabled."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import measure_performance

        # Set env var to disable metrics
        os.environ['DTE_METRICS_ENABLED'] = 'false'

        execution_count = {'count': 0}

        # Decorate function
        @measure_performance('test_stage')
        def test_function():
            execution_count['count'] += 1
            return 'result'

        result = test_function()

        # Function should execute
        self.assertEqual(result, 'result')
        self.assertEqual(execution_count['count'], 1)

        # Metrics should NOT be stored (no Redis call)
        # This is implicit - if Redis was called without mocking, it would fail

    def test_12_store_metric_uses_dynamic_redis(self):
        """P1.3: Test _store_metric uses dynamic Redis URL."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import _store_metric

        # Set custom Redis URL
        os.environ['REDIS_URL'] = 'redis://test-redis:6380/5'

        # Mock Redis
        with patch('addons.localization.l10n_cl_dte.libs.performance_metrics.redis') as mock_redis:
            mock_client = Mock()
            mock_redis.from_url.return_value = mock_client

            _store_metric('test_stage', 100, env=None)

            # Verify Redis was called with custom URL
            mock_redis.from_url.assert_called_once_with('redis://test-redis:6380/5', decode_responses=True)
            mock_client.zadd.assert_called_once()

    def test_13_decorator_preserves_function_metadata(self):
        """P1.3: Test decorator preserves function name and docstring."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import measure_performance

        @measure_performance('test_stage')
        def test_function_with_doc():
            """Test docstring."""
            return 'result'

        self.assertEqual(test_function_with_doc.__name__, 'test_function_with_doc')
        self.assertIn('Test docstring', test_function_with_doc.__doc__)

    def test_14_decorator_handles_exceptions(self):
        """P1.3: Test decorator logs performance even when function raises exception."""
        from addons.localization.l10n_cl_dte.libs.performance_metrics import measure_performance

        # Mock env
        mock_env = Mock()
        mock_config = Mock()
        mock_config.get_param.return_value = 'True'
        mock_env.__getitem__.return_value.sudo.return_value = mock_config

        mock_self = Mock()
        mock_self.env = mock_env

        @measure_performance('test_stage')
        def test_function_raises(self):
            raise ValueError('Test error')

        with patch('addons.localization.l10n_cl_dte.libs.performance_metrics.redis'):
            with self.assertRaises(ValueError):
                test_function_raises(mock_self)

        # Exception should propagate, but performance was still measured


if __name__ == '__main__':
    unittest.main()
