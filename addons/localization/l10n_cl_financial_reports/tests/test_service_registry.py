# -*- coding: utf-8 -*-
"""
Unit tests for Financial Report Service Registry
===============================================

Tests the service registry functionality for dynamic service registration
and discovery without altering existing business logic.

Author: EERGYGROUP - Based on technical audit specifications
"""

import logging
from datetime import date, timedelta

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class TestFinancialReportServiceRegistry(TransactionCase):
    """Test cases for the Financial Report Service Registry."""
    
    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.registry = self.env['financial.report.service.registry']
        
        # Clear registry before each test
        self.registry.clear_registry()
    
    def test_service_registration(self):
        """Test basic service registration functionality."""
        # Test valid service registration
        result = self.registry.register_service(
            service_type='kpi',
            service_name='test_kpi_service',
            service_class='test.kpi.provider',
            module_name='test_module'
        )
        
        self.assertTrue(result, "Service registration should succeed")
        
        # Test retrieving registered services
        services = self.registry.get_available_services('kpi')
        self.assertIn('test_kpi_service', services, "Registered service should be available")
        
        service_info = services['test_kpi_service']
        self.assertEqual(service_info['class'], 'test.kpi.provider')
        self.assertEqual(service_info['module'], 'test_module')
    
    def test_invalid_service_type(self):
        """Test registration with invalid service type."""
        with self.assertRaises(ValidationError):
            self.registry.register_service(
                service_type='invalid_type',
                service_name='test_service',
                service_class='test.class',
                module_name='test_module'
            )
    
    def test_kpi_provider_registration(self):
        """Test KPI provider registration."""
        # Mock KPI method
        def mock_kpi_method(date_from, date_to, company_ids):
            return {'test_kpi': 42}
        
        # Register KPI provider
        result = self.registry.register_kpi_provider(
            provider_name='test_kpi_provider',
            kpi_method=mock_kpi_method,
            module_name='test_module'
        )
        
        self.assertTrue(result, "KPI provider registration should succeed")
        
        # Test KPI retrieval
        kpis = self.registry.get_consolidated_kpis(
            date_from=date.today() - timedelta(days=30),
            date_to=date.today(),
            company_ids=[self.env.company.id]
        )
        
        self.assertIn('test_kpi_provider', kpis, "KPI provider should be in consolidated KPIs")
        self.assertEqual(kpis['test_kpi_provider']['data']['test_kpi'], 42)
    
    def test_widget_provider_registration(self):
        """Test widget provider registration."""
        # Register widget provider
        result = self.registry.register_widget_provider(
            widget_type='test_widget',
            widget_class='test.widget.provider',
            module_name='test_module'
        )
        
        self.assertTrue(result, "Widget provider registration should succeed")
        
        # Test widget retrieval
        widgets = self.registry.get_available_widgets('test_widget')
        self.assertIn('test_widget', widgets, "Widget type should be available")
        
        widget_providers = widgets['test_widget']
        self.assertEqual(len(widget_providers), 1)
        self.assertEqual(widget_providers[0]['class'], 'test.widget.provider')
        self.assertEqual(widget_providers[0]['module'], 'test_module')
    
    def test_auto_discovery(self):
        """Test auto-discovery functionality."""
        # This test verifies that auto-discovery doesn't break
        # The actual discovery depends on installed modules
        
        discovery_results = self.registry.auto_discover_services()
        
        self.assertIsInstance(discovery_results, dict)
        self.assertIn('discovered_modules', discovery_results)
        self.assertIn('registered_services', discovery_results)
        self.assertIn('errors', discovery_results)
    
    def test_registry_statistics(self):
        """Test registry statistics functionality."""
        # Register some test services
        self.registry.register_service('kpi', 'test_kpi', 'test.class', 'test_module')
        self.registry.register_widget_provider('test_widget', 'test.widget', 'test_module')
        
        stats = self.registry.get_registry_stats()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('total_services', stats)
        self.assertIn('kpi_providers', stats)
        self.assertIn('widget_providers', stats)
        self.assertGreaterEqual(stats['total_services'], 1)
    
    def test_clear_registry(self):
        """Test registry clearing functionality."""
        # Register some test data
        self.registry.register_service('kpi', 'test_kpi', 'test.class', 'test_module')
        self.registry.register_kpi_provider('test_provider', lambda: {}, 'test_module')
        
        # Verify data exists
        stats_before = self.registry.get_registry_stats()
        self.assertGreater(stats_before['total_services'], 0)
        
        # Clear registry
        result = self.registry.clear_registry()
        self.assertTrue(result)
        
        # Verify data is cleared
        stats_after = self.registry.get_registry_stats()
        self.assertEqual(stats_after['total_services'], 0)
        self.assertEqual(stats_after['kpi_providers'], 0)
    
    def test_kpi_provider_error_handling(self):
        """Test error handling in KPI provider calls."""
        # Register a KPI provider that raises an error
        def error_kpi_method(date_from, date_to, company_ids):
            raise Exception("Test error")
        
        self.registry.register_kpi_provider(
            provider_name='error_provider',
            kpi_method=error_kpi_method,
            module_name='test_module'
        )
        
        # Test that errors are handled gracefully
        kpis = self.registry.get_consolidated_kpis(
            date_from=date.today() - timedelta(days=30),
            date_to=date.today(),
            company_ids=[self.env.company.id]
        )
        
        self.assertIn('error_provider', kpis)
        self.assertIn('error', kpis['error_provider'])
        self.assertEqual(kpis['error_provider']['error'], "Test error")
    
    def tearDown(self):
        """Clean up after tests."""
        super().tearDown()
        # Clear registry to avoid affecting other tests
        self.registry.clear_registry()
