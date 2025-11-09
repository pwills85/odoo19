# -*- coding: utf-8 -*-
"""
Unit tests for Universal Dashboard Engine
=========================================

Tests the universal dashboard engine functionality for dynamic dashboard
generation without altering existing business logic.

Author: EERGYGROUP - Based on technical audit specifications
"""

import logging
from datetime import date, timedelta

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class TestUniversalDashboardEngine(TransactionCase):
    """Test cases for the Universal Dashboard Engine."""
    
    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.dashboard_engine = self.env['financial.report.universal.dashboard']
        self.registry = self.env['financial.report.service.registry']
        
        # Clear registry and set up test data
        self.registry.clear_registry()
        
        # Register test KPI provider
        def test_kpi_method(date_from, date_to, company_ids):
            return {
                'test_revenue': 100000,
                'test_expenses': 75000,
                'test_profit': 25000,
            }
        
        self.registry.register_kpi_provider(
            provider_name='test_financial_kpis',
            kpi_method=test_kpi_method,
            module_name='test_module'
        )
    
    def test_dashboard_type_validation(self):
        """Test dashboard type validation."""
        # Test valid dashboard types
        valid_types = ['executive', 'operational', 'financial', 'technical']
        
        for dashboard_type in valid_types:
            try:
                result = self.dashboard_engine.generate_dynamic_dashboard(dashboard_type)
                self.assertIsInstance(result, dict, f"Should return dict for {dashboard_type}")
                self.assertEqual(result['type'], dashboard_type)
            except Exception as e:
                self.fail(f"Valid dashboard type {dashboard_type} should not raise exception: {e}")
        
        # Test invalid dashboard type
        with self.assertRaises(ValidationError):
            self.dashboard_engine.generate_dynamic_dashboard('invalid_type')
    
    def test_executive_dashboard_generation(self):
        """Test executive dashboard generation."""
        result = self.dashboard_engine.generate_dynamic_dashboard('executive')
        
        # Verify basic structure
        self.assertIsInstance(result, dict)
        self.assertEqual(result['type'], 'executive')
        self.assertIn('title', result)
        self.assertIn('widgets', result)
        self.assertIn('layout', result)
        self.assertIn('generated_at', result)
        self.assertIn('metadata', result)
        
        # Verify widgets are present
        self.assertIsInstance(result['widgets'], list)
        
        # Verify layout configuration
        layout = result['layout']
        self.assertIn('columns', layout)
        self.assertIn('responsive', layout)
        self.assertTrue(layout['responsive'])
    
    def test_dashboard_filters_preparation(self):
        """Test dashboard filters preparation."""
        # Test with custom filters
        custom_filters = {
            'date_from': '2024-01-01',
            'date_to': '2024-01-31',
            'company_ids': [1, 2, 3],
        }
        
        result = self.dashboard_engine.generate_dynamic_dashboard(
            'executive', **custom_filters
        )
        
        filters = result['filters']
        self.assertIsInstance(filters['date_from'], date)
        self.assertIsInstance(filters['date_to'], date)
        self.assertEqual(filters['company_ids'], [1, 2, 3])
    
    def test_widget_generation_for_different_types(self):
        """Test widget generation for different dashboard types."""
        dashboard_types = ['executive', 'operational', 'financial', 'technical']
        
        for dashboard_type in dashboard_types:
            result = self.dashboard_engine.generate_dynamic_dashboard(dashboard_type)
            
            widgets = result['widgets']
            self.assertIsInstance(widgets, list, f"Widgets should be list for {dashboard_type}")
            
            # Verify each widget has required fields
            for widget in widgets:
                self.assertIn('id', widget, "Widget should have id")
                self.assertIn('type', widget, "Widget should have type")
                self.assertIn('title', widget, "Widget should have title")
                self.assertIn('size', widget, "Widget should have size")
                
                # Verify size structure
                size = widget['size']
                self.assertIn('w', size, "Size should have width")
                self.assertIn('h', size, "Size should have height")
    
    def test_kpi_sources_information(self):
        """Test KPI sources information generation."""
        result = self.dashboard_engine.generate_dynamic_dashboard('executive')
        
        kpi_sources = result['kpi_sources']
        self.assertIsInstance(kpi_sources, list)
        
        # Should include our test KPI provider
        test_provider_found = False
        for source in kpi_sources:
            if source['name'] == 'test_financial_kpis':
                test_provider_found = True
                self.assertEqual(source['module'], 'test_module')
                break
        
        self.assertTrue(test_provider_found, "Test KPI provider should be in sources")
    
    def test_user_preferences_application(self):
        """Test user preferences application."""
        preferences = {
            'hidden_widgets': ['financial_summary'],
            'widget_sizes': {
                'test_widget': {'w': 12, 'h': 6}
            },
            'layout': {
                'widget_margin': 15
            }
        }
        
        result = self.dashboard_engine.generate_dynamic_dashboard(
            'executive', 
            user_preferences=preferences
        )
        
        # Verify hidden widgets are not included
        widget_ids = [w['id'] for w in result['widgets']]
        self.assertNotIn('financial_summary', widget_ids)
        
        # Verify layout preferences applied
        self.assertEqual(result['layout']['widget_margin'], 15)
    
    def test_widget_priority_sorting(self):
        """Test widget priority sorting."""
        result = self.dashboard_engine.generate_dynamic_dashboard('executive')
        
        widgets = result['widgets']
        
        # Verify widgets are sorted by priority (high to low)
        if len(widgets) > 1:
            for i in range(len(widgets) - 1):
                current_priority = self.dashboard_engine._get_widget_priority_score(widgets[i])
                next_priority = self.dashboard_engine._get_widget_priority_score(widgets[i + 1])
                self.assertGreaterEqual(current_priority, next_priority, 
                                      "Widgets should be sorted by priority")
    
    def test_error_dashboard_generation(self):
        """Test error dashboard generation when services fail."""
        # Temporarily break the service registry to test error handling
        original_method = self.registry.get_available_services
        
        def broken_method():
            raise Exception("Test service failure")
        
        self.registry.get_available_services = broken_method
        
        try:
            result = self.dashboard_engine.generate_dynamic_dashboard('executive')
            
            # Should return error dashboard
            self.assertEqual(result['title'], 'Dashboard Error')
            self.assertIn('error', result)
            
            # Should have error widget
            widgets = result['widgets']
            self.assertEqual(len(widgets), 1)
            self.assertEqual(widgets[0]['type'], 'error')
            
        finally:
            # Restore original method
            self.registry.get_available_services = original_method
    
    def test_built_in_widget_data(self):
        """Test built-in widget data generation."""
        filters = {
            'date_from': date.today() - timedelta(days=30),
            'date_to': date.today(),
            'company_ids': [self.env.company.id]
        }
        
        # Test financial summary data
        financial_data = self.dashboard_engine._get_financial_summary_data(filters)
        self.assertIsInstance(financial_data, dict)
        self.assertIn('kpis', financial_data)
        
        # Test system health data
        health_data = self.dashboard_engine._get_system_health_data(filters)
        self.assertIsInstance(health_data, dict)
        self.assertIn('value', health_data)
        self.assertIn('thresholds', health_data)
    
    def test_max_widgets_constraint(self):
        """Test maximum widgets constraint per dashboard type."""
        # Generate dashboard and verify widget count doesn't exceed maximum
        result = self.dashboard_engine.generate_dynamic_dashboard('executive')
        
        max_widgets = self.dashboard_engine._get_max_widgets_for_type('executive')
        actual_widgets = len(result['widgets'])
        
        self.assertLessEqual(actual_widgets, max_widgets, 
                           f"Widget count ({actual_widgets}) should not exceed maximum ({max_widgets})")
    
    def test_widget_data_loading_error_handling(self):
        """Test error handling in widget data loading."""
        # Create a dashboard with widgets
        result = self.dashboard_engine.generate_dynamic_dashboard('executive')
        
        # Verify that widgets with data errors still exist in result
        for widget in result['widgets']:
            self.assertIn('data', widget, "All widgets should have data field")
            
            # If there's an error, it should be handled gracefully
            if isinstance(widget.get('data'), dict) and widget['data'].get('error'):
                self.assertIsInstance(widget['data']['error'], str, 
                                    "Error should be a string")
    
    def tearDown(self):
        """Clean up after tests."""
        super().tearDown()
        # Clear registry to avoid affecting other tests
        self.registry.clear_registry()
