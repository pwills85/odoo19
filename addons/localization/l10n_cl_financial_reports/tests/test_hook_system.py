# -*- coding: utf-8 -*-
"""
Unit tests for Financial Report Hook System
===========================================

Tests the hook system functionality for event-driven integration
between modules without altering existing business logic.

Author: EERGYGROUP - Based on technical audit specifications
"""

import logging

from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class TestFinancialReportHookSystem(TransactionCase):
    """Test cases for the Financial Report Hook System."""
    
    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.hook_system = self.env['financial.report.hook.system']
        
        # Clear hooks before each test
        self.hook_system.clear_all_hooks()
    
    def test_hook_registration(self):
        """Test basic hook registration functionality."""
        # Test callback function
        def test_callback(data, context):
            data['test_flag'] = True
            return data
        
        # Register hook
        result = self.hook_system.register_hook(
            hook_name='test_hook',
            callback=test_callback,
            priority=10,
            module_name='test_module'
        )
        
        self.assertTrue(result, "Hook registration should succeed")
        
        # Test retrieving registered hooks
        hooks = self.hook_system.get_registered_hooks('test_hook')
        self.assertIn('test_hook', hooks, "Registered hook should be available")
        
        hook_info = hooks['test_hook'][0]
        self.assertEqual(hook_info['module'], 'test_module')
        self.assertEqual(hook_info['priority'], 10)
    
    def test_invalid_callback(self):
        """Test registration with invalid callback."""
        with self.assertRaises(UserError):
            self.hook_system.register_hook(
                hook_name='test_hook',
                callback='not_callable',  # Invalid callback
                priority=10,
                module_name='test_module'
            )
    
    def test_hook_triggering(self):
        """Test hook triggering functionality."""
        # Test callback function
        def test_callback(data, context):
            if data is None:
                data = {}
            data['callback_executed'] = True
            data['context_hook_name'] = context.get('hook_name')
            return data
        
        # Register hook
        self.hook_system.register_hook(
            hook_name='test_trigger_hook',
            callback=test_callback,
            priority=10,
            module_name='test_module'
        )
        
        # Trigger hook
        test_data = {'initial': True}
        result = self.hook_system.trigger_hook('test_trigger_hook', test_data)
        
        # Verify data was modified by callback
        self.assertTrue(result['callback_executed'], "Callback should have been executed")
        self.assertEqual(result['context_hook_name'], 'test_trigger_hook')
        self.assertTrue(result['initial'], "Original data should be preserved")
    
    def test_hook_priority_ordering(self):
        """Test that hooks are executed in priority order."""
        execution_order = []
        
        def high_priority_callback(data, context):
            execution_order.append('high')
            return data
        
        def low_priority_callback(data, context):
            execution_order.append('low')
            return data
        
        # Register hooks with different priorities
        self.hook_system.register_hook(
            hook_name='priority_test_hook',
            callback=low_priority_callback,
            priority=20,  # Lower priority (higher number)
            module_name='test_module'
        )
        
        self.hook_system.register_hook(
            hook_name='priority_test_hook',
            callback=high_priority_callback,
            priority=5,   # Higher priority (lower number)
            module_name='test_module'
        )
        
        # Trigger hook
        self.hook_system.trigger_hook('priority_test_hook', {})
        
        # Verify execution order
        self.assertEqual(execution_order, ['high', 'low'], "Hooks should execute in priority order")
    
    def test_hook_error_handling(self):
        """Test error handling in hook callbacks."""
        execution_log = []
        
        def error_callback(data, context):
            execution_log.append('error_callback')
            raise Exception("Test error")
        
        def success_callback(data, context):
            execution_log.append('success_callback')
            return data
        
        # Register both callbacks
        self.hook_system.register_hook(
            hook_name='error_test_hook',
            callback=error_callback,
            priority=5,
            module_name='test_module'
        )
        
        self.hook_system.register_hook(
            hook_name='error_test_hook',
            callback=success_callback,
            priority=10,
            module_name='test_module'
        )
        
        # Trigger hook - should not raise exception
        result = self.hook_system.trigger_hook('error_test_hook', {'test': True})
        
        # Verify both callbacks were attempted
        self.assertIn('error_callback', execution_log)
        self.assertIn('success_callback', execution_log)
        
        # Verify result still contains original data
        self.assertTrue(result['test'])
    
    def test_hook_unregistration(self):
        """Test hook unregistration functionality."""
        def test_callback(data, context):
            return data
        
        # Register hook
        self.hook_system.register_hook(
            hook_name='unregister_test_hook',
            callback=test_callback,
            priority=10,
            module_name='test_module'
        )
        
        # Verify hook is registered
        hooks_before = self.hook_system.get_registered_hooks('unregister_test_hook')
        self.assertIn('unregister_test_hook', hooks_before)
        
        # Unregister hook
        removed_count = self.hook_system.unregister_hook('unregister_test_hook', 'test_module')
        self.assertEqual(removed_count, 1, "Should have removed one hook")
        
        # Verify hook is unregistered
        hooks_after = self.hook_system.get_registered_hooks('unregister_test_hook')
        self.assertEqual(len(hooks_after.get('unregister_test_hook', [])), 0)
    
    def test_hook_statistics(self):
        """Test hook system statistics."""
        # Register some test hooks
        def dummy_callback(data, context):
            return data
        
        self.hook_system.register_hook('stats_hook_1', dummy_callback, module_name='module_1')
        self.hook_system.register_hook('stats_hook_2', dummy_callback, module_name='module_2')
        self.hook_system.register_hook('stats_hook_1', dummy_callback, module_name='module_2')
        
        stats = self.hook_system.get_hook_stats()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('total_hooks', stats)
        self.assertIn('hook_names', stats)
        self.assertIn('registered_modules', stats)
        
        self.assertEqual(stats['total_hooks'], 3)
        self.assertIn('stats_hook_1', stats['hook_names'])
        self.assertIn('stats_hook_2', stats['hook_names'])
        self.assertIn('module_1', stats['registered_modules'])
        self.assertIn('module_2', stats['registered_modules'])
    
    def test_hook_validation(self):
        """Test hook integrity validation."""
        # Register a valid hook
        def valid_callback(data, context):
            return data
        
        self.hook_system.register_hook(
            hook_name='validation_test_hook',
            callback=valid_callback,
            module_name='test_module'
        )
        
        # Validate hooks
        validation_results = self.hook_system.validate_hook_integrity()
        
        self.assertIsInstance(validation_results, dict)
        self.assertIn('valid_hooks', validation_results)
        self.assertIn('invalid_hooks', validation_results)
        self.assertIn('errors', validation_results)
        
        self.assertGreaterEqual(validation_results['valid_hooks'], 1)
        self.assertEqual(validation_results['invalid_hooks'], 0)
    
    def test_predefined_hook_constants(self):
        """Test that predefined hook constants are available."""
        # Test that predefined hook constants exist
        self.assertTrue(hasattr(self.hook_system, 'HOOK_DASHBOARD_DATA_LOADED'))
        self.assertTrue(hasattr(self.hook_system, 'HOOK_KPI_CALCULATION'))
        self.assertTrue(hasattr(self.hook_system, 'HOOK_REPORT_GENERATED'))
        self.assertTrue(hasattr(self.hook_system, 'HOOK_EXPORT_REQUESTED'))
        self.assertTrue(hasattr(self.hook_system, 'HOOK_ALERT_TRIGGERED'))
        
        # Test that constants have expected values
        self.assertEqual(self.hook_system.HOOK_DASHBOARD_DATA_LOADED, 'dashboard_data_loaded')
        self.assertEqual(self.hook_system.HOOK_KPI_CALCULATION, 'kpi_calculation')
    
    def test_clear_all_hooks(self):
        """Test clearing all hooks functionality."""
        # Register some test hooks
        def dummy_callback(data, context):
            return data
        
        self.hook_system.register_hook('clear_test_hook_1', dummy_callback, module_name='test_module')
        self.hook_system.register_hook('clear_test_hook_2', dummy_callback, module_name='test_module')
        
        # Verify hooks exist
        stats_before = self.hook_system.get_hook_stats()
        self.assertGreater(stats_before['total_hooks'], 0)
        
        # Clear all hooks
        cleared_count = self.hook_system.clear_all_hooks()
        self.assertGreaterEqual(cleared_count, 2)
        
        # Verify hooks are cleared
        stats_after = self.hook_system.get_hook_stats()
        self.assertEqual(stats_after['total_hooks'], 0)
    
    def tearDown(self):
        """Clean up after tests."""
        super().tearDown()
        # Clear hooks to avoid affecting other tests
        self.hook_system.clear_all_hooks()
