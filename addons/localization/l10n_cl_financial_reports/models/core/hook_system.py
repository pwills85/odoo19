# -*- coding: utf-8 -*-
"""
Financial Report Hook System
============================

Hook system for event-driven integration between modules.
Enables modules to register callbacks for specific events without tight coupling.

Author: EERGYGROUP - Based on technical audit specifications
"""

import logging
from collections import defaultdict

from odoo import api, fields, models, _
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


class FinancialReportHookSystem(models.AbstractModel):
    """
    Hook system for event-driven integration between modules.

    This system allows modules to register callback functions that will be
    executed when specific events occur in the financial reporting system.
    All callbacks are executed in priority order and can modify the data
    being passed through the hook.
    """
    _name = 'financial.report.hook.system'
    _description = 'Financial Report Hook System'

    @api.model
    def _init_hooks(self):
        """Initialize the hook system with empty collections."""
        # Hook registry - reset on each restart
        self._hooks = defaultdict(list)

    # Predefined hook names for common integration points
    HOOK_DASHBOARD_DATA_LOADED = 'dashboard_data_loaded'
    HOOK_KPI_CALCULATION = 'kpi_calculation'
    HOOK_REPORT_GENERATED = 'report_generated'
    HOOK_EXPORT_REQUESTED = 'export_requested'
    HOOK_ALERT_TRIGGERED = 'alert_triggered'
    HOOK_WIDGET_DATA_REQUESTED = 'widget_data_requested'
    HOOK_MODULE_INTEGRATION = 'module_integration'

    @api.model
    def register_hook(self, hook_name, callback, priority=10, module_name=None):
        """
        Register a hook callback.

        Args:
            hook_name (str): Name of the hook (e.g., 'dashboard_data_loaded')
            callback (callable): Function to call when hook is triggered
            priority (int): Execution priority (lower number = higher priority)
            module_name (str, optional): Name of module registering the hook

        Returns:
            bool: True if registration successful

        Raises:
            UserError: If callback is not callable
        """
        if not callable(callback):
            raise UserError(_("Hook callback must be callable"))

        hook_info = {
            'callback': callback,
            'priority': priority,
            'module': module_name or 'unknown',
            'registered_at': fields.Datetime.now(),
        }

        self._hooks[hook_name].append(hook_info)

        # Sort by priority (lower number = higher priority)
        self._hooks[hook_name].sort(key=lambda x: x['priority'])

        _logger.info(
            "Registered hook '%s' with priority %d from module %s",
            hook_name, priority, module_name or 'unknown'
        )
        return True

    @api.model
    def trigger_hook(self, hook_name, data=None, context=None):
        """
        Trigger all callbacks registered for a hook.

        Args:
            hook_name (str): Name of the hook to trigger
            data (any): Data to pass to callbacks (will be modified in-place)
            context (dict, optional): Additional context information

        Returns:
            any: Modified data after all callbacks have been executed
        """
        if hook_name not in self._hooks:
            _logger.debug("No callbacks registered for hook '%s'", hook_name)
            return data

        _logger.debug(
            "Triggering hook '%s' with %d callbacks",
            hook_name, len(self._hooks[hook_name])
        )

        # Prepare context
        hook_context = context or {}
        hook_context.update({
            'hook_name': hook_name,
            'triggered_at': fields.Datetime.now(),
            'env': self.env,
        })

        # Execute callbacks in priority order
        for hook_info in self._hooks[hook_name]:
            try:
                callback = hook_info['callback']
                module_name = hook_info['module']

                _logger.debug(
                    "Executing hook callback from module %s for hook '%s'",
                    module_name, hook_name
                )

                # Execute callback with data and context
                result = callback(data, hook_context)

                # If callback returns a value, use it as the new data
                if result is not None:
                    data = result

            except Exception as e:
                _logger.error(
                    "Error executing hook callback from module %s for hook '%s': %s",
                    hook_info['module'], hook_name, str(e)
                )
                # Continue with other callbacks even if one fails
                continue

        return data

    @api.model
    def get_registered_hooks(self, hook_name=None):
        """
        Get information about registered hooks.

        Args:
            hook_name (str, optional): Filter by specific hook name

        Returns:
            dict: Information about registered hooks
        """
        if hook_name:
            hooks_info = {}
            if hook_name in self._hooks:
                hooks_info[hook_name] = [
                    {
                        'module': hook_info['module'],
                        'priority': hook_info['priority'],
                        'registered_at': hook_info['registered_at'],
                    }
                    for hook_info in self._hooks[hook_name]
                ]
            return hooks_info

        # Return all hooks information
        all_hooks_info = {}
        for hook_name, hook_list in self._hooks.items():
            all_hooks_info[hook_name] = [
                {
                    'module': hook_info['module'],
                    'priority': hook_info['priority'],
                    'registered_at': hook_info['registered_at'],
                }
                for hook_info in hook_list
            ]

        return all_hooks_info

    @api.model
    def unregister_hook(self, hook_name, module_name=None):
        """
        Unregister hooks for a specific module or all hooks for a hook name.

        Args:
            hook_name (str): Name of the hook
            module_name (str, optional): Module name to filter unregistration

        Returns:
            int: Number of hooks unregistered
        """
        if hook_name not in self._hooks:
            return 0

        initial_count = len(self._hooks[hook_name])

        if module_name:
            # Remove only hooks from specific module
            self._hooks[hook_name] = [
                hook_info for hook_info in self._hooks[hook_name]
                if hook_info['module'] != module_name
            ]
        else:
            # Remove all hooks for this hook name
            self._hooks[hook_name] = []

        removed_count = initial_count - len(self._hooks[hook_name])

        if removed_count > 0:
            _logger.info(
                "Unregistered %d hook(s) for '%s'%s",
                removed_count, hook_name,
                f" from module {module_name}" if module_name else ""
            )

        return removed_count

    @api.model
    def clear_all_hooks(self):
        """
        Clear all registered hooks (used for testing and cleanup).

        Returns:
            int: Number of hooks cleared
        """
        total_hooks = sum(len(hook_list) for hook_list in self._hooks.values())
        self._hooks.clear()

        _logger.info("Cleared %d hooks from hook system", total_hooks)
        return total_hooks

    @api.model
    def get_hook_stats(self):
        """
        Get statistics about the hook system.

        Returns:
            dict: Hook system statistics
        """
        hook_counts = {name: len(hooks) for name, hooks in self._hooks.items()}
        modules = set()

        for hook_list in self._hooks.values():
            for hook_info in hook_list:
                modules.add(hook_info['module'])

        return {
            'total_hooks': sum(hook_counts.values()),
            'hook_names': list(self._hooks.keys()),
            'hook_counts': hook_counts,
            'registered_modules': list(modules),
            'predefined_hooks': [
                self.HOOK_DASHBOARD_DATA_LOADED,
                self.HOOK_KPI_CALCULATION,
                self.HOOK_REPORT_GENERATED,
                self.HOOK_EXPORT_REQUESTED,
                self.HOOK_ALERT_TRIGGERED,
                self.HOOK_WIDGET_DATA_REQUESTED,
                self.HOOK_MODULE_INTEGRATION,
            ],
        }

    @api.model
    def validate_hook_integrity(self):
        """
        Validate that all registered hooks have valid callbacks.

        Returns:
            dict: Validation results
        """
        results = {
            'valid_hooks': 0,
            'invalid_hooks': 0,
            'errors': [],
        }

        for hook_name, hook_list in self._hooks.items():
            for i, hook_info in enumerate(hook_list):
                try:
                    callback = hook_info['callback']
                    if not callable(callback):
                        error_msg = f"Hook {hook_name}[{i}] from {hook_info['module']} has non-callable callback"
                        results['errors'].append(error_msg)
                        results['invalid_hooks'] += 1
                    else:
                        results['valid_hooks'] += 1

                except Exception as e:
                    error_msg = f"Hook {hook_name}[{i}] from {hook_info['module']} validation error: {str(e)}"
                    results['errors'].append(error_msg)
                    results['invalid_hooks'] += 1

        return results
