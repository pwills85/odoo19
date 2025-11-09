# -*- coding: utf-8 -*-
"""
Post-init hooks for l10n_cl_financial_reports module
====================================================

Hooks for initializing the integration layer and auto-discovering services.

Author: EERGYGROUP - Based on technical audit specifications
"""

import logging

_logger = logging.getLogger(__name__)


def post_init_hook(env):
    """
    Post-installation hook for l10n_cl_financial_reports module.

    Initializes the integration layer and auto-discovers services from
    installed modules.

    Args:
        env: Odoo environment
    """

    try:
        _logger.info("l10n_cl_financial_reports: Starting integration layer initialization")

        # Check if integration models are available
        if 'financial.report.service.registry' not in env:
            _logger.error("l10n_cl_financial_reports: Service registry model not available")
            return

        # Initialize the service registry
        service_registry = env['financial.report.service.registry']

        # Auto-discover services from all installed modules
        _logger.info("l10n_cl_financial_reports: Starting auto-discovery of services")
        discovery_results = service_registry.auto_discover_services()

        _logger.info(
            "l10n_cl_financial_reports: Auto-discovery completed - Modules: %s, Services: %d",
            discovery_results.get('discovered_modules', []),
            discovery_results.get('registered_services', 0)
        )

        if discovery_results.get('errors'):
            for error in discovery_results['errors']:
                _logger.warning("l10n_cl_financial_reports: Discovery error: %s", error)

        # Mark initialization as complete
        service_registry.mark_initialization_complete()

        # Log registry statistics
        stats = service_registry.get_registry_stats()
        _logger.info(
            "l10n_cl_financial_reports: Integration layer initialized - "
            "Services: %d, KPI providers: %d, Widget providers: %d",
            stats.get('total_services', 0),
            stats.get('kpi_providers', 0),
            stats.get('widget_providers', 0)
        )

        # Initialize hook system if available
        if 'financial.report.hook.system' in env:
            hook_system = env['financial.report.hook.system']
            hook_stats = hook_system.get_hook_stats()
            _logger.info(
                "l10n_cl_financial_reports: Hook system initialized - "
                "Registered hooks: %d, Hook names: %s",
                hook_stats.get('total_hooks', 0),
                hook_stats.get('hook_names', [])
            )

        _logger.info("l10n_cl_financial_reports: Integration layer initialization completed successfully")

    except Exception as e:
        _logger.error("l10n_cl_financial_reports: Error during integration layer initialization: %s", str(e))
        # Don't raise the exception to avoid breaking module installation


def uninstall_hook(env):
    """
    Uninstall hook for l10n_cl_financial_reports module.

    Cleans up integration layer and services.

    Args:
        env: Odoo environment
    """
    try:
        _logger.info("l10n_cl_financial_reports: Starting module uninstall cleanup")

        # Clean up service registry if available
        if 'financial.report.service.registry' in env:
            service_registry = env['financial.report.service.registry']
            service_registry.cleanup_module_services('l10n_cl_financial_reports')
            _logger.info("l10n_cl_financial_reports: Service registry cleaned up")

        _logger.info("l10n_cl_financial_reports: Module uninstall cleanup completed")

    except Exception as e:
        _logger.error("l10n_cl_financial_reports: Error during module uninstall: %s", str(e))
