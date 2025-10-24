# -*- coding: utf-8 -*-
"""
Financial Report Service Registry
=================================

Universal service registry for dynamic service discovery and registration.
Allows any module to register services that integrate with financial reports.

Author: EERGYGROUP - Based on technical audit specifications
"""

import logging
from collections import defaultdict
from datetime import datetime

from odoo import api, fields, models, _
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)


class FinancialReportServiceRegistry(models.AbstractModel):
    """
    Universal service registry for dynamic service discovery and registration.

    This registry allows any installed module to register KPI providers, widget providers,
    export providers, and alert providers that can be consumed by the universal dashboard
    engine without duplicating business logic or data.

    All registrations are done through method calls and stored in memory during the
    Odoo session lifecycle.
    """
    _name = 'financial.report.service.registry'
    _description = 'Financial Report Service Registry'

    @api.model
    def _init_registry(self):
        """Initialize the registry with empty collections."""
        # Internal registry storage - reset on each restart
        self._service_registry = defaultdict(dict)
        self._kpi_providers = {}
        self._widget_providers = defaultdict(list)
        self._export_providers = {}
        self._alert_providers = {}
        self._initialization_complete = False

    @api.model
    def register_service(self, service_type, service_name, service_class, module_name):
        """
        Register a service in the global registry.

        Args:
            service_type (str): Type of service ('kpi', 'widget', 'export', 'alert', 'dashboard')
            service_name (str): Unique service identifier
            service_class: Service class or callable method
            module_name (str): Module that provides the service

        Returns:
            bool: True if registration successful

        Raises:
            ValidationError: If service_type is invalid or service_name already exists
        """
        valid_service_types = ['kpi', 'widget', 'export', 'alert', 'dashboard']
        if service_type not in valid_service_types:
            raise ValidationError(_(
                "Invalid service type '%s'. Valid types are: %s"
            ) % (service_type, ', '.join(valid_service_types)))

        if service_name in self._service_registry[service_type]:
            _logger.warning(
                "Service '%s' of type '%s' already registered. Overwriting with new registration from '%s'",
                service_name, service_type, module_name
            )

        self._service_registry[service_type][service_name] = {
            'class': service_class,
            'module': module_name,
            'registered_at': fields.Datetime.now(),
        }

        _logger.info(
            "Registered %s service: %s from module %s",
            service_type, service_name, module_name
        )
        return True

    @api.model
    def get_available_services(self, service_type=None):
        """
        Get all available services of a specific type or all types.

        Args:
            service_type (str, optional): Filter by service type

        Returns:
            dict: Dictionary of available services
        """
        if service_type:
            return dict(self._service_registry.get(service_type, {}))
        return {
            service_type: dict(services)
            for service_type, services in self._service_registry.items()
        }

    @api.model
    def auto_discover_services(self):
        """
        Auto-discover services from installed modules that follow naming conventions.

        This method scans all installed modules for integration providers following
        the standard naming pattern: {module_name}.{service_type}_provider

        Returns:
            dict: Summary of discovered services
        """
        installed_modules = self.env['ir.module.module'].search([
            ('state', '=', 'installed'),
            ('name', 'in', [
                'l10n_cl_base', 'l10n_cl_fe', 'l10n_cl_payroll',
                'l10n_cl_project', 'account_budget', 'monitoring_integration'
            ])
        ])

        discovery_summary = {
            'discovered_modules': [],
            'registered_services': 0,
            'errors': []
        }

        for module in installed_modules:
            try:
                discovered_count = self._discover_module_services(module.name)
                if discovered_count > 0:
                    discovery_summary['discovered_modules'].append(module.name)
                    discovery_summary['registered_services'] += discovered_count

            except Exception as e:
                error_msg = f"Could not discover services in {module.name}: {str(e)}"
                _logger.warning(error_msg)
                discovery_summary['errors'].append(error_msg)

        _logger.info(
            "Auto-discovery completed. Modules: %s, Services: %d",
            discovery_summary['discovered_modules'],
            discovery_summary['registered_services']
        )

        return discovery_summary

    def _discover_module_services(self, module_name):
        """
        Discover services in a specific module.

        Args:
            module_name (str): Name of the module to scan

        Returns:
            int: Number of services discovered and registered
        """
        discovered_count = 0

        # Service provider model patterns to look for
        provider_patterns = [
            (f'{module_name}.kpi_provider', 'kpi'),
            (f'{module_name}.widget_provider', 'widget'),
            (f'{module_name}.export_provider', 'export'),
            (f'{module_name}.alert_provider', 'alert'),
        ]

        for model_name, service_type in provider_patterns:
            try:
                if model_name in self.env:
                    # Model exists, register it
                    service_name = f"{module_name}_{service_type}"
                    self.register_service(
                        service_type=service_type,
                        service_name=service_name,
                        service_class=model_name,
                        module_name=module_name
                    )
                    discovered_count += 1

            except Exception as e:
                _logger.debug(
                    "Could not register %s service from %s: %s",
                    service_type, module_name, str(e)
                )

        return discovered_count

    @api.model
    def register_kpi_provider(self, provider_name, kpi_method, module_name):
        """
        Register a KPI provider method.

        Args:
            provider_name (str): Unique provider identifier
            kpi_method (callable): Method that returns KPI data
            module_name (str): Module that provides the KPIs

        Returns:
            bool: True if registration successful
        """
        if not callable(kpi_method):
            raise ValidationError(_("KPI method must be callable"))

        self._kpi_providers[provider_name] = {
            'method': kpi_method,
            'module': module_name,
            'registered_at': fields.Datetime.now(),
        }

        _logger.info("Registered KPI provider: %s from %s", provider_name, module_name)
        return True

    @api.model
    def register_widget_provider(self, widget_type, widget_class, module_name):
        """
        Register a widget provider.

        Args:
            widget_type (str): Type of widget provided
            widget_class: Widget class or model name
            module_name (str): Module that provides the widget

        Returns:
            bool: True if registration successful
        """
        self._widget_providers[widget_type].append({
            'class': widget_class,
            'module': module_name,
            'registered_at': fields.Datetime.now(),
        })

        _logger.info(
            "Registered widget provider: %s (%s) from %s",
            widget_type, widget_class, module_name
        )
        return True

    @api.model
    def get_consolidated_kpis(self, date_from, date_to, company_ids=None):
        """
        Get KPIs from all registered providers.

        Args:
            date_from (date): Start date for KPI calculation
            date_to (date): End date for KPI calculation
            company_ids (list, optional): List of company IDs to filter

        Returns:
            dict: Consolidated KPIs from all registered providers
        """
        if not company_ids:
            company_ids = [self.env.company.id]

        consolidated_kpis = {}

        for provider_name, provider_info in self._kpi_providers.items():
            try:
                kpi_method = provider_info['method']
                provider_kpis = kpi_method(date_from, date_to, company_ids)

                if provider_kpis and isinstance(provider_kpis, dict):
                    consolidated_kpis[provider_name] = {
                        'data': provider_kpis,
                        'module': provider_info['module'],
                        'generated_at': fields.Datetime.now(),
                    }

            except Exception as e:
                _logger.error(
                    "Error getting KPIs from provider %s: %s",
                    provider_name, str(e)
                )
                consolidated_kpis[provider_name] = {
                    'data': {},
                    'module': provider_info['module'],
                    'error': str(e),
                    'generated_at': fields.Datetime.now(),
                }

        return consolidated_kpis

    @api.model
    def get_available_widgets(self, widget_type=None):
        """
        Get available widgets from registered providers.

        Args:
            widget_type (str, optional): Filter by widget type

        Returns:
            dict: Available widgets by type
        """
        if widget_type:
            return {widget_type: list(self._widget_providers.get(widget_type, []))}

        return {
            wtype: list(widgets)
            for wtype, widgets in self._widget_providers.items()
        }

    @api.model
    def clear_registry(self):
        """
        Clear all registered services (used for testing and cleanup).

        Returns:
            bool: True if cleanup successful
        """
        self._service_registry.clear()
        self._kpi_providers.clear()
        self._widget_providers.clear()
        self._export_providers.clear()
        self._alert_providers.clear()
        self._initialization_complete = False

        _logger.info("Service registry cleared")
        return True

    @api.model
    def get_registry_stats(self):
        """
        Get statistics about the current registry state.

        Returns:
            dict: Registry statistics
        """
        return {
            'total_services': sum(len(services) for services in self._service_registry.values()),
            'kpi_providers': len(self._kpi_providers),
            'widget_providers': sum(len(widgets) for widgets in self._widget_providers.values()),
            'export_providers': len(self._export_providers),
            'alert_providers': len(self._alert_providers),
            'service_types': list(self._service_registry.keys()),
            'widget_types': list(self._widget_providers.keys()),
            'initialization_complete': self._initialization_complete,
        }

    @api.model
    def mark_initialization_complete(self):
        """Mark registry initialization as complete."""
        self._initialization_complete = True
        _logger.info("Service registry initialization marked as complete")
