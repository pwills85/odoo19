# -*- coding: utf-8 -*-
"""
Universal Financial API Controller
==================================

Universal REST API for financial report integration.
Provides standardized endpoints for all modules to integrate with the financial reporting system.

Author: EERGYGROUP - Based on technical audit specifications
"""

import logging
import json
from datetime import datetime, date

from odoo import http, fields, _
from odoo.http import request
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)


class UniversalFinancialAPI(http.Controller):
    """
    Universal REST API for financial report integration.
    
    This controller provides standardized endpoints that allow any module
    to integrate with the financial reporting system and access consolidated
    data from all registered providers.
    """
    
    @http.route('/api/financial/dashboard/<string:dashboard_type>', 
                type='json', auth='user', methods=['GET'])
    def get_dashboard(self, dashboard_type, **filters):
        """
        Get dashboard data for any registered dashboard type.
        
        Args:
            dashboard_type (str): Type of dashboard requested ('executive', 'operational', 'financial', 'technical')
            **filters: Additional filters (date_from, date_to, company_ids, preferences)
            
        Returns:
            dict: Complete dashboard data with metadata
        """
        try:
            # Validate dashboard type
            valid_types = ['executive', 'operational', 'financial', 'technical']
            if dashboard_type not in valid_types:
                return {
                    'success': False,
                    'error': _('Invalid dashboard type. Valid types: %s') % ', '.join(valid_types),
                    'dashboard': None,
                }
            
            # Check if universal dashboard engine is available
            if 'financial.report.universal.dashboard' not in request.env:
                return {
                    'success': False,
                    'error': _('Universal dashboard engine not available'),
                    'dashboard': None,
                }
            
            # Prepare filters
            prepared_filters = self._prepare_api_filters(filters)
            
            # Get dashboard engine
            dashboard_engine = request.env['financial.report.universal.dashboard']
            
            # Generate dashboard
            dashboard_data = dashboard_engine.generate_dynamic_dashboard(
                dashboard_type=dashboard_type,
                user_preferences=filters.get('preferences'),
                **prepared_filters
            )
            
            return {
                'success': True,
                'dashboard': dashboard_data,
                'metadata': {
                    'generated_at': fields.Datetime.now(),
                    'user_id': request.env.user.id,
                    'company_id': request.env.company.id,
                    'api_version': '1.0',
                    'request_filters': prepared_filters,
                }
            }
            
        except Exception as e:
            _logger.error("Error in get_dashboard API: %s", str(e))
            return {
                'success': False,
                'error': str(e),
                'dashboard': None,
            }
    
    @http.route('/api/financial/kpis', type='json', auth='user', methods=['GET'])
    def get_consolidated_kpis(self, **filters):
        """
        Get KPIs from all registered providers.
        
        Args:
            **filters: Filters (date_from, date_to, company_ids, kpi_types, providers)
            
        Returns:
            dict: Consolidated KPIs from all modules
        """
        try:
            # Check if service registry is available
            if 'financial.report.service.registry' not in request.env:
                return {
                    'success': False,
                    'error': _('Service registry not available'),
                    'kpis': {},
                }
            
            # Prepare filters
            prepared_filters = self._prepare_api_filters(filters)
            
            # Get service registry
            service_registry = request.env['financial.report.service.registry']
            
            # Get consolidated KPIs
            consolidated_kpis = service_registry.get_consolidated_kpis(
                date_from=prepared_filters['date_from'],
                date_to=prepared_filters['date_to'],
                company_ids=prepared_filters['company_ids']
            )
            
            # Filter by requested KPI types if specified
            kpi_types = filters.get('kpi_types', [])
            if kpi_types:
                filtered_kpis = {}
                for kpi_type in kpi_types:
                    if kpi_type in consolidated_kpis:
                        filtered_kpis[kpi_type] = consolidated_kpis[kpi_type]
                consolidated_kpis = filtered_kpis
            
            # Filter by requested providers if specified
            providers = filters.get('providers', [])
            if providers:
                filtered_kpis = {}
                for provider in providers:
                    if provider in consolidated_kpis:
                        filtered_kpis[provider] = consolidated_kpis[provider]
                consolidated_kpis = filtered_kpis
            
            return {
                'success': True,
                'kpis': consolidated_kpis,
                'metadata': {
                    'period': {
                        'from': prepared_filters['date_from'],
                        'to': prepared_filters['date_to'],
                    },
                    'companies': prepared_filters['company_ids'],
                    'providers_count': len(consolidated_kpis),
                    'generated_at': fields.Datetime.now(),
                }
            }
            
        except Exception as e:
            _logger.error("Error in get_consolidated_kpis API: %s", str(e))
            return {
                'success': False,
                'error': str(e),
                'kpis': {},
            }
    
    @http.route('/api/financial/widgets/<string:widget_type>', 
                type='json', auth='user', methods=['GET'])
    def get_widget_data(self, widget_type, **filters):
        """
        Get specific widget data from registered providers.
        
        Args:
            widget_type (str): Type of widget requested
            **filters: Widget filters
            
        Returns:
            dict: Widget configuration and data
        """
        try:
            # Check if service registry is available
            if 'financial.report.service.registry' not in request.env:
                return {
                    'success': False,
                    'error': _('Service registry not available'),
                    'widget': None,
                }
            
            # Prepare filters
            prepared_filters = self._prepare_api_filters(filters)
            
            # Get available widgets
            service_registry = request.env['financial.report.service.registry']
            available_widgets = service_registry.get_available_widgets(widget_type)
            
            if not available_widgets.get(widget_type):
                return {
                    'success': False,
                    'error': _('Widget type not found: %s') % widget_type,
                    'widget': None,
                }
            
            # Get the first available widget provider for this type
            widget_providers = available_widgets[widget_type]
            if not widget_providers:
                return {
                    'success': False,
                    'error': _('No providers found for widget type: %s') % widget_type,
                    'widget': None,
                }
            
            # Use the first provider
            provider_info = widget_providers[0]
            widget_class = provider_info['class']
            module_name = provider_info['module']
            
            # Load widget data
            widget_data = self._load_widget_data_from_provider(
                widget_class, widget_type, prepared_filters
            )
            
            return {
                'success': True,
                'widget': widget_data,
                'metadata': {
                    'widget_type': widget_type,
                    'provider_module': module_name,
                    'generated_at': fields.Datetime.now(),
                }
            }
            
        except Exception as e:
            _logger.error("Error in get_widget_data API: %s", str(e))
            return {
                'success': False,
                'error': str(e),
                'widget': None,
            }
    
    @http.route('/api/financial/services/register', 
                type='json', auth='user', methods=['POST'])
    def register_external_service(self, service_config):
        """
        Allow external modules to register services dynamically.
        
        Args:
            service_config (dict): Service configuration
            
        Returns:
            dict: Registration result
        """
        try:
            # Validate required fields
            required_fields = ['service_type', 'service_name', 'module_name']
            if not all(field in service_config for field in required_fields):
                return {
                    'success': False,
                    'error': _('Missing required fields: %s') % required_fields,
                }
            
            # Check if service registry is available
            if 'financial.report.service.registry' not in request.env:
                return {
                    'success': False,
                    'error': _('Service registry not available'),
                }
            
            # Get service registry
            service_registry = request.env['financial.report.service.registry']
            
            # Register the service
            success = service_registry.register_service(
                service_type=service_config['service_type'],
                service_name=service_config['service_name'],
                service_class=service_config.get('service_class'),
                module_name=service_config['module_name']
            )
            
            if success:
                return {
                    'success': True,
                    'message': _("Service '%s' registered successfully") % service_config['service_name'],
                }
            else:
                return {
                    'success': False,
                    'error': _("Failed to register service '%s'") % service_config['service_name'],
                }
            
        except Exception as e:
            _logger.error("Error in register_external_service API: %s", str(e))
            return {
                'success': False,
                'error': str(e),
            }
    
    @http.route('/api/financial/modules/integration-status', 
                type='json', auth='user', methods=['GET'])
    def get_integration_status(self):
        """
        Get integration status of all modules with financial reports.
        
        Returns:
            dict: Integration status for each module
        """
        try:
            # Check if service registry is available
            if 'financial.report.service.registry' not in request.env:
                return {
                    'success': False,
                    'error': _('Service registry not available'),
                    'integration_status': {},
                }
            
            # Get service registry
            service_registry = request.env['financial.report.service.registry']
            available_services = service_registry.get_available_services()
            
            integration_status = {}
            
            # Define modules to check
            modules_to_check = [
                'l10n_cl_base', 'l10n_cl_fe', 'l10n_cl_payroll', 
                'l10n_cl_project', 'account_budget', 'monitoring_integration'
            ]
            
            for module_name in modules_to_check:
                is_installed = self._is_module_installed(module_name)
                
                if is_installed:
                    # Count registered services for this module
                    service_count = 0
                    for service_type in available_services.values():
                        for service in service_type.values():
                            if service.get('module') == module_name:
                                service_count += 1
                    
                    # Get KPI providers count
                    kpi_providers_count = len([
                        provider for provider in service_registry._kpi_providers.values()
                        if provider.get('module') == module_name
                    ])
                    
                    # Get widget providers count
                    widget_providers_count = 0
                    for widget_list in service_registry._widget_providers.values():
                        widget_providers_count += len([
                            provider for provider in widget_list
                            if provider.get('module') == module_name
                        ])
                    
                    # Determine integration status
                    total_providers = kpi_providers_count + widget_providers_count
                    if total_providers >= 2:
                        status = 'fully_integrated'
                    elif total_providers > 0:
                        status = 'partially_integrated'
                    else:
                        status = 'not_integrated'
                    
                    integration_status[module_name] = {
                        'installed': True,
                        'integrated': total_providers > 0,
                        'service_count': service_count,
                        'kpi_providers': kpi_providers_count,
                        'widget_providers': widget_providers_count,
                        'status': status,
                    }
                else:
                    integration_status[module_name] = {
                        'installed': False,
                        'integrated': False,
                        'service_count': 0,
                        'kpi_providers': 0,
                        'widget_providers': 0,
                        'status': 'not_installed',
                    }
            
            # Calculate summary
            summary = {
                'total_modules': len(modules_to_check),
                'installed_modules': sum(1 for status in integration_status.values() if status['installed']),
                'integrated_modules': sum(1 for status in integration_status.values() if status['integrated']),
                'total_services': sum(status['service_count'] for status in integration_status.values()),
                'total_kpi_providers': sum(status['kpi_providers'] for status in integration_status.values()),
                'total_widget_providers': sum(status['widget_providers'] for status in integration_status.values()),
            }
            
            return {
                'success': True,
                'integration_status': integration_status,
                'summary': summary,
                'generated_at': fields.Datetime.now(),
            }
            
        except Exception as e:
            _logger.error("Error in get_integration_status API: %s", str(e))
            return {
                'success': False,
                'error': str(e),
                'integration_status': {},
            }
    
    @http.route('/api/financial/registry/stats', 
                type='json', auth='user', methods=['GET'])
    def get_registry_statistics(self):
        """
        Get detailed statistics about the service registry.
        
        Returns:
            dict: Registry statistics and health information
        """
        try:
            # Check if service registry is available
            if 'financial.report.service.registry' not in request.env:
                return {
                    'success': False,
                    'error': _('Service registry not available'),
                    'stats': {},
                }
            
            # Get service registry and hook system
            service_registry = request.env['financial.report.service.registry']
            registry_stats = service_registry.get_registry_stats()
            
            # Get hook system stats if available
            hook_stats = {}
            if 'financial.report.hook.system' in request.env:
                hook_system = request.env['financial.report.hook.system']
                hook_stats = hook_system.get_hook_stats()
            
            # Get auto-integration stats if available
            integration_stats = {}
            if 'financial.report.chilean.auto.integration' in request.env:
                auto_integration = request.env['financial.report.chilean.auto.integration']
                # This would get integration statistics if method exists
                integration_stats = {
                    'supported_modules': len(auto_integration.SUPPORTED_MODULES),
                    'supported_module_list': auto_integration.SUPPORTED_MODULES,
                }
            
            return {
                'success': True,
                'stats': {
                    'registry': registry_stats,
                    'hooks': hook_stats,
                    'integration': integration_stats,
                },
                'health': {
                    'registry_initialized': registry_stats.get('initialization_complete', False),
                    'services_available': registry_stats.get('total_services', 0) > 0,
                    'kpi_providers_available': registry_stats.get('kpi_providers', 0) > 0,
                    'hooks_registered': hook_stats.get('total_hooks', 0) > 0,
                },
                'generated_at': fields.Datetime.now(),
            }
            
        except Exception as e:
            _logger.error("Error in get_registry_statistics API: %s", str(e))
            return {
                'success': False,
                'error': str(e),
                'stats': {},
            }
    
    # Helper methods
    def _prepare_api_filters(self, filters):
        """Prepare and validate API filters."""
        prepared_filters = {}
        
        # Handle date_from
        date_from = filters.get('date_from')
        if isinstance(date_from, str):
            prepared_filters['date_from'] = datetime.strptime(date_from, '%Y-%m-%d').date()
        elif isinstance(date_from, date):
            prepared_filters['date_from'] = date_from
        else:
            prepared_filters['date_from'] = fields.Date.today().replace(day=1)
        
        # Handle date_to
        date_to = filters.get('date_to')
        if isinstance(date_to, str):
            prepared_filters['date_to'] = datetime.strptime(date_to, '%Y-%m-%d').date()
        elif isinstance(date_to, date):
            prepared_filters['date_to'] = date_to
        else:
            prepared_filters['date_to'] = fields.Date.today()
        
        # Handle company_ids
        company_ids = filters.get('company_ids')
        if isinstance(company_ids, list) and company_ids:
            prepared_filters['company_ids'] = company_ids
        elif isinstance(company_ids, int):
            prepared_filters['company_ids'] = [company_ids]
        else:
            prepared_filters['company_ids'] = [request.env.company.id]
        
        return prepared_filters
    
    def _is_module_installed(self, module_name):
        """Check if a module is installed."""
        return bool(request.env['ir.module.module'].search([
            ('name', '=', module_name),
            ('state', '=', 'installed')
        ], limit=1))
    
    def _load_widget_data_from_provider(self, widget_class, widget_type, filters):
        """Load widget data from a specific provider."""
        try:
            # If widget_class is a string (model name), get the model
            if isinstance(widget_class, str):
                if widget_class in request.env:
                    provider = request.env[widget_class]
                else:
                    return {'error': _('Widget provider model not found: %s') % widget_class}
            else:
                # Assume it's a callable method
                if callable(widget_class):
                    return widget_class(**filters)
                else:
                    return {'error': _('Invalid widget provider')}
            
            # Try to find the appropriate method for this widget type
            method_name = f"get_{widget_type}_data"
            if hasattr(provider, method_name):
                method = getattr(provider, method_name)
                return method(**filters)
            else:
                # Try generic widget data method
                if hasattr(provider, 'get_widget_data'):
                    return provider.get_widget_data(widget_type, **filters)
                else:
                    return {'error': _('Widget method not found: %s') % method_name}
                    
        except Exception as e:
            _logger.error("Error loading widget data from provider: %s", str(e))
            return {'error': str(e)}
