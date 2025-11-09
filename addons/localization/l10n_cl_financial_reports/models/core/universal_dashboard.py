# -*- coding: utf-8 -*-
"""
Universal Dashboard Engine
==========================

Dashboard engine that dynamically creates dashboards based on registered services
and available modules without duplicating business logic.

Author: EERGYGROUP - Based on technical audit specifications
"""

import logging

from odoo import api, fields, models, _
from odoo.exceptions import UserError, ValidationError

_logger = logging.getLogger(__name__)


class UniversalDashboardEngine(models.AbstractModel):
    """
    Universal dashboard engine that dynamically creates dashboards
    based on registered services and available modules.
    
    This engine orchestrates data from multiple modules to create
    consolidated dashboards without duplicating business logic.
    """
    _name = 'financial.report.universal.dashboard'
    _description = 'Universal Dashboard Engine'
    
    # Dashboard types
    DASHBOARD_EXECUTIVE = 'executive'
    DASHBOARD_OPERATIONAL = 'operational'
    DASHBOARD_FINANCIAL = 'financial'
    DASHBOARD_TECHNICAL = 'technical'
    
    @api.model
    def generate_dynamic_dashboard(self, dashboard_type='executive', user_preferences=None, **filters):
        """
        Generate a dashboard dynamically based on available modules and services.
        
        Args:
            dashboard_type (str): Type of dashboard ('executive', 'operational', 'financial', 'technical')
            user_preferences (dict, optional): User customization preferences
            **filters: Additional filters (date_from, date_to, company_ids, etc.)
            
        Returns:
            dict: Complete dashboard configuration with data
        """
        if dashboard_type not in [self.DASHBOARD_EXECUTIVE, self.DASHBOARD_OPERATIONAL, 
                                  self.DASHBOARD_FINANCIAL, self.DASHBOARD_TECHNICAL]:
            raise ValidationError(_("Invalid dashboard type: %s") % dashboard_type)
        
        try:
            # Get service registry
            if 'financial.report.service.registry' not in self.env:
                raise UserError(_("Financial report service registry not available"))
            
            service_registry = self.env['financial.report.service.registry']
            available_services = service_registry.get_available_services()
            
            # Set default filters
            filters = self._prepare_dashboard_filters(filters)
            
            # Generate dashboard configuration
            dashboard_config = {
                'type': dashboard_type,
                'title': self._get_dashboard_title(dashboard_type),
                'widgets': [],
                'kpi_sources': [],
                'layout': self._get_default_layout(dashboard_type),
                'filters': filters,
                'generated_at': fields.Datetime.now(),
                'metadata': {
                    'available_modules': self._get_installed_modules(),
                    'service_count': len(available_services.get('kpi', {})) + len(available_services.get('widget', {})),
                }
            }
            
            # Add widgets based on installed modules and dashboard type
            dashboard_config['widgets'] = self._generate_dynamic_widgets(
                dashboard_type, available_services, user_preferences, filters
            )
            
            # Add KPI sources information
            dashboard_config['kpi_sources'] = self._get_available_kpi_sources(available_services)
            
            # Apply user preferences if provided
            if user_preferences:
                dashboard_config = self._apply_user_preferences(dashboard_config, user_preferences)
            
            # Load actual data for widgets
            dashboard_config = self._load_widget_data(dashboard_config, filters)
            
            # Trigger hook for dashboard data loaded
            if 'financial.report.hook.system' in self.env:
                hook_system = self.env['financial.report.hook.system']
                dashboard_config = hook_system.trigger_hook(
                    hook_system.HOOK_DASHBOARD_DATA_LOADED,
                    dashboard_config,
                    {'dashboard_type': dashboard_type, 'filters': filters}
                )
            
            return dashboard_config
            
        except Exception as e:
            _logger.error("Error generating dynamic dashboard: %s", str(e))
            return self._get_error_dashboard(dashboard_type, str(e))
    
    def _prepare_dashboard_filters(self, filters):
        """Prepare and validate dashboard filters."""
        prepared_filters = {
            'date_from': filters.get('date_from', fields.Date.today().replace(day=1)),
            'date_to': filters.get('date_to', fields.Date.today()),
            'company_ids': filters.get('company_ids', [self.env.company.id]),
        }
        
        # Ensure date_from is before date_to
        if prepared_filters['date_from'] > prepared_filters['date_to']:
            prepared_filters['date_from'] = prepared_filters['date_to'].replace(day=1)
        
        return prepared_filters
    
    def _get_dashboard_title(self, dashboard_type):
        """Get localized title for dashboard type."""
        titles = {
            self.DASHBOARD_EXECUTIVE: _('Executive Dashboard'),
            self.DASHBOARD_OPERATIONAL: _('Operational Dashboard'),
            self.DASHBOARD_FINANCIAL: _('Financial Dashboard'),
            self.DASHBOARD_TECHNICAL: _('Technical Dashboard'),
        }
        return titles.get(dashboard_type, _('Dashboard'))
    
    def _get_default_layout(self, dashboard_type):
        """Get default layout configuration for dashboard type."""
        layouts = {
            self.DASHBOARD_EXECUTIVE: {
                'columns': 12,
                'rows': 8,
                'widget_margin': 10,
                'responsive': True,
                'mobile_layout': 'stack',
            },
            self.DASHBOARD_OPERATIONAL: {
                'columns': 12,
                'rows': 10,
                'widget_margin': 8,
                'responsive': True,
                'mobile_layout': 'grid',
            },
            self.DASHBOARD_FINANCIAL: {
                'columns': 12,
                'rows': 12,
                'widget_margin': 8,
                'responsive': True,
                'mobile_layout': 'scroll',
            },
            self.DASHBOARD_TECHNICAL: {
                'columns': 12,
                'rows': 10,
                'widget_margin': 5,
                'responsive': True,
                'mobile_layout': 'tabs',
            },
        }
        return layouts.get(dashboard_type, layouts[self.DASHBOARD_EXECUTIVE])
    
    def _generate_dynamic_widgets(self, dashboard_type, available_services, user_preferences, filters):
        """Generate widgets based on available services and dashboard type."""
        widgets = []
        
        # Get base widgets for dashboard type
        base_widgets = self._get_base_widgets_for_type(dashboard_type)
        widgets.extend(base_widgets)
        
        # Add module-specific widgets based on installed modules
        installed_modules = self._get_installed_modules()
        
        for module_name in installed_modules:
            module_widgets = self._get_module_widgets(module_name, dashboard_type, available_services)
            widgets.extend(module_widgets)
        
        # Sort widgets by priority
        widgets.sort(key=lambda w: self._get_widget_priority_score(w), reverse=True)
        
        # Apply layout constraints (max widgets per dashboard type)
        max_widgets = self._get_max_widgets_for_type(dashboard_type)
        widgets = widgets[:max_widgets]
        
        return widgets
    
    def _get_base_widgets_for_type(self, dashboard_type):
        """Get base widgets that are always included for each dashboard type."""
        base_widgets = {
            self.DASHBOARD_EXECUTIVE: [
                {
                    'id': 'financial_summary',
                    'type': 'kpi_card',
                    'title': _('Financial Summary'),
                    'size': {'w': 12, 'h': 2},
                    'priority': 'high',
                    'module': 'l10n_cl_financial_reports',
                    'data_source': 'built_in',
                },
            ],
            self.DASHBOARD_OPERATIONAL: [
                {
                    'id': 'process_metrics',
                    'type': 'kpi_card',
                    'title': _('Process Metrics'),
                    'size': {'w': 8, 'h': 2},
                    'priority': 'high',
                    'module': 'l10n_cl_financial_reports',
                    'data_source': 'built_in',
                },
            ],
            self.DASHBOARD_FINANCIAL: [
                {
                    'id': 'balance_sheet_summary',
                    'type': 'kpi_card',
                    'title': _('Balance Sheet Summary'),
                    'size': {'w': 8, 'h': 2},
                    'priority': 'high',
                    'module': 'l10n_cl_financial_reports',
                    'data_source': 'built_in',
                },
            ],
            self.DASHBOARD_TECHNICAL: [
                {
                    'id': 'system_health',
                    'type': 'gauge',
                    'title': _('System Health'),
                    'size': {'w': 4, 'h': 4},
                    'priority': 'high',
                    'module': 'l10n_cl_financial_reports',
                    'data_source': 'built_in',
                },
            ],
        }
        
        return base_widgets.get(dashboard_type, [])
    
    def _get_module_widgets(self, module_name, dashboard_type, available_services):
        """Get widgets provided by a specific module for the dashboard type."""
        widgets = []
        
        # Module-specific widget mappings
        module_widget_map = {
            'l10n_cl_fe': {
                self.DASHBOARD_EXECUTIVE: ['dte_summary_kpi_widget', 'dte_status_widget'],
                self.DASHBOARD_OPERATIONAL: ['dte_status_widget', 'caf_usage_gauge_widget'],
                self.DASHBOARD_FINANCIAL: ['dte_summary_kpi_widget'],
                self.DASHBOARD_TECHNICAL: ['dte_status_widget'],
            },
            'l10n_cl_payroll': {
                self.DASHBOARD_EXECUTIVE: ['payroll_summary_kpi_widget'],
                self.DASHBOARD_OPERATIONAL: ['payroll_cost_breakdown_widget', 'employee_distribution_widget'],
                self.DASHBOARD_FINANCIAL: ['payroll_summary_kpi_widget', 'payroll_cost_breakdown_widget'],
                self.DASHBOARD_TECHNICAL: ['compliance_status_widget'],
            },
            'account_budget': {
                self.DASHBOARD_EXECUTIVE: ['budget_summary_kpi_widget', 'budget_utilization_gauge_widget'],
                self.DASHBOARD_OPERATIONAL: ['budget_comparison_chart_widget', 'budget_alerts_table_widget'],
                self.DASHBOARD_FINANCIAL: ['budget_summary_kpi_widget', 'budget_comparison_chart_widget'],
                self.DASHBOARD_TECHNICAL: ['budget_status_distribution_widget'],
            },
            'monitoring_integration': {
                self.DASHBOARD_TECHNICAL: ['system_health_widget', 'performance_metrics_widget'],
                self.DASHBOARD_OPERATIONAL: ['error_trends_widget'],
            }
        }
        
        if module_name in module_widget_map:
            widget_types = module_widget_map[module_name].get(dashboard_type, [])
            
            for widget_type in widget_types:
                widget_config = {
                    'id': f"{module_name}_{widget_type}",
                    'type': widget_type,
                    'title': self._get_widget_title(widget_type),
                    'size': self._get_widget_default_size(widget_type),
                    'priority': 'medium',
                    'module': module_name,
                    'data_source': 'module_provider',
                }
                widgets.append(widget_config)
        
        return widgets
    
    def _get_widget_title(self, widget_type):
        """Get localized title for widget type."""
        titles = {
            'dte_summary_kpi_widget': _('DTE Summary'),
            'dte_status_widget': _('DTE Status'),
            'caf_usage_gauge_widget': _('CAF Usage'),
            'payroll_summary_kpi_widget': _('Payroll Summary'),
            'payroll_cost_breakdown_widget': _('Payroll Costs'),
            'employee_distribution_widget': _('Employee Distribution'),
            'compliance_status_widget': _('Compliance Status'),
            'budget_summary_kpi_widget': _('Budget Summary'),
            'budget_utilization_gauge_widget': _('Budget Utilization'),
            'budget_comparison_chart_widget': _('Budget vs Actual'),
            'budget_alerts_table_widget': _('Budget Alerts'),
            'budget_status_distribution_widget': _('Budget Status'),
        }
        return titles.get(widget_type, widget_type.replace('_', ' ').title())
    
    def _get_widget_default_size(self, widget_type):
        """Get default size for widget type."""
        sizes = {
            'kpi_card': {'w': 8, 'h': 2},
            'gauge': {'w': 4, 'h': 4},
            'chart_line': {'w': 8, 'h': 4},
            'chart_bar': {'w': 8, 'h': 4},
            'chart_pie': {'w': 6, 'h': 4},
            'chart_doughnut': {'w': 6, 'h': 4},
            'table': {'w': 12, 'h': 4},
        }
        
        # Extract widget type from widget name
        for size_key in sizes.keys():
            if size_key in widget_type:
                return sizes[size_key]
        
        return {'w': 6, 'h': 3}  # Default size
    
    def _get_widget_priority_score(self, widget):
        """Calculate priority score for widget sorting."""
        priority_scores = {
            'high': 100,
            'medium': 50,
            'low': 10,
        }
        
        score = priority_scores.get(widget.get('priority', 'medium'), 50)
        
        # Bonus for KPI widgets
        if 'kpi' in widget.get('type', ''):
            score += 20
        
        # Bonus for summary widgets
        if 'summary' in widget.get('title', '').lower():
            score += 10
        
        return score
    
    def _get_max_widgets_for_type(self, dashboard_type):
        """Get maximum number of widgets for dashboard type."""
        max_widgets = {
            self.DASHBOARD_EXECUTIVE: 8,
            self.DASHBOARD_OPERATIONAL: 12,
            self.DASHBOARD_FINANCIAL: 10,
            self.DASHBOARD_TECHNICAL: 15,
        }
        return max_widgets.get(dashboard_type, 10)
    
    def _get_available_kpi_sources(self, available_services):
        """Get information about available KPI sources."""
        kpi_services = available_services.get('kpi', {})
        
        sources = []
        for service_name, service_info in kpi_services.items():
            sources.append({
                'name': service_name,
                'module': service_info.get('module', 'unknown'),
                'registered_at': service_info.get('registered_at'),
            })
        
        return sources
    
    def _load_widget_data(self, dashboard_config, filters):
        """Load actual data for all widgets in the dashboard."""
        for widget in dashboard_config['widgets']:
            try:
                if widget.get('data_source') == 'module_provider':
                    widget['data'] = self._load_module_widget_data(widget, filters)
                elif widget.get('data_source') == 'built_in':
                    widget['data'] = self._load_built_in_widget_data(widget, filters)
                else:
                    widget['data'] = {'error': 'Unknown data source'}
                    
            except Exception as e:
                _logger.error("Error loading data for widget %s: %s", widget.get('id'), str(e))
                widget['data'] = {'error': str(e)}
        
        return dashboard_config
    
    def _load_module_widget_data(self, widget, filters):
        """Load data from module widget providers."""
        module_name = widget.get('module')
        widget_type = widget.get('type')
        
        # Try to find the widget provider
        provider_model_name = f"{module_name}.{widget_type.split('_')[0]}_widget_provider"
        
        if provider_model_name in self.env:
            provider = self.env[provider_model_name]
            method_name = f"get_{widget_type}_data"
            
            if hasattr(provider, method_name):
                method = getattr(provider, method_name)
                return method(**filters)
        
        return {'error': f'Widget provider not found: {provider_model_name}'}
    
    def _load_built_in_widget_data(self, widget, filters):
        """Load data for built-in widgets."""
        widget_id = widget.get('id')
        
        if widget_id == 'financial_summary':
            return self._get_financial_summary_data(filters)
        elif widget_id == 'process_metrics':
            return self._get_process_metrics_data(filters)
        elif widget_id == 'balance_sheet_summary':
            return self._get_balance_sheet_summary_data(filters)
        elif widget_id == 'system_health':
            return self._get_system_health_data(filters)
        
        return {'message': 'Built-in widget data not implemented'}
    
    def _get_financial_summary_data(self, filters):
        """Get financial summary data for built-in widget."""
        # This would use existing financial report services
        return {
            'kpis': [
                {'label': _('Total Revenue'), 'value': 0, 'format': 'currency'},
                {'label': _('Total Expenses'), 'value': 0, 'format': 'currency'},
                {'label': _('Net Income'), 'value': 0, 'format': 'currency'},
                {'label': _('Active Accounts'), 'value': 0, 'format': 'number'},
            ]
        }
    
    def _get_process_metrics_data(self, filters):
        """Get process metrics data for built-in widget."""
        return {
            'kpis': [
                {'label': _('Active Processes'), 'value': 0, 'format': 'number'},
                {'label': _('Completed Today'), 'value': 0, 'format': 'number'},
                {'label': _('Success Rate'), 'value': 0, 'format': 'percentage'},
                {'label': _('Avg Processing Time'), 'value': 0, 'format': 'duration'},
            ]
        }
    
    def _get_balance_sheet_summary_data(self, filters):
        """Get balance sheet summary data for built-in widget."""
        return {
            'kpis': [
                {'label': _('Total Assets'), 'value': 0, 'format': 'currency'},
                {'label': _('Total Liabilities'), 'value': 0, 'format': 'currency'},
                {'label': _('Equity'), 'value': 0, 'format': 'currency'},
                {'label': _('Working Capital'), 'value': 0, 'format': 'currency'},
            ]
        }
    
    def _get_system_health_data(self, filters):
        """Get system health data for built-in widget."""
        return {
            'value': 95,
            'min': 0,
            'max': 100,
            'unit': '%',
            'thresholds': [
                {'value': 70, 'color': '#dc3545'},
                {'value': 90, 'color': '#ffc107'},
                {'value': 100, 'color': '#28a745'},
            ]
        }
    
    def _apply_user_preferences(self, dashboard_config, preferences):
        """Apply user preferences to dashboard configuration."""
        if not preferences:
            return dashboard_config
        
        # Apply widget visibility preferences
        if 'hidden_widgets' in preferences:
            hidden_widgets = preferences['hidden_widgets']
            dashboard_config['widgets'] = [
                w for w in dashboard_config['widgets'] 
                if w.get('id') not in hidden_widgets
            ]
        
        # Apply widget size preferences
        if 'widget_sizes' in preferences:
            size_prefs = preferences['widget_sizes']
            for widget in dashboard_config['widgets']:
                widget_id = widget.get('id')
                if widget_id in size_prefs:
                    widget['size'] = size_prefs[widget_id]
        
        # Apply layout preferences
        if 'layout' in preferences:
            dashboard_config['layout'].update(preferences['layout'])
        
        return dashboard_config
    
    def _get_installed_modules(self):
        """Get list of installed modules relevant to financial reporting."""
        relevant_modules = [
            'l10n_cl_base', 'l10n_cl_fe', 'l10n_cl_payroll', 
            'l10n_cl_project', 'account_budget', 'monitoring_integration'
        ]
        
        installed = self.env['ir.module.module'].search([
            ('name', 'in', relevant_modules),
            ('state', '=', 'installed')
        ])
        
        return installed.mapped('name')
    
    def _get_error_dashboard(self, dashboard_type, error_message):
        """Get error dashboard configuration when generation fails."""
        return {
            'type': dashboard_type,
            'title': _('Dashboard Error'),
            'widgets': [{
                'id': 'error_widget',
                'type': 'error',
                'title': _('Error Loading Dashboard'),
                'size': {'w': 12, 'h': 4},
                'data': {
                    'error': True,
                    'message': _('Unable to generate dashboard'),
                    'details': error_message,
                },
                'priority': 'high',
            }],
            'kpi_sources': [],
            'layout': self._get_default_layout(dashboard_type),
            'error': error_message,
            'generated_at': fields.Datetime.now(),
        }
