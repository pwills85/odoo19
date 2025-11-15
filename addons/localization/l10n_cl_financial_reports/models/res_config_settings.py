
# -*- coding: utf-8 -*-

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError

class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    # ====== FINANCIAL DASHBOARD SETTINGS ======

    # Dashboard Layout
    dashboard_auto_refresh = fields.Boolean(
        string='Auto Refresh Dashboard',
        config_parameter='l10n_cl_financial_reports.dashboard_auto_refresh',
        default=True,
        help="Enable automatic refresh of financial dashboard every 5 minutes"
    )

    dashboard_refresh_interval = fields.Integer(
        string='Dashboard Refresh Interval (seconds)',
        config_parameter='l10n_cl_financial_reports.dashboard_refresh_interval',
        default=300,
        help="Interval in seconds for dashboard auto-refresh"
    )

    dashboard_default_period = fields.Selection([
        ('current_month', 'Current Month'),
        ('last_month', 'Last Month'),
        ('current_quarter', 'Current Quarter'),
        ('current_year', 'Current Year'),
        ('custom', 'Custom Period'),
    ], string='Default Dashboard Period',
       config_parameter='l10n_cl_financial_reports.dashboard_default_period',
       default='current_month',
       help="Default time period shown in dashboard")

    # Performance Settings
    dashboard_cache_enabled = fields.Boolean(
        string='Enable Dashboard Cache',
        config_parameter='l10n_cl_financial_reports.dashboard_cache_enabled',
        default=True,
        help="Enable caching for better dashboard performance"
    )

    dashboard_cache_ttl = fields.Integer(
        string='Cache TTL (seconds)',
        config_parameter='l10n_cl_financial_reports.dashboard_cache_ttl',
        default=3600,
        help="Time to live for dashboard cache in seconds"
    )

    enable_prefetch_optimization = fields.Boolean(
        string='Enable Prefetch Optimization',
        config_parameter='l10n_cl_financial_reports.enable_prefetch_optimization',
        default=True,
        help="Enable query prefetch optimization for better performance"
    )

    enable_query_optimization = fields.Boolean(
        string='Enable Query Optimization',
        config_parameter='l10n_cl_financial_reports.enable_query_optimization',
        default=True,
        help="Enable database query optimization"
    )

    # ====== FINANCIAL REPORTS SETTINGS ======

    financial_report_auto_refresh = fields.Boolean(
        string='Auto Refresh Financial Reports',
        config_parameter='l10n_cl_financial_reports.financial_report_auto_refresh',
        default=False,
        help="Automatically refresh financial reports when data changes"
    )

    financial_report_batch_size = fields.Integer(
        string='Report Batch Size',
        config_parameter='l10n_cl_financial_reports.financial_report_batch_size',
        default=1000,
        help="Number of records to process in batch for financial reports"
    )

    financial_report_cache_timeout = fields.Integer(
        string='Report Cache Timeout (seconds)',
        config_parameter='l10n_cl_financial_reports.financial_report_cache_timeout',
        default=3600,
        help="Cache timeout for generated financial reports"
    )

    # ====== F29 CONFIGURATION ======

    f29_auto_calculate = fields.Boolean(
        string='F29 Auto Calculate',
        config_parameter='l10n_cl_financial_reports.f29_auto_calculate',
        default=False,
        help="Automatically calculate F29 when period is closed"
    )

    f29_validation_strict = fields.Boolean(
        string='F29 Strict Validation',
        config_parameter='l10n_cl_financial_reports.f29_validation_strict',
        default=True,
        help="Enable strict validation for F29 calculations"
    )

    f29_backup_before_submit = fields.Boolean(
        string='F29 Backup Before Submit',
        config_parameter='l10n_cl_financial_reports.f29_backup_before_submit',
        default=True,
        help="Create backup before submitting F29 to SII"
    )

    # ====== F22 CONFIGURATION ======

    f22_monthly_generation = fields.Boolean(
        string='F22 Monthly Generation',
        config_parameter='l10n_cl_financial_reports.f22_monthly_generation',
        default=True,
        help="Generate F22 reports monthly automatically"
    )

    f22_include_zero_values = fields.Boolean(
        string='F22 Include Zero Values',
        config_parameter='l10n_cl_financial_reports.f22_include_zero_values',
        default=False,
        help="Include accounts with zero values in F22 report"
    )

    # ====== REPORTING SETTINGS ======

    report_default_format = fields.Selection([
        ('pdf', 'PDF'),
        ('xlsx', 'Excel'),
        ('csv', 'CSV'),
        ('html', 'HTML'),
    ], string='Default Report Format',
       config_parameter='l10n_cl_financial_reports.report_default_format',
       default='pdf',
       help="Default format for financial reports")

    report_logo_position = fields.Selection([
        ('header_left', 'Header Left'),
        ('header_center', 'Header Center'),
        ('header_right', 'Header Right'),
        ('footer_center', 'Footer Center'),
    ], string='Logo Position in Reports',
       config_parameter='l10n_cl_financial_reports.report_logo_position',
       default='header_right',
       help="Position of company logo in reports")

    report_watermark_enabled = fields.Boolean(
        string='Enable Report Watermark',
        config_parameter='l10n_cl_financial_reports.report_watermark_enabled',
        default=False,
        help="Add watermark to financial reports"
    )

    report_watermark_text = fields.Char(
        string='Watermark Text',
        config_parameter='l10n_cl_financial_reports.report_watermark_text',
        default='CONFIDENTIAL',
        help="Text to use as watermark in reports"
    )

    # ====== MOBILE SETTINGS ======

    mobile_dashboard_enabled = fields.Boolean(
        string='Enable Mobile Dashboard',
        config_parameter='l10n_cl_financial_reports.mobile_dashboard_enabled',
        default=True,
        help="Enable mobile-optimized dashboard"
    )

    mobile_touch_gestures = fields.Boolean(
        string='Touch Gestures Support',
        config_parameter='l10n_cl_financial_reports.mobile_touch_gestures',
        default=True,
        help="Enable touch gestures for mobile devices"
    )

    mobile_offline_mode = fields.Boolean(
        string='Offline Mode Support',
        config_parameter='l10n_cl_financial_reports.mobile_offline_mode',
        default=False,
        help="Enable offline mode for mobile devices"
    )

    # ====== SECURITY & AUDIT ======

    audit_trail_enabled = fields.Boolean(
        string='Enable Audit Trail',
        config_parameter='l10n_cl_financial_reports.audit_trail_enabled',
        default=True,
        help="Log all financial report access and modifications"
    )

    data_retention_days = fields.Integer(
        string='Data Retention (days)',
        config_parameter='l10n_cl_financial_reports.data_retention_days',
        default=2555,  # 7 years
        help="Number of days to retain financial data"
    )

    # ====== INTEGRATION SETTINGS ======

    sii_integration_enabled = fields.Boolean(
        string='SII Integration',
        config_parameter='l10n_cl_financial_reports.sii_integration_enabled',
        default=True,
        help="Enable integration with SII systems"
    )

    external_api_timeout = fields.Integer(
        string='External API Timeout (seconds)',
        config_parameter='l10n_cl_financial_reports.external_api_timeout',
        default=30,
        help="Timeout for external API calls"
    )

    # ====== VALIDATION METHODS ======

    @api.constrains('dashboard_refresh_interval')
    def _check_refresh_interval(self):
        for record in self:
            if record.dashboard_refresh_interval < 60:
                raise ValidationError(_("Refresh interval must be at least 60 seconds"))

    @api.constrains('dashboard_cache_ttl')
    def _check_cache_ttl(self):
        for record in self:
            if record.dashboard_cache_ttl < 300:
                raise ValidationError(_("Cache TTL must be at least 300 seconds"))

    @api.constrains('data_retention_days')
    def _check_retention_days(self):
        for record in self:
            if record.data_retention_days < 365:
                raise ValidationError(_("Data retention must be at least 365 days for legal compliance"))

    # ====== CONFIGURATION HELPERS ======

    def action_reset_dashboard_cache(self):
        """Reset dashboard cache"""
        try:
            # Clear cache service
            cache_service = self.env['cache.service'].sudo()
            if cache_service:
                cache_service.invalidate('dashboard_*')

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Dashboard cache cleared successfully'),
                    'type': 'success',
                    'sticky': False,
                }
            }
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Error clearing cache: %s') % str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }

    def action_test_sii_connection(self):
        """Test SII connection"""
        try:
            # Test SII connection
            sii_service = self.env['sii.integration.service'].sudo()
            if sii_service:
                result = sii_service.test_connection()
                message = _('SII connection successful') if result else _('SII connection failed')
                msg_type = 'success' if result else 'warning'
            else:
                message = _('SII service not available')
                msg_type = 'warning'

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': message,
                    'type': msg_type,
                    'sticky': False,
                }
            }
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Error testing SII connection: %s') % str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }

    def action_optimize_database(self):
        """Optimize database for better performance"""
        try:
            # Execute optimization queries
            optimization_queries = [
                "VACUUM ANALYZE account_move_line",
                "VACUUM ANALYZE l10n_cl_f29",
                "VACUUM ANALYZE l10n_cl_f22",
                "REINDEX TABLE account_move_line",
            ]

            for query in optimization_queries:
                try:
                    self.env.cr.execute(query)
                except Exception as query_error:
                    logger.warning(f"Query optimization warning: {query_error}")

            self.env.cr.commit()

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Database optimization completed'),
                    'type': 'success',
                    'sticky': False,
                }
            }
        except Exception as e:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('Error optimizing database: %s') % str(e),
                    'type': 'danger',
                    'sticky': True,
                }
            }

    def get_values(self):
        """Get configuration values"""
        res = super().get_values()

        # Add any computed configuration values here
        params = self.env['ir.config_parameter'].sudo()

        res.update({
            'dashboard_auto_refresh': params.get_param('l10n_cl_financial_reports.dashboard_auto_refresh', True),
            'dashboard_refresh_interval': int(params.get_param('l10n_cl_financial_reports.dashboard_refresh_interval', 300)),
            'dashboard_default_period': params.get_param('l10n_cl_financial_reports.dashboard_default_period', 'current_month'),
            'dashboard_cache_enabled': params.get_param('l10n_cl_financial_reports.dashboard_cache_enabled', True),
            'dashboard_cache_ttl': int(params.get_param('l10n_cl_financial_reports.dashboard_cache_ttl', 3600)),
            'f29_auto_calculate': params.get_param('l10n_cl_financial_reports.f29_auto_calculate', False),
            'f29_validation_strict': params.get_param('l10n_cl_financial_reports.f29_validation_strict', True),
            'f29_backup_before_submit': params.get_param('l10n_cl_financial_reports.f29_backup_before_submit', True),
            'f22_monthly_generation': params.get_param('l10n_cl_financial_reports.f22_monthly_generation', True),
            'f22_include_zero_values': params.get_param('l10n_cl_financial_reports.f22_include_zero_values', False),
            'report_default_format': params.get_param('l10n_cl_financial_reports.report_default_format', 'pdf'),
            'report_logo_position': params.get_param('l10n_cl_financial_reports.report_logo_position', 'header_right'),
            'report_watermark_enabled': params.get_param('l10n_cl_financial_reports.report_watermark_enabled', False),
            'report_watermark_text': params.get_param('l10n_cl_financial_reports.report_watermark_text', 'CONFIDENTIAL'),
            'mobile_dashboard_enabled': params.get_param('l10n_cl_financial_reports.mobile_dashboard_enabled', True),
            'mobile_touch_gestures': params.get_param('l10n_cl_financial_reports.mobile_touch_gestures', True),
            'mobile_offline_mode': params.get_param('l10n_cl_financial_reports.mobile_offline_mode', False),
            'audit_trail_enabled': params.get_param('l10n_cl_financial_reports.audit_trail_enabled', True),
            'data_retention_days': int(params.get_param('l10n_cl_financial_reports.data_retention_days', 2555)),
            'sii_integration_enabled': params.get_param('l10n_cl_financial_reports.sii_integration_enabled', True),
            'external_api_timeout': int(params.get_param('l10n_cl_financial_reports.external_api_timeout', 30)),
        })

        return res

    def set_values(self):
        """Set configuration values"""
        super().set_values()

        params = self.env['ir.config_parameter'].sudo()

        # Store all configuration parameters
        config_fields = [
            'dashboard_auto_refresh', 'dashboard_refresh_interval', 'dashboard_default_period',
            'dashboard_cache_enabled', 'dashboard_cache_ttl', 'f29_auto_calculate',
            'f29_validation_strict', 'f29_backup_before_submit', 'f22_monthly_generation',
            'f22_include_zero_values', 'report_default_format', 'report_logo_position',
            'report_watermark_enabled', 'report_watermark_text', 'mobile_dashboard_enabled',
            'mobile_touch_gestures', 'mobile_offline_mode', 'audit_trail_enabled',
            'data_retention_days', 'sii_integration_enabled', 'external_api_timeout'
        ]

        for field in config_fields:
            if hasattr(self, field):
                value = getattr(self, field)
                params.set_param(f'l10n_cl_financial_reports.{field}', value)
