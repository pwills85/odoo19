# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import json
import logging

_logger = logging.getLogger(__name__)


class FinancialDashboardAddWidgetWizard(models.TransientModel):
    _name = 'financial.dashboard.add.widget.wizard'
    _description = 'Wizard para Añadir Widget al Dashboard Financiero'

    # Basic widget information
    widget_template_id = fields.Many2one(
        'financial.dashboard.widget',
        string='Plantilla de Widget',
        required=True,
        help="Selecciona la plantilla de widget predefinida"
    )
    title = fields.Char(
        string='Título del Widget',
        required=True,
        help="Título personalizado que aparecerá en el dashboard"
    )
    widget_type = fields.Selection(
        related='widget_template_id.widget_type',
        readonly=True,
        string='Tipo de Widget'
    )

    # Position and size settings
    position_x = fields.Integer(
        string='Posición X',
        default=0,
        help="Posición horizontal en el dashboard (columnas)"
    )
    position_y = fields.Integer(
        string='Posición Y',
        default=0,
        help="Posición vertical en el dashboard (filas)"
    )
    size_w = fields.Integer(
        string='Ancho',
        default=4,
        help="Ancho del widget en columnas"
    )
    size_h = fields.Integer(
        string='Alto',
        default=2,
        help="Alto del widget en filas"
    )

    # Configuration
    config_data = fields.Text(
        string='Configuración Avanzada',
        help="Configuración adicional en formato JSON"
    )
    dashboard_id = fields.Many2one(
        'financial.dashboard.layout',
        string='Dashboard',
        required=True,
        help="Dashboard donde añadir el widget"
    )

    # Filters configuration
    date_from = fields.Date(
        string='Fecha Desde',
        default=lambda self: fields.Date.today().replace(month=1, day=1),
        help="Fecha inicial para filtros de datos"
    )
    date_to = fields.Date(
        string='Fecha Hasta',
        default=fields.Date.today,
        help="Fecha final para filtros de datos"
    )
    company_ids = fields.Many2many(
        'res.company',
        string='Compañías',
        default=lambda self: self.env.company,
        help="Compañías incluidas en el widget"
    )

    # Advanced settings
    refresh_interval = fields.Integer(
        string='Intervalo de Actualización (segundos)',
        default=300,
        help="Frecuencia de actualización automática"
    )
    enable_cache = fields.Boolean(
        string='Habilitar Caché',
        default=True,
        help="Usar caché para mejorar rendimiento"
    )

    @api.onchange('widget_template_id')
    def _onchange_widget_template_id(self):
        """Update default values based on selected template"""
        if self.widget_template_id:
            self.title = self.widget_template_id.name
            self.size_w = self.widget_template_id.default_size_w
            self.size_h = self.widget_template_id.default_size_h
            self.refresh_interval = self.widget_template_id.refresh_interval
            self.enable_cache = self.widget_template_id.enable_cache

    @api.constrains('size_w', 'size_h')
    def _check_widget_size(self):
        """Validate widget dimensions"""
        for wizard in self:
            if wizard.size_w < 1 or wizard.size_w > 12:
                raise ValidationError(_('El ancho del widget debe estar entre 1 y 12 columnas'))
            if wizard.size_h < 1 or wizard.size_h > 12:
                raise ValidationError(_('El alto del widget debe estar entre 1 y 12 filas'))

    @api.constrains('refresh_interval')
    def _check_refresh_interval(self):
        """Validate refresh interval"""
        for wizard in self:
            if wizard.refresh_interval < 0:
                raise ValidationError(_('El intervalo de actualización debe ser 0 o mayor'))

    @api.constrains('config_data')
    def _check_config_data(self):
        """Validate JSON configuration"""
        for wizard in self:
            if wizard.config_data:
                try:
                    json.loads(wizard.config_data)
                except (json.JSONDecodeError, TypeError):
                    raise ValidationError(_('La configuración avanzada debe ser JSON válido'))

    def get_available_widget_types(self):
        """Return available widget types for the interface"""
        return self.env['financial.dashboard.widget'].search([])

    def _prepare_widget_config(self):
        """Prepare widget configuration dictionary"""
        self.ensure_one()

        # Base configuration
        config = {
            'title': self.title,
            'widget_type': self.widget_type,
            'position': {'x': self.position_x, 'y': self.position_y},
            'size': {'w': self.size_w, 'h': self.size_h},
            'refresh_interval': self.refresh_interval,
            'enable_cache': self.enable_cache,
            'template_id': self.widget_template_id.id,
        }

        # Data service configuration
        if self.widget_template_id.data_service_model:
            config['data_service'] = {
                'model': self.widget_template_id.data_service_model,
                'method': self.widget_template_id.data_service_method,
            }

        # Filters configuration
        config['filters'] = {
            'date_from': self.date_from.isoformat() if self.date_from else None,
            'date_to': self.date_to.isoformat() if self.date_to else None,
            'company_ids': self.company_ids.ids,
        }

        # Additional configuration from config_data field
        if self.config_data:
            try:
                additional_config = json.loads(self.config_data)
                config.update(additional_config)
            except (json.JSONDecodeError, TypeError):
                _logger.warning("Invalid JSON in config_data field")

        return config

    def action_add_widget(self):
        """Add widget to dashboard"""
        self.ensure_one()

        if not self.dashboard_id:
            raise UserError(_('Debe seleccionar un dashboard'))

        if not self.widget_template_id:
            raise UserError(_('Debe seleccionar una plantilla de widget'))

        try:
            # Prepare widget configuration
            widget_config = self._prepare_widget_config()

            # Get current dashboard configuration
            current_config = json.loads(self.dashboard_id.layout_config or '{}')

            # Add new widget to configuration
            widgets = current_config.get('widgets', [])

            # Generate unique widget ID
            widget_id = f"widget_{len(widgets)}_{self.widget_template_id.id}"

            # Create widget configuration
            new_widget = {
                'id': widget_id,
                'config': widget_config,
                'created_at': fields.Datetime.now().isoformat(),
                'created_by': self.env.user.id,
            }

            widgets.append(new_widget)
            current_config['widgets'] = widgets

            # Update dashboard configuration
            self.dashboard_id.write({
                'layout_config': json.dumps(current_config, indent=2)
            })

            _logger.info(f"Widget {widget_id} added to dashboard {self.dashboard_id.name}")

            return {
                'type': 'ir.actions.client',
                'tag': 'reload',
            }

        except Exception as e:
            _logger.error(f"Error adding widget to dashboard: {e}", exc_info=True)
            raise UserError(_('Error al añadir widget al dashboard: %s') % str(e))

    def action_preview_widget(self):
        """Preview widget configuration"""
        self.ensure_one()

        # Get sample data from the widget template
        sample_data = {'value': 0, 'label': 'Vista previa'}

        if self.widget_template_id:
            try:
                sample_data = self.widget_template_id.get_widget_data()
            except Exception as e:
                _logger.warning(f"Could not get sample data: {e}")
                sample_data = {'error': True, 'message': str(e)}

        return {
            'type': 'ir.actions.act_window',
            'name': _('Vista Previa del Widget'),
            'res_model': 'financial.dashboard.add.widget.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'view_id': self.env.ref(
                'l10n_cl_financial_reports.financial_dashboard_add_widget_wizard_preview_view'
            ).id,
            'target': 'new',
            'context': {
                'sample_data': sample_data,
                'widget_config': self._prepare_widget_config(),
            }
        }

    @api.model
    def get_dashboard_stats(self, dashboard_id):
        """Get dashboard statistics for the wizard"""
        dashboard = self.env['financial.dashboard.layout'].browse(dashboard_id)
        if not dashboard:
            return {}

        try:
            config = json.loads(dashboard.layout_config or '{}')
            widgets = config.get('widgets', [])

            return {
                'total_widgets': len(widgets),
                'last_modified': dashboard.write_date.isoformat() if dashboard.write_date else None,
                'created_by': dashboard.create_uid.name if dashboard.create_uid else None,
            }
        except (json.JSONDecodeError, TypeError):
            return {'error': 'Invalid dashboard configuration'}

    def action_cancel(self):
        '''Cancel wizard'''
        return {'type': 'ir.actions.act_window_close'}

    @api.model
    def _get_available_widgets(self):
        '''Get list of available widget types'''
        return [
            ('kpi', 'KPI Card'),
            ('chart', 'Chart'),
            ('table', 'Data Table'),
            ('gauge', 'Gauge'),
            ('timeline', 'Timeline'),
        ]
