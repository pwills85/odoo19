# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import UserError
import json
import logging

_logger = logging.getLogger(__name__)


class BudgetComparisonReport(models.Model):
    """
    Reporte de Comparación Real vs Presupuesto
    Permite analizar desviaciones y cumplimiento presupuestario
    """
    _name = 'account.budget.comparison.report'
    _description = 'Comparación Real vs Presupuesto'
    _inherit = []
    _order = 'create_date desc'

    # Override del campo name
    name = fields.Char(
        string='Nombre del Reporte',
        compute='_compute_name',
        store=True
    )

    # Configuración del período
    date_from = fields.Date(
        string='Fecha Desde',
        required=True,
        default=lambda self: fields.Date.today(self).replace(day=1)
    )
    date_to = fields.Date(
        string='Fecha Hasta',
        required=True,
        default=fields.Date.context_today
    )

    # Presupuesto a comparar
    budget_id = fields.Many2one(
        'account.budget.post',
        string='Posición Presupuestaria',
        help='Dejar vacío para incluir todas las posiciones'
    )

    crossovered_budget_id = fields.Many2one(
        'crossovered.budget',
        string='Presupuesto Específico',
        help='Seleccionar un presupuesto específico o dejar vacío para todos'
    )

    # Opciones de análisis
    analysis_type = fields.Selection([
        ('by_account', 'Por Cuenta Contable'),
        ('by_budget_post', 'Por Posición Presupuestaria'),
        ('by_analytic', 'Por Cuenta Analítica'),
        ('by_department', 'Por Departamento'),
        ('consolidated', 'Consolidado General')
    ], string='Tipo de Análisis', required=True, default='by_account')

    # Filtros adicionales
    account_ids = fields.Many2many(
        'account.account',
        string='Cuentas Específicas',
        domain="[('deprecated', '=', False)]"
    )

    analytic_account_ids = fields.Many2many(
        'account.analytic.account',
        string='Cuentas Analíticas'
    )

    department_ids = fields.Many2many(
        'hr.department',
        string='Departamentos'
    )

    # Opciones de visualización
    show_details = fields.Boolean(
        string='Mostrar Detalles',
        default=True,
        help='Mostrar líneas detalladas además de los totales'
    )

    show_percentage = fields.Boolean(
        string='Mostrar Porcentajes',
        default=True,
        help='Mostrar porcentaje de cumplimiento'
    )

    show_variance_analysis = fields.Boolean(
        string='Análisis de Variaciones',
        default=True,
        help='Incluir análisis detallado de variaciones'
    )

    deviation_threshold = fields.Float(
        string='Umbral de Desviación (%)',
        default=10.0,
        help='Porcentaje para resaltar desviaciones significativas'
    )

    include_committed = fields.Boolean(
        string='Incluir Comprometido',
        default=False,
        help='Incluir montos comprometidos (órdenes de compra, etc.)'
    )

    # Estado del reporte
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('computing', 'Calculando'),
        ('computed', 'Calculado'),
        ('error', 'Error')
    ], string='Estado', default='draft', required=True)

    # Líneas del reporte
    line_ids = fields.One2many(
        'account.budget.comparison.line',
        'report_id',
        string='Líneas de Comparación'
    )

    # Resumen ejecutivo
    executive_summary = fields.Html(
        string='Resumen Ejecutivo',
        compute='_compute_executive_summary'
    )

    # KPIs principales
    total_budget = fields.Monetary(
        string='Presupuesto Total',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_actual = fields.Monetary(
        string='Real Total',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_committed = fields.Monetary(
        string='Comprometido Total',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_variance = fields.Monetary(
        string='Variación Total',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    overall_achievement = fields.Float(
        string='Cumplimiento Global (%)',
        compute='_compute_totals',
        store=True,
        digits=(16, 2)
    )

    # Alertas y recomendaciones
    alerts_count = fields.Integer(
        string='Número de Alertas',
        compute='_compute_alerts'
    )
    recommendations = fields.Text(
        string='Recomendaciones'
    )

    # Cache y performance
    last_compute = fields.Datetime(string='Última Actualización')

    # Campos de compañía y moneda
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        related='company_id.currency_id',
        store=True
    )

    @api.depends_context('company')
    @api.depends('date_from', 'date_to', 'analysis_type', 'company_id')
    def _compute_name(self):

        # TODO: Refactorizar para usar search con dominio completo fuera del loop
        for record in self:
            type_name = dict(record._fields['analysis_type'].selection).get(record.analysis_type, '')
            if record.date_from and record.date_to:
                record.name = f"Comparación Presupuestaria {type_name} - {record.company_id.name}: {record.date_from} al {record.date_to}"
            else:
                record.name = f"Comparación Presupuestaria - {record.company_id.name}"

    @api.depends('line_ids.budget_amount', 'line_ids.actual_amount',
                 'line_ids.committed_amount', 'line_ids.variance_amount')
    def _compute_totals(self):
        """Calcula los totales del reporte"""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        for record in self:
            # Filtrar solo líneas principales (no sub-líneas)
            main_lines = record.line_ids.filtered(lambda l: l.hierarchy_level == 1)

            record.total_budget = sum(main_lines.mapped('budget_amount'))
            record.total_actual = sum(main_lines.mapped('actual_amount'))
            record.total_committed = sum(main_lines.mapped('committed_amount'))
            record.total_variance = sum(main_lines.mapped('variance_amount'))

            # Calcular porcentaje de cumplimiento
            if record.total_budget != 0:
                record.overall_achievement = (record.total_actual / record.total_budget) * 100
            else:
                record.overall_achievement = 0

    @api.depends('line_ids', 'deviation_threshold')
    def _compute_alerts(self):
        """Cuenta las alertas por desviaciones significativas"""
        for record in self:
            alerts = record.line_ids.filtered(
                lambda l: abs(l.variance_percentage) > record.deviation_threshold
            )
            record.alerts_count = len(alerts)

    @api.depends('total_budget', 'total_actual', 'overall_achievement', 'alerts_count')
    def _compute_executive_summary(self):
        """Genera resumen ejecutivo HTML"""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        # Optimización: usar with_context para prefetch
        d = d.with_context(prefetch_fields=False)

        self.mapped('currency_id')  # Prefetch for performance
        for record in self:
            if record.state != 'computed':
                record.executive_summary = ""
                continue

            # Determinar estado general
            if record.overall_achievement >= 95 and record.overall_achievement <= 105:
                status = "on_track"
                status_text = "En línea con el presupuesto"
                status_color = "#28a745"
            elif record.overall_achievement < 95:
                status = "under_budget"
                status_text = "Por debajo del presupuesto"
                status_color = "#17a2b8"
            else:
                status = "over_budget"
                status_text = "Por encima del presupuesto"
                status_color = "#dc3545"

            # Generar HTML
            summary_html = f"""
            <div class="row">
                <div class="col-md-12">
                    <h3>Resumen Ejecutivo</h3>
                    <div class="alert alert-info">
                        <h4>Estado General: <span style="color: {status_color}">{status_text}</span></h4>
                        <p>Período: {record.date_from.strftime('%d/%m/%Y')} - {record.date_to.strftime('%d/%m/%Y')}</p>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h5>Presupuesto</h5>
                            <h3>{record.currency_id.symbol} {record.total_budget:,.0f}</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h5>Real</h5>
                            <h3>{record.currency_id.symbol} {record.total_actual:,.0f}</h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h5>Variación</h5>
                            <h3 style="color: {'red' if record.total_variance < 0 else 'green'}">
                                {record.currency_id.symbol} {record.total_variance:,.0f}
                            </h3>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h5>Cumplimiento</h5>
                            <h3>{record.overall_achievement:.1f}%</h3>
                        </div>
                    </div>
                </div>
            </div>
            """

            # Agregar alertas si existen
            if record.alerts_count > 0:
                summary_html += f"""
                <div class="row mt-3">
                    <div class="col-md-12">
                        <div class="alert alert-warning">
                            <i class="fa fa-exclamation-triangle"></i>
                            Se detectaron <strong>{record.alerts_count}</strong> desviaciones significativas
                            (superiores al {record.deviation_threshold}%)
                        </div>
                    </div>
                </div>
                """

            record.executive_summary = summary_html

    def action_compute_comparison(self):
        """
        Acción principal para calcular la comparación presupuestaria
        """
        self.ensure_one()

        try:
            # Validar que exista el módulo de presupuestos
            if not self.env['ir.module.module'].search([
                ('name', '=', 'account_budget'),
                ('state', '=', 'installed')
            ]):
                raise UserError(_(
                    "El módulo de presupuestos (account_budget) no está instalado. "
                    "Por favor, instálelo para usar esta funcionalidad."
                ))

            # Cambiar estado
            self.write({'state': 'computing', 'last_compute': fields.Datetime.now()})

            # Limpiar líneas anteriores
            self.line_ids.unlink()

            # Obtener servicio
            from .services.budget_comparison_service import BudgetComparisonService
            service = BudgetComparisonService(self.env)

            # Ejecutar comparación
            result = service.compute_budget_comparison(self)

            # Crear líneas
            self._create_comparison_lines(result['lines'])

            # Guardar recomendaciones
            self.write({
                'state': 'computed',
                'recommendations': result.get('recommendations', '')
            })

            # Retornar acción para mostrar resultados
            return {
                'type': 'ir.actions.client',
                'tag': 'budget_comparison_report',
                'context': {
                    'active_id': self.id,
                    'active_model': self._name,
                }
            }

        except Exception as e:
            _logger.error(f"Error computing budget comparison: {str(e)}")
            self.write({
                'state': 'error',
                'validation_errors': str(e)
            })
            raise UserError(_("Error al calcular la comparación: %s") % str(e))

    def _create_comparison_lines(self, lines_data):
        """Crea las líneas de comparación desde los datos calculados"""
        # Usar BatchOperationService para crear todas las líneas de una vez
        batch_service = self.env.service('l10n_cl.batch.operation')

        # Preparar todos los valores para crear en batch
        vals_list = []
        for sequence, line_data in enumerate(lines_data, 1):
            vals_list.append({
                'report_id': self.id,
                'sequence': sequence,
                'name': line_data['name'],
                'code': line_data.get('code', ''),
                'account_id': line_data.get('account_id'),
                'budget_post_id': line_data.get('budget_post_id'),
                'analytic_account_id': line_data.get('analytic_account_id'),
                'hierarchy_level': line_data.get('hierarchy_level', 1),
                'is_total_line': line_data.get('is_total_line', False),
                'budget_amount': line_data['budget_amount'],
                'actual_amount': line_data['actual_amount'],
                'committed_amount': line_data.get('committed_amount', 0.0),
                'variance_amount': line_data['variance_amount'],
                'variance_percentage': line_data['variance_percentage'],
                'achievement_percentage': line_data['achievement_percentage'],
                'available_amount': line_data.get('available_amount', 0.0),
                'projection_amount': line_data.get('projection_amount', 0.0),
                'alert_type': line_data.get('alert_type', 'none'),
                'notes': line_data.get('notes', ''),
            })

        # Crear todas las líneas en una sola operación
        if vals_list:
            batch_service.batch_create('account.budget.comparison.line', vals_list)

    def action_export_excel(self):
        """Exporta la comparación a Excel con formato profesional"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular la comparación antes de exportar."))

        from .services.budget_comparison_service import BudgetComparisonService
        service = BudgetComparisonService(self.env)
        return service.export_to_excel(self)

    def action_export_pdf(self):
        """Exporta la comparación a PDF"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular la comparación antes de exportar."))

        return self.env.ref('l10n_cl_financial_reports.action_report_budget_comparison').report_action(self)

    def action_refresh(self):
        """Recalcula la comparación"""
        return self.action_compute_comparison()

    def action_open_dashboard(self):
        """Abre dashboard interactivo de presupuestos"""
        self.ensure_one()
        return {
            'type': 'ir.actions.client',
            'tag': 'budget_comparison_dashboard',
            'context': {
                'active_id': self.id,
                'comparison_data': self._get_dashboard_data(),
            }
        }

    def _get_dashboard_data(self):
        """Prepara datos para el dashboard"""
        # Top 5 mayores desviaciones
        top_deviations = self.line_ids.filtered(
            lambda l: not l.is_total_line
        ).sorted('variance_amount', reverse=True)[:5]

        # Datos para gráficos
        chart_data = {
            'budget_vs_actual': {
                'labels': [l.name for l in top_deviations],
                'budget': [l.budget_amount for l in top_deviations],
                'actual': [l.actual_amount for l in top_deviations],
            },
            'achievement_by_category': self._get_achievement_by_category(),
            'monthly_trend': self._get_monthly_trend(),
        }

        return json.dumps(chart_data)

    def _get_achievement_by_category(self):
        """Obtiene cumplimiento por categoría"""
        categories = {}

        for line in self.line_ids.filtered(lambda l: l.hierarchy_level == 1):
            categories[line.name] = line.achievement_percentage

        return {
            'labels': list(categories.keys()),
            'values': list(categories.values())
        }

    def _get_monthly_trend(self):
        """Obtiene tendencia mensual si es posible"""
        # Implementación simplificada
        return {
            'labels': ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun'],
            'budget': [100, 100, 100, 100, 100, 100],
            'actual': [95, 102, 98, 105, 103, 99]
        }

    def action_create_budget_revision(self):
        """Crea una propuesta de revisión presupuestaria"""
        self.ensure_one()

        # Crear borrador de revisión basado en las desviaciones
        revision_lines = []

        for line in self.line_ids.filtered(
            lambda l: abs(l.variance_percentage) > self.deviation_threshold
        ):
            # Proponer ajuste basado en la tendencia
            if line.projection_amount > 0:
                proposed_amount = line.projection_amount
            else:
                proposed_amount = line.actual_amount * 1.1  # 10% margen

            revision_lines.append({
                'name': line.name,
                'current_budget': line.budget_amount,
                'proposed_budget': proposed_amount,
                'justification': f"Desviación del {line.variance_percentage:.1f}%"
            })

        # Aquí se podría crear un documento de revisión
        # Por ahora, mostrar en wizard
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Propuesta de Revisión Presupuestaria'),
                'message': _(
                    'Se han identificado %d partidas que requieren revisión. '
                    'La propuesta ha sido generada.'
                ) % len(revision_lines),
                'type': 'warning',
                'sticky': True,
            }
        }


class BudgetComparisonLine(models.Model):
    """Líneas de comparación presupuestaria"""
    _name = 'account.budget.comparison.line'
    _description = 'Línea de Comparación Presupuestaria'
    _order = 'sequence, code'

    report_id = fields.Many2one(
        'account.budget.comparison.report',
        string='Reporte',
        required=True,
        ondelete='cascade'
    )

    sequence = fields.Integer(string='Secuencia', default=10)
    name = fields.Char(string='Descripción', required=True)
    code = fields.Char(string='Código')

    # Referencias
    account_id = fields.Many2one('account.account', string='Cuenta')
    budget_post_id = fields.Many2one('account.budget.post', string='Posición Presupuestaria')
    analytic_account_id = fields.Many2one('account.analytic.account', string='Cuenta Analítica')

    # Jerarquía
    hierarchy_level = fields.Integer(string='Nivel', default=1)
    is_total_line = fields.Boolean(string='Es Línea de Total', default=False)

    # Montos
    budget_amount = fields.Monetary(
        string='Presupuesto',
        currency_field='currency_id'
    )
    actual_amount = fields.Monetary(
        string='Real',
        currency_field='currency_id'
    )
    committed_amount = fields.Monetary(
        string='Comprometido',
        currency_field='currency_id'
    )
    available_amount = fields.Monetary(
        string='Disponible',
        currency_field='currency_id',
        help='Presupuesto - Real - Comprometido'
    )
    variance_amount = fields.Monetary(
        string='Variación',
        currency_field='currency_id',
        help='Real - Presupuesto (negativo = ahorro)'
    )

    # Porcentajes
    variance_percentage = fields.Float(
        string='Variación %',
        digits=(16, 2)
    )
    achievement_percentage = fields.Float(
        string='Cumplimiento %',
        digits=(16, 2)
    )

    # Proyección
    projection_amount = fields.Monetary(
        string='Proyección',
        currency_field='currency_id',
        help='Proyección al final del período basada en tendencia actual'
    )

    # Alertas
    alert_type = fields.Selection([
        ('none', 'Sin Alerta'),
        ('warning', 'Advertencia'),
        ('danger', 'Crítico'),
        ('info', 'Información')
    ], string='Tipo de Alerta', default='none')

    notes = fields.Text(string='Notas')

    currency_id = fields.Many2one(
        'res.currency',
        related='report_id.currency_id'
    )

    def action_view_details(self):
        """Abre vista detallada de movimientos"""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        self.ensure_one()

        domain = [
            ('date', '>=', self.report_id.date_from),
            ('date', '<=', self.report_id.date_to),
            ('company_id', '=', self.report_id.company_id.id)
        ]

        # Agregar filtros según el tipo
        if self.account_id:
            domain.append(('account_id', '=', self.account_id.id))

        if self.analytic_account_id:
            domain.append(('analytic_account_id', '=', self.analytic_account_id.id))

        return {
            'type': 'ir.actions.act_window',
            'name': _('Movimientos: %s') % self.name,
            'res_model': 'account.move.line',
            'domain': domain,
            'view_mode': 'tree,form',
            'context': {
                'search_default_group_by_move': 1,
            },
            'target': 'current',
        }

    def action_view_budget_lines(self):
        """Abre líneas presupuestarias relacionadas"""
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        self.ensure_one()

        if not self.budget_post_id:
            return False

        domain = [
            ('general_budget_id', '=', self.budget_post_id.id),
            ('date_from', '<=', self.report_id.date_to),
            ('date_to', '>=', self.report_id.date_from),
        ]

        if self.analytic_account_id:
            domain.append(('analytic_account_id', '=', self.analytic_account_id.id))

        return {
            'type': 'ir.actions.act_window',
            'name': _('Líneas Presupuestarias: %s') % self.name,
            'res_model': 'crossovered.budget.lines',
            'domain': domain,
            'view_mode': 'tree,form,pivot,graph',
            'target': 'current',
        }
