# -*- coding: utf-8 -*-
"""
Dashboard Central de DTEs - Monitoreo SII

Este dashboard proporciona una vista unificada del estado de los DTEs
emitidos, su relación con el SII y métricas clave de facturación.

Diseñado para operadores de facturación y gerencia.

Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
Fecha: 2025-11-07
Fase: 2.1 - Dashboard Central de DTE
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError, UserError
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)


class DteDashboard(models.Model):
    """
    Dashboard Central de DTEs - Monitoreo SII.

    Este modelo actúa como un singleton por compañía, proporcionando
    KPIs en tiempo real sobre el estado de los DTEs emitidos.

    NO confundir con analytic_dashboard (rentabilidad por proyecto).
    Este dashboard es específico para gestión de DTEs y compliance SII.
    """
    _name = 'l10n_cl.dte_dashboard'
    _description = 'Dashboard Central DTEs - Monitoreo SII'
    _rec_name = 'display_name'
    _order = 'company_id asc'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    display_name = fields.Char(
        string='Nombre',
        compute='_compute_display_name',
        store=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        index=True
    )

    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        string='Moneda'
    )

    # ═══════════════════════════════════════════════════════════
    # KPIs PRINCIPALES (COMPUTED)
    # ═══════════════════════════════════════════════════════════

    dtes_aceptados_30d = fields.Integer(
        string='DTEs Aceptados (30d)',
        compute='_compute_kpis_30d',
        help='DTEs aceptados por el SII en los últimos 30 días'
    )

    dtes_rechazados_30d = fields.Integer(
        string='DTEs Rechazados (30d)',
        compute='_compute_kpis_30d',
        help='DTEs rechazados por el SII en los últimos 30 días'
    )

    dtes_pendientes = fields.Integer(
        string='DTEs Pendientes',
        compute='_compute_kpis_30d',
        help='DTEs pendientes de envío al SII'
    )

    monto_facturado_mes = fields.Monetary(
        string='Monto Facturado Mes Actual',
        currency_field='currency_id',
        compute='_compute_kpis_30d',
        help='Monto total facturado con DTEs aceptados en el mes actual (CLP)'
    )

    # ═══════════════════════════════════════════════════════════
    # CONTADORES ADICIONALES
    # ═══════════════════════════════════════════════════════════

    total_dtes_emitidos_mes = fields.Integer(
        string='Total DTEs Mes',
        compute='_compute_kpis_30d',
        help='Total de DTEs emitidos en el mes actual'
    )

    dtes_con_reparos = fields.Integer(
        string='DTEs con Reparos',
        compute='_compute_kpis_30d',
        help='DTEs que requieren acción del usuario (rechazados o con errores)'
    )

    # ═══════════════════════════════════════════════════════════
    # PORCENTAJES (INDICADORES)
    # ═══════════════════════════════════════════════════════════

    tasa_aceptacion_30d = fields.Float(
        string='Tasa Aceptación (%)',
        compute='_compute_kpis_30d',
        digits=(5, 2),
        help='Porcentaje de DTEs aceptados sobre el total emitido (últimos 30 días)'
    )

    tasa_rechazo_30d = fields.Float(
        string='Tasa Rechazo (%)',
        compute='_compute_kpis_30d',
        digits=(5, 2),
        help='Porcentaje de DTEs rechazados sobre el total emitido (últimos 30 días)'
    )

    # ═══════════════════════════════════════════════════════════
    # METADATA
    # ═══════════════════════════════════════════════════════════

    last_update = fields.Datetime(
        string='Última Actualización',
        default=fields.Datetime.now,
        readonly=True
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════

    @api.depends('company_id')
    def _compute_display_name(self):
        """Display name basado en compañía"""
        for record in self:
            record.display_name = f"Dashboard DTEs - {record.company_id.name}"

    def _compute_kpis_30d(self):
        """
        Calcula todos los KPIs del dashboard en un solo método.

        Optimización: Usa read_group y SQL para evitar N+1 queries.

        KPIs calculados:
        - DTEs aceptados/rechazados últimos 30 días
        - DTEs pendientes de envío
        - Monto facturado mes actual (solo DTEs aceptados)
        - Total DTEs emitidos mes
        - DTEs con reparos (requieren acción)
        - Tasas de aceptación/rechazo
        """
        AccountMove = self.env['account.move']

        # Fechas de referencia
        today = fields.Date.today()
        fecha_30d_atras = today - timedelta(days=30)
        fecha_inicio_mes = today.replace(day=1)

        for dashboard in self:
            company_id = dashboard.company_id.id

            # ══════════════════════════════════════════════
            # KPI 1 y 2: DTEs Aceptados/Rechazados (30 días)
            # ══════════════════════════════════════════════
            domain_30d = [
                ('company_id', '=', company_id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('invoice_date', '>=', fecha_30d_atras),
            ]

            # Aceptados
            dtes_aceptados = AccountMove.search_count(
                domain_30d + [('l10n_cl_dte_status', '=', 'accepted')]
            )

            # Rechazados
            dtes_rechazados = AccountMove.search_count(
                domain_30d + [('l10n_cl_dte_status', '=', 'rejected')]
            )

            dashboard.dtes_aceptados_30d = dtes_aceptados
            dashboard.dtes_rechazados_30d = dtes_rechazados

            # ══════════════════════════════════════════════
            # KPI 3: DTEs Pendientes de envío
            # ══════════════════════════════════════════════
            dtes_pendientes = AccountMove.search_count([
                ('company_id', '=', company_id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', 'in', ['draft', 'to_send']),
            ])

            dashboard.dtes_pendientes = dtes_pendientes

            # ══════════════════════════════════════════════
            # KPI 4: Monto Facturado Mes Actual (solo aceptados)
            # ══════════════════════════════════════════════
            domain_mes = [
                ('company_id', '=', company_id),
                ('move_type', '=', 'out_invoice'),
                ('state', '=', 'posted'),
                ('invoice_date', '>=', fecha_inicio_mes),
                ('l10n_cl_dte_status', '=', 'accepted'),
            ]

            # Usar read_group para sumar amount_total
            result = AccountMove.read_group(
                domain_mes,
                ['amount_total:sum'],
                []
            )

            dashboard.monto_facturado_mes = result[0]['amount_total'] if result else 0

            # ══════════════════════════════════════════════
            # CONTADOR ADICIONAL: Total DTEs emitidos mes
            # ══════════════════════════════════════════════
            total_mes = AccountMove.search_count([
                ('company_id', '=', company_id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('invoice_date', '>=', fecha_inicio_mes),
            ])

            dashboard.total_dtes_emitidos_mes = total_mes

            # ══════════════════════════════════════════════
            # CONTADOR ADICIONAL: DTEs con reparos
            # ══════════════════════════════════════════════
            dtes_reparos = AccountMove.search_count([
                ('company_id', '=', company_id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', 'in', ['rejected', 'error']),
            ])

            dashboard.dtes_con_reparos = dtes_reparos

            # ══════════════════════════════════════════════
            # PORCENTAJES: Tasas de aceptación y rechazo
            # ══════════════════════════════════════════════
            total_30d = dtes_aceptados + dtes_rechazados

            if total_30d > 0:
                dashboard.tasa_aceptacion_30d = (dtes_aceptados / total_30d) * 100
                dashboard.tasa_rechazo_30d = (dtes_rechazados / total_30d) * 100
            else:
                dashboard.tasa_aceptacion_30d = 0
                dashboard.tasa_rechazo_30d = 0

            # Actualizar timestamp
            dashboard.last_update = fields.Datetime.now()

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS PARA GRÁFICOS
    # ═══════════════════════════════════════════════════════════

    def get_chart_dtes_por_tipo(self):
        """
        Obtiene datos para gráfico de barras: DTEs emitidos por tipo en mes actual.

        Returns:
            dict: {
                'labels': ['DTE 33', 'DTE 56', 'DTE 61', 'DTE 52', 'DTE 34'],
                'data': [120, 45, 30, 80, 25]
            }
        """
        self.ensure_one()

        fecha_inicio_mes = fields.Date.today().replace(day=1)

        # Query SQL para contar por tipo de DTE
        self.env.cr.execute("""
            SELECT
                COALESCE(l10n_latam_document_type_id, 0) as doc_type_id,
                COUNT(*) as count
            FROM account_move
            WHERE company_id = %s
              AND move_type IN ('out_invoice', 'out_refund')
              AND state = 'posted'
              AND invoice_date >= %s
            GROUP BY l10n_latam_document_type_id
            ORDER BY count DESC
        """, (self.company_id.id, fecha_inicio_mes))

        results = self.env.cr.fetchall()

        # Mapear document_type_id a nombre legible
        labels = []
        data = []

        DocumentType = self.env['l10n_latam.document.type']
        for doc_type_id, count in results:
            if doc_type_id:
                doc_type = DocumentType.browse(doc_type_id)
                labels.append(f"DTE {doc_type.code}" if doc_type.code else doc_type.name)
            else:
                labels.append('Sin Tipo DTE')

            data.append(count)

        return {
            'labels': labels,
            'data': data
        }

    def get_chart_facturacion_diaria(self):
        """
        Obtiene datos para gráfico de línea: Evolución de facturación diaria en mes actual.

        Returns:
            dict: {
                'labels': ['2025-11-01', '2025-11-02', ...],
                'data': [1200000, 1500000, ...]
            }
        """
        self.ensure_one()

        fecha_inicio_mes = fields.Date.today().replace(day=1)
        fecha_fin_mes = fecha_inicio_mes + relativedelta(months=1) - timedelta(days=1)

        # Query SQL para sumar facturación por día
        self.env.cr.execute("""
            SELECT
                invoice_date,
                SUM(amount_total) as total
            FROM account_move
            WHERE company_id = %s
              AND move_type = 'out_invoice'
              AND state = 'posted'
              AND l10n_cl_dte_status = 'accepted'
              AND invoice_date >= %s
              AND invoice_date <= %s
            GROUP BY invoice_date
            ORDER BY invoice_date ASC
        """, (self.company_id.id, fecha_inicio_mes, fecha_fin_mes))

        results = self.env.cr.fetchall()

        labels = []
        data = []

        for fecha, total in results:
            labels.append(str(fecha))
            data.append(float(total))

        return {
            'labels': labels,
            'data': data
        }

    # ═══════════════════════════════════════════════════════════
    # ACCIONES (DRILL-DOWN)
    # ═══════════════════════════════════════════════════════════

    def action_view_dtes_aceptados(self):
        """Ver DTEs aceptados últimos 30 días"""
        self.ensure_one()

        fecha_30d_atras = fields.Date.today() - timedelta(days=30)

        return {
            'type': 'ir.actions.act_window',
            'name': _('DTEs Aceptados (30 días)'),
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('invoice_date', '>=', fecha_30d_atras),
                ('l10n_cl_dte_status', '=', 'accepted'),
            ],
            'context': {'default_company_id': self.company_id.id}
        }

    def action_view_dtes_rechazados(self):
        """Ver DTEs rechazados últimos 30 días"""
        self.ensure_one()

        fecha_30d_atras = fields.Date.today() - timedelta(days=30)

        return {
            'type': 'ir.actions.act_window',
            'name': _('DTEs Rechazados (30 días)'),
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('invoice_date', '>=', fecha_30d_atras),
                ('l10n_cl_dte_status', '=', 'rejected'),
            ],
            'context': {'default_company_id': self.company_id.id}
        }

    def action_view_dtes_pendientes(self):
        """Ver DTEs pendientes de envío"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('DTEs Pendientes de Envío'),
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', 'in', ['draft', 'to_send']),
            ],
            'context': {'default_company_id': self.company_id.id}
        }

    def action_view_dtes_con_reparos(self):
        """
        Ver DTEs con reparos (requieren acción).

        Esta es una de las listas de acceso rápido requeridas.
        """
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Mis DTEs con Reparos'),
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', 'in', ['rejected', 'error']),
            ],
            'context': {'default_company_id': self.company_id.id}
        }

    def action_view_ultimos_dtes(self):
        """
        Ver últimos 10 DTEs enviados con su estado.

        Esta es la segunda lista de acceso rápido requerida.
        """
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Últimos DTEs Enviados'),
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', '!=', False),
            ],
            'limit': 10,
            'context': {
                'default_company_id': self.company_id.id,
                'search_default_order_date_desc': 1,
            }
        }

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS DE CREACIÓN/SINGLETON
    # ═══════════════════════════════════════════════════════════

    @api.model
    def get_or_create_dashboard(self, company_id=None):
        """
        Obtiene o crea el dashboard para una compañía.

        Este modelo actúa como singleton por compañía.

        Args:
            company_id (int): ID de la compañía. Si no se proporciona, usa la compañía actual.

        Returns:
            l10n_cl.dte_dashboard: Dashboard de la compañía
        """
        if not company_id:
            company_id = self.env.company.id

        dashboard = self.search([('company_id', '=', company_id)], limit=1)

        if not dashboard:
            dashboard = self.create({'company_id': company_id})
            _logger.info(f"Dashboard DTE creado para compañía {company_id}")

        return dashboard

    def action_refresh_kpis(self):
        """
        Fuerza recálculo de KPIs.

        Útil para debugging o cuando el usuario quiere actualizar manualmente.
        """
        self.ensure_one()
        self._compute_kpis_30d()

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('KPIs Actualizados'),
                'message': _('Los KPIs del dashboard han sido actualizados.'),
                'type': 'success',
                'sticky': False,
            }
        }
