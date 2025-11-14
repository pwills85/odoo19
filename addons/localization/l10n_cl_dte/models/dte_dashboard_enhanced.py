# -*- coding: utf-8 -*-
"""
Dashboard Central de DTEs - Monitoreo SII (Enhanced)

Dashboard operacional-regulatorio con KPIs críticos de compliance SII.

Mejoras Fase 2.1 (Cierre de Brechas):
- Métrica financiera neta (incluye NC)
- KPIs regulatorios: CAF, certificados, envejecidos
- Tasas aceptación regulatoria vs operacional
- Optimización queries (read_group consolidado)
- i18n completo
- Multi-compañía estricta

Autor: EERGYGROUP - Ing. Pedro Troncoso Willz
Fecha: 2025-11-07
Fase: 2.1 - Cierre de Brechas Dashboard
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError, UserError
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)


class DteDashboardEnhanced(models.Model):
    """
    Dashboard Central de DTEs - Monitoreo SII (Enhanced).

    Singleton por compañía con KPIs operacionales y regulatorios.
    """
    _inherit = 'l10n_cl.dte_dashboard'

    # ═══════════════════════════════════════════════════════════
    # NUEVOS KPIs - MÉTRICA FINANCIERA NETA
    # ═══════════════════════════════════════════════════════════

    monto_facturado_neto_mes = fields.Monetary(
        string='Monto Facturado Neto Mes',
        currency_field='currency_id',
        compute='_compute_kpis_enhanced',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        help=_('Monto neto facturado (facturas - notas de crédito) del mes actual con DTEs aceptados')
    )

    # ═══════════════════════════════════════════════════════════
    # NUEVOS KPIs - REGULATORIOS CRÍTICOS
    # ═══════════════════════════════════════════════════════════

    pendientes_total = fields.Integer(
        string='Pendientes Total',
        compute='_compute_kpis_enhanced',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        help=_('Total de DTEs en estados pendientes (draft, to_send, sending, sent, contingency)')
    )

    dtes_enviados_sin_respuesta_6h = fields.Integer(
        string='DTEs Sin Respuesta +6h',
        compute='_compute_kpis_enhanced',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        help=_('DTEs enviados al SII hace más de 6 horas sin respuesta (estado sent > 6h)')
    )

    folios_restantes_total = fields.Integer(
        string='Folios CAF Restantes',
        compute='_compute_kpis_regulatory',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        help=_('Total de folios disponibles en CAFs activos de todos los tipos de DTE')
    )

    dias_certificado_expira = fields.Integer(
        string='Días a Expiración Certificado',
        compute='_compute_kpis_regulatory',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        help=_('Días restantes hasta la expiración del certificado digital SII')
    )

    # ═══════════════════════════════════════════════════════════
    # ALERTAS REGULATORIAS
    # ═══════════════════════════════════════════════════════════

    alerta_caf_bajo = fields.Boolean(
        string='Alerta: CAF Bajo',
        compute='_compute_kpis_regulatory',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        help=_('Alerta activada cuando folios CAF restantes < 10% del total activo')
    )

    alerta_certificado = fields.Boolean(
        string='Alerta: Certificado',
        compute='_compute_kpis_regulatory',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        help=_('Alerta activada cuando certificado expira en menos de 30 días')
    )

    # ═══════════════════════════════════════════════════════════
    # TASAS DE ACEPTACIÓN (REGULATORIA VS OPERACIONAL)
    # ═══════════════════════════════════════════════════════════

    tasa_aceptacion_regulatoria = fields.Float(
        string='Tasa Aceptación Regulatoria (%)',
        compute='_compute_kpis_enhanced',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        digits=(5, 2),
        help=_('Tasa regulatoria: aceptados / (aceptados + rechazados) × 100. '
               'No incluye pendientes. Métrica oficial SII.')
    )

    tasa_aceptacion_operacional = fields.Float(
        string='Tasa Aceptación Operacional (%)',
        compute='_compute_kpis_enhanced',
        store=True,
        compute_sudo=True,  # Odoo 19 CE: Required for stored computed fields
        digits=(5, 2),
        help=_('Tasa operacional: aceptados / total_emitidos × 100. '
               'Incluye pendientes y errores. Métrica gestión interna.')
    )

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS COMPUTADOS MEJORADOS
    # ═══════════════════════════════════════════════════════════

    @api.depends('company_id')
    def _compute_kpis_enhanced(self):
        """
        Calcula KPIs mejorados con consolidación de queries.

        Optimizaciones Fase 2.1:
        - Un solo read_group por l10n_cl_dte_status y move_type
        - Memoization temporal de resultados parciales
        - Facturación neta incluye NC

        KPIs calculados:
        - monto_facturado_neto_mes (facturas - NC)
        - pendientes_total (draft+to_send+sending+sent+contingency)
        - dtes_enviados_sin_respuesta_6h (sent > 6h)
        - tasa_aceptacion_regulatoria
        - tasa_aceptacion_operacional
        """
        AccountMove = self.env['account.move']

        # Fechas de referencia
        today = fields.Date.today()
        fecha_30d_atras = today - timedelta(days=30)
        fecha_inicio_mes = today.replace(day=1)
        fecha_6h_atras = fields.Datetime.now() - timedelta(hours=6)

        for dashboard in self:
            company_id = dashboard.company_id.id

            # ══════════════════════════════════════════════
            # OPTIMIZACIÓN: Single read_group para 30 días
            # ══════════════════════════════════════════════
            domain_30d = [
                ('company_id', '=', company_id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('invoice_date', '>=', fecha_30d_atras),
            ]

            # Agrupar por estado DTE en 30 días
            groups_30d = AccountMove.read_group(
                domain_30d,
                ['l10n_cl_dte_status'],
                ['l10n_cl_dte_status']
            )

            # Memoization: almacenar contadores por estado
            contadores_30d = {
                group['l10n_cl_dte_status']: group['l10n_cl_dte_status_count']
                for group in groups_30d
                if group['l10n_cl_dte_status']
            }

            dtes_aceptados = contadores_30d.get('accepted', 0)
            dtes_rechazados = contadores_30d.get('rejected', 0)

            # ══════════════════════════════════════════════
            # OPTIMIZACIÓN: Single read_group para mes actual
            # ══════════════════════════════════════════════
            domain_mes = [
                ('company_id', '=', company_id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('invoice_date', '>=', fecha_inicio_mes),
                ('l10n_cl_dte_status', '=', 'accepted'),
            ]

            # Agrupar por move_type para calcular neto
            groups_mes = AccountMove.read_group(
                domain_mes,
                ['amount_total_signed:sum'],
                ['move_type']
            )

            # Calcular monto neto (facturas - NC)
            monto_neto = 0
            for group in groups_mes:
                move_type = group['move_type']
                monto = group['amount_total_signed']

                if move_type == 'out_invoice':
                    monto_neto += monto
                elif move_type == 'out_refund':
                    # NC son negativas en amount_total_signed
                    monto_neto += monto  # Ya viene negativo

            dashboard.monto_facturado_neto_mes = monto_neto

            # ══════════════════════════════════════════════
            # PENDIENTES TOTAL (todos los estados pendientes)
            # ══════════════════════════════════════════════
            estados_pendientes = ['draft', 'to_send', 'sending', 'sent', 'contingency']

            pendientes_total = AccountMove.search_count([
                ('company_id', '=', company_id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', 'in', estados_pendientes),
            ])

            dashboard.pendientes_total = pendientes_total

            # ══════════════════════════════════════════════
            # DTEs ENVIADOS SIN RESPUESTA > 6H
            # ══════════════════════════════════════════════
            dtes_envejecidos = AccountMove.search_count([
                ('company_id', '=', company_id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', '=', 'sent'),
                ('write_date', '<', fecha_6h_atras),
            ])

            dashboard.dtes_enviados_sin_respuesta_6h = dtes_envejecidos

            # ══════════════════════════════════════════════
            # TASAS DE ACEPTACIÓN
            # ══════════════════════════════════════════════

            # Tasa Regulatoria: aceptados / (aceptados + rechazados)
            total_regulatorio = dtes_aceptados + dtes_rechazados
            if total_regulatorio > 0:
                dashboard.tasa_aceptacion_regulatoria = (dtes_aceptados / total_regulatorio) * 100
            else:
                dashboard.tasa_aceptacion_regulatoria = 0

            # Tasa Operacional: aceptados / total_emitidos
            # total_emitidos incluye: aceptados, rechazados, pendientes, error, contingency
            total_operacional = sum(contadores_30d.values())

            if total_operacional > 0:
                dashboard.tasa_aceptacion_operacional = (dtes_aceptados / total_operacional) * 100
            else:
                dashboard.tasa_aceptacion_operacional = 0

    @api.depends('company_id')
    def _compute_kpis_regulatory(self):
        """
        Calcula KPIs regulatorios críticos.

        KPIs:
        - folios_restantes_total (suma de remaining_folios en CAFs activos)
        - dias_certificado_expira (días hasta expiración certificado)
        - alerta_caf_bajo (< 10% folios totales)
        - alerta_certificado (< 30 días)
        """
        DteCaf = self.env['dte.caf']
        DteCertificate = self.env['dte.certificate']

        for dashboard in self:
            company_id = dashboard.company_id.id

            # ══════════════════════════════════════════════
            # FOLIOS CAF RESTANTES
            # ══════════════════════════════════════════════
            cafs_activos = DteCaf.search([
                ('company_id', '=', company_id),
                ('state', '=', 'active'),
            ])

            folios_restantes = sum(cafs_activos.mapped('remaining_folios'))
            folios_totales = sum(cafs_activos.mapped('final_folio')) - sum(cafs_activos.mapped('initial_folio')) + len(cafs_activos)

            dashboard.folios_restantes_total = folios_restantes

            # Alerta CAF: < 10% del total
            if folios_totales > 0:
                porcentaje_restante = (folios_restantes / folios_totales) * 100
                dashboard.alerta_caf_bajo = porcentaje_restante < 10
            else:
                dashboard.alerta_caf_bajo = False

            # ══════════════════════════════════════════════
            # CERTIFICADO DIGITAL
            # ══════════════════════════════════════════════
            certificado = DteCertificate.search([
                ('company_id', '=', company_id),
                ('state', '=', 'valid'),
            ], limit=1, order='valid_to desc')

            if certificado and certificado.valid_to:
                dias_expiracion = (certificado.valid_to.date() - fields.Date.today()).days
                dashboard.dias_certificado_expira = dias_expiracion

                # Alerta certificado: < 30 días
                dashboard.alerta_certificado = dias_expiracion < 30
            else:
                dashboard.dias_certificado_expira = 0
                dashboard.alerta_certificado = True  # Sin certificado = alerta crítica

    # ═══════════════════════════════════════════════════════════
    # ACCIONES DRILL-DOWN MEJORADAS
    # ═══════════════════════════════════════════════════════════

    def action_view_dtes_envejecidos(self):
        """Ver DTEs enviados sin respuesta > 6h"""
        self.ensure_one()

        fecha_6h_atras = fields.Datetime.now() - timedelta(hours=6)

        return {
            'type': 'ir.actions.act_window',
            'name': _('DTEs Sin Respuesta (+6h)'),
            'res_model': 'account.move',
            'view_mode': 'list,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('move_type', 'in', ['out_invoice', 'out_refund']),
                ('state', '=', 'posted'),
                ('l10n_cl_dte_status', '=', 'sent'),
                ('write_date', '<', fecha_6h_atras),
            ],
            'context': {'default_company_id': self.company_id.id}
        }

    def action_view_cafs(self):
        """Ver CAFs activos de la compañía"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('CAFs Activos'),
            'res_model': 'dte.caf',
            'view_mode': 'list,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
                ('state', '=', 'active'),
            ],
            'context': {'default_company_id': self.company_id.id}
        }

    def action_view_certificados(self):
        """Ver certificados digitales de la compañía"""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Certificados Digitales'),
            'res_model': 'dte.certificate',
            'view_mode': 'list,form',
            'domain': [
                ('company_id', '=', self.company_id.id),
            ],
            'context': {'default_company_id': self.company_id.id}
        }
