# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import logging

_logger = logging.getLogger(__name__)


class L10nClReportComparisonWizard(models.TransientModel):
    """
    Wizard para comparar F22 (declaración anual) vs F29 (suma declaraciones mensuales).

    Detecta discrepancias entre ambas fuentes y las presenta en formato visual
    con alertas rojas para diferencias significativas.
    """

    _name = 'l10n_cl.report.comparison.wizard'
    _description = 'Wizard Comparación F22 vs F29'

    year = fields.Integer(
        string='Año Fiscal',
        required=True,
        default=lambda self: fields.Date.today().year,
        help='Año fiscal a comparar'
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        help='Compañía para la cual realizar la comparación'
    )

    # Resultados de la comparación (campos computados)
    comparison_line_ids = fields.One2many(
        'l10n_cl.report.comparison.line',
        'wizard_id',
        string='Líneas de Comparación',
        readonly=True
    )

    total_discrepancies = fields.Integer(
        string='Total Discrepancias',
        compute='_compute_summary_stats',
        help='Número de conceptos con discrepancias'
    )

    max_discrepancy_amount = fields.Monetary(
        string='Mayor Discrepancia',
        compute='_compute_summary_stats',
        currency_field='currency_id',
        help='Monto de la mayor discrepancia detectada'
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        related='company_id.currency_id',
        readonly=True
    )

    state = fields.Selection([
        ('draft', 'Configuración'),
        ('compared', 'Comparado'),
    ], string='Estado', default='draft')

    @api.depends('comparison_line_ids', 'comparison_line_ids.has_discrepancy')
    def _compute_summary_stats(self):
        """Calcula estadísticas resumen de las discrepancias"""
        for wizard in self:
            lines_with_discrepancy = wizard.comparison_line_ids.filtered('has_discrepancy')
            wizard.total_discrepancies = len(lines_with_discrepancy)

            if lines_with_discrepancy:
                wizard.max_discrepancy_amount = max(
                    abs(line.difference) for line in lines_with_discrepancy
                )
            else:
                wizard.max_discrepancy_amount = 0.0

    def action_compare(self):
        """
        Ejecuta la comparación F22 vs suma de F29.

        Returns:
            dict: Acción para mostrar resultados
        """
        self.ensure_one()

        # 1. Obtener F22 del año
        f22 = self.env['l10n_cl.f22'].search([
            ('company_id', '=', self.company_id.id),
            ('fiscal_year', '=', self.year),
            ('state', '!=', 'replaced'),
        ], limit=1)

        if not f22:
            raise UserError(
                _('No se encontró F22 para el año %s en la compañía %s.\n\n'
                  'Por favor, asegúrese de que existe una declaración F22 para ese año.') %
                (self.year, self.company_id.name)
            )

        # 2. Obtener todos los F29 del año
        f29_records = self.env['l10n_cl.f29'].search([
            ('company_id', '=', self.company_id.id),
            ('period_date', '>=', f'{self.year}-01-01'),
            ('period_date', '<=', f'{self.year}-12-31'),
            ('state', 'in', ['confirmed', 'sent', 'accepted']),
        ])

        if not f29_records:
            raise UserError(
                _('No se encontraron declaraciones F29 confirmadas para el año %s.\n\n'
                  'Debe tener al menos una declaración F29 confirmada para realizar la comparación.') %
                self.year
            )

        # 3. Calcular suma de F29
        f29_totals = self._aggregate_f29_totals(f29_records)

        # 4. Generar líneas de comparación
        self._generate_comparison_lines(f22, f29_totals)

        # 5. Cambiar estado
        self.state = 'compared'

        # 6. Retornar vista de resultados
        return {
            'type': 'ir.actions.act_window',
            'name': _('Comparación F22 vs F29 - Año %s') % self.year,
            'res_model': 'l10n_cl.report.comparison.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
            'context': {'show_results': True},
        }

    def _aggregate_f29_totals(self, f29_records):
        """
        Agrega totales de todos los F29 del año.

        Args:
            f29_records: Recordset de l10n_cl.f29

        Returns:
            dict: Totales agregados por concepto
        """
        return {
            'ventas_afectas': sum(f29_records.mapped('ventas_afectas')),
            'ventas_exentas': sum(f29_records.mapped('ventas_exentas')),
            'ventas_exportacion': sum(f29_records.mapped('ventas_exportacion')),
            'debito_fiscal': sum(f29_records.mapped('debito_fiscal')),
            'compras_afectas': sum(f29_records.mapped('compras_afectas')),
            'compras_exentas': sum(f29_records.mapped('compras_exentas')),
            'compras_activo_fijo': sum(f29_records.mapped('compras_activo_fijo')),
            'credito_fiscal': sum(f29_records.mapped('credito_fiscal')),
            'ppm_mes': sum(f29_records.mapped('ppm_mes')),
            'ppm_voluntario': sum(f29_records.mapped('ppm_voluntario')),
            'iva_a_pagar': sum(f29_records.mapped('iva_a_pagar')),
            'saldo_favor': sum(f29_records.mapped('saldo_favor')),
        }

    def _generate_comparison_lines(self, f22, f29_totals):
        """
        Genera líneas de comparación entre F22 y suma F29.

        Args:
            f22: Record de l10n_cl.f22
            f29_totals: Dict con totales F29 agregados
        """
        # Borrar líneas existentes
        self.comparison_line_ids.unlink()

        # Definir conceptos a comparar (campo F22, campo F29, nombre display)
        concepts_to_compare = [
            ('ingresos_totales', 'ventas_afectas', 'Ingresos / Ventas Afectas'),
            ('ventas_exentas', 'ventas_exentas', 'Ventas Exentas'),
            ('ventas_exportacion', 'ventas_exportacion', 'Exportaciones'),
            ('debito_fiscal_total', 'debito_fiscal', 'Débito Fiscal IVA'),
            ('compras_totales', 'compras_afectas', 'Compras Afectas'),
            ('credito_fiscal_total', 'credito_fiscal', 'Crédito Fiscal IVA'),
            ('ppm_pagado_total', 'ppm_mes', 'PPM Pagado (mes)'),
            ('impuesto_primera_categoria', 'iva_a_pagar', 'Impuesto a Pagar'),
        ]

        lines_to_create = []

        for f22_field, f29_field, display_name in concepts_to_compare:
            # Obtener valores (usar 0 si el campo no existe)
            f22_value = getattr(f22, f22_field, 0) if hasattr(f22, f22_field) else 0
            f29_value = f29_totals.get(f29_field, 0)

            lines_to_create.append({
                'wizard_id': self.id,
                'concept': display_name,
                'total_f29': f29_value,
                'total_f22': f22_value,
                'difference': f29_value - f22_value,
            })

        # Crear todas las líneas
        self.env['l10n_cl.report.comparison.line'].create(lines_to_create)

        _logger.info(
            "Comparación F22 vs F29 completada para año %s, compañía %s. "
            "Líneas generadas: %d, Discrepancias: %d",
            self.year, self.company_id.name, len(lines_to_create), self.total_discrepancies
        )

    def action_close(self):
        """Cierra el wizard"""
        return {'type': 'ir.actions.act_window_close'}


class L10nClReportComparisonLine(models.TransientModel):
    """
    Línea de comparación individual (un concepto específico).
    """

    _name = 'l10n_cl.report.comparison.line'
    _description = 'Línea de Comparación F22 vs F29'
    _order = 'sequence, id'

    wizard_id = fields.Many2one(
        'l10n_cl.report.comparison.wizard',
        string='Wizard',
        required=True,
        ondelete='cascade'
    )

    sequence = fields.Integer(string='Secuencia', default=10)

    concept = fields.Char(
        string='Concepto',
        required=True,
        help='Nombre del concepto comparado (ej: Ventas Afectas)'
    )

    total_f29 = fields.Monetary(
        string='Total F29 (Suma Mensual)',
        currency_field='currency_id',
        help='Suma de todos los F29 del año para este concepto'
    )

    total_f22 = fields.Monetary(
        string='Total F22 (Anual)',
        currency_field='currency_id',
        help='Valor declarado en F22 para este concepto'
    )

    difference = fields.Monetary(
        string='Diferencia (F29 - F22)',
        currency_field='currency_id',
        help='Diferencia entre suma F29 y F22'
    )

    has_discrepancy = fields.Boolean(
        string='Tiene Discrepancia',
        compute='_compute_has_discrepancy',
        store=True,
        help='True si la diferencia supera la tolerancia de $100'
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        related='wizard_id.currency_id',
        readonly=True
    )

    @api.depends('difference')
    def _compute_has_discrepancy(self):
        """
        Calcula si hay discrepancia significativa.

        Tolerancia: $100 (para manejar diferencias de redondeo)
        """
        TOLERANCE = 100.0

        for line in self:
            line.has_discrepancy = abs(line.difference) > TOLERANCE
