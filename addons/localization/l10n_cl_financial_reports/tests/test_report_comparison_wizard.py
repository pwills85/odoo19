# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError
from datetime import date


class TestReportComparisonWizard(TransactionCase):
    """
    Tests para el wizard de comparación F22 vs F29.
    """

    def setUp(self):
        super().setUp()

        # Crear compañía de prueba
        self.company = self.env['res.company'].create({
            'name': 'Test Company Comparison',
            'currency_id': self.env.ref('base.CLP').id,
        })

        self.year = 2024

        # Crear F29 mensuales de prueba (3 meses)
        self.f29_jan = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-01-01',
            'state': 'confirmed',
            'ventas_afectas': 1000000.0,
            'ventas_exentas': 100000.0,
            'ventas_exportacion': 50000.0,
            'compras_afectas': 600000.0,
            'compras_exentas': 50000.0,
            'compras_activo_fijo': 100000.0,
            'ppm_mes': 50000.0,
            'ppm_voluntario': 10000.0,
        })

        self.f29_feb = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-02-01',
            'state': 'confirmed',
            'ventas_afectas': 1200000.0,
            'ventas_exentas': 120000.0,
            'ventas_exportacion': 60000.0,
            'compras_afectas': 700000.0,
            'compras_exentas': 60000.0,
            'compras_activo_fijo': 120000.0,
            'ppm_mes': 60000.0,
            'ppm_voluntario': 12000.0,
        })

        self.f29_mar = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-03-01',
            'state': 'confirmed',
            'ventas_afectas': 1100000.0,
            'ventas_exentas': 110000.0,
            'ventas_exportacion': 55000.0,
            'compras_afectas': 650000.0,
            'compras_exentas': 55000.0,
            'compras_activo_fijo': 110000.0,
            'ppm_mes': 55000.0,
            'ppm_voluntario': 11000.0,
        })

        # Calcular totales esperados (3 meses)
        self.expected_totals = {
            'ventas_afectas': 3300000.0,  # 1M + 1.2M + 1.1M
            'ventas_exentas': 330000.0,
            'ventas_exportacion': 165000.0,
            'compras_afectas': 1950000.0,
            'compras_activo_fijo': 330000.0,
            'ppm_mes': 165000.0,
        }

    def test_01_wizard_creation(self):
        """Test que el wizard se puede crear correctamente"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        self.assertEqual(wizard.year, self.year)
        self.assertEqual(wizard.company_id, self.company)
        self.assertEqual(wizard.state, 'draft')

    def test_02_wizard_default_year(self):
        """Test que el wizard usa el año actual por defecto"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'company_id': self.company.id,
        })

        self.assertEqual(wizard.year, date.today().year)

    def test_03_wizard_default_company(self):
        """Test que el wizard usa la compañía del contexto por defecto"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].with_context(
            allowed_company_ids=[self.company.id]
        ).with_company(self.company).create({
            'year': self.year,
        })

        self.assertEqual(wizard.company_id, self.company)

    def test_04_aggregate_f29_totals(self):
        """Test que la agregación de F29 suma correctamente los totales"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        f29_records = self.f29_jan | self.f29_feb | self.f29_mar
        totals = wizard._aggregate_f29_totals(f29_records)

        self.assertEqual(totals['ventas_afectas'], self.expected_totals['ventas_afectas'])
        self.assertEqual(totals['ventas_exentas'], self.expected_totals['ventas_exentas'])
        self.assertEqual(totals['ventas_exportacion'], self.expected_totals['ventas_exportacion'])
        self.assertEqual(totals['compras_afectas'], self.expected_totals['compras_afectas'])
        self.assertEqual(totals['compras_activo_fijo'], self.expected_totals['compras_activo_fijo'])
        self.assertEqual(totals['ppm_mes'], self.expected_totals['ppm_mes'])

    def test_05_action_compare_no_f22_raises_error(self):
        """Test que ejecutar comparación sin F22 lanza error"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        with self.assertRaises(UserError) as context:
            wizard.action_compare()

        self.assertIn('No se encontró F22', str(context.exception))

    def test_06_action_compare_no_f29_raises_error(self):
        """Test que ejecutar comparación sin F29 lanza error"""
        # Crear F22 pero sin F29
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.year,
            'state': 'draft',
            'ingresos_totales': 3300000.0,
        })

        # Borrar todos los F29
        (self.f29_jan | self.f29_feb | self.f29_mar).unlink()

        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        with self.assertRaises(UserError) as context:
            wizard.action_compare()

        self.assertIn('No se encontraron declaraciones F29', str(context.exception))

    def test_07_action_compare_generates_lines(self):
        """Test que la comparación genera líneas de comparación"""
        # Crear F22
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.year,
            'state': 'draft',
            'ingresos_totales': 3300000.0,  # Coincide con suma F29
            'ventas_exentas': 330000.0,
            'ventas_exportacion': 165000.0,
            'debito_fiscal_total': 627000.0,  # 3.3M * 0.19
            'compras_totales': 1950000.0,
            'credito_fiscal_total': 433500.0,  # (1.95M + 330K) * 0.19
            'ppm_pagado_total': 165000.0,
            'impuesto_primera_categoria': 193500.0,  # Débito - Crédito
        })

        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        wizard.action_compare()

        # Verificar que se generaron líneas
        self.assertTrue(len(wizard.comparison_line_ids) > 0)

        # Verificar que el estado cambió
        self.assertEqual(wizard.state, 'compared')

    def test_08_comparison_line_detects_no_discrepancy(self):
        """Test que una línea sin diferencia no tiene discrepancia"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        line = self.env['l10n_cl.report.comparison.line'].create({
            'wizard_id': wizard.id,
            'concept': 'Test Concepto',
            'total_f29': 1000000.0,
            'total_f22': 1000050.0,  # Diferencia de $50 (dentro de tolerancia)
            'difference': 50.0,
        })

        self.assertFalse(line.has_discrepancy)

    def test_09_comparison_line_detects_discrepancy(self):
        """Test que una línea con diferencia >$100 tiene discrepancia"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        line = self.env['l10n_cl.report.comparison.line'].create({
            'wizard_id': wizard.id,
            'concept': 'Test Concepto',
            'total_f29': 1000000.0,
            'total_f22': 1001000.0,  # Diferencia de $1000 (fuera de tolerancia)
            'difference': 1000.0,
        })

        self.assertTrue(line.has_discrepancy)

    def test_10_comparison_line_detects_negative_discrepancy(self):
        """Test que una línea con diferencia negativa >$100 tiene discrepancia"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        line = self.env['l10n_cl.report.comparison.line'].create({
            'wizard_id': wizard.id,
            'concept': 'Test Concepto',
            'total_f29': 1000000.0,
            'total_f22': 1001000.0,
            'difference': -1000.0,  # Diferencia negativa
        })

        self.assertTrue(line.has_discrepancy)

    def test_11_summary_stats_computed(self):
        """Test que las estadísticas resumen se calculan correctamente"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        # Crear líneas con discrepancias
        self.env['l10n_cl.report.comparison.line'].create({
            'wizard_id': wizard.id,
            'concept': 'Concepto 1',
            'total_f29': 1000000.0,
            'total_f22': 1000000.0,
            'difference': 0.0,  # Sin discrepancia
        })

        self.env['l10n_cl.report.comparison.line'].create({
            'wizard_id': wizard.id,
            'concept': 'Concepto 2',
            'total_f29': 1000000.0,
            'total_f22': 1001000.0,
            'difference': 1000.0,  # Con discrepancia
        })

        self.env['l10n_cl.report.comparison.line'].create({
            'wizard_id': wizard.id,
            'concept': 'Concepto 3',
            'total_f29': 500000.0,
            'total_f22': 502000.0,
            'difference': 2000.0,  # Con discrepancia mayor
        })

        # Verificar estadísticas
        self.assertEqual(wizard.total_discrepancies, 2)
        self.assertEqual(wizard.max_discrepancy_amount, 2000.0)

    def test_12_action_compare_with_matching_values(self):
        """Test comparación completa con valores que coinciden exactamente"""
        # Crear F22 con valores que coinciden exactamente
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.year,
            'state': 'draft',
            'ingresos_totales': 3300000.0,
            'ventas_exentas': 330000.0,
            'ventas_exportacion': 165000.0,
            'debito_fiscal_total': 627000.0,
            'compras_totales': 1950000.0,
            'credito_fiscal_total': 433500.0,
            'ppm_pagado_total': 165000.0,
            'impuesto_primera_categoria': 193500.0,
        })

        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        result = wizard.action_compare()

        # Verificar que no hay discrepancias
        self.assertEqual(wizard.total_discrepancies, 0)
        self.assertEqual(wizard.max_discrepancy_amount, 0.0)

        # Verificar que retorna una acción
        self.assertEqual(result['type'], 'ir.actions.act_window')
        self.assertEqual(result['res_model'], 'l10n_cl.report.comparison.wizard')

    def test_13_action_compare_with_discrepancies(self):
        """Test comparación completa con valores que tienen discrepancias"""
        # Crear F22 con valores diferentes
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': self.year,
            'state': 'draft',
            'ingresos_totales': 3500000.0,  # Diferencia de 200K
            'ventas_exentas': 350000.0,  # Diferencia de 20K
            'ventas_exportacion': 165000.0,  # Sin diferencia
            'debito_fiscal_total': 665000.0,  # Diferencia
            'compras_totales': 2000000.0,  # Diferencia de 50K
            'credito_fiscal_total': 442700.0,  # Diferencia
            'ppm_pagado_total': 165000.0,  # Sin diferencia
            'impuesto_primera_categoria': 222300.0,  # Diferencia
        })

        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        wizard.action_compare()

        # Verificar que hay discrepancias
        self.assertGreater(wizard.total_discrepancies, 0)
        self.assertGreater(wizard.max_discrepancy_amount, 0.0)

    def test_14_action_close(self):
        """Test que action_close cierra el wizard correctamente"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        result = wizard.action_close()

        self.assertEqual(result['type'], 'ir.actions.act_window_close')

    def test_15_comparison_tolerates_rounding_errors(self):
        """Test que la comparación tolera errores de redondeo pequeños ($100)"""
        wizard = self.env['l10n_cl.report.comparison.wizard'].create({
            'year': self.year,
            'company_id': self.company.id,
        })

        # Crear línea con error de redondeo exactamente en el límite
        line = self.env['l10n_cl.report.comparison.line'].create({
            'wizard_id': wizard.id,
            'concept': 'Test Redondeo',
            'total_f29': 1000000.0,
            'total_f22': 1000100.0,
            'difference': 100.0,  # Exactamente en la tolerancia
        })

        # No debe marcar como discrepancia (tolerancia es >100, no >=100)
        self.assertFalse(line.has_discrepancy)
