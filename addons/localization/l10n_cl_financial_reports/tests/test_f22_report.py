# -*- coding: utf-8 -*-
# Copyright 2025 EERGYGROUP - Ing. Pedro Troncoso Willz
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from odoo.tests import tagged, TransactionCase
from odoo.tools import mute_logger


@tagged('post_install', '-at_install', 'f22_report')

class TestF22Report(TransactionCase):
    """Test para el Formulario F22 - Declaración Anual de Renta"""

    def setUp(self):
        super().setUp()

        # Configurar compañía chilena
        self.company = self.env.user.company_id
        self.company.write({
            'country_id': self.env.ref('base.cl').id,
            'currency_id': self.env.ref('base.CLP').id,
        })

        # Crear cuentas de prueba
        self.account_income = self.env['account.account'].create({
            'name': 'Ingresos por Ventas',
            'code': '4101',
            'account_type': 'income',
            'company_id': self.company.id,
        })

        self.account_expense = self.env['account.account'].create({
            'name': 'Gastos Operacionales',
            'code': '6101',
            'account_type': 'expense',
            'company_id': self.company.id,
        })

        # Obtener el reporte F22
        self.f22_report = self.env.ref('account_financial_report.report_f22_cl')

    def test_f22_report_exists(self):
        """Test que verifica que el reporte F22 existe y está bien configurado"""

        self.assertTrue(self.f22_report.exists())
        self.assertEqual(self.f22_report.name, 'Formulario 22 - Declaración Anual de Renta')
        self.assertEqual(self.f22_report.country_id.code, 'CL')

    def test_f22_tax_tags_exist(self):
        """Test que verifica que los tax_tags del F22 existen"""

        tag_629 = self.env.ref('account_financial_report.tax_tag_f22_629')
        tag_631 = self.env.ref('account_financial_report.tax_tag_f22_631')
        tag_633 = self.env.ref('account_financial_report.tax_tag_f22_633')
        tag_31_ppm = self.env.ref('account_financial_report.tax_tag_f22_31_ppm')

        self.assertTrue(tag_629.exists())
        self.assertTrue(tag_631.exists())
        self.assertTrue(tag_633.exists())
        self.assertTrue(tag_31_ppm.exists())

        # Verificar que son para Chile
        self.assertEqual(tag_629.country_id.code, 'CL')

    def test_f22_report_lines_structure(self):
        """Test que verifica la estructura de líneas del F22"""

        # Verificar líneas principales
        line_628 = self.env.ref('account_financial_report.report_f22_cl_line_628')
        line_629 = self.env.ref('account_financial_report.report_f22_cl_line_629')
        line_1075 = self.env.ref('account_financial_report.report_f22_cl_line_1075')
        line_1077 = self.env.ref('account_financial_report.report_f22_cl_line_1077')

        self.assertTrue(line_628.exists())
        self.assertTrue(line_629.exists())
        self.assertTrue(line_1075.exists())
        self.assertTrue(line_1077.exists())

        # Verificar códigos de líneas
        self.assertEqual(line_628.code, 'F22_L628')
        self.assertEqual(line_629.code, 'F22_L629')
        self.assertEqual(line_1075.code, 'F22_L1075')
        self.assertEqual(line_1077.code, 'F22_L1077')

    def test_f22_expression_formulas(self):
        """Test que verifica las expresiones y fórmulas del F22"""

        # Línea 1075: Total Ingresos (suma)
        line_1075 = self.env.ref('account_financial_report.report_f22_cl_line_1075')
        expr_1075 = line_1075.expression_ids[0]

        self.assertEqual(expr_1075.engine, 'aggregation')
        self.assertEqual(expr_1075.formula, 'F22_L628 + F22_L629 + F22_L651')

        # Línea 1077: Resultado Tributario (resta)
        line_1077 = self.env.ref('account_financial_report.report_f22_cl_line_1077')
        expr_1077 = line_1077.expression_ids[0]

        self.assertEqual(expr_1077.engine, 'aggregation')
        self.assertEqual(expr_1077.formula, 'F22_L1075 - F22_L1076')

    @mute_logger('odoo.addons.account.models.account_report')
    def test_f22_report_generation(self):
        """Test básico de generación del reporte F22"""

        # Crear algunos asientos contables de prueba
        self._create_test_moves()

        # Generar el reporte
        options = {
            'date': {
                'date_from': '2024-01-01',
                'date_to': '2024-12-31',
                'filter': 'this_year',
                'mode': 'range',
            },
        }

        try:
            report_data = self.f22_report._get_lines(options)
            # Si no hay error, el test pasa
            self.assertTrue(True, "Reporte F22 se genera sin errores")
        except Exception as e:
            self.fail(f"Error al generar reporte F22: {str(e)}")

    def _create_test_moves(self):
        """Crear movimientos contables de prueba"""

        # Crear diario
        journal = self.env['account.journal'].create({
            'name': 'Test Journal',
            'code': 'TEST',
            'type': 'general',
            'company_id': self.company.id,
        })

        # Crear asiento de ingresos
        self.env['account.move'].create({
            'journal_id': journal.id,
            'date': '2024-06-01',
            'line_ids': [
                (0, 0, {
                    'name': 'Ingreso por ventas',
                    'account_id': self.account_income.id,
                    'credit': 1000000,
                }),
                (0, 0, {
                    'name': 'Banco',
                    'account_id': self.env['account.account'].search([
                        ('account_type', '=', 'asset_current'),
                        ('company_id', '=', self.company.id)
                    ], limit=1).id,
                    'debit': 1000000,
                }),
            ],
        }).action_post()

        # Crear asiento de gastos
        self.env['account.move'].create({
            'journal_id': journal.id,
            'date': '2024-06-01',
            'line_ids': [
                (0, 0, {
                    'name': 'Gasto operacional',
                    'account_id': self.account_expense.id,
                    'debit': 500000,
                }),
                (0, 0, {
                    'name': 'Banco',
                    'account_id': self.env['account.account'].search([
                        ('account_type', '=', 'asset_current'),
                        ('company_id', '=', self.company.id)
                    ], limit=1).id,
                    'credit': 500000,
                }),
            ],
        }).action_post()

    def test_f22_aggregation_formulas_syntax(self):
        """Test específico para validar sintaxis de fórmulas de agregación"""

        # Líneas que usan agregación
        aggregation_lines = [
            'report_f22_cl_line_1075',  # Total Ingresos
            'report_f22_cl_line_1076',  # Total Costos y Gastos
            'report_f22_cl_line_1077',  # Resultado Tributario
            'report_f22_cl_line_30',    # Impuesto Primera Categoría
            'report_f22_cl_line_34',    # Impuesto a Pagar
            'report_f22_cl_line_36',    # Devolución a Solicitar
        ]

        for line_id in aggregation_lines:
            line = self.env.ref(f'account_financial_report.{line_id}')
            expr = line.expression_ids[0]

            self.assertEqual(expr.engine, 'aggregation')
            # Verificar que la fórmula no contiene '.balance'
            self.assertNotIn('.balance', expr.formula,
                f"La fórmula de {line_id} no debe contener '.balance'")
            # Verificar que no contiene función max()
            self.assertNotIn('max(', expr.formula,
                f"La fórmula de {line_id} no debe contener 'max()'")

    def test_f22_tax_tags_formulas_syntax(self):
        """Test específico para validar sintaxis de fórmulas con tax_tags"""

        # Líneas que usan tax_tags
        tax_tag_lines = [
            ('report_f22_cl_line_629', 'tax_tag_f22_629'),
            ('report_f22_cl_line_631', 'tax_tag_f22_631'),
            ('report_f22_cl_line_633', 'tax_tag_f22_633'),
            ('report_f22_cl_line_31', 'tax_tag_f22_31_ppm'),
        ]

        for line_id, expected_tag in tax_tag_lines:
            line = self.env.ref(f'account_financial_report.{line_id}')
            expr = line.expression_ids[0]

            self.assertEqual(expr.engine, 'tax_tags')
            self.assertEqual(expr.formula, expected_tag,
                f"La fórmula de {line_id} debe referenciar {expected_tag}")
