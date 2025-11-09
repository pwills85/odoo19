# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo.tests import tagged
from odoo.addons.account.tests.common import AccountTestInvoicingCommon


@tagged('post_install', '-at_install')
class TestKpiCalculation(AccountTestInvoicingCommon):

    @classmethod
    def setUpClass(cls, chart_template_ref=None):
        super().setUpClass(chart_template_ref=chart_template_ref)

        # Find a specific report line to use for our KPI tests, e.g., Gross Profit
        cls.profit_loss_report = cls.env.ref('account.profit_and_loss')
        cls.gross_profit_line = cls.env['account.report.line'].search([
            ('report_id', '=', cls.profit_loss_report.id),
            ('name', '=', 'Gross Profit')
        ], limit=1)

        if not cls.gross_profit_line:
            # Fallback for different chart of accounts or languages
            # This makes the test more robust
            cls.gross_profit_line = cls.env['account.report.line'].search([
                ('report_id', '=', cls.profit_loss_report.id),
                ('code', '=', 'GROSS_PROFIT')
            ], limit=1)

    def test_create_and_get_kpi_value(self):
        """ Test creating a KPI and fetching its value. """
        self.assertTrue(self.gross_profit_line, "Test setup failed: Could not find Gross Profit report line.")

        # Create a KPI for the Gross Profit line for the default user
        kpi = self.env['financial.report.kpi'].create({
            'name': 'My Gross Profit KPI',
            'report_line_id': self.gross_profit_line.id,
        })

        self.assertEqual(kpi.user_id, self.env.user)

        # Create some accounting data to have a value
        receivable_account = self.company_data['default_account_receivable']
        sale_account = self.company_data['default_account_sale']
        self.env['account.move'].create({
            'move_type': 'out_invoice',
            'journal_id': self.company_data['default_journal_sale'].id,
            'partner_id': self.partner_a.id,
            'invoice_date': '2025-06-22',
            'date': '2025-06-22',
            'line_ids': [
                (0, 0, {
                    'name': 'product sale',
                    'quantity': 1,
                    'price_unit': 1000.0,
                    'account_id': sale_account.id,
                }),
                (0, 0, {
                    'name': 'receivable',
                    'quantity': 1,
                    'price_unit': -1000.0,
                    'account_id': receivable_account.id,
                    'exclude_from_invoice_tab': True,
                }),
            ],
        }).action_post()

        # Call the method to get KPI values
        kpi_values = kpi.get_kpi_values([kpi.id])

        self.assertIn(kpi.id, kpi_values)
        kpi_data = kpi_values[kpi.id]

        # Check the returned data structure
        self.assertEqual(kpi_data['name'], 'My Gross Profit KPI')
        self.assertEqual(kpi_data['report_id'], self.profit_loss_report.id)

        # Check the value. Gross Profit should be 1000.0 (as we have no cost of revenue)
        # Note: The formatted value depends on the currency, so we check the raw value.
        self.assertAlmostEqual(kpi_data['raw_value'], 1000.0)
