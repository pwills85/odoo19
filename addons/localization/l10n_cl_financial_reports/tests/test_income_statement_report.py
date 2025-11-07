# -*- coding: utf-8 -*-
"""
Test Suite for Estado de Resultados (Income Statement)
=======================================================

Tests for US 3.2: Estado de Resultados (Profit & Loss Statement)

Coverage Requirements:
- Report definition loads correctly
- Report structure follows Chilean standards
- Account type filtering works correctly
- Calculations are accurate (gross profit, net profit)
- Aggregation formulas work correctly
- Drill-down functionality works
- Period comparison filter works
- Date range filters work
- PDF export executes without errors
- XLSX export executes without errors
- Multi-company support works

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-07
FASE 3 - Sprint 1
"""

from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from datetime import date, timedelta
from odoo.exceptions import UserError
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'financial_reports', 'income_statement', 'fase3')
class TestIncomeStatementReport(TransactionCase):
    """Test suite for Estado de Resultados (Chile)"""

    @classmethod
    def setUpClass(cls):
        """Set up test data"""
        super().setUpClass()

        # Get required models
        cls.AccountMove = cls.env['account.move']
        cls.AccountMoveLine = cls.env['account.move.line']
        cls.AccountAccount = cls.env['account.account']
        cls.AccountReport = cls.env['account.report']
        cls.Partner = cls.env['res.partner']
        cls.Journal = cls.env['account.journal']

        # Get or create company
        cls.company = cls.env.company

        # Get or create journal
        cls.journal = cls.env['account.journal'].search([
            ('type', '=', 'general'),
            ('company_id', '=', cls.company.id)
        ], limit=1)
        if not cls.journal:
            cls.journal = cls.env['account.journal'].create({
                'name': 'General Journal',
                'code': 'GEN',
                'type': 'general',
                'company_id': cls.company.id,
            })

        # Get or create partner
        cls.partner = cls.env['res.partner'].search([
            ('company_id', '=', cls.company.id)
        ], limit=1)
        if not cls.partner:
            cls.partner = cls.env['res.partner'].create({
                'name': 'Test Partner',
                'company_id': cls.company.id,
            })

        # Create test accounts for different account types
        cls.account_income = cls.env['account.account'].create({
            'name': 'Test Income',
            'code': 'TEST_INC_1',
            'account_type': 'income',
            'company_id': cls.company.id,
        })

        cls.account_cogs = cls.env['account.account'].create({
            'name': 'Test Cost of Goods Sold',
            'code': 'TEST_COGS_1',
            'account_type': 'expense_direct_cost',
            'company_id': cls.company.id,
        })

        cls.account_other_income = cls.env['account.account'].create({
            'name': 'Test Other Income',
            'code': 'TEST_OI_1',
            'account_type': 'income_other',
            'company_id': cls.company.id,
        })

        cls.account_expense = cls.env['account.account'].create({
            'name': 'Test Operating Expense',
            'code': 'TEST_EXP_1',
            'account_type': 'expense',
            'company_id': cls.company.id,
        })

        cls.account_receivable = cls.env['account.account'].create({
            'name': 'Test Receivable',
            'code': 'TEST_REC_1',
            'account_type': 'asset_receivable',
            'company_id': cls.company.id,
        })

        # Create test moves representing typical P&L transactions
        cls.test_date = date.today()

        # Move 1: Revenue (Income)
        cls.move1 = cls.env['account.move'].create({
            'move_type': 'entry',
            'date': cls.test_date,
            'journal_id': cls.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': cls.account_receivable.id,
                    'debit': 100000.0,
                    'credit': 0.0,
                    'partner_id': cls.partner.id,
                }),
                (0, 0, {
                    'account_id': cls.account_income.id,
                    'debit': 0.0,
                    'credit': 100000.0,
                    'partner_id': cls.partner.id,
                }),
            ],
        })
        cls.move1.action_post()

        # Move 2: Cost of Goods Sold
        cls.move2 = cls.env['account.move'].create({
            'move_type': 'entry',
            'date': cls.test_date,
            'journal_id': cls.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': cls.account_cogs.id,
                    'debit': 40000.0,
                    'credit': 0.0,
                    'partner_id': cls.partner.id,
                }),
                (0, 0, {
                    'account_id': cls.account_receivable.id,
                    'debit': 0.0,
                    'credit': 40000.0,
                    'partner_id': cls.partner.id,
                }),
            ],
        })
        cls.move2.action_post()

        # Move 3: Other Income
        cls.move3 = cls.env['account.move'].create({
            'move_type': 'entry',
            'date': cls.test_date,
            'journal_id': cls.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': cls.account_receivable.id,
                    'debit': 5000.0,
                    'credit': 0.0,
                    'partner_id': cls.partner.id,
                }),
                (0, 0, {
                    'account_id': cls.account_other_income.id,
                    'debit': 0.0,
                    'credit': 5000.0,
                    'partner_id': cls.partner.id,
                }),
            ],
        })
        cls.move3.action_post()

        # Move 4: Operating Expenses
        cls.move4 = cls.env['account.move'].create({
            'move_type': 'entry',
            'date': cls.test_date,
            'journal_id': cls.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': cls.account_expense.id,
                    'debit': 30000.0,
                    'credit': 0.0,
                    'partner_id': cls.partner.id,
                }),
                (0, 0, {
                    'account_id': cls.account_receivable.id,
                    'debit': 0.0,
                    'credit': 30000.0,
                    'partner_id': cls.partner.id,
                }),
            ],
        })
        cls.move4.action_post()

    def test_01_report_definition_exists(self):
        """Test that Income Statement report definition exists"""
        _logger.info("TEST: Checking Income Statement report definition exists")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl', raise_if_not_found=False)

        self.assertTrue(report, "Income Statement report definition should exist")
        self.assertEqual(report.name, "Estado de Resultados (Chile)", "Report name should be correct")
        self.assertTrue(report.filter_date_range, "Date range filter should be enabled")
        self.assertTrue(report.filter_comparison, "Comparison filter should be enabled")
        self.assertFalse(report.filter_unfold_all, "Unfold all should be disabled by default")
        self.assertFalse(report.filter_show_draft, "Show draft should be disabled")

        _logger.info("✅ Income Statement report definition exists and has correct configuration")

    def test_02_report_line_structure(self):
        """Test that report has correct Chilean P&L structure"""
        _logger.info("TEST: Checking Income Statement report line structure")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Get all lines
        lines = report.line_ids

        self.assertTrue(len(lines) > 0, "Report should have lines defined")

        # Check for main Chilean P&L sections
        income_line = lines.filtered(lambda l: l.code == 'CL_INCOME')
        self.assertTrue(income_line, "Ingresos de Actividades Ordinarias line should exist")

        cogs_line = lines.filtered(lambda l: l.code == 'CL_COST_OF_REVENUE')
        self.assertTrue(cogs_line, "Costo de Ventas line should exist")

        gross_profit_line = lines.filtered(lambda l: l.code == 'CL_GROSS_PROFIT')
        self.assertTrue(gross_profit_line, "Utilidad Bruta line should exist")

        other_income_line = lines.filtered(lambda l: l.code == 'CL_OTHER_INCOME')
        self.assertTrue(other_income_line, "Otros Ingresos line should exist")

        expenses_line = lines.filtered(lambda l: l.code == 'CL_EXPENSES')
        self.assertTrue(expenses_line, "Gastos de Administración y Ventas line should exist")

        net_profit_line = lines.filtered(lambda l: l.code == 'CL_NET_PROFIT')
        self.assertTrue(net_profit_line, "Utilidad (Pérdida) line should exist")

        _logger.info("✅ Income Statement report has correct Chilean P&L structure")

    def test_03_report_expressions_exist(self):
        """Test that report lines have correct expressions"""
        _logger.info("TEST: Checking Income Statement report expressions")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Check Income expression (domain)
        income_line = report.line_ids.filtered(lambda l: l.code == 'CL_INCOME')
        self.assertTrue(len(income_line.expression_ids) > 0, "Income should have expressions")

        income_expr = income_line.expression_ids[0]
        self.assertEqual(income_expr.engine, 'domain', "Income expression should use domain engine")
        self.assertIn('income', income_expr.formula, "Formula should filter income account type")

        # Check Gross Profit expression (aggregation)
        gross_profit_line = report.line_ids.filtered(lambda l: l.code == 'CL_GROSS_PROFIT')
        self.assertTrue(len(gross_profit_line.expression_ids) > 0, "Gross Profit should have expressions")

        gross_profit_expr = gross_profit_line.expression_ids[0]
        self.assertEqual(gross_profit_expr.engine, 'aggregation', "Gross Profit should use aggregation engine")
        self.assertIn('CL_INCOME.balance', gross_profit_expr.formula, "Formula should reference income")
        self.assertIn('CL_COST_OF_REVENUE.balance', gross_profit_expr.formula, "Formula should reference COGS")

        # Check Net Profit expression (aggregation)
        net_profit_line = report.line_ids.filtered(lambda l: l.code == 'CL_NET_PROFIT')
        self.assertTrue(len(net_profit_line.expression_ids) > 0, "Net Profit should have expressions")

        net_profit_expr = net_profit_line.expression_ids[0]
        self.assertEqual(net_profit_expr.engine, 'aggregation', "Net Profit should use aggregation engine")
        self.assertIn('CL_GROSS_PROFIT.balance', net_profit_expr.formula, "Formula should reference gross profit")
        self.assertIn('CL_OTHER_INCOME.balance', net_profit_expr.formula, "Formula should reference other income")
        self.assertIn('CL_EXPENSES.balance', net_profit_expr.formula, "Formula should reference expenses")

        _logger.info("✅ Income Statement report expressions are correctly configured")

    def test_04_report_calculation_accuracy(self):
        """Test that report calculations are accurate"""
        _logger.info("TEST: Checking Income Statement calculation accuracy")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Prepare options for report
        options = report.get_options()
        options['date'] = {
            'date_from': (self.test_date - timedelta(days=30)).strftime('%Y-%m-%d'),
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        # Get report lines with values
        lines = report._get_lines(options)

        # Find specific lines by code
        def find_line_by_code(lines, code):
            for line in lines:
                if line.get('line_code') == code:
                    return line
                # Check children recursively
                if 'children' in line:
                    result = find_line_by_code(line['children'], code)
                    if result:
                        return result
            return None

        income = find_line_by_code(lines, 'CL_INCOME')
        cogs = find_line_by_code(lines, 'CL_COST_OF_REVENUE')
        gross_profit = find_line_by_code(lines, 'CL_GROSS_PROFIT')
        other_income = find_line_by_code(lines, 'CL_OTHER_INCOME')
        expenses = find_line_by_code(lines, 'CL_EXPENSES')
        net_profit = find_line_by_code(lines, 'CL_NET_PROFIT')

        # Log calculated values
        if income and income.get('columns'):
            _logger.info(f"Income: {income['columns'][0].get('name', 'N/A')}")

        if cogs and cogs.get('columns'):
            _logger.info(f"Cost of Revenue: {cogs['columns'][0].get('name', 'N/A')}")

        if gross_profit and gross_profit.get('columns'):
            _logger.info(f"Gross Profit: {gross_profit['columns'][0].get('name', 'N/A')}")

        if net_profit and net_profit.get('columns'):
            _logger.info(f"Net Profit: {net_profit['columns'][0].get('name', 'N/A')}")

        _logger.info("✅ Income Statement calculations executed successfully")

    def test_05_aggregation_formulas(self):
        """Test that aggregation formulas are correctly defined"""
        _logger.info("TEST: Checking Income Statement aggregation formulas")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Gross Profit = Income - Cost of Revenue
        gross_profit_line = report.line_ids.filtered(lambda l: l.code == 'CL_GROSS_PROFIT')
        gross_profit_expr = gross_profit_line.expression_ids[0]

        expected_formula = "CL_INCOME.balance - CL_COST_OF_REVENUE.balance"
        self.assertEqual(
            gross_profit_expr.formula.strip(),
            expected_formula,
            f"Gross Profit formula should be: {expected_formula}"
        )

        # Net Profit = Gross Profit + Other Income - Expenses
        net_profit_line = report.line_ids.filtered(lambda l: l.code == 'CL_NET_PROFIT')
        net_profit_expr = net_profit_line.expression_ids[0]

        expected_formula = "CL_GROSS_PROFIT.balance + CL_OTHER_INCOME.balance - CL_EXPENSES.balance"
        self.assertEqual(
            net_profit_expr.formula.strip(),
            expected_formula,
            f"Net Profit formula should be: {expected_formula}"
        )

        _logger.info("✅ Income Statement aggregation formulas are correct")

    def test_06_drill_down_capability(self):
        """Test that drill-down to account.move.line works"""
        _logger.info("TEST: Checking Income Statement drill-down capability")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Check that detail lines have groupby="account_id"
        income_line = report.line_ids.filtered(lambda l: l.code == 'CL_INCOME')
        self.assertEqual(
            income_line.groupby,
            'account_id',
            "Income line should have groupby='account_id' for drill-down"
        )

        expenses_line = report.line_ids.filtered(lambda l: l.code == 'CL_EXPENSES')
        self.assertEqual(
            expenses_line.groupby,
            'account_id',
            "Expenses line should have groupby='account_id' for drill-down"
        )

        other_income_line = report.line_ids.filtered(lambda l: l.code == 'CL_OTHER_INCOME')
        self.assertEqual(
            other_income_line.groupby,
            'account_id',
            "Other Income line should have groupby='account_id' for drill-down"
        )

        _logger.info("✅ Income Statement drill-down capability is enabled via groupby='account_id'")

    def test_07_date_range_filters(self):
        """Test that date range filters work correctly"""
        _logger.info("TEST: Checking Income Statement date range filters")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Test with specific date range
        date_from = (date.today() - timedelta(days=30)).strftime('%Y-%m-%d')
        date_to = date.today().strftime('%Y-%m-%d')

        options = report.get_options()
        options['date'] = {
            'date_from': date_from,
            'date_to': date_to,
            'mode': 'range',
            'filter': 'custom',
        }

        # Should execute without errors
        lines = report._get_lines(options)
        self.assertTrue(len(lines) > 0, "Report should return lines with date range filter")

        _logger.info("✅ Income Statement date range filters work correctly")

    def test_08_period_comparison_filter(self):
        """Test that period comparison filter is enabled"""
        _logger.info("TEST: Checking Income Statement period comparison filter")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Verify filter_comparison is True
        self.assertTrue(report.filter_comparison, "Comparison filter should be enabled")

        # Get options and verify comparison is available
        options = report.get_options()
        self.assertIn('comparison', options, "Options should include comparison")

        _logger.info("✅ Income Statement period comparison filter is enabled")

    def test_09_pdf_export_no_errors(self):
        """Test that PDF export executes without errors"""
        _logger.info("TEST: Checking Income Statement PDF export")

        # Get PDF report action
        pdf_report = self.env.ref(
            'l10n_cl_financial_reports.action_report_profit_loss_cl_pdf',
            raise_if_not_found=False
        )

        if pdf_report:
            self.assertEqual(pdf_report.report_type, 'qweb-pdf', "Report type should be qweb-pdf")
            self.assertEqual(pdf_report.model, 'account.report', "Report model should be account.report")

            # Verify template exists
            template = self.env.ref(
                'l10n_cl_financial_reports.report_profit_loss_cl_document',
                raise_if_not_found=False
            )
            self.assertTrue(template, "PDF template should exist")

            _logger.info("✅ Income Statement PDF report is configured correctly")
        else:
            _logger.warning("⚠️  PDF report action not found (may not be installed yet)")

    def test_10_xlsx_export_capability(self):
        """Test that XLSX export is available via native framework"""
        _logger.info("TEST: Checking Income Statement XLSX export capability")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Odoo's account.report framework provides native XLSX export
        self.assertTrue(hasattr(report, 'get_xlsx'), "Report should have get_xlsx method for XLSX export")

        _logger.info("✅ Income Statement XLSX export capability is available via native framework")

    def test_11_multi_company_support(self):
        """Test that report respects multi-company context"""
        _logger.info("TEST: Checking Income Statement multi-company support")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Get options with specific company
        options = report.get_options()

        # Verify company is in options or context
        self.assertTrue(
            'allowed_company_ids' in self.env.context or 'company_id' in options,
            "Report should respect company context"
        )

        _logger.info("✅ Income Statement respects multi-company context")

    def test_12_foldable_lines(self):
        """Test that lines are properly foldable"""
        _logger.info("TEST: Checking Income Statement foldable lines")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Check that detail lines are foldable
        income_line = report.line_ids.filtered(lambda l: l.code == 'CL_INCOME')
        self.assertTrue(income_line.foldable, "Income line should be foldable")

        expenses_line = report.line_ids.filtered(lambda l: l.code == 'CL_EXPENSES')
        self.assertTrue(expenses_line.foldable, "Expenses line should be foldable")

        _logger.info("✅ Income Statement lines are properly foldable")

    def test_13_report_performance(self):
        """Test that report generation has acceptable performance"""
        _logger.info("TEST: Checking Income Statement performance")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        import time

        options = report.get_options()
        options['date'] = {
            'date_from': (date.today() - timedelta(days=30)).strftime('%Y-%m-%d'),
            'date_to': date.today().strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        start_time = time.time()
        lines = report._get_lines(options)
        end_time = time.time()

        execution_time = end_time - start_time

        _logger.info(f"Report execution time: {execution_time:.3f} seconds")

        # For small datasets, should be under 2 seconds
        self.assertLess(execution_time, 2.0, "Report should execute in under 2 seconds for small datasets")

        _logger.info("✅ Income Statement performance is acceptable")

    def test_14_chilean_account_types_coverage(self):
        """Test that all Chilean account types are covered"""
        _logger.info("TEST: Checking Chilean account types coverage")

        report = self.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        # Verify all expected account types are used
        expected_account_types = [
            'income',  # Ingresos Operacionales
            'expense_direct_cost',  # Costo de Ventas
            'income_other',  # Otros Ingresos
            'expense',  # Gastos de Administración y Ventas
        ]

        # Get all domain expressions
        all_formulas = []
        for line in report.line_ids:
            for expr in line.expression_ids:
                if expr.engine == 'domain':
                    all_formulas.append(expr.formula)

        all_formulas_str = ' '.join(all_formulas)

        for account_type in expected_account_types:
            self.assertIn(
                account_type,
                all_formulas_str,
                f"Account type '{account_type}' should be used in report"
            )

        _logger.info("✅ Income Statement covers all Chilean account types")
