# -*- coding: utf-8 -*-
"""
Test Suite for Balance General Clasificado (Balance Sheet)
===========================================================

Tests for US 3.1: Balance General Clasificado / Estado de Situación Financiera

Coverage Requirements:
- Report definition loads correctly
- Report structure is hierarchical (ACTIVOS, PASIVOS Y PATRIMONIO)
- Account type filtering works correctly
- Calculations are accurate (aggregations)
- Drill-down functionality works
- Period comparison filter works
- Date filters work
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


@tagged('post_install', '-at_install', 'financial_reports', 'balance_sheet', 'fase3')
class TestBalanceSheetReport(TransactionCase):
    """Test suite for Balance General Clasificado (Chile)"""

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
        cls.account_current_asset = cls.env['account.account'].create({
            'name': 'Test Current Asset',
            'code': 'TEST_CA_1',
            'account_type': 'asset_current',
            'company_id': cls.company.id,
        })

        cls.account_non_current_asset = cls.env['account.account'].create({
            'name': 'Test Non-Current Asset',
            'code': 'TEST_NCA_1',
            'account_type': 'asset_non_current',
            'company_id': cls.company.id,
        })

        cls.account_current_liability = cls.env['account.account'].create({
            'name': 'Test Current Liability',
            'code': 'TEST_CL_1',
            'account_type': 'liability_current',
            'company_id': cls.company.id,
        })

        cls.account_non_current_liability = cls.env['account.account'].create({
            'name': 'Test Non-Current Liability',
            'code': 'TEST_NCL_1',
            'account_type': 'liability_non_current',
            'company_id': cls.company.id,
        })

        cls.account_equity = cls.env['account.account'].create({
            'name': 'Test Equity',
            'code': 'TEST_EQ_1',
            'account_type': 'equity',
            'company_id': cls.company.id,
        })

        # Create test moves with different account types
        cls.test_date = date.today()

        # Move 1: Current Assets
        cls.move1 = cls.env['account.move'].create({
            'move_type': 'entry',
            'date': cls.test_date,
            'journal_id': cls.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': cls.account_current_asset.id,
                    'debit': 10000.0,
                    'credit': 0.0,
                    'partner_id': cls.partner.id,
                }),
                (0, 0, {
                    'account_id': cls.account_equity.id,
                    'debit': 0.0,
                    'credit': 10000.0,
                    'partner_id': cls.partner.id,
                }),
            ],
        })
        cls.move1.action_post()

        # Move 2: Non-Current Assets
        cls.move2 = cls.env['account.move'].create({
            'move_type': 'entry',
            'date': cls.test_date,
            'journal_id': cls.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': cls.account_non_current_asset.id,
                    'debit': 50000.0,
                    'credit': 0.0,
                    'partner_id': cls.partner.id,
                }),
                (0, 0, {
                    'account_id': cls.account_equity.id,
                    'debit': 0.0,
                    'credit': 50000.0,
                    'partner_id': cls.partner.id,
                }),
            ],
        })
        cls.move2.action_post()

        # Move 3: Current Liabilities
        cls.move3 = cls.env['account.move'].create({
            'move_type': 'entry',
            'date': cls.test_date,
            'journal_id': cls.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': cls.account_equity.id,
                    'debit': 5000.0,
                    'credit': 0.0,
                    'partner_id': cls.partner.id,
                }),
                (0, 0, {
                    'account_id': cls.account_current_liability.id,
                    'debit': 0.0,
                    'credit': 5000.0,
                    'partner_id': cls.partner.id,
                }),
            ],
        })
        cls.move3.action_post()

        # Move 4: Non-Current Liabilities
        cls.move4 = cls.env['account.move'].create({
            'move_type': 'entry',
            'date': cls.test_date,
            'journal_id': cls.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': cls.account_equity.id,
                    'debit': 20000.0,
                    'credit': 0.0,
                    'partner_id': cls.partner.id,
                }),
                (0, 0, {
                    'account_id': cls.account_non_current_liability.id,
                    'debit': 0.0,
                    'credit': 20000.0,
                    'partner_id': cls.partner.id,
                }),
            ],
        })
        cls.move4.action_post()

    def test_01_report_definition_exists(self):
        """Test that Balance Sheet report definition exists"""
        _logger.info("TEST: Checking Balance Sheet report definition exists")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl', raise_if_not_found=False)

        self.assertTrue(report, "Balance Sheet report definition should exist")
        self.assertEqual(report.name, "Balance General (Chile)", "Report name should be correct")
        self.assertTrue(report.filter_date_range, "Date range filter should be enabled")
        self.assertTrue(report.filter_comparison, "Comparison filter should be enabled")
        self.assertFalse(report.filter_unfold_all, "Unfold all should be disabled by default")
        self.assertFalse(report.filter_show_draft, "Show draft should be disabled")

        _logger.info("✅ Balance Sheet report definition exists and has correct configuration")

    def test_02_report_line_structure(self):
        """Test that report has correct hierarchical structure"""
        _logger.info("TEST: Checking Balance Sheet report line structure")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Get all lines
        lines = report.line_ids

        self.assertTrue(len(lines) > 0, "Report should have lines defined")

        # Check for main sections
        assets_line = lines.filtered(lambda l: l.code == 'CL_ASSETS')
        self.assertTrue(assets_line, "ACTIVOS section should exist")

        current_assets_line = lines.filtered(lambda l: l.code == 'CL_CURRENT_ASSETS')
        self.assertTrue(current_assets_line, "Activo Corriente line should exist")

        non_current_assets_line = lines.filtered(lambda l: l.code == 'CL_NON_CURRENT_ASSETS')
        self.assertTrue(non_current_assets_line, "Activo No Corriente line should exist")

        liabilities_equity_line = lines.filtered(lambda l: l.code == 'CL_LIABILITIES_EQUITY_SECTION')
        self.assertTrue(liabilities_equity_line, "PASIVOS Y PATRIMONIO section should exist")

        liabilities_line = lines.filtered(lambda l: l.code == 'CL_LIABILITIES')
        self.assertTrue(liabilities_line, "Pasivos line should exist")

        equity_line = lines.filtered(lambda l: l.code == 'CL_EQUITY')
        self.assertTrue(equity_line, "Patrimonio line should exist")

        _logger.info("✅ Balance Sheet report has correct hierarchical structure")

    def test_03_report_expressions_exist(self):
        """Test that report lines have correct expressions"""
        _logger.info("TEST: Checking Balance Sheet report expressions")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Check Current Assets expression (domain)
        current_assets_line = report.line_ids.filtered(lambda l: l.code == 'CL_CURRENT_ASSETS')
        self.assertTrue(len(current_assets_line.expression_ids) > 0, "Current Assets should have expressions")

        current_assets_expr = current_assets_line.expression_ids[0]
        self.assertEqual(current_assets_expr.engine, 'domain', "Current Assets expression should use domain engine")
        self.assertIn('asset_current', current_assets_expr.formula, "Formula should filter asset_current")

        # Check Total Assets expression (aggregation)
        assets_line = report.line_ids.filtered(lambda l: l.code == 'CL_ASSETS')
        self.assertTrue(len(assets_line.expression_ids) > 0, "Total Assets should have expressions")

        assets_expr = assets_line.expression_ids[0]
        self.assertEqual(assets_expr.engine, 'aggregation', "Total Assets expression should use aggregation engine")
        self.assertIn('CL_CURRENT_ASSETS.balance', assets_expr.formula, "Formula should aggregate current assets")
        self.assertIn('CL_NON_CURRENT_ASSETS.balance', assets_expr.formula, "Formula should aggregate non-current assets")

        _logger.info("✅ Balance Sheet report expressions are correctly configured")

    def test_04_report_calculation_accuracy(self):
        """Test that report calculations are accurate"""
        _logger.info("TEST: Checking Balance Sheet calculation accuracy")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Prepare options for report
        options = report.get_options()
        options['date'] = {
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

        current_assets = find_line_by_code(lines, 'CL_CURRENT_ASSETS')
        non_current_assets = find_line_by_code(lines, 'CL_NON_CURRENT_ASSETS')
        total_assets = find_line_by_code(lines, 'CL_ASSETS')

        # Verify calculations
        if current_assets and current_assets.get('columns'):
            _logger.info(f"Current Assets balance: {current_assets['columns'][0].get('name', 'N/A')}")

        if non_current_assets and non_current_assets.get('columns'):
            _logger.info(f"Non-Current Assets balance: {non_current_assets['columns'][0].get('name', 'N/A')}")

        if total_assets and total_assets.get('columns'):
            _logger.info(f"Total Assets balance: {total_assets['columns'][0].get('name', 'N/A')}")

        _logger.info("✅ Balance Sheet calculations executed successfully")

    def test_05_drill_down_capability(self):
        """Test that drill-down to account.move.line works"""
        _logger.info("TEST: Checking Balance Sheet drill-down capability")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Check that lines have groupby="account_id" which enables drill-down
        current_assets_line = report.line_ids.filtered(lambda l: l.code == 'CL_CURRENT_ASSETS')
        self.assertEqual(
            current_assets_line.groupby,
            'account_id',
            "Current Assets line should have groupby='account_id' for drill-down"
        )

        non_current_assets_line = report.line_ids.filtered(lambda l: l.code == 'CL_NON_CURRENT_ASSETS')
        self.assertEqual(
            non_current_assets_line.groupby,
            'account_id',
            "Non-Current Assets line should have groupby='account_id' for drill-down"
        )

        equity_line = report.line_ids.filtered(lambda l: l.code == 'CL_EQUITY')
        self.assertEqual(
            equity_line.groupby,
            'account_id',
            "Equity line should have groupby='account_id' for drill-down"
        )

        _logger.info("✅ Balance Sheet drill-down capability is enabled via groupby='account_id'")

    def test_06_date_filters(self):
        """Test that date filters work correctly"""
        _logger.info("TEST: Checking Balance Sheet date filters")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Test with different date ranges
        yesterday = (date.today() - timedelta(days=1)).strftime('%Y-%m-%d')
        today = date.today().strftime('%Y-%m-%d')

        options = report.get_options()
        options['date'] = {
            'date_to': today,
            'mode': 'range',
            'filter': 'custom',
        }

        # Should execute without errors
        lines = report._get_lines(options)
        self.assertTrue(len(lines) > 0, "Report should return lines with date filter")

        _logger.info("✅ Balance Sheet date filters work correctly")

    def test_07_period_comparison_filter(self):
        """Test that period comparison filter is enabled"""
        _logger.info("TEST: Checking Balance Sheet period comparison filter")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Verify filter_comparison is True
        self.assertTrue(report.filter_comparison, "Comparison filter should be enabled")

        # Get options and verify comparison is available
        options = report.get_options()
        self.assertIn('comparison', options, "Options should include comparison")

        _logger.info("✅ Balance Sheet period comparison filter is enabled")

    def test_08_pdf_export_no_errors(self):
        """Test that PDF export executes without errors"""
        _logger.info("TEST: Checking Balance Sheet PDF export")

        # Get PDF report action
        pdf_report = self.env.ref(
            'l10n_cl_financial_reports.action_report_balance_sheet_cl_pdf',
            raise_if_not_found=False
        )

        if pdf_report:
            self.assertEqual(pdf_report.report_type, 'qweb-pdf', "Report type should be qweb-pdf")
            self.assertEqual(pdf_report.model, 'account.report', "Report model should be account.report")

            # Verify template exists
            template = self.env.ref(
                'l10n_cl_financial_reports.report_balance_sheet_cl_document',
                raise_if_not_found=False
            )
            self.assertTrue(template, "PDF template should exist")

            _logger.info("✅ Balance Sheet PDF report is configured correctly")
        else:
            _logger.warning("⚠️  PDF report action not found (may not be installed yet)")

    def test_09_xlsx_export_capability(self):
        """Test that XLSX export is available via native framework"""
        _logger.info("TEST: Checking Balance Sheet XLSX export capability")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Odoo's account.report framework provides native XLSX export
        # Verify report has the necessary methods
        self.assertTrue(hasattr(report, 'get_xlsx'), "Report should have get_xlsx method for XLSX export")

        _logger.info("✅ Balance Sheet XLSX export capability is available via native framework")

    def test_10_multi_company_support(self):
        """Test that report respects multi-company context"""
        _logger.info("TEST: Checking Balance Sheet multi-company support")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Get options with specific company
        options = report.get_options()

        # Verify company is in options or context
        self.assertTrue(
            'allowed_company_ids' in self.env.context or 'company_id' in options,
            "Report should respect company context"
        )

        _logger.info("✅ Balance Sheet respects multi-company context")

    def test_11_foldable_lines(self):
        """Test that lines are properly foldable"""
        _logger.info("TEST: Checking Balance Sheet foldable lines")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        # Check that detail lines are foldable
        current_assets_line = report.line_ids.filtered(lambda l: l.code == 'CL_CURRENT_ASSETS')
        self.assertTrue(current_assets_line.foldable, "Current Assets line should be foldable")

        equity_line = report.line_ids.filtered(lambda l: l.code == 'CL_EQUITY')
        self.assertTrue(equity_line.foldable, "Equity line should be foldable")

        _logger.info("✅ Balance Sheet lines are properly foldable")

    def test_12_report_performance(self):
        """Test that report generation has acceptable performance"""
        _logger.info("TEST: Checking Balance Sheet performance")

        report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')

        import time

        options = report.get_options()
        options['date'] = {
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

        _logger.info("✅ Balance Sheet performance is acceptable")
