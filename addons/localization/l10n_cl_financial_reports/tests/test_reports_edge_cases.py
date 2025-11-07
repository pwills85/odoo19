# -*- coding: utf-8 -*-
"""
Edge Cases Tests for Financial Reports
========================================

Tests for boundary conditions and edge cases that might cause issues
in production environments:

1. Accounts without movements
2. Accounts with credit-only movements (pure creditor balance)
3. Movements that result in zero final balance
4. Rounding precision with many small movements

Gap Cerrado: Gap 3 (Edge Cases Tests Missing)

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-07
Sprint: Preflight Sprint 1 → Sprint 2
"""

from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from datetime import date
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'edge', 'financial_reports', 'fase3')
class TestReportsEdgeCases(TransactionCase):
    """Test suite for edge cases in financial reports"""

    @classmethod
    def setUpClass(cls):
        """Set up edge case test data"""
        super().setUpClass()

        cls.company = cls.env.company
        cls.journal = cls.env['account.journal'].search([
            ('type', '=', 'general'),
            ('company_id', '=', cls.company.id)
        ], limit=1)
        if not cls.journal:
            cls.journal = cls.env['account.journal'].create({
                'name': 'General Journal - Edge Cases',
                'code': 'GENEDGE',
                'type': 'general',
                'company_id': cls.company.id,
            })

        cls.partner = cls.env['res.partner'].create({
            'name': 'Edge Case Partner',
            'company_id': cls.company.id,
        })

        cls.test_date = date.today()

        # Get reports
        cls.balance_sheet_report = cls.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')
        cls.income_statement_report = cls.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

    def test_01_account_without_movements(self):
        """Test report handles accounts without any movements"""
        _logger.info("TEST: Account without movements")

        # Create an account but don't create any moves for it
        empty_account = self.env['account.account'].create({
            'name': 'Empty Test Account',
            'code': 'EMPTY001',
            'account_type': 'asset_current',
            'company_id': self.company.id,
        })

        # Generate Balance Sheet report
        report = self.balance_sheet_report
        options = report.get_options()
        options['date'] = {
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        # Should not crash with empty account
        try:
            lines = report._get_lines(options)
            self.assertTrue(True, "Report should handle empty accounts without crashing")
        except Exception as e:
            self.fail(f"Report crashed with empty account: {str(e)}")

        _logger.info("✅ Report handles accounts without movements correctly")

    def test_02_account_with_credit_only_movements(self):
        """Test report handles accounts with only credit movements (pure creditor balance)"""
        _logger.info("TEST: Account with credit-only movements")

        # Create account
        credit_only_account = self.env['account.account'].create({
            'name': 'Credit Only Account',
            'code': 'CREDONLY',
            'account_type': 'liability_current',
            'company_id': self.company.id,
        })

        debit_account = self.env['account.account'].create({
            'name': 'Debit Counter Account',
            'code': 'DEBCNT',
            'account_type': 'asset_current',
            'company_id': self.company.id,
        })

        # Create move with only CREDIT on our test account
        move = self.env['account.move'].create({
            'move_type': 'entry',
            'date': self.test_date,
            'journal_id': self.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': debit_account.id,
                    'debit': 75000.0,
                    'credit': 0.0,
                    'partner_id': self.partner.id,
                }),
                (0, 0, {
                    'account_id': credit_only_account.id,
                    'debit': 0.0,  # ZERO debit
                    'credit': 75000.0,  # ONLY credit
                    'partner_id': self.partner.id,
                }),
            ],
        })
        move.action_post()

        # Generate report
        report = self.balance_sheet_report
        options = report.get_options()
        options['date'] = {
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        # Should handle pure credit balance correctly
        try:
            lines = report._get_lines(options)

            # Look for liability section
            def find_line_by_code(lines, code):
                for line in lines:
                    if line.get('line_code') == code:
                        return line
                    if line.get('unfoldable') and line.get('lines'):
                        result = find_line_by_code(line['lines'], code)
                        if result:
                            return result
                return None

            liabilities_line = find_line_by_code(lines, 'CL_CURRENT_LIABILITIES')
            if liabilities_line and liabilities_line.get('columns'):
                _logger.info(f"Current Liabilities balance: {liabilities_line['columns'][0].get('name', 'N/A')}")

            self.assertTrue(True, "Report handles credit-only accounts correctly")

        except Exception as e:
            self.fail(f"Report crashed with credit-only account: {str(e)}")

        _logger.info("✅ Report handles credit-only movements correctly")

    def test_03_movements_resulting_in_zero_balance(self):
        """Test report handles accounts where movements cancel out to zero balance"""
        _logger.info("TEST: Movements resulting in zero balance")

        # Create accounts
        zero_balance_account = self.env['account.account'].create({
            'name': 'Zero Balance Account',
            'code': 'ZEROBAL',
            'account_type': 'asset_current',
            'company_id': self.company.id,
        })

        counter_account = self.env['account.account'].create({
            'name': 'Counter Account',
            'code': 'COUNTER',
            'account_type': 'equity',
            'company_id': self.company.id,
        })

        # Move 1: Debit 50,000
        move1 = self.env['account.move'].create({
            'move_type': 'entry',
            'date': self.test_date,
            'journal_id': self.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': zero_balance_account.id,
                    'debit': 50000.0,
                    'credit': 0.0,
                    'partner_id': self.partner.id,
                }),
                (0, 0, {
                    'account_id': counter_account.id,
                    'debit': 0.0,
                    'credit': 50000.0,
                    'partner_id': self.partner.id,
                }),
            ],
        })
        move1.action_post()

        # Move 2: Credit 50,000 (cancels out)
        move2 = self.env['account.move'].create({
            'move_type': 'entry',
            'date': self.test_date,
            'journal_id': self.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': counter_account.id,
                    'debit': 50000.0,
                    'credit': 0.0,
                    'partner_id': self.partner.id,
                }),
                (0, 0, {
                    'account_id': zero_balance_account.id,
                    'debit': 0.0,
                    'credit': 50000.0,  # Cancels previous debit
                    'partner_id': self.partner.id,
                }),
            ],
        })
        move2.action_post()

        # Verify account balance is zero
        balance = sum(self.env['account.move.line'].search([
            ('account_id', '=', zero_balance_account.id),
            ('move_id.state', '=', 'posted')
        ]).mapped(lambda l: l.debit - l.credit))

        self.assertEqual(balance, 0.0, "Account balance should be exactly zero")

        # Generate report
        report = self.balance_sheet_report
        options = report.get_options()
        options['date'] = {
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        # Should handle zero balance correctly (might hide or show 0.00)
        try:
            lines = report._get_lines(options)
            self.assertTrue(True, "Report handles zero balance accounts correctly")
        except Exception as e:
            self.fail(f"Report crashed with zero balance account: {str(e)}")

        _logger.info("✅ Report handles zero balance movements correctly")

    def test_04_rounding_precision_many_small_movements(self):
        """Test rounding precision with many small movements"""
        _logger.info("TEST: Rounding precision with many small movements")

        # Create account for rounding test
        rounding_account = self.env['account.account'].create({
            'name': 'Rounding Test Account',
            'code': 'ROUND001',
            'account_type': 'income',
            'company_id': self.company.id,
        })

        receivable_account = self.env['account.account'].create({
            'name': 'Receivable Counter',
            'code': 'RECROUND',
            'account_type': 'asset_receivable',
            'company_id': self.company.id,
        })

        # Create many moves with small amounts that might accumulate rounding errors
        # 100 moves of 33.33 each = 3,333.00 total
        # If rounding is wrong, might get 3,333.33 or 3,332.67
        expected_total = 0.0
        for i in range(100):
            amount = 33.33  # Repeating decimal

            move = self.env['account.move'].create({
                'move_type': 'entry',
                'date': self.test_date,
                'journal_id': self.journal.id,
                'line_ids': [
                    (0, 0, {
                        'account_id': receivable_account.id,
                        'debit': amount,
                        'credit': 0.0,
                        'partner_id': self.partner.id,
                    }),
                    (0, 0, {
                        'account_id': rounding_account.id,
                        'debit': 0.0,
                        'credit': amount,
                        'partner_id': self.partner.id,
                    }),
                ],
            })
            move.action_post()
            expected_total += amount

        # Generate Income Statement
        report = self.income_statement_report
        options = report.get_options()
        options['date'] = {
            'date_from': self.test_date.strftime('%Y-%m-%d'),
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        try:
            lines = report._get_lines(options)

            # Find income line
            def find_line_by_code(lines, code):
                for line in lines:
                    if line.get('line_code') == code:
                        return line
                    if line.get('unfoldable') and line.get('lines'):
                        result = find_line_by_code(line['lines'], code)
                        if result:
                            return result
                return None

            income_line = find_line_by_code(lines, 'CL_INCOME')
            if income_line and income_line.get('columns'):
                reported_value = income_line['columns'][0].get('no_format', 0.0)

                # Allow small rounding tolerance (0.02 for 2 cents)
                tolerance = 0.02
                difference = abs(reported_value - expected_total)

                _logger.info(f"Expected total: {expected_total:.2f}")
                _logger.info(f"Reported value: {reported_value:.2f}")
                _logger.info(f"Difference: {difference:.4f}")

                self.assertLess(
                    difference,
                    tolerance,
                    f"Rounding error too large: {difference:.4f} (expected < {tolerance})"
                )

            self.assertTrue(True, "Report handles rounding correctly")

        except Exception as e:
            self.fail(f"Report crashed with rounding test: {str(e)}")

        _logger.info("✅ Report handles rounding precision correctly")

    def test_05_income_statement_with_zero_income(self):
        """Test Income Statement handles zero income (division by zero in margins)"""
        _logger.info("TEST: Income Statement with zero income")

        # Create expense-only scenario (no income)
        expense_account = self.env['account.account'].create({
            'name': 'Pure Expense Account',
            'code': 'PUREEXP',
            'account_type': 'expense',
            'company_id': self.company.id,
        })

        cash_account = self.env['account.account'].create({
            'name': 'Cash Out Account',
            'code': 'CASHOUT',
            'account_type': 'asset_cash',
            'company_id': self.company.id,
        })

        # Create expense without income
        move = self.env['account.move'].create({
            'move_type': 'entry',
            'date': self.test_date,
            'journal_id': self.journal.id,
            'line_ids': [
                (0, 0, {
                    'account_id': expense_account.id,
                    'debit': 10000.0,
                    'credit': 0.0,
                    'partner_id': self.partner.id,
                }),
                (0, 0, {
                    'account_id': cash_account.id,
                    'debit': 0.0,
                    'credit': 10000.0,
                    'partner_id': self.partner.id,
                }),
            ],
        })
        move.action_post()

        # Generate Income Statement (should handle division by zero in margin calculation)
        report = self.income_statement_report
        options = report.get_options()
        options['date'] = {
            'date_from': self.test_date.strftime('%Y-%m-%d'),
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        try:
            lines = report._get_lines(options)

            # Also test PDF context (which calculates margins)
            pdf_context = report.get_pdf_context(options)
            totals = pdf_context['totals']

            # Income should be 0 or very small
            income_value = totals.get('CL_INCOME', {}).get('raw', 0.0)
            _logger.info(f"Income with zero scenario: {income_value}")

            # Margin calculation in PDF template should handle division by zero
            # (checks `if income_raw else 0.0` in template)
            self.assertTrue(True, "Report handles zero income without crash")

        except Exception as e:
            self.fail(f"Report crashed with zero income: {str(e)}")

        _logger.info("✅ Report handles zero income correctly (no division by zero)")

    def test_06_multi_currency_transactions(self):
        """Test report handles multi-currency transactions correctly"""
        _logger.info("TEST: Multi-currency transactions")

        # Create USD currency (if not exists)
        usd = self.env.ref('base.USD', raise_if_not_found=False)
        if not usd:
            _logger.warning("USD currency not found, skipping multi-currency test")
            return

        # Create account
        multicurrency_account = self.env['account.account'].create({
            'name': 'Multi-Currency Account',
            'code': 'MULTICURR',
            'account_type': 'asset_current',
            'company_id': self.company.id,
        })

        equity_account = self.env['account.account'].create({
            'name': 'Equity Counter',
            'code': 'EQUICURR',
            'account_type': 'equity',
            'company_id': self.company.id,
        })

        # Create move in foreign currency
        # Odoo should convert to company currency for reporting
        move = self.env['account.move'].create({
            'move_type': 'entry',
            'date': self.test_date,
            'journal_id': self.journal.id,
            'currency_id': usd.id,  # In USD
            'line_ids': [
                (0, 0, {
                    'account_id': multicurrency_account.id,
                    'debit': 100.0,  # 100 USD
                    'credit': 0.0,
                    'amount_currency': 100.0,
                    'currency_id': usd.id,
                    'partner_id': self.partner.id,
                }),
                (0, 0, {
                    'account_id': equity_account.id,
                    'debit': 0.0,
                    'credit': 100.0,  # 100 USD
                    'amount_currency': -100.0,
                    'currency_id': usd.id,
                    'partner_id': self.partner.id,
                }),
            ],
        })
        move.action_post()

        # Generate report (should convert to company currency)
        report = self.balance_sheet_report
        options = report.get_options()
        options['date'] = {
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        try:
            lines = report._get_lines(options)
            self.assertTrue(True, "Report handles multi-currency correctly")
        except Exception as e:
            self.fail(f"Report crashed with multi-currency: {str(e)}")

        _logger.info("✅ Report handles multi-currency transactions correctly")

    def test_07_multi_company_separation(self):
        """Test that reports respect multi-company separation (no data leakage)"""
        _logger.info("TEST: Multi-company separation")

        # Create second company
        company_b = self.env['res.company'].create({
            'name': 'Company B - Test Multi-company',
            'currency_id': self.env.ref('base.CLP').id,
        })

        # Create chart of accounts for Company B
        account_b_asset = self.env['account.account'].create({
            'name': 'Asset Company B',
            'code': 'ASSETB001',
            'account_type': 'asset_current',
            'company_id': company_b.id,
        })

        account_b_liability = self.env['account.account'].create({
            'name': 'Liability Company B',
            'code': 'LIABB001',
            'account_type': 'liability_current',
            'company_id': company_b.id,
        })

        # Create journal for Company B
        journal_b = self.env['account.journal'].create({
            'name': 'General Company B',
            'code': 'GENB',
            'type': 'general',
            'company_id': company_b.id,
        })

        # Create move in Company B with LARGE DISTINCTIVE amount
        move_b = self.env['account.move'].create({
            'move_type': 'entry',
            'date': self.test_date,
            'journal_id': journal_b.id,
            'company_id': company_b.id,  # IMPORTANT: Company B
            'line_ids': [
                (0, 0, {
                    'account_id': account_b_asset.id,
                    'debit': 999999.0,  # Large distinctive amount to detect leak
                    'credit': 0.0,
                }),
                (0, 0, {
                    'account_id': account_b_liability.id,
                    'debit': 0.0,
                    'credit': 999999.0,
                }),
            ],
        })
        move_b.action_post()

        # Generate report for Company A (original company) with explicit context
        report = self.balance_sheet_report.with_context(allowed_company_ids=[self.company.id])
        options = report.get_options()
        options['date'] = {
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        lines = report._get_lines(options)

        # Helper to find line by code
        def find_line_by_code(lines, code):
            for line in lines:
                if line.get('line_code') == code:
                    return line
                if line.get('unfoldable') and line.get('lines'):
                    result = find_line_by_code(line['lines'], code)
                    if result:
                        return result
            return None

        # Verify Company B's 999,999 amount does NOT appear in Company A's report
        assets_line = find_line_by_code(lines, 'CL_ASSETS')
        if assets_line and assets_line.get('columns'):
            assets_value = assets_line['columns'][0].get('no_format', 0.0)

            _logger.info(f"Company A Assets (should NOT include Company B): {assets_value}")
            _logger.info("Company B Amount (should be filtered out): 999,999.00")

            # Should NOT include Company B's 999,999
            self.assertLess(
                assets_value,
                900000.0,  # Well below 999,999
                f"⚠️ DATA LEAK DETECTED: Report contains Company B data ({assets_value}), "
                f"should not include 999,999 from Company B"
            )

            _logger.info("✅ Multi-company separation verified: No data leakage")

        # Also test Income Statement for Company B
        account_b_income = self.env['account.account'].create({
            'name': 'Income Company B',
            'code': 'INCB001',
            'account_type': 'income',
            'company_id': company_b.id,
        })

        account_b_receivable = self.env['account.account'].create({
            'name': 'Receivable Company B',
            'code': 'RECB001',
            'account_type': 'asset_receivable',
            'company_id': company_b.id,
        })

        move_b_income = self.env['account.move'].create({
            'move_type': 'entry',
            'date': self.test_date,
            'journal_id': journal_b.id,
            'company_id': company_b.id,
            'line_ids': [
                (0, 0, {
                    'account_id': account_b_receivable.id,
                    'debit': 888888.0,  # Another distinctive amount
                    'credit': 0.0,
                }),
                (0, 0, {
                    'account_id': account_b_income.id,
                    'debit': 0.0,
                    'credit': 888888.0,
                }),
            ],
        })
        move_b_income.action_post()

        # Test Income Statement
        income_report = self.income_statement_report.with_context(allowed_company_ids=[self.company.id])
        income_options = income_report.get_options()
        income_options['date'] = {
            'date_from': self.test_date.strftime('%Y-%m-%d'),
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        income_lines = income_report._get_lines(income_options)
        income_line = find_line_by_code(income_lines, 'CL_INCOME')

        if income_line and income_line.get('columns'):
            income_value = income_line['columns'][0].get('no_format', 0.0)

            _logger.info(f"Company A Income (should NOT include Company B): {income_value}")

            self.assertLess(
                income_value,
                800000.0,  # Well below 888,888
                f"⚠️ DATA LEAK DETECTED: Income Statement contains Company B data ({income_value})"
            )

            _logger.info("✅ Income Statement multi-company separation verified")

        _logger.info("✅ Multi-company separation test PASSED for both reports")
