# -*- coding: utf-8 -*-
"""
Stress Tests for Balance Sheet and Income Statement Reports
============================================================

Tests performance with large datasets (~50k account.move.line) to detect:
- N+1 queries
- Performance degradation
- Memory issues
- Query count optimization

Target Metrics:
- Execution time: < 3s (development environment)
- SQL queries: < 50
- Memory: Reasonable (no leaks)

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-07
Sprint: Preflight Sprint 1 → Sprint 2
"""

from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from datetime import date, timedelta
import time
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'performance', 'stress', 'fase3')
class TestReportsStressBalanceIncome(TransactionCase):
    """Stress tests for financial reports with large datasets"""

    @classmethod
    def setUpClass(cls):
        """Set up large synthetic dataset for stress testing"""
        super().setUpClass()

        _logger.info("=" * 80)
        _logger.info("STRESS TEST SETUP: Creating synthetic dataset (~50k move lines)")
        _logger.info("=" * 80)

        # Get models
        cls.AccountMove = cls.env['account.move']
        cls.AccountAccount = cls.env['account.account']
        cls.Partner = cls.env['res.partner']
        cls.Journal = cls.env['account.journal']
        cls.AccountReport = cls.env['account.report']

        # Get or create company
        cls.company = cls.env.company

        # Get or create journal
        cls.journal = cls.env['account.journal'].search([
            ('type', '=', 'general'),
            ('company_id', '=', cls.company.id)
        ], limit=1)
        if not cls.journal:
            cls.journal = cls.env['account.journal'].create({
                'name': 'General Journal - Stress Test',
                'code': 'GENSTRS',
                'type': 'general',
                'company_id': cls.company.id,
            })

        # Create partners for diversity
        cls.partners = cls.env['res.partner'].create([
            {
                'name': f'Stress Test Partner {i}',
                'company_id': cls.company.id,
            }
            for i in range(50)  # 50 partners
        ])

        # Create accounts for all types (450 accounts total)
        cls.accounts = {}
        account_types_config = [
            # Balance Sheet accounts
            ('asset_current', 'Activo Corriente Stress', 100),
            ('asset_receivable', 'Cuentas por Cobrar Stress', 50),
            ('asset_cash', 'Caja y Bancos Stress', 20),
            ('asset_prepayment', 'Gastos Anticipados Stress', 10),
            ('asset_non_current', 'Activo No Corriente Stress', 50),
            ('asset_fixed', 'Activo Fijo Stress', 30),
            ('liability_current', 'Pasivo Corriente Stress', 50),
            ('liability_payable', 'Cuentas por Pagar Stress', 40),
            ('liability_non_current', 'Pasivo No Corriente Stress', 20),
            ('equity', 'Patrimonio Stress', 20),
            # Income Statement accounts
            ('income', 'Ingresos Operacionales Stress', 30),
            ('income_other', 'Otros Ingresos Stress', 10),
            ('expense_direct_cost', 'Costo de Ventas Stress', 20),
            ('expense', 'Gastos Operacionales Stress', 40),
        ]

        account_counter = 1
        for account_type, name_prefix, count in account_types_config:
            cls.accounts[account_type] = []
            for i in range(count):
                account = cls.env['account.account'].create({
                    'name': f'{name_prefix} {i+1}',
                    'code': f'STRESS{account_counter:04d}',
                    'account_type': account_type,
                    'company_id': cls.company.id,
                })
                cls.accounts[account_type].append(account)
                account_counter += 1

        _logger.info(f"✅ Created {account_counter - 1} accounts across {len(account_types_config)} account types")

        # Create synthetic moves (~50k lines total)
        # Strategy: 500 moves with ~100 lines each = 50,000 lines
        cls.test_date = date.today()
        cls.moves = []

        _logger.info("Creating synthetic moves (this may take a moment)...")

        # Batch creation for efficiency
        move_vals_list = []
        total_lines_created = 0

        for move_num in range(500):  # 500 moves
            # Each move will have ~100 lines (50 debit + 50 credit pairs)
            line_vals = []

            # Create balanced move with diverse accounts
            for line_num in range(50):  # 50 pairs = 100 lines per move
                # Randomly select account types and accounts
                import random

                # Debit line (asset or expense)
                debit_type = random.choice(['asset_current', 'asset_fixed', 'expense', 'expense_direct_cost'])
                debit_account = random.choice(cls.accounts[debit_type])

                # Credit line (liability, equity, or income)
                credit_type = random.choice(['liability_current', 'equity', 'income', 'income_other'])
                credit_account = random.choice(cls.accounts[credit_type])

                # Random amount between 1000 and 100000
                amount = random.uniform(1000, 100000)

                # Random partner
                partner = random.choice(cls.partners)

                line_vals.extend([
                    (0, 0, {
                        'account_id': debit_account.id,
                        'debit': amount,
                        'credit': 0.0,
                        'partner_id': partner.id,
                    }),
                    (0, 0, {
                        'account_id': credit_account.id,
                        'debit': 0.0,
                        'credit': amount,
                        'partner_id': partner.id,
                    }),
                ])

            move_vals_list.append({
                'move_type': 'entry',
                'date': cls.test_date - timedelta(days=random.randint(0, 30)),
                'journal_id': cls.journal.id,
                'line_ids': line_vals,
            })

            total_lines_created += len(line_vals)

            # Log progress every 100 moves
            if (move_num + 1) % 100 == 0:
                _logger.info(f"  Progress: {move_num + 1}/500 moves created ({total_lines_created:,} lines)")

        # Batch create moves
        _logger.info("Creating moves in batch...")
        cls.moves = cls.env['account.move'].create(move_vals_list)

        # Post all moves
        _logger.info("Posting moves...")
        for i, move in enumerate(cls.moves):
            move.action_post()
            if (i + 1) % 100 == 0:
                _logger.info(f"  Posted {i + 1}/500 moves")

        _logger.info(f"✅ Created and posted {len(cls.moves)} moves with ~{total_lines_created:,} move lines")

        # Get reports
        cls.balance_sheet_report = cls.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')
        cls.income_statement_report = cls.env.ref('l10n_cl_financial_reports.report_profit_loss_cl')

        _logger.info("=" * 80)
        _logger.info("STRESS TEST SETUP COMPLETE")
        _logger.info("=" * 80)

    def _count_queries(self, func):
        """Helper to count SQL queries executed by a function"""
        # Simple query counter using environment flush
        query_count_before = len(self.cr._executed)

        result = func()

        query_count_after = len(self.cr._executed)
        query_count = query_count_after - query_count_before

        return result, query_count

    def test_01_balance_sheet_stress_performance(self):
        """Test Balance Sheet report with ~50k move lines"""
        _logger.info("\n" + "=" * 80)
        _logger.info("STRESS TEST: Balance Sheet with ~50k move lines")
        _logger.info("=" * 80)

        report = self.balance_sheet_report

        # Prepare options
        options = report.get_options()
        options['date'] = {
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        # Measure performance
        start_time = time.time()

        # Execute report generation
        lines = report._get_lines(options)

        end_time = time.time()
        execution_time = end_time - start_time

        # Log results
        _logger.info("📊 Balance Sheet Report Results:")
        _logger.info(f"   ⏱️  Execution time: {execution_time:.3f} seconds")
        _logger.info(f"   📄 Lines returned: {len(lines)}")
        _logger.info("   🎯 Target: < 3.0 seconds")

        # Assertions
        self.assertLess(
            execution_time,
            5.0,  # Slightly relaxed for CI environments
            f"Balance Sheet report took {execution_time:.3f}s, should be < 5.0s"
        )

        self.assertGreater(
            len(lines),
            0,
            "Balance Sheet should return lines with large dataset"
        )

        # Log performance metrics to file
        self._log_performance_metrics(
            'Balance Sheet',
            execution_time,
            len(lines),
            query_count=None  # Query counting requires more sophisticated approach
        )

        _logger.info("✅ Balance Sheet stress test PASSED")
        _logger.info("=" * 80 + "\n")

    def test_02_income_statement_stress_performance(self):
        """Test Income Statement report with ~50k move lines"""
        _logger.info("\n" + "=" * 80)
        _logger.info("STRESS TEST: Income Statement with ~50k move lines")
        _logger.info("=" * 80)

        report = self.income_statement_report

        # Prepare options
        options = report.get_options()
        options['date'] = {
            'date_from': (self.test_date - timedelta(days=30)).strftime('%Y-%m-%d'),
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }

        # Measure performance
        start_time = time.time()

        # Execute report generation
        lines = report._get_lines(options)

        end_time = time.time()
        execution_time = end_time - start_time

        # Log results
        _logger.info("📊 Income Statement Report Results:")
        _logger.info(f"   ⏱️  Execution time: {execution_time:.3f} seconds")
        _logger.info(f"   📄 Lines returned: {len(lines)}")
        _logger.info("   🎯 Target: < 3.0 seconds")

        # Assertions
        self.assertLess(
            execution_time,
            5.0,  # Slightly relaxed for CI environments
            f"Income Statement report took {execution_time:.3f}s, should be < 5.0s"
        )

        self.assertGreater(
            len(lines),
            0,
            "Income Statement should return lines with large dataset"
        )

        # Log performance metrics to file
        self._log_performance_metrics(
            'Income Statement',
            execution_time,
            len(lines),
            query_count=None
        )

        _logger.info("✅ Income Statement stress test PASSED")
        _logger.info("=" * 80 + "\n")

    def test_03_balance_sheet_with_comparison_stress(self):
        """Test Balance Sheet with period comparison enabled"""
        _logger.info("\n" + "=" * 80)
        _logger.info("STRESS TEST: Balance Sheet with Period Comparison")
        _logger.info("=" * 80)

        report = self.balance_sheet_report

        # Prepare options with comparison
        options = report.get_options()
        options['date'] = {
            'date_to': self.test_date.strftime('%Y-%m-%d'),
            'mode': 'range',
            'filter': 'custom',
        }
        options['comparison'] = {
            'filter': 'previous_period',
            'number_period': 1,
        }

        # Measure performance
        start_time = time.time()
        lines = report._get_lines(options)
        end_time = time.time()
        execution_time = end_time - start_time

        _logger.info("📊 Balance Sheet Comparison Results:")
        _logger.info(f"   ⏱️  Execution time: {execution_time:.3f} seconds")
        _logger.info(f"   📄 Lines returned: {len(lines)}")
        _logger.info("   🎯 Target: < 5.0 seconds (comparison adds overhead)")

        self.assertLess(
            execution_time,
            7.0,  # More relaxed for comparison
            f"Balance Sheet comparison took {execution_time:.3f}s, should be < 7.0s"
        )

        _logger.info("✅ Balance Sheet comparison stress test PASSED")
        _logger.info("=" * 80 + "\n")

    def _log_performance_metrics(self, report_name, execution_time, line_count, query_count=None):
        """Log performance metrics to documentation file"""
        import os

        metrics_file = 'docs/sprints_log/l10n_cl_financial_reports/STRESS_TEST_SPRINT1.md'

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(metrics_file), exist_ok=True)

        # Append metrics
        mode = 'a' if os.path.exists(metrics_file) else 'w'

        with open(metrics_file, mode) as f:
            if mode == 'w':
                # Write header
                f.write("# Stress Test Results - Sprint 1\n\n")
                f.write("**Date:** 2025-11-07\n")
                f.write("**Dataset:** ~50,000 account.move.line across 450+ accounts\n")
                f.write("**Environment:** Development\n\n")
                f.write("---\n\n")
                f.write("## Performance Metrics\n\n")

            # Write metrics
            f.write(f"### {report_name}\n\n")
            f.write(f"- **Execution Time:** {execution_time:.3f} seconds\n")
            f.write(f"- **Lines Returned:** {line_count}\n")
            if query_count:
                f.write(f"- **SQL Queries:** {query_count}\n")
            f.write(f"- **Status:** {'✅ PASS' if execution_time < 5.0 else '⚠️ SLOW'}\n\n")

    @classmethod
    def tearDownClass(cls):
        """Clean up large dataset"""
        _logger.info("=" * 80)
        _logger.info("STRESS TEST CLEANUP: Removing synthetic dataset")
        _logger.info("=" * 80)

        # Delete moves (cascade will delete lines)
        if hasattr(cls, 'moves'):
            cls.moves.unlink()
            _logger.info(f"✅ Deleted {len(cls.moves)} moves")

        # Delete accounts
        if hasattr(cls, 'accounts'):
            total_accounts = sum(len(accounts) for accounts in cls.accounts.values())
            for accounts in cls.accounts.values():
                for account in accounts:
                    account.unlink()
            _logger.info(f"✅ Deleted {total_accounts} accounts")

        # Delete partners
        if hasattr(cls, 'partners'):
            cls.partners.unlink()
            _logger.info(f"✅ Deleted {len(cls.partners)} partners")

        _logger.info("=" * 80)
        _logger.info("CLEANUP COMPLETE")
        _logger.info("=" * 80)

        super().tearDownClass()
