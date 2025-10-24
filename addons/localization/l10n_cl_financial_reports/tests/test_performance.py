# -*- coding: utf-8 -*-
import time
import logging
from odoo.tests.common import TransactionCase
from odoo.tools import mute_logger

_logger = logging.getLogger(__name__)

class TestFinancialReportPerformance(TransactionCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.company = self.env.ref('base.main_company')
        self.journal = self.env['account.journal'].search([('type', '=', 'sale'), ('company_id', '=', self.company.id)], limit=1)
        self.account_receivable = self.env['account.account'].search([
            ('account_type', '=', 'asset_receivable'),
            ('company_id', '=', self.company.id)
        ], limit=1)
        self.account_revenue = self.env['account.account'].search([
            ('account_type', '=', 'income'),
            ('company_id', '=', self.company.id)
        ], limit=1)

    @mute_logger('odoo.models.unlink')
    def test_report_performance_with_large_data(self):
        """
        Test performance of financial reports with a large volume of journal entries.
        This is not a functional test, but a performance benchmark.
        It is meant to be run manually to identify potential bottlenecks.
        """
        # --- Configuration ---
        # Set the number of journal entries to create.
        # Warning: A high number will consume significant time and resources.
        # 1,000,000 entries can take several minutes to generate.
        NUM_ENTRIES = 100000  # Adjust this number for more intensive testing

        _logger.info("--- Starting Performance Test for Financial Reports ---")
        _logger.info("Preparing to generate %s journal entries. This may take a while...", NUM_ENTRIES)

        # --- Data Generation ---
        start_generation_time = time.time()
        move_vals_list = []
        for i in range(NUM_ENTRIES):
            move_vals_list.append({
                'journal_id': self.journal.id,
                'date': '2023-01-15',
                'line_ids': [
                    (0, 0, {
                        'name': 'Performance Test Entry ' + str(i),
                        'account_id': self.account_receivable.id,
                        'debit': 100.0,
                        'credit': 0.0,
                    }),
                    (0, 0, {
                        'name': 'Performance Test Entry ' + str(i),
                        'account_id': self.account_revenue.id,
                        'debit': 0.0,
                        'credit': 100.0,
                    }),
                ]
            })
        
        self.env['account.move'].create(move_vals_list)
        end_generation_time = time.time()
        _logger.info(
            "Data generation completed in %.2f seconds.",
            end_generation_time - start_generation_time
        )

        # --- Performance Measurement ---
        report = self.env['account.report'].search([('name', '=', 'Balance Sheet')], limit=1)
        if not report:
            _logger.warning("Could not find 'Balance Sheet' report. Skipping performance test.")
            return

        _logger.info("Measuring performance of Balance Sheet report...")
        start_report_time = time.time()

        # The 'get_html' method is a good proxy for the report generation logic.
        report.with_context(
            date_from='2023-01-01',
            date_to='2023-12-31').get_html({})
        
        end_report_time = time.time()
        execution_time = end_report_time - start_report_time

        _logger.info("--- Financial Report Performance Results ---")
        _logger.info("Report: Balance Sheet")
        _logger.info("Journal Entries Tested: %s", NUM_ENTRIES)
        _logger.info("Execution Time: %.4f seconds", execution_time)
        _logger.info("-------------------------------------------")

        # --- Assertion (Optional) ---
        # We can add a non-strict assertion to flag potential regressions.
        # A reasonable threshold might be 10-15 seconds for 1 million entries.
        # This is highly dependent on the hardware.
        max_execution_time = 15.0  # seconds
        self.assertLess(
            execution_time,
            max_execution_time,
            f"Report generation took {execution_time:.2f}s, which is longer than the "
            f"threshold of {max_execution_time}s for {NUM_ENTRIES} entries."
        )
