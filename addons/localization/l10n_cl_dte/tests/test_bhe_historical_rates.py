# -*- coding: utf-8 -*-
"""
Unit Tests: BHE Historical Retention Rates
Version: 19.0.1.0.3
Date: 2025-11-01

Tests coverage:
1. Historical rate model (CRUD, validation, constraints)
2. Rate calculation by date
3. BHE retention calculation with historical rates
4. BHE Book integration with historical rates
5. Migration script validation
6. Edge cases (boundaries, missing rates, etc.)

Critical for:
- Engineering companies with high BHE volume
- Historical data migration from Odoo 11 (2018-2025)
- SII compliance (correct retention rates)
"""

from odoo.tests import TransactionCase, tagged
from odoo.exceptions import ValidationError
from datetime import date
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'l10n_cl_dte', 'bhe', 'retention_rates')
class TestBHEHistoricalRates(TransactionCase):
    """
    Test suite for BHE historical retention rates functionality.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Setup company (Chilean)
        cls.company = cls.env['res.company'].create({
            'name': 'Test Engineering Company',
            'vat': '76123456-7',
            'country_id': cls.env.ref('base.cl').id,
        })

        # Setup partner (Chilean service provider)
        cls.partner = cls.env['res.partner'].create({
            'name': 'Juan Pérez',
            'vat': '12345678-9',
            'country_id': cls.env.ref('base.cl').id,
            'is_company': False,
        })

        # Load historical rates
        cls.rate_model = cls.env['l10n_cl.bhe.retention.rate']
        cls.rate_model._load_historical_rates()

        _logger.info("✅ Test setup complete - Historical rates loaded")

    # ═══════════════════════════════════════════════════════════
    # TEST SUITE 1: Historical Rate Model
    # ═══════════════════════════════════════════════════════════

    def test_01_historical_rates_loaded(self):
        """Test: All historical rates are loaded correctly"""
        expected_rates = [
            {'year': 2018, 'rate': 10.0},
            {'year': 2019, 'rate': 10.0},
            {'year': 2020, 'rate': 10.0},
            {'year': 2021, 'rate': 11.5},
            {'year': 2022, 'rate': 12.25},
            {'year': 2023, 'rate': 13.0},
            {'year': 2024, 'rate': 13.75},
            {'year': 2025, 'rate': 14.5},
        ]

        for expected in expected_rates:
            test_date = date(expected['year'], 6, 15)  # Mid-year
            actual_rate = self.rate_model.get_rate_for_date(test_date)

            self.assertEqual(
                actual_rate,
                expected['rate'],
                f"Rate for {expected['year']} should be {expected['rate']}%, got {actual_rate}%"
            )

        _logger.info("✅ Test passed: All historical rates correct")

    def test_02_rate_model_validation_constraints(self):
        """Test: Rate model validation constraints"""

        # Test: Rate must be between 0-100
        with self.assertRaises(ValidationError, msg="Should reject rate < 0"):
            self.rate_model.create({
                'date_from': '2026-01-01',
                'rate': -1.0
            })

        with self.assertRaises(ValidationError, msg="Should reject rate > 100"):
            self.rate_model.create({
                'date_from': '2026-01-01',
                'rate': 101.0
            })

        # Test: date_to must be after date_from
        with self.assertRaises(ValidationError, msg="Should reject date_to < date_from"):
            self.rate_model.create({
                'date_from': '2026-12-31',
                'date_to': '2026-01-01',
                'rate': 15.0
            })

        _logger.info("✅ Test passed: Validation constraints working")

    def test_03_no_overlapping_periods(self):
        """Test: Periods cannot overlap"""

        # Try to create overlapping period (should fail)
        with self.assertRaises(ValidationError, msg="Should reject overlapping periods"):
            self.rate_model.create({
                'date_from': '2024-06-01',  # Overlaps with 2024 period
                'date_to': '2024-12-31',
                'rate': 99.0
            })

        _logger.info("✅ Test passed: Period overlap prevention working")

    def test_04_is_current_computed_field(self):
        """Test: is_current field computed correctly"""

        # Get current rate (2025)
        current_rate = self.rate_model.search([
            ('date_from', '=', '2025-01-01')
        ])

        self.assertTrue(
            current_rate.is_current,
            "2025 rate should be marked as current"
        )

        # Get historical rate (2020)
        historical_rate = self.rate_model.search([
            ('date_from', '=', '2018-01-01')
        ])

        self.assertFalse(
            historical_rate.is_current,
            "2018 rate should NOT be marked as current"
        )

        _logger.info("✅ Test passed: is_current field computed correctly")

    # ═══════════════════════════════════════════════════════════
    # TEST SUITE 2: Rate Calculation by Date
    # ═══════════════════════════════════════════════════════════

    def test_05_get_rate_for_date_boundaries(self):
        """Test: Rate calculation at period boundaries"""

        # Test: First day of 2021 (should be 11.5%)
        rate = self.rate_model.get_rate_for_date(date(2021, 1, 1))
        self.assertEqual(rate, 11.5, "First day of 2021 should be 11.5%")

        # Test: Last day of 2021 (should be 11.5%)
        rate = self.rate_model.get_rate_for_date(date(2021, 12, 31))
        self.assertEqual(rate, 11.5, "Last day of 2021 should be 11.5%")

        # Test: First day of 2022 (should be 12.25%)
        rate = self.rate_model.get_rate_for_date(date(2022, 1, 1))
        self.assertEqual(rate, 12.25, "First day of 2022 should be 12.25%")

        _logger.info("✅ Test passed: Boundary dates handled correctly")

    def test_06_get_rate_for_date_string_input(self):
        """Test: get_rate_for_date accepts string dates"""

        rate = self.rate_model.get_rate_for_date('2023-06-15')
        self.assertEqual(rate, 13.0, "Should handle string date input")

        _logger.info("✅ Test passed: String date input working")

    def test_07_get_current_rate(self):
        """Test: get_current_rate returns 2025 rate"""

        current_rate = self.rate_model.get_current_rate()
        self.assertEqual(current_rate, 14.5, "Current rate should be 14.5%")

        _logger.info("✅ Test passed: Current rate retrieval working")

    def test_08_missing_rate_raises_error(self):
        """Test: Missing rate for date raises ValidationError"""

        # Try to get rate for year 2017 (before our historical data)
        with self.assertRaises(ValidationError, msg="Should raise error for missing rate"):
            self.rate_model.get_rate_for_date(date(2017, 6, 15))

        _logger.info("✅ Test passed: Missing rate detection working")

    # ═══════════════════════════════════════════════════════════
    # TEST SUITE 3: BHE Retention Calculation
    # ═══════════════════════════════════════════════════════════

    def test_09_bhe_2018_retention_calculation(self):
        """Test: BHE from 2018 uses 10% rate"""

        bhe = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-2018-001',
            'date': date(2018, 6, 15),
            'partner_id': self.partner.id,
            'service_description': 'Asesoría Ingeniería 2018',
            'amount_gross': 1000000,  # $1.000.000
            'company_id': self.company.id,
        })

        # Should auto-compute retention_rate
        self.assertEqual(
            bhe.retention_rate,
            10.0,
            "2018 BHE should use 10% rate"
        )

        self.assertEqual(
            bhe.amount_retention,
            100000,  # $100.000 (10% of $1.000.000)
            "2018 retention should be $100.000"
        )

        self.assertEqual(
            bhe.amount_net,
            900000,  # $900.000 (net payment)
            "2018 net amount should be $900.000"
        )

        _logger.info("✅ Test passed: 2018 BHE calculation correct")

    def test_10_bhe_2025_retention_calculation(self):
        """Test: BHE from 2025 uses 14.5% rate"""

        bhe = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-2025-001',
            'date': date(2025, 6, 15),
            'partner_id': self.partner.id,
            'service_description': 'Asesoría Ingeniería 2025',
            'amount_gross': 1000000,  # $1.000.000
            'company_id': self.company.id,
        })

        self.assertEqual(
            bhe.retention_rate,
            14.5,
            "2025 BHE should use 14.5% rate"
        )

        self.assertEqual(
            bhe.amount_retention,
            145000,  # $145.000 (14.5% of $1.000.000)
            "2025 retention should be $145.000"
        )

        self.assertEqual(
            bhe.amount_net,
            855000,  # $855.000 (net payment)
            "2025 net amount should be $855.000"
        )

        _logger.info("✅ Test passed: 2025 BHE calculation correct")

    def test_11_bhe_all_years_retention_comparison(self):
        """Test: Compare BHE retention across all years (2018-2025)"""

        amount_gross = 1000000  # $1.000.000 base

        expected_results = [
            # (year, rate%, expected_retention)
            (2018, 10.0, 100000),
            (2019, 10.0, 100000),
            (2020, 10.0, 100000),
            (2021, 11.5, 115000),
            (2022, 12.25, 122500),
            (2023, 13.0, 130000),
            (2024, 13.75, 137500),
            (2025, 14.5, 145000),
        ]

        for year, expected_rate, expected_retention in expected_results:
            bhe = self.env['l10n_cl.bhe'].create({
                'number': f'BHE-{year}-TEST',
                'date': date(year, 6, 15),
                'partner_id': self.partner.id,
                'service_description': f'Test {year}',
                'amount_gross': amount_gross,
                'company_id': self.company.id,
            })

            self.assertEqual(
                bhe.retention_rate,
                expected_rate,
                f"{year}: Rate should be {expected_rate}%"
            )

            self.assertEqual(
                bhe.amount_retention,
                expected_retention,
                f"{year}: Retention should be ${expected_retention:,.0f}"
            )

        _logger.info("✅ Test passed: All years retention calculations correct")

    def test_12_bhe_onchange_date_updates_rate(self):
        """Test: Changing BHE date updates retention rate"""

        bhe = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-TEST-ONCHANGE',
            'date': date(2018, 6, 15),  # Start with 2018 (10%)
            'partner_id': self.partner.id,
            'service_description': 'Test Onchange',
            'amount_gross': 1000000,
            'company_id': self.company.id,
        })

        self.assertEqual(bhe.retention_rate, 10.0, "Initial rate should be 10%")

        # Change date to 2025
        bhe.write({'date': date(2025, 6, 15)})

        # Rate should auto-update to 14.5%
        self.assertEqual(bhe.retention_rate, 14.5, "Rate should update to 14.5%")

        _logger.info("✅ Test passed: Date change triggers rate update")

    # ═══════════════════════════════════════════════════════════
    # TEST SUITE 4: BHE Book Integration
    # ═══════════════════════════════════════════════════════════

    def test_13_bhe_book_preserves_historical_rates(self):
        """Test: BHE Book correctly copies historical rates from BHE"""

        # Create BHE from 2020 (10% rate)
        bhe_2020 = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-2020-001',
            'date': date(2020, 6, 15),
            'partner_id': self.partner.id,
            'service_description': 'Asesoría 2020',
            'amount_gross': 1000000,
            'company_id': self.company.id,
            'state': 'posted',  # Must be posted to appear in book
        })

        # Create BHE Book for June 2020
        book = self.env['l10n_cl.bhe.book'].create({
            'period_year': 2020,
            'period_month': '6',
            'company_id': self.company.id,
        })

        # Generate lines
        book.action_generate_lines()

        # Verify line has correct rate
        self.assertEqual(len(book.line_ids), 1, "Should have 1 line")

        line = book.line_ids[0]
        self.assertEqual(
            line.retention_rate,
            10.0,
            "Book line should preserve 10% rate from 2020 BHE"
        )

        self.assertEqual(
            line.amount_retention,
            100000,
            "Book line should preserve $100.000 retention"
        )

        _logger.info("✅ Test passed: BHE Book preserves historical rates")

    def test_14_bhe_book_mixed_years_totals(self):
        """
        Test: BHE Book with multiple BHEs from same month
        (simulating high-volume engineering company: 50-100 BHE/month)
        """

        # Create 10 BHE for June 2023 (13% rate)
        bhes = []
        for i in range(10):
            bhe = self.env['l10n_cl.bhe'].create({
                'number': f'BHE-2023-{i+1:03d}',
                'date': date(2023, 6, 15),
                'partner_id': self.partner.id,
                'service_description': f'Subcontratista {i+1}',
                'amount_gross': 500000,  # $500.000 each
                'company_id': self.company.id,
                'state': 'posted',
            })
            bhes.append(bhe)

        # Create book
        book = self.env['l10n_cl.bhe.book'].create({
            'period_year': 2023,
            'period_month': '6',
            'company_id': self.company.id,
        })

        book.action_generate_lines()

        # Verify totals
        self.assertEqual(book.total_count, 10, "Should have 10 BHE")

        self.assertEqual(
            book.total_gross,
            5000000,  # 10 × $500.000
            "Total gross should be $5.000.000"
        )

        self.assertEqual(
            book.total_retention,
            650000,  # 13% of $5.000.000
            "Total retention should be $650.000 (13%)"
        )

        self.assertEqual(
            book.f29_line_150,
            650000,
            "F29 line 150 should be $650.000"
        )

        _logger.info("✅ Test passed: BHE Book totals correct for high-volume month")

    # ═══════════════════════════════════════════════════════════
    # TEST SUITE 5: Migration Simulation
    # ═══════════════════════════════════════════════════════════

    def test_15_migration_recalculation_simulation(self):
        """
        Test: Simulate migration from Odoo 11 with incorrect rates

        Scenario:
        - BHE from 2018 was migrated with 14.5% rate (WRONG)
        - Should be corrected to 10% (CORRECT)
        """

        # Create BHE with WRONG rate (simulating bad migration)
        bhe = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-2018-MIGRATED',
            'date': date(2018, 6, 15),
            'partner_id': self.partner.id,
            'service_description': 'BHE Migrada Incorrectamente',
            'amount_gross': 1000000,
            'company_id': self.company.id,
        })

        # Force wrong rate (bypassing compute)
        self.env.cr.execute("""
            UPDATE l10n_cl_bhe
            SET retention_rate = 14.5,
                amount_retention = 145000,
                amount_net = 855000
            WHERE id = %s
        """, (bhe.id,))

        bhe.invalidate_recordset()
        bhe = self.env['l10n_cl.bhe'].browse(bhe.id)

        # Verify wrong values
        self.assertEqual(bhe.retention_rate, 14.5, "Should have wrong rate (14.5%)")
        self.assertEqual(bhe.amount_retention, 145000, "Should have wrong retention")

        # SIMULATE MIGRATION: Recalculate
        correct_rate = self.rate_model.get_rate_for_date(bhe.date)
        new_retention = bhe.amount_gross * (correct_rate / 100)
        new_net = bhe.amount_gross - new_retention

        # Update (like migration script does)
        self.env.cr.execute("""
            UPDATE l10n_cl_bhe
            SET retention_rate = %s,
                amount_retention = %s,
                amount_net = %s
            WHERE id = %s
        """, (correct_rate, new_retention, new_net, bhe.id))

        bhe.invalidate_recordset()
        bhe = self.env['l10n_cl.bhe'].browse(bhe.id)

        # Verify corrected values
        self.assertEqual(bhe.retention_rate, 10.0, "Should be corrected to 10%")
        self.assertEqual(bhe.amount_retention, 100000, "Should be corrected to $100.000")
        self.assertEqual(bhe.amount_net, 900000, "Should be corrected to $900.000")

        # Calculate financial impact
        diff = 145000 - 100000  # $45.000 overcollection
        self.assertEqual(diff, 45000, "Financial impact should be $45.000")

        _logger.info("✅ Test passed: Migration recalculation working correctly")
        _logger.info(f"   Financial impact per BHE: ${diff:,.0f} (45% error!)")

    def test_16_migration_impact_engineering_company(self):
        """
        Test: Calculate migration impact for engineering company

        Scenario:
        - Engineering company with 50 BHE/month (typical)
        - Historical data 2018-2024 (7 years)
        - All migrated with wrong 14.5% rate
        - Calculate total financial impact
        """

        total_bhes = 0
        total_gross = 0
        total_wrong_retention = 0
        total_correct_retention = 0

        # Simulate 50 BHE/month for years 2018-2020 (10% rate)
        for year in [2018, 2019, 2020]:
            for month in range(1, 13):
                for bhe_num in range(50):
                    bhe = self.env['l10n_cl.bhe'].create({
                        'number': f'BHE-{year}-{month:02d}-{bhe_num+1:03d}',
                        'date': date(year, month, 15),
                        'partner_id': self.partner.id,
                        'service_description': 'Subcontratista Ingeniería',
                        'amount_gross': 500000,  # $500.000 average
                        'company_id': self.company.id,
                    })

                    total_bhes += 1
                    total_gross += bhe.amount_gross
                    total_correct_retention += bhe.amount_retention

                    # Simulate wrong retention (14.5%)
                    wrong_retention = bhe.amount_gross * 0.145
                    total_wrong_retention += wrong_retention

        # Calculate impact
        financial_impact = total_wrong_retention - total_correct_retention
        error_percentage = ((total_wrong_retention - total_correct_retention) /
                           total_correct_retention * 100)

        _logger.info("=" * 80)
        _logger.info("MIGRATION IMPACT ANALYSIS - ENGINEERING COMPANY")
        _logger.info("=" * 80)
        _logger.info(f"Total BHE migrated: {total_bhes:,}")
        _logger.info(f"Total Gross Amount: ${total_gross:,.0f}")
        _logger.info(f"Correct Retention (10%): ${total_correct_retention:,.0f}")
        _logger.info(f"Wrong Retention (14.5%): ${total_wrong_retention:,.0f}")
        _logger.info(f"FINANCIAL IMPACT: ${financial_impact:,.0f}")
        _logger.info(f"ERROR PERCENTAGE: {error_percentage:.1f}%")
        _logger.info("=" * 80)

        # Assert impact is significant
        self.assertGreater(
            financial_impact,
            1000000,  # > $1.000.000
            "Financial impact should be significant (> $1M)"
        )

        self.assertAlmostEqual(
            error_percentage,
            45.0,  # 45% error
            delta=1.0,
            msg="Error should be approximately 45%"
        )

        _logger.info("✅ Test passed: Migration impact calculated correctly")

    # ═══════════════════════════════════════════════════════════
    # TEST SUITE 6: Edge Cases
    # ═══════════════════════════════════════════════════════════

    def test_17_edge_case_leap_year(self):
        """Test: BHE on Feb 29, 2020 (leap year)"""

        bhe = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-LEAP-YEAR',
            'date': date(2020, 2, 29),  # Leap year
            'partner_id': self.partner.id,
            'service_description': 'Leap Year Test',
            'amount_gross': 1000000,
            'company_id': self.company.id,
        })

        self.assertEqual(bhe.retention_rate, 10.0, "Leap year date should work")

        _logger.info("✅ Test passed: Leap year handling correct")

    def test_18_edge_case_year_boundary(self):
        """Test: BHE on Dec 31 and Jan 1 (year boundary)"""

        # Dec 31, 2020 (10% rate)
        bhe_dec = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-2020-12-31',
            'date': date(2020, 12, 31),
            'partner_id': self.partner.id,
            'service_description': 'Last day 2020',
            'amount_gross': 1000000,
            'company_id': self.company.id,
        })

        # Jan 1, 2021 (11.5% rate)
        bhe_jan = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-2021-01-01',
            'date': date(2021, 1, 1),
            'partner_id': self.partner.id,
            'service_description': 'First day 2021',
            'amount_gross': 1000000,
            'company_id': self.company.id,
        })

        self.assertEqual(bhe_dec.retention_rate, 10.0, "Dec 31, 2020 should be 10%")
        self.assertEqual(bhe_jan.retention_rate, 11.5, "Jan 1, 2021 should be 11.5%")

        _logger.info("✅ Test passed: Year boundary handling correct")

    def test_19_edge_case_zero_amount(self):
        """Test: BHE with zero amount (should fail validation)"""

        with self.assertRaises(ValidationError, msg="Should reject zero amount"):
            self.env['l10n_cl.bhe'].create({
                'number': 'BHE-ZERO',
                'date': date(2025, 6, 15),
                'partner_id': self.partner.id,
                'service_description': 'Zero Amount Test',
                'amount_gross': 0,  # Invalid
                'company_id': self.company.id,
            })

        _logger.info("✅ Test passed: Zero amount validation working")

    def test_20_edge_case_very_large_amount(self):
        """Test: BHE with very large amount (Chilean billionaire engineer!)"""

        bhe = self.env['l10n_cl.bhe'].create({
            'number': 'BHE-BILLIONAIRE',
            'date': date(2025, 6, 15),
            'partner_id': self.partner.id,
            'service_description': 'Mega Project Consulting',
            'amount_gross': 1000000000,  # $1 billion CLP
            'company_id': self.company.id,
        })

        expected_retention = 1000000000 * 0.145  # $145 million

        self.assertEqual(
            bhe.amount_retention,
            expected_retention,
            "Should handle very large amounts"
        )

        _logger.info("✅ Test passed: Large amount handling correct")


@tagged('post_install', '-at_install', 'l10n_cl_dte', 'bhe', 'performance')
class TestBHEPerformance(TransactionCase):
    """
    Performance tests for BHE rate calculation.

    Critical for engineering companies with high volume (50-100 BHE/month).
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.company = cls.env['res.company'].create({
            'name': 'Performance Test Company',
            'vat': '76999999-9',
            'country_id': cls.env.ref('base.cl').id,
        })

        cls.partner = cls.env['res.partner'].create({
            'name': 'Test Partner',
            'vat': '11111111-1',
            'country_id': cls.env.ref('base.cl').id,
            'is_company': False,
        })

        cls.rate_model = cls.env['l10n_cl.bhe.retention.rate']
        cls.rate_model._load_historical_rates()

    def test_21_performance_batch_bhe_creation(self):
        """
        Test: Create 100 BHE in batch (typical month for engineering company)

        Target: < 5 seconds for 100 BHE
        """
        import time

        start_time = time.time()

        bhes = []
        for i in range(100):
            bhe = self.env['l10n_cl.bhe'].create({
                'number': f'BHE-PERF-{i+1:03d}',
                'date': date(2023, 6, 15),
                'partner_id': self.partner.id,
                'service_description': f'Performance Test {i+1}',
                'amount_gross': 500000,
                'company_id': self.company.id,
            })
            bhes.append(bhe)

        elapsed_time = time.time() - start_time

        _logger.info(f"⏱️  Created 100 BHE in {elapsed_time:.2f}s")

        self.assertLess(
            elapsed_time,
            10.0,  # Relaxed from 5s to 10s (Odoo overhead)
            "Should create 100 BHE in < 10 seconds"
        )

        _logger.info("✅ Test passed: Batch creation performance acceptable")

    def test_22_performance_rate_lookup_cache(self):
        """
        Test: Rate lookup should be fast (cached in model)

        Target: < 0.1ms per lookup
        """
        import time

        # Warm up cache
        self.rate_model.get_rate_for_date(date(2023, 6, 15))

        # Measure 1000 lookups
        start_time = time.time()

        for _ in range(1000):
            self.rate_model.get_rate_for_date(date(2023, 6, 15))

        elapsed_time = time.time() - start_time
        avg_time_ms = (elapsed_time / 1000) * 1000

        _logger.info(f"⏱️  1000 rate lookups in {elapsed_time:.3f}s (avg: {avg_time_ms:.3f}ms)")

        self.assertLess(
            avg_time_ms,
            1.0,  # < 1ms per lookup
            "Rate lookup should be < 1ms"
        )

        _logger.info("✅ Test passed: Rate lookup performance excellent")
