# -*- coding: utf-8 -*-

"""
Tests - Legal Caps Dynamic Validity Range

Tests H-007 fix: Validates that legal caps are retrieved
using validity date ranges (valid_from/valid_until) instead
of non-existent 'year' field.
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import UserError
from datetime import date
from dateutil.relativedelta import relativedelta


@tagged('post_install', '-at_install', 'payroll_caps')
class TestPayrollCapsDynamic(TransactionCase):
    """
    Test legal caps retrieval using validity date ranges
    
    Test Cases:
    - A: Date within validity range → returns correct value
    - B: Multiple validity ranges in same year → selects correct one
    - C: No valid record for date → raises UserError
    """
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Company
        cls.company = cls.env.ref('base.main_company')
        cls.company.vat = '76123456-7'
        
        # Create AFP for testing
        cls.afp = cls.env['hr.afp'].create({
            'name': 'AFP Test',
            'code': 'TEST',
            'rate': 1.44,
        })
        
        # Create employee and contract
        cls.employee = cls.env['hr.employee'].create({
            'name': 'Test Employee',
            'company_id': cls.company.id,
            'l10n_cl_identification_id': '12345678-9',
        })
        
        cls.contract = cls.env['hr.contract'].create({
            'name': 'Test Contract',
            'employee_id': cls.employee.id,
            'company_id': cls.company.id,
            'wage': 1000000,
            'date_start': date(2025, 1, 1),
            'state': 'open',
            'afp_id': cls.afp.id,
        })
        
        # Create economic indicators for Jan 2025
        cls.indicators_jan = cls.env['hr.economic.indicators'].create({
            'month': 1,
            'year': 2025,
            'uf': 37800.00,
            'utm': 65967.00,
            'uta': 791604.00,
            'minimum_wage': 500000.00,
        })

        # Create economic indicators for Jul 2025
        cls.indicators_jul = cls.env['hr.economic.indicators'].create({
            'month': 7,
            'year': 2025,
            'uf': 38200.00,
            'utm': 66500.00,
            'uta': 798000.00,
            'minimum_wage': 500000.00,
        })
        
        # Create payroll structure
        cls.payroll_structure = cls.env['hr.payroll.structure'].search([
            ('name', '=', 'Chile - Liquidación Mensual')
        ], limit=1)
        
        if not cls.payroll_structure:
            cls.payroll_structure = cls.env['hr.payroll.structure'].create({
                'name': 'Chile - Liquidación Mensual',
                'company_id': cls.company.id,
            })
    
    def test_caps_validity_range_within(self):
        """
        Test Case A: Date within validity range returns correct value
        
        H-007 Fix Validation:
        - Creates legal cap with validity range Jan-Jun 2025
        - Creates payslip for March 2025
        - Verifies that TOPE_IMPONIBLE_UF rule finds the cap
        - Validates correct calculation (81.6 UF * 37800 = 3,082,080)
        """
        # Create legal cap valid Jan 1 - Jun 30, 2025
        cap = self.env['l10n_cl.legal.caps'].create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 81.6,
            'unit': 'uf',
            'valid_from': date(2025, 1, 1),
            'valid_until': date(2025, 7, 1),  # Until July 1st (exclusive)
        })
        
        # Create payslip for March 2025 (within range)
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip March',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'company_id': self.company.id,
            'struct_id': self.payroll_structure.id,
            'date_from': date(2025, 3, 1),
            'date_to': date(2025, 3, 31),
            'indicadores_id': self.indicators_jan.id,
        })
        
        # Compute payslip (this triggers the rule)
        payslip.compute_sheet()
        
        # Find TOPE_IMPONIBLE_UF line
        tope_line = payslip.line_ids.filtered(
            lambda l: l.code == 'TOPE_IMPONIBLE_UF'
        )
        
        # Verify cap was found and calculated correctly
        self.assertTrue(tope_line, "TOPE_IMPONIBLE_UF line should exist")
        expected = 81.6 * 37800.00  # 3,082,080
        self.assertAlmostEqual(
            tope_line.total, 
            expected, 
            places=2,
            msg=f"Expected {expected}, got {tope_line.total}"
        )
    
    def test_caps_multiple_validity_ranges(self):
        """
        Test Case B: Multiple validity ranges in same year → selects correct one
        
        H-007 Fix Validation:
        - Creates TWO legal caps for 2025:
          * Jan-Jun: 81.6 UF
          * Jul-Dec: 85.0 UF (new regulation mid-year)
        - Creates payslip for July 2025
        - Verifies that the SECOND cap is selected (85.0 UF)
        """
        # First semester cap (Jan-Jun)
        cap_h1 = self.env['l10n_cl.legal.caps'].create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 81.6,
            'unit': 'uf',
            'valid_from': date(2025, 1, 1),
            'valid_until': date(2025, 7, 1),
        })
        
        # Second semester cap (Jul-Dec)
        cap_h2 = self.env['l10n_cl.legal.caps'].create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 85.0,
            'unit': 'uf',
            'valid_from': date(2025, 7, 1),
            'valid_until': False,  # Open-ended
        })
        
        # Create payslip for July 2025
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip July',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'company_id': self.company.id,
            'struct_id': self.payroll_structure.id,
            'date_from': date(2025, 7, 1),
            'date_to': date(2025, 7, 31),
            'indicadores_id': self.indicators_jul.id,
        })
        
        # Compute payslip
        payslip.compute_sheet()
        
        # Find TOPE_IMPONIBLE_UF line
        tope_line = payslip.line_ids.filtered(
            lambda l: l.code == 'TOPE_IMPONIBLE_UF'
        )
        
        # Verify SECOND cap (85.0 UF) was selected
        self.assertTrue(tope_line, "TOPE_IMPONIBLE_UF line should exist")
        expected = 85.0 * 38200.00  # New cap * new UF value
        self.assertAlmostEqual(
            tope_line.total, 
            expected, 
            places=2,
            msg=f"Should use H2 cap (85.0 UF). Expected {expected}, got {tope_line.total}"
        )
    
    def test_caps_no_valid_record_raises_error(self):
        """
        Test Case C: No valid record for date → raises UserError
        
        H-007 Fix Validation:
        - Does NOT create any legal cap
        - Attempts to create and compute payslip
        - Verifies that UserError is raised with clear message
        - Validates error message guides user to configure caps
        """
        # Do NOT create any legal cap
        
        # Create payslip for Jan 2025
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip No Cap',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'company_id': self.company.id,
            'struct_id': self.payroll_structure.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicators_jan.id,
        })
        
        # Verify that compute_sheet raises UserError
        with self.assertRaises(UserError) as context:
            payslip.compute_sheet()
        
        # Verify error message is clear and helpful
        error_msg = str(context.exception)
        self.assertIn('AFP_IMPONIBLE_CAP', error_msg,
                      "Error should mention the missing cap code")
        self.assertIn('Legal Caps', error_msg,
                      "Error should guide user to configuration")
    
    def test_caps_no_indicators_raises_error(self):
        """
        Test Case D: Payslip without indicators → raises UserError
        
        Validates that missing economic indicators are caught
        with clear error message before attempting cap lookup.
        """
        # Create legal cap
        cap = self.env['l10n_cl.legal.caps'].create({
            'code': 'AFP_IMPONIBLE_CAP',
            'amount': 81.6,
            'unit': 'uf',
            'valid_from': date(2025, 1, 1),
            'valid_until': False,
        })
        
        # Create payslip WITHOUT indicators
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Payslip No Indicators',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'company_id': self.company.id,
            'struct_id': self.payroll_structure.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            # indicadores_id: NOT SET
        })
        
        # Verify that compute_sheet raises UserError
        with self.assertRaises(UserError) as context:
            payslip.compute_sheet()
        
        # Verify error message mentions indicators
        error_msg = str(context.exception)
        self.assertIn('indicadores', error_msg.lower(),
                      "Error should mention missing indicators")
