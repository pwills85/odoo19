# -*- coding: utf-8 -*-

"""
Tests - LRE Wizard Access Rights

Tests H-002 fix: Validates that LRE wizard has proper
access controls for HR payroll users and managers.
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import AccessError
from datetime import date


@tagged('post_install', '-at_install', 'payroll_access')
class TestLREAccessRights(TransactionCase):
    """
    Test LRE Wizard access rights
    
    Test Cases:
    - User with hr_payroll_user group can access wizard
    - User with hr_payroll_manager group can access wizard
    - User without HR groups cannot access wizard
    """
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Company
        cls.company = cls.env.ref('base.main_company')
        
        # Get or create HR groups
        cls.group_payroll_user = cls.env.ref(
            'l10n_cl_hr_payroll.group_hr_payroll_user',
            raise_if_not_found=False
        )
        
        if not cls.group_payroll_user:
            cls.group_payroll_user = cls.env['res.groups'].create({
                'name': 'HR Payroll User',
                'category_id': cls.env.ref('base.module_category_human_resources').id,
            })
        
        cls.group_payroll_manager = cls.env.ref(
            'l10n_cl_hr_payroll.group_hr_payroll_manager',
            raise_if_not_found=False
        )
        
        if not cls.group_payroll_manager:
            cls.group_payroll_manager = cls.env['res.groups'].create({
                'name': 'HR Payroll Manager',
                'category_id': cls.env.ref('base.module_category_human_resources').id,
            })
        
        # Create test users
        cls.user_payroll = cls.env['res.users'].create({
            'name': 'Payroll User',
            'login': 'payroll_user',
            'email': 'payroll@test.com',
            'company_id': cls.company.id,
            'groups_id': [(6, 0, [
                cls.env.ref('base.group_user').id,
                cls.group_payroll_user.id,
            ])],
        })
        
        cls.user_manager = cls.env['res.users'].create({
            'name': 'Payroll Manager',
            'login': 'payroll_manager',
            'email': 'manager@test.com',
            'company_id': cls.company.id,
            'groups_id': [(6, 0, [
                cls.env.ref('base.group_user').id,
                cls.group_payroll_manager.id,
            ])],
        })
        
        cls.user_basic = cls.env['res.users'].create({
            'name': 'Basic User',
            'login': 'basic_user',
            'email': 'basic@test.com',
            'company_id': cls.company.id,
            'groups_id': [(6, 0, [
                cls.env.ref('base.group_user').id,
            ])],
        })
        
        # Create payslip run for testing
        cls.payslip_run = cls.env['hr.payslip.run'].create({
            'name': 'Test Run Jan 2025',
            'date_start': date(2025, 1, 1),
            'date_end': date(2025, 1, 31),
            'company_id': cls.company.id,
        })
    
    def test_lre_access_payroll_user(self):
        """
        Test: Payroll user CAN access LRE wizard
        
        H-002 Fix Validation:
        - User with group_hr_payroll_user can create wizard
        - User can read wizard records
        - User can execute wizard actions
        """
        # Create wizard as payroll user
        wizard = self.env['hr.lre.wizard'].with_user(self.user_payroll).create({
            'payslip_run_id': self.payslip_run.id,
            'period_month': 1,
            'period_year': 2025,
        })
        
        # Verify creation succeeded
        self.assertTrue(wizard.id, "Payroll user should be able to create LRE wizard")
        
        # Verify read access
        wizard_read = self.env['hr.lre.wizard'].with_user(self.user_payroll).browse(wizard.id)
        self.assertEqual(wizard_read.period_month, 1,
                         "Payroll user should be able to read wizard")
        
        # Verify write access
        wizard_read.write({'period_month': 2})
        self.assertEqual(wizard_read.period_month, 2,
                         "Payroll user should be able to update wizard")
    
    def test_lre_access_payroll_manager(self):
        """
        Test: Payroll manager CAN access LRE wizard
        
        H-002 Fix Validation:
        - User with group_hr_payroll_manager has full access
        - Manager can create, read, write, unlink
        """
        # Create wizard as payroll manager
        wizard = self.env['hr.lre.wizard'].with_user(self.user_manager).create({
            'payslip_run_id': self.payslip_run.id,
            'period_month': 1,
            'period_year': 2025,
        })
        
        # Verify creation succeeded
        self.assertTrue(wizard.id, "Payroll manager should be able to create LRE wizard")
        
        # Verify full CRUD access
        wizard_read = self.env['hr.lre.wizard'].with_user(self.user_manager).browse(wizard.id)
        self.assertEqual(wizard_read.period_month, 1)
        
        # Manager can unlink
        wizard_read.unlink()
        self.assertFalse(wizard_read.exists(),
                         "Payroll manager should be able to delete wizard")
    
    def test_lre_access_basic_user_denied(self):
        """
        Test: Basic user CANNOT access LRE wizard
        
        H-002 Fix Validation:
        - User without HR groups gets AccessError
        - Error is raised on create attempt
        """
        # Attempt to create wizard as basic user (should fail)
        with self.assertRaises(AccessError) as context:
            self.env['hr.lre.wizard'].with_user(self.user_basic).create({
                'payslip_run_id': self.payslip_run.id,
                'period_month': 1,
                'period_year': 2025,
            })
        
        # Verify it's an access error
        self.assertIn('access', str(context.exception).lower(),
                      "Should raise AccessError for basic user")
    
    def test_lre_model_access_rules_exist(self):
        """
        Test: Verify ir.model.access records exist for hr.lre.wizard
        
        H-002 Fix Validation:
        - Check that access rules are properly configured
        - Verify both user and manager rules exist
        """
        # Find access rules for hr.lre.wizard model
        model = self.env['ir.model'].search([('model', '=', 'hr.lre.wizard')], limit=1)
        self.assertTrue(model.id, "hr.lre.wizard model should exist")
        
        access_rules = self.env['ir.model.access'].search([
            ('model_id', '=', model.id)
        ])
        
        # Should have at least 2 rules (user + manager)
        self.assertGreaterEqual(len(access_rules), 2,
                                "Should have at least 2 access rules for LRE wizard")
        
        # Verify user rule exists
        user_rule = access_rules.filtered(
            lambda r: r.group_id == self.group_payroll_user
        )
        self.assertTrue(user_rule, "Access rule for payroll_user should exist")
        self.assertTrue(user_rule.perm_read, "User should have read permission")
        self.assertTrue(user_rule.perm_write, "User should have write permission")
        self.assertTrue(user_rule.perm_create, "User should have create permission")
        
        # Verify manager rule exists
        manager_rule = access_rules.filtered(
            lambda r: r.group_id == self.group_payroll_manager
        )
        self.assertTrue(manager_rule, "Access rule for payroll_manager should exist")
        self.assertTrue(manager_rule.perm_read, "Manager should have read permission")
        self.assertTrue(manager_rule.perm_write, "Manager should have write permission")
        self.assertTrue(manager_rule.perm_create, "Manager should have create permission")
        self.assertTrue(manager_rule.perm_unlink, "Manager should have unlink permission")
