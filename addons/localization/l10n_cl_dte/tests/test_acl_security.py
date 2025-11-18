# -*- coding: utf-8 -*-
"""
Test ACL Security for DTE Models.

This module tests that Access Control Lists (ACLs) are properly enforced
for all DTE models across different user groups.

Author: Engineering Team
Date: 2025-11-17
Sprint: P1-001 Critical Security Fix
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import AccessError


@tagged('post_install', '-at_install', 'l10n_cl', 'security')
class TestACLSecurity(TransactionCase):
    """
    Test ACL enforcement for DTE models.
    
    This test suite validates that:
    1. Basic users have appropriate read access
    2. Accountants have read/write access
    3. System admins have full access
    4. Restricted models block unauthorized access
    """

    def setUp(self):
        """Set up test users with different permission levels."""
        super().setUp()
        
        # Create basic user (minimal permissions)
        self.user_basic = self.env['res.users'].create({
            'name': 'Test User Basic',
            'login': 'test_basic',
            'email': 'test_basic@example.com',
            'groups_id': [(6, 0, [self.env.ref('base.group_user').id])],
        })
        
        # Create accountant user (read/write accounting)
        self.user_accountant = self.env['res.users'].create({
            'name': 'Test User Accountant',
            'login': 'test_accountant',
            'email': 'test_accountant@example.com',
            'groups_id': [(6, 0, [
                self.env.ref('base.group_user').id,
                self.env.ref('account.group_account_user').id,
            ])],
        })
        
        # Create accounting manager (full accounting access)
        self.user_manager = self.env['res.users'].create({
            'name': 'Test User Manager',
            'login': 'test_manager',
            'email': 'test_manager@example.com',
            'groups_id': [(6, 0, [
                self.env.ref('base.group_user').id,
                self.env.ref('account.group_account_manager').id,
            ])],
        })

    # ===================================================================
    # AI CHAT MODELS TESTS
    # ===================================================================

    def test_ai_chat_session_basic_user_read(self):
        """Test: Basic user can read AI chat sessions."""
        # Basic user should have read access (perm_read=1)
        sessions = self.env['ai.chat.session'].with_user(self.user_basic).search([])
        self.assertTrue(True, "Basic user can read AI chat sessions")

    def test_ai_chat_session_basic_user_create(self):
        """Test: Basic user can create AI chat sessions."""
        # Basic user CAN create (perm_create=1 in ACL)
        session = self.env['ai.chat.session'].with_user(self.user_basic).create({
            'name': 'Test Session Basic',
        })
        self.assertTrue(session, "Basic user can create AI chat sessions")

    def test_ai_chat_integration_accountant_write(self):
        """Test: Accountant can write AI chat integrations."""
        # Manager creates integration first
        integration = self.env['ai.chat.integration'].with_user(self.user_manager).create({
            'name': 'Test Integration',
        })
        
        # Accountant can write (perm_write=1 for account.group_account_user)
        integration.with_user(self.user_accountant).write({
            'name': 'Updated by Accountant',
        })
        self.assertEqual(integration.name, 'Updated by Accountant')

    def test_ai_chat_integration_basic_user_cannot_unlink(self):
        """Test: Basic user cannot delete AI chat integrations."""
        # Manager creates integration
        integration = self.env['ai.chat.integration'].with_user(self.user_manager).create({
            'name': 'Test Integration',
        })
        
        # Basic user cannot delete (perm_unlink=0)
        with self.assertRaises(AccessError):
            integration.with_user(self.user_basic).unlink()

    # ===================================================================
    # WIZARD MODELS TESTS
    # ===================================================================

    def test_dte_commercial_response_wizard_accountant(self):
        """Test: Accountant can create/use DTE commercial response wizards."""
        wizard = self.env['dte.commercial.response.wizard'].with_user(self.user_accountant).create({
            'response_type': 'accept',
        })
        self.assertTrue(wizard, "Accountant can create DTE commercial response wizards")

    def test_dte_commercial_response_wizard_basic_user_cannot_create(self):
        """Test: Basic user cannot create DTE commercial response wizards."""
        # Basic users should NOT have access to DTE wizards
        with self.assertRaises(AccessError):
            self.env['dte.commercial.response.wizard'].with_user(self.user_basic).create({
                'response_type': 'accept',
            })

    def test_dte_service_integration_manager_read_only(self):
        """Test: Manager can read but not write DTE service integrations."""
        # System creates integration (only system should)
        integration = self.env['dte.service.integration'].sudo().create({
            'name': 'Test Service',
        })
        
        # Manager can read (perm_read=1)
        result = self.env['dte.service.integration'].with_user(self.user_manager).search([
            ('id', '=', integration.id)
        ])
        self.assertTrue(result, "Manager can read DTE service integration")
        
        # Manager cannot write (perm_write=0)
        with self.assertRaises(AccessError):
            integration.with_user(self.user_manager).write({
                'name': 'Updated',
            })

    # ===================================================================
    # RCV INTEGRATION TESTS
    # ===================================================================

    def test_rcv_integration_accountant_read(self):
        """Test: Accountant can read RCV integrations."""
        # System creates RCV integration
        rcv = self.env['l10n_cl.rcv.integration'].sudo().create({
            'name': 'Test RCV',
        })
        
        # Accountant can read (perm_read=1)
        result = self.env['l10n_cl.rcv.integration'].with_user(self.user_accountant).search([
            ('id', '=', rcv.id)
        ])
        self.assertTrue(result, "Accountant can read RCV integration")

    def test_rcv_integration_basic_user_cannot_read(self):
        """Test: Basic user cannot read RCV integrations."""
        # RCV integration is restricted to accounting users only
        with self.assertRaises(AccessError):
            self.env['l10n_cl.rcv.integration'].with_user(self.user_basic).search([])

    # ===================================================================
    # RABBITMQ HELPER TESTS (SYSTEM ONLY)
    # ===================================================================

    def test_rabbitmq_helper_restricted_manager(self):
        """Test: Even manager cannot access RabbitMQ helper."""
        # RabbitMQ helper is system-only (base.group_system)
        with self.assertRaises(AccessError):
            self.env['rabbitmq.helper'].with_user(self.user_manager).search([])

    def test_rabbitmq_helper_restricted_accountant(self):
        """Test: Accountant cannot access RabbitMQ helper."""
        with self.assertRaises(AccessError):
            self.env['rabbitmq.helper'].with_user(self.user_accountant).search([])

    def test_rabbitmq_helper_restricted_basic_user(self):
        """Test: Basic user cannot access RabbitMQ helper."""
        with self.assertRaises(AccessError):
            self.env['rabbitmq.helper'].with_user(self.user_basic).search([])

    # ===================================================================
    # INTEGRATION TESTS (CROSS-MODEL)
    # ===================================================================

    def test_all_dte_models_have_acl(self):
        """Test: Verify all DTE models have at least one ACL definition."""
        # Get all models in l10n_cl_dte module
        dte_models = [
            'ai.agent.selector',
            'ai.chat.integration',
            'ai.chat.session',
            'ai.chat.wizard',
            'dte.commercial.response.wizard',
            'dte.service.integration',
            'l10n_cl.rcv.integration',
            'rabbitmq.helper',
        ]
        
        for model_name in dte_models:
            if model_name not in self.env:
                continue  # Skip if model not installed
            
            # Check if ACL exists
            acls = self.env['ir.model.access'].sudo().search([
                ('model_id.model', '=', model_name)
            ])
            
            self.assertGreater(
                len(acls), 0,
                f"Model {model_name} must have at least one ACL definition"
            )

    def test_no_orphan_acls(self):
        """Test: Verify no ACLs reference non-existent models."""
        # Get all ACLs for l10n_cl_dte
        all_acls = self.env['ir.model.access'].sudo().search([
            ('model_id.model', 'like', 'ai.%'),
        ])
        all_acls |= self.env['ir.model.access'].sudo().search([
            ('model_id.model', 'like', 'dte.%'),
        ])
        all_acls |= self.env['ir.model.access'].sudo().search([
            ('model_id.model', 'like', 'l10n_cl.rcv%'),
        ])
        all_acls |= self.env['ir.model.access'].sudo().search([
            ('model_id.model', '=', 'rabbitmq.helper'),
        ])
        
        for acl in all_acls:
            model_name = acl.model_id.model
            if model_name not in ['ir.model.access', 'ir.model']:
                self.assertIn(
                    model_name, self.env.registry.models,
                    f"ACL {acl.name} references non-existent model {model_name}"
                )
