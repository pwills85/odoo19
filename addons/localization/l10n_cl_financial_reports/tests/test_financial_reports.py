# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase, tagged
from datetime import date

@tagged('post_install', '-at_install')
class TestTrialBalanceReport(TransactionCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.TrialBalance = self.env['account.trial.balance']
        self.Account = self.env['account.account']
        self.Move = self.env['account.move']
        self.company = self.env.company

        # Create accounts
        self.account_a = self.Account.create({
            'name': 'Test Account A',
            'code': 'TEST.A',
            'account_type': 'asset_receivable',
            'company_id': self.company.id,
        })
        self.account_b = self.Account.create({
            'name': 'Test Account B',
            'code': 'TEST.B',
            'account_type': 'liability_payable',
            'company_id': self.company.id,
        })

        # Create a move
        self.Move.create({
            'name': 'Test Move',
            'date': date(2025, 7, 15),
            'journal_id': self.env['account.journal'].search([('type', '=', 'general')], limit=1).id,
            'line_ids': [
                (0, 0, {'account_id': self.account_a.id, 'debit': 100, 'credit': 0}),
                (0, 0, {'account_id': self.account_b.id, 'debit': 0, 'credit': 100}),
            ]
        }).action_post()

    def test_trial_balance_computation(self):
        """Test the computation of the trial balance."""
        report = self.TrialBalance.create({
            'name': 'Test Balance',
            'company_id': self.company.id,
            'date_from': date(2025, 7, 1),
            'date_to': date(2025, 7, 31),
        })

        report.action_compute_balance()

        self.assertEqual(report.state, 'computed', "Report should be in 'computed' state.")
        self.assertTrue(report.is_balanced, "Report should be balanced.")
        self.assertEqual(report.total_period_debit, 100, "Total debit should be 100.")
        self.assertEqual(report.total_period_credit, 100, "Total credit should be 100.")
        
        # Check one line
        line_a = report.line_ids.filtered(lambda l: l.account_id == self.account_a)
        self.assertEqual(line_a.ending_balance, 100, "Account A ending balance should be 100.")
