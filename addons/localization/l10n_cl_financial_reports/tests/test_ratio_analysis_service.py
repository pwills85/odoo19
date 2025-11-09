# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase
from odoo.fields import Date

class TestRatioAnalysisService(TransactionCase):

    def setUp(self, *args, **kwargs):
        super().setUp(*args, **kwargs)
        self.RatioService = self.env['ratio.analysis.service']
        self.AccountMove = self.env['account.move']
        self.AccountMoveLine = self.env['account.move.line']
        
        # Create accounts
        self.income_account = self.env['account.account'].create({
            'name': 'Test Income Account',
            'code': 'INCOME_TEST',
            'account_type': 'income',
            'company_id': self.env.company.id,
        })
        self.expense_account = self.env['account.account'].create({
            'name': 'Test Expense Account',
            'code': 'EXPENSE_TEST',
            'account_type': 'expense',
            'company_id': self.env.company.id,
        })
        
        # Create a posted journal entry
        self.move = self.AccountMove.create({
            'name': 'Test Entry for Ratios',
            'journal_id': self.env['account.journal'].search([('type', '=', 'general')], limit=1).id,
            'date': '2025-07-15',
            'line_ids': [
                (0, 0, {'account_id': self.income_account.id, 'name': 'Sale', 'debit': 0, 'credit': 1000}),
                (0, 0, {'account_id': self.expense_account.id, 'name': 'Cost', 'debit': 400, 'credit': 0}),
            ],
        })
        self.move.action_post()

    def test_get_net_income_orm(self):
        """
        Test that the _get_net_income method, refactored to use the ORM,
        calculates the correct value.
        """
        date_from = Date.to_date('2025-07-01')
        date_to = Date.to_date('2025-07-31')
        
        net_income = self.RatioService._get_net_income(self.env.company, date_from, date_to)
        
        # Expected: 1000 (credit/income) - 400 (debit/expense) = 600
        self.assertAlmostEqual(net_income, 600.0, msg="Net income should be 600")

    def test_get_net_income_orm_no_entries(self):
        """
        Test that the _get_net_income method returns 0 when there are no entries.
        """
        date_from = Date.to_date('2024-01-01')
        date_to = Date.to_date('2024-12-31')
        
        net_income = self.RatioService._get_net_income(self.env.company, date_from, date_to)
        
        self.assertAlmostEqual(net_income, 0.0, msg="Net income should be 0 for a period with no entries")
