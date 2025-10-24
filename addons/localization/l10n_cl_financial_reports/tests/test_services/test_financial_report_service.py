# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError, UserError
from datetime import date, datetime
from unittest.mock import patch, MagicMock


class TestFinancialReportService(TransactionCase):
    """Test cases for Financial Report Service."""
    
    def setUp(self):
        super().setUp()
        self.service = self.env['financial.report.service']
        self.company = self.env.ref('base.main_company')
        self.currency = self.company.currency_id
        
        # Create test data
        self.account_receivable = self.env['account.account'].create({
            'name': 'Test Receivable',
            'code': '110001',
            'account_type': 'asset_receivable',
            'company_id': self.company.id,
        })
        
        self.account_payable = self.env['account.account'].create({
            'name': 'Test Payable',
            'code': '210001',
            'account_type': 'liability_payable',
            'company_id': self.company.id,
        })
    
    def test_create_financial_report_success(self):
        """Test successful creation of financial report."""
        vals = {
            'name': 'Test Balance Sheet',
            'report_type': 'balance_sheet',
            'date_from': '2024-01-01',
            'date_to': '2024-12-31',
            'company_id': self.company.id,
        }
        
        report = self.service.create(vals)
        
        self.assertEqual(report.name, 'Test Balance Sheet')
        self.assertEqual(report.report_type, 'balance_sheet')
        self.assertEqual(report.company_id, self.company)
        self.assertEqual(report.state, 'draft')
    
    def test_create_financial_report_invalid_dates(self):
        """Test creation with invalid date range."""
        vals = {
            'name': 'Test Report',
            'report_type': 'balance_sheet',
            'date_from': '2024-12-31',
            'date_to': '2024-01-01',  # End date before start date
            'company_id': self.company.id,
        }
        
        with self.assertRaises(ValidationError):
            self.service.create(vals)
    
    def test_compute_balance_sheet(self):
        """Test balance sheet computation."""
        report = self.service.create({
            'name': 'Test Balance Sheet',
            'report_type': 'balance_sheet',
            'date_from': '2024-01-01',
            'date_to': '2024-12-31',
            'company_id': self.company.id,
        })
        
        # Mock the service layer
        with patch.object(self.service, '_balance_sheet_service') as mock_service:
            mock_service.generate_report.return_value = {
                'assets': {'current': 10000, 'non_current': 50000},
                'liabilities': {'current': 5000, 'non_current': 20000},
                'equity': {'total': 35000}
            }
            
            result = report.compute_balance_sheet()
            
            self.assertIn('assets', result)
            self.assertIn('liabilities', result)
            self.assertIn('equity', result)
            self.assertEqual(result['assets']['current'], 10000)
    
    def test_export_to_excel(self):
        """Test Excel export functionality."""
        report = self.service.create({
            'name': 'Test Report',
            'report_type': 'balance_sheet',
            'date_from': '2024-01-01',
            'date_to': '2024-12-31',
            'company_id': self.company.id,
        })
        
        # Compute report first
        report.action_compute()
        
        # Test export
        result = report.export_to_excel()
        
        self.assertIn('type', result)
        self.assertEqual(result['type'], 'ir.actions.act_url')
        self.assertIn('url', result)
    
    def test_state_transitions(self):
        """Test report state transitions."""
        report = self.service.create({
            'name': 'Test Report',
            'report_type': 'balance_sheet',
            'date_from': '2024-01-01',
            'date_to': '2024-12-31',
            'company_id': self.company.id,
        })
        
        # Initial state
        self.assertEqual(report.state, 'draft')
        
        # Compute report
        report.action_compute()
        self.assertEqual(report.state, 'computed')
        
        # Reset to draft
        report.action_reset_to_draft()
        self.assertEqual(report.state, 'draft')
    
    def test_company_security(self):
        """Test multi-company security."""
        # Create another company
        other_company = self.env['res.company'].create({
            'name': 'Other Company',
            'currency_id': self.currency.id,
        })
        
        # Create report for other company
        report = self.service.create({
            'name': 'Other Company Report',
            'report_type': 'balance_sheet',
            'date_from': '2024-01-01',
            'date_to': '2024-12-31',
            'company_id': other_company.id,
        })
        
        # Switch to main company context
        report_main_company = report.with_company(self.company)
        
        # Should not be able to access other company's report
        with self.assertRaises(Exception):
            report_main_company.compute_balance_sheet()
    
    def test_performance_large_dataset(self):
        """Test performance with large dataset."""
        # Create multiple accounts
        accounts = []
        for i in range(100):
            account = self.env['account.account'].create({
                'name': f'Test Account {i}',
                'code': f'1100{i:02d}',
                'account_type': 'asset_current',
                'company_id': self.company.id,
            })
            accounts.append(account)
        
        report = self.service.create({
            'name': 'Performance Test Report',
            'report_type': 'balance_sheet',
            'date_from': '2024-01-01',
            'date_to': '2024-12-31',
            'company_id': self.company.id,
        })
        
        # Measure computation time
        start_time = datetime.now()
        report.action_compute()
        end_time = datetime.now()
        
        computation_time = (end_time - start_time).total_seconds()
        
        # Should complete within reasonable time (5 seconds)
        self.assertLess(computation_time, 5.0)
    
    def test_error_handling(self):
        """Test error handling in service methods."""
        report = self.service.create({
            'name': 'Error Test Report',
            'report_type': 'balance_sheet',
            'date_from': '2024-01-01',
            'date_to': '2024-12-31',
            'company_id': self.company.id,
        })
        
        # Mock service to raise exception
        with patch.object(self.service, '_balance_sheet_service') as mock_service:
            mock_service.generate_report.side_effect = Exception("Database error")
            
            with self.assertRaises(UserError):
                report.compute_balance_sheet()
            
            # Report should be in error state
            self.assertEqual(report.state, 'error')
    
    def test_caching_mechanism(self):
        """Test report caching mechanism."""
        report = self.service.create({
            'name': 'Cache Test Report',
            'report_type': 'balance_sheet',
            'date_from': '2024-01-01',
            'date_to': '2024-12-31',
            'company_id': self.company.id,
        })
        
        # First computation
        result1 = report.compute_balance_sheet()
        
        # Second computation should use cache
        with patch.object(self.service, '_balance_sheet_service') as mock_service:
            result2 = report.compute_balance_sheet()
            
            # Service should not be called again
            mock_service.generate_report.assert_not_called()
            
            # Results should be identical
            self.assertEqual(result1, result2)
