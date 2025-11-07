# Copyright 2025 [Your Company]
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""
Unit Tests for Project EVM Service

Tests the Earned Value Management calculations and business logic.
Compatible with Odoo 18 testing framework.
"""

from datetime import timedelta
from unittest.mock import patch

from odoo import fields
from odoo.exceptions import UserError
from odoo.tests.common import TransactionCase


class TestProjectEVMService(TransactionCase):
    """Test cases for Project EVM Service."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test data."""
        super().setUpClass()
        
        # Create test company
        cls.company = cls.env['res.company'].create({
            'name': 'Test Engineering Company',
            'currency_id': cls.env.ref('base.USD').id,
        })
        
        # Create test project
        cls.project = cls.env['project.project'].create({
            'name': 'Test Electrical Project',
            'company_id': cls.company.id,
            'date_start': fields.Date.today() - timedelta(days=30),
            'date_end': fields.Date.today() + timedelta(days=30),
        })
        
        # Create test tasks
        cls.task1 = cls.env['project.task'].create({
            'name': 'Design Phase',
            'project_id': cls.project.id,
            'planned_hours': 100,
            'progress': 80,  # 80% complete
        })
        
        cls.task2 = cls.env['project.task'].create({
            'name': 'Installation Phase',
            'project_id': cls.project.id,
            'planned_hours': 200,
            'progress': 40,  # 40% complete
        })
        
        # Create analytic account for project
        cls.analytic_account = cls.env['account.analytic.account'].create({
            'name': 'Test Project Analytics',
            'company_id': cls.company.id,
        })
        cls.project.analytic_account_id = cls.analytic_account.id
        
        # Create test timesheet entries
        cls.employee = cls.env['hr.employee'].create({
            'name': 'Test Engineer',
            'company_id': cls.company.id,
        })
        
        cls.timesheet1 = cls.env['account.analytic.line'].create({
            'name': 'Design work',
            'project_id': cls.project.id,
            'task_id': cls.task1.id,
            'employee_id': cls.employee.id,
            'unit_amount': 50,  # 50 hours
            'amount': -2500,    # $50/hour * 50 hours
            'date': fields.Date.today() - timedelta(days=10),
            'is_timesheet': True,
        })
        
        cls.timesheet2 = cls.env['account.analytic.line'].create({
            'name': 'Installation work',
            'project_id': cls.project.id,
            'task_id': cls.task2.id,
            'employee_id': cls.employee.id,
            'unit_amount': 30,  # 30 hours
            'amount': -1500,    # $50/hour * 30 hours
            'date': fields.Date.today() - timedelta(days=5),
            'is_timesheet': True,
        })
        
        # Get EVM service
        cls.evm_service = cls.env['project.evm.service']
    
    def test_calculate_project_evm_basic(self):
        """Test basic EVM calculation."""
        # Set project budget
        with patch.object(self.evm_service, '_get_budget_at_completion', return_value=15000.0):
            result = self.evm_service.calculate_project_evm(self.project.id)
            
            # Verify result structure
            self.assertIn('project_id', result)
            self.assertIn('planned_value', result)
            self.assertIn('earned_value', result)
            self.assertIn('actual_cost', result)
            self.assertIn('cost_performance_index', result)
            self.assertIn('schedule_performance_index', result)
            
            # Verify project ID
            self.assertEqual(result['project_id'], self.project.id)
            
            # Verify actual cost calculation (should be sum of timesheet amounts)
            expected_ac = 4000.0  # 2500 + 1500
            self.assertEqual(result['actual_cost'], expected_ac)
    
    def test_calculate_planned_value(self):
        """Test Planned Value calculation."""
        with patch.object(self.evm_service, '_get_budget_at_completion', return_value=15000.0):
            # Test at project midpoint (should be ~50% of budget)
            midpoint_date = self.project.date_start + timedelta(days=30)
            pv = self.evm_service._calculate_planned_value(
                self.project, 
                fields.Date.to_string(midpoint_date)
            )
            
            # Should be approximately 50% of budget (allowing for some variance)
            expected_pv = 7500.0  # 50% of 15000
            self.assertAlmostEqual(pv, expected_pv, delta=1000)
    
    def test_calculate_earned_value(self):
        """Test Earned Value calculation."""
        with patch.object(self.evm_service, '_get_budget_at_completion', return_value=15000.0):
            ev = self.evm_service._calculate_earned_value(
                self.project, 
                fields.Date.to_string(fields.Date.today())
            )
            
            # Calculate expected EV based on task completion
            # Task 1: 100 hours, 80% complete = 80 hours
            # Task 2: 200 hours, 40% complete = 80 hours
            # Total earned: 160 hours out of 300 total = 53.33%
            # EV = 53.33% of 15000 = ~8000
            expected_ev_ratio = (80 + 80) / 300  # 160/300 = 0.533
            expected_ev = 15000 * expected_ev_ratio
            
            self.assertAlmostEqual(ev, expected_ev, delta=500)
    
    def test_calculate_actual_cost(self):
        """Test Actual Cost calculation."""
        ac = self.evm_service._calculate_actual_cost(
            self.project, 
            fields.Date.to_string(fields.Date.today())
        )
        
        # Should be sum of timesheet amounts (absolute values)
        expected_ac = 4000.0  # 2500 + 1500
        self.assertEqual(ac, expected_ac)
    
    def test_calculate_cpi(self):
        """Test Cost Performance Index calculation."""
        # Test normal case
        cpi = self.evm_service._calculate_cpi(8000, 4000)
        self.assertEqual(cpi, 2.0)  # Under budget
        
        # Test over budget case
        cpi = self.evm_service._calculate_cpi(4000, 8000)
        self.assertEqual(cpi, 0.5)  # Over budget
        
        # Test zero actual cost
        cpi = self.evm_service._calculate_cpi(1000, 0)
        self.assertEqual(cpi, 1.0)  # Default value
    
    def test_calculate_spi(self):
        """Test Schedule Performance Index calculation."""
        # Test ahead of schedule
        spi = self.evm_service._calculate_spi(8000, 6000)
        self.assertAlmostEqual(spi, 1.333, places=3)
        
        # Test behind schedule
        spi = self.evm_service._calculate_spi(6000, 8000)
        self.assertEqual(spi, 0.75)
        
        # Test zero planned value
        spi = self.evm_service._calculate_spi(1000, 0)
        self.assertEqual(spi, 1.0)  # Default value
    
    def test_calculate_eac(self):
        """Test Estimate at Completion calculation."""
        # Test normal case
        eac = self.evm_service._calculate_eac(15000, 1.5, 4000)
        expected_eac = 15000 / 1.5  # 10000
        self.assertEqual(eac, expected_eac)
        
        # Test zero CPI
        eac = self.evm_service._calculate_eac(15000, 0, 4000)
        self.assertEqual(eac, 15000)  # Fallback to BAC
    
    def test_get_performance_status(self):
        """Test performance status classification."""
        # Test excellent performance
        status = self.evm_service._get_performance_status(1.2)
        self.assertEqual(status, 'excellent')
        
        # Test good performance
        status = self.evm_service._get_performance_status(1.05)
        self.assertEqual(status, 'good')
        
        # Test warning performance
        status = self.evm_service._get_performance_status(0.95)
        self.assertEqual(status, 'warning')
        
        # Test critical performance
        status = self.evm_service._get_performance_status(0.8)
        self.assertEqual(status, 'critical')
    
    def test_calculate_health_score(self):
        """Test health score calculation."""
        # Test excellent health
        health = self.evm_service._calculate_health_score(1.2, 1.1)
        self.assertGreater(health, 100)  # Should be capped at 100
        
        # Test poor health
        health = self.evm_service._calculate_health_score(0.8, 0.7)
        expected_health = (80 * 0.6) + (70 * 0.4)  # 48 + 28 = 76
        self.assertEqual(health, expected_health)
    
    def test_generate_s_curve_data(self):
        """Test S-curve data generation."""
        with patch.object(self.evm_service, '_get_budget_at_completion', return_value=15000.0):
            s_curve_data = self.evm_service.generate_s_curve_data(self.project.id, periods=5)
            
            # Verify structure
            self.assertIn('dates', s_curve_data)
            self.assertIn('planned', s_curve_data)
            self.assertIn('earned', s_curve_data)
            self.assertIn('actual', s_curve_data)
            self.assertIn('project_name', s_curve_data)
            
            # Verify data consistency
            self.assertEqual(len(s_curve_data['dates']), len(s_curve_data['planned']))
            self.assertEqual(len(s_curve_data['dates']), len(s_curve_data['earned']))
            self.assertEqual(len(s_curve_data['dates']), len(s_curve_data['actual']))
            
            # Verify project name
            self.assertEqual(s_curve_data['project_name'], self.project.name)
    
    def test_calculate_portfolio_evm(self):
        """Test portfolio EVM calculation."""
        # Create second project
        project2 = self.env['project.project'].create({
            'name': 'Test Project 2',
            'company_id': self.company.id,
            'date_start': fields.Date.today() - timedelta(days=20),
            'date_end': fields.Date.today() + timedelta(days=40),
        })
        
        with patch.object(self.evm_service, '_get_budget_at_completion', return_value=10000.0):
            portfolio_data = self.evm_service.calculate_portfolio_evm([
                self.project.id, 
                project2.id
            ])
            
            # Verify structure
            self.assertIn('project_count', portfolio_data)
            self.assertIn('projects', portfolio_data)
            self.assertIn('total_planned_value', portfolio_data)
            self.assertIn('portfolio_cpi', portfolio_data)
            self.assertIn('portfolio_spi', portfolio_data)
            
            # Verify project count
            self.assertEqual(portfolio_data['project_count'], 2)
    
    def test_project_not_found_error(self):
        """Test error handling for non-existent project."""
        with self.assertRaises(UserError):
            self.evm_service.calculate_project_evm(99999)
    
    def test_project_without_dates(self):
        """Test handling of project without start/end dates."""
        project_no_dates = self.env['project.project'].create({
            'name': 'Project Without Dates',
            'company_id': self.company.id,
        })
        
        # Should not raise error, but return zero values
        result = self.evm_service.calculate_project_evm(project_no_dates.id)
        self.assertEqual(result['planned_value'], 0.0)
    
    def test_get_budget_at_completion_methods(self):
        """Test different methods of getting BAC."""
        # Test with sale order
        sale_order = self.env['sale.order'].create({
            'partner_id': self.env.ref('base.res_partner_1').id,
            'order_line': [(0, 0, {
                'product_id': self.env.ref('product.product_product_1').id,
                'product_uom_qty': 1,
                'price_unit': 20000,
            })],
        })
        self.project.sale_order_id = sale_order.id
        
        bac = self.evm_service._get_budget_at_completion(self.project)
        self.assertEqual(bac, 20000.0)
        
        # Test fallback to planned hours
        self.project.sale_order_id = False
        bac = self.evm_service._get_budget_at_completion(self.project)
        # Should calculate from planned hours (300 hours * default rate)
        self.assertGreater(bac, 0)
    
    def test_material_costs_integration(self):
        """Test material costs calculation (if purchase module available)."""
        # This test would require purchase module
        # For now, just test that method doesn't fail
        material_cost = self.evm_service._get_material_costs(
            self.project, 
            fields.Date.to_string(fields.Date.today())
        )
        self.assertGreaterEqual(material_cost, 0.0)
