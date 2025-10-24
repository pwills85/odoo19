# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError, UserError
import json


class TestFinancialDashboardWizard(TransactionCase):

    def setUp(self):
        super().setUp()

        # Create a test user
        self.test_user = self.env['res.users'].create({
            'name': 'Test User',
            'login': 'test_user',
            'email': 'test@example.com',
            'groups_id': [(6, 0, [self.env.ref('account.group_account_manager').id])]
        })

        # Create a test dashboard
        self.dashboard = self.env['financial.dashboard.layout'].create({
            'name': 'Test Dashboard',
            'user_id': self.test_user.id,
            'description': 'Dashboard for testing',
            'layout_config': json.dumps({
                'widgets': [],
                'grid_options': {'columns': 12, 'margin': 10}
            })
        })

        # Create a test widget template
        self.widget_template = self.env['financial.dashboard.widget'].create({
            'name': 'Test KPI Widget',
            'widget_type': 'kpi',
            'data_service_model': 'account.move',
            'data_service_method': 'get_test_data',
            'default_size_w': 4,
            'default_size_h': 2,
        })

    def test_wizard_creation(self):
        """Test basic wizard creation and field validation"""
        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Test Widget',
            'widget_template_id': self.widget_template.id,
            'dashboard_id': self.dashboard.id,
            'position_x': 0,
            'position_y': 0,
            'size_w': 4,
            'size_h': 2,
        })

        self.assertTrue(wizard)
        self.assertEqual(wizard.title, 'Test Widget')
        self.assertEqual(wizard.widget_type, 'kpi')

    def test_wizard_onchange_template(self):
        """Test onchange method when template is selected"""
        wizard = self.env['financial.dashboard.add.widget.wizard'].new({
            'dashboard_id': self.dashboard.id,
        })

        wizard.widget_template_id = self.widget_template
        wizard._onchange_widget_template_id()

        self.assertEqual(wizard.title, self.widget_template.name)
        self.assertEqual(wizard.size_w, self.widget_template.default_size_w)
        self.assertEqual(wizard.size_h, self.widget_template.default_size_h)

    def test_wizard_validation_constraints(self):
        """Test wizard field validation constraints"""
        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Test Widget',
            'widget_template_id': self.widget_template.id,
            'dashboard_id': self.dashboard.id,
            'position_x': 0,
            'position_y': 0,
            'size_w': 15,  # Invalid width > 12
            'size_h': 2,
        })

        with self.assertRaises(ValidationError):
            wizard._check_widget_size()

    def test_wizard_json_validation(self):
        """Test JSON configuration validation"""
        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Test Widget',
            'widget_template_id': self.widget_template.id,
            'dashboard_id': self.dashboard.id,
            'config_data': 'invalid json',
        })

        with self.assertRaises(ValidationError):
            wizard._check_config_data()

    def test_widget_config_preparation(self):
        """Test widget configuration preparation"""
        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Test Widget',
            'widget_template_id': self.widget_template.id,
            'dashboard_id': self.dashboard.id,
            'position_x': 2,
            'position_y': 1,
            'size_w': 6,
            'size_h': 3,
            'refresh_interval': 600,
            'config_data': '{"custom_option": "test_value"}',
        })

        config = wizard._prepare_widget_config()

        self.assertEqual(config['title'], 'Test Widget')
        self.assertEqual(config['widget_type'], 'kpi')
        self.assertEqual(config['position']['x'], 2)
        self.assertEqual(config['position']['y'], 1)
        self.assertEqual(config['size']['w'], 6)
        self.assertEqual(config['size']['h'], 3)
        self.assertEqual(config['refresh_interval'], 600)
        self.assertEqual(config['custom_option'], 'test_value')

    def test_add_widget_to_dashboard(self):
        """Test adding widget to dashboard"""
        initial_config = json.loads(self.dashboard.layout_config)
        initial_widget_count = len(initial_config.get('widgets', []))

        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'New Test Widget',
            'widget_template_id': self.widget_template.id,
            'dashboard_id': self.dashboard.id,
            'position_x': 0,
            'position_y': 0,
            'size_w': 4,
            'size_h': 2,
        })

        result = wizard.action_add_widget()

        # Refresh dashboard from database
        self.dashboard.refresh()

        # Check that widget was added to configuration
        updated_config = json.loads(self.dashboard.layout_config)
        updated_widget_count = len(updated_config.get('widgets', []))

        self.assertEqual(updated_widget_count, initial_widget_count + 1)
        self.assertEqual(result['type'], 'ir.actions.client')
        self.assertEqual(result['tag'], 'reload')

    def test_add_widget_validation_errors(self):
        """Test validation errors when adding widgets"""
        # Test missing dashboard
        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Test Widget',
            'widget_template_id': self.widget_template.id,
        })

        with self.assertRaises(UserError):
            wizard.action_add_widget()

        # Test missing widget template
        wizard2 = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Test Widget',
            'dashboard_id': self.dashboard.id,
        })

        with self.assertRaises(UserError):
            wizard2.action_add_widget()

    def test_dashboard_default_creation(self):
        """Test creating a default dashboard"""
        dashboard = self.env['financial.dashboard.layout'].create_default_dashboard(
            user_id=self.test_user.id
        )

        self.assertTrue(dashboard.is_default)
        self.assertEqual(dashboard.user_id, self.test_user)
        self.assertEqual(dashboard.name, 'Dashboard Principal')

        # Test that creating another default dashboard returns the existing one
        dashboard2 = self.env['financial.dashboard.layout'].create_default_dashboard(
            user_id=self.test_user.id
        )

        self.assertEqual(dashboard, dashboard2)

    def test_dashboard_widget_count(self):
        """Test dashboard widget count calculation"""
        # Initially no widgets
        self.assertEqual(self.dashboard.widget_count, 0)

        # Add a widget through wizard
        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Count Test Widget',
            'widget_template_id': self.widget_template.id,
            'dashboard_id': self.dashboard.id,
        })

        wizard.action_add_widget()
        self.dashboard.refresh()

        # Check widget count increased
        self.assertEqual(self.dashboard.widget_count, 1)

    def test_dashboard_action_add_widget(self):
        """Test dashboard action to open wizard"""
        result = self.dashboard.action_add_widget()

        self.assertEqual(result['type'], 'ir.actions.act_window')
        self.assertEqual(result['res_model'], 'financial.dashboard.add.widget.wizard')
        self.assertEqual(result['view_mode'], 'form')
        self.assertEqual(result['target'], 'new')
        self.assertEqual(result['context']['default_dashboard_id'], self.dashboard.id)

    def test_get_available_widget_types(self):
        """Test getting available widget types"""
        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Test Widget',
            'dashboard_id': self.dashboard.id,
        })

        available_types = wizard.get_available_widget_types()

        self.assertIn(self.widget_template, available_types)

    def test_wizard_preview_functionality(self):
        """Test wizard preview functionality"""
        wizard = self.env['financial.dashboard.add.widget.wizard'].create({
            'title': 'Preview Test Widget',
            'widget_template_id': self.widget_template.id,
            'dashboard_id': self.dashboard.id,
        })

        result = wizard.action_preview_widget()

        self.assertEqual(result['type'], 'ir.actions.act_window')
        self.assertEqual(result['res_model'], 'financial.dashboard.add.widget.wizard')
        self.assertEqual(result['target'], 'new')
        self.assertIn('sample_data', result['context'])
        self.assertIn('widget_config', result['context'])

    def test_dashboard_stats_retrieval(self):
        """Test dashboard statistics retrieval"""
        wizard_model = self.env['financial.dashboard.add.widget.wizard']
        stats = wizard_model.get_dashboard_stats(self.dashboard.id)

        self.assertIn('total_widgets', stats)
        self.assertIn('last_modified', stats)
        self.assertIn('created_by', stats)
        self.assertEqual(stats['total_widgets'], 0)
