# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from datetime import date


class TestKPIDashboardViews(TransactionCase):
    """
    Smoke tests para las vistas del dashboard de KPIs.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Crear compañía de prueba
        cls.company = cls.env['res.company'].create({
            'name': 'Test Company Dashboard',
            'currency_id': cls.env.ref('base.CLP').id,
        })

        # Crear un F29 de prueba
        cls.f29 = cls.env['l10n_cl.f29'].create({
            'company_id': cls.company.id,
            'period_date': '2024-01-01',
            'state': 'confirmed',
            'ventas_afectas': 10000000.0,
            'compras_afectas': 6000000.0,
            'ppm_mes': 200000.0,
        })

    def test_01_dashboard_creation(self):
        """Test que se puede crear un dashboard"""
        dashboard = self.env['l10n_cl.kpi.dashboard'].create({
            'company_id': self.company.id,
            'date_from': date(2024, 1, 1),
            'date_to': date(2024, 1, 31),
        })

        self.assertTrue(dashboard)
        self.assertEqual(dashboard.company_id, self.company)

    def test_02_dashboard_computes_kpis(self):
        """Test que el dashboard calcula KPIs correctamente"""
        dashboard = self.env['l10n_cl.kpi.dashboard'].create({
            'company_id': self.company.id,
            'date_from': date(2024, 1, 1),
            'date_to': date(2024, 1, 31),
        })

        # Los KPIs deben estar calculados
        self.assertGreater(dashboard.ventas_netas, 0)
        self.assertEqual(dashboard.ventas_netas, 10000000.0)

    def test_03_action_refresh_kpis(self):
        """Test que la acción de refrescar KPIs funciona"""
        dashboard = self.env['l10n_cl.kpi.dashboard'].create({
            'company_id': self.company.id,
            'date_from': date(2024, 1, 1),
            'date_to': date(2024, 1, 31),
        })

        result = dashboard.action_refresh_kpis()
        self.assertEqual(result['type'], 'ir.actions.client')

    def test_04_action_view_f29_records(self):
        """Test que la acción para ver F29 funciona"""
        dashboard = self.env['l10n_cl.kpi.dashboard'].create({
            'company_id': self.company.id,
            'date_from': date(2024, 1, 1),
            'date_to': date(2024, 1, 31),
        })

        result = dashboard.action_view_f29_records()
        self.assertEqual(result['type'], 'ir.actions.act_window')
        self.assertEqual(result['res_model'], 'l10n_cl.f29')

    def test_05_action_open_dashboard(self):
        """Test que la acción para abrir dashboard funciona"""
        result = self.env['l10n_cl.kpi.dashboard'].action_open_dashboard()
        self.assertEqual(result['type'], 'ir.actions.act_window')
        self.assertEqual(result['res_model'], 'l10n_cl.kpi.dashboard')

    def test_06_dashboard_view_form_loads(self):
        """Test que la vista form se carga correctamente"""
        view = self.env.ref('l10n_cl_financial_reports.view_l10n_cl_kpi_dashboard_form')
        self.assertTrue(view)
        self.assertEqual(view.model, 'l10n_cl.kpi.dashboard')

    def test_07_dashboard_view_kanban_loads(self):
        """Test que la vista kanban se carga correctamente"""
        view = self.env.ref('l10n_cl_financial_reports.view_l10n_cl_kpi_dashboard_kanban')
        self.assertTrue(view)
        self.assertEqual(view.model, 'l10n_cl.kpi.dashboard')

    def test_08_dashboard_view_graph_loads(self):
        """Test que la vista graph se carga correctamente"""
        view = self.env.ref('l10n_cl_financial_reports.view_l10n_cl_kpi_dashboard_graph')
        self.assertTrue(view)
        self.assertEqual(view.model, 'l10n_cl.kpi.dashboard')

    def test_09_dashboard_view_pivot_loads(self):
        """Test que la vista pivot se carga correctamente"""
        view = self.env.ref('l10n_cl_financial_reports.view_l10n_cl_kpi_dashboard_pivot')
        self.assertTrue(view)
        self.assertEqual(view.model, 'l10n_cl.kpi.dashboard')

    def test_10_dashboard_view_tree_loads(self):
        """Test que la vista tree se carga correctamente"""
        view = self.env.ref('l10n_cl_financial_reports.view_l10n_cl_kpi_dashboard_tree')
        self.assertTrue(view)
        self.assertEqual(view.model, 'l10n_cl.kpi.dashboard')

    def test_11_dashboard_action_exists(self):
        """Test que la acción del dashboard existe"""
        action = self.env.ref('l10n_cl_financial_reports.action_l10n_cl_kpi_dashboard')
        self.assertTrue(action)
        self.assertEqual(action.res_model, 'l10n_cl.kpi.dashboard')

    def test_12_dashboard_menu_exists(self):
        """Test que el menú del dashboard existe"""
        menu = self.env.ref('l10n_cl_financial_reports.menu_l10n_cl_kpi_dashboard')
        self.assertTrue(menu)
        self.assertEqual(menu.action.res_model, 'l10n_cl.kpi.dashboard')
