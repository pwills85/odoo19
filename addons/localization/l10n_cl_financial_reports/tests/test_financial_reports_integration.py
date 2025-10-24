# -*- coding: utf-8 -*-
"""
Tests de integración avanzada para account_financial_report
Siguiendo documentación oficial Odoo 18 Testing Framework
FASE 3: TESTING EXHAUSTIVO - Tests de integración
"""

from odoo.tests import TransactionCase, tagged
from odoo import fields
from dateutil.relativedelta import relativedelta


@tagged('post_install', 'account_financial_report', 'integration')  
class TestAccountFinancialReportIntegration(TransactionCase):
    """
    Tests de integración para módulo account_financial_report
    Verifica integración con otros módulos y servicios
    """
    
    def setUp(self):
        super().setUp()
        
        self.company = self.env.user.company_id
        
        # Configurar datos para tests de integración
        self.partner = self.env['res.partner'].create({
            'name': 'Integration Test Partner',
            'is_company': True,
            'email': 'integration@test.com',
        })
        
        # Crear cuentas necesarias
        self.account_receivable = self.env['account.account'].create({
            'name': 'Integration Receivable',
            'code': 'INT.REC',
            'account_type': 'asset_receivable',
            'company_id': self.company.id,
        })
        
        self.account_revenue = self.env['account.account'].create({
            'name': 'Integration Revenue',
            'code': 'INT.REV',
            'account_type': 'income',
            'company_id': self.company.id,
        })
        
        # Journal de ventas
        self.sales_journal = self.env['account.journal'].create({
            'name': 'Integration Sales',
            'code': 'INTS',
            'type': 'sale',
            'company_id': self.company.id,
        })
        
    def test_integration_with_account_module(self):
        """
        Test integración con módulo account nativo
        """
        # Crear factura en módulo account
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'journal_id': self.sales_journal.id,
            'invoice_date': fields.Date.today(),
            'invoice_line_ids': [
                (0, 0, {
                    'name': 'Integration Test Product',
                    'quantity': 1,
                    'price_unit': 2000.0,
                    'account_id': self.account_revenue.id,
                }),
            ],
        })
        invoice.action_post()
        
        # Verificar que aparece en reportes financieros
        trial_balance = self.env['account.trial.balance'].create({
            'name': 'Integration Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today(),
            'date_to': fields.Date.today(),
        })
        
        trial_balance.action_compute_balance()
        
        # Verificar que la factura impacta el reporte
        revenue_line = trial_balance.line_ids.filtered(
            lambda l: l.account_id == self.account_revenue
        )
        self.assertTrue(revenue_line, "Línea de ingresos debe aparecer")
        self.assertEqual(revenue_line.period_credit, 2000.0,
                        "Crédito debe ser 2000")
        
    def test_integration_with_analytic_accounting(self):
        """
        Test integración con contabilidad analítica
        """
        # Crear cuenta analítica
        analytic_account = self.env['account.analytic.account'].create({
            'name': 'Integration Analytic',
            'company_id': self.company.id,
        })
        
        # Crear movimiento con distribución analítica
        move = self.env['account.move'].create({
            'move_type': 'entry',
            'date': fields.Date.today(),
            'journal_id': self.sales_journal.id,
            'line_ids': [
                (0, 0, {
                    'name': 'Analytic Test',
                    'account_id': self.account_receivable.id,
                    'analytic_account_id': analytic_account.id,
                    'debit': 1500.0,
                    'credit': 0.0,
                }),
                (0, 0, {
                    'name': 'Analytic Test',
                    'account_id': self.account_revenue.id,
                    'analytic_account_id': analytic_account.id,
                    'debit': 0.0,
                    'credit': 1500.0,
                }),
            ],
        })
        move.action_post()
        
        # Verificar en reporte analítico si existe
        if self.env.get('analytic.cost.benefit.report'):
            analytic_report = self.env['analytic.cost.benefit.report'].create({
                'name': 'Analytic Integration Test',
                'company_id': self.company.id,
                'date_from': fields.Date.today(),
                'date_to': fields.Date.today(),
                'analytic_account_ids': [(6, 0, [analytic_account.id])],
            })
            
            analytic_report.action_compute_data()
            self.assertEqual(analytic_report.state, 'computed',
                           "Reporte analítico debe computarse")
            
    def test_integration_with_multi_currency(self):
        """
        Test integración con multi-moneda
        """
        # Crear moneda de prueba
        usd = self.env.ref('base.USD')
        
        # Configurar tasa de cambio
        self.env['res.currency.rate'].create({
            'currency_id': usd.id,
            'company_id': self.company.id,
            'rate': 0.0012,  # 1 USD = 800 CLP aprox
            'name': fields.Date.today(),
        })
        
        # Crear factura en USD
        invoice_usd = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'journal_id': self.sales_journal.id,
            'currency_id': usd.id,
            'invoice_date': fields.Date.today(),
            'invoice_line_ids': [
                (0, 0, {
                    'name': 'USD Product',
                    'quantity': 1,
                    'price_unit': 100.0,  # 100 USD
                    'account_id': self.account_revenue.id,
                }),
            ],
        })
        invoice_usd.action_post()
        
        # Verificar conversión en reportes
        trial_balance = self.env['account.trial.balance'].create({
            'name': 'Multi Currency Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today(),
            'date_to': fields.Date.today(),
        })
        
        trial_balance.action_compute_balance()
        
        # Verificar que se convierte a moneda de la empresa
        revenue_line = trial_balance.line_ids.filtered(
            lambda l: l.account_id == self.account_revenue
        )
        self.assertTrue(revenue_line, "Debe haber línea de ingresos")
        # El monto debe estar en moneda de la empresa (convertido)
        self.assertGreater(revenue_line.period_credit, 100.0,
                          "Monto debe estar convertido a moneda empresa")
        
    def test_integration_with_partner_management(self):
        """
        Test integración con gestión de partners
        """
        # Crear múltiples partners
        partners = self.env['res.partner'].create([
            {
                'name': 'Partner A',
                'is_company': True,
                'customer_rank': 1,
            },
            {
                'name': 'Partner B', 
                'is_company': True,
                'supplier_rank': 1,
            },
        ])
        
        # Crear facturas para cada partner
        for i, partner in enumerate(partners):
            invoice = self.env['account.move'].create({
                'move_type': 'out_invoice' if partner.customer_rank else 'in_invoice',
                'partner_id': partner.id,
                'journal_id': self.sales_journal.id,
                'invoice_date': fields.Date.today() - relativedelta(days=i*10),
                'invoice_line_ids': [
                    (0, 0, {
                        'name': f'Product for {partner.name}',
                        'quantity': 1,
                        'price_unit': (i + 1) * 500.0,
                        'account_id': self.account_revenue.id,
                    }),
                ],
            })
            invoice.action_post()
            
        # Test reporte de saldos por partner
        aged_balance = self.env['account.aged.partner.balance'].create({
            'name': 'Partner Integration Test',
            'company_id': self.company.id,
            'date_at': fields.Date.today(),
            'result_selection': 'customer',
        })
        
        aged_balance.action_compute_data()
        
        # Verificar que ambos partners aparecen
        partner_lines = aged_balance.line_ids.filtered(
            lambda l: l.partner_id in partners
        )
        self.assertTrue(partner_lines, "Debe haber líneas de partners")
        
    def test_integration_with_project_module(self):
        """
        Test integración con módulo project si está disponible
        """
        if not self.env.get('project.project'):
            self.skipTest("Módulo project no disponible")
            
        # Crear proyecto
        project = self.env['project.project'].create({
            'name': 'Integration Test Project',
        })
        
        # Si existe reporte de proyectos, probarlo
        if self.env.get('project.profitability.report'):
            profit_report = self.env['project.profitability.report'].create({
                'name': 'Project Integration Test',
                'company_id': self.company.id,
                'date_from': fields.Date.today() - relativedelta(months=1),
                'date_to': fields.Date.today(),
                'project_ids': [(6, 0, [project.id])],
            })
            
            profit_report.action_compute_data()
            self.assertEqual(profit_report.state, 'computed',
                           "Reporte de rentabilidad debe computarse")
            
    def test_integration_with_budget_module(self):
        """
        Test integración con módulo de presupuestos
        """
        if not self.env.get('crossovered.budget'):
            self.skipTest("Módulo budget no disponible")
            
        # Si existe reporte de comparación presupuestaria
        if self.env.get('budget.comparison.report'):
            budget_report = self.env['budget.comparison.report'].create({
                'name': 'Budget Integration Test',
                'company_id': self.company.id,
                'date_from': fields.Date.today() - relativedelta(months=1),
                'date_to': fields.Date.today(),
            })
            
            budget_report.action_compute_data()
            self.assertEqual(budget_report.state, 'computed',
                           "Reporte presupuestario debe computarse")
            
    def test_integration_financial_kpi_calculation(self):
        """
        Test integración con cálculo de KPIs financieros
        """
        # Crear datos financieros base
        moves_data = [
            {
                'name': 'Revenue Transaction',
                'account': self.account_revenue,
                'credit': 5000.0,
                'debit': 0.0,
            },
            {
                'name': 'Receivable Transaction',
                'account': self.account_receivable,
                'credit': 0.0,
                'debit': 5000.0,
            },
        ]
        
        for data in moves_data:
            move = self.env['account.move'].create({
                'move_type': 'entry',
                'date': fields.Date.today(),
                'journal_id': self.sales_journal.id,
                'line_ids': [
                    (0, 0, {
                        'name': data['name'],
                        'account_id': data['account'].id,
                        'debit': data['debit'],
                        'credit': data['credit'],
                    }),
                ],
            })
            move.action_post()
            
        # Test cálculo de KPIs si existe
        if self.env.get('financial.report.kpi'):
            kpi_report = self.env['financial.report.kpi'].create({
                'name': 'KPI Integration Test',
                'company_id': self.company.id,
                'date_from': fields.Date.today(),
                'date_to': fields.Date.today(),
            })
            
            kpi_report.action_compute_kpis()
            self.assertEqual(kpi_report.state, 'computed',
                           "KPIs deben computarse")
            
    def test_integration_ratio_analysis_service(self):
        """
        Test integración con servicio de análisis de ratios
        """
        # Test servicio de análisis de ratios
        if self.env.get('ratio.analysis.service'):
            service = self.env['ratio.analysis.service']
            
            # Computar ratios básicos
            ratios = service.compute_basic_ratios(
                company_id=self.company.id,
                date_from=fields.Date.today() - relativedelta(months=1),
                date_to=fields.Date.today()
            )
            
            self.assertIsInstance(ratios, dict, "Ratios debe ser diccionario")
            
    def test_integration_export_functionality(self):
        """
        Test integración con funcionalidad de exportación
        """
        # Crear reporte para exportar
        trial_balance = self.env['account.trial.balance'].create({
            'name': 'Export Test',
            'company_id': self.company.id,
            'date_from': fields.Date.today(),
            'date_to': fields.Date.today(),
        })
        
        trial_balance.action_compute_balance()
        
        # Test exportación si está disponible
        if hasattr(trial_balance, 'action_export_xlsx'):
            export_result = trial_balance.action_export_xlsx()
            self.assertIsInstance(export_result, dict,
                                "Exportación debe retornar acción")
            
    def test_integration_email_reports(self):
        """
        Test integración con envío de reportes por email
        """
        # Crear reporte
        trial_balance = self.env['account.trial.balance'].create({
            'name': 'Email Test Report',
            'company_id': self.company.id,
            'date_from': fields.Date.today(),
            'date_to': fields.Date.today(),
        })
        
        trial_balance.action_compute_balance()
        
        # Test envío por email si está disponible
        if hasattr(trial_balance, 'action_send_by_email'):
            # Configurar parámetros de email
            email_result = trial_balance.action_send_by_email()
            # Verificar que la acción se ejecuta sin errores
            self.assertIsNotNone(email_result, "Acción de email debe ejecutarse")
            
    def test_integration_dashboard_widgets(self):
        """
        Test integración con widgets de dashboard
        """
        # Test widgets de dashboard financiero si existen
        if self.env.get('financial.dashboard.widget'):
            widget = self.env['financial.dashboard.widget'].create({
                'name': 'Integration Test Widget',
                'widget_type': 'revenue_summary',
                'company_id': self.company.id,
            })
            
            # Test actualización de datos
            if hasattr(widget, 'action_refresh_data'):
                widget.action_refresh_data()
                self.assertTrue(widget.last_update,
                              "Widget debe tener fecha de última actualización")
                
    def test_integration_security_rules(self):
        """
        Test integración con reglas de seguridad
        """
        # Crear usuario con permisos limitados
        user = self.env['res.users'].create({
            'name': 'Limited User',
            'login': 'limited_integration',
            'email': 'limited@test.com',
            'groups_id': [(6, 0, [self.env.ref('base.group_user').id])],
        })
        
        # Test acceso a reportes con usuario limitado
        with self.assertRaises(Exception):
            self.env['account.trial.balance'].with_user(user).create({
                'name': 'Unauthorized Report',
                'company_id': self.company.id,
                'date_from': fields.Date.today(),
                'date_to': fields.Date.today(),
            })
