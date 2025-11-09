# -*- coding: utf-8 -*-
"""
Tests de integración para el servicio financiero con datos reales
"""
from odoo.tests import TransactionCase, tagged
from datetime import datetime, timedelta
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'financial_report')
class TestFinancialServiceIntegration(TransactionCase):
    """Test de integración del servicio financiero con datos reales"""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Obtener compañía de prueba
        cls.company = cls.env.company
        
        # Servicio financiero
        cls.financial_service = cls.env['financial.report.service']
        
        # Fechas de prueba
        cls.date_to = datetime.now().date()
        cls.date_from = (datetime.now() - timedelta(days=365)).date()
        
        # Crear algunos datos de prueba si no existen
        cls._create_test_data()
    
    @classmethod
    def _create_test_data(cls):
        """Crea datos de prueba mínimos si no existen movimientos"""
        AccountMove = cls.env['account.move']
        
        # Verificar si ya hay datos
        existing_moves = AccountMove.search([
            ('company_id', '=', cls.company.id),
            ('state', '=', 'posted'),
            ('date', '>=', cls.date_from),
            ('date', '<=', cls.date_to)
        ], limit=1)
        
        if not existing_moves:
            _logger.info("Creando datos de prueba para tests de servicio financiero")
            
            # Crear factura de venta de prueba
            invoice = AccountMove.create({
                'move_type': 'out_invoice',
                'partner_id': cls.env.ref('base.res_partner_1').id,
                'invoice_date': cls.date_to,
                'date': cls.date_to,
                'invoice_line_ids': [(0, 0, {
                    'name': 'Servicio de prueba',
                    'quantity': 1,
                    'price_unit': 1000000,  # 1 millón CLP
                })]
            })
            invoice.action_post()
            
            # Crear factura de compra de prueba
            bill = AccountMove.create({
                'move_type': 'in_invoice',
                'partner_id': cls.env.ref('base.res_partner_2').id,
                'invoice_date': cls.date_to,
                'date': cls.date_to,
                'invoice_line_ids': [(0, 0, {
                    'name': 'Compra de prueba',
                    'quantity': 1,
                    'price_unit': 500000,  # 500 mil CLP
                })]
            })
            bill.action_post()
    
    def test_01_get_dashboard_kpis(self):
        """Test obtención de KPIs del dashboard"""
        filters = {
            'dateFrom': self.date_from.strftime('%Y-%m-%d'),
            'dateTo': self.date_to.strftime('%Y-%m-%d'),
            'companyId': self.company.id,
        }
        
        kpis = self.financial_service.get_dashboard_kpis(self.company.id, filters)
        
        # Verificar estructura
        self.assertIsInstance(kpis, list)
        self.assertGreater(len(kpis), 0)
        
        # Verificar KPIs básicos
        kpi_ids = [kpi['id'] for kpi in kpis]
        self.assertIn('total_revenue', kpi_ids)
        self.assertIn('net_profit', kpi_ids)
        self.assertIn('current_ratio', kpi_ids)
        
        # Verificar estructura de cada KPI
        for kpi in kpis:
            self.assertIn('name', kpi)
            self.assertIn('value', kpi)
            self.assertIn('formatted_value', kpi)
            self.assertIn('trend', kpi)
            self.assertIn('icon', kpi)
            self.assertIn('color', kpi)
            
        _logger.info(f"KPIs obtenidos: {len(kpis)}")
    
    def test_02_get_chart_data(self):
        """Test obtención de datos para gráficos"""
        filters = {
            'dateFrom': self.date_from.strftime('%Y-%m-%d'),
            'dateTo': self.date_to.strftime('%Y-%m-%d'),
            'comparison': 'month',
        }
        
        chart_data = self.financial_service.get_chart_data(self.company.id, filters)
        
        # Verificar estructura principal
        self.assertIn('revenue', chart_data)
        self.assertIn('expenses', chart_data)
        self.assertIn('cashFlow', chart_data)
        self.assertIn('ratios', chart_data)
        
        # Verificar datos de ingresos
        revenue_data = chart_data['revenue']
        self.assertIn('labels', revenue_data)
        self.assertIn('datasets', revenue_data)
        self.assertIsInstance(revenue_data['labels'], list)
        self.assertIsInstance(revenue_data['datasets'], list)
        
        _logger.info(f"Períodos en gráfico: {len(revenue_data['labels'])}")
    
    def test_03_calculate_financial_ratios(self):
        """Test cálculo de ratios financieros"""
        ratios = self.financial_service.calculate_financial_ratios(
            self.company.id,
            self.date_from.strftime('%Y-%m-%d'),
            self.date_to.strftime('%Y-%m-%d')
        )
        
        # Verificar categorías
        self.assertIn('liquidity', ratios)
        self.assertIn('leverage', ratios)
        self.assertIn('profitability', ratios)
        self.assertIn('efficiency', ratios)
        
        # Verificar ratios de liquidez
        liquidity = ratios['liquidity']
        self.assertIn('current_ratio', liquidity)
        self.assertIn('quick_ratio', liquidity)
        self.assertIn('cash_ratio', liquidity)
        
        # Verificar que los valores son numéricos
        for category in ratios.values():
            for ratio_value in category.values():
                self.assertIsInstance(ratio_value, (int, float))
                
        _logger.info(f"Ratios calculados: {list(ratios.keys())}")
    
    def test_04_export_to_excel(self):
        """Test exportación a Excel"""
        filters = {
            'dateFrom': self.date_from.strftime('%Y-%m-%d'),
            'dateTo': self.date_to.strftime('%Y-%m-%d'),
            'companyId': self.company.id,
        }
        
        # Obtener datos del dashboard
        dashboard_data = {
            'kpis': self.financial_service.get_dashboard_kpis(self.company.id, filters),
            'chartData': self.financial_service.get_chart_data(self.company.id, filters),
            'ratios': self.financial_service.calculate_financial_ratios(
                self.company.id,
                filters['dateFrom'],
                filters['dateTo']
            )
        }
        
        # Exportar a Excel
        excel_file = self.financial_service.export_dashboard_to_excel(dashboard_data, filters)
        
        # Verificar que se generó el archivo
        self.assertIsNotNone(excel_file)
        self.assertIsInstance(excel_file, bytes)
        self.assertGreater(len(excel_file), 0)
        
        _logger.info(f"Archivo Excel generado: {len(excel_file)} bytes")
    
    def test_05_performance_with_large_dataset(self):
        """Test de performance con dataset grande"""
        import time
        
        filters = {
            'dateFrom': self.date_from.strftime('%Y-%m-%d'),
            'dateTo': self.date_to.strftime('%Y-%m-%d'),
            'companyId': self.company.id,
        }
        
        # Medir tiempo de KPIs
        start_time = time.time()
        kpis = self.financial_service.get_dashboard_kpis(self.company.id, filters)
        kpi_time = time.time() - start_time
        
        # Medir tiempo de gráficos
        start_time = time.time()
        charts = self.financial_service.get_chart_data(self.company.id, filters)
        chart_time = time.time() - start_time
        
        # Medir tiempo de ratios
        start_time = time.time()
        ratios = self.financial_service.calculate_financial_ratios(
            self.company.id,
            filters['dateFrom'],
            filters['dateTo']
        )
        ratio_time = time.time() - start_time
        
        # Verificar tiempos aceptables (menos de 2 segundos cada uno)
        self.assertLess(kpi_time, 2.0, f"KPIs tardaron {kpi_time:.2f}s")
        self.assertLess(chart_time, 2.0, f"Charts tardaron {chart_time:.2f}s")
        self.assertLess(ratio_time, 2.0, f"Ratios tardaron {ratio_time:.2f}s")
        
        _logger.info(f"Performance - KPIs: {kpi_time:.2f}s, Charts: {chart_time:.2f}s, Ratios: {ratio_time:.2f}s")
    
    def test_06_data_consistency(self):
        """Test consistencia de datos entre diferentes métodos"""
        filters = {
            'dateFrom': self.date_from.strftime('%Y-%m-%d'),
            'dateTo': self.date_to.strftime('%Y-%m-%d'),
            'companyId': self.company.id,
        }
        
        # Obtener KPIs
        kpis = self.financial_service.get_dashboard_kpis(self.company.id, filters)
        kpi_dict = {kpi['id']: kpi['value'] for kpi in kpis}
        
        # Obtener ratios
        ratios = self.financial_service.calculate_financial_ratios(
            self.company.id,
            filters['dateFrom'],
            filters['dateTo']
        )
        
        # Verificar consistencia de ratio de liquidez
        if 'current_ratio' in kpi_dict and 'current_ratio' in ratios.get('liquidity', {}):
            self.assertAlmostEqual(
                kpi_dict['current_ratio'],
                ratios['liquidity']['current_ratio'],
                places=2,
                msg="Ratio de liquidez inconsistente entre KPIs y ratios"
            )
        
        _logger.info("Consistencia de datos verificada")
