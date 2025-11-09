# -*- coding: utf-8 -*-

"""
Tests Automatización Indicadores Económicos - P0-4
===================================================

Verificar:
- Cron job se crea correctamente
- Fetch API maneja respuesta exitosa
- Fetch API maneja fallo y ejecuta reintentos
- Wizard importación CSV funciona
- Idempotencia del cron
"""

from odoo.tests import tagged, TransactionCase
from unittest.mock import patch, MagicMock
from datetime import date, timedelta
import base64


@tagged('post_install', '-at_install', 'payroll_indicators')
class TestIndicatorAutomation(TransactionCase):
    """Test automatización de indicadores económicos"""
    
    def setUp(self):
        super().setUp()
        
        self.IndicatorModel = self.env['hr.economic.indicators']
        self.WizardModel = self.env['hr.economic.indicators.import.wizard']
    
    def test_01_cron_job_exists(self):
        """Test que el cron job se crea correctamente"""
        cron = self.env.ref(
            'l10n_cl_hr_payroll.cron_fetch_economic_indicators_monthly',
            raise_if_not_found=False
        )
        
        self.assertTrue(cron, "Debe existir el cron job de indicadores")
        self.assertEqual(cron.model_id.model, 'hr.economic.indicators',
                        "Cron debe apuntar al modelo correcto")
        self.assertTrue(cron.active, "Cron debe estar activo")
        self.assertEqual(cron.interval_type, 'months',
                        "Cron debe ejecutarse mensualmente")
    
    @patch('requests.get')
    def test_02_fetch_api_success(self, mock_get):
        """Test fetch API maneja respuesta exitosa"""
        # Mock respuesta exitosa de AI-Service
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'success': True,
            'indicators': {
                'uf': 39000.0,
                'utm': 68000.0,
                'uta': 816000.0,
                'sueldo_minimo': 500000.0,
                'afp_tope_uf': 87.8,
            }
        }
        mock_get.return_value = mock_response
        
        # Llamar método
        indicator = self.IndicatorModel.fetch_from_ai_service(2025, 6)
        
        # Verificar que se creó el indicador
        self.assertTrue(indicator, "Debe crearse el indicador")
        self.assertEqual(indicator.period, date(2025, 6, 1))
        self.assertAlmostEqual(indicator.uf, 39000.0, delta=1)
        self.assertAlmostEqual(indicator.utm, 68000.0, delta=1)
        self.assertAlmostEqual(indicator.minimum_wage, 500000.0, delta=1)
    
    @patch('requests.get')
    @patch('time.sleep')  # Mock sleep para no esperar en tests
    def test_03_fetch_api_retry_on_failure(self, mock_sleep, mock_get):
        """Test fetch API ejecuta reintentos en caso de fallo"""
        # Mock: primera llamada falla, segunda falla, tercera exitosa
        mock_get.side_effect = [
            MagicMock(status_code=500, text='Server Error'),  # Intento 1: falla
            MagicMock(status_code=500, text='Server Error'),  # Intento 2: falla
            MagicMock(  # Intento 3: éxito
                status_code=200,
                json=lambda: {
                    'success': True,
                    'indicators': {
                        'uf': 39000.0,
                        'utm': 68000.0,
                        'uta': 816000.0,
                        'sueldo_minimo': 500000.0,
                        'afp_tope_uf': 87.8,
                    }
                }
            )
        ]
        
        # Llamar cron
        indicator = self.IndicatorModel._run_fetch_indicators_cron()
        
        # Verificar que se reintentó y finalmente tuvo éxito
        self.assertTrue(indicator, "Debe crear indicador después de reintentos")
        self.assertEqual(mock_get.call_count, 3, "Debe haber 3 intentos")
        self.assertEqual(mock_sleep.call_count, 2, "Debe hacer sleep entre intentos")
    
    def test_04_wizard_import_csv(self):
        """Test wizard importa CSV correctamente"""
        # Crear CSV de prueba
        csv_content = """period,uf,utm,uta,minimum_wage,afp_limit
2025-07-01,39100.00,68200.00,818000.00,505000.00,87.8
2025-08-01,39200.00,68400.00,820000.00,505000.00,87.8"""
        
        csv_base64 = base64.b64encode(csv_content.encode('utf-8'))
        
        # Crear wizard
        wizard = self.WizardModel.create({
            'csv_file': csv_base64,
            'filename': 'test_indicators.csv',
        })
        
        # Ejecutar importación
        wizard.action_import_indicators()
        
        # Verificar que se crearon los indicadores
        ind_july = self.IndicatorModel.search([('period', '=', '2025-07-01')])
        ind_august = self.IndicatorModel.search([('period', '=', '2025-08-01')])
        
        self.assertEqual(len(ind_july), 1, "Debe crear indicador julio")
        self.assertEqual(len(ind_august), 1, "Debe crear indicador agosto")
        
        self.assertAlmostEqual(ind_july.uf, 39100.0, delta=1)
        self.assertAlmostEqual(ind_august.uf, 39200.0, delta=1)
    
    @patch('requests.get')
    def test_05_cron_idempotent(self, mock_get):
        """Test cron es idempotente (no duplica indicadores)"""
        # Crear indicador para el mes siguiente manualmente
        next_month = (date.today().replace(day=1) + timedelta(days=32)).replace(day=1)
        
        existing = self.IndicatorModel.create({
            'period': next_month,
            'uf': 39000.0,
            'utm': 68000.0,
            'uta': 816000.0,
            'minimum_wage': 500000.0,
            'afp_limit': 87.8,
        })
        
        # Ejecutar cron
        result = self.IndicatorModel._run_fetch_indicators_cron()
        
        # Verificar que retornó el existente (no llamó API)
        self.assertEqual(result.id, existing.id, "Debe retornar el indicador existente")
        mock_get.assert_not_called()  # No debe llamar API
        
        # Verificar que no se duplicó
        count = self.IndicatorModel.search_count([('period', '=', next_month)])
        self.assertEqual(count, 1, "No debe duplicar indicadores")
    
    def test_06_wizard_csv_validation(self):
        """Test wizard valida formato CSV"""
        # CSV sin columnas requeridas
        csv_invalid = """fecha,valor
2025-07-01,39000.00"""
        
        csv_base64 = base64.b64encode(csv_invalid.encode('utf-8'))
        
        wizard = self.WizardModel.create({
            'csv_file': csv_base64,
            'filename': 'invalid.csv',
        })
        
        # Debe fallar la importación
        with self.assertRaises(Exception):
            wizard.action_import_indicators()
    
    def test_07_wizard_skip_duplicates(self):
        """Test wizard omite indicadores duplicados"""
        # Crear indicador existente
        self.IndicatorModel.create({
            'period': date(2025, 7, 1),
            'uf': 38000.0,  # Valor antiguo
            'utm': 67000.0,
            'uta': 814000.0,
            'minimum_wage': 490000.0,
            'afp_limit': 87.8,
        })
        
        # Intentar importar con mismo período
        csv_content = """period,uf,utm,uta,minimum_wage,afp_limit
2025-07-01,39000.00,68000.00,816000.00,500000.00,87.8"""
        
        csv_base64 = base64.b64encode(csv_content.encode('utf-8'))
        
        wizard = self.WizardModel.create({
            'csv_file': csv_base64,
            'filename': 'duplicate.csv',
        })
        
        wizard.action_import_indicators()
        
        # Verificar que NO se creó duplicado (sigue existiendo solo 1)
        count = self.IndicatorModel.search_count([('period', '=', '2025-07-01')])
        self.assertEqual(count, 1, "No debe duplicar indicadores")
        
        # Verificar que conserva valor original
        indicator = self.IndicatorModel.search([('period', '=', '2025-07-01')])
        self.assertAlmostEqual(indicator.uf, 38000.0, delta=1,
                              msg="Debe conservar valor original")
    
    @patch('requests.get')
    def test_08_indicator_consumed_by_payslip(self, mock_get):
        """Test indicador creado por cron es consumido por liquidación"""
        # Crear indicador
        indicator = self.IndicatorModel.create({
            'period': date(2025, 1, 1),
            'uf': 39000.0,
            'utm': 68000.0,
            'uta': 816000.0,
            'minimum_wage': 500000.0,
            'afp_limit': 87.8,
        })
        
        # Crear empleado y contrato
        afp = self.env['hr.afp'].create({
            'name': 'AFP Capital',
            'code': 'CAPITAL',
            'rate': 11.44,
        })
        
        employee = self.env['hr.employee'].create({
            'name': 'Test Employee Indicators',
        })
        
        contract = self.env['hr.contract'].create({
            'name': 'Test Contract Indicators',
            'employee_id': employee.id,
            'wage': 1000000,
            'afp_id': afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'weekly_hours': 44,
            'state': 'open',
            'date_start': date(2025, 1, 1),
        })
        
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': employee.id,
            'contract_id': contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': indicator.id,
        })
        
        # Calcular
        payslip.action_compute_sheet()
        
        # Verificar que usó los indicadores
        self.assertTrue(payslip.line_ids, "Debe tener líneas calculadas")
        self.assertGreater(payslip.net_wage, 0, "Debe calcular líquido")
        
        # Verificar que vinculó el indicador correcto
        self.assertEqual(payslip.indicadores_id.id, indicator.id,
                        "Debe usar el indicador correcto")
