# -*- coding: utf-8 -*-
"""
Test Suite para verificar correcciones de configuración
del módulo account_financial_report

Tests de integración que verifican:
1. Cron jobs funcionando correctamente
2. Configuraciones accesibles desde Settings
3. Modelos F29 y F22 operativos
4. XPath de vistas funcionando

🔗 REFERENCIAS:
- GUIA_TECNICA_DESARROLLO_MODULOS_ODOO18_CE.md: Testing - Sección 5.0
- Odoo Testing Documentation: https://www.odoo.com/documentation/18.0/developer/tutorials/server_framework_101/12_testing.html
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError, ValidationError
from datetime import date
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)

class TestConfigFixesIntegration(TransactionCase):
    """Test suite para correcciones de configuración"""

    def setUp(self):
        """Configuración inicial de tests"""
        super().setUp()

        # Configurar compañía para pruebas Chilean
        self.company = self.env['res.company'].browse(1)  # Main company
        self.company.write({
            'country_id': self.env.ref('base.cl').id,
            'vat': '12345678-9',
            'l10n_cl_sii_enabled': True
        })

        # Usuario de prueba
        self.test_user = self.env['res.users'].browse(1)  # admin

    def test_01_cron_jobs_creation(self):
        """Test: Verificar que los cron jobs se crean correctamente"""
        _logger.info("🧪 Testing cron jobs creation...")

        # Buscar cron jobs creados
        f29_cron = self.env['ir.cron'].search([
            ('name', '=', 'Crear F29 Mensual')
        ])
        self.assertTrue(f29_cron, "Cron job F29 no encontrado")
        self.assertEqual(f29_cron.model_id.model, 'l10n_cl.f29')

        f22_cron = self.env['ir.cron'].search([
            ('name', '=', 'Crear F22 Anual')
        ])
        self.assertTrue(f22_cron, "Cron job F22 no encontrado")
        self.assertEqual(f22_cron.model_id.model, 'l10n_cl.f22')

        status_cron = self.env['ir.cron'].search([
            ('name', '=', 'Verificar Estado Documentos SII')
        ])
        self.assertTrue(status_cron, "Cron job verificación estado no encontrado")

        _logger.info("✅ Cron jobs creados correctamente")

    def test_02_f29_model_functionality(self):
        """Test: Verificar funcionalidad completa del modelo F29"""
        _logger.info("🧪 Testing F29 model functionality...")

        # Crear F29 de prueba
        period_date = date.today().replace(day=1) - relativedelta(months=1)

        f29 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': period_date,
        })

        # Verificar campos calculados
        self.assertTrue(f29.display_name)
        self.assertEqual(f29.state, 'draft')
        self.assertEqual(f29.currency_id, self.company.currency_id)

        # Test constraint de período único
        with self.assertRaises(ValidationError):
            self.env['l10n_cl.f29'].create({
                'company_id': self.company.id,
                'period_date': period_date,  # Mismo período
            })

        # Test transiciones de estado
        f29.action_to_review()
        self.assertEqual(f29.state, 'review')

        _logger.info("✅ Modelo F29 funcionando correctamente")

    def test_03_f22_model_functionality(self):
        """Test: Verificar funcionalidad completa del modelo F22"""
        _logger.info("🧪 Testing F22 model functionality...")

        # Crear F22 de prueba
        fiscal_year = date.today().year

        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': fiscal_year,
        })

        # Verificar campos calculados
        self.assertTrue(f22.display_name)
        self.assertEqual(f22.state, 'draft')
        self.assertTrue(f22.period_start)
        self.assertTrue(f22.period_end)

        # Test constraint de año único
        with self.assertRaises(ValidationError):
            self.env['l10n_cl.f22'].create({
                'company_id': self.company.id,
                'fiscal_year': fiscal_year,  # Mismo año
            })

        # Test cálculos tributarios
        f22.write({
            'ingresos_operacionales': 1000000,
            'costos_directos': 600000,
            'gastos_operacionales': 200000,
        })

        # Verificar cálculos automáticos
        self.assertEqual(f22.ingresos_totales, 1000000)
        self.assertEqual(f22.gastos_totales, 800000)
        self.assertEqual(f22.resultado_antes_impuesto, 200000)
        self.assertEqual(f22.renta_liquida_imponible, 200000)
        self.assertEqual(f22.impuesto_primera_categoria, 200000 * 0.27)  # 27%

        _logger.info("✅ Modelo F22 funcionando correctamente")

    def test_04_config_settings_fields(self):
        """Test: Verificar que los campos de configuración son accesibles"""
        _logger.info("🧪 Testing config settings fields...")

        # Crear configuración
        config = self.env['res.config.settings'].create({})

        # Verificar campos disponibles
        field_names = [
            'financial_report_auto_refresh',
            'financial_report_cache_timeout',
            'enable_query_optimization',
            'enable_prefetch_optimization',
            'financial_report_batch_size',
        ]

        for field_name in field_names:
            self.assertTrue(
                hasattr(config, field_name),
                f"Campo {field_name} no encontrado en res.config.settings"
            )

        # Test valores por defecto
        self.assertEqual(config.financial_report_cache_timeout, 30)
        self.assertEqual(config.enable_query_optimization, True)
        self.assertEqual(config.enable_prefetch_optimization, True)
        self.assertEqual(config.financial_report_batch_size, 1000)

        # Test modificación y guardado
        config.write({
            'financial_report_auto_refresh': True,
            'financial_report_cache_timeout': 45,
        })
        config.execute()

        # Verificar persistencia
        param_value = self.env['ir.config_parameter'].sudo().get_param(
            'account_financial_report.auto_refresh'
        )
        self.assertEqual(param_value, 'True')

        _logger.info("✅ Campos de configuración funcionando correctamente")

    def test_05_cron_execution_simulation(self):
        """Test: Simular ejecución de cron jobs"""
        _logger.info("🧪 Testing cron job execution simulation...")

        # Test método de creación automática F29
        initial_count = self.env['l10n_cl.f29'].search_count([])

        # Ejecutar método del cron
        self.env['l10n_cl.f29'].create_monthly_f29()

        # Verificar que se creó F29 automáticamente
        final_count = self.env['l10n_cl.f29'].search_count([])
        self.assertGreater(final_count, initial_count, "F29 no fue creado automáticamente")

        # Test método de creación automática F22
        initial_f22_count = self.env['l10n_cl.f22'].search_count([])

        # Ejecutar método del cron
        self.env['l10n_cl.f22'].create_annual_f22()

        # Verificar que se creó F22 automáticamente
        final_f22_count = self.env['l10n_cl.f22'].search_count([])
        self.assertGreater(final_f22_count, initial_f22_count, "F22 no fue creado automáticamente")

        _logger.info("✅ Cron jobs simulados correctamente")

    def test_06_view_inheritance_functionality(self):
        """Test: Verificar que las vistas se cargan correctamente"""
        _logger.info("🧪 Testing view inheritance functionality...")

        # Test vista de configuraciones principales
        main_config_view = self.env.ref(
            'account_financial_report.res_config_settings_view_form_inherit_account_financial_report'
        )
        self.assertTrue(main_config_view, "Vista principal de configuración no encontrada")
        self.assertEqual(main_config_view.model, 'res.config.settings')

        # Test vista de configuraciones de rendimiento
        performance_view = self.env.ref(
            'account_financial_report.res_config_settings_view_form_inherit_financial_performance'
        )
        self.assertTrue(performance_view, "Vista de configuración de rendimiento no encontrada")

        # Test vista de monitoreo
        monitoring_view = self.env.ref(
            'account_financial_report.performance_monitoring_view'
        )
        self.assertTrue(monitoring_view, "Vista de monitoreo no encontrada")

        _logger.info("✅ Vistas cargadas correctamente")

    def test_07_integration_workflow(self):
        """Test: Workflow completo de integración"""
        _logger.info("🧪 Testing complete integration workflow...")

        # 1. Configurar settings
        config = self.env['res.config.settings'].create({
            'financial_report_auto_refresh': True,
            'financial_report_cache_timeout': 60,
            'enable_query_optimization': True,
        })
        config.execute()

        # 2. Crear F29 manualmente
        f29 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': date.today().replace(day=1) - relativedelta(months=1),
        })

        # 3. Simular datos para cálculo
        f29.write({
            'ventas_gravadas': 1000000,
            'iva_debito': 190000,
            'compras_gravadas': 600000,
            'iva_credito': 114000,
        })

        # 4. Verificar cálculos automáticos
        self.assertEqual(f29.ventas_total, 1000000)
        self.assertEqual(f29.compras_total, 600000)
        self.assertEqual(f29.total_debito, 190000)
        self.assertEqual(f29.total_credito, 114000)
        self.assertEqual(f29.iva_a_pagar, 76000)  # 190000 - 114000

        # 5. Transición de estados
        f29.action_to_review()
        self.assertEqual(f29.state, 'review')

        # 6. Crear F22 y verificar integración
        f22 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': date.today().year,
            'ingresos_operacionales': 5000000,
            'costos_directos': 3000000,
        })

        # Verificar cálculos F22
        self.assertEqual(f22.ingresos_totales, 5000000)
        self.assertEqual(f22.gastos_totales, 3000000)
        self.assertEqual(f22.resultado_antes_impuesto, 2000000)
        self.assertEqual(f22.renta_liquida_imponible, 2000000)
        self.assertEqual(f22.impuesto_primera_categoria, 540000)  # 2000000 * 0.27

        _logger.info("✅ Workflow completo de integración exitoso")

    def test_08_error_handling(self):
        """Test: Manejo de errores y excepciones"""
        _logger.info("🧪 Testing error handling...")

        # Test error en F29 con período duplicado
        period_date = date.today().replace(day=1)
        f29_1 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': period_date,
        })

        with self.assertRaises(ValidationError):
            self.env['l10n_cl.f29'].create({
                'company_id': self.company.id,
                'period_date': period_date,  # Duplicado
            })

        # Test error en transiciones de estado inválidas
        f29_1.state = 'sent'  # Estado avanzado

        with self.assertRaises(UserError):
            f29_1.action_to_review()  # No debería poder retroceder

        # Test error en F22 con año duplicado
        fiscal_year = date.today().year
        f22_1 = self.env['l10n_cl.f22'].create({
            'company_id': self.company.id,
            'fiscal_year': fiscal_year,
        })

        with self.assertRaises(ValidationError):
            self.env['l10n_cl.f22'].create({
                'company_id': self.company.id,
                'fiscal_year': fiscal_year,  # Duplicado
            })

        _logger.info("✅ Manejo de errores funcionando correctamente")

class TestConfigPerformance(TransactionCase):
    """Test suite para verificar rendimiento de configuraciones"""

    def test_01_bulk_operations_performance(self):
        """Test: Rendimiento en operaciones masivas"""
        _logger.info("🧪 Testing bulk operations performance...")

        import time

        # Test creación masiva de F29
        start_time = time.time()

        f29_data = []
        for i in range(12):  # 12 meses
            period_date = date.today().replace(day=1) - relativedelta(months=i)
            f29_data.append({
                'company_id': self.env.company.id,
                'period_date': period_date,
            })

        f29_records = self.env['l10n_cl.f29'].create(f29_data)
        creation_time = time.time() - start_time

        self.assertEqual(len(f29_records), 12)
        self.assertLess(creation_time, 5.0, "Creación masiva F29 demasiado lenta")

        # Test actualización masiva
        start_time = time.time()
        f29_records.write({
            'ventas_gravadas': 100000,
            'iva_debito': 19000,
        })
        update_time = time.time() - start_time

        self.assertLess(update_time, 2.0, "Actualización masiva F29 demasiado lenta")

        _logger.info(f"✅ Performance test passed - Creation: {creation_time:.2f}s, Update: {update_time:.2f}s")

    def test_02_config_parameter_performance(self):
        """Test: Rendimiento de acceso a parámetros de configuración"""
        _logger.info("🧪 Testing config parameter performance...")

        import time

        config = self.env['res.config.settings'].create({
            'financial_report_cache_timeout': 45,
            'financial_report_batch_size': 2000,
        })
        config.execute()

        # Test acceso repetitivo a parámetros (simulando uso en producción)
        start_time = time.time()

        for _ in range(100):
            timeout = self.env['ir.config_parameter'].sudo().get_param(
                'account_financial_report.cache_timeout'
            )
            batch_size = self.env['ir.config_parameter'].sudo().get_param(
                'account_financial_report.batch_size'
            )

        access_time = time.time() - start_time
        self.assertLess(access_time, 1.0, "Acceso a parámetros de configuración demasiado lento")

        _logger.info(f"✅ Config access performance test passed: {access_time:.3f}s for 100 accesses")
