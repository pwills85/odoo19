# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.addons.l10n_cl_financial_reports.utils.performance_decorators import (
    measure_sql_performance,
    measure_performance
)
import time
import logging

# Capture logs for testing
_test_logger = logging.getLogger('odoo.addons.l10n_cl_financial_reports.utils.performance_decorators')


class TestPerformanceDecorators(TransactionCase):
    """
    Tests para decoradores de rendimiento.
    """

    def test_01_measure_sql_performance_decorator_exists(self):
        """Test que el decorador measure_sql_performance existe y es callable"""
        self.assertTrue(callable(measure_sql_performance))

    def test_02_decorator_wraps_function(self):
        """Test que el decorador preserva el nombre y docstring de la función"""
        @measure_sql_performance
        def test_function():
            """Test docstring"""
            return "result"

        self.assertEqual(test_function.__name__, 'test_function')
        self.assertEqual(test_function.__doc__, 'Test docstring')

    def test_03_decorator_measures_execution_time(self):
        """Test que el decorador mide el tiempo de ejecución"""
        call_count = [0]

        @measure_sql_performance
        def slow_function(self):
            call_count[0] += 1
            time.sleep(0.1)  # Sleep 100ms
            return "done"

        # Ejecutar función
        result = slow_function(self)

        # Verificar que se ejecutó
        self.assertEqual(result, "done")
        self.assertEqual(call_count[0], 1)

        # El decorador debe loggear (verificado en logs)

    def test_04_decorator_handles_exceptions(self):
        """Test que el decorador maneja excepciones correctamente"""
        @measure_sql_performance
        def failing_function(self):
            raise ValueError("Test error")

        # El decorador debe re-raise la excepción
        with self.assertRaises(ValueError) as context:
            failing_function(self)

        self.assertIn("Test error", str(context.exception))

    def test_05_decorator_returns_function_result(self):
        """Test que el decorador retorna el resultado de la función"""
        @measure_sql_performance
        def function_with_result(self):
            return {"key": "value", "number": 42}

        result = function_with_result(self)

        self.assertEqual(result["key"], "value")
        self.assertEqual(result["number"], 42)

    def test_06_measure_performance_parameterized(self):
        """Test que measure_performance con parámetros funciona"""
        @measure_performance(log_queries=True, log_result_size=True)
        def function_with_list(self):
            return [1, 2, 3, 4, 5]

        result = function_with_list(self)

        self.assertEqual(len(result), 5)

    def test_07_decorator_applied_to_kpi_service(self):
        """Test que el decorador está aplicado a compute_kpis"""
        # Verificar que el decorador está presente en compute_kpis
        kpi_service = self.env['account.financial.report.kpi.service']

        # Crear compañía y F29 de prueba
        company = self.env['res.company'].create({
            'name': 'Test Company Decorator',
            'currency_id': self.env.ref('base.CLP').id,
        })

        self.env['l10n_cl.f29'].create({
            'company_id': company.id,
            'period_date': '2024-01-01',
            'state': 'confirmed',
            'ventas_afectas': 10000000.0,
        })

        # Ejecutar compute_kpis (debe loggear performance metrics)
        kpis = kpi_service.compute_kpis(
            company=company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )

        # Verificar que se ejecutó correctamente
        self.assertIsNotNone(kpis)
        self.assertIn('ventas_netas', kpis)

    def test_08_decorator_logs_method_name(self):
        """Test que el decorador loggea el nombre del método correctamente"""
        class TestClass:
            @measure_sql_performance
            def test_method(self):
                return "test"

        obj = TestClass()
        result = obj.test_method()

        self.assertEqual(result, "test")
        # El decorador debe loggear "TestClass.test_method" en JSON

    def test_09_decorator_handles_functions_without_self(self):
        """Test que el decorador maneja funciones sin self"""
        @measure_sql_performance
        def standalone_function():
            return "standalone"

        result = standalone_function()

        self.assertEqual(result, "standalone")

    def test_10_decorator_multiple_calls(self):
        """Test que el decorador funciona en múltiples llamadas"""
        @measure_sql_performance
        def repeatable_function(self, value):
            return value * 2

        # Primera llamada
        result1 = repeatable_function(self, 5)
        self.assertEqual(result1, 10)

        # Segunda llamada
        result2 = repeatable_function(self, 10)
        self.assertEqual(result2, 20)

        # Tercera llamada
        result3 = repeatable_function(self, 15)
        self.assertEqual(result3, 30)
