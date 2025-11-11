# -*- coding: utf-8 -*-

from odoo.tests import tagged, TransactionCase
from unittest.mock import patch, MagicMock
from datetime import date
import requests


@tagged('post_install', '-at_install', 'p1_fix', 'api', 'cron', 'high_012')
class TestEconomicIndicatorsAPI(TransactionCase):
    """
    Test integración API mindicador.cl - HIGH-012

    Tests:
    1. Actualización exitosa desde API
    2. Retry logic con timeouts
    3. Validación rangos UF/UTM
    4. Update sin duplicar registros
    """

    def setUp(self):
        super().setUp()
        self.indicators_model = self.env['hr.economic.indicators']

    @patch('requests.get')
    def test_cron_update_indicators_success(self, mock_get):
        """Test actualización exitosa indicadores desde mindicador.cl"""
        # Mock response API
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'uf': {'valor': 38500.50},
            'utm': {'valor': 67200},
            'ipc': {'valor': 3.5}
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        # Ejecutar cron
        result = self.indicators_model._cron_update_economic_indicators()

        # Validaciones
        self.assertTrue(result, "Cron debe retornar True en éxito")

        # Verificar registro creado
        indicator = self.indicators_model.search([
            ('period', '=', date.today())
        ], limit=1)

        self.assertTrue(indicator, "Debe existir indicador para hoy")
        self.assertAlmostEqual(indicator.uf, 38500.50, places=2,
                               msg="UF debe coincidir con API")
        self.assertAlmostEqual(indicator.utm, 67200, places=0,
                               msg="UTM debe coincidir con API")

    @patch('requests.get')
    @patch('time.sleep')  # Mock sleep para no esperar en tests
    def test_cron_retry_on_timeout(self, mock_sleep, mock_get):
        """Test reintentos en caso de timeout"""
        # Mock timeout 2 veces, éxito en 3ra
        mock_get.side_effect = [
            requests.exceptions.Timeout("Timeout 1"),
            requests.exceptions.Timeout("Timeout 2"),
            MagicMock(
                json=lambda: {
                    'uf': {'valor': 38500},
                    'utm': {'valor': 67200},
                    'ipc': {'valor': 0}
                },
                raise_for_status=MagicMock()
            )
        ]

        result = self.indicators_model._cron_update_economic_indicators()

        # Debe reintentar y finalmente tener éxito
        self.assertTrue(result, "Debe tener éxito después de reintentos")
        self.assertEqual(mock_get.call_count, 3, "Debe reintentar 3 veces")
        # Verificar backoff exponencial: 2 sleeps (intento 1→2, intento 2→3)
        self.assertEqual(mock_sleep.call_count, 2, "Debe hacer 2 sleeps entre 3 intentos")

    @patch('requests.get')
    @patch('time.sleep')
    def test_cron_validation_uf_out_of_range(self, mock_sleep, mock_get):
        """Test validación UF fuera de rango razonable"""
        # Mock UF inválida (muy baja)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'uf': {'valor': 10000},  # ❌ Fuera de rango [30k-50k]
            'utm': {'valor': 67200},
            'ipc': {'valor': 0}
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.indicators_model._cron_update_economic_indicators()

        # Debe fallar por validación después de 3 intentos
        self.assertFalse(result, "Debe fallar con UF fuera de rango")
        self.assertEqual(mock_get.call_count, 3, "Debe intentar 3 veces antes de fallar")

    @patch('requests.get')
    def test_cron_update_existing_indicator(self, mock_get):
        """Test actualización de indicador existente (no duplicado)"""
        # Crear indicador previo
        existing = self.indicators_model.create({
            'period': date.today(),
            'uf': 38000.0,
            'utm': 66000.0,
            'uta': 450000.0,
            'minimum_wage': 500000,
            'afp_limit': 83.1,
            'family_allowance_t1': 15000,
            'family_allowance_t2': 9000,
            'family_allowance_t3': 3000,
        })

        # Mock nueva API response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'uf': {'valor': 38500.0},  # Nuevo valor
            'utm': {'valor': 67200.0},  # Nuevo valor
            'ipc': {'valor': 0}
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.indicators_model._cron_update_economic_indicators()

        self.assertTrue(result)

        # Verificar que se actualizó (no duplicó)
        indicators_today = self.indicators_model.search([
            ('period', '=', date.today())
        ])
        self.assertEqual(len(indicators_today), 1, "No debe duplicar registro")
        self.assertAlmostEqual(indicators_today.uf, 38500.0, places=1,
                               msg="Debe actualizar UF existente")
        self.assertAlmostEqual(indicators_today.utm, 67200.0, places=1,
                               msg="Debe actualizar UTM existente")
        # Verificar que otros campos se preservaron (solo actualiza UF/UTM)
        self.assertEqual(indicators_today.minimum_wage, 500000,
                         "No debe modificar minimum_wage")

    @patch('requests.get')
    @patch('time.sleep')
    def test_cron_all_retries_fail(self, mock_sleep, mock_get):
        """Test fallo total después de todos los reintentos"""
        # Mock fallo en todos los intentos
        mock_get.side_effect = requests.exceptions.RequestException("Connection failed")

        result = self.indicators_model._cron_update_economic_indicators()

        # Debe fallar después de 3 intentos
        self.assertFalse(result, "Debe retornar False después de fallos")
        self.assertEqual(mock_get.call_count, 3, "Debe intentar 3 veces")

    @patch('requests.get')
    def test_cron_validation_utm_out_of_range(self, mock_get):
        """Test validación UTM fuera de rango razonable"""
        # Mock UTM inválida (muy alta)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'uf': {'valor': 38500},
            'utm': {'valor': 100000},  # ❌ Fuera de rango [60k-80k]
            'ipc': {'valor': 0}
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.indicators_model._cron_update_economic_indicators()

        # Debe fallar por validación
        self.assertFalse(result, "Debe fallar con UTM fuera de rango")

    @patch('requests.get')
    def test_cron_missing_required_fields(self, mock_get):
        """Test manejo de respuesta API con campos faltantes"""
        # Mock response incompleta (falta 'utm')
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'uf': {'valor': 38500},
            # 'utm' faltante
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.indicators_model._cron_update_economic_indicators()

        # Debe fallar por KeyError
        self.assertFalse(result, "Debe fallar con campos faltantes")
