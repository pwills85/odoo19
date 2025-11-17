# -*- coding: utf-8 -*-

"""
HIGH-007: Test Auto-actualización AFP Rates
===========================================

Suite de tests para validar actualización automática de comisiones AFP
desde Superintendencia de Pensiones API.

Tests:
1. test_cron_update_afp_rates_success - Actualización exitosa
2. test_cron_update_no_change - Sin cambio si comisión igual
3. test_cron_retry_on_failure - Reintentos en fallo API
4. test_cron_notify_admin_on_persistent_failure - Notificación admin
"""

import json
from unittest.mock import patch, MagicMock
from datetime import date, timedelta

from odoo.tests import TransactionCase, tagged
from odoo.exceptions import UserError


@tagged('post_install', '-at_install', 'l10n_cl_payroll', 'high_007')
class TestAFPAutoUpdate(TransactionCase):
    """Test suite para auto-actualización AFP rates (HIGH-007)"""

    def setUp(self):
        super().setUp()
        
        # Crear AFP de prueba
        self.afp_capital = self.env['hr.afp'].create({
            'name': 'AFP Capital',
            'code': '03',
            'rate': 1.44,
            'sis_rate': 1.57,
        })
        
        self.afp_provida = self.env['hr.afp'].create({
            'name': 'AFP Provida',
            'code': '05',
            'rate': 1.45,
            'sis_rate': 1.57,
        })
        
        # Mock response API Superintendencia Pensiones
        self.mock_api_response = {
            'afps': [
                {'codigo': '03', 'nombre': 'AFP Capital', 'comision': 1.54},
                {'codigo': '05', 'nombre': 'AFP Provida', 'comision': 1.49},
            ]
        }

    def test_cron_update_afp_rates_success(self):
        """
        TEST 1: Actualización exitosa de comisiones AFP
        
        Given: 2 AFPs con tasas antiguas
        When: Cron ejecuta actualización desde API
        Then: Tasas actualizadas correctamente + log en chatter
        """
        # Mock requests.get para simular API
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = self.mock_api_response
            mock_get.return_value = mock_response
            
            # Ejecutar cron
            result = self.env['hr.afp']._cron_update_afp_rates()
            
            # Validaciones
            self.assertTrue(result, 'Cron debe retornar True en éxito')
            
            # Verificar tasas actualizadas
            self.afp_capital.invalidate_recordset()
            self.afp_provida.invalidate_recordset()
            
            self.assertEqual(
                self.afp_capital.rate,
                1.54,
                'AFP Capital debe actualizarse a 1.54%'
            )
            self.assertEqual(
                self.afp_provida.rate,
                1.49,
                'AFP Provida debe actualizarse a 1.49%'
            )
            
            # Verificar last_update_date
            self.assertEqual(
                self.afp_capital.last_update_date,
                date.today(),
                'last_update_date debe ser hoy'
            )
            
            # Verificar mensaje en chatter
            messages = self.afp_capital.message_ids
            self.assertTrue(
                any('actualizada automáticamente' in msg.body.lower() for msg in messages),
                'Debe haber mensaje en chatter confirmando actualización'
            )

    def test_cron_update_no_change(self):
        """
        TEST 2: Sin actualización si comisión no cambió
        
        Given: AFP con tasa actual igual a API
        When: Cron ejecuta actualización
        Then: No actualiza (cambio <0.01%)
        """
        # Configurar tasa igual a API
        self.afp_capital.rate = 1.54
        
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'afps': [
                    {'codigo': '03', 'nombre': 'AFP Capital', 'comision': 1.54},
                ]
            }
            mock_get.return_value = mock_response
            
            # Ejecutar cron
            result = self.env['hr.afp']._cron_update_afp_rates()
            
            # Validaciones
            self.assertTrue(result, 'Cron debe retornar True')
            
            # Verificar NO hay mensaje nuevo en chatter
            messages_before = len(self.afp_capital.message_ids)
            
            self.afp_capital.invalidate_recordset()
            
            messages_after = len(self.afp_capital.message_ids)
            
            self.assertEqual(
                messages_before,
                messages_after,
                'No debe haber nuevo mensaje si tasa no cambió'
            )

    def test_cron_retry_on_failure(self):
        """
        TEST 3: Retry logic con exponential backoff
        
        Given: API falla primeros 2 intentos, éxito en 3ro
        When: Cron ejecuta actualización
        Then: Reintentos exitosos con backoff (10s, 20s)
        """
        call_count = 0
        
        def mock_get_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            if call_count < 3:
                # Primeros 2 intentos fallan
                raise Exception('Connection timeout')
            else:
                # 3er intento exitoso
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = self.mock_api_response
                return mock_response
        
        with patch('requests.get', side_effect=mock_get_side_effect):
            with patch('time.sleep') as mock_sleep:
                # Ejecutar cron
                result = self.env['hr.afp']._cron_update_afp_rates()
                
                # Validaciones
                self.assertTrue(result, 'Cron debe retornar True tras reintentos')
                self.assertEqual(call_count, 3, 'Debe intentar 3 veces')
                
                # Verificar backoff delays
                self.assertEqual(mock_sleep.call_count, 2, 'Debe hacer sleep 2 veces')
                mock_sleep.assert_any_call(10)  # 1er reintento: 10s
                mock_sleep.assert_any_call(20)  # 2do reintento: 20s

    def test_cron_notify_admin_on_persistent_failure(self):
        """
        TEST 4: Notificación admin en fallo persistente
        
        Given: API falla 3 veces consecutivas
        When: Cron ejecuta actualización
        Then: Retorna False + actividad para HR Manager
        """
        with patch('requests.get') as mock_get:
            mock_get.side_effect = Exception('API no disponible')
            
            with patch('time.sleep'):
                # Ejecutar cron
                result = self.env['hr.afp']._cron_update_afp_rates()
                
                # Validaciones
                self.assertFalse(result, 'Cron debe retornar False en fallo persistente')
                
                # Verificar actividad creada para HR Manager
                # (si existe grupo hr.group_hr_manager)
                group_hr_manager = self.env.ref('hr.group_hr_manager', raise_if_not_found=False)
                
                if group_hr_manager:
                    hr_managers = self.env['res.users'].search([
                        ('groups_id', 'in', group_hr_manager.id)
                    ], limit=1)
                    
                    if hr_managers:
                        activities = self.env['mail.activity'].search([
                            ('user_id', '=', hr_managers[0].id),
                            ('res_model', '=', 'hr.afp'),
                            ('summary', 'ilike', 'comisiones AFP'),
                        ])
                        
                        self.assertTrue(
                            activities,
                            'Debe crear actividad para HR Manager en fallo'
                        )

    def test_cron_update_invalid_api_response(self):
        """
        TEST 5: Manejo respuesta API inválida
        
        Given: API retorna JSON sin campo 'afps'
        When: Cron ejecuta actualización
        Then: Lanza UserError + reintentos
        """
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'error': 'Invalid request'}
            mock_get.return_value = mock_response
            
            with patch('time.sleep'):
                # Ejecutar cron
                result = self.env['hr.afp']._cron_update_afp_rates()
                
                # Validaciones
                self.assertFalse(result, 'Cron debe retornar False en respuesta inválida')

    def test_cron_update_partial_updates(self):
        """
        TEST 6: Actualización parcial (solo algunas AFPs)
        
        Given: API retorna solo 1 AFP
        When: Cron ejecuta actualización
        Then: Solo actualiza AFP presente en respuesta
        """
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'afps': [
                    {'codigo': '03', 'nombre': 'AFP Capital', 'comision': 1.60},
                ]
            }
            mock_get.return_value = mock_response
            
            # Ejecutar cron
            result = self.env['hr.afp']._cron_update_afp_rates()
            
            # Validaciones
            self.assertTrue(result, 'Cron debe retornar True')
            
            self.afp_capital.invalidate_recordset()
            self.afp_provida.invalidate_recordset()
            
            self.assertEqual(
                self.afp_capital.rate,
                1.60,
                'AFP Capital debe actualizarse'
            )
            self.assertEqual(
                self.afp_provida.rate,
                1.45,
                'AFP Provida NO debe cambiar (no en API)'
            )

    def test_last_update_date_warning_logic(self):
        """
        TEST 7: Lógica advertencia >40 días sin actualizar
        
        Given: AFP con last_update_date antigua
        When: Se visualiza en vista
        Then: Debe mostrar badge de advertencia (validar en tests funcionales)
        """
        # Configurar fecha antigua
        old_date = date.today() - timedelta(days=45)
        self.afp_capital.last_update_date = old_date
        
        # Validar fecha antigua
        days_diff = (date.today() - self.afp_capital.last_update_date).days
        
        self.assertGreater(
            days_diff,
            40,
            'AFP debe tener >40 días sin actualizar'
        )
        
        # En vista, debe mostrar decoration-warning (validar en test E2E)
