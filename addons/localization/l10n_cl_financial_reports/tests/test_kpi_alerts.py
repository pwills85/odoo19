# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta


class TestKpiAlerts(TransactionCase):
    """
    Tests para el sistema de alertas de KPI.
    """

    def setUp(self):
        super().setUp()

        # Crear compañía de prueba
        self.company = self.env['res.company'].create({
            'name': 'Test Company Alerts',
            'currency_id': self.env.ref('base.CLP').id,
        })

        # Crear usuarios de prueba
        self.user1 = self.env['res.users'].create({
            'name': 'Test User 1',
            'login': 'testuser1@alerts.com',
            'email': 'testuser1@alerts.com',
        })

        self.user2 = self.env['res.users'].create({
            'name': 'Test User 2',
            'login': 'testuser2@alerts.com',
            'email': 'testuser2@alerts.com',
        })

    def test_01_alert_creation(self):
        """Test que se puede crear una alerta correctamente"""
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'iva_debito_fiscal',
            'threshold_type': 'above',
            'threshold_value': 1000000.0,
            'alert_level': 'warning',
        })

        self.assertTrue(alert.name)
        self.assertEqual(alert.company_id, self.company)
        self.assertEqual(alert.kpi_type, 'iva_debito_fiscal')
        self.assertTrue(alert.active)

    def test_02_alert_name_computed(self):
        """Test que el nombre se genera automáticamente"""
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'ventas_netas',
            'threshold_type': 'below',
            'threshold_value': 500000.0,
            'alert_level': 'critical',
        })

        self.assertIn('Ventas Netas', alert.name)
        self.assertIn('Menor que', alert.name)
        self.assertIn(self.company.name, alert.name)

    def test_03_threshold_value_must_be_positive(self):
        """Test que el valor umbral debe ser positivo"""
        with self.assertRaises(ValidationError) as context:
            self.env['l10n_cl.kpi.alert'].create({
                'company_id': self.company.id,
                'kpi_type': 'iva_credito_fiscal',
                'threshold_type': 'above',
                'threshold_value': -100000.0,
                'alert_level': 'warning',
            })

        self.assertIn('debe ser positivo', str(context.exception))

    def test_04_default_values(self):
        """Test que los valores por defecto se aplican correctamente"""
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'ppm_pagado',
            'threshold_value': 200000.0,
        })

        self.assertEqual(alert.threshold_type, 'above')
        self.assertEqual(alert.alert_level, 'warning')
        self.assertEqual(alert.priority, '1')
        self.assertTrue(alert.active)
        self.assertEqual(alert.triggered_count, 0)

    def test_05_notification_users_many2many(self):
        """Test que se pueden asignar múltiples usuarios para notificaciones"""
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'compras_netas',
            'threshold_value': 800000.0,
            'notification_user_ids': [(6, 0, [self.user1.id, self.user2.id])],
        })

        self.assertEqual(len(alert.notification_user_ids), 2)
        self.assertIn(self.user1, alert.notification_user_ids)
        self.assertIn(self.user2, alert.notification_user_ids)

    def test_06_evaluate_alert_condition_above(self):
        """Test que la evaluación 'above' funciona correctamente"""
        alert_model = self.env['l10n_cl.kpi.alert']

        # Caso: valor por encima del umbral (debe disparar)
        should_trigger = alert_model._evaluate_alert_condition(
            'above', 1500000.0, 1000000.0
        )
        self.assertTrue(should_trigger)

        # Caso: valor por debajo del umbral (no debe disparar)
        should_trigger = alert_model._evaluate_alert_condition(
            'above', 800000.0, 1000000.0
        )
        self.assertFalse(should_trigger)

        # Caso: valor igual al umbral (no debe disparar)
        should_trigger = alert_model._evaluate_alert_condition(
            'above', 1000000.0, 1000000.0
        )
        self.assertFalse(should_trigger)

    def test_07_evaluate_alert_condition_below(self):
        """Test que la evaluación 'below' funciona correctamente"""
        alert_model = self.env['l10n_cl.kpi.alert']

        # Caso: valor por debajo del umbral (debe disparar)
        should_trigger = alert_model._evaluate_alert_condition(
            'below', 800000.0, 1000000.0
        )
        self.assertTrue(should_trigger)

        # Caso: valor por encima del umbral (no debe disparar)
        should_trigger = alert_model._evaluate_alert_condition(
            'below', 1500000.0, 1000000.0
        )
        self.assertFalse(should_trigger)

        # Caso: valor igual al umbral (no debe disparar)
        should_trigger = alert_model._evaluate_alert_condition(
            'below', 1000000.0, 1000000.0
        )
        self.assertFalse(should_trigger)

    def test_08_send_alert_notification(self):
        """Test que se envían notificaciones correctamente"""
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'iva_debito_fiscal',
            'threshold_type': 'above',
            'threshold_value': 1000000.0,
            'alert_level': 'critical',
            'notification_user_ids': [(6, 0, [self.user1.id])],
        })

        # Contar actividades antes
        activities_before = self.env['mail.activity'].search_count([
            ('user_id', '=', self.user1.id),
            ('res_model', '=', 'l10n_cl.kpi.alert'),
        ])

        # Enviar notificación
        alert._send_alert_notification(1500000.0, '2024-01-01', '2024-01-31')

        # Contar actividades después
        activities_after = self.env['mail.activity'].search_count([
            ('user_id', '=', self.user1.id),
            ('res_model', '=', 'l10n_cl.kpi.alert'),
        ])

        self.assertEqual(activities_after, activities_before + 1)

    def test_09_send_notification_multiple_users(self):
        """Test que se envían notificaciones a múltiples usuarios"""
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'ventas_netas',
            'threshold_value': 2000000.0,
            'notification_user_ids': [(6, 0, [self.user1.id, self.user2.id])],
        })

        # Contar actividades antes para ambos usuarios
        activities_user1_before = self.env['mail.activity'].search_count([
            ('user_id', '=', self.user1.id),
        ])
        activities_user2_before = self.env['mail.activity'].search_count([
            ('user_id', '=', self.user2.id),
        ])

        # Enviar notificación
        alert._send_alert_notification(2500000.0, '2024-01-01', '2024-01-31')

        # Contar actividades después
        activities_user1_after = self.env['mail.activity'].search_count([
            ('user_id', '=', self.user1.id),
        ])
        activities_user2_after = self.env['mail.activity'].search_count([
            ('user_id', '=', self.user2.id),
        ])

        self.assertEqual(activities_user1_after, activities_user1_before + 1)
        self.assertEqual(activities_user2_after, activities_user2_before + 1)

    @patch('odoo.addons.l10n_cl_financial_reports.models.l10n_cl_kpi_alert.datetime')
    def test_10_cron_check_kpi_alerts_no_active_alerts(self, mock_datetime):
        """Test que el cron maneja correctamente cuando no hay alertas activas"""
        # Mock de la fecha actual
        mock_datetime.now.return_value.date.return_value = datetime(2024, 2, 15).date()

        # No hay alertas activas
        alert_model = self.env['l10n_cl.kpi.alert']

        # Ejecutar cron (no debe fallar)
        alert_model._cron_check_kpi_alerts()

        # No debe haber errores

    @patch('odoo.addons.l10n_cl_financial_reports.models.l10n_cl_kpi_alert.datetime')
    def test_11_cron_updates_alert_statistics(self, mock_datetime):
        """Test que el cron actualiza estadísticas de alertas disparadas"""
        # Mock de la fecha actual
        mock_datetime.now.return_value.date.return_value = datetime(2024, 2, 15).date()
        mock_datetime.now.return_value = datetime(2024, 2, 15, 10, 30, 0)

        # Crear F29 de prueba (mes anterior)
        self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-01-01',
            'state': 'confirmed',
            'ventas_afectas': 10000000.0,  # 10M
        })

        # Crear alerta que se debe disparar (umbral: 1M, valor real: 1.9M débito)
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'iva_debito_fiscal',
            'threshold_type': 'above',
            'threshold_value': 1000000.0,
            'alert_level': 'warning',
            'notification_user_ids': [(6, 0, [self.user1.id])],
        })

        # Estadísticas iniciales
        self.assertFalse(alert.last_triggered_date)
        self.assertEqual(alert.triggered_count, 0)

        # Ejecutar cron
        alert_model = self.env['l10n_cl.kpi.alert']
        alert_model._cron_check_kpi_alerts()

        # Refrescar alerta
        alert.invalidate_recordset()

        # Verificar que las estadísticas se actualizaron
        self.assertTrue(alert.last_triggered_date)
        self.assertEqual(alert.triggered_count, 1)

    def test_12_inactive_alerts_not_processed(self):
        """Test que las alertas inactivas no se procesan"""
        # Crear alerta inactiva
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'iva_credito_fiscal',
            'threshold_value': 500000.0,
            'active': False,
            'notification_user_ids': [(6, 0, [self.user1.id])],
        })

        # Estadísticas iniciales
        initial_triggered_count = alert.triggered_count

        # Ejecutar cron
        alert_model = self.env['l10n_cl.kpi.alert']
        alert_model._cron_check_kpi_alerts()

        # Refrescar alerta
        alert.invalidate_recordset()

        # Verificar que NO se procesó
        self.assertEqual(alert.triggered_count, initial_triggered_count)

    def test_13_action_test_alert_triggers(self):
        """Test que action_test_alert funciona cuando la alerta se dispara"""
        # Crear F29 de prueba (mes anterior)
        today = datetime.now().date()
        first_day_this_month = today.replace(day=1)
        last_day_last_month = first_day_this_month - timedelta(days=1)
        first_day_last_month = last_day_last_month.replace(day=1)

        self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': first_day_last_month.strftime('%Y-%m-%d'),
            'state': 'confirmed',
            'ventas_afectas': 8000000.0,  # 8M (débito: 1.52M)
        })

        # Crear alerta que se debe disparar
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'iva_debito_fiscal',
            'threshold_type': 'above',
            'threshold_value': 1000000.0,
            'notification_user_ids': [(6, 0, [self.user1.id])],
        })

        # Ejecutar test manual
        result = alert.action_test_alert()

        # Verificar que retorna notificación de alerta disparada
        self.assertEqual(result['type'], 'ir.actions.client')
        self.assertEqual(result['tag'], 'display_notification')
        self.assertIn('Alerta Disparada', result['params']['title'])

    def test_14_action_test_alert_not_triggers(self):
        """Test que action_test_alert funciona cuando la alerta NO se dispara"""
        # Crear F29 de prueba con valores bajos
        today = datetime.now().date()
        first_day_this_month = today.replace(day=1)
        last_day_last_month = first_day_this_month - timedelta(days=1)
        first_day_last_month = last_day_last_month.replace(day=1)

        self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': first_day_last_month.strftime('%Y-%m-%d'),
            'state': 'confirmed',
            'ventas_afectas': 1000000.0,  # 1M (débito: 190K)
        })

        # Crear alerta que NO se debe disparar
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'iva_debito_fiscal',
            'threshold_type': 'above',
            'threshold_value': 5000000.0,  # Umbral muy alto
            'notification_user_ids': [(6, 0, [self.user1.id])],
        })

        # Ejecutar test manual
        result = alert.action_test_alert()

        # Verificar que retorna notificación de alerta NO disparada
        self.assertEqual(result['type'], 'ir.actions.client')
        self.assertIn('NO Disparada', result['params']['title'])

    def test_15_alert_priority_ordering(self):
        """Test que las alertas se ordenan correctamente por prioridad"""
        alert_low = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'ppm_pagado',
            'threshold_value': 100000.0,
            'priority': '0',
        })

        alert_high = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'iva_debito_fiscal',
            'threshold_value': 1000000.0,
            'priority': '3',
        })

        # Buscar por orden por defecto
        alerts = self.env['l10n_cl.kpi.alert'].search([
            ('id', 'in', [alert_low.id, alert_high.id])
        ])

        # La primera debe ser la de mayor prioridad
        self.assertEqual(alerts[0], alert_high)
        self.assertEqual(alerts[1], alert_low)

    def test_16_cron_handles_kpi_service_errors(self):
        """Test que el cron maneja errores del servicio de KPIs correctamente"""
        # Crear alerta
        alert = self.env['l10n_cl.kpi.alert'].create({
            'company_id': self.company.id,
            'kpi_type': 'ventas_netas',
            'threshold_value': 1000000.0,
        })

        # Mock del servicio de KPIs para que falle
        with patch.object(
            type(self.env['account.financial.report.kpi.service']),
            'compute_kpis',
            side_effect=Exception('Test error')
        ):
            # Ejecutar cron (no debe fallar)
            alert_model = self.env['l10n_cl.kpi.alert']
            alert_model._cron_check_kpi_alerts()

            # El cron debe continuar sin errores

    def test_17_alert_level_options(self):
        """Test que todos los niveles de alerta funcionan correctamente"""
        levels = ['info', 'warning', 'critical']

        for level in levels:
            alert = self.env['l10n_cl.kpi.alert'].create({
                'company_id': self.company.id,
                'kpi_type': 'compras_netas',
                'threshold_value': 1000000.0,
                'alert_level': level,
            })

            self.assertEqual(alert.alert_level, level)

    def test_18_all_kpi_types_supported(self):
        """Test que todos los tipos de KPI están soportados"""
        kpi_types = [
            'iva_debito_fiscal',
            'iva_credito_fiscal',
            'ventas_netas',
            'compras_netas',
            'ppm_pagado'
        ]

        for kpi_type in kpi_types:
            alert = self.env['l10n_cl.kpi.alert'].create({
                'company_id': self.company.id,
                'kpi_type': kpi_type,
                'threshold_value': 1000000.0,
            })

            self.assertEqual(alert.kpi_type, kpi_type)
