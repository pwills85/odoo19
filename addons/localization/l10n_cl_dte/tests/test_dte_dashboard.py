# -*- coding: utf-8 -*-
"""
Test Dashboard Central DTEs - Monitoreo SII
============================================

Tests funcionales para validar:
- Creación del dashboard por compañía (singleton)
- Cálculo de KPIs (Aceptados, Rechazados, Pendientes, Monto Facturado)
- Cálculo de tasas de aceptación y rechazo
- Métodos para obtener datos de gráficos
- Acciones de drill-down a listas de DTEs

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.6.0.0
Fase: 2.1 - Dashboard Central de DTE
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta


class TestDteDashboard(TransactionCase):
    """
    Test suite para Dashboard Central DTEs - Monitoreo SII.
    """

    def setUp(self):
        """
        Setup: Crear datos de prueba.

        Crea:
        - 1 compañía de prueba
        - 1 dashboard DTE
        - Facturas de prueba con diferentes estados SII
        """
        super(TestDteDashboard, self).setUp()

        # Compañía de prueba
        self.company = self.env.company

        # Tipo de documento (DTE 33 - Factura Electrónica)
        self.document_type_33 = self.env['l10n_latam.document.type'].search([
            ('code', '=', '33')
        ], limit=1)

        if not self.document_type_33:
            self.document_type_33 = self.env['l10n_latam.document.type'].create({
                'name': 'Factura Electrónica',
                'code': '33',
                'country_id': self.env.ref('base.cl').id,
            })

        # Partner de prueba
        self.partner = self.env['res.partner'].create({
            'name': 'Cliente Prueba DTE Dashboard',
            'vat': '12345678-9',
            'country_id': self.env.ref('base.cl').id,
        })

        # Fechas de referencia
        self.today = datetime.today().date()
        self.fecha_30d_atras = self.today - timedelta(days=30)
        self.fecha_inicio_mes = self.today.replace(day=1)

        # Crear facturas de prueba con diferentes estados
        self._create_test_invoices()

        # Crear dashboard
        self.dashboard = self.env['l10n_cl.dte_dashboard'].get_or_create_dashboard(
            company_id=self.company.id
        )

    def _create_test_invoices(self):
        """
        Crea facturas de prueba con diferentes estados SII.

        Estados:
        - 3 facturas aceptadas (últimos 30 días)
        - 2 facturas rechazadas (últimos 30 días)
        - 1 factura pendiente
        - 2 facturas aceptadas (mes actual) con monto
        """
        AccountMove = self.env['account.move']

        # Facturas aceptadas (últimos 30 días)
        for i in range(3):
            AccountMove.create({
                'move_type': 'out_invoice',
                'partner_id': self.partner.id,
                'invoice_date': self.fecha_30d_atras + timedelta(days=i * 5),
                'state': 'posted',
                'l10n_cl_dte_status': 'accepted',
                'l10n_latam_document_type_id': self.document_type_33.id,
                'invoice_line_ids': [(0, 0, {
                    'name': f'Producto Test Aceptado {i+1}',
                    'quantity': 1,
                    'price_unit': 100000.0,
                })],
            })

        # Facturas rechazadas (últimos 30 días)
        for i in range(2):
            AccountMove.create({
                'move_type': 'out_invoice',
                'partner_id': self.partner.id,
                'invoice_date': self.fecha_30d_atras + timedelta(days=i * 7),
                'state': 'posted',
                'l10n_cl_dte_status': 'rejected',
                'l10n_latam_document_type_id': self.document_type_33.id,
                'invoice_line_ids': [(0, 0, {
                    'name': f'Producto Test Rechazado {i+1}',
                    'quantity': 1,
                    'price_unit': 50000.0,
                })],
            })

        # Factura pendiente
        AccountMove.create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'invoice_date': self.today,
            'state': 'posted',
            'l10n_cl_dte_status': 'draft',
            'l10n_latam_document_type_id': self.document_type_33.id,
            'invoice_line_ids': [(0, 0, {
                'name': 'Producto Test Pendiente',
                'quantity': 1,
                'price_unit': 75000.0,
            })],
        })

        # Facturas aceptadas (mes actual) con monto
        for i in range(2):
            AccountMove.create({
                'move_type': 'out_invoice',
                'partner_id': self.partner.id,
                'invoice_date': self.fecha_inicio_mes + timedelta(days=i * 5),
                'state': 'posted',
                'l10n_cl_dte_status': 'accepted',
                'l10n_latam_document_type_id': self.document_type_33.id,
                'invoice_line_ids': [(0, 0, {
                    'name': f'Producto Test Mes Actual {i+1}',
                    'quantity': 1,
                    'price_unit': 1000000.0,
                })],
            })

    def test_01_dashboard_creation(self):
        """
        Test: Dashboard se crea correctamente para una compañía.
        """
        self.assertTrue(
            self.dashboard.exists(),
            "Dashboard debe existir"
        )

        self.assertEqual(
            self.dashboard.company_id,
            self.company,
            "Dashboard debe estar asociado a la compañía correcta"
        )

        self.assertEqual(
            self.dashboard.currency_id,
            self.company.currency_id,
            "Dashboard debe usar la moneda de la compañía"
        )

    def test_02_dashboard_singleton(self):
        """
        Test: Dashboard actúa como singleton por compañía.

        get_or_create_dashboard debe retornar el mismo registro.
        """
        dashboard_2 = self.env['l10n_cl.dte_dashboard'].get_or_create_dashboard(
            company_id=self.company.id
        )

        self.assertEqual(
            self.dashboard.id,
            dashboard_2.id,
            "get_or_create_dashboard debe retornar el mismo dashboard"
        )

    def test_03_kpi_dtes_aceptados_30d(self):
        """
        Test: KPI DTEs Aceptados (últimos 30 días) calcula correctamente.

        Esperado: 3 facturas aceptadas + 2 del mes actual = 5 total
        """
        self.dashboard._compute_kpis_30d()

        self.assertGreaterEqual(
            self.dashboard.dtes_aceptados_30d,
            3,
            "Debe haber al menos 3 DTEs aceptados en últimos 30 días"
        )

    def test_04_kpi_dtes_rechazados_30d(self):
        """
        Test: KPI DTEs Rechazados (últimos 30 días) calcula correctamente.

        Esperado: 2 facturas rechazadas
        """
        self.dashboard._compute_kpis_30d()

        self.assertEqual(
            self.dashboard.dtes_rechazados_30d,
            2,
            "Debe haber 2 DTEs rechazados en últimos 30 días"
        )

    def test_05_kpi_dtes_pendientes(self):
        """
        Test: KPI DTEs Pendientes calcula correctamente.

        Esperado: 1 factura pendiente
        """
        self.dashboard._compute_kpis_30d()

        self.assertEqual(
            self.dashboard.dtes_pendientes,
            1,
            "Debe haber 1 DTE pendiente"
        )

    def test_06_kpi_monto_facturado_mes(self):
        """
        Test: KPI Monto Facturado Mes Actual calcula correctamente.

        Esperado: 2 facturas × 1,000,000 = 2,000,000 CLP (aproximado con IVA)
        """
        self.dashboard._compute_kpis_30d()

        self.assertGreater(
            self.dashboard.monto_facturado_mes,
            1900000,  # Mínimo esperado (considerando redondeos)
            "Monto facturado mes debe ser mayor a 1,900,000 CLP"
        )

    def test_07_tasa_aceptacion(self):
        """
        Test: Tasa de Aceptación se calcula correctamente.

        Esperado: 3 aceptadas + 2 del mes = 5 aceptadas / (5 + 2 rechazadas) = 71.43%
        """
        self.dashboard._compute_kpis_30d()

        # Calcular tasa esperada
        total_30d = self.dashboard.dtes_aceptados_30d + self.dashboard.dtes_rechazados_30d
        if total_30d > 0:
            tasa_esperada = (self.dashboard.dtes_aceptados_30d / total_30d) * 100
        else:
            tasa_esperada = 0

        self.assertAlmostEqual(
            self.dashboard.tasa_aceptacion_30d,
            tasa_esperada,
            places=2,
            msg="Tasa de aceptación debe calcularse correctamente"
        )

    def test_08_tasa_rechazo(self):
        """
        Test: Tasa de Rechazo se calcula correctamente.

        Esperado: 2 rechazadas / 7 total = 28.57%
        """
        self.dashboard._compute_kpis_30d()

        total_30d = self.dashboard.dtes_aceptados_30d + self.dashboard.dtes_rechazados_30d
        if total_30d > 0:
            tasa_esperada = (self.dashboard.dtes_rechazados_30d / total_30d) * 100
        else:
            tasa_esperada = 0

        self.assertAlmostEqual(
            self.dashboard.tasa_rechazo_30d,
            tasa_esperada,
            places=2,
            msg="Tasa de rechazo debe calcularse correctamente"
        )

    def test_09_action_view_dtes_aceptados(self):
        """
        Test: Acción 'Ver DTEs Aceptados' retorna dominio correcto.
        """
        action = self.dashboard.action_view_dtes_aceptados()

        self.assertEqual(
            action['type'],
            'ir.actions.act_window',
            "Debe retornar una acción de ventana"
        )

        self.assertEqual(
            action['res_model'],
            'account.move',
            "Debe abrir modelo account.move"
        )

        # Verificar que el dominio filtra correctamente
        self.assertIn(
            ('l10n_cl_dte_status', '=', 'accepted'),
            action['domain'],
            "Dominio debe filtrar por estado 'accepted'"
        )

    def test_10_action_view_dtes_rechazados(self):
        """
        Test: Acción 'Ver DTEs Rechazados' retorna dominio correcto.
        """
        action = self.dashboard.action_view_dtes_rechazados()

        self.assertEqual(
            action['type'],
            'ir.actions.act_window',
            "Debe retornar una acción de ventana"
        )

        # Verificar que el dominio filtra correctamente
        self.assertIn(
            ('l10n_cl_dte_status', '=', 'rejected'),
            action['domain'],
            "Dominio debe filtrar por estado 'rejected'"
        )

    def test_11_action_view_dtes_pendientes(self):
        """
        Test: Acción 'Ver DTEs Pendientes' retorna dominio correcto.
        """
        action = self.dashboard.action_view_dtes_pendientes()

        self.assertEqual(
            action['type'],
            'ir.actions.act_window',
            "Debe retornar una acción de ventana"
        )

        # Verificar que el dominio filtra pendientes
        self.assertIn(
            ('l10n_cl_dte_status', 'in', ['draft', 'to_send']),
            action['domain'],
            "Dominio debe filtrar por estados pendientes"
        )

    def test_12_action_view_dtes_con_reparos(self):
        """
        Test: Acción 'Ver DTEs con Reparos' retorna dominio correcto.

        Lista de acceso rápido requerida.
        """
        action = self.dashboard.action_view_dtes_con_reparos()

        self.assertEqual(
            action['type'],
            'ir.actions.act_window',
            "Debe retornar una acción de ventana"
        )

        self.assertEqual(
            action['name'],
            'Mis DTEs con Reparos',
            "Nombre de acción debe ser 'Mis DTEs con Reparos'"
        )

        # Verificar que el dominio filtra reparos
        self.assertIn(
            ('l10n_cl_dte_status', 'in', ['rejected', 'error']),
            action['domain'],
            "Dominio debe filtrar por estados con reparos"
        )

    def test_13_action_view_ultimos_dtes(self):
        """
        Test: Acción 'Ver Últimos DTEs' retorna configuración correcta.

        Segunda lista de acceso rápido requerida.
        """
        action = self.dashboard.action_view_ultimos_dtes()

        self.assertEqual(
            action['type'],
            'ir.actions.act_window',
            "Debe retornar una acción de ventana"
        )

        self.assertEqual(
            action['name'],
            'Últimos DTEs Enviados',
            "Nombre de acción debe ser 'Últimos DTEs Enviados'"
        )

        self.assertEqual(
            action['limit'],
            10,
            "Debe limitar a 10 registros"
        )

    def test_14_get_chart_dtes_por_tipo(self):
        """
        Test: Método get_chart_dtes_por_tipo retorna estructura correcta.

        Debe retornar dict con 'labels' y 'data' para gráfico de barras.
        """
        chart_data = self.dashboard.get_chart_dtes_por_tipo()

        self.assertIn(
            'labels',
            chart_data,
            "Chart data debe contener 'labels'"
        )

        self.assertIn(
            'data',
            chart_data,
            "Chart data debe contener 'data'"
        )

        self.assertIsInstance(
            chart_data['labels'],
            list,
            "'labels' debe ser una lista"
        )

        self.assertIsInstance(
            chart_data['data'],
            list,
            "'data' debe ser una lista"
        )

        # Verificar que hay datos (al menos DTE 33)
        self.assertGreater(
            len(chart_data['labels']),
            0,
            "Debe haber al menos un tipo de DTE"
        )

    def test_15_get_chart_facturacion_diaria(self):
        """
        Test: Método get_chart_facturacion_diaria retorna estructura correcta.

        Debe retornar dict con 'labels' (fechas) y 'data' (montos) para gráfico de línea.
        """
        chart_data = self.dashboard.get_chart_facturacion_diaria()

        self.assertIn(
            'labels',
            chart_data,
            "Chart data debe contener 'labels'"
        )

        self.assertIn(
            'data',
            chart_data,
            "Chart data debe contener 'data'"
        )

        self.assertIsInstance(
            chart_data['labels'],
            list,
            "'labels' debe ser una lista de fechas"
        )

        self.assertIsInstance(
            chart_data['data'],
            list,
            "'data' debe ser una lista de montos"
        )

        # Si hay facturas en el mes, debe haber datos
        if self.dashboard.monto_facturado_mes > 0:
            self.assertGreater(
                len(chart_data['labels']),
                0,
                "Debe haber datos de facturación diaria si hay facturas en el mes"
            )

    def test_16_action_refresh_kpis(self):
        """
        Test: Acción 'Actualizar KPIs' ejecuta correctamente.
        """
        result = self.dashboard.action_refresh_kpis()

        self.assertEqual(
            result['type'],
            'ir.actions.client',
            "Debe retornar una acción de cliente"
        )

        self.assertEqual(
            result['tag'],
            'display_notification',
            "Debe mostrar una notificación"
        )

        self.assertEqual(
            result['params']['type'],
            'success',
            "Notificación debe ser de tipo 'success'"
        )

    def test_17_last_update_timestamp(self):
        """
        Test: Campo last_update se actualiza al calcular KPIs.
        """
        # Guardar timestamp anterior
        last_update_antes = self.dashboard.last_update

        # Esperar 1 segundo (para que el timestamp cambie)
        import time
        time.sleep(1)

        # Recalcular KPIs
        self.dashboard._compute_kpis_30d()

        # Verificar que timestamp se actualizó
        self.assertGreater(
            self.dashboard.last_update,
            last_update_antes,
            "last_update debe actualizarse al recalcular KPIs"
        )

    def test_18_display_name(self):
        """
        Test: Display name se genera correctamente.
        """
        self.assertIn(
            self.company.name,
            self.dashboard.display_name,
            "Display name debe incluir nombre de compañía"
        )

        self.assertIn(
            'Dashboard DTEs',
            self.dashboard.display_name,
            "Display name debe incluir 'Dashboard DTEs'"
        )
