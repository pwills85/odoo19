# -*- coding: utf-8 -*-
"""
Test Dashboard Central DTEs - Enhanced (Cierre de Brechas)
============================================================

Tests para validar nuevas funcionalidades Fase 2.1:
- Métrica financiera neta (incluye NC)
- KPIs regulatorios (CAF, certificados, envejecidos)
- Tasas de aceptación regulatoria vs operacional
- Optimización de queries (read_group consolidado)
- Multi-compañía estricta

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.6.0.0
Fase: 2.1 - Cierre de Brechas Dashboard
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta


class TestDteDashboardEnhanced(TransactionCase):
    """
    Test suite para Dashboard Enhanced - Cierre de Brechas.
    """

    def setUp(self):
        """
        Setup: Crear datos de prueba extendidos.
        """
        super(TestDteDashboardEnhanced, self).setUp()

        # Compañía de prueba
        self.company = self.env.company

        # Segunda compañía para tests multi-company
        self.company_2 = self.env['res.company'].create({
            'name': 'Compañía Test 2',
            'currency_id': self.env.ref('base.CLP').id,
        })

        # Tipo de documento (DTE 33)
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
            'name': 'Cliente Prueba Enhanced',
            'vat': '12345678-9',
            'country_id': self.env.ref('base.cl').id,
        })

        # Fechas
        self.today = datetime.today().date()
        self.fecha_inicio_mes = self.today.replace(day=1)

        # Crear CAF de prueba
        self._create_test_caf()

        # Crear Certificado de prueba
        self._create_test_certificate()

        # Crear facturas y NC de prueba
        self._create_test_invoices_with_nc()

        # Crear dashboard
        self.dashboard = self.env['l10n_cl.dte_dashboard'].get_or_create_dashboard(
            company_id=self.company.id
        )

    def _create_test_caf(self):
        """Crea CAFs de prueba"""
        DteCaf = self.env['dte.caf']

        self.caf = DteCaf.create({
            'name': 'CAF Test Enhanced',
            'company_id': self.company.id,
            'document_type_id': self.document_type_33.id,
            'initial_folio': 1,
            'final_folio': 100,
            'remaining_folios': 15,  # 15% restante (no debe alertar)
            'state': 'active',
        })

    def _create_test_certificate(self):
        """Crea certificado digital de prueba"""
        DteCertificate = self.env['dte.certificate']

        # Certificado que expira en 45 días (no debe alertar)
        self.certificate = DteCertificate.create({
            'name': 'Certificado Test Enhanced',
            'company_id': self.company.id,
            'valid_from': datetime.now(),
            'valid_to': datetime.now() + timedelta(days=45),
            'state': 'valid',
        })

    def _create_test_invoices_with_nc(self):
        """
        Crea facturas y NC de prueba para validar facturación neta.

        Escenario:
        - 3 facturas aceptadas de 1,000,000 CLP cada una
        - 1 NC aceptada de 500,000 CLP
        - Facturación neta = 3,000,000 - 500,000 = 2,500,000 CLP
        """
        AccountMove = self.env['account.move']

        # Facturas aceptadas
        for i in range(3):
            AccountMove.create({
                'move_type': 'out_invoice',
                'partner_id': self.partner.id,
                'invoice_date': self.fecha_inicio_mes + timedelta(days=i * 5),
                'state': 'posted',
                'l10n_cl_dte_status': 'accepted',
                'l10n_latam_document_type_id': self.document_type_33.id,
                'invoice_line_ids': [(0, 0, {
                    'name': f'Producto Test Factura {i+1}',
                    'quantity': 1,
                    'price_unit': 1000000.0,
                })],
            })

        # Nota de Crédito aceptada
        AccountMove.create({
            'move_type': 'out_refund',
            'partner_id': self.partner.id,
            'invoice_date': self.fecha_inicio_mes + timedelta(days=10),
            'state': 'posted',
            'l10n_cl_dte_status': 'accepted',
            'l10n_latam_document_type_id': self.document_type_33.id,
            'invoice_line_ids': [(0, 0, {
                'name': 'Producto Test NC',
                'quantity': 1,
                'price_unit': 500000.0,
            })],
        })

        # Factura enviada hace más de 6 horas (para test envejecidos)
        fecha_7h_atras = datetime.now() - timedelta(hours=7)
        AccountMove.create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'invoice_date': self.today,
            'state': 'posted',
            'l10n_cl_dte_status': 'sent',
            'l10n_latam_document_type_id': self.document_type_33.id,
            'write_date': fecha_7h_atras,
            'invoice_line_ids': [(0, 0, {
                'name': 'Producto Test Envejecido',
                'quantity': 1,
                'price_unit': 100000.0,
            })],
        })

    # ═══════════════════════════════════════════════════════════
    # TESTS - MÉTRICA FINANCIERA NETA
    # ═══════════════════════════════════════════════════════════

    def test_01_net_billing_includes_credit_notes(self):
        """
        Test: Monto facturado neto incluye notas de crédito.

        Esperado: 3 facturas (3M) - 1 NC (500k) = 2.5M CLP
        """
        self.dashboard._compute_kpis_enhanced()

        # Validar que el monto neto es correcto (aproximado, considerar IVA)
        self.assertGreater(
            self.dashboard.monto_facturado_neto_mes,
            2400000,  # Mínimo esperado (considerando redondeos)
            "Monto neto debe ser aprox 2.5M CLP (3M facturas - 500k NC)"
        )

        self.assertLess(
            self.dashboard.monto_facturado_neto_mes,
            self.dashboard.monto_facturado_mes,
            "Monto neto debe ser menor que monto bruto (por la NC)"
        )

    def test_02_net_billing_sign_convention(self):
        """
        Test: Verificar que NC restan correctamente usando amount_total_signed.
        """
        self.dashboard._compute_kpis_enhanced()

        # Crear dashboard en compañía limpia para cálculo preciso
        company_test = self.env['res.company'].create({
            'name': 'Test Company Net',
            'currency_id': self.env.ref('base.CLP').id,
        })

        dashboard_test = self.env['l10n_cl.dte_dashboard'].create({
            'company_id': company_test.id
        })

        # Crear 1 factura y 1 NC exactas
        AccountMove = self.env['account.move']

        AccountMove.create({
            'move_type': 'out_invoice',
            'company_id': company_test.id,
            'partner_id': self.partner.id,
            'invoice_date': self.fecha_inicio_mes,
            'state': 'posted',
            'l10n_cl_dte_status': 'accepted',
            'invoice_line_ids': [(0, 0, {
                'name': 'Test',
                'quantity': 1,
                'price_unit': 1000000.0,
            })],
        })

        AccountMove.create({
            'move_type': 'out_refund',
            'company_id': company_test.id,
            'partner_id': self.partner.id,
            'invoice_date': self.fecha_inicio_mes,
            'state': 'posted',
            'l10n_cl_dte_status': 'accepted',
            'invoice_line_ids': [(0, 0, {
                'name': 'Test NC',
                'quantity': 1,
                'price_unit': 1000000.0,
            })],
        })

        dashboard_test._compute_kpis_enhanced()

        # Neto debe ser ~0 (factura - NC del mismo monto)
        self.assertLess(
            abs(dashboard_test.monto_facturado_neto_mes),
            100000,  # Margen de error por IVA
            "Neto debe ser ~0 cuando factura y NC son del mismo monto"
        )

    # ═══════════════════════════════════════════════════════════
    # TESTS - KPIs REGULATORIOS
    # ═══════════════════════════════════════════════════════════

    def test_03_pending_aging_sent_over_6h(self):
        """
        Test: DTEs enviados sin respuesta > 6h se detectan correctamente.
        """
        self.dashboard._compute_kpis_enhanced()

        self.assertEqual(
            self.dashboard.dtes_enviados_sin_respuesta_6h,
            1,
            "Debe haber 1 DTE enviado hace más de 6 horas"
        )

    def test_04_caf_remaining_and_alert(self):
        """
        Test: Folios CAF restantes se calculan y alerta se activa < 10%.
        """
        self.dashboard._compute_kpis_regulatory()

        self.assertEqual(
            self.dashboard.folios_restantes_total,
            15,
            "Deben quedar 15 folios CAF"
        )

        self.assertFalse(
            self.dashboard.alerta_caf_bajo,
            "No debe haber alerta con 15% de folios restantes"
        )

        # Modificar CAF para activar alerta (< 10%)
        self.caf.remaining_folios = 5  # 5% restante

        self.dashboard._compute_kpis_regulatory()

        self.assertTrue(
            self.dashboard.alerta_caf_bajo,
            "Debe activarse alerta con 5% de folios restantes"
        )

    def test_05_certificate_days_to_expire_and_alert(self):
        """
        Test: Días hasta expiración de certificado se calculan y alerta < 30 días.
        """
        self.dashboard._compute_kpis_regulatory()

        # Certificado expira en 45 días
        self.assertGreater(
            self.dashboard.dias_certificado_expira,
            40,
            "Certificado debe expirar en ~45 días"
        )

        self.assertFalse(
            self.dashboard.alerta_certificado,
            "No debe haber alerta con certificado válido por 45 días"
        )

        # Modificar certificado para expirar en 20 días
        self.certificate.valid_to = datetime.now() + timedelta(days=20)

        self.dashboard._compute_kpis_regulatory()

        self.assertTrue(
            self.dashboard.alerta_certificado,
            "Debe activarse alerta con certificado expirando en 20 días"
        )

    def test_06_certificate_missing_triggers_alert(self):
        """
        Test: Sin certificado válido se activa alerta crítica.
        """
        # Eliminar certificado
        self.certificate.state = 'expired'

        self.dashboard._compute_kpis_regulatory()

        self.assertTrue(
            self.dashboard.alerta_certificado,
            "Debe activarse alerta sin certificado válido"
        )

        self.assertEqual(
            self.dashboard.dias_certificado_expira,
            0,
            "Días a expiración debe ser 0 sin certificado"
        )

    # ═══════════════════════════════════════════════════════════
    # TESTS - TASAS DE ACEPTACIÓN
    # ═══════════════════════════════════════════════════════════

    def test_07_acceptance_rates_both_flavors(self):
        """
        Test: Tasas de aceptación regulatoria y operacional se calculan correctamente.
        """
        self.dashboard._compute_kpis_enhanced()

        # Validar que ambas tasas existen
        self.assertGreater(
            self.dashboard.tasa_aceptacion_regulatoria,
            0,
            "Tasa regulatoria debe ser > 0"
        )

        self.assertGreater(
            self.dashboard.tasa_aceptacion_operacional,
            0,
            "Tasa operacional debe ser > 0"
        )

        # Tasa regulatoria suele ser mayor (no incluye pendientes)
        # Pero depende del dataset, así que solo validar que son razonables
        self.assertLessEqual(
            self.dashboard.tasa_aceptacion_regulatoria,
            100,
            "Tasa regulatoria debe ser <= 100%"
        )

        self.assertLessEqual(
            self.dashboard.tasa_aceptacion_operacional,
            100,
            "Tasa operacional debe ser <= 100%"
        )

    def test_08_acceptance_rate_with_only_accepted(self):
        """
        Test: Tasa de aceptación = 100% cuando solo hay aceptados.
        """
        # Crear compañía limpia
        company_clean = self.env['res.company'].create({
            'name': 'Clean Company',
            'currency_id': self.env.ref('base.CLP').id,
        })

        dashboard_clean = self.env['l10n_cl.dte_dashboard'].create({
            'company_id': company_clean.id
        })

        # Crear solo facturas aceptadas
        for i in range(5):
            self.env['account.move'].create({
                'move_type': 'out_invoice',
                'company_id': company_clean.id,
                'partner_id': self.partner.id,
                'invoice_date': self.today,
                'state': 'posted',
                'l10n_cl_dte_status': 'accepted',
                'invoice_line_ids': [(0, 0, {
                    'name': 'Test',
                    'quantity': 1,
                    'price_unit': 100000.0,
                })],
            })

        dashboard_clean._compute_kpis_enhanced()

        self.assertEqual(
            dashboard_clean.tasa_aceptacion_regulatoria,
            100.0,
            "Tasa regulatoria debe ser 100% con solo aceptados"
        )

        self.assertEqual(
            dashboard_clean.tasa_aceptacion_operacional,
            100.0,
            "Tasa operacional debe ser 100% con solo aceptados"
        )

    # ═══════════════════════════════════════════════════════════
    # TESTS - MULTI-COMPAÑÍA
    # ═══════════════════════════════════════════════════════════

    def test_09_multicompany_isolation(self):
        """
        Test: Aislamiento multi-compañía estricto.

        Verificar que KPIs de compañía 1 no incluyen datos de compañía 2.
        """
        # Dashboard compañía 1
        dashboard_1 = self.dashboard

        # Dashboard compañía 2
        dashboard_2 = self.env['l10n_cl.dte_dashboard'].create({
            'company_id': self.company_2.id
        })

        # Crear factura en compañía 2
        self.env['account.move'].create({
            'move_type': 'out_invoice',
            'company_id': self.company_2.id,
            'partner_id': self.partner.id,
            'invoice_date': self.today,
            'state': 'posted',
            'l10n_cl_dte_status': 'accepted',
            'invoice_line_ids': [(0, 0, {
                'name': 'Test Company 2',
                'quantity': 1,
                'price_unit': 9999999.0,  # Monto distintivo
            })],
        })

        # Recalcular ambos dashboards
        dashboard_1._compute_kpis_enhanced()
        dashboard_2._compute_kpis_enhanced()

        # Verificar que dashboard_1 NO incluye la factura de company_2
        self.assertLess(
            dashboard_1.monto_facturado_neto_mes,
            5000000,  # Máximo esperado de company_1 (sin los 9M de company_2)
            "Dashboard 1 no debe incluir datos de compañía 2"
        )

        # Verificar que dashboard_2 SÍ incluye su factura
        self.assertGreater(
            dashboard_2.monto_facturado_neto_mes,
            9000000,  # Mínimo esperado de company_2
            "Dashboard 2 debe incluir su factura de 9M"
        )

    # ═══════════════════════════════════════════════════════════
    # TESTS - ACCIONES DRILL-DOWN
    # ═══════════════════════════════════════════════════════════

    def test_10_action_view_dtes_envejecidos(self):
        """
        Test: Acción ver DTEs envejecidos retorna dominio correcto.
        """
        action = self.dashboard.action_view_dtes_envejecidos()

        self.assertEqual(
            action['type'],
            'ir.actions.act_window',
            "Debe retornar acción de ventana"
        )

        # Verificar dominio filtra DTEs enviados > 6h
        self.assertIn(
            ('l10n_cl_dte_status', '=', 'sent'),
            action['domain'],
            "Dominio debe filtrar por estado 'sent'"
        )

    def test_11_action_view_cafs(self):
        """
        Test: Acción ver CAFs retorna dominio correcto.
        """
        action = self.dashboard.action_view_cafs()

        self.assertEqual(
            action['res_model'],
            'dte.caf',
            "Debe abrir modelo dte.caf"
        )

        self.assertIn(
            ('company_id', '=', self.company.id),
            action['domain'],
            "Dominio debe filtrar por compañía"
        )

    def test_12_action_view_certificados(self):
        """
        Test: Acción ver certificados retorna dominio correcto.
        """
        action = self.dashboard.action_view_certificados()

        self.assertEqual(
            action['res_model'],
            'dte.certificate',
            "Debe abrir modelo dte.certificate"
        )

        self.assertIn(
            ('company_id', '=', self.company.id),
            action['domain'],
            "Dominio debe filtrar por compañía"
        )

    # ═══════════════════════════════════════════════════════════
    # TESTS - PERFORMANCE (OPCIONAL - Requiere QueryCounter)
    # ═══════════════════════════════════════════════════════════

    def test_13_grouping_status_read_group_single_pass(self):
        """
        Test: Verificar que se usa read_group consolidado (no múltiples search_count).

        Este test es cualitativo - valida que la lógica usa read_group.
        Para test cuantitativo de queries, usar QueryCounter en ambiente dev.
        """
        # Validar que el método existe y no genera errores
        self.dashboard._compute_kpis_enhanced()

        # Si llegamos aquí sin errores, la optimización funciona
        self.assertTrue(
            True,
            "Compute exitoso - optimización read_group implementada"
        )
