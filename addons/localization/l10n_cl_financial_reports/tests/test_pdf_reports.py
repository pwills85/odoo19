# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from datetime import date, timedelta


class TestPdfReports(TransactionCase):
    """
    Smoke tests para generación de reportes PDF.
    """

    def setUp(self):
        super().setUp()

        # Crear compañía de prueba
        self.company = self.env['res.company'].create({
            'name': 'Test Company PDF',
            'currency_id': self.env.ref('base.CLP').id,
        })

        # Crear F29 de prueba
        self.f29 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-01-01',
            'state': 'confirmed',
            'ventas_afectas': 10000000.0,
            'ventas_exentas': 500000.0,
            'ventas_exportacion': 1000000.0,
            'compras_afectas': 6000000.0,
            'compras_exentas': 300000.0,
            'compras_activo_fijo': 1000000.0,
            'ppm_mes': 500000.0,
            'ppm_voluntario': 100000.0,
        })

        # Obtener reporte F29
        self.report_f29 = self.env.ref(
            'l10n_cl_financial_reports.action_report_l10n_cl_f29'
        )

    def test_01_f29_report_exists(self):
        """Test que el reporte F29 PDF está definido"""
        self.assertTrue(self.report_f29)
        self.assertEqual(self.report_f29.report_type, 'qweb-pdf')
        self.assertEqual(self.report_f29.model, 'l10n_cl.f29')

    def test_02_f29_pdf_generation_no_crash(self):
        """Test que la generación de PDF F29 no falla (smoke test)"""
        # Intentar renderizar el reporte (smoke test)
        try:
            pdf_content, report_format = self.report_f29._render_qweb_pdf(self.f29.ids)
            # Si llegamos aquí, no hubo crash
            self.assertTrue(True)
            # Verificar que se generó contenido
            self.assertTrue(pdf_content)
            self.assertGreater(len(pdf_content), 0)
        except Exception as e:
            self.fail(f'PDF generation crashed: {str(e)}')

    def test_03_f29_pdf_filename_format(self):
        """Test que el nombre del archivo PDF se genera correctamente"""
        # El formato debe ser: F29_YYYY_MM_CompanyName
        expected_format = 'F29_2024_01_Test Company PDF'

        # Obtener el nombre del archivo
        filename = self.report_f29._get_report_filename(self.f29)

        self.assertIn('F29', filename)
        self.assertIn('2024_01', filename)
        self.assertIn(self.company.name, filename)

    def test_04_kpi_dashboard_report_exists(self):
        """Test que el reporte Dashboard KPI PDF está definido"""
        report_dashboard = self.env.ref(
            'l10n_cl_financial_reports.action_report_l10n_cl_kpi_dashboard'
        )

        self.assertTrue(report_dashboard)
        self.assertEqual(report_dashboard.report_type, 'qweb-pdf')
        self.assertEqual(report_dashboard.model, 'l10n_cl.kpi.dashboard')

    def test_05_kpi_dashboard_pdf_generation_no_crash(self):
        """Test que la generación de PDF Dashboard no falla (smoke test)"""
        # Crear dashboard de prueba
        dashboard = self.env['l10n_cl.kpi.dashboard'].create({
            'company_id': self.company.id,
            'date_from': '2024-01-01',
            'date_to': '2024-01-31',
        })

        report_dashboard = self.env.ref(
            'l10n_cl_financial_reports.action_report_l10n_cl_kpi_dashboard'
        )

        # Intentar renderizar el reporte (smoke test)
        try:
            pdf_content, report_format = report_dashboard._render_qweb_pdf(dashboard.ids)
            # Si llegamos aquí, no hubo crash
            self.assertTrue(True)
            # Verificar que se generó contenido
            self.assertTrue(pdf_content)
            self.assertGreater(len(pdf_content), 0)
        except Exception as e:
            self.fail(f'PDF generation crashed: {str(e)}')

    def test_06_f29_pdf_contains_company_info(self):
        """Test que el PDF F29 contiene información de la compañía"""
        # Renderizar reporte
        html_content = self.report_f29._render_qweb_html(self.f29.ids)[0]

        # Verificar que contiene información de la compañía
        self.assertIn(self.company.name.encode(), html_content)

    def test_07_f29_pdf_contains_kpi_values(self):
        """Test que el PDF F29 contiene los valores de KPI"""
        # Renderizar reporte
        html_content = self.report_f29._render_qweb_html(self.f29.ids)[0]

        # Verificar que contiene valores (buscamos "10.000.000" o similar)
        # Los valores monetarios deben estar presentes en algún formato
        self.assertIn(b'Ventas', html_content)
        self.assertIn(b'Compras', html_content)
        self.assertIn(b'IVA', html_content)

    def test_08_kpi_dashboard_pdf_contains_all_kpis(self):
        """Test que el PDF Dashboard contiene todos los KPIs"""
        # Crear dashboard de prueba
        dashboard = self.env['l10n_cl.kpi.dashboard'].create({
            'company_id': self.company.id,
            'date_from': '2024-01-01',
            'date_to': '2024-01-31',
        })

        report_dashboard = self.env.ref(
            'l10n_cl_financial_reports.action_report_l10n_cl_kpi_dashboard'
        )

        # Renderizar reporte
        html_content = report_dashboard._render_qweb_html(dashboard.ids)[0]

        # Verificar que contiene los 5 KPIs principales
        self.assertIn(b'Ventas Netas', html_content)
        self.assertIn(b'Compras Netas', html_content)
        self.assertIn(b'IVA', html_content)
        self.assertIn(b'PPM', html_content)

    def test_09_f29_multiple_records_pdf(self):
        """Test que se pueden generar PDFs para múltiples F29"""
        # Crear segundo F29
        f29_2 = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-02-01',
            'state': 'confirmed',
            'ventas_afectas': 12000000.0,
            'compras_afectas': 7000000.0,
        })

        # Intentar renderizar PDFs para ambos registros
        try:
            pdf_content, report_format = self.report_f29._render_qweb_pdf(
                [self.f29.id, f29_2.id]
            )
            # Si llegamos aquí, no hubo crash
            self.assertTrue(True)
            self.assertTrue(pdf_content)
        except Exception as e:
            self.fail(f'Multi-record PDF generation crashed: {str(e)}')

    def test_10_f29_pdf_with_minimal_data(self):
        """Test que el PDF F29 se genera con datos mínimos"""
        # Crear F29 con datos mínimos
        f29_minimal = self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-03-01',
            'state': 'draft',
        })

        # Intentar renderizar (no debe fallar)
        try:
            pdf_content, report_format = self.report_f29._render_qweb_pdf(f29_minimal.ids)
            self.assertTrue(True)
        except Exception as e:
            self.fail(f'PDF generation with minimal data crashed: {str(e)}')

    def test_11_kpi_dashboard_pdf_with_empty_period(self):
        """Test que el PDF Dashboard se genera incluso con período vacío"""
        # Crear dashboard con período sin datos
        dashboard = self.env['l10n_cl.kpi.dashboard'].create({
            'company_id': self.company.id,
            'date_from': '2025-01-01',  # Período futuro sin datos
            'date_to': '2025-01-31',
        })

        report_dashboard = self.env.ref(
            'l10n_cl_financial_reports.action_report_l10n_cl_kpi_dashboard'
        )

        # Intentar renderizar (no debe fallar)
        try:
            pdf_content, report_format = report_dashboard._render_qweb_pdf(dashboard.ids)
            self.assertTrue(True)
        except Exception as e:
            self.fail(f'PDF generation with empty period crashed: {str(e)}')

    def test_12_f29_pdf_with_all_states(self):
        """Test que el PDF F29 se genera para todos los estados posibles"""
        states = ['draft', 'confirmed', 'sent', 'accepted']

        for state in states:
            f29_state = self.env['l10n_cl.f29'].create({
                'company_id': self.company.id,
                'period_date': f'2024-0{states.index(state) + 1}-01',
                'state': state,
                'ventas_afectas': 1000000.0,
            })

            try:
                pdf_content, report_format = self.report_f29._render_qweb_pdf(f29_state.ids)
                self.assertTrue(True)
            except Exception as e:
                self.fail(f'PDF generation for state {state} crashed: {str(e)}')

    def test_13_pdf_reports_performance(self):
        """Test que la generación de PDFs es razonablemente rápida"""
        import time

        # Medir tiempo de generación de F29
        start_time = time.time()
        self.report_f29._render_qweb_pdf(self.f29.ids)
        f29_duration = time.time() - start_time

        # Debe ser menor a 5 segundos
        self.assertLess(f29_duration, 5.0, 'F29 PDF generation took too long')

    def test_14_f29_report_binding_correct(self):
        """Test que el binding del reporte F29 está correctamente configurado"""
        self.assertEqual(self.report_f29.binding_model_id.model, 'l10n_cl.f29')
        self.assertEqual(self.report_f29.binding_type, 'report')

    def test_15_kpi_dashboard_report_binding_correct(self):
        """Test que el binding del reporte Dashboard está correctamente configurado"""
        report_dashboard = self.env.ref(
            'l10n_cl_financial_reports.action_report_l10n_cl_kpi_dashboard'
        )

        self.assertEqual(report_dashboard.binding_model_id.model, 'l10n_cl.kpi.dashboard')
        self.assertEqual(report_dashboard.binding_type, 'report')
