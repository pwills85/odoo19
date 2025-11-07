# -*- coding: utf-8 -*-

from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError
from datetime import date, timedelta
import time


class TestKPIService(TransactionCase):
    """
    Tests para el servicio de KPIs del dashboard con integración de cache.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Crear compañía de prueba
        cls.company = cls.env['res.company'].create({
            'name': 'Test Company KPI',
            'currency_id': cls.env.ref('base.CLP').id,
        })

        # Crear registros F29 de prueba para un año
        cls.f29_records = []

        # Mes 1: Enero 2024
        cls.f29_01 = cls.env['l10n_cl.f29'].create({
            'company_id': cls.company.id,
            'period_date': '2024-01-01',
            'state': 'confirmed',
            'ventas_afectas': 10000000.0,  # 10M
            'ventas_exentas': 1000000.0,   # 1M
            'ventas_exportacion': 500000.0,  # 0.5M
            'compras_afectas': 6000000.0,   # 6M
            'compras_exentas': 500000.0,    # 0.5M
            'compras_activo_fijo': 1000000.0,  # 1M
            'ppm_mes': 200000.0,            # 200K
            'ppm_voluntario': 50000.0,      # 50K
        })

        # Mes 2: Febrero 2024
        cls.f29_02 = cls.env['l10n_cl.f29'].create({
            'company_id': cls.company.id,
            'period_date': '2024-02-01',
            'state': 'confirmed',
            'ventas_afectas': 12000000.0,
            'ventas_exentas': 1200000.0,
            'ventas_exportacion': 600000.0,
            'compras_afectas': 7000000.0,
            'compras_exentas': 600000.0,
            'compras_activo_fijo': 1200000.0,
            'ppm_mes': 250000.0,
            'ppm_voluntario': 60000.0,
        })

        # Mes 3: Marzo 2024
        cls.f29_03 = cls.env['l10n_cl.f29'].create({
            'company_id': cls.company.id,
            'period_date': '2024-03-01',
            'state': 'confirmed',
            'ventas_afectas': 15000000.0,
            'ventas_exentas': 1500000.0,
            'ventas_exportacion': 700000.0,
            'compras_afectas': 9000000.0,
            'compras_exentas': 700000.0,
            'compras_activo_fijo': 1500000.0,
            'ppm_mes': 300000.0,
            'ppm_voluntario': 70000.0,
        })

        cls.f29_records = cls.f29_01 + cls.f29_02 + cls.f29_03

        # Servicio KPI
        cls.kpi_service = cls.env['account.financial.report.kpi.service']

    def test_01_compute_kpis_single_month(self):
        """Test que compute_kpis calcula correctamente KPIs de un mes"""
        kpis = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )

        # Verificar estructura del resultado
        self.assertIn('iva_debito_fiscal', kpis)
        self.assertIn('iva_credito_fiscal', kpis)
        self.assertIn('ventas_netas', kpis)
        self.assertIn('compras_netas', kpis)
        self.assertIn('ppm_pagado', kpis)
        self.assertIn('cache_hit', kpis)
        self.assertIn('calculation_time_ms', kpis)

        # Verificar valores calculados (Enero 2024)
        # IVA Débito = 10M * 0.19 = 1.9M (calculado por computed field)
        self.assertAlmostEqual(kpis['iva_debito_fiscal'], 1900000.0, places=2)

        # IVA Crédito = (6M + 1M) * 0.19 = 1.33M
        self.assertAlmostEqual(kpis['iva_credito_fiscal'], 1330000.0, places=2)

        # Ventas Netas = 10M + 1M + 0.5M = 11.5M
        self.assertEqual(kpis['ventas_netas'], 11500000.0)

        # Compras Netas = 6M + 0.5M + 1M = 7.5M
        self.assertEqual(kpis['compras_netas'], 7500000.0)

        # PPM Pagado = 200K + 50K = 250K
        self.assertEqual(kpis['ppm_pagado'], 250000.0)

        # Primera llamada no debe ser cache hit
        self.assertFalse(kpis['cache_hit'])

    def test_02_compute_kpis_multiple_months(self):
        """Test que compute_kpis agrega correctamente múltiples meses"""
        kpis = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-03-31'
        )

        # Ventas Netas Q1 = (10M+1M+0.5M) + (12M+1.2M+0.6M) + (15M+1.5M+0.7M)
        #                  = 11.5M + 13.8M + 17.2M = 42.5M
        expected_ventas = 11500000.0 + 13800000.0 + 17200000.0
        self.assertEqual(kpis['ventas_netas'], expected_ventas)

        # Compras Netas Q1 = (6M+0.5M+1M) + (7M+0.6M+1.2M) + (9M+0.7M+1.5M)
        #                  = 7.5M + 8.8M + 11.2M = 27.5M
        expected_compras = 7500000.0 + 8800000.0 + 11200000.0
        self.assertEqual(kpis['compras_netas'], expected_compras)

        # PPM Pagado Q1 = 250K + 310K + 370K = 930K
        expected_ppm = 250000.0 + 310000.0 + 370000.0
        self.assertEqual(kpis['ppm_pagado'], expected_ppm)

    def test_03_cache_hit_on_second_call(self):
        """Test que la segunda llamada usa cache"""
        # Primera llamada (cache MISS)
        kpis1 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-02-01',
            period_end='2024-02-29'
        )
        self.assertFalse(kpis1['cache_hit'])

        # Segunda llamada (cache HIT)
        kpis2 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-02-01',
            period_end='2024-02-29'
        )
        self.assertTrue(kpis2['cache_hit'])

        # Los valores deben ser idénticos
        self.assertEqual(kpis1['ventas_netas'], kpis2['ventas_netas'])
        self.assertEqual(kpis1['compras_netas'], kpis2['compras_netas'])
        self.assertEqual(kpis1['ppm_pagado'], kpis2['ppm_pagado'])

    def test_04_cache_improves_performance(self):
        """Test que el cache mejora significativamente el rendimiento"""
        # Primera llamada (sin cache)
        start1 = time.time()
        kpis1 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-03-31'
        )
        time1_ms = (time.time() - start1) * 1000

        # Segunda llamada (con cache)
        start2 = time.time()
        kpis2 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-03-31'
        )
        time2_ms = (time.time() - start2) * 1000

        # Cache debe ser más rápido
        self.assertFalse(kpis1['cache_hit'])
        self.assertTrue(kpis2['cache_hit'])

        # Segunda llamada debe ser < 200ms (criterio de aceptación)
        self.assertLess(time2_ms, 200, f"Cache hit tomó {time2_ms}ms (debería ser <200ms)")

        # Cache debe ser al menos 2x más rápido
        self.assertLess(time2_ms, time1_ms / 2, "Cache debería ser al menos 2x más rápido")

    def test_05_compute_kpis_no_data_returns_zeros(self):
        """Test que compute_kpis retorna 0s cuando no hay datos"""
        # Crear compañía sin datos
        empty_company = self.env['res.company'].create({
            'name': 'Empty Company',
            'currency_id': self.env.ref('base.CLP').id,
        })

        kpis = self.kpi_service.compute_kpis(
            company=empty_company,
            period_start='2024-01-01',
            period_end='2024-12-31'
        )

        # Todos los KPIs deben ser 0
        self.assertEqual(kpis['iva_debito_fiscal'], 0.0)
        self.assertEqual(kpis['iva_credito_fiscal'], 0.0)
        self.assertEqual(kpis['ventas_netas'], 0.0)
        self.assertEqual(kpis['compras_netas'], 0.0)
        self.assertEqual(kpis['ppm_pagado'], 0.0)

    def test_06_compute_kpis_validates_input(self):
        """Test que compute_kpis valida inputs incorrectos"""
        # Sin compañía
        with self.assertRaises(UserError):
            self.kpi_service.compute_kpis(
                company=None,
                period_start='2024-01-01',
                period_end='2024-12-31'
            )

        # Fechas inválidas
        with self.assertRaises(UserError):
            self.kpi_service.compute_kpis(
                company=self.company,
                period_start='invalid-date',
                period_end='2024-12-31'
            )

    def test_07_compute_kpis_accepts_date_objects(self):
        """Test que compute_kpis acepta objetos date además de strings"""
        kpis = self.kpi_service.compute_kpis(
            company=self.company,
            period_start=date(2024, 1, 1),
            period_end=date(2024, 1, 31)
        )

        self.assertIsNotNone(kpis)
        self.assertEqual(kpis['period_start'], '2024-01-01')
        self.assertEqual(kpis['period_end'], '2024-01-31')

    def test_08_invalidate_kpi_cache_specific_period(self):
        """Test que invalidate_kpi_cache invalida cache de un período específico"""
        # Calcular KPIs (genera cache)
        kpis1 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )
        self.assertFalse(kpis1['cache_hit'])

        # Segunda llamada debe usar cache
        kpis2 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )
        self.assertTrue(kpis2['cache_hit'])

        # Invalidar cache
        self.kpi_service.invalidate_kpi_cache(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )

        # Tercera llamada NO debe usar cache (fue invalidado)
        kpis3 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )
        self.assertFalse(kpis3['cache_hit'])

    def test_09_invalidate_kpi_cache_entire_company(self):
        """Test que invalidate_kpi_cache puede invalidar todo el cache de una compañía"""
        # Calcular KPIs para dos períodos diferentes
        kpis1 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )
        kpis2 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-02-01',
            period_end='2024-02-29'
        )

        # Ambos deben cachear
        kpis1_cached = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )
        kpis2_cached = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-02-01',
            period_end='2024-02-29'
        )
        self.assertTrue(kpis1_cached['cache_hit'])
        self.assertTrue(kpis2_cached['cache_hit'])

        # Invalidar TODO el cache de la compañía
        self.kpi_service.invalidate_kpi_cache(company=self.company)

        # Ambos períodos deben recalcular (cache invalidado)
        kpis1_new = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )
        kpis2_new = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-02-01',
            period_end='2024-02-29'
        )
        self.assertFalse(kpis1_new['cache_hit'])
        self.assertFalse(kpis2_new['cache_hit'])

    def test_10_get_kpi_trends_monthly(self):
        """Test que get_kpi_trends retorna tendencias mensuales correctamente"""
        trends = self.kpi_service.get_kpi_trends(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-03-31',
            granularity='month'
        )

        # Debe retornar 3 meses (Enero, Febrero, Marzo)
        self.assertEqual(len(trends), 3)

        # Verificar estructura de cada trend
        for trend in trends:
            self.assertIn('period', trend)
            self.assertIn('iva_debito_fiscal', trend)
            self.assertIn('ventas_netas', trend)

        # Verificar períodos
        self.assertEqual(trends[0]['period'], '2024-01')
        self.assertEqual(trends[1]['period'], '2024-02')
        self.assertEqual(trends[2]['period'], '2024-03')

        # Verificar valores de Enero
        self.assertEqual(trends[0]['ventas_netas'], 11500000.0)
        # Febrero
        self.assertEqual(trends[1]['ventas_netas'], 13800000.0)
        # Marzo
        self.assertEqual(trends[2]['ventas_netas'], 17200000.0)

    def test_11_compute_kpis_only_confirmed_f29(self):
        """Test que compute_kpis solo considera F29 en estado válido"""
        # Crear F29 en draft (no debe contarse)
        self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-04-01',
            'state': 'draft',  # DRAFT no se cuenta
            'ventas_afectas': 99999999.0,  # Valor muy alto para detectar si se cuenta
        })

        # Crear F29 cancelado (no debe contarse)
        self.env['l10n_cl.f29'].create({
            'company_id': self.company.id,
            'period_date': '2024-05-01',
            'state': 'cancel',  # CANCEL no se cuenta
            'ventas_afectas': 88888888.0,
        })

        # Calcular KPIs para Q2
        kpis = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-04-01',
            period_end='2024-06-30'
        )

        # Ventas deben ser 0 (no hay F29 válidos en Q2)
        self.assertEqual(kpis['ventas_netas'], 0.0)

    def test_12_get_kpi_trends_invalid_granularity(self):
        """Test que get_kpi_trends valida granularidad"""
        with self.assertRaises(UserError):
            self.kpi_service.get_kpi_trends(
                company=self.company,
                period_start='2024-01-01',
                period_end='2024-12-31',
                granularity='invalid'  # Granularidad inválida
            )

    def test_13_compute_kpis_metadata_correctness(self):
        """Test que compute_kpis retorna metadata correcta"""
        kpis = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-03-31'
        )

        # Verificar metadata
        self.assertEqual(kpis['company_id'], self.company.id)
        self.assertEqual(kpis['company_name'], self.company.name)
        self.assertEqual(kpis['period_start'], '2024-01-01')
        self.assertEqual(kpis['period_end'], '2024-03-31')
        self.assertIsInstance(kpis['calculation_time_ms'], int)
        self.assertIsInstance(kpis['cache_hit'], bool)

    def test_14_kpi_service_multicompany_isolation(self):
        """Test que KPIs están aislados por compañía"""
        # Crear segunda compañía con sus propios F29
        company2 = self.env['res.company'].create({
            'name': 'Test Company 2',
            'currency_id': self.env.ref('base.CLP').id,
        })

        self.env['l10n_cl.f29'].create({
            'company_id': company2.id,
            'period_date': '2024-01-01',
            'state': 'confirmed',
            'ventas_afectas': 20000000.0,  # Diferente de company 1
        })

        # Calcular KPIs para ambas compañías
        kpis1 = self.kpi_service.compute_kpis(
            company=self.company,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )

        kpis2 = self.kpi_service.compute_kpis(
            company=company2,
            period_start='2024-01-01',
            period_end='2024-01-31'
        )

        # Los KPIs deben ser diferentes
        self.assertNotEqual(kpis1['ventas_netas'], kpis2['ventas_netas'])

        # Company 1: 11.5M
        self.assertEqual(kpis1['ventas_netas'], 11500000.0)

        # Company 2: 20M (solo ventas_afectas, sin exentas ni exportación)
        self.assertEqual(kpis2['ventas_netas'], 20000000.0)
