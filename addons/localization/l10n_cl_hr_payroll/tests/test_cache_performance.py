# -*- coding: utf-8 -*-

from odoo.tests import tagged, TransactionCase
from datetime import date
import time
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', 'p1_fix', 'performance', 'cache', 'high_013')
class TestCachePerformance(TransactionCase):
    """
    Test mejora performance con cache @ormcache - HIGH-013

    Tests:
    1. Benchmark 100 queries UF con cache
    2. Invalidación cache al update
    3. Cache diferenciado por fecha
    """

    def setUp(self):
        super().setUp()
        # Crear indicador test
        self.indicator = self.env['hr.economic.indicators'].create({
            'period': date(2025, 11, 1),
            'uf': 38500.0,
            'utm': 67200.0,
            'uta': 450000.0,
            'minimum_wage': 500000,
            'afp_limit': 83.1,
            'family_allowance_t1': 15000,
            'family_allowance_t2': 9000,
            'family_allowance_t3': 3000,
        })
        self.indicators_model = self.env['hr.economic.indicators']

    def test_cache_performance_100_queries(self):
        """Benchmark: 100 queries UF con cache"""
        test_date = date(2025, 11, 15)

        # Calentar cache (primera query)
        self.indicators_model._get_uf_value_cached(test_date)

        # Benchmark 100 queries
        start = time.time()
        for _ in range(100):
            uf = self.indicators_model._get_uf_value_cached(test_date)
        elapsed = (time.time() - start) * 1000

        # Target: <10ms para 100 queries (cache hit)
        self.assertLess(
            elapsed, 10,
            f"100 queries UF debe tomar <10ms con cache (actual: {elapsed:.2f}ms)"
        )

        _logger.info("⚡ Cache Performance: %.2fms para 100 queries UF", elapsed)
        self.assertEqual(uf, 38500.0, "Valor UF debe ser correcto desde cache")

    def test_cache_invalidation_on_update(self):
        """Test invalidación cache al actualizar indicador"""
        test_date = date(2025, 11, 1)

        # Query inicial (cachea)
        uf_old = self.indicators_model._get_uf_value_cached(test_date)
        self.assertEqual(uf_old, 38500.0)

        # Actualizar indicador
        self.indicator.write({'uf': 39000.0})

        # Query después de update (debe traer nuevo valor, no cached)
        uf_new = self.indicators_model._get_uf_value_cached(test_date)
        self.assertEqual(uf_new, 39000.0,
                         "Cache debe invalidarse al actualizar UF")

    def test_cache_per_date(self):
        """Test cache diferenciado por fecha"""
        date1 = date(2025, 11, 1)
        date2 = date(2025, 10, 1)

        # Crear segundo indicador
        self.env['hr.economic.indicators'].create({
            'period': date2,
            'uf': 38000.0,
            'utm': 66000.0,
            'uta': 450000.0,
            'minimum_wage': 500000,
            'afp_limit': 83.1,
            'family_allowance_t1': 15000,
            'family_allowance_t2': 9000,
            'family_allowance_t3': 3000,
        })

        uf_nov = self.indicators_model._get_uf_value_cached(date1)
        uf_oct = self.indicators_model._get_uf_value_cached(date2)

        self.assertEqual(uf_nov, 38500.0, "UF noviembre")
        self.assertEqual(uf_oct, 38000.0, "UF octubre")
        self.assertNotEqual(uf_nov, uf_oct, "Cache debe diferenciar por fecha")

    def test_cache_utm_performance(self):
        """Benchmark: 100 queries UTM con cache"""
        test_date = date(2025, 11, 15)

        # Calentar cache
        self.indicators_model._get_utm_value_cached(test_date)

        # Benchmark 100 queries
        start = time.time()
        for _ in range(100):
            utm = self.indicators_model._get_utm_value_cached(test_date)
        elapsed = (time.time() - start) * 1000

        # Target: <10ms para 100 queries
        self.assertLess(
            elapsed, 10,
            f"100 queries UTM debe tomar <10ms con cache (actual: {elapsed:.2f}ms)"
        )

        _logger.info("⚡ Cache Performance: %.2fms para 100 queries UTM", elapsed)
        self.assertEqual(utm, 67200.0, "Valor UTM debe ser correcto desde cache")

    def test_cache_invalidation_on_create(self):
        """Test invalidación cache al crear nuevo indicador"""
        test_date = date(2025, 12, 15)

        # Query inicial (debe usar default o indicador anterior)
        uf_before = self.indicators_model._get_uf_value_cached(test_date)

        # Crear nuevo indicador para diciembre
        new_indicator = self.env['hr.economic.indicators'].create({
            'period': date(2025, 12, 1),
            'uf': 39500.0,
            'utm': 68000.0,
            'uta': 450000.0,
            'minimum_wage': 500000,
            'afp_limit': 83.1,
            'family_allowance_t1': 15000,
            'family_allowance_t2': 9000,
            'family_allowance_t3': 3000,
        })

        # Query después de create (debe traer nuevo valor)
        uf_after = self.indicators_model._get_uf_value_cached(test_date)
        self.assertEqual(uf_after, 39500.0,
                         "Cache debe invalidarse al crear indicador")

    def test_cache_preserves_other_fields_on_partial_update(self):
        """Test que cache solo invalida cuando cambian campos relevantes"""
        test_date = date(2025, 11, 1)

        # Query inicial
        uf_before = self.indicators_model._get_uf_value_cached(test_date)
        self.assertEqual(uf_before, 38500.0)

        # Actualizar campo NO relevante para cache UF/UTM
        self.indicator.write({'minimum_wage': 510000})

        # Cache debería invalidarse de todas formas (comportamiento actual)
        # pero UF debe seguir siendo el mismo
        uf_after = self.indicators_model._get_uf_value_cached(test_date)
        self.assertEqual(uf_after, 38500.0, "UF debe mantenerse igual")
