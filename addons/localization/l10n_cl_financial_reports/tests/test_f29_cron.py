# -*- coding: utf-8 -*-
from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from odoo import fields
from datetime import timedelta
import logging

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'f29', 'cron')
class TestF29Cron(TransactionCase):
    """
    Tests para el método create_monthly_f29 (REP-C006)

    Cobertura:
    - Idempotencia: no crea duplicados
    - Multi-compañía: procesa todas las compañías habilitadas
    - Logging: verifica registro de eventos
    - Estado: F29 creado en draft
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Crear compañías de prueba
        cls.company_1 = cls.env['res.company'].create({
            'name': 'Test Company 1',
            'currency_id': cls.env.ref('base.CLP').id,
        })

        cls.company_2 = cls.env['res.company'].create({
            'name': 'Test Company 2',
            'currency_id': cls.env.ref('base.CLP').id,
        })

        # Modelo F29
        cls.f29_model = cls.env['l10n_cl.f29']

    def test_create_monthly_f29_creates_one_per_company(self):
        """
        Test: create_monthly_f29 crea exactamente 1 F29 por compañía
        """
        # Calcular período esperado (mes anterior)
        today = fields.Date.today()
        first_of_month = today.replace(day=1)
        expected_period = (first_of_month - timedelta(days=1)).replace(day=1)

        # Limpiar F29s previos del período
        self.f29_model.search([
            ('period_date', '=', expected_period),
        ]).unlink()

        # Ejecutar cron
        created_count = self.f29_model.create_monthly_f29()

        # Verificar cantidad creada
        self.assertGreaterEqual(
            created_count, 2,
            "Debe crear al menos 2 F29 (1 por cada compañía de prueba)"
        )

        # Verificar F29 para company_1
        f29_company1 = self.f29_model.search([
            ('company_id', '=', self.company_1.id),
            ('period_date', '=', expected_period),
        ])
        self.assertEqual(
            len(f29_company1), 1,
            f"Debe existir exactamente 1 F29 para {self.company_1.name}"
        )
        self.assertEqual(
            f29_company1.state, 'draft',
            "F29 creado debe estar en estado draft"
        )
        self.assertEqual(
            f29_company1.tipo_declaracion, 'original',
            "F29 creado debe ser tipo 'original'"
        )

        # Verificar F29 para company_2
        f29_company2 = self.f29_model.search([
            ('company_id', '=', self.company_2.id),
            ('period_date', '=', expected_period),
        ])
        self.assertEqual(
            len(f29_company2), 1,
            f"Debe existir exactamente 1 F29 para {self.company_2.name}"
        )

    def test_create_monthly_f29_idempotent(self):
        """
        Test: create_monthly_f29 es idempotente (no crea duplicados)
        """
        # Calcular período
        today = fields.Date.today()
        first_of_month = today.replace(day=1)
        expected_period = (first_of_month - timedelta(days=1)).replace(day=1)

        # Limpiar F29s previos
        self.f29_model.search([
            ('period_date', '=', expected_period),
        ]).unlink()

        # Primera ejecución
        created_first = self.f29_model.create_monthly_f29()
        self.assertGreater(created_first, 0, "Primera ejecución debe crear al menos 1 F29")

        # Contar F29s después de primera ejecución
        f29_count_first = self.f29_model.search_count([
            ('period_date', '=', expected_period),
        ])

        # Segunda ejecución (idempotencia)
        created_second = self.f29_model.create_monthly_f29()
        self.assertEqual(
            created_second, 0,
            "Segunda ejecución NO debe crear nuevos F29 (idempotencia)"
        )

        # Contar F29s después de segunda ejecución
        f29_count_second = self.f29_model.search_count([
            ('period_date', '=', expected_period),
        ])

        # Verificar que NO se crearon duplicados
        self.assertEqual(
            f29_count_first, f29_count_second,
            "Cantidad de F29 debe ser la misma después de segunda ejecución"
        )

    def test_create_monthly_f29_skips_cancelled(self):
        """
        Test: create_monthly_f29 no cuenta F29 cancelados como duplicados
        """
        # Calcular período
        today = fields.Date.today()
        first_of_month = today.replace(day=1)
        expected_period = (first_of_month - timedelta(days=1)).replace(day=1)

        # Crear F29 cancelado manualmente
        self.f29_model.create({
            'company_id': self.company_1.id,
            'period_date': expected_period,
            'state': 'cancel',
        })

        # Ejecutar cron
        created_count = self.f29_model.create_monthly_f29()

        # Verificar que sí creó uno nuevo (porque el existente está cancelado)
        f29_active = self.f29_model.search([
            ('company_id', '=', self.company_1.id),
            ('period_date', '=', expected_period),
            ('state', '!=', 'cancel'),
        ])

        self.assertEqual(
            len(f29_active), 1,
            "Debe crear 1 F29 activo aunque exista uno cancelado"
        )

    def test_create_monthly_f29_correct_period(self):
        """
        Test: create_monthly_f29 usa el período correcto (mes anterior, día 1)
        """
        # Calcular período esperado
        today = fields.Date.today()
        first_of_month = today.replace(day=1)
        expected_period = (first_of_month - timedelta(days=1)).replace(day=1)

        # Limpiar
        self.f29_model.search([
            ('period_date', '=', expected_period),
        ]).unlink()

        # Ejecutar cron
        self.f29_model.create_monthly_f29()

        # Verificar período de F29 creados
        f29_created = self.f29_model.search([
            ('company_id', '=', self.company_1.id),
            ('period_date', '=', expected_period),
        ])

        self.assertEqual(
            len(f29_created), 1,
            "Debe existir F29 para el período calculado"
        )

        # Verificar que period_date es día 1 del mes
        self.assertEqual(
            f29_created.period_date.day, 1,
            "period_date debe ser día 1 del mes"
        )

    def test_create_monthly_f29_returns_count(self):
        """
        Test: create_monthly_f29 retorna cantidad de F29 creados
        """
        # Calcular período
        today = fields.Date.today()
        first_of_month = today.replace(day=1)
        expected_period = (first_of_month - timedelta(days=1)).replace(day=1)

        # Limpiar
        self.f29_model.search([
            ('period_date', '=', expected_period),
        ]).unlink()

        # Ejecutar cron
        result = self.f29_model.create_monthly_f29()

        # Verificar que retorna un entero
        self.assertIsInstance(result, int, "Debe retornar un entero")
        self.assertGreaterEqual(result, 0, "Debe retornar valor >= 0")

        # Verificar consistencia con F29s creados
        f29_count = self.f29_model.search_count([
            ('period_date', '=', expected_period),
        ])

        self.assertEqual(
            result, f29_count,
            "Valor retornado debe coincidir con cantidad de F29 creados"
        )
