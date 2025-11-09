# -*- coding: utf-8 -*-
"""
🚀 FASE 3.2: Test de Integración l10n_cl_fe + l10n_cl_payroll
Consolidación de retenciones en F29 mensual

Siguiendo protocolo PROMPT_AGENT_IA.md:
🏆 NIVEL 1: Documentación Oficial Odoo 18 - TransactionCase con @tagged
🎯 NIVEL 2: Arquitectura y patrones internos
🔍 NIVEL 3: Validación MCP aplicada

Flujo Real Correcto:
1. l10n_cl_payroll: Calcula retenciones de TRABAJADORES (impuesto único, 2da categoría)
2. l10n_cl_fe: RECIBE y VALIDA BHE con retenciones pre-calculadas por emisor
3. F29 (en l10n_cl_fe): CONSOLIDA retenciones de trabajadores + retenciones de proveedores
"""

import logging
from datetime import date, datetime, timedelta

from odoo.tests.common import TransactionCase, tagged

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install', 'l10n_cl', 'integration')
class TestF29RetentionConsolidation(TransactionCase):
    """
    Test de integración crítico: Consolidación de retenciones en F29 mensual
    
    NATURALEZA DE LA INTEGRACIÓN:
    - l10n_cl_payroll: Calcula retenciones de trabajadores 
    - l10n_cl_fe: Recibe BHE con retenciones pre-calculadas
    - F29: Consolida ambas fuentes para declaración SII
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Company chilena para testing
        cls.company_cl = cls.env['res.company'].create({
            'name': 'Test Company Chile',
            'country_id': cls.env.ref('base.cl').id,
            'currency_id': cls.env.ref('base.CLP').id,
            'vat': '76123456-7',
        })
        
        # Partner prestador de servicios (emisor BHE)
        cls.service_provider = cls.env['res.partner'].create({
            'name': 'Consultor Independiente',
            'vat': '12345678-9',
            'country_id': cls.env.ref('base.cl').id,
            'supplier_rank': 1,
        })
        
        # Empleado para nómina
        cls.employee = cls.env['hr.employee'].create({
            'name': 'Juan Pérez',
            'company_id': cls.company_cl.id,
        })
        
        # Fecha de testing (enero 2025)
        cls.test_date = date(2025, 1, 15)
        cls.period_start = date(2025, 1, 1)
        cls.period_end = date(2025, 1, 31)

    def setUp(self):
        super().setUp()
        # Cambiar a company chilena
        self.env.user.company_id = self.company_cl

    def test_f29_consolidates_payroll_and_bhe_retentions(self):
        """
        Test principal: F29 consolida correctamente retenciones de nómina y BHE
        
        Escenario:
        1. Crear nómina con retenciones de trabajadores
        2. Recibir BHE con retenciones de proveedores
        3. Generar F29 mensual
        4. Verificar consolidación correcta
        """
        # === SETUP: Nómina con retenciones de trabajadores ===
        payslip = self._create_payslip_with_retentions()
        payslip.action_payslip_done()
        
        # === SETUP: BHE recibida con retenciones de proveedores ===
        bhe_record = self._create_received_bhe()
        bhe_record.action_validate()
        
        # === ACCIÓN: Generar F29 mensual ===
        f29 = self._create_f29_for_period()
        f29.action_calculate()
        
        # === VERIFICACIONES ===
        
        # 1. F29 debe incluir retenciones de trabajadores (desde payroll)
        expected_worker_retention = 50000  # Impuesto único trabajador
        self.assertEqual(
            f29.impuesto_unico_trabajadores,
            expected_worker_retention,
            "F29 debe incluir impuesto único de trabajadores calculado por l10n_cl_payroll"
        )
        
        # 2. F29 debe incluir retenciones de BHE (desde proveedores)
        expected_bhe_retention = 29000  # 14.5% de 200,000 (BHE)
        self.assertEqual(
            f29.retencion_honorarios,
            expected_bhe_retention,
            "F29 debe incluir retenciones de BHE recibidas (calculadas por emisor)"
        )
        
        # 3. Total retenciones debe ser la suma correcta
        expected_total = expected_worker_retention + expected_bhe_retention
        self.assertEqual(
            f29.total_retenciones,
            expected_total,
            "F29 debe consolidar correctamente retenciones de trabajadores + proveedores"
        )
        
        # 4. Verificar que no hay duplicación de datos
        self.assertEqual(len(f29.line_ids), 2, "Debe haber exactamente 2 líneas de retención")
        
        # 5. Verificar líneas específicas de F29
        worker_line = f29.line_ids.filtered(lambda l: l.line_type == 'worker_retention')
        bhe_line = f29.line_ids.filtered(lambda l: l.line_type == 'bhe_retention')
        
        self.assertTrue(worker_line, "Debe existir línea de retenciones de trabajadores")
        self.assertTrue(bhe_line, "Debe existir línea de retenciones de BHE")
        
        self.assertEqual(worker_line.amount, expected_worker_retention)
        self.assertEqual(bhe_line.amount, expected_bhe_retention)

    def test_f29_handles_no_payroll_data(self):
        """Test edge case: F29 sin datos de nómina, solo BHE"""
        # Solo BHE, sin nómina
        bhe_record = self._create_received_bhe()
        bhe_record.action_validate()
        
        f29 = self._create_f29_for_period()
        f29.action_calculate()
        
        # Debe funcionar solo con BHE
        self.assertEqual(f29.impuesto_unico_trabajadores, 0)
        self.assertEqual(f29.retencion_honorarios, 29000)
        self.assertEqual(f29.total_retenciones, 29000)

    def test_f29_handles_no_bhe_data(self):
        """Test edge case: F29 sin BHE, solo nómina"""
        # Solo nómina, sin BHE
        payslip = self._create_payslip_with_retentions()
        payslip.action_payslip_done()
        
        f29 = self._create_f29_for_period()
        f29.action_calculate()
        
        # Debe funcionar solo con nómina
        self.assertEqual(f29.impuesto_unico_trabajadores, 50000)
        self.assertEqual(f29.retencion_honorarios, 0)
        self.assertEqual(f29.total_retenciones, 50000)

    def test_f29_multiple_bhe_consolidation(self):
        """Test: F29 consolida múltiples BHE del período"""
        # Crear múltiples BHE
        bhe1 = self._create_received_bhe(amount=200000)  # Retención: 29,000
        bhe2 = self._create_received_bhe(amount=100000)  # Retención: 14,500
        
        bhe1.action_validate()
        bhe2.action_validate()
        
        f29 = self._create_f29_for_period()
        f29.action_calculate()
        
        # Debe sumar todas las BHE
        expected_total_bhe = 29000 + 14500  # 43,500
        self.assertEqual(f29.retencion_honorarios, expected_total_bhe)

    def test_f29_filters_by_period_correctly(self):
        """Test: F29 solo incluye datos del período correcto"""
        # BHE en período correcto
        bhe_current = self._create_received_bhe(
            date_reception=self.period_start + timedelta(days=5)
        )
        bhe_current.action_validate()
        
        # BHE fuera del período
        bhe_previous = self._create_received_bhe(
            date_reception=self.period_start - timedelta(days=5)
        )
        bhe_previous.action_validate()
        
        f29 = self._create_f29_for_period()
        f29.action_calculate()
        
        # Solo debe incluir BHE del período actual
        self.assertEqual(f29.retencion_honorarios, 29000)  # Solo una BHE

    # === MÉTODOS AUXILIARES ===
    
    def _create_payslip_with_retentions(self):
        """Crear nómina con retenciones de trabajadores"""
        # Crear contrato
        contract = self.env['hr.contract'].create({
            'name': 'Contrato Juan Pérez',
            'employee_id': self.employee.id,
            'wage': 800000,  # Sueldo base
            'date_start': self.period_start,
        })
        
        # Crear nómina
        payslip = self.env['hr.payslip'].create({
            'name': f'Nómina {self.test_date.strftime("%Y-%m")}',
            'employee_id': self.employee.id,
            'contract_id': contract.id,
            'date_from': self.period_start,
            'date_to': self.period_end,
        })
        
        # Calcular nómina (esto incluirá retenciones)
        payslip.compute_sheet()
        
        # Agregar línea de impuesto único manualmente para testing
        self.env['hr.payslip.line'].create({
            'payslip_id': payslip.id,
            'name': 'Impuesto Único',
            'code': 'IMPUNI',
            'amount': -50000,  # Retención
            'total': -50000,
        })
        
        return payslip

    def _create_received_bhe(self, amount=200000, date_reception=None):
        """Crear BHE recibida con retención pre-calculada"""
        if date_reception is None:
            date_reception = self.test_date
            
        # Calcular retención 14.5% (tasa 2025)
        retention_amount = amount * 0.145
        net_amount = amount - retention_amount
        
        bhe = self.env['l10n_cl.bhe'].create({
            'number': f'BHE-{date_reception.strftime("%Y%m%d")}-001',
            'date': date_reception,
            'company_id': self.company_cl.id,
            'partner_id': self.service_provider.id,
            'service_description': 'Servicios de consultoría',
            'amount_gross': amount,
            'retention_rate': 14.5,
            'amount_retention': retention_amount,
            'amount_net': net_amount,
        })
        
        return bhe

    def _create_f29_for_period(self):
        """Crear F29 para el período de testing"""
        f29 = self.env['l10n_cl.f29'].create({
            'company_id': self.company_cl.id,
            'period_date': self.period_start,
            'period_month': str(self.period_start.month).zfill(2),
            'period_year': self.period_start.year,
        })
        
        return f29

    def test_integration_performance(self):
        """Test: Verificar performance de consolidación con volumen"""
        # Crear múltiples registros para test de performance
        start_time = datetime.now()
        
        # 10 BHE
        for i in range(10):
            bhe = self._create_received_bhe(amount=100000 + (i * 10000))
            bhe.action_validate()
        
        # 5 nóminas
        for i in range(5):
            payslip = self._create_payslip_with_retentions()
            payslip.action_payslip_done()
        
        # Generar F29
        f29 = self._create_f29_for_period()
        f29.action_calculate()
        
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        # Verificar que el procesamiento es eficiente (< 5 segundos)
        self.assertLess(processing_time, 5.0, "Consolidación F29 debe ser eficiente")
        
        # Verificar resultados
        expected_bhe_total = sum([
            (100000 + (i * 10000)) * 0.145 for i in range(10)
        ])
        expected_payroll_total = 5 * 50000  # 5 nóminas con 50k cada una
        
        self.assertEqual(f29.retencion_honorarios, expected_bhe_total)
        self.assertEqual(f29.impuesto_unico_trabajadores, expected_payroll_total)

    def test_data_consistency_after_modifications(self):
        """Test: Consistencia de datos tras modificaciones"""
        # Crear datos iniciales
        bhe = self._create_received_bhe()
        payslip = self._create_payslip_with_retentions()
        
        bhe.action_validate()
        payslip.action_payslip_done()
        
        # Crear F29 inicial
        f29 = self._create_f29_for_period()
        f29.action_calculate()
        
        initial_total = f29.total_retenciones
        
        # Modificar BHE (simular corrección)
        bhe.write({
            'amount_gross': 300000,
            'amount_retention': 43500,  # 14.5% de 300k
        })
        
        # Recalcular F29
        f29.action_calculate()
        
        # Verificar que F29 refleja cambios
        expected_new_total = 50000 + 43500  # payroll + nueva BHE
        self.assertEqual(f29.total_retenciones, expected_new_total)
