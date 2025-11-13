# -*- coding: utf-8 -*-

"""
Test P0-4: Payslip Validations (CAF Enhancement)
=================================================

Verifica que validaciones críticas bloqueen confirmación de nóminas
con datos incompletos o inconsistentes.

Validaciones testadas:
1. Reforma 2025 faltante (contratos nuevos)
2. Indicadores económicos faltantes
3. RUT trabajador faltante
4. AFP no asignada
5. Campos obligatorios

Referencias:
- Auditoría 2025-11-07: P0-4
- Previred - Requisitos de exportación
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError
from datetime import date


@tagged('post_install', '-at_install', 'p0_critical', 'validations')
class TestPayslipValidations(TransactionCase):
    """Test P0-4: Validar constraints antes de confirmar nómina"""

    def setUp(self):
        super().setUp()

        # Crear compañía
        self.company = self.env['res.company'].create({
            'name': 'Test Company',
            'vat': '76.123.456-7'
        })

        # Crear empleado
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee',
            'identification_id': '12.345.678-9',
            'company_id': self.company.id
        })

        # Crear AFP
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Test',
            'code': 'TEST',
            'rate': 10.0
        })

        # Crear indicadores económicos
        self.indicadores = self.env['hr.economic.indicators'].create({
            'period': date(2025, 1, 1),
            'uf': 37500.00,
            'utm': 65000.00,
            'uta': 780000.00,
            'minimum_wage': 500000.00
        })

        # Contrato 2025 (con reforma)
        self.contract = self.env['hr.contract'].create({
            'name': 'Contrato Test',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': date(2025, 1, 1),
            'state': 'open',
            'afp_id': self.afp.id,
            'company_id': self.company.id
        })

        # Estructura salarial
        self.struct = self.env.ref('l10n_cl_hr_payroll.structure_base_cl',
                                   raise_if_not_found=False)
        if not self.struct:
            self.struct = self.env['hr.payroll.structure'].create({
                'name': 'Estructura Chile',
                'code': 'CL_BASE'
            })

    def test_validation_blocks_missing_reforma(self):
        """
        P0-4: Validación debe bloquear nómina sin reforma 2025

        Contratos desde 2025-01-01 deben tener aporte reforma calculado.
        Si falta, no debe permitir confirmar nómina.
        """
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Sin Reforma',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False,
            'company_id': self.company.id,
            'indicadores_id': self.indicadores.id,
            'state': 'draft'  # Iniciar en draft
        })

        # Forzar employer_reforma_2025 = 0 (simular bug o cálculo no ejecutado)
        payslip.employer_reforma_2025 = 0

        # Intentar confirmar (debe fallar)
        with self.assertRaises(ValidationError) as context:
            payslip.write({'state': 'done'})

        # Validar mensaje de error
        error_msg = str(context.exception).lower()
        self.assertIn('reforma 2025', error_msg,
                     "Error debe mencionar Reforma 2025")
        self.assertIn('1%', error_msg,
                     "Error debe mencionar porcentaje 1%")

    def test_validation_blocks_missing_indicadores(self):
        """
        P0-4: Validación debe bloquear nómina sin indicadores económicos

        Indicadores UF/UTM son obligatorios para cálculos correctos.
        """
        payslip_sin_indicadores = self.env['hr.payslip'].create({
            'name': 'Test Sin Indicadores',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False,
            'company_id': self.company.id,
            # indicadores_id = False (no asignado)
            'state': 'draft'
        })

        # Computar reforma (aunque no haya indicadores)
        payslip_sin_indicadores._compute_employer_reforma_2025()

        # Intentar confirmar (debe fallar)
        with self.assertRaises(ValidationError) as context:
            payslip_sin_indicadores.write({'state': 'done'})

        error_msg = str(context.exception).lower()
        self.assertIn('indicadores', error_msg,
                     "Error debe mencionar indicadores económicos")

    def test_validation_blocks_missing_rut(self):
        """
        P0-4: Validación debe bloquear nómina sin RUT trabajador

        RUT es obligatorio para export Previred.
        """
        # Crear empleado sin RUT
        empleado_sin_rut = self.env['hr.employee'].create({
            'name': 'Sin RUT',
            'company_id': self.company.id
            # identification_id = False
        })

        contract_sin_rut = self.env['hr.contract'].create({
            'name': 'Contract Sin RUT',
            'employee_id': empleado_sin_rut.id,
            'wage': 1000000,
            'date_start': date(2025, 1, 1),
            'afp_id': self.afp.id,
            'company_id': self.company.id
        })

        payslip_sin_rut = self.env['hr.payslip'].create({
            'name': 'Test Sin RUT',
            'employee_id': empleado_sin_rut.id,
            'contract_id': contract_sin_rut.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicadores.id,
            'company_id': self.company.id,
            'state': 'draft'
        })

        # Computar reforma
        payslip_sin_rut._compute_employer_reforma_2025()

        # Intentar confirmar (debe fallar)
        with self.assertRaises(ValidationError) as context:
            payslip_sin_rut.write({'state': 'done'})

        error_msg = str(context.exception).lower()
        self.assertIn('rut', error_msg,
                     "Error debe mencionar RUT faltante")

    def test_validation_blocks_missing_afp(self):
        """
        P0-4: Validación debe bloquear nómina sin AFP asignada

        AFP es obligatoria para calcular cotizaciones.
        """
        contract_sin_afp = self.env['hr.contract'].create({
            'name': 'Contract Sin AFP',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'date_start': date(2025, 1, 1),
            # afp_id = False (no asignada)
            'company_id': self.company.id
        })

        payslip_sin_afp = self.env['hr.payslip'].create({
            'name': 'Test Sin AFP',
            'employee_id': self.employee.id,
            'contract_id': contract_sin_afp.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicadores.id,
            'company_id': self.company.id,
            'state': 'draft'
        })

        # Intentar confirmar (debe fallar)
        with self.assertRaises(ValidationError) as context:
            payslip_sin_afp.write({'state': 'done'})

        error_msg = str(context.exception).lower()
        self.assertIn('afp', error_msg,
                     "Error debe mencionar AFP faltante")

    def test_validation_allows_complete_payslip(self):
        """
        P0-4: Validación debe PERMITIR confirmar nómina completa

        Si todos los datos están completos y correctos,
        debe permitir confirmar sin errores.
        """
        payslip_completo = self.env['hr.payslip'].create({
            'name': 'Test Completo',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False,
            'company_id': self.company.id,
            'indicadores_id': self.indicadores.id,
            'state': 'draft'
        })

        # Computar reforma
        payslip_completo._compute_employer_reforma_2025()

        # Validar que reforma fue calculada
        self.assertEqual(
            payslip_completo.employer_reforma_2025,
            15000,  # 1% de $1.500.000
            "Reforma debe estar calculada"
        )

        # Confirmar (NO debe lanzar excepción)
        try:
            payslip_completo.write({'state': 'done'})
            self.assertEqual(payslip_completo.state, 'done',
                           "Nómina completa debe poder confirmarse")
        except ValidationError as e:
            self.fail(f"Nómina completa NO debería lanzar error: {e}")

    def test_validation_contrato_2024_sin_reforma_es_valido(self):
        """
        P0-4: Contratos pre-2025 SIN reforma deben poder confirmarse

        Contratos anteriores a 2025-01-01 NO tienen obligación
        de tener reforma 2025. Deben poder confirmarse sin error.
        """
        # Crear empleado para este test para evitar conflicto de contratos
        employee_2024 = self.env['hr.employee'].create({
            'name': 'Test Employee 2024',
            'identification_id': '10.345.678-9',
            'company_id': self.company.id
        })

        # Crear contrato 2024
        contract_2024 = self.env['hr.contract'].create({
            'name': 'Contract 2024',
            'employee_id': employee_2024.id,
            'wage': 1000000,
            'date_start': date(2024, 6, 1),  # Pre-2025
            'state': 'open',
            'afp_id': self.afp.id,
            'company_id': self.company.id
        })

        payslip_2024 = self.env['hr.payslip'].create({
            'name': 'Test Contrato 2024',
            'employee_id': employee_2024.id,
            'contract_id': contract_2024.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicadores.id,
            'company_id': self.company.id,
            'state': 'draft'
        })

        # Computar reforma (debe dar 0 para contratos 2024)
        payslip_2024._compute_employer_reforma_2025()
        self.assertEqual(payslip_2024.employer_reforma_2025, 0,
                        "Contrato 2024 NO debe tener reforma")

        # Confirmar (NO debe lanzar excepción)
        try:
            payslip_2024.write({'state': 'done'})
            self.assertEqual(payslip_2024.state, 'done',
                           "Contrato 2024 sin reforma debe poder confirmarse")
        except ValidationError as e:
            self.fail(f"Contrato 2024 sin reforma NO debería lanzar error: {e}")

    def test_validation_error_message_format(self):
        """
        P0-4: Mensaje de error debe ser claro y accionable

        Verifica que el mensaje de error:
        - Lista todos los problemas encontrados
        - Indica dónde configurar cada campo
        - Incluye emoji para mejor UX
        """
        # Crear caso con múltiples errores
        empleado_sin_rut = self.env['hr.employee'].create({
            'name': 'Multi Errors',
            'company_id': self.company.id
        })

        contract_errores = self.env['hr.contract'].create({
            'name': 'Contract Multi Errors',
            'employee_id': empleado_sin_rut.id,
            'wage': 1000000,
            'date_start': date(2025, 1, 1),
            # Sin AFP
            'company_id': self.company.id
        })

        payslip_errores = self.env['hr.payslip'].create({
            'name': 'Test Multi Errors',
            'employee_id': empleado_sin_rut.id,
            'contract_id': contract_errores.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            # Sin indicadores
            'company_id': self.company.id,
            'state': 'draft'
        })

        # Intentar confirmar
        with self.assertRaises(ValidationError) as context:
            payslip_errores.write({'state': 'done'})

        error_msg = str(context.exception)

        # Validar formato del mensaje
        self.assertIn('❌', error_msg, "Debe incluir emoji de error")
        self.assertIn('⚠️', error_msg, "Debe incluir emoji de advertencia")

        # Validar que lista múltiples errores
        self.assertIn('indicadores', error_msg.lower())
        self.assertIn('rut', error_msg.lower())
        self.assertIn('afp', error_msg.lower())

    def test_validation_only_applies_on_confirm(self):
        """
        P0-4: Validaciones solo deben aplicar al confirmar (state=done)

        En estado draft, debe permitir guardar sin validaciones.
        Solo al confirmar debe validar.
        """
        # Crear payslip incompleto en draft
        payslip_draft = self.env['hr.payslip'].create({
            'name': 'Test Draft',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'company_id': self.company.id,
            'state': 'draft'  # Mantener en draft
        })

        # Forzar employer_reforma_2025 = 0 (incompleto)
        payslip_draft.employer_reforma_2025 = 0

        # Guardar en draft (NO debe lanzar excepción)
        try:
            payslip_draft.write({'name': 'Test Draft Modified'})
            self.assertEqual(payslip_draft.state, 'draft')
        except ValidationError:
            self.fail("Guardar en draft NO debería lanzar ValidationError")

        # Ahora intentar confirmar (SÍ debe lanzar excepción)
        with self.assertRaises(ValidationError):
            payslip_draft.write({'state': 'done'})
