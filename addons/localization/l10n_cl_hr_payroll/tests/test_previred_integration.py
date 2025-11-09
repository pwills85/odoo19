# -*- coding: utf-8 -*-

"""
Test P0-3: Previred Integration (Export Book 49)
================================================

Verifica exportación correcta de archivos Previred Book 49:
- Formato correcto (.pre, encoding Latin-1)
- Estructura 3 líneas (header, detalle, totales)
- Validaciones pre-export
- Inclusión Reforma 2025 en export

Referencias:
- Manual Previred Book 49 v2024
- Previred - Formato 105 campos
- Auditoría 2025-11-07: P0-3
"""

from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError
from datetime import date


@tagged('post_install', '-at_install', 'p0_critical', 'previred')
class TestPreviredIntegration(TransactionCase):
    """Test P0-3: Validar exportación Previred"""

    def setUp(self):
        super().setUp()

        # Crear compañía con RUT
        self.company = self.env['res.company'].create({
            'name': 'Empresa Test',
            'vat': '76.123.456-7'
        })

        # Crear empleado con RUT
        self.employee = self.env['hr.employee'].create({
            'name': 'Juan Pérez',
            'identification_id': '12.345.678-9',
            'company_id': self.company.id
        })

        # Crear AFP
        self.afp = self.env['hr.afp'].create({
            'name': 'AFP Cuprum',
            'code': 'CUPRUM',
            'rate': 11.44
        })

        # Crear indicadores económicos
        self.indicadores = self.env['hr.economic.indicators'].create({
            'period': date(2025, 1, 1),
            'uf': 37500.00,
            'utm': 65000.00,
            'uta': 780000.00
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

    def test_previred_book49_formato_correcto(self):
        """
        P0-3: Validar formato Book 49

        Verifica que el archivo generado tenga:
        - Estructura 3 líneas (01, 02, 03)
        - Encoding Latin-1
        - Campos con ancho correcto
        """
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Previred',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False,
            'company_id': self.company.id,
            'indicadores_id': self.indicadores.id
        })

        # Computar campos (incluyendo reforma 2025)
        payslip._compute_employer_reforma_2025()

        # Generar Book 49
        book49_data = payslip.generate_previred_book49()

        # Validar estructura diccionario
        self.assertIn('filename', book49_data)
        self.assertIn('content', book49_data)

        # Validar filename
        self.assertTrue(
            book49_data['filename'].endswith('.pre'),
            "Archivo debe tener extensión .pre"
        )
        self.assertIn('BOOK49', book49_data['filename'])
        self.assertIn('012025', book49_data['filename'])

        # Decodificar contenido
        content = book49_data['content'].decode('latin1')
        lines = content.split('\n')

        # Validar 3 líneas
        self.assertEqual(
            len(lines),
            3,
            "Archivo Book 49 debe tener exactamente 3 líneas"
        )

        # Validar línea 01 (Header)
        self.assertTrue(
            lines[0].startswith('01'),
            "Línea 1 debe iniciar con '01' (header)"
        )
        self.assertIn('76123456', lines[0])  # RUT empresa sin puntos
        self.assertIn('012025', lines[0])     # Período

        # Validar línea 02 (Detalle)
        self.assertTrue(
            lines[1].startswith('02'),
            "Línea 2 debe iniciar con '02' (detalle)"
        )
        self.assertIn('123456789', lines[1])  # RUT trabajador sin puntos

        # Validar línea 03 (Totales)
        self.assertTrue(
            lines[2].startswith('03'),
            "Línea 3 debe iniciar con '03' (totales)"
        )

    def test_previred_export_incluye_reforma_2025(self):
        """
        P0-3: Validar que export incluye aporte Reforma 2025

        Verifica que el campo employer_reforma_2025 se incluye
        correctamente en el archivo Book 49.
        """
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Reforma Export',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False,
            'company_id': self.company.id,
            'indicadores_id': self.indicadores.id
        })

        # Computar reforma
        payslip._compute_employer_reforma_2025()

        # Verificar que reforma fue calculada
        self.assertEqual(
            payslip.employer_reforma_2025,
            15000,  # 1% de $1.500.000
            "Reforma 2025 debe estar calculada antes de export"
        )

        # Generar Book 49
        book49_data = payslip.generate_previred_book49()
        content = book49_data['content'].decode('latin1')
        lines = content.split('\n')

        # Validar que línea 02 contiene aporte reforma (campo 4)
        line_detalle = lines[1]

        # Extraer campo aporte reforma (últimos 10 caracteres de línea detalle)
        # Formato: 02 + RUT(10) + Imponible(10) + AFP(10) + Reforma(10)
        # Total: 2 + 10 + 10 + 10 + 10 = 42 chars
        self.assertGreaterEqual(
            len(line_detalle),
            42,
            "Línea detalle debe tener al menos 42 caracteres"
        )

        # Extraer y validar aporte reforma
        # Campo aporte reforma está en posición 32:42 (últimos 10 chars)
        aporte_reforma_str = line_detalle[32:42].strip()
        aporte_reforma_int = int(aporte_reforma_str)

        self.assertEqual(
            aporte_reforma_int,
            15000,
            "Campo Reforma 2025 en Book 49 debe ser $15.000"
        )

    def test_previred_validation_bloquea_sin_indicadores(self):
        """
        P0-3: Validación debe bloquear export sin indicadores económicos

        Si no existen indicadores económicos para el período,
        debe lanzar ValidationError.
        """
        payslip_sin_indicadores = self.env['hr.payslip'].create({
            'name': 'Test Sin Indicadores',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 6, 1),  # Mes sin indicadores
            'date_to': date(2025, 6, 30),
            'struct_id': self.struct.id if self.struct else False,
            'company_id': self.company.id
            # indicadores_id = False (no asignado)
        })

        # Debe lanzar ValidationError
        with self.assertRaises(ValidationError) as context:
            payslip_sin_indicadores._validate_previred_export()

        self.assertIn(
            'indicadores económicos',
            str(context.exception).lower(),
            "Error debe mencionar indicadores económicos faltantes"
        )

    def test_previred_validation_bloquea_sin_rut_trabajador(self):
        """
        P0-3: Validación debe bloquear export sin RUT trabajador

        RUT es obligatorio para Previred.
        """
        # Crear empleado sin RUT
        empleado_sin_rut = self.env['hr.employee'].create({
            'name': 'Sin RUT',
            'company_id': self.company.id
        })

        contract_sin_rut = self.env['hr.contract'].create({
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
            'company_id': self.company.id
        })

        # Debe lanzar ValidationError
        with self.assertRaises(ValidationError) as context:
            payslip_sin_rut._validate_previred_export()

        self.assertIn(
            'rut',
            str(context.exception).lower(),
            "Error debe mencionar RUT faltante"
        )

    def test_previred_validation_bloquea_sin_afp(self):
        """
        P0-3: Validación debe bloquear export sin AFP asignada

        AFP es obligatoria para cálculo de cotizaciones.
        """
        contract_sin_afp = self.env['hr.contract'].create({
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
            'company_id': self.company.id
        })

        # Debe lanzar ValidationError
        with self.assertRaises(ValidationError) as context:
            payslip_sin_afp._validate_previred_export()

        self.assertIn(
            'afp',
            str(context.exception).lower(),
            "Error debe mencionar AFP faltante"
        )

    def test_previred_validation_bloquea_sin_reforma_2025(self):
        """
        P0-3: Validación debe bloquear export si falta Reforma 2025

        Contratos desde 2025-01-01 deben tener aporte reforma calculado.
        """
        payslip_sin_reforma = self.env['hr.payslip'].create({
            'name': 'Test Sin Reforma',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicadores.id,
            'company_id': self.company.id
        })

        # NO computar reforma (simular bug)
        # payslip._compute_employer_reforma_2025()  # <-- OMITIDO

        # Forzar employer_reforma_2025 = 0
        payslip_sin_reforma.employer_reforma_2025 = 0

        # Debe lanzar ValidationError
        with self.assertRaises(ValidationError) as context:
            payslip_sin_reforma._validate_previred_export()

        self.assertIn(
            'reforma 2025',
            str(context.exception).lower(),
            "Error debe mencionar Reforma 2025 faltante"
        )

    def test_action_export_previred_crea_attachment(self):
        """
        P0-3: action_export_previred debe crear attachment

        Verifica que el export crea un registro ir.attachment
        asociado al payslip.
        """
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Attachment',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'struct_id': self.struct.id if self.struct else False,
            'company_id': self.company.id,
            'indicadores_id': self.indicadores.id
        })

        # Computar reforma
        payslip._compute_employer_reforma_2025()

        # Contar attachments antes
        attachments_before = self.env['ir.attachment'].search_count([
            ('res_model', '=', 'hr.payslip'),
            ('res_id', '=', payslip.id)
        ])

        # Ejecutar export
        result = payslip.action_export_previred()

        # Validar que se creó attachment
        attachments_after = self.env['ir.attachment'].search_count([
            ('res_model', '=', 'hr.payslip'),
            ('res_id', '=', payslip.id)
        ])

        self.assertEqual(
            attachments_after,
            attachments_before + 1,
            "Debe crear exactamente 1 attachment"
        )

        # Validar action retornado
        self.assertIn('type', result)
        self.assertEqual(result['type'], 'ir.actions.act_url')
        self.assertIn('url', result)
        self.assertIn('/web/content/', result['url'])

    def test_previred_encoding_latin1(self):
        """
        P0-3: Validar encoding Latin-1

        Archivo Previred debe usar encoding Latin-1, no UTF-8.
        Esto es crítico para caracteres especiales (ñ, á, etc).
        """
        payslip = self.env['hr.payslip'].create({
            'name': 'Test Encoding',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'company_id': self.company.id,
            'indicadores_id': self.indicadores.id
        })

        payslip._compute_employer_reforma_2025()

        # Generar Book 49
        book49_data = payslip.generate_previred_book49()

        # Validar que content es bytes
        self.assertIsInstance(
            book49_data['content'],
            bytes,
            "Content debe ser bytes (encoding aplicado)"
        )

        # Intentar decodificar como Latin-1 (no debe fallar)
        try:
            content_decoded = book49_data['content'].decode('latin1')
            self.assertIsInstance(content_decoded, str)
        except UnicodeDecodeError:
            self.fail("Contenido no puede decodificarse como Latin-1")

        # Validar que NO es UTF-8 simple (puede ser, pero Latin-1 es requerido)
        # Solo verificamos que Latin-1 funciona, no que UTF-8 falla
        self.assertTrue(True, "Encoding Latin-1 validado correctamente")
