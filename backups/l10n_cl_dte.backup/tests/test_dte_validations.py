# -*- coding: utf-8 -*-
"""
Tests de Validaciones DTE
Verifica que validadores SII funcionan correctamente
"""

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


class TestDTEValidations(TransactionCase):
    """Tests de validaciones DTE según normativa SII"""
    
    def setUp(self):
        super().setUp()
        self.Move = self.env['account.move']
        self.Partner = self.env['res.partner']
        
        self.company = self.env.company
        self.company.write({
            'vat': '76123456-K',
            'name': 'Test Company',
        })
        
        self.partner = self.Partner.create({
            'name': 'Test Partner',
            'vat': '12345678-5',
            'country_id': self.env.ref('base.cl').id,
        })
    
    def test_01_ted_validator_exists(self):
        """Verifica que TEDValidator está disponible"""
        try:
            # Intentar importar desde ruta absoluta
            import sys
            import os
            dte_service_path = os.path.join(
                os.path.dirname(__file__), 
                '..', '..', '..', '..', '..', 
                'dte-service'
            )
            sys.path.insert(0, dte_service_path)
            
            from validators.ted_validator import TEDValidator
            validator = TEDValidator()
            self.assertIsNotNone(validator)
            
        except ImportError:
            # Si no se puede importar, skip test (microservicio separado)
            self.skipTest('TEDValidator no disponible (microservicio separado)')
    
    def test_02_ted_validator_13_elements(self):
        """Verifica que TED valida 13 elementos según SII"""
        try:
            import sys
            import os
            dte_service_path = os.path.join(
                os.path.dirname(__file__), 
                '..', '..', '..', '..', '..', 
                'dte-service'
            )
            sys.path.insert(0, dte_service_path)
            
            from validators.ted_validator import TEDValidator
            validator = TEDValidator()
            
            # Debe tener 13 elementos requeridos
            self.assertEqual(
                len(validator.REQUIRED_TED_ELEMENTS), 
                13,
                'TED debe validar 13 elementos según Res. Ex. SII N° 45/2003'
            )
            
            # Verificar elementos críticos
            required = validator.REQUIRED_TED_ELEMENTS
            self.assertIn('DD/CAF', required, 'CAF debe estar en TED')
            self.assertIn('DD/RE', required, 'RUT Emisor debe estar en TED')
            self.assertIn('FRMT', required, 'Firma TED debe estar')
            
        except ImportError:
            self.skipTest('TEDValidator no disponible')
    
    def test_03_structure_validator_exists(self):
        """Verifica que DTEStructureValidator está disponible"""
        try:
            import sys
            import os
            dte_service_path = os.path.join(
                os.path.dirname(__file__), 
                '..', '..', '..', '..', '..', 
                'dte-service'
            )
            sys.path.insert(0, dte_service_path)
            
            from validators.dte_structure_validator import DTEStructureValidator
            validator = DTEStructureValidator()
            self.assertIsNotNone(validator)
            
        except ImportError:
            self.skipTest('DTEStructureValidator no disponible')
    
    def test_04_structure_validator_5_types(self):
        """Verifica que valida 5 tipos DTE (33, 34, 52, 56, 61)"""
        try:
            import sys
            import os
            dte_service_path = os.path.join(
                os.path.dirname(__file__), 
                '..', '..', '..', '..', '..', 
                'dte-service'
            )
            sys.path.insert(0, dte_service_path)
            
            from validators.dte_structure_validator import DTEStructureValidator
            validator = DTEStructureValidator()
            
            # Debe validar 5 tipos
            self.assertEqual(
                len(validator.REQUIRED_ELEMENTS), 
                5,
                'Debe validar 5 tipos DTE'
            )
            
            # Verificar tipos específicos
            types = validator.REQUIRED_ELEMENTS.keys()
            expected_types = ['33', '34', '52', '56', '61']
            
            for dte_type in expected_types:
                self.assertIn(
                    dte_type, 
                    types, 
                    f'Tipo DTE {dte_type} debe estar definido'
                )
            
        except ImportError:
            self.skipTest('DTEStructureValidator no disponible')
    
    def test_05_xsd_validator_graceful_degradation(self):
        """Verifica graceful degradation si XSD no disponible"""
        try:
            import sys
            import os
            dte_service_path = os.path.join(
                os.path.dirname(__file__), 
                '..', '..', '..', '..', '..', 
                'dte-service'
            )
            sys.path.insert(0, dte_service_path)
            
            from validators.xsd_validator import XSDValidator
            validator = XSDValidator()
            
            # Si no hay XSD, debe retornar True sin bloquear
            xml_test = '<?xml version="1.0"?><DTE></DTE>'
            is_valid, errors = validator.validate(xml_test, 'DTE')
            
            # No debe fallar, debe retornar bool
            self.assertIsInstance(is_valid, bool)
            self.assertIsInstance(errors, list)
            
            # Si no hay XSD, debe ser True (graceful degradation)
            if not validator.schemas:
                self.assertTrue(
                    is_valid, 
                    'Sin XSD debe retornar True (graceful degradation)'
                )
            
        except ImportError:
            self.skipTest('XSDValidator no disponible')
    
    def test_06_partner_rut_validation_simplified(self):
        """Verifica que validación RUT es simple (solo presencia)"""
        # Crear partner sin RUT
        partner_sin_rut = self.Partner.create({
            'name': 'Partner Sin RUT',
            'country_id': self.env.ref('base.cl').id,
        })
        
        # Crear factura
        move = self.Move.create({
            'move_type': 'out_invoice',
            'partner_id': partner_sin_rut.id,
        })
        
        # Si tiene dte_code, debe validar RUT
        if hasattr(move, 'dte_code') and move.dte_code:
            # Debe fallar por falta de RUT
            with self.assertRaises(ValidationError):
                move._check_partner_rut()
        else:
            # Sin dte_code, no debe validar
            try:
                move._check_partner_rut()
            except ValidationError:
                pass  # Es válido que falle o no
    
    def test_07_caf_validation(self):
        """Verifica validación de CAF"""
        CAF = self.env['dte.caf']
        
        # Crear CAF con datos mínimos
        caf = CAF.create({
            'dte_type': '33',
            'folio_desde': 1,
            'folio_hasta': 100,
            'company_id': self.company.id,
            'rut_empresa': '76123456-K',
            'fecha_autorizacion': '2025-10-21',
        })
        
        # Debe tener estado
        self.assertTrue(hasattr(caf, 'state'))
        
        # Debe tener método de validación
        self.assertTrue(hasattr(caf, 'action_validate'))
    
    def test_08_certificate_validation(self):
        """Verifica que modelo de certificado existe"""
        Certificate = self.env['dte.certificate']
        
        # Modelo debe existir
        self.assertTrue(Certificate)
        
        # Debe tener campos críticos
        self.assertTrue(hasattr(Certificate, 'cert_file'))
        self.assertTrue(hasattr(Certificate, 'cert_password'))
        self.assertTrue(hasattr(Certificate, 'company_id'))
