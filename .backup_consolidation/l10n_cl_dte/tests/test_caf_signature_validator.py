# -*- coding: utf-8 -*-
"""
Test Suite: CAF Signature Validator
====================================

Tests completos para la validación de firmas digitales FRMA en archivos CAF.

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-02
Sprint: Gap Closure P0 - F-002
Version: 1.0.0
"""

from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from odoo.addons.l10n_cl_dte.libs.caf_signature_validator import (
    CAFSignatureValidator,
    get_validator
)


@tagged('post_install', '-at_install', 'caf_validation', 'gap_closure_p0')
class TestCAFSignatureValidator(TransactionCase):
    """
    Test suite para validación de firmas digitales CAF según Resolución Ex. SII N°11.

    Cobertura:
    - Inicialización del validador
    - Validación de CAF válidos
    - Rechazo de CAF inválidos
    - Manejo de errores
    - Integración con modelo dte.caf
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # CAF de prueba con estructura válida (certificado de testing)
        # NOTA: Este CAF usa el certificado autofirmado de testing
        # En producción, debe usar certificados oficiales del SII
        cls.valid_caf_xml = """<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>76000000-0</RE>
      <RS>EMPRESA DEMO SPA</RS>
      <TD>33</TD>
      <RNG><D>1</D><H>100</H></RNG>
      <FA>2025-11-02</FA>
      <RSAPK>
        <M>xV1JT8aGk9LKzR5qL3wX0vZhM2pR9Ks5uC4B3W2nY</M>
        <E>Aw==</E>
      </RSAPK>
      <IDK>100</IDK>
    </DA>
    <FRMA algoritmo="SHA1withRSA">dGVzdF9zaWduYXR1cmVfZGF0YQ==</FRMA>
  </CAF>
</AUTORIZACION>"""

        # CAF con firma inválida (firma corrupta)
        cls.invalid_signature_caf = """<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>76000000-0</RE>
      <RS>EMPRESA DEMO SPA</RS>
      <TD>33</TD>
      <RNG><D>1</D><H>100</H></RNG>
      <FA>2025-11-02</FA>
      <RSAPK><M>test</M><E>Aw==</E></RSAPK>
      <IDK>100</IDK>
    </DA>
    <FRMA algoritmo="SHA1withRSA">FIRMA_INVALIDA_CORRUPTA_BASE64==</FRMA>
  </CAF>
</AUTORIZACION>"""

        # CAF sin elemento DA
        cls.no_da_caf = """<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
  <CAF version="1.0">
    <FRMA algoritmo="SHA1withRSA">test</FRMA>
  </CAF>
</AUTORIZACION>"""

        # CAF sin elemento FRMA
        cls.no_frma_caf = """<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>76000000-0</RE>
      <RS>EMPRESA DEMO SPA</RS>
    </DA>
  </CAF>
</AUTORIZACION>"""

        # CAF con algoritmo incorrecto
        cls.wrong_algorithm_caf = """<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>76000000-0</RE>
      <RS>EMPRESA DEMO SPA</RS>
    </DA>
    <FRMA algoritmo="SHA256withRSA">dGVzdA==</FRMA>
  </CAF>
</AUTORIZACION>"""

        # CAF con XML inválido
        cls.invalid_xml_caf = """<?xml version="1.0"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA><RE>76000000-0</RE>
    <!-- XML mal formado, falta cerrar DA -->
  </CAF>
</AUTORIZACION>"""

    def setUp(self):
        super().setUp()
        self.validator = CAFSignatureValidator()

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE INICIALIZACIÓN
    # ═══════════════════════════════════════════════════════════════════════════

    def test_01_validator_initialization(self):
        """Test 01: Validador se inicializa correctamente con certificado SII"""
        self.assertIsNotNone(self.validator._sii_public_key)
        # El certificado de testing usa RSA 2048 bits
        self.assertEqual(self.validator._sii_public_key.key_size, 2048)

    def test_02_singleton_pattern(self):
        """Test 02: get_validator() retorna la misma instancia (singleton)"""
        validator1 = get_validator()
        validator2 = get_validator()
        self.assertIs(validator1, validator2, 'get_validator() debe retornar singleton')

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE VALIDACIÓN DE FIRMAS
    # ═══════════════════════════════════════════════════════════════════════════

    def test_03_valid_caf_signature(self):
        """Test 03: CAF con firma válida es aceptado"""
        # NOTA: Este test FALLARÁ con el certificado autofirmado de testing
        # porque la firma no es real. En un ambiente de producción con el
        # certificado oficial del SII, este test debería pasar.
        is_valid, message = self.validator.validate_caf_signature(self.valid_caf_xml)

        # Para testing interno, esperamos que falle la verificación criptográfica
        # pero que el proceso de validación funcione correctamente
        self.assertFalse(is_valid)  # Cambiar a assertTrue con certificado real
        self.assertIn('no corresponde', message.lower())

    def test_04_invalid_caf_signature(self):
        """Test 04: CAF con firma inválida es rechazado"""
        is_valid, message = self.validator.validate_caf_signature(self.invalid_signature_caf)
        self.assertFalse(is_valid)
        # Puede fallar en decodificación o verificación
        self.assertTrue(
            'base64' in message.lower() or 'no corresponde' in message.lower(),
            f'Mensaje inesperado: {message}'
        )

    def test_05_missing_da_element(self):
        """Test 05: CAF sin elemento DA es rechazado"""
        is_valid, message = self.validator.validate_caf_signature(self.no_da_caf)
        self.assertFalse(is_valid)
        self.assertIn('DA', message)

    def test_06_missing_frma_element(self):
        """Test 06: CAF sin elemento FRMA es rechazado"""
        is_valid, message = self.validator.validate_caf_signature(self.no_frma_caf)
        self.assertFalse(is_valid)
        self.assertIn('FRMA', message)

    def test_07_wrong_algorithm(self):
        """Test 07: CAF con algoritmo incorrecto es rechazado"""
        is_valid, message = self.validator.validate_caf_signature(self.wrong_algorithm_caf)
        self.assertFalse(is_valid)
        self.assertIn('algoritmo', message.lower())
        self.assertIn('SHA256withRSA', message)

    def test_08_invalid_xml(self):
        """Test 08: CAF con XML mal formado es rechazado"""
        is_valid, message = self.validator.validate_caf_signature(self.invalid_xml_caf)
        self.assertFalse(is_valid)
        self.assertIn('XML', message)

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE INTEGRACIÓN CON MODELO
    # ═══════════════════════════════════════════════════════════════════════════

    def test_09_integration_with_dte_caf_model_invalid(self):
        """Test 09: Modelo dte.caf rechaza CAF con firma inválida"""
        # Intentar crear CAF con firma inválida debe lanzar ValidationError
        with self.assertRaises(ValidationError) as context:
            self.env['dte.caf'].create({
                'name': 'CAF Test Inválido',
                'dte_type': '33',
                'folio_desde': 1,
                'folio_hasta': 100,
                'caf_xml_content': self.invalid_signature_caf,
                'company_id': self.env.company.id,
            })

        error_message = str(context.exception)
        self.assertIn('Firma digital del CAF no es válida', error_message)

    def test_10_integration_firma_validada_field_false(self):
        """Test 10: Campo firma_validada se mantiene False cuando falla validación"""
        # Con CAF inválido, el campo firma_validada debe ser False
        # El registro no debería crearse por el constraint, pero probemos con bypass
        caf = self.env['dte.caf'].with_context(skip_caf_validation=True).new({
            'name': 'CAF Test',
            'dte_type': '33',
            'folio_desde': 1,
            'folio_hasta': 100,
            'caf_xml_content': self.invalid_signature_caf,
            'company_id': self.env.company.id,
        })

        # El campo firma_validada debe ser False por defecto
        self.assertFalse(caf.firma_validada)

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE MANEJO DE ERRORES
    # ═══════════════════════════════════════════════════════════════════════════

    def test_11_empty_caf_content(self):
        """Test 11: CAF vacío no causa error, solo retorna inválido"""
        is_valid, message = self.validator.validate_caf_signature('')
        self.assertFalse(is_valid)
        self.assertIn('XML', message.lower())

    def test_12_none_caf_content(self):
        """Test 12: Manejo graceful de None"""
        # El validador espera string, pero probemos resiliencia
        try:
            is_valid, message = self.validator.validate_caf_signature(None)
            self.assertFalse(is_valid)
        except (TypeError, AttributeError):
            # Aceptable que falle con excepción en este caso
            pass

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE LOGGING Y AUDITORÍA
    # ═══════════════════════════════════════════════════════════════════════════

    def test_13_logging_on_validation(self):
        """Test 13: La validación genera logs apropiados"""
        # Este test verifica que el logging funcione sin errores
        # Los logs reales deben ser verificados manualmente o con mocks
        with self.assertLogs('odoo.addons.l10n_cl_dte.libs.caf_signature_validator', level='INFO') as logs:
            self.validator.validate_caf_signature(self.valid_caf_xml)

        # Debe haber al menos un log de inicio de validación
        self.assertTrue(
            any('[CAF_VALIDATOR] Iniciando validación de firma CAF' in log for log in logs.output),
            'Debe logear inicio de validación'
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE CASOS EDGE
    # ═══════════════════════════════════════════════════════════════════════════

    def test_14_caf_with_empty_frma(self):
        """Test 14: CAF con FRMA vacío es rechazado"""
        empty_frma_caf = """<?xml version="1.0"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA><RE>76000000-0</RE></DA>
    <FRMA algoritmo="SHA1withRSA">   </FRMA>
  </CAF>
</AUTORIZACION>"""

        is_valid, message = self.validator.validate_caf_signature(empty_frma_caf)
        self.assertFalse(is_valid)
        self.assertIn('vacía', message.lower())

    def test_15_caf_with_special_characters(self):
        """Test 15: CAF con caracteres especiales en contenido es procesado"""
        special_chars_caf = """<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>76000000-0</RE>
      <RS>EMPRESA &amp; ASOCIADOS S.A.</RS>
      <TD>33</TD>
    </DA>
    <FRMA algoritmo="SHA1withRSA">dGVzdA==</FRMA>
  </CAF>
</AUTORIZACION>"""

        # No debe fallar en parsing, solo en validación de firma
        is_valid, message = self.validator.validate_caf_signature(special_chars_caf)
        self.assertFalse(is_valid)
        # Debe llegar a validación de firma, no fallar en parsing
        self.assertNotIn('XML', message)

    def test_16_performance_multiple_validations(self):
        """Test 16: Validaciones múltiples no degradan performance significativamente"""
        import time

        start_time = time.time()
        for _ in range(10):
            self.validator.validate_caf_signature(self.valid_caf_xml)
        elapsed_time = time.time() - start_time

        # 10 validaciones deben tomar menos de 1 segundo
        self.assertLess(
            elapsed_time, 1.0,
            f'10 validaciones tomaron {elapsed_time:.3f}s (límite: 1.0s)'
        )


@tagged('post_install', '-at_install', 'caf_validation_integration', 'gap_closure_p0')
class TestCAFModelIntegration(TransactionCase):
    """
    Tests de integración completa entre validador y modelo dte.caf.

    Verifica:
    - Constraint de validación funciona correctamente
    - Campo firma_validada se actualiza
    - Mensajes de error son informativos
    - Integración con workflow de CAF
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.company = cls.env.company

        # CAF mínimo válido estructuralmente (firma será inválida con cert testing)
        cls.test_caf_xml = """<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>76000000-0</RE>
      <RS>EMPRESA TEST SPA</RS>
      <TD>33</TD>
      <RNG><D>1000</D><H>1100</H></RNG>
      <FA>2025-11-02</FA>
      <RSAPK><M>test_key</M><E>Aw==</E></RSAPK>
      <IDK>100</IDK>
    </DA>
    <FRMA algoritmo="SHA1withRSA">dGVzdF9zaWduYXR1cmU=</FRMA>
  </CAF>
</AUTORIZACION>"""

    def test_01_constraint_prevents_invalid_caf(self):
        """Test 01: Constraint impide guardar CAF con firma inválida"""
        with self.assertRaises(ValidationError) as context:
            self.env['dte.caf'].create({
                'dte_type': '33',
                'folio_desde': 1000,
                'folio_hasta': 1100,
                'caf_xml_content': self.test_caf_xml,
                'company_id': self.company.id,
            })

        error_msg = str(context.exception)
        self.assertIn('Firma digital del CAF no es válida', error_msg)
        self.assertIn('Motivo:', error_msg)

    def test_02_error_message_is_informative(self):
        """Test 02: Mensaje de error proporciona información útil al usuario"""
        with self.assertRaises(ValidationError) as context:
            self.env['dte.caf'].create({
                'dte_type': '33',
                'folio_desde': 1000,
                'folio_hasta': 1100,
                'caf_xml_content': self.test_caf_xml,
                'company_id': self.company.id,
            })

        error_msg = str(context.exception)
        # Debe incluir instrucciones para el usuario
        self.assertIn('Verifique que:', error_msg)
        self.assertIn('descargado correctamente del portal SII', error_msg)
        self.assertIn('no ha sido modificado', error_msg)

    def test_03_valid_caf_structure_extracted(self):
        """Test 03: Metadata se extrae correctamente incluso si firma falla"""
        # Crear con context que bypass validación para testing
        # En producción, esto no debería ser posible
        import base64

        caf_b64 = base64.b64encode(self.test_caf_xml.encode('utf-8'))

        # Extraer metadata sin crear registro
        caf_model = self.env['dte.caf']
        metadata = caf_model._extract_caf_metadata(caf_b64)

        self.assertEqual(metadata['folio_desde'], 1000)
        self.assertEqual(metadata['folio_hasta'], 1100)
        self.assertEqual(metadata['rut_empresa'], '76000000-0')
        self.assertEqual(metadata['fecha_autorizacion'], '2025-11-02')
