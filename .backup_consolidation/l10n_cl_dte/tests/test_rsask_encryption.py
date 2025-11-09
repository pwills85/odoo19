# -*- coding: utf-8 -*-
"""
Test Suite: RSASK Encryption
==============================

Tests completos para la encriptación de llaves privadas RSA (RSASK) en CAFs.

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-02
Sprint: Gap Closure P0 - F-005
Version: 1.0.0
"""

from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError
from odoo.addons.l10n_cl_dte.tools.encryption_helper import get_encryption_helper
import base64


@tagged('post_install', '-at_install', 'rsask_encryption', 'gap_closure_p0')
class TestRSASKEncryption(TransactionCase):
    """
    Test suite para encriptación de RSASK en CAFs.

    Cobertura:
    - Encriptación automática al crear CAF
    - Desencriptación correcta al leer
    - RSASK nunca almacenado en texto plano
    - Compute/inverse fields funcionando
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.company = cls.env.company

        # RSASK de prueba (similar al formato SII)
        cls.test_rsask = """MIICXQIBAAKBgQC5JZ7cZ+BkKbP3xRlk8h6T7sKLwF8L3Y4QnZ9YxKpL3wX0vZhM
2pR9Ks5uC4B3W2nY5qL3wX0vZhM2pR9Ks5uC4B3W2nY5qL3wX0vZhM2pR9Ks5uC
4B3W2nY5qL3wX0vZhM2pR9Ks5uC4B3W2nYwIDAQAB"""

        # CAF de prueba con RSASK
        cls.test_caf_xml = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>76000000-0</RE>
      <RS>EMPRESA TEST SPA</RS>
      <TD>33</TD>
      <RNG><D>2000</D><H>2100</H></RNG>
      <FA>2025-11-02</FA>
      <RSAPK>
        <M>xV1JT8aGk9LKzR5qL3wX0vZhM2pR9Ks5uC4B3W2nY</M>
        <E>Aw==</E>
      </RSAPK>
      <RSASK>{cls.test_rsask}</RSASK>
      <IDK>100</IDK>
    </DA>
    <FRMA algoritmo="SHA1withRSA">dGVzdF9zaWduYXR1cmVfZGF0YQ==</FRMA>
  </CAF>
</AUTORIZACION>"""

        cls.test_caf_b64 = base64.b64encode(cls.test_caf_xml.encode('utf-8')).decode('utf-8')

    def setUp(self):
        super().setUp()
        self.encryption_helper = get_encryption_helper(self.env)

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE ENCRIPTACIÓN AUTOMÁTICA
    # ═══════════════════════════════════════════════════════════════════════════

    def test_01_rsask_encrypted_on_caf_upload(self):
        """Test 01: RSASK se encripta automáticamente al cargar CAF"""
        # Nota: Este test fallará debido al constraint de firma CAF (F-002)
        # que valida la firma digital. Para testing, necesitaríamos un CAF real.
        # Por ahora, validamos la lógica de encriptación con datos directos.

        rsask_plaintext = self.test_rsask

        # Crear CAF directamente con rsask (bypass constraint para testing)
        caf = self.env['dte.caf'].with_context(skip_signature_validation=True).new({
            'name': 'CAF Test Encryption',
            'dte_type': '33',
            'folio_desde': 2000,
            'folio_hasta': 2100,
            'company_id': self.company.id,
        })

        # Asignar RSASK usando inverse method
        caf.rsask = rsask_plaintext

        # Verificar que fue encriptado
        self.assertTrue(caf.rsask_encrypted, 'RSASK no fue encriptado')

        # Verificar que no está en texto plano
        encrypted_b64 = base64.b64encode(caf.rsask_encrypted).decode('utf-8')
        self.assertNotEqual(encrypted_b64, rsask_plaintext, 'RSASK almacenado sin encriptar')

        # Verificar que empieza con prefijo Fernet
        self.assertTrue(encrypted_b64.startswith('gA'), 'RSASK no tiene formato Fernet válido')

    def test_02_rsask_decrypted_on_read(self):
        """Test 02: RSASK se desencripta correctamente al leer"""
        rsask_plaintext = self.test_rsask

        caf = self.env['dte.caf'].with_context(skip_signature_validation=True).new({
            'name': 'CAF Test Decryption',
            'dte_type': '33',
            'folio_desde': 2000,
            'folio_hasta': 2100,
            'company_id': self.company.id,
        })

        # Asignar y encriptar
        caf.rsask = rsask_plaintext

        # Limpiar cache para forzar recomputación
        caf.invalidate_cache(['rsask'])

        # Verificar desencriptación (compute method)
        self.assertEqual(caf.rsask, rsask_plaintext, 'RSASK no se desencriptó correctamente')

    def test_03_rsask_field_not_stored(self):
        """Test 03: Campo rsask (computed) nunca se almacena en base de datos"""
        # Verificar que el campo rsask tiene store=False
        rsask_field = self.env['dte.caf']._fields['rsask']
        self.assertFalse(rsask_field.store, 'Campo rsask NO debe estar almacenado (store=True)')

    def test_04_rsask_encrypted_field_is_binary(self):
        """Test 04: Campo rsask_encrypted es Binary con attachment"""
        rsask_encrypted_field = self.env['dte.caf']._fields['rsask_encrypted']

        self.assertEqual(rsask_encrypted_field.type, 'binary', 'rsask_encrypted debe ser Binary')
        self.assertTrue(rsask_encrypted_field.attachment, 'rsask_encrypted debe usar attachment')

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE SEGURIDAD
    # ═══════════════════════════════════════════════════════════════════════════

    def test_05_encryption_helper_available(self):
        """Test 05: EncryptionHelper está disponible y funcional"""
        self.assertIsNotNone(self.encryption_helper, 'EncryptionHelper no disponible')

        # Test encrypt/decrypt básico
        plaintext = 'LLAVE_PRIVADA_TEST'
        encrypted = self.encryption_helper.encrypt(plaintext)
        decrypted = self.encryption_helper.decrypt(encrypted)

        self.assertEqual(decrypted, plaintext, 'EncryptionHelper encrypt/decrypt fallido')

    def test_06_cannot_encrypt_empty_rsask(self):
        """Test 06: No se puede encriptar RSASK vacío"""
        with self.assertRaises(ValueError):
            self.encryption_helper.encrypt('')

        with self.assertRaises(ValueError):
            self.encryption_helper.encrypt(None)

    def test_07_cannot_decrypt_invalid_data(self):
        """Test 07: No se puede desencriptar datos inválidos"""
        with self.assertRaises(ValueError):
            self.encryption_helper.decrypt('DATOS_INVALIDOS_NO_ENCRIPTADOS')

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE INTEGRACIÓN
    # ═══════════════════════════════════════════════════════════════════════════

    def test_08_extract_caf_metadata_encrypts_rsask(self):
        """Test 08: _extract_caf_metadata extrae y encripta RSASK automáticamente"""
        caf_model = self.env['dte.caf']

        # Extraer metadata del CAF de prueba
        metadata = caf_model._extract_caf_metadata(self.test_caf_b64)

        # Verificar que RSASK fue extraído y encriptado
        self.assertIn('rsask_encrypted', metadata, 'rsask_encrypted no en metadata')
        self.assertIsNotNone(metadata['rsask_encrypted'], 'RSASK no fue encriptado')

        # Verificar que es bytes (Binary)
        self.assertIsInstance(metadata['rsask_encrypted'], bytes, 'rsask_encrypted debe ser bytes')

        # Verificar que está encriptado (no es el texto plano)
        encrypted_b64 = base64.b64encode(metadata['rsask_encrypted']).decode('utf-8')
        self.assertNotIn(self.test_rsask, encrypted_b64, 'RSASK no está encriptado')

    def test_09_roundtrip_encrypt_decrypt(self):
        """Test 09: Roundtrip completo: asignar → encriptar → leer → desencriptar"""
        original_rsask = self.test_rsask

        caf = self.env['dte.caf'].with_context(skip_signature_validation=True).new({
            'name': 'CAF Roundtrip Test',
            'dte_type': '33',
            'folio_desde': 3000,
            'folio_hasta': 3100,
            'company_id': self.company.id,
        })

        # Paso 1: Asignar RSASK (trigger _inverse_rsask)
        caf.rsask = original_rsask

        # Paso 2: Verificar encriptación
        self.assertTrue(caf.rsask_encrypted, 'RSASK no encriptado en Paso 2')

        # Paso 3: Limpiar cache y leer (trigger _compute_rsask)
        caf.invalidate_cache(['rsask'])
        decrypted_rsask = caf.rsask

        # Paso 4: Verificar que coincide con original
        self.assertEqual(
            decrypted_rsask,
            original_rsask,
            'RSASK no sobrevivió roundtrip encrypt→decrypt'
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # TESTS DE CASOS EDGE
    # ═══════════════════════════════════════════════════════════════════════════

    def test_10_rsask_none_handled_gracefully(self):
        """Test 10: RSASK None se maneja gracefully"""
        caf = self.env['dte.caf'].with_context(skip_signature_validation=True).new({
            'name': 'CAF Test None',
            'dte_type': '33',
            'folio_desde': 4000,
            'folio_hasta': 4100,
            'company_id': self.company.id,
        })

        # Asignar None
        caf.rsask = None

        # Debe resultar en rsask_encrypted = False, no error
        self.assertFalse(caf.rsask_encrypted, 'rsask_encrypted debe ser False para None')

    def test_11_rsask_empty_string_handled(self):
        """Test 11: RSASK empty string se maneja sin encriptar"""
        caf = self.env['dte.caf'].with_context(skip_signature_validation=True).new({
            'name': 'CAF Test Empty',
            'dte_type': '33',
            'folio_desde': 5000,
            'folio_hasta': 5100,
            'company_id': self.company.id,
        })

        # Asignar empty string
        caf.rsask = ''

        # Debe resultar en rsask_encrypted = False
        self.assertFalse(caf.rsask_encrypted, 'rsask_encrypted debe ser False para empty string')


@tagged('post_install', '-at_install', 'rsask_encryption_performance', 'gap_closure_p0')
class TestRSASKEncryptionPerformance(TransactionCase):
    """
    Tests de performance para encriptación RSASK.

    Verifica que la encriptación no degrada el rendimiento significativamente.
    """

    def test_01_encryption_performance(self):
        """Test 01: Encriptación de RSASK toma < 100ms"""
        import time
        from odoo.addons.l10n_cl_dte.tools.encryption_helper import get_encryption_helper

        encryption_helper = get_encryption_helper(self.env)
        rsask_test = "A" * 1000  # RSASK de 1KB

        start = time.time()
        for _ in range(10):
            encrypted = encryption_helper.encrypt(rsask_test)
            decrypted = encryption_helper.decrypt(encrypted)
            assert decrypted == rsask_test
        elapsed = time.time() - start

        # 10 ciclos encrypt→decrypt deben tomar < 100ms
        self.assertLess(elapsed, 0.1, f'10 ciclos tomaron {elapsed*1000:.1f}ms (límite: 100ms)')

    def test_02_caf_creation_not_degraded(self):
        """Test 02: Creación de CAF con RSASK no degrada significativamente"""
        import time

        rsask_test = "LLAVE_PRIVADA_RSA_TEST"

        caf_data = {
            'name': 'CAF Performance Test',
            'dte_type': '33',
            'folio_desde': 6000,
            'folio_hasta': 6100,
            'company_id': self.env.company.id,
        }

        # Crear múltiples CAFs y medir tiempo
        start = time.time()
        for i in range(5):
            caf = self.env['dte.caf'].with_context(skip_signature_validation=True).new({
                **caf_data,
                'folio_desde': 6000 + (i * 100),
                'folio_hasta': 6100 + (i * 100),
            })
            caf.rsask = rsask_test
            # Verificar que fue encriptado
            assert caf.rsask_encrypted
        elapsed = time.time() - start

        # 5 creaciones + encriptación deben tomar < 500ms
        self.assertLess(elapsed, 0.5, f'5 creaciones tomaron {elapsed*1000:.1f}ms (límite: 500ms)')
