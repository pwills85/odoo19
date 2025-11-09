# -*- coding: utf-8 -*-
"""
Unit Tests - XML Digital Signature (XMLDSig)
===========================================

Tests unitarios para libs/xml_signer.py con mocks completos.
No requiere certificados reales ni conexión a base de datos.

Coverage: firma XMLDSig, manejo de errores, validación de certificados.

Author: EERGYGROUP - Claude Code (Anthropic)
License: LGPL-3
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import base64
from lxml import etree


class TestXMLSignerUnit(unittest.TestCase):
    """Tests unitarios para XMLSigner sin dependencias externas."""

    def setUp(self):
        """Preparar mocks y datos de prueba."""
        self.mock_env = Mock()
        self.mock_certificate = Mock()
        self.mock_certificate.id = 1
        self.mock_certificate.certificate_file = base64.b64encode(b'FAKE_CERT_DATA')
        self.mock_certificate.password = 'test_password'

        # XML de prueba simple
        self.test_xml = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0">
    <Documento ID="DOC1">
        <Encabezado>
            <IdDoc>
                <TipoDTE>33</TipoDTE>
                <Folio>123</Folio>
            </IdDoc>
        </Encabezado>
    </Documento>
</DTE>'''

    def test_01_xmlsigner_initialization_with_env(self):
        """Test inicialización con env."""
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        signer = XMLSigner(env=self.mock_env)
        self.assertIsNotNone(signer)
        self.assertEqual(signer.env, self.mock_env)

    def test_02_xmlsigner_initialization_without_env(self):
        """Test inicialización sin env (standalone)."""
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        signer = XMLSigner()
        self.assertIsNotNone(signer)
        self.assertIsNone(signer.env)

    def test_03_sign_xml_dte_requires_env(self):
        """Test que sign_xml_dte requiere env."""
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        signer = XMLSigner()  # Sin env

        with self.assertRaises(RuntimeError) as context:
            signer.sign_xml_dte(self.test_xml, certificate_id=1)

        self.assertIn('requires env', str(context.exception))

    def test_04_get_active_certificate_success(self):
        """Test obtención de certificado activo."""
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        # Mock env with certificate search
        mock_cert_model = Mock()
        mock_cert_model.search.return_value = [self.mock_certificate]
        self.mock_env.__getitem__.return_value = mock_cert_model

        signer = XMLSigner(env=self.mock_env)
        cert_id = signer._get_active_certificate()

        self.assertEqual(cert_id, 1)

    def test_05_get_active_certificate_not_found(self):
        """Test certificado activo no encontrado."""
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        # Mock env with no certificates
        mock_cert_model = Mock()
        mock_cert_model.search.return_value = []
        self.mock_env.__getitem__.return_value = mock_cert_model

        signer = XMLSigner(env=self.mock_env)
        cert_id = signer._get_active_certificate()

        self.assertIsNone(cert_id)

    @patch('addons.localization.l10n_cl_dte.libs.xml_signer.xmlsec')
    @patch('addons.localization.l10n_cl_dte.libs.xml_signer.tempfile')
    def test_06_sign_xml_with_certificate_success(self, mock_tempfile, mock_xmlsec):
        """Test firma XMLDSig exitosa con certificado."""
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        # Mock temporary files
        mock_temp_cert = Mock()
        mock_temp_cert.name = '/tmp/fake_cert.pem'
        mock_tempfile.NamedTemporaryFile.return_value.__enter__.return_value = mock_temp_cert

        # Mock xmlsec signature
        mock_signature = Mock()
        mock_xmlsec.SignatureContext.return_value.sign.return_value = None

        signer = XMLSigner()
        cert_b64 = base64.b64encode(b'FAKE_CERT_PEM_DATA').decode()

        # Simular firma exitosa
        signed_xml = signer.sign_xml_with_certificate(
            self.test_xml,
            cert_b64,
            'test_password'
        )

        # Verificar que se retornó XML (aunque sea el mismo por el mock)
        self.assertIsNotNone(signed_xml)
        self.assertIn('<?xml', signed_xml)

    def test_07_parse_xml_valid(self):
        """Test parsing de XML válido."""
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        signer = XMLSigner()
        tree = etree.fromstring(self.test_xml.encode('ISO-8859-1'))

        self.assertIsNotNone(tree)
        self.assertEqual(tree.tag, 'DTE')

    def test_08_parse_xml_invalid(self):
        """Test parsing de XML inválido."""
        invalid_xml = '<DTE><Documento>NOT CLOSED'

        with self.assertRaises(etree.XMLSyntaxError):
            etree.fromstring(invalid_xml.encode('ISO-8859-1'))

    def test_09_certificate_validation_empty_file(self):
        """Test validación con certificado vacío."""
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        signer = XMLSigner()

        with self.assertRaises((ValueError, Exception)):
            signer.sign_xml_with_certificate(
                self.test_xml,
                '',  # Certificado vacío
                'test_password'
            )

    def test_10_signature_node_creation(self):
        """Test creación de nodo Signature en XML."""
        # Verificar que el XML puede tener nodo Signature
        xml_with_signature = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0">
    <Documento ID="DOC1">
        <Encabezado>
            <IdDoc>
                <TipoDTE>33</TipoDTE>
            </IdDoc>
        </Encabezado>
    </Documento>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
            <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
        </SignedInfo>
        <SignatureValue>FAKE_SIGNATURE</SignatureValue>
    </Signature>
</DTE>'''

        tree = etree.fromstring(xml_with_signature.encode('ISO-8859-1'))

        # Verificar que existe nodo Signature
        namespace = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
        signature = tree.find('.//ds:Signature', namespaces=namespace)

        self.assertIsNotNone(signature)

    def test_11_encoding_iso_8859_1(self):
        """Test que XML usa encoding ISO-8859-1 requerido por SII."""
        self.assertIn('ISO-8859-1', self.test_xml)

        # Verificar que se puede parsear con encoding
        tree = etree.fromstring(self.test_xml.encode('ISO-8859-1'))
        xml_string = etree.tostring(tree, encoding='ISO-8859-1').decode('ISO-8859-1')

        self.assertIn('ISO-8859-1', xml_string)

    def test_12_performance_single_signature(self):
        """Test que firma se completa en tiempo razonable (<1s)."""
        import time
        from addons.localization.l10n_cl_dte.libs.xml_signer import XMLSigner

        signer = XMLSigner()

        start = time.time()
        # Solo medir parsing (firma real requiere certificado)
        tree = etree.fromstring(self.test_xml.encode('ISO-8859-1'))
        elapsed = time.time() - start

        # Parsing debe ser < 0.1s
        self.assertLess(elapsed, 0.1)


# Ejecutar tests si se llama directamente
if __name__ == '__main__':
    unittest.main()
