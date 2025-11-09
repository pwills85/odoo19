# -*- coding: utf-8 -*-
"""
Safe XML Parser - XXE Protection
==================================

Parser seguro para XML con protección contra ataques XXE (XML External Entity).

Características de seguridad:
- Desactiva resolución de entidades externas
- Desactiva acceso a red
- Desactiva procesamiento de DTD externos
- Protege contra billion laughs attack
- Protege contra quadratic blowup attack

Referencias:
- OWASP Top 10 - A4:2017 XXE
- CWE-611: Improper Restriction of XML External Entity Reference
- https://docs.python.org/3/library/xml.html#xml-vulnerabilities

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-02
Sprint: Gap Closure P0 - S-005
Version: 1.0.0
"""

import logging
from lxml import etree

_logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# SAFE XML PARSER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Parser seguro para lxml - Configuración enterprise-grade
SAFE_XML_PARSER = etree.XMLParser(
    # ⭐ PROTECCIÓN XXE CRÍTICA
    resolve_entities=False,      # No resuelve entidades externas (&xxe;)
    no_network=True,             # No permite acceso a red (http://, ftp://)

    # PROTECCIÓN ADICIONAL
    remove_comments=True,        # Elimina comentarios XML (potencial vector)
    remove_pis=True,             # Elimina processing instructions
    huge_tree=False,             # Protege contra árboles XML masivos
    collect_ids=False,           # No colecta IDs (mejora performance)

    # MANEJO DE DTD
    dtd_validation=False,        # No valida DTD (DTD puede ser malicioso)
    load_dtd=False,              # No carga DTD externo

    # ENCODING
    encoding='utf-8',            # Fuerza UTF-8
)


# ═══════════════════════════════════════════════════════════════════════════
# SAFE PARSING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def fromstring_safe(xml_string, parser=None):
    """
    Parse XML string de forma segura con protección XXE.

    Args:
        xml_string (str or bytes): XML a parsear
        parser (XMLParser, optional): Parser customizado (usa SAFE por defecto)

    Returns:
        Element: Elemento raíz del árbol XML

    Raises:
        etree.XMLSyntaxError: Si XML es inválido
        ValueError: Si xml_string es None o vacío

    Security:
        - Protege contra XXE attacks
        - Protege contra billion laughs
        - Protege contra quadratic blowup

    Usage:
        >>> from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe
        >>> root = fromstring_safe('<root><child>data</child></root>')
        >>> print(root.tag)
        'root'
    """
    if not xml_string:
        raise ValueError('XML string cannot be None or empty')

    # Usar parser seguro por defecto
    if parser is None:
        parser = SAFE_XML_PARSER

    # Convertir a bytes si es string
    if isinstance(xml_string, str):
        xml_bytes = xml_string.encode('utf-8')
    else:
        xml_bytes = xml_string

    try:
        root = etree.fromstring(xml_bytes, parser=parser)
        _logger.debug('[SAFE_XML] XML parseado exitosamente (XXE protection enabled)')
        return root
    except etree.XMLSyntaxError as e:
        _logger.error(f'[SAFE_XML] XML Syntax Error: {e}')
        raise
    except Exception as e:
        _logger.error(f'[SAFE_XML] Error parsing XML: {e}', exc_info=True)
        raise ValueError(f'Invalid XML: {e}')


def parse_safe(source, parser=None):
    """
    Parse XML file de forma segura con protección XXE.

    Args:
        source (str or file-like): Ruta al archivo XML o file object
        parser (XMLParser, optional): Parser customizado (usa SAFE por defecto)

    Returns:
        ElementTree: Árbol XML completo

    Raises:
        FileNotFoundError: Si archivo no existe
        etree.XMLSyntaxError: Si XML es inválido

    Usage:
        >>> from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import parse_safe
        >>> tree = parse_safe('/path/to/file.xml')
        >>> root = tree.getroot()
    """
    # Usar parser seguro por defecto
    if parser is None:
        parser = SAFE_XML_PARSER

    try:
        tree = etree.parse(source, parser=parser)
        _logger.debug('[SAFE_XML] XML file parseado exitosamente (XXE protection enabled)')
        return tree
    except FileNotFoundError:
        _logger.error(f'[SAFE_XML] File not found: {source}')
        raise
    except etree.XMLSyntaxError as e:
        _logger.error(f'[SAFE_XML] XML Syntax Error in file: {e}')
        raise
    except Exception as e:
        _logger.error(f'[SAFE_XML] Error parsing XML file: {e}', exc_info=True)
        raise


def tostring_safe(element, encoding='unicode', method='xml'):
    """
    Serializa Element a string XML de forma segura.

    Args:
        element (Element): Elemento XML a serializar
        encoding (str): Encoding de salida ('unicode' para str, 'utf-8' para bytes)
        method (str): Método de serialización ('xml', 'html', 'text', 'c14n')

    Returns:
        str or bytes: XML serializado

    Usage:
        >>> from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import tostring_safe
        >>> xml_str = tostring_safe(root_element)
    """
    try:
        return etree.tostring(element, encoding=encoding, method=method)
    except Exception as e:
        _logger.error(f'[SAFE_XML] Error serializing XML: {e}', exc_info=True)
        raise


# ═══════════════════════════════════════════════════════════════════════════
# VALIDATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def is_xml_safe(xml_string):
    """
    Verifica si XML string contiene patrones maliciosos conocidos.

    Este es un check heurístico adicional, NO reemplaza el parser seguro.

    Args:
        xml_string (str): XML a verificar

    Returns:
        tuple: (is_safe: bool, reason: str)

    Patterns detectados:
        - DTD con ENTITY declarations
        - SYSTEM entity references
        - PUBLIC entity references
        - Excesivas entidades anidadas (billion laughs)

    Usage:
        >>> is_safe, reason = is_xml_safe(suspicious_xml)
        >>> if not is_safe:
        >>>     raise ValueError(f'XML malicioso detectado: {reason}')
    """
    if not xml_string:
        return True, 'Empty XML'

    xml_lower = xml_string.lower()

    # Detectar DOCTYPE con ENTITY (XXE attack vector)
    if '<!doctype' in xml_lower and '<!entity' in xml_lower:
        if 'system' in xml_lower:
            return False, 'XXE attack detected: DOCTYPE with SYSTEM ENTITY'
        if 'public' in xml_lower:
            return False, 'XXE attack detected: DOCTYPE with PUBLIC ENTITY'

    # Detectar billion laughs attack (entidades recursivas)
    entity_count = xml_string.count('<!ENTITY')
    if entity_count > 10:
        return False, f'Billion laughs attack suspected: {entity_count} entities declared'

    # Detectar referencias a archivos locales comunes
    dangerous_paths = ['file:///', '/etc/passwd', '/etc/shadow', 'c:\\windows']
    for path in dangerous_paths:
        if path in xml_lower:
            return False, f'File system access detected: {path}'

    # Detectar referencias a red
    dangerous_protocols = ['http://', 'https://', 'ftp://', 'gopher://']
    for protocol in dangerous_protocols:
        if protocol in xml_lower and '<!entity' in xml_lower:
            return False, f'Network access in entity detected: {protocol}'

    return True, 'XML appears safe'


def sanitize_xml_input(xml_string):
    """
    Sanitiza input XML removiendo patrones peligrosos.

    ADVERTENCIA: Esta función NO es un reemplazo del parser seguro.
    Siempre usar SAFE_XML_PARSER para parsing real.

    Args:
        xml_string (str): XML a sanitizar

    Returns:
        str: XML sanitizado (DOCTYPE removido)

    Usage:
        >>> sanitized = sanitize_xml_input(user_provided_xml)
        >>> root = fromstring_safe(sanitized)
    """
    if not xml_string:
        return xml_string

    # Remover DOCTYPE declaration completa
    import re

    # Pattern para detectar y remover DOCTYPE
    # Captura: <!DOCTYPE ... > o <!DOCTYPE ... [...]>
    doctype_pattern = r'<!DOCTYPE[^>\[]*(\[[^\]]*\])?\s*>'

    sanitized = re.sub(doctype_pattern, '', xml_string, flags=re.IGNORECASE | re.DOTALL)

    if sanitized != xml_string:
        _logger.warning('[SAFE_XML] DOCTYPE declaration removed from XML (security)')

    return sanitized


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def get_safe_parser():
    """
    Obtiene una instancia del parser seguro.

    Útil para casos donde se necesita pasar el parser como argumento.

    Returns:
        XMLParser: Parser configurado con protección XXE

    Usage:
        >>> parser = get_safe_parser()
        >>> tree = etree.parse('file.xml', parser=parser)
    """
    return SAFE_XML_PARSER


def test_xxe_protection():
    """
    Test rápido de protección XXE (para debugging).

    Returns:
        bool: True si protección XXE funciona correctamente

    Usage (desde Odoo shell):
        >>> from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import test_xxe_protection
        >>> test_xxe_protection()
        True
    """
    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

    try:
        # Intentar parsear con parser seguro
        root = fromstring_safe(xxe_payload)

        # Si llegamos aquí, verificar que NO se expandió la entidad
        root_text = root.text if root.text else ''

        if '/etc/passwd' in root_text or 'root:' in root_text:
            _logger.error('[SAFE_XML] XXE PROTECTION FAILED - Entity was expanded!')
            return False
        else:
            _logger.info('[SAFE_XML] ✅ XXE protection working correctly')
            return True

    except Exception as e:
        # Parser seguro rechazó el XML (también es éxito)
        _logger.info(f'[SAFE_XML] ✅ XXE attack blocked: {e}')
        return True
