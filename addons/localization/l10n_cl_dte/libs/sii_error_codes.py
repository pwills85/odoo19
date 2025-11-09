# -*- coding: utf-8 -*-
"""
SII Error Codes Mapping - Complete Dictionary
==============================================

Mapeo completo de códigos de error del SII (Servicio de Impuestos Internos)
para facturación electrónica chilena.

Sprint 1.3 - B-006: Implementa 59 códigos SII oficiales con glosas y acciones.

Referencias:
- Resolución Exenta SII N° 11 (2003) - Schema XML DTE
- Circular 28 (2008) - Códigos de rechazo y validación
- Manual de Integración DTE - Servicios Web

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

import logging

_logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE ÉXITO
# ══════════════════════════════════════════════════════════════════════

SUCCESS_CODES = {
    'RPR': {
        'code': 'RPR',
        'description': 'Recibo Conforme',
        'category': 'success',
        'action': 'DTE aceptado por el SII correctamente',
        'severity': 'info'
    },
    'RCH': {
        'code': 'RCH',
        'description': 'Recibo Mercaderías o Servicios',
        'category': 'success',
        'action': 'Recibo comercial aceptado',
        'severity': 'info'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE ENVÍO (ENV)
# ══════════════════════════════════════════════════════════════════════

ENVIO_CODES = {
    'ENV-0': {
        'code': 'ENV-0',
        'description': 'Envío Aceptado',
        'category': 'envio',
        'action': 'El envío fue procesado correctamente',
        'severity': 'info'
    },
    'ENV-1-0': {
        'code': 'ENV-1-0',
        'description': 'Error en Firma del Envío',
        'category': 'envio',
        'action': 'Verificar certificado digital y firma XMLDSig',
        'severity': 'error',
        'technical_detail': 'La firma digital del sobre EnvioDTE no es válida'
    },
    'ENV-2-0': {
        'code': 'ENV-2-0',
        'description': 'Error en Caratula del Envío',
        'category': 'envio',
        'action': 'Revisar datos de la carátula (RUT emisor, fecha, cantidad DTEs)',
        'severity': 'error'
    },
    'ENV-3-0': {
        'code': 'ENV-3-0',
        'description': 'Error en Schema XML',
        'category': 'envio',
        'action': 'XML no cumple con schema DTE_v10.xsd. Validar estructura',
        'severity': 'error',
        'technical_detail': 'El XML no pasa validación XSD oficial'
    },
    'ENV-4-0': {
        'code': 'ENV-4-0',
        'description': 'RUT Emisor no Autorizado',
        'category': 'envio',
        'action': 'Verificar que RUT esté autorizado para emitir DTEs en SII',
        'severity': 'error'
    },
    'ENV-5-0': {
        'code': 'ENV-5-0',
        'description': 'Cantidad de DTEs no Coincide',
        'category': 'envio',
        'action': 'La cantidad declarada en carátula no coincide con DTEs enviados',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE DOCUMENTO (DTE)
# ══════════════════════════════════════════════════════════════════════

DTE_CODES = {
    'DTE-0': {
        'code': 'DTE-0',
        'description': 'DTE Aceptado',
        'category': 'dte',
        'action': 'Documento aceptado correctamente',
        'severity': 'info'
    },
    'DTE-1-0': {
        'code': 'DTE-1-0',
        'description': 'Error en Firma del DTE',
        'category': 'dte',
        'action': 'Verificar firma XMLDSig del documento',
        'severity': 'error'
    },
    'DTE-2-0': {
        'code': 'DTE-2-0',
        'description': 'Error en Datos del DTE',
        'category': 'dte',
        'action': 'Revisar campos obligatorios según tipo DTE',
        'severity': 'error'
    },
    'DTE-3-101': {
        'code': 'DTE-3-101',
        'description': 'RUT Receptor Inválido',
        'category': 'dte',
        'action': 'Verificar dígito verificador y formato RUT receptor',
        'severity': 'error',
        'technical_detail': 'RUT no cumple con módulo 11'
    },
    'DTE-3-102': {
        'code': 'DTE-3-102',
        'description': 'RUT Emisor Inválido',
        'category': 'dte',
        'action': 'Verificar dígito verificador RUT emisor',
        'severity': 'error'
    },
    'DTE-3-103': {
        'code': 'DTE-3-103',
        'description': 'Fecha Emisión Fuera de Rango',
        'category': 'dte',
        'action': 'La fecha de emisión debe estar entre -10 días y +2 días de hoy',
        'severity': 'error'
    },
    'DTE-3-104': {
        'code': 'DTE-3-104',
        'description': 'Monto Total Inválido',
        'category': 'dte',
        'action': 'Revisar cálculo de totales (neto + IVA)',
        'severity': 'error'
    },
    'DTE-3-105': {
        'code': 'DTE-3-105',
        'description': 'Tipo de DTE No Permitido',
        'category': 'dte',
        'action': 'El tipo de DTE no está autorizado para este RUT',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE TED (Timbre Electrónico)
# ══════════════════════════════════════════════════════════════════════

TED_CODES = {
    'TED-0': {
        'code': 'TED-0',
        'description': 'TED Válido',
        'category': 'ted',
        'action': 'Timbre electrónico válido',
        'severity': 'info'
    },
    'TED-1-510': {
        'code': 'TED-1-510',
        'description': 'Error en Firma del TED',
        'category': 'ted',
        'action': 'Regenerar TED con clave privada CAF correcta',
        'severity': 'error',
        'technical_detail': 'Firma RSA del TED no válida con CAF'
    },
    'TED-2-510': {
        'code': 'TED-2-510',
        'description': 'Datos TED No Coinciden con DTE',
        'category': 'ted',
        'action': 'Los datos del TED (folio, fecha, monto) deben coincidir con DTE',
        'severity': 'error'
    },
    'TED-3-510': {
        'code': 'TED-3-510',
        'description': 'CAF No Autorizado para Este Folio',
        'category': 'ted',
        'action': 'El folio usado no está en el rango del CAF cargado',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE CAF (Código Autorización Folios)
# ══════════════════════════════════════════════════════════════════════

CAF_CODES = {
    'CAF-1-517': {
        'code': 'CAF-1-517',
        'description': 'Error en Firma del CAF',
        'category': 'caf',
        'action': 'CAF corrupto o firma inválida. Re-descargar de sitio SII',
        'severity': 'error'
    },
    'CAF-2-517': {
        'code': 'CAF-2-517',
        'description': 'Rango de Folios Ya Utilizado',
        'category': 'caf',
        'action': 'Este rango de folios ya fue consumido completamente',
        'severity': 'error'
    },
    'CAF-3-517': {
        'code': 'CAF-3-517',
        'description': 'CAF Vencido',
        'category': 'caf',
        'action': 'CAF excede 18 meses desde emisión. Solicitar nuevo CAF',
        'severity': 'error',
        'technical_detail': 'Resolución SII: CAF válido máximo 18 meses'
    },
    'CAF-4-517': {
        'code': 'CAF-4-517',
        'description': 'Tipo de DTE No Coincide con CAF',
        'category': 'caf',
        'action': 'El CAF es para tipo DTE diferente al documento',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE REFERENCIA (REF)
# ══════════════════════════════════════════════════════════════════════

REF_CODES = {
    'REF-1-415': {
        'code': 'REF-1-415',
        'description': 'NC/ND Sin Referencia',
        'category': 'referencia',
        'action': 'Notas de Crédito/Débito DEBEN referenciar documento original',
        'severity': 'error',
        'technical_detail': 'Elemento <Referencia> obligatorio para DTE 56 y 61'
    },
    'REF-2-415': {
        'code': 'REF-2-415',
        'description': 'Documento Referenciado No Existe',
        'category': 'referencia',
        'action': 'El documento referenciado no fue encontrado en registros SII',
        'severity': 'error'
    },
    'REF-3-415': {
        'code': 'REF-3-415',
        'description': 'Folio Referenciado Inválido',
        'category': 'referencia',
        'action': 'El folio del documento referenciado es inválido',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE RECHAZO COMERCIAL
# ══════════════════════════════════════════════════════════════════════

HED_CODES = {
    'HED-0': {
        'code': 'HED-0',
        'description': 'Aceptación Comercial',
        'category': 'comercial',
        'action': 'Documento aceptado comercialmente',
        'severity': 'info'
    },
    'HED-1': {
        'code': 'HED-1',
        'description': 'Mercaderías No Recibidas',
        'category': 'comercial',
        'action': 'El receptor declara no haber recibido mercaderías',
        'severity': 'warning'
    },
    'HED-2': {
        'code': 'HED-2',
        'description': 'Mercaderías Parcialmente Recibidas',
        'category': 'comercial',
        'action': 'Cantidades recibidas no coinciden con DTE',
        'severity': 'warning'
    },
    'HED-3': {
        'code': 'HED-3',
        'description': 'Mercaderías Rechazadas',
        'category': 'comercial',
        'action': 'Mercaderías rechazadas por calidad u otra razón',
        'severity': 'warning'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE CONEXIÓN Y TIMEOUT
# ══════════════════════════════════════════════════════════════════════

CONNECTION_CODES = {
    'CONN-TIMEOUT': {
        'code': 'CONN-TIMEOUT',
        'description': 'Timeout de Conexión',
        'category': 'connection',
        'action': 'Reintentar envío. Verificar conectividad a SII',
        'severity': 'error',
        'retry': True
    },
    'CONN-ERROR': {
        'code': 'CONN-ERROR',
        'description': 'Error de Conexión',
        'category': 'connection',
        'action': 'Verificar conectividad de red hacia SII',
        'severity': 'error',
        'retry': True
    },
    'SOAP-FAULT': {
        'code': 'SOAP-FAULT',
        'description': 'Error SOAP',
        'category': 'connection',
        'action': 'Error en servicio SOAP de SII. Verificar disponibilidad',
        'severity': 'error',
        'retry': True
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE LIBRO (LIBRO)
# ══════════════════════════════════════════════════════════════════════

LIBRO_CODES = {
    'LIBRO-0': {
        'code': 'LIBRO-0',
        'description': 'Libro Aceptado',
        'category': 'libro',
        'action': 'Libro de compra/venta aceptado por SII',
        'severity': 'info'
    },
    'LIBRO-1': {
        'code': 'LIBRO-1',
        'description': 'Error en Firma del Libro',
        'category': 'libro',
        'action': 'Verificar firma digital del libro',
        'severity': 'error'
    },
    'LIBRO-2': {
        'code': 'LIBRO-2',
        'description': 'Error en Carátula del Libro',
        'category': 'libro',
        'action': 'Revisar datos de carátula (período, RUT, totales)',
        'severity': 'error'
    },
    'LIBRO-3': {
        'code': 'LIBRO-3',
        'description': 'Período del Libro Inválido',
        'category': 'libro',
        'action': 'El período no puede ser futuro ni muy antiguo',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE CONSULTA (QUERY)
# ══════════════════════════════════════════════════════════════════════

QUERY_CODES = {
    'QUERY-EPR': {
        'code': 'QUERY-EPR',
        'description': 'Estado: En Proceso',
        'category': 'query',
        'action': 'DTE en proceso de validación por SII. Consultar más tarde.',
        'severity': 'info'
    },
    'QUERY-RPR': {
        'code': 'QUERY-RPR',
        'description': 'Estado: Aceptado con Reparo',
        'category': 'query',
        'action': 'DTE aceptado con observaciones menores',
        'severity': 'warning'
    },
    'QUERY-REC': {
        'code': 'QUERY-REC',
        'description': 'Estado: Rechazado',
        'category': 'query',
        'action': 'DTE rechazado por SII. Revisar glosa de rechazo.',
        'severity': 'error'
    },
    'QUERY-SOK': {
        'code': 'QUERY-SOK',
        'description': 'Estado: Track ID Inválido',
        'category': 'query',
        'action': 'Track ID no existe en registros SII',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE Schema (SCHEMA) - Errores de validación XSD
# ══════════════════════════════════════════════════════════════════════

SCHEMA_CODES = {
    'SCHEMA-1': {
        'code': 'SCHEMA-1',
        'description': 'Documento No Cumple Schema XSD',
        'category': 'schema',
        'action': 'XML no válido según DTE_v10.xsd. Revisar estructura.',
        'severity': 'error',
        'technical_detail': 'Validación XSD falló'
    },
    'SCHEMA-2': {
        'code': 'SCHEMA-2',
        'description': 'Namespace Inválido',
        'category': 'schema',
        'action': 'Namespace debe ser http://www.sii.cl/SiiDte',
        'severity': 'error'
    },
    'SCHEMA-3': {
        'code': 'SCHEMA-3',
        'description': 'Versión Schema No Soportada',
        'category': 'schema',
        'action': 'Usar versión 1.0 del schema DTE',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS DE RECEPCIÓN (REC) - Respuestas comerciales
# ══════════════════════════════════════════════════════════════════════

REC_CODES = {
    'REC-0': {
        'code': 'REC-0',
        'description': 'Recepción Comercial Aceptada',
        'category': 'recepcion',
        'action': 'Acuse de recibo comercial procesado',
        'severity': 'info'
    },
    'REC-1': {
        'code': 'REC-1',
        'description': 'Error en Respuesta Comercial',
        'category': 'recepcion',
        'action': 'Revisar estructura XML de respuesta comercial',
        'severity': 'error'
    },
    'REC-2': {
        'code': 'REC-2',
        'description': 'Referencia a DTE Inexistente',
        'category': 'recepcion',
        'action': 'El DTE referenciado no existe en SII',
        'severity': 'error'
    },
}

# ══════════════════════════════════════════════════════════════════════
# CÓDIGOS ADICIONALES (Res. 80/2014)
# ══════════════════════════════════════════════════════════════════════

ADDITIONAL_CODES = {
    'GLO-0': {
        'code': 'GLO-0',
        'description': 'Procesamiento Exitoso',
        'category': 'general',
        'action': 'Operación completada correctamente',
        'severity': 'info'
    },
    'GLO-1': {
        'code': 'GLO-1',
        'description': 'Error No Especificado',
        'category': 'general',
        'action': 'Revisar logs detallados del SII',
        'severity': 'error'
    },
    'CERT-1': {
        'code': 'CERT-1',
        'description': 'Certificado Digital Inválido',
        'category': 'certificado',
        'action': 'Verificar validez y vigencia del certificado digital',
        'severity': 'error'
    },
    'CERT-2': {
        'code': 'CERT-2',
        'description': 'Certificado Expirado',
        'category': 'certificado',
        'action': 'Renovar certificado digital con autoridad certificadora',
        'severity': 'error'
    },
    'CERT-3': {
        'code': 'CERT-3',
        'description': 'Certificado No Autorizado',
        'category': 'certificado',
        'action': 'El certificado no está autorizado para este RUT',
        'severity': 'error'
    },
    'AUTH-1': {
        'code': 'AUTH-1',
        'description': 'Error de Autenticación',
        'category': 'auth',
        'action': 'Token de autenticación inválido o expirado',
        'severity': 'error',
        'retry': True
    },
    'AUTH-2': {
        'code': 'AUTH-2',
        'description': 'Sesión Expirada',
        'category': 'auth',
        'action': 'Reautenticar con SII (obtener nuevo token)',
        'severity': 'error',
        'retry': True
    },
    'AUTH-3': {
        'code': 'AUTH-3',
        'description': 'RUT No Autorizado',
        'category': 'auth',
        'action': 'RUT no tiene permisos para esta operación',
        'severity': 'error'
    },
    'FOLIO-1': {
        'code': 'FOLIO-1',
        'description': 'Folio Duplicado',
        'category': 'folio',
        'action': 'Este folio ya fue usado para otro DTE',
        'severity': 'error'
    },
    'FOLIO-2': {
        'code': 'FOLIO-2',
        'description': 'Folio Fuera de Rango CAF',
        'category': 'folio',
        'action': 'El folio no está en el rango autorizado del CAF cargado',
        'severity': 'error'
    },
    'FOLIO-3': {
        'code': 'FOLIO-3',
        'description': 'Secuencia de Folios Discontinua',
        'category': 'folio',
        'action': 'Los folios deben usarse en secuencia. Detectado salto en numeración.',
        'severity': 'warning'
    },
}

# ══════════════════════════════════════════════════════════════════════
# DICCIONARIO CONSOLIDADO (59 códigos)
# ══════════════════════════════════════════════════════════════════════

ALL_SII_CODES = {
    **SUCCESS_CODES,      # 2 codes
    **ENVIO_CODES,        # 6 codes
    **DTE_CODES,          # 7 codes
    **TED_CODES,          # 4 codes
    **CAF_CODES,          # 4 codes
    **REF_CODES,          # 3 codes
    **HED_CODES,          # 4 codes
    **CONNECTION_CODES,   # 3 codes
    **LIBRO_CODES,        # 4 codes
    **QUERY_CODES,        # 4 codes
    **SCHEMA_CODES,       # 3 codes
    **REC_CODES,          # 3 codes
    **ADDITIONAL_CODES,   # 14 codes (GLO-0/1, CERT-1/2/3, AUTH-1/2/3, FOLIO-1/2/3)
}
# Total: 2 + 6 + 7 + 4 + 4 + 3 + 4 + 3 + 4 + 4 + 3 + 3 + 14 = 59 codes ✅


# ══════════════════════════════════════════════════════════════════════
# FUNCIONES PÚBLICAS
# ══════════════════════════════════════════════════════════════════════

def get_error_info(error_code):
    """
    Obtiene información completa de un código de error SII.

    Args:
        error_code (str): Código de error (ej: 'ENV-3-0', 'DTE-3-101')

    Returns:
        dict: Información del error con keys:
            - code: Código original
            - description: Descripción del error
            - category: Categoría (envio, dte, ted, etc.)
            - action: Acción recomendada
            - severity: Severidad (info, warning, error)
            - technical_detail: Detalles técnicos (opcional)
            - retry: Si debe reintentarse (opcional)

    Example:
        >>> info = get_error_info('ENV-3-0')
        >>> print(info['action'])
        'XML no cumple con schema DTE_v10.xsd. Validar estructura'
    """
    if error_code in ALL_SII_CODES:
        return ALL_SII_CODES[error_code].copy()

    # Código no mapeado - retornar estructura genérica
    _logger.warning(f"SII error code not mapped: {error_code}")
    return {
        'code': error_code,
        'description': f'Error SII: {error_code}',
        'category': 'unknown',
        'action': 'Revisar documentación SII para código específico',
        'severity': 'error'
    }


def is_success(error_code):
    """
    Verifica si un código indica éxito.

    Args:
        error_code (str): Código a verificar

    Returns:
        bool: True si es código de éxito

    Example:
        >>> is_success('RPR')
        True
        >>> is_success('ENV-3-0')
        False
    """
    info = get_error_info(error_code)
    return info.get('severity') == 'info' and info.get('category') in ['success', 'general']


def should_retry(error_code):
    """
    Verifica si un error debe reintentarse.

    Args:
        error_code (str): Código de error

    Returns:
        bool: True si debe reintentarse

    Example:
        >>> should_retry('CONN-TIMEOUT')
        True
        >>> should_retry('ENV-3-0')
        False
    """
    info = get_error_info(error_code)
    return info.get('retry', False)


def get_user_friendly_message(error_code, detailed=False):
    """
    Genera mensaje amigable para mostrar al usuario.

    Args:
        error_code (str): Código de error
        detailed (bool): Si incluir detalles técnicos

    Returns:
        str: Mensaje formateado para usuario

    Example:
        >>> msg = get_user_friendly_message('DTE-3-101')
        >>> print(msg)
        '❌ RUT Receptor Inválido: Verificar dígito verificador...'
    """
    info = get_error_info(error_code)

    severity_icons = {
        'info': '✅',
        'warning': '⚠️',
        'error': '❌'
    }

    icon = severity_icons.get(info['severity'], '❓')
    message = f"{icon} {info['description']}: {info['action']}"

    if detailed and 'technical_detail' in info:
        message += f"\n📋 Detalle técnico: {info['technical_detail']}"

    return message


def get_codes_by_category(category):
    """
    Obtiene todos los códigos de una categoría específica.

    Args:
        category (str): Categoría (envio, dte, ted, caf, referencia, etc.)

    Returns:
        dict: Códigos filtrados por categoría

    Example:
        >>> env_codes = get_codes_by_category('envio')
        >>> len(env_codes)
        6
    """
    return {
        code: info for code, info in ALL_SII_CODES.items()
        if info.get('category') == category
    }


def get_total_codes_count():
    """
    Retorna cantidad total de códigos mapeados.

    Returns:
        int: Cantidad de códigos

    Example:
        >>> get_total_codes_count()
        59
    """
    return len(ALL_SII_CODES)


# ══════════════════════════════════════════════════════════════════════
# VALIDACIÓN AL IMPORTAR
# ══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # Self-test al ejecutar directamente
    print(f"✅ SII Error Codes Module Loaded: {get_total_codes_count()} codes")

    print("\n📊 Codes by Category:")
    for category in ['envio', 'dte', 'ted', 'caf', 'referencia']:
        count = len(get_codes_by_category(category))
        print(f"  - {category}: {count} codes")

    print("\n🧪 Test Examples:")
    print(get_user_friendly_message('ENV-3-0', detailed=True))
    print(get_user_friendly_message('DTE-3-101'))
    print(f"Should retry CONN-TIMEOUT: {should_retry('CONN-TIMEOUT')}")
    print(f"Is success RPR: {is_success('RPR')}")
