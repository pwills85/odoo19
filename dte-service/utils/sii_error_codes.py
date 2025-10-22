# -*- coding: utf-8 -*-
"""
Códigos de Error del SII Chile
Mapping oficial de códigos de respuesta del SII

Fuente: Documentación técnica SII
"""

# Códigos principales del SII
SII_ERROR_CODES = {
    # Códigos de éxito
    '0': {
        'message': 'Envío Aceptado',
        'level': 'success',
        'action': 'continue',
        'description': 'El DTE fue aceptado por el SII correctamente'
    },
    
    # Códigos de rechazo - Carátula
    '1': {
        'message': 'Envío Rechazado - Error en Carátula',
        'level': 'error',
        'action': 'review',
        'description': 'Revisar datos de la carátula del envío'
    },
    '2': {
        'message': 'Envío Rechazado - Error en Schema',
        'level': 'error',
        'action': 'review',
        'description': 'El XML no cumple con el esquema XSD del SII'
    },
    '3': {
        'message': 'Envío Rechazado - Error en Firma',
        'level': 'error',
        'action': 'review',
        'description': 'La firma digital no es válida'
    },
    
    # Códigos específicos de validación
    'RPR': {
        'message': 'Folio Repetido',
        'level': 'error',
        'action': 'review',
        'description': 'El folio ya fue utilizado anteriormente'
    },
    'RCT': {
        'message': 'RUT Contribuyente Erróneo',
        'level': 'error',
        'action': 'review',
        'description': 'El RUT del emisor o receptor es inválido'
    },
    'RFR': {
        'message': 'Rango de Folios Excedido',
        'level': 'error',
        'action': 'review',
        'description': 'El folio está fuera del rango autorizado en el CAF'
    },
    'RFP': {
        'message': 'Folio Fuera de Rango',
        'level': 'error',
        'action': 'review',
        'description': 'El folio no está dentro del CAF autorizado'
    },
    'RCD': {
        'message': 'Error en Código',
        'level': 'error',
        'action': 'review',
        'description': 'Código de documento incorrecto'
    },
    
    # Códigos de certificado
    'RCE': {
        'message': 'Certificado no Autorizado',
        'level': 'error',
        'action': 'review_certificate',
        'description': 'El certificado digital no está autorizado por el SII'
    },
    'RCV': {
        'message': 'Certificado Vencido',
        'level': 'error',
        'action': 'renew_certificate',
        'description': 'El certificado digital ha vencido'
    },
    
    # Códigos de formato
    'RFN': {
        'message': 'Formato de Número Incorrecto',
        'level': 'error',
        'action': 'review',
        'description': 'Los montos o números no tienen el formato correcto'
    },
    'RFD': {
        'message': 'Formato de Fecha Incorrecto',
        'level': 'error',
        'action': 'review',
        'description': 'Las fechas no tienen el formato YYYY-MM-DD'
    },
    
    # Más códigos comunes
    'DOK': {
        'message': 'Documento OK',
        'level': 'success',
        'action': 'continue',
        'description': 'Documento procesado correctamente'
    },
    'DNK': {
        'message': 'Documento con Errores',
        'level': 'error',
        'action': 'review',
        'description': 'El documento tiene errores de validación'
    },
    
    # Código genérico
    'UNKNOWN': {
        'message': 'Código Desconocido',
        'level': 'warning',
        'action': 'review',
        'description': 'Código de error no documentado'
    },
}


def interpret_sii_error(code: str) -> dict:
    """
    Interpreta un código de error del SII.
    
    Args:
        code: Código retornado por el SII
    
    Returns:
        dict: Información del error con message, level, action, description
    """
    code_upper = str(code).upper().strip()
    
    error_info = SII_ERROR_CODES.get(code_upper, SII_ERROR_CODES['UNKNOWN'])
    
    return {
        'code': code,
        'message': error_info['message'],
        'level': error_info['level'],
        'action': error_info['action'],
        'description': error_info['description'],
        'user_message': f"SII: {error_info['message']} - {error_info['description']} (Código: {code})"
    }


def get_user_friendly_message(code: str) -> str:
    """
    Retorna mensaje amigable para el usuario.
    
    Args:
        code: Código del SII
    
    Returns:
        str: Mensaje para mostrar al usuario
    """
    info = interpret_sii_error(code)
    return info['user_message']


def is_retriable_error(code: str) -> bool:
    """
    Determina si un error es retriable (temporal).
    
    Args:
        code: Código del SII
    
    Returns:
        bool: True si se puede reintentar
    """
    # Errores que NO se deben reintentar (permanentes)
    permanent_errors = ['RPR', 'RCT', 'RFR', 'RFP', 'RCD', 'RFN', 'RFD']
    
    return code not in permanent_errors

