# -*- coding: utf-8 -*-
"""
Códigos de Error del SII Chile
Mapping oficial de códigos de respuesta del SII

Fuente: Documentación técnica SII
"""

# Códigos principales del SII - Mapping Completo (50+ códigos)
# Fuente: Documentación oficial SII Chile
SII_ERROR_CODES = {
    # ══════════════════════════════════════════════════════════════
    # CÓDIGOS DE ESTADO GENERAL (0-99)
    # ══════════════════════════════════════════════════════════════
    '0': {
        'message': 'Envío Aceptado',
        'level': 'success',
        'action': 'continue',
        'description': 'El DTE fue aceptado por el SII correctamente'
    },
    '1': {
        'message': 'Envío Rechazado - Error en Carátula',
        'level': 'error',
        'action': 'review',
        'description': 'Revisar datos de la carátula del envío'
    },
    '2': {
        'message': 'Envío Rechazado - Error en Schema XML',
        'level': 'error',
        'action': 'review',
        'description': 'El XML no cumple con el esquema XSD del SII'
    },
    '3': {
        'message': 'Envío Rechazado - Error en Firma Digital',
        'level': 'error',
        'action': 'review',
        'description': 'La firma digital no es válida o no corresponde'
    },
    '4': {
        'message': 'Envío Rechazado - Error en Certificado',
        'level': 'error',
        'action': 'review_certificate',
        'description': 'El certificado digital no es válido o no autorizado'
    },
    '5': {
        'message': 'Envío Rechazado - RUT Emisor Erróneo',
        'level': 'error',
        'action': 'review',
        'description': 'El RUT del emisor no es válido o no existe'
    },
    '6': {
        'message': 'Envío Rechazado - RUT Receptor Erróneo',
        'level': 'error',
        'action': 'review',
        'description': 'El RUT del receptor no es válido'
    },
    '7': {
        'message': 'Envío Rechazado - Fecha Emisión Inválida',
        'level': 'error',
        'action': 'review',
        'description': 'La fecha de emisión es inválida o fuera de rango'
    },
    '8': {
        'message': 'Envío Rechazado - Monto Total Inconsistente',
        'level': 'error',
        'action': 'review',
        'description': 'El monto total no coincide con la suma de las líneas'
    },
    '9': {
        'message': 'Envío Rechazado - IVA Inconsistente',
        'level': 'error',
        'action': 'review',
        'description': 'El cálculo del IVA no es correcto'
    },
    '10': {
        'message': 'Envío en Proceso',
        'level': 'info',
        'action': 'wait',
        'description': 'El envío está siendo procesado por el SII'
    },
    '11': {
        'message': 'Envío Pendiente de Validación',
        'level': 'info',
        'action': 'wait',
        'description': 'El envío está en cola de validación'
    },

    # ══════════════════════════════════════════════════════════════
    # CÓDIGOS DE RECHAZO ESPECÍFICO (Códigos Alfabéticos)
    # ══════════════════════════════════════════════════════════════

    # Errores de Carátula (RC*)
    'RCT': {
        'message': 'RUT Contribuyente Erróneo',
        'level': 'error',
        'action': 'review',
        'description': 'El RUT del emisor o receptor es inválido'
    },
    'RCD': {
        'message': 'Error en Código Documento',
        'level': 'error',
        'action': 'review',
        'description': 'Código de tipo de documento incorrecto (debe ser 33, 34, 52, 56, 61, etc.)'
    },
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
    'RCS': {
        'message': 'Error en Secuencia',
        'level': 'error',
        'action': 'review',
        'description': 'La secuencia de envío no es válida'
    },

    # Errores de Folio (RF*)
    'RPR': {
        'message': 'Folio Repetido',
        'level': 'error',
        'action': 'review',
        'description': 'El folio ya fue utilizado anteriormente'
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
    'RFT': {
        'message': 'CAF no Autorizado',
        'level': 'error',
        'action': 'review_caf',
        'description': 'El archivo CAF (Código de Autorización de Folios) no es válido'
    },
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
    'RFO': {
        'message': 'Folio Anulado',
        'level': 'error',
        'action': 'review',
        'description': 'El folio fue previamente anulado'
    },

    # Errores de Validación (RV*)
    'RVT': {
        'message': 'Error en Tipo de Transacción',
        'level': 'error',
        'action': 'review',
        'description': 'El tipo de transacción no es válido para este tipo de DTE'
    },
    'RVM': {
        'message': 'Error en Moneda',
        'level': 'error',
        'action': 'review',
        'description': 'La moneda especificada no es válida'
    },
    'RVD': {
        'message': 'Error en Detalle',
        'level': 'error',
        'action': 'review',
        'description': 'Error en las líneas de detalle del documento'
    },
    'RVR': {
        'message': 'Error en Referencia',
        'level': 'error',
        'action': 'review',
        'description': 'Error en las referencias a otros documentos'
    },
    'RVN': {
        'message': 'Neto Inválido',
        'level': 'error',
        'action': 'review',
        'description': 'El monto neto es inválido o inconsistente'
    },
    'RVI': {
        'message': 'IVA Inválido',
        'level': 'error',
        'action': 'review',
        'description': 'El cálculo del IVA no corresponde (debe ser 19%)'
    },
    'RVE': {
        'message': 'Monto Exento Inválido',
        'level': 'error',
        'action': 'review',
        'description': 'El monto exento es inválido'
    },

    # Errores de Firma (RS*)
    'RSF': {
        'message': 'Firma Inválida',
        'level': 'error',
        'action': 'review',
        'description': 'La firma digital XMLDSig no es válida'
    },
    'RST': {
        'message': 'TED Inválido',
        'level': 'error',
        'action': 'review',
        'description': 'El Timbre Electrónico (TED) no es válido'
    },
    'RSC': {
        'message': 'Canonicalización Incorrecta',
        'level': 'error',
        'action': 'review',
        'description': 'La canonicalización C14N no es correcta'
    },

    # Errores de Negocio (RN*)
    'RNO': {
        'message': 'Operación No Permitida',
        'level': 'error',
        'action': 'review',
        'description': 'La operación no está permitida para este contribuyente'
    },
    'RNP': {
        'message': 'Período Cerrado',
        'level': 'error',
        'action': 'review',
        'description': 'El período tributario ya está cerrado'
    },
    'RNE': {
        'message': 'Empresa No Autorizada',
        'level': 'error',
        'action': 'review',
        'description': 'La empresa no está autorizada para emitir este tipo de DTE'
    },
    'RNS': {
        'message': 'Servicio No Disponible',
        'level': 'warning',
        'action': 'retry',
        'description': 'El servicio del SII no está disponible temporalmente'
    },

    # Errores de Conexión (RE*)
    'RET': {
        'message': 'Timeout de Conexión',
        'level': 'warning',
        'action': 'retry',
        'description': 'Tiempo de espera agotado en la conexión con SII'
    },
    'REC': {
        'message': 'Error de Conexión',
        'level': 'warning',
        'action': 'retry',
        'description': 'No se pudo establecer conexión con el SII'
    },
    'RES': {
        'message': 'Servidor Sobrecargado',
        'level': 'warning',
        'action': 'retry',
        'description': 'El servidor del SII está sobrecargado, reintentar más tarde'
    },

    # ══════════════════════════════════════════════════════════════
    # CÓDIGOS DE ESTADO POSTERIOR (Consulta Estado)
    # ══════════════════════════════════════════════════════════════
    'EPR': {
        'message': 'Procesado',
        'level': 'success',
        'action': 'continue',
        'description': 'El DTE fue procesado exitosamente'
    },
    'EOK': {
        'message': 'DTE OK',
        'level': 'success',
        'action': 'continue',
        'description': 'DTE procesado y aceptado'
    },
    'ERR': {
        'message': 'DTE con Errores',
        'level': 'error',
        'action': 'review',
        'description': 'El DTE fue procesado pero tiene errores'
    },
    'FAU': {
        'message': 'Falla Autenticación',
        'level': 'error',
        'action': 'review',
        'description': 'Fallo en la autenticación con el SII'
    },
    'FNA': {
        'message': 'Firma No Auténtica',
        'level': 'error',
        'action': 'review',
        'description': 'La firma no pudo ser autenticada'
    },

    # ══════════════════════════════════════════════════════════════
    # CÓDIGOS ADICIONALES ESPECÍFICOS CHILE
    # ══════════════════════════════════════════════════════════════
    'SCO': {
        'message': 'Schema no Corresponde',
        'level': 'error',
        'action': 'review',
        'description': 'El schema XML utilizado no corresponde a la versión esperada'
    },
    'CDO': {
        'message': 'Contrato de Envío no Vigente',
        'level': 'error',
        'action': 'review',
        'description': 'El contrato con SII no está vigente o no existe'
    },
    'PDF': {
        'message': 'Error en Generación PDF',
        'level': 'warning',
        'action': 'review',
        'description': 'Error al generar la representación PDF del DTE'
    },
    'TED': {
        'message': 'Error en TED',
        'level': 'error',
        'action': 'review',
        'description': 'El Timbre Electrónico (TED) tiene errores o no corresponde'
    },

    # Códigos de Rechazo Comercial
    'RCH': {
        'message': 'Rechazo Comercial',
        'level': 'info',
        'action': 'notify',
        'description': 'El receptor rechazó comercialmente el DTE'
    },
    'RLI': {
        'message': 'Reclamo de Contenido',
        'level': 'warning',
        'action': 'notify',
        'description': 'El receptor reclama sobre el contenido del DTE'
    },

    # Códigos de Estado de Track ID
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
    'ACD': {
        'message': 'Aceptado con Discrepancias',
        'level': 'warning',
        'action': 'review',
        'description': 'DTE aceptado pero con discrepancias menores'
    },
    'PRC': {
        'message': 'En Proceso',
        'level': 'info',
        'action': 'wait',
        'description': 'El DTE está siendo procesado'
    },
    'REP': {
        'message': 'Documento Repetido',
        'level': 'error',
        'action': 'review',
        'description': 'El DTE ya fue enviado previamente'
    },
    'REC_TEMP': {
        'message': 'Recibo Temporal',
        'level': 'info',
        'action': 'wait',
        'description': 'Recibo temporal, esperando procesamiento final'
    },

    # Código genérico
    'UNKNOWN': {
        'message': 'Código Desconocido',
        'level': 'warning',
        'action': 'review',
        'description': 'Código de error no documentado en este sistema'
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
    error_info = interpret_sii_error(code)

    # Errores retriables son aquellos con action='retry' o action='wait'
    return error_info['action'] in ['retry', 'wait']

