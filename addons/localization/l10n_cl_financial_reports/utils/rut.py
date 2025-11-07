# -*- coding: utf-8 -*-
"""
Utilidades para validación y formateo de RUT chileno
"""

import re


def validate_rut(rut_string):
    """
    Valida un RUT chileno verificando el dígito verificador.

    Args:
        rut_string (str): RUT a validar. Puede contener puntos, guiones y espacios.
                         Ejemplos: '12.345.678-9', '12345678-9', '123456789'

    Returns:
        bool: True si el RUT es válido (verificador correcto), False en caso contrario.

    Examples:
        >>> validate_rut('12.345.678-5')
        True
        >>> validate_rut('12345678-5')
        True
        >>> validate_rut('123456785')
        True
        >>> validate_rut('12.345.678-9')  # Verificador incorrecto
        False
    """
    if not rut_string:
        return False

    # Normalizar: eliminar puntos, guiones y espacios
    rut_clean = re.sub(r'[.\-\s]', '', str(rut_string).upper())

    # Validar formato: debe tener al menos 2 caracteres (número + verificador)
    if len(rut_clean) < 2:
        return False

    # Separar número y verificador
    rut_number = rut_clean[:-1]
    verificador_ingresado = rut_clean[-1]

    # Validar que el número sea numérico
    if not rut_number.isdigit():
        return False

    # Calcular verificador esperado
    verificador_calculado = _calcular_verificador(rut_number)

    # Comparar verificadores
    return verificador_ingresado == verificador_calculado


def format_rut(rut_string):
    """
    Formatea un RUT chileno en el formato estándar: 12.345.678-9

    Args:
        rut_string (str): RUT a formatear. Puede contener puntos, guiones y espacios.
                         Ejemplos: '123456789', '12345678-9', '12.345.678-9'

    Returns:
        str: RUT formateado como '12.345.678-9', o cadena vacía si el RUT es inválido.

    Examples:
        >>> format_rut('123456785')
        '12.345.678-5'
        >>> format_rut('12345678-5')
        '12.345.678-5'
        >>> format_rut('12.345.678-5')
        '12.345.678-5'
    """
    if not rut_string:
        return ''

    # Normalizar: eliminar puntos, guiones y espacios
    rut_clean = re.sub(r'[.\-\s]', '', str(rut_string).upper())

    # Validar formato básico
    if len(rut_clean) < 2:
        return ''

    # Separar número y verificador
    rut_number = rut_clean[:-1]
    verificador = rut_clean[-1]

    # Validar que el número sea numérico
    if not rut_number.isdigit():
        return ''

    # Formatear número con puntos (separador de miles)
    rut_formateado = _formatear_numero_con_puntos(rut_number)

    # Retornar RUT formateado: 12.345.678-9
    return f"{rut_formateado}-{verificador}"


def _calcular_verificador(rut_number):
    """
    Calcula el dígito verificador de un RUT chileno usando el algoritmo módulo 11.

    Args:
        rut_number (str): Número de RUT sin verificador (solo dígitos)

    Returns:
        str: Dígito verificador calculado ('0'-'9' o 'K')

    Algorithm:
        1. Multiplicar cada dígito por la serie 2,3,4,5,6,7 (de derecha a izquierda, cíclico)
        2. Sumar todos los productos
        3. Calcular módulo 11
        4. Restar el resultado de 11
        5. Si es 11 retorna '0', si es 10 retorna 'K', sino retorna el dígito
    """
    # Serie multiplicadora: 2,3,4,5,6,7 (cíclica)
    serie = [2, 3, 4, 5, 6, 7]

    # Invertir el número para multiplicar de derecha a izquierda
    digitos = [int(d) for d in reversed(rut_number)]

    # Calcular suma de productos
    suma = 0
    for i, digito in enumerate(digitos):
        multiplicador = serie[i % len(serie)]
        suma += digito * multiplicador

    # Calcular verificador: 11 - (suma % 11)
    resto = suma % 11
    verificador = 11 - resto

    # Casos especiales
    if verificador == 11:
        return '0'
    elif verificador == 10:
        return 'K'
    else:
        return str(verificador)


def _formatear_numero_con_puntos(numero_str):
    """
    Formatea un número agregando puntos como separador de miles.

    Args:
        numero_str (str): Número como cadena (solo dígitos)

    Returns:
        str: Número formateado con puntos (ej: '12.345.678')

    Examples:
        >>> _formatear_numero_con_puntos('12345678')
        '12.345.678'
        >>> _formatear_numero_con_puntos('1234')
        '1.234'
        >>> _formatear_numero_con_puntos('123')
        '123'
    """
    # Invertir el número para agregar puntos de derecha a izquierda
    numero_invertido = numero_str[::-1]

    # Separar en grupos de 3 dígitos
    grupos = []
    for i in range(0, len(numero_invertido), 3):
        grupos.append(numero_invertido[i:i+3])

    # Unir grupos con puntos y revertir
    numero_formateado = '.'.join(grupos)[::-1]

    return numero_formateado
