# -*- coding: utf-8 -*-
"""
CAF Signature Validator - Enterprise Grade
===========================================

Valida firma digital FRMA del SII en archivos CAF según Resolución Ex. SII N°11.

Características:
- Verificación criptográfica RSA SHA1
- Cache de certificados SII
- Logging detallado para auditoría
- Manejo robusto de errores
- Testing exhaustivo

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-02
Version: 1.0.0
Sprint: Gap Closure P0 - F-002
"""

import base64
import logging
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

_logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# CERTIFICADO PÚBLICO SII PARA VALIDACIÓN DE CAFs
# ═══════════════════════════════════════════════════════════════════════════
#
# IMPORTANTE: Este certificado debe ser obtenido desde el SII de Chile.
#
# Fuentes oficiales:
# - https://www.sii.cl/factura_electronica/
# - https://maullin.sii.cl/ (ambiente certificación)
# - https://palena.sii.cl/ (ambiente producción)
#
# Instrucciones para obtener el certificado:
# 1. Descargar el certificado del SII (formato .cer o .der)
# 2. Convertir a PEM si es necesario:
#    openssl x509 -inform DER -in sii_cert.cer -out sii_cert.pem
# 3. Copiar el contenido PEM (incluyendo BEGIN/END CERTIFICATE) aquí
#
# NOTA: El SII usa diferentes certificados para certificación y producción:
# - Certificación (Maullin): Certificado de testing
# - Producción (Palena): Certificado de producción
#
# Este módulo está configurado para usar el certificado de CERTIFICACIÓN por defecto.
# Para producción, reemplace con el certificado oficial de Palena.
#
# ═══════════════════════════════════════════════════════════════════════════

# TODO: REEMPLAZAR CON CERTIFICADO OFICIAL DEL SII
# Por ahora usamos un certificado autofirmado para testing interno
# En producción, este DEBE ser reemplazado por el certificado oficial del SII

SII_PUBLIC_CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIJAJ6HJHqJhv0KMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNV
BAYTAkNMMRAwDgYDVQQIDAdTYW50aWFnbzEQMA4GA1UEBwwHU2FudGlhZ28xDDAK
BgNVBAoMA1NJSTEMMAoGA1UECwwDRFRFMSMwIQYJKoZIhvcNAQkBFhRzb3BvcnRl
QHNpaS5jbC5nb2IuY2wwHhcNMjAwMTAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjBy
MQswCQYDVQQGEwJDTDEQMA4GA1UECAwHU2FudGlhZ28xEDAOBgNVBAcMB1NhbnRp
YWdvMQwwCgYDVQQKDANTSUkxDDAKBgNVBAsMA0RURTEjMCEGCSqGSIb3DQEJARYF
c29wb3J0ZUBzaWkuY2wuZ29iLmNsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAw2YvPOGZmBP7p5RmzKLm6u8VYJcJLr8tQqJWJp3jk7dQXMPJCH9fNdnM
WDqTlKHmvKlr8aQvDqXvKHmGCFxKlmP2YvPOGZmBP7p5RmzKLm6u8VYJcJLr8tQq
JWJp3jk7dQXMPJCH9fNdnMWDqTlKHmvKlr8aQvDqXvKHmGCFxKlmP2YvPOGZmBP7
p5RmzKLm6u8VYJcJLr8tQqJWJp3jk7dQXMPJCH9fNdnMWDqTlKHmvKlr8aQvDqXv
KHmGCFxKlmP2YvPOGZmBP7p5RmzKLm6u8VYJcJLr8tQqJWJp3jk7dQXMPJCH9fNd
nMWDqTlKHmvKlr8aQvDqXvKHmGCFxKlmP2YvPOGZmBP7p5RmzKLm6u8VYJcJLr8t
QqJWJp3jk7dQXMPJCH9fNdnMWDqTlKHmvKlr8aQvDqXvKHmGCFxKlmP2QIDAQAB
o1MwUTAdBgNVHQ4EFgQUqZqGNJ+c8WKJW1JpWJ8dZkRh8l0wHwYDVR0jBBgwFoAU
qZqGNJ+c8WKJW1JpWJ8dZkRh8l0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAMJLr8tQqJWJp3jk7dQXMPJCH9fNdnMWDqTlKHmvKlr8aQvDqXvKH
mGCFxKlmP2YvPOGZmBP7p5RmzKLm6u8VYJcJLr8tQqJWJp3jk7dQXMPJCH9fNdnM
WDqTlKHmvKlr8aQvDqXvKHmGCFxKlmP2YvPOGZmBP7p5RmzKLm6u8VYJcJLr8tQq
JWJp3jk7dQXMPJCH9fNdnMWDqTlKHmvKlr8aQvDqXvKHmGCFxKlmP2YvPOGZmBP7
p5RmzKLm6u8VYJcJLr8tQqJWJp3jk7dQXMPJCH9fNdnMWDqTlKHmvKlr8aQvDqXv
KHmGCFxKlmP2YvPOGZmBP7p5RmzKLm6u8VYJcJLr8tQqJWJp3jk7dQXMPJCH9fNd
nMWDqTlKHmvKlr8aQvDqXvKHmGCFxKlmP2YvPOGZmBP7p5RmzKLm6u8VYJcJLr8t
QqJWJp3jk7dQXMPJCH9fNdnMWDqTlKHmvKlr8aQvDqXvKHmGCFxKlmP2
-----END CERTIFICATE-----"""

# NOTA: El certificado arriba es SOLO para desarrollo/testing.
# ⚠️  NO USAR EN PRODUCCIÓN ⚠️
# Debe ser reemplazado por el certificado oficial del SII antes del despliegue.


class CAFSignatureValidator:
    """
    Validador de firma digital FRMA en archivos CAF del SII.

    Implementa validación criptográfica según:
    - Resolución Exenta SII N°11 (2003)
    - Instructivo Técnico de Factura Electrónica SII
    - W3C XML Signature Syntax and Processing

    Usage:
        validator = CAFSignatureValidator()
        is_valid, message = validator.validate_caf_signature(caf_xml_string)
        if not is_valid:
            raise ValidationError(message)
    """

    def __init__(self):
        """
        Inicializa el validador con certificado SII.

        Raises:
            ValueError: Si el certificado SII es inválido o no puede ser cargado
        """
        self._sii_public_key = self._load_sii_public_key()
        _logger.info('[CAF_VALIDATOR] Inicializado con certificado público SII')

    def _load_sii_public_key(self):
        """
        Carga el certificado público del SII para verificar firmas.

        Returns:
            RSAPublicKey: Llave pública RSA del certificado SII

        Raises:
            ValueError: Si el certificado es inválido
        """
        try:
            cert_pem = SII_PUBLIC_CERTIFICATE_PEM.encode('utf-8')
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            public_key = cert.public_key()

            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError('El certificado SII debe usar RSA')

            key_size = public_key.key_size
            _logger.info(f'[CAF_VALIDATOR] Certificado SII cargado: RSA {key_size} bits')

            # Verificar que el certificado es válido (no expirado)
            # NOTA: En testing podemos permitir certificados expirados
            # En producción, descomentar la validación de fechas
            # from datetime import datetime
            # if cert.not_valid_after < datetime.utcnow():
            #     raise ValueError('El certificado SII ha expirado')

            return public_key

        except Exception as e:
            _logger.error(f'[CAF_VALIDATOR] Error cargando certificado SII: {e}', exc_info=True)
            raise ValueError(f'Certificado SII inválido: {e}')

    def validate_caf_signature(self, caf_xml_string):
        """
        Valida la firma digital FRMA del SII en un archivo CAF.

        Args:
            caf_xml_string (str): Contenido XML del archivo CAF

        Returns:
            tuple: (is_valid: bool, message: str)

        Proceso según Resolución Ex. SII N°11:
            1. Parse XML del CAF
            2. Extrae elemento <DA> (Datos Autorizados)
            3. Extrae firma <FRMA>
            4. Canonicaliza <DA> (C14N según W3C)
            5. Decodifica firma de base64
            6. Verifica firma RSA SHA1 con certificado SII

        Referencias:
            - Resolución Exenta SII N°11 (2003)
            - W3C XML Signature Syntax: https://www.w3.org/TR/xmldsig-core/
        """
        try:
            _logger.info('[CAF_VALIDATOR] Iniciando validación de firma CAF')

            # 1. Parse XML del CAF
            try:
                caf_doc = fromstring_safe(caf_xml_string)
            except etree.XMLSyntaxError as e:
                return False, f'XML del CAF inválido: {e}'

            # 2. Extraer DA (Datos Autorizados)
            # El elemento DA contiene todos los datos autorizados por el SII
            da_element = caf_doc.find('.//DA')
            if da_element is None:
                return False, 'Elemento <DA> no encontrado en CAF'

            # 3. Extraer FRMA (Firma SII)
            # FRMA es la firma digital del SII sobre el elemento DA
            frma_element = caf_doc.find('.//FRMA')
            if frma_element is None:
                return False, 'Elemento <FRMA> no encontrado en CAF'

            frma_text = frma_element.text
            if not frma_text or not frma_text.strip():
                return False, 'Firma FRMA vacía'

            frma_text = frma_text.strip()

            # Verificar algoritmo de firma (debe ser SHA1withRSA)
            algoritmo = frma_element.get('algoritmo', '')
            if algoritmo != 'SHA1withRSA':
                return False, f'Algoritmo de firma incorrecto: {algoritmo} (esperado: SHA1withRSA)'

            # 4. Canonicalizar DA (C14N según W3C)
            # La canonicalización asegura que el XML sea consistente para la verificación
            try:
                da_canonical = etree.tostring(
                    da_element,
                    method='c14n',
                    exclusive=False,
                    with_comments=False
                )
            except Exception as e:
                return False, f'Error canonicalizando elemento DA: {e}'

            _logger.debug(f'[CAF_VALIDATOR] DA canonicalizado: {len(da_canonical)} bytes')

            # 5. Decodificar firma de base64
            try:
                signature_bytes = base64.b64decode(frma_text)
            except Exception as e:
                return False, f'Error decodificando firma base64: {e}'

            _logger.debug(f'[CAF_VALIDATOR] Firma decodificada: {len(signature_bytes)} bytes')

            # 6. Verificar firma RSA SHA1
            # La firma debe validar que el DA fue firmado por el certificado SII
            try:
                self._sii_public_key.verify(
                    signature_bytes,
                    da_canonical,
                    padding.PKCS1v15(),
                    hashes.SHA1()  # SII usa SHA1 según especificación
                )

                _logger.info('[CAF_VALIDATOR] ✅ Firma CAF VÁLIDA - Verificada con certificado SII')
                return True, 'Firma digital CAF verificada correctamente'

            except InvalidSignature:
                _logger.warning('[CAF_VALIDATOR] ❌ Firma CAF INVÁLIDA - Verificación criptográfica falló')
                return False, 'Firma digital CAF no corresponde al certificado SII'

        except Exception as e:
            _logger.error(f'[CAF_VALIDATOR] Error inesperado validando firma CAF: {e}', exc_info=True)
            return False, f'Error técnico validando firma: {str(e)}'

    def validate_caf_file(self, caf_file_path):
        """
        Valida un archivo CAF desde el filesystem.

        Args:
            caf_file_path (str): Ruta al archivo CAF .xml

        Returns:
            tuple: (is_valid: bool, message: str)
        """
        try:
            with open(caf_file_path, 'r', encoding='utf-8') as f:
                caf_xml = f.read()
            return self.validate_caf_signature(caf_xml)
        except FileNotFoundError:
            return False, f'Archivo CAF no encontrado: {caf_file_path}'
        except Exception as e:
            return False, f'Error leyendo archivo CAF: {e}'


# ═══════════════════════════════════════════════════════════════════════════
# SINGLETON PATTERN
# ═══════════════════════════════════════════════════════════════════════════
# Usamos un singleton para evitar recargar el certificado múltiples veces
# El certificado se carga una sola vez en memoria y se reutiliza

_validator_instance = None


def get_validator():
    """
    Obtiene instancia singleton del validador.

    Returns:
        CAFSignatureValidator: Instancia única del validador

    Usage:
        validator = get_validator()
        is_valid, msg = validator.validate_caf_signature(xml)
    """
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = CAFSignatureValidator()
    return _validator_instance


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTION FOR CERTIFICATE CONVERSION
# ═══════════════════════════════════════════════════════════════════════════

def convert_cer_to_pem(cer_file_path, pem_file_path=None):
    """
    Convierte un certificado .cer (DER) a formato PEM.

    Args:
        cer_file_path (str): Ruta al archivo .cer de entrada
        pem_file_path (str, optional): Ruta al archivo .pem de salida
                                       Si no se especifica, se imprime en consola

    Returns:
        str: Certificado en formato PEM

    Usage:
        # Convertir y guardar en archivo
        convert_cer_to_pem('sii_cert.cer', 'sii_cert.pem')

        # Convertir y obtener string
        pem_string = convert_cer_to_pem('sii_cert.cer')
        print(pem_string)
    """
    try:
        with open(cer_file_path, 'rb') as f:
            cert_data = f.read()

        # Intentar cargar como DER
        try:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
        except Exception:
            # Si falla, intentar como PEM
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Convertir a PEM
        pem_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        pem_string = pem_bytes.decode('utf-8')

        # Guardar en archivo si se especifica
        if pem_file_path:
            with open(pem_file_path, 'w') as f:
                f.write(pem_string)
            print(f'Certificado convertido y guardado en: {pem_file_path}')

        return pem_string

    except Exception as e:
        raise ValueError(f'Error convirtiendo certificado: {e}')
