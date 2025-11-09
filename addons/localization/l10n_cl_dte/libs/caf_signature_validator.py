# -*- coding: utf-8 -*-
"""
CAF Signature Validator - Enterprise Grade (Multi-Environment)
================================================================

Valida firma digital FRMA del SII en archivos CAF según Resolución Ex. SII N°11.

Características:
- Verificación criptográfica RSA SHA1
- Multi-environment: Staging (Maullin) / Production (Palena)
- Certificados oficiales SII dinámicos
- Cache de certificados SII
- Logging detallado para auditoría
- Manejo robusto de errores
- Testing exhaustivo

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
Date: 2025-11-02
Version: 2.0.0
Sprint: H10 (P1 High Priority) - Official SII Certificate Management
Previous: Gap Closure P0 - F-002
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
# MULTI-ENVIRONMENT SII CERTIFICATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════
#
# El SII Chile usa diferentes servidores según el ambiente:
# - STAGING (Certificación): Maullin (https://maullin.sii.cl)
# - PRODUCTION: Palena (https://palena.sii.cl)
#
# Cada ambiente tiene su propio certificado digital oficial.
#
# Configuración:
# - Environment se configura via: l10n_cl_dte.sii_environment
# - Valores permitidos: 'sandbox', 'testing', 'certification' (staging) | 'production'
# - Certificados se almacenan en: data/certificates/{staging|production}/
#
# Obtener certificados oficiales:
# - Maullin: https://maullin.sii.cl/cgi_rtc/RTC/RTCCertif.cgi
# - Palena: https://palena.sii.cl/cgi_rtc/RTC/RTCCertif.cgi
#
# Sprint: H10 (P1 High Priority) - Official SII Certificate Management
# ═══════════════════════════════════════════════════════════════════════════

import os
from pathlib import Path


def _get_sii_environment_from_odoo():
    """
    Obtiene el environment SII desde Odoo config parameter.

    Returns:
        str: 'staging' o 'production'

    Note:
        Requiere que Odoo esté inicializado. Si no está disponible,
        retorna el default del sistema operativo.
    """
    try:
        # Intentar obtener desde Odoo (si está disponible)
        from odoo import api, SUPERUSER_ID
        from odoo.modules.registry import Registry

        # Obtener registry (si Odoo está inicializado)
        try:
            registry = Registry.registries.get('odoo')
            if registry:
                with registry.cursor() as cr:
                    env = api.Environment(cr, SUPERUSER_ID, {})
                    env_param = env['ir.config_parameter'].sudo().get_param(
                        'l10n_cl_dte.sii_environment', 'sandbox'
                    )

                    # Mapeo: sandbox/testing/certification → staging | production → production
                    if env_param in ('sandbox', 'testing', 'certification'):
                        return 'staging'
                    elif env_param == 'production':
                        return 'production'
                    else:
                        _logger.warning(f"Environment '{env_param}' no reconocido, usando staging")
                        return 'staging'
        except Exception:
            pass  # Odoo no disponible, usar fallback

    except ImportError:
        pass  # Odoo no disponible, usar fallback

    # Fallback: Variable de entorno o default
    env_var = os.getenv('L10N_CL_SII_ENVIRONMENT', 'staging')
    if env_var in ('production', 'palena'):
        return 'production'
    else:
        return 'staging'


def _get_sii_certificate_content():
    """
    Obtiene contenido del certificado SII según environment configurado.

    Returns:
        str: Contenido PEM del certificado SII

    Raises:
        FileNotFoundError: Si no existe archivo certificado para el environment

    Environment Detection:
    1. Odoo config parameter: l10n_cl_dte.sii_environment
    2. Environment variable: L10N_CL_SII_ENVIRONMENT
    3. Default: staging (Maullin)

    Certificate Locations:
    - Staging: data/certificates/staging/sii_cert_maullin.pem
    - Production: data/certificates/production/sii_cert_palena.pem
    """
    environment = _get_sii_environment_from_odoo()

    # Determinar ruta certificado
    base_path = Path(__file__).parent.parent / 'data' / 'certificates'

    if environment == 'production':
        cert_path = base_path / 'production' / 'sii_cert_palena.pem'
        server_name = 'Palena (Producción)'
        download_url = 'https://palena.sii.cl/cgi_rtc/RTC/RTCCertif.cgi'
    else:
        cert_path = base_path / 'staging' / 'sii_cert_maullin.pem'
        server_name = 'Maullin (Certificación/Testing)'
        download_url = 'https://maullin.sii.cl/cgi_rtc/RTC/RTCCertif.cgi'

    # Leer certificado
    if not cert_path.exists():
        error_msg = f"""
═══════════════════════════════════════════════════════════════════════════
CERTIFICADO SII NO ENCONTRADO
═══════════════════════════════════════════════════════════════════════════

Environment Configurado: {environment}
Servidor SII: {server_name}
Archivo Esperado: {cert_path}

ACCIÓN REQUERIDA:

1. Descargue el certificado oficial del SII desde:
   {download_url}

2. Guarde el archivo como:
   {cert_path}

3. Verifique el certificado con:
   openssl x509 -in {cert_path} -text -noout

4. Reinicie Odoo

NOTA: Para cambiar de environment, configure el parámetro del sistema:
   Settings → Technical → Parameters → System Parameters
   Key: l10n_cl_dte.sii_environment
   Values: 'sandbox'|'testing'|'certification' (staging) | 'production'

═══════════════════════════════════════════════════════════════════════════
"""
        _logger.error(error_msg)
        raise FileNotFoundError(error_msg)

    # Leer y retornar contenido
    with open(cert_path, 'r', encoding='utf-8') as f:
        cert_content = f.read()

    _logger.info(f'[CAF_VALIDATOR] Certificado SII cargado: {server_name} ({cert_path})')
    return cert_content


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

        Multi-Environment Support:
        - Staging (Maullin): data/certificates/staging/sii_cert_maullin.pem
        - Production (Palena): data/certificates/production/sii_cert_palena.pem

        Returns:
            RSAPublicKey: Llave pública RSA del certificado SII

        Raises:
            ValueError: Si el certificado es inválido
            FileNotFoundError: Si no existe el certificado para el environment
        """
        try:
            # Obtener certificado según environment (staging/production)
            cert_pem_content = _get_sii_certificate_content()
            cert_pem = cert_pem_content.encode('utf-8')

            # Cargar certificado X.509
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            public_key = cert.public_key()

            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError('El certificado SII debe usar RSA')

            key_size = public_key.key_size
            _logger.info(f'[CAF_VALIDATOR] Certificado SII cargado: RSA {key_size} bits')

            # Verificar fecha de expiración (OPCIONAL en staging)
            environment = _get_sii_environment_from_odoo()
            if environment == 'production':
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc)
                if cert.not_valid_after_utc < now:
                    raise ValueError(
                        f'El certificado SII ha expirado: '
                        f'válido hasta {cert.not_valid_after_utc.isoformat()}'
                    )
                _logger.info(
                    f'[CAF_VALIDATOR] Certificado válido hasta: '
                    f'{cert.not_valid_after_utc.isoformat()}'
                )

            return public_key

        except FileNotFoundError:
            # Propagar error con instrucciones claras
            raise

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
