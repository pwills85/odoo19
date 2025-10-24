"""
Certificate Management Routes
==============================

FastAPI endpoints para gestión de certificados digitales.

Based on Odoo 18: l10n_cl_fe/controllers/certificates.py
"""

from fastapi import APIRouter, HTTPException, status, UploadFile, File
from pydantic import BaseModel
from typing import Optional
import logging
import base64

from security.certificate_encryption import get_certificate_encryption, EncryptionError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/certificates", tags=["Certificates"])


# ═══════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════

class EncryptCertificateRequest(BaseModel):
    """Request para encriptar certificado."""
    cert_data_b64: str  # Certificado en base64
    password: str       # Password para encriptar


class DecryptCertificateRequest(BaseModel):
    """Request para desencriptar certificado."""
    encrypted_data_b64: str  # Certificado encriptado en base64
    password: str            # Password para desencriptar
    salt_b64: str           # Salt en base64


class ChangePasswordRequest(BaseModel):
    """Request para cambiar password."""
    encrypted_data_b64: str
    old_password: str
    new_password: str
    salt_b64: str


class ValidateCertificateRequest(BaseModel):
    """Request para validar certificado .p12."""
    cert_data_b64: str
    password: str


# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

@router.post("/encrypt")
async def encrypt_certificate(request: EncryptCertificateRequest):
    """
    Encripta certificado digital con PBKDF2 + AES-256.

    Args:
        request: Certificado y password

    Returns:
        Certificado encriptado y salt
    """
    try:
        encryption = get_certificate_encryption()

        # Decodificar certificado desde base64
        cert_data = base64.b64decode(request.cert_data_b64)

        # Encriptar
        encrypted_data, salt_b64 = encryption.encrypt_certificate(
            cert_data=cert_data,
            password=request.password
        )

        # Convertir a base64 para retorno
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode('ascii')

        return {
            'success': True,
            'encrypted_data_b64': encrypted_data_b64,
            'salt_b64': salt_b64,
            'format_version': encryption.FORMAT_VERSION,
            'iterations': encryption.PBKDF2_ITERATIONS
        }

    except Exception as e:
        logger.error(f"Failed to encrypt certificate: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption failed: {str(e)}"
        )


@router.post("/decrypt")
async def decrypt_certificate(request: DecryptCertificateRequest):
    """
    Desencripta certificado digital.

    Args:
        request: Certificado encriptado, password y salt

    Returns:
        Certificado desencriptado
    """
    try:
        encryption = get_certificate_encryption()

        # Decodificar encrypted_data desde base64
        encrypted_data = base64.b64decode(request.encrypted_data_b64)

        # Desencriptar
        cert_data = encryption.decrypt_certificate(
            encrypted_data=encrypted_data,
            password=request.password,
            salt_b64=request.salt_b64
        )

        # Convertir a base64 para retorno
        cert_data_b64 = base64.b64encode(cert_data).decode('ascii')

        return {
            'success': True,
            'cert_data_b64': cert_data_b64
        }

    except EncryptionError as e:
        logger.error(f"Decryption failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to decrypt certificate: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption failed: {str(e)}"
        )


@router.post("/change_password")
async def change_certificate_password(request: ChangePasswordRequest):
    """
    Cambia password de certificado encriptado.

    Args:
        request: Certificado, passwords y salt

    Returns:
        Certificado re-encriptado con nuevo password
    """
    try:
        encryption = get_certificate_encryption()

        # Decodificar encrypted_data
        encrypted_data = base64.b64decode(request.encrypted_data_b64)

        # Cambiar password
        new_encrypted_data, new_salt_b64 = encryption.change_password(
            encrypted_data=encrypted_data,
            old_password=request.old_password,
            new_password=request.new_password,
            salt_b64=request.salt_b64
        )

        # Convertir a base64
        new_encrypted_data_b64 = base64.b64encode(new_encrypted_data).decode('ascii')

        return {
            'success': True,
            'encrypted_data_b64': new_encrypted_data_b64,
            'salt_b64': new_salt_b64
        }

    except EncryptionError as e:
        logger.error(f"Password change failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to change password: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Password change failed: {str(e)}"
        )


@router.post("/validate")
async def validate_certificate(request: ValidateCertificateRequest):
    """
    Valida certificado .p12 (verifica que se puede abrir con password).

    Args:
        request: Certificado y password

    Returns:
        Información del certificado si es válido
    """
    try:
        from OpenSSL import crypto

        # Decodificar certificado
        cert_data = base64.b64decode(request.cert_data_b64)

        # Intentar cargar PKCS#12
        p12 = crypto.load_pkcs12(cert_data, request.password.encode())

        # Extraer información
        certificate = p12.get_certificate()
        subject = certificate.get_subject()
        issuer = certificate.get_issuer()

        # Extraer RUT del subject (CN generalmente contiene el RUT)
        cn = subject.CN if hasattr(subject, 'CN') else None
        rut = None
        if cn:
            # Intentar extraer RUT del CN (formato común: "RUT 12345678-9")
            import re
            rut_match = re.search(r'(\d{7,8}-[\dkK])', cn)
            if rut_match:
                rut = rut_match.group(1)

        # Validar fechas
        from datetime import datetime
        not_before = datetime.strptime(certificate.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
        not_after = datetime.strptime(certificate.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
        now = datetime.utcnow()

        is_valid_date = not_before <= now <= not_after

        # Extraer OID para detectar clase de certificado (2 o 3)
        # OID 2.16.152.1.2.2.1 = Certificado Clase 2
        # OID 2.16.152.1.2.3.1 = Certificado Clase 3
        cert_class = None
        extensions = [certificate.get_extension(i) for i in range(certificate.get_extension_count())]
        for ext in extensions:
            if 'certificatePolicies' in str(ext.get_short_name(), 'utf-8'):
                data = str(ext)
                if '2.16.152.1.2.2.1' in data:
                    cert_class = 2
                elif '2.16.152.1.2.3.1' in data:
                    cert_class = 3

        return {
            'success': True,
            'valid': True,
            'info': {
                'subject_cn': cn,
                'rut': rut,
                'issuer_cn': issuer.CN if hasattr(issuer, 'CN') else None,
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'is_valid_date': is_valid_date,
                'cert_class': cert_class,
                'serial_number': str(certificate.get_serial_number())
            }
        }

    except crypto.Error as e:
        logger.error(f"Invalid certificate or password: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid certificate or wrong password"
        )
    except Exception as e:
        logger.error(f"Certificate validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation failed: {str(e)}"
        )


@router.post("/upload")
async def upload_certificate(
    file: UploadFile = File(...),
    password: str = None
):
    """
    Upload y validación de certificado .p12.

    Args:
        file: Archivo .p12
        password: Password del certificado (opcional para validación)

    Returns:
        Certificado en base64 y validación si se provee password
    """
    try:
        # Leer contenido del archivo
        cert_data = await file.read()

        # Convertir a base64
        cert_data_b64 = base64.b64encode(cert_data).decode('ascii')

        result = {
            'success': True,
            'filename': file.filename,
            'size_bytes': len(cert_data),
            'cert_data_b64': cert_data_b64
        }

        # Si se provee password, validar certificado
        if password:
            validation_request = ValidateCertificateRequest(
                cert_data_b64=cert_data_b64,
                password=password
            )
            validation_result = await validate_certificate(validation_request)
            result['validation'] = validation_result

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Certificate upload failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {str(e)}"
        )
