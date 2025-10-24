"""
Certificate Encryption with PBKDF2
===================================

Encriptación robusta de certificados digitales usando PBKDF2-SHA256.
Protege certificados .p12 almacenados en base de datos.

Based on Odoo 18: l10n_cl_fe/models/certificate_encryption.py

Security standards:
- PBKDF2-SHA256 (NIST approved)
- 100,000 iterations (OWASP recommendation 2023)
- 32-byte salt (256 bits)
- AES-256-CBC encryption
- HMAC authentication
"""

import os
import logging
import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac as crypto_hmac
import struct

logger = logging.getLogger(__name__)


class CertificateEncryption:
    """
    Encriptación de certificados digitales con PBKDF2.

    Features:
    - PBKDF2-SHA256 key derivation
    - 100,000 iterations (OWASP 2023)
    - AES-256-CBC encryption
    - HMAC-SHA256 authentication
    - Salts únicos por certificado
    - Versión de formato para compatibilidad futura
    """

    # Configuración de seguridad
    PBKDF2_ITERATIONS = 100000      # OWASP recommendation 2023
    SALT_SIZE = 32                  # 256 bits
    KEY_SIZE = 32                   # 256 bits (AES-256)
    IV_SIZE = 16                    # 128 bits (AES block size)
    HMAC_KEY_SIZE = 32              # 256 bits
    FORMAT_VERSION = 1              # Para compatibilidad futura

    def __init__(self):
        """Inicializa certificate encryption."""
        self.backend = default_backend()
        logger.info("Certificate encryption initialized (PBKDF2-SHA256, 100k iterations)")

    def encrypt_certificate(
        self,
        cert_data: bytes,
        password: str
    ) -> Tuple[bytes, str]:
        """
        Encripta certificado con PBKDF2 + AES-256-CBC.

        Args:
            cert_data: Datos del certificado (.p12 binary)
            password: Password para derivar clave

        Returns:
            Tuple (encrypted_data, salt_b64)
                - encrypted_data: Certificado encriptado (incluye IV + HMAC)
                - salt_b64: Salt en base64 (para almacenar por separado)

        Format del encrypted_data:
            [version:1byte][iv:16bytes][encrypted_cert:N bytes][hmac:32bytes]
        """
        try:
            # 1. Generar salt aleatorio
            salt = os.urandom(self.SALT_SIZE)

            # 2. Derivar claves (encryption + HMAC) usando PBKDF2
            encryption_key, hmac_key = self._derive_keys(password, salt)

            # 3. Generar IV aleatorio para AES-CBC
            iv = os.urandom(self.IV_SIZE)

            # 4. Encriptar certificado con AES-256-CBC
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()

            # Padding PKCS7 (AES requiere múltiplos de 16 bytes)
            padded_data = self._pkcs7_pad(cert_data)
            encrypted_cert = encryptor.update(padded_data) + encryptor.finalize()

            # 5. Calcular HMAC para autenticación
            # HMAC cubre: version + iv + encrypted_cert
            version_byte = struct.pack('B', self.FORMAT_VERSION)
            data_to_authenticate = version_byte + iv + encrypted_cert

            h = crypto_hmac.HMAC(hmac_key, hashes.SHA256(), backend=self.backend)
            h.update(data_to_authenticate)
            hmac_digest = h.finalize()

            # 6. Ensamblar formato final
            encrypted_data = version_byte + iv + encrypted_cert + hmac_digest

            # 7. Convertir salt a base64 para almacenamiento
            salt_b64 = base64.b64encode(salt).decode('ascii')

            logger.info(
                "certificate_encrypted",
                cert_size_bytes=len(cert_data),
                encrypted_size_bytes=len(encrypted_data)
            )

            return encrypted_data, salt_b64

        except Exception as e:
            logger.error(f"Failed to encrypt certificate: {e}")
            raise EncryptionError(f"Encryption failed: {str(e)}")

    def decrypt_certificate(
        self,
        encrypted_data: bytes,
        password: str,
        salt_b64: str
    ) -> bytes:
        """
        Desencripta certificado.

        Args:
            encrypted_data: Datos encriptados (incluye version + IV + HMAC)
            password: Password para derivar clave
            salt_b64: Salt en base64

        Returns:
            Certificado desencriptado (bytes)

        Raises:
            EncryptionError: Si falla la desencriptación o autenticación
        """
        try:
            # 1. Decodificar salt
            salt = base64.b64decode(salt_b64)

            # 2. Derivar claves usando mismo password y salt
            encryption_key, hmac_key = self._derive_keys(password, salt)

            # 3. Parsear encrypted_data
            # Format: [version:1][iv:16][encrypted:N][hmac:32]
            if len(encrypted_data) < (1 + self.IV_SIZE + self.HMAC_KEY_SIZE):
                raise EncryptionError("Invalid encrypted data format (too short)")

            version = struct.unpack('B', encrypted_data[0:1])[0]
            iv = encrypted_data[1:1 + self.IV_SIZE]
            encrypted_cert = encrypted_data[1 + self.IV_SIZE:-self.HMAC_KEY_SIZE]
            stored_hmac = encrypted_data[-self.HMAC_KEY_SIZE:]

            # 4. Verificar versión
            if version != self.FORMAT_VERSION:
                raise EncryptionError(
                    f"Unsupported format version: {version} (expected {self.FORMAT_VERSION})"
                )

            # 5. Verificar HMAC (autenticación)
            data_to_authenticate = encrypted_data[:-self.HMAC_KEY_SIZE]

            h = crypto_hmac.HMAC(hmac_key, hashes.SHA256(), backend=self.backend)
            h.update(data_to_authenticate)

            try:
                h.verify(stored_hmac)
            except Exception:
                raise EncryptionError("HMAC verification failed (wrong password or tampered data)")

            # 6. Desencriptar con AES-256-CBC
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()

            padded_data = decryptor.update(encrypted_cert) + decryptor.finalize()

            # 7. Remover padding PKCS7
            cert_data = self._pkcs7_unpad(padded_data)

            logger.info(
                "certificate_decrypted",
                cert_size_bytes=len(cert_data)
            )

            return cert_data

        except EncryptionError:
            raise
        except Exception as e:
            logger.error(f"Failed to decrypt certificate: {e}")
            raise EncryptionError(f"Decryption failed: {str(e)}")

    def _derive_keys(self, password: str, salt: bytes) -> Tuple[bytes, bytes]:
        """
        Deriva dos claves (encryption + HMAC) usando PBKDF2.

        Args:
            password: Password del usuario
            salt: Salt único

        Returns:
            Tuple (encryption_key, hmac_key)
        """
        # Convertir password a bytes
        password_bytes = password.encode('utf-8')

        # Derivar 64 bytes totales (32 para AES + 32 para HMAC)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE + self.HMAC_KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=self.backend
        )

        derived_key = kdf.derive(password_bytes)

        # Split en dos claves
        encryption_key = derived_key[:self.KEY_SIZE]
        hmac_key = derived_key[self.KEY_SIZE:]

        return encryption_key, hmac_key

    def _pkcs7_pad(self, data: bytes) -> bytes:
        """
        Aplica padding PKCS7.

        Args:
            data: Datos a hacer padding

        Returns:
            Datos con padding
        """
        block_size = 16  # AES block size
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _pkcs7_unpad(self, padded_data: bytes) -> bytes:
        """
        Remueve padding PKCS7.

        Args:
            padded_data: Datos con padding

        Returns:
            Datos sin padding

        Raises:
            EncryptionError: Si padding es inválido
        """
        if len(padded_data) == 0:
            raise EncryptionError("Cannot unpad empty data")

        padding_length = padded_data[-1]

        # Validar padding
        if padding_length < 1 or padding_length > 16:
            raise EncryptionError("Invalid PKCS7 padding")

        # Verificar que todos los bytes de padding sean iguales
        padding = padded_data[-padding_length:]
        if not all(b == padding_length for b in padding):
            raise EncryptionError("Invalid PKCS7 padding bytes")

        return padded_data[:-padding_length]

    def change_password(
        self,
        encrypted_data: bytes,
        old_password: str,
        new_password: str,
        salt_b64: str
    ) -> Tuple[bytes, str]:
        """
        Cambia password de un certificado encriptado.

        Args:
            encrypted_data: Certificado encriptado con old_password
            old_password: Password actual
            new_password: Nuevo password
            salt_b64: Salt actual

        Returns:
            Tuple (new_encrypted_data, new_salt_b64)

        Raises:
            EncryptionError: Si old_password es incorrecto
        """
        try:
            # 1. Desencriptar con old_password
            cert_data = self.decrypt_certificate(encrypted_data, old_password, salt_b64)

            # 2. Re-encriptar con new_password (genera nuevo salt)
            new_encrypted_data, new_salt_b64 = self.encrypt_certificate(cert_data, new_password)

            logger.info("certificate_password_changed")

            return new_encrypted_data, new_salt_b64

        except EncryptionError as e:
            logger.error(f"Failed to change password: {e}")
            raise


class EncryptionError(Exception):
    """Excepción para errores de encriptación."""
    pass


# Singleton instance
_certificate_encryption = None


def get_certificate_encryption() -> CertificateEncryption:
    """Obtiene certificate encryption singleton."""
    global _certificate_encryption

    if _certificate_encryption is None:
        _certificate_encryption = CertificateEncryption()

    return _certificate_encryption
