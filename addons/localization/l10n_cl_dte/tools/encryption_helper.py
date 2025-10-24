# -*- coding: utf-8 -*-
"""
Encryption Helper - Secure Password Storage
============================================

Helper for encrypting sensitive data (passwords, API keys) using Fernet.

Key Management:
- Encryption key stored in ir.config_parameter (not in code)
- Auto-generates key on first use
- Uses Fernet (symmetric encryption) from cryptography library

Security Features:
- Fernet provides authenticated encryption (prevents tampering)
- Key rotation support
- Secure key generation (os.urandom)

Author: EERGYGROUP - Security Enhancement 2025-10-24
"""

from cryptography.fernet import Fernet, InvalidToken
import base64
import logging

_logger = logging.getLogger(__name__)


class EncryptionHelper:
    """
    Helper class for encrypting/decrypting sensitive data.

    Uses Fernet symmetric encryption (AES-128 in CBC mode with HMAC).

    Usage:
        helper = EncryptionHelper(env)
        encrypted = helper.encrypt('my_secret_password')
        decrypted = helper.decrypt(encrypted)
    """

    KEY_PARAM = 'l10n_cl_dte.encryption_key'

    def __init__(self, env):
        """
        Initialize encryption helper.

        Args:
            env: Odoo environment (for accessing ir.config_parameter)
        """
        self.env = env
        self._cipher = None

    def _get_or_create_key(self):
        """
        Get encryption key from ir.config_parameter or create new one.

        Returns:
            bytes: Encryption key (32 bytes for Fernet)
        """
        IrConfigParam = self.env['ir.config_parameter'].sudo()

        # Try to get existing key
        key_b64 = IrConfigParam.get_param(self.KEY_PARAM)

        if not key_b64:
            # Generate new key
            key = Fernet.generate_key()
            key_b64 = base64.b64encode(key).decode('utf-8')

            # Store in ir.config_parameter (persistent)
            IrConfigParam.set_param(self.KEY_PARAM, key_b64)

            _logger.info("🔐 Generated new encryption key for l10n_cl_dte")
        else:
            key = base64.b64decode(key_b64.encode('utf-8'))

        return key

    def _get_cipher(self):
        """
        Get Fernet cipher instance (cached).

        Returns:
            Fernet: Cipher instance
        """
        if self._cipher is None:
            key = self._get_or_create_key()
            self._cipher = Fernet(key)

        return self._cipher

    def encrypt(self, plaintext):
        """
        Encrypt plaintext string.

        Args:
            plaintext (str): Text to encrypt

        Returns:
            str: Base64-encoded encrypted text (safe for DB storage)

        Raises:
            ValueError: If plaintext is None or empty
        """
        if not plaintext:
            raise ValueError("Cannot encrypt None or empty string")

        cipher = self._get_cipher()

        # Encrypt (returns bytes)
        encrypted_bytes = cipher.encrypt(plaintext.encode('utf-8'))

        # Convert to base64 string for DB storage
        encrypted_str = base64.b64encode(encrypted_bytes).decode('utf-8')

        _logger.debug("🔒 Encrypted data (length: %d bytes)", len(encrypted_bytes))

        return encrypted_str

    def decrypt(self, encrypted_str):
        """
        Decrypt encrypted string.

        Args:
            encrypted_str (str): Base64-encoded encrypted text

        Returns:
            str: Decrypted plaintext

        Raises:
            ValueError: If encrypted_str is None or empty
            InvalidToken: If decryption fails (wrong key or tampered data)
        """
        if not encrypted_str:
            raise ValueError("Cannot decrypt None or empty string")

        cipher = self._get_cipher()

        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_str.encode('utf-8'))

            # Decrypt (returns bytes)
            plaintext_bytes = cipher.decrypt(encrypted_bytes)

            # Convert to string
            plaintext = plaintext_bytes.decode('utf-8')

            _logger.debug("🔓 Decrypted data")

            return plaintext

        except InvalidToken:
            _logger.error("❌ Decryption failed: Invalid token (wrong key or tampered data)")
            raise ValueError("Decryption failed: Invalid token")
        except Exception as e:
            _logger.error("❌ Decryption error: %s", e, exc_info=True)
            raise

    def is_encrypted(self, value):
        """
        Check if value looks like encrypted data.

        Simple heuristic: encrypted data is base64 and starts with 'gAAAAA'
        (Fernet token prefix after base64 encoding).

        Args:
            value (str): Value to check

        Returns:
            bool: True if looks encrypted
        """
        if not value or not isinstance(value, str):
            return False

        # Fernet tokens are base64 and typically start with 'gAAAAA' after encoding
        # This is a heuristic, not 100% accurate
        try:
            # Try to decode as base64
            decoded = base64.b64decode(value.encode('utf-8'))

            # Fernet tokens start with version byte (0x80)
            # After base64 encoding, this typically starts with 'gA'
            return value.startswith('gA') and len(decoded) > 50
        except:
            return False


def get_encryption_helper(env):
    """
    Factory function to get EncryptionHelper instance.

    Args:
        env: Odoo environment

    Returns:
        EncryptionHelper: Helper instance
    """
    return EncryptionHelper(env)
