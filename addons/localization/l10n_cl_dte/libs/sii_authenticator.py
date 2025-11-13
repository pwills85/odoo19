# -*- coding: utf-8 -*-
"""
SII Authenticator - Authentication flow for Chilean SII (Servicio de Impuestos Internos)

This module implements the complete authentication flow required by SII:
1. getSeed: Obtain seed (semilla) from SII
2. Sign seed with digital certificate
3. getToken: Exchange signed seed for authentication token
4. Token management (storage, expiry, renewal)

Author: Pedro Troncoso
Date: 2025-10-29
License: LGPL-3
"""

import base64
import hashlib
import logging
from datetime import datetime, timedelta
from lxml import etree
from zeep import Client
from zeep.transports import Transport
from requests import Session
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from .i18n import gettext as _
from .exceptions import DTEAuthenticationError as UserError
from .safe_xml_parser import fromstring_safe

_logger = logging.getLogger(__name__)

# SII WSDL URLs
SII_WSDL_URLS = {
    'certificacion': {
        'crm': 'https://maullin.sii.cl/DTEWS/CrSeed.jws?WSDL',
        'queryseed': 'https://maullin.sii.cl/DTEWS/QueryEstUp.jws?WSDL',
    },
    'produccion': {
        'crm': 'https://palena.sii.cl/DTEWS/CrSeed.jws?WSDL',
        'queryseed': 'https://palena.sii.cl/DTEWS/QueryEstUp.jws?WSDL',
    }
}


class SIIAuthenticator:
    """
    Handles authentication with Chilean SII web services.

    Authentication flow:
    1. getSeed() - Request seed from SII
    2. _sign_seed() - Sign seed with digital certificate
    3. getToken() - Exchange signed seed for token
    4. Token stored in memory with expiry (6 hours validity)
    """

    def __init__(self, company, environment='certificacion'):
        """
        Initialize authenticator

        Args:
            company: res.company record with certificate
            environment: 'certificacion' (sandbox) or 'produccion'
        """
        self.company = company
        self.environment = environment
        self.token = None
        self.token_expiry = None

        # Validate company has certificate
        if not company.dte_certificate_id:
            raise UserError(_(
                "Company %s does not have a digital certificate configured. "
                "Please go to Settings → DTE Configuration and upload a certificate."
            ) % company.name)

        # Setup SOAP client with timeout
        session = Session()
        transport = Transport(session=session, timeout=30)
        self.wsdl_url = SII_WSDL_URLS[environment]['crm']
        self.client = Client(self.wsdl_url, transport=transport)

        _logger.info(
            f"[SII Auth] Initialized for company {company.name}, "
            f"environment: {environment}"
        )

    def get_token(self, force_refresh=False):
        """
        Get valid authentication token, refreshing if necessary

        Args:
            force_refresh: Force token refresh even if not expired

        Returns:
            str: Valid SII token

        Raises:
            UserError: If authentication fails
        """
        # Check if we have valid token
        if not force_refresh and self._is_token_valid():
            _logger.debug(
                f"[SII Auth] Using cached token (expires {self.token_expiry})"
            )
            return self.token

        # Need to authenticate
        _logger.info("[SII Auth] Token expired or not present, authenticating...")

        try:
            # Step 1: Get seed
            seed = self._get_seed()

            # Step 2: Sign seed
            signed_seed = self._sign_seed(seed)

            # Step 3: Get token
            token = self._get_token(signed_seed)

            # Store token with expiry (6 hours validity per SII docs)
            self.token = token
            self.token_expiry = datetime.now() + timedelta(hours=6)

            _logger.info(
                f"[SII Auth] ✅ Authentication successful. "
                f"Token expires: {self.token_expiry}"
            )

            return self.token

        except Exception as e:
            _logger.error(f"[SII Auth] ❌ Authentication failed: {str(e)}")
            raise UserError(_(
                "Failed to authenticate with SII:\n%s\n\n"
                "Please verify:\n"
                "- Digital certificate is valid and not expired\n"
                "- SII services are available\n"
                "- Internet connection is working"
            ) % str(e))

    def _is_token_valid(self):
        """Check if current token is still valid"""
        if not self.token or not self.token_expiry:
            return False

        # Token expires in less than 5 minutes → consider invalid
        # (gives buffer for long-running operations)
        expires_soon = datetime.now() + timedelta(minutes=5)
        return self.token_expiry > expires_soon

    def _get_seed(self):
        """
        Step 1: Request seed from SII

        Returns:
            str: Seed value from SII

        Raises:
            UserError: If getSeed fails
        """
        _logger.debug("[SII Auth] Step 1: Requesting seed from SII...")

        try:
            # Call getSeed SOAP method
            response = self.client.service.getSeed()

            # Parse XML response
            # Expected format:
            # <SII:RESPUESTA>
            #   <SII:RESP_BODY>
            #     <SEMILLA>123456789</SEMILLA>
            #   </SII:RESP_BODY>
            #   <SII:RESP_HDR>
            #     <ESTADO>00</ESTADO>
            #     <GLOSA>SEMILLA GENERADA</GLOSA>
            #   </SII:RESP_HDR>
            # </SII:RESPUESTA>

            if isinstance(response, str):
                root = fromstring_safe(response)
            else:
                root = response

            # Extract status
            estado = root.find('.//ESTADO')
            if estado is None or estado.text != '00':
                glosa = root.find('.//GLOSA')
                error_msg = glosa.text if glosa is not None else 'Unknown error'
                raise UserError(_(
                    "SII rejected seed request.\n"
                    "Status: %s\n"
                    "Message: %s"
                ) % (estado.text if estado is not None else 'N/A', error_msg))

            # Extract seed
            semilla = root.find('.//SEMILLA')
            if semilla is None or not semilla.text:
                raise UserError(_("SII response does not contain valid seed"))

            seed = semilla.text.strip()

            _logger.debug(
                f"[SII Auth] ✅ Seed received from SII: {seed[:10]}..."
            )

            return seed

        except etree.XMLSyntaxError as e:
            _logger.error(f"[SII Auth] Failed to parse seed response: {e}")
            raise UserError(_(
                "Failed to parse SII response. "
                "SII services may be temporarily unavailable."
            ))
        except Exception as e:
            _logger.error(f"[SII Auth] getSeed failed: {e}")
            raise

    def _sign_seed(self, seed):
        """
        Step 2: Sign seed with digital certificate

        Args:
            seed: Seed string from SII

        Returns:
            str: Base64 encoded signed seed XML

        Raises:
            UserError: If signing fails
        """
        _logger.debug("[SII Auth] Step 2: Signing seed with certificate...")

        try:
            # Get certificate
            certificate = self.company.dte_certificate_id

            # Extract private key from PKCS#12
            private_key = certificate._get_private_key()

            # Create XML structure for seed
            # Format required by SII:
            # <getToken>
            #   <item>
            #     <Semilla>SEED_VALUE</Semilla>
            #   </item>
            # </getToken>

            seed_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<getToken>
  <item>
    <Semilla>{seed}</Semilla>
  </item>
</getToken>"""

            # Sign with RSA-SHA1 (required by SII)
            signature = private_key.sign(
                seed_xml.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA1()
            )

            # Base64 encode signature
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            # Create signed XML
            # Format:
            # <getToken>
            #   <item>
            #     <Semilla>SEED</Semilla>
            #   </item>
            #   <Signature>BASE64_SIGNATURE</Signature>
            # </getToken>

            signed_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<getToken>
  <item>
    <Semilla>{seed}</Semilla>
  </item>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>{self._calculate_digest(seed_xml)}</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>{signature_b64}</SignatureValue>
  </Signature>
</getToken>"""

            _logger.debug(
                f"[SII Auth] ✅ Seed signed successfully "
                f"(signature length: {len(signature_b64)})"
            )

            return signed_xml

        except Exception as e:
            _logger.error(f"[SII Auth] Failed to sign seed: {e}")
            raise UserError(_(
                "Failed to sign seed with certificate:\n%s\n\n"
                "Please verify the digital certificate is valid and contains a private key."
            ) % str(e))

    def _calculate_digest(self, data):
        """Calculate SHA1 digest for XML signature"""
        digest = hashlib.sha1(data.encode('utf-8')).digest()
        return base64.b64encode(digest).decode('utf-8')

    def _get_token(self, signed_seed):
        """
        Step 3: Exchange signed seed for authentication token

        Args:
            signed_seed: Signed seed XML string

        Returns:
            str: Authentication token

        Raises:
            UserError: If getToken fails
        """
        _logger.debug("[SII Auth] Step 3: Exchanging signed seed for token...")

        try:
            # Call getToken SOAP method
            response = self.client.service.getToken(signed_seed)

            # Parse XML response
            # Expected format:
            # <SII:RESPUESTA>
            #   <SII:RESP_BODY>
            #     <TOKEN>ABC123TOKEN456</TOKEN>
            #   </SII:RESP_BODY>
            #   <SII:RESP_HDR>
            #     <ESTADO>00</ESTADO>
            #     <GLOSA>TOKEN GENERADO</GLOSA>
            #   </SII:RESP_HDR>
            # </SII:RESPUESTA>

            if isinstance(response, str):
                root = fromstring_safe(response)
            else:
                root = response

            # Extract status
            estado = root.find('.//ESTADO')
            if estado is None or estado.text != '00':
                glosa = root.find('.//GLOSA')
                error_msg = glosa.text if glosa is not None else 'Unknown error'
                raise UserError(_(
                    "SII rejected token request.\n"
                    "Status: %s\n"
                    "Message: %s\n\n"
                    "This usually means:\n"
                    "- Digital certificate is invalid or expired\n"
                    "- Seed signature is incorrect\n"
                    "- Certificate is not authorized for this environment (%s)"
                ) % (
                    estado.text if estado is not None else 'N/A',
                    error_msg,
                    self.environment
                ))

            # Extract token
            token_elem = root.find('.//TOKEN')
            if token_elem is None or not token_elem.text:
                raise UserError(_("SII response does not contain valid token"))

            token = token_elem.text.strip()

            _logger.debug(
                f"[SII Auth] ✅ Token received from SII: {token[:20]}..."
            )

            return token

        except etree.XMLSyntaxError as e:
            _logger.error(f"[SII Auth] Failed to parse token response: {e}")
            raise UserError(_(
                "Failed to parse SII token response. "
                "SII services may be temporarily unavailable."
            ))
        except Exception as e:
            _logger.error(f"[SII Auth] getToken failed: {e}")
            raise

    def invalidate_token(self):
        """
        Invalidate current token (force re-authentication on next use)

        Useful when:
        - Token is suspected to be invalid
        - Switching environments
        - Certificate changed
        """
        _logger.info("[SII Auth] Token invalidated manually")
        self.token = None
        self.token_expiry = None

    def get_auth_headers(self):
        """
        Get HTTP headers with authentication token

        Returns:
            dict: Headers dict with Cookie/Token

        Usage:
            headers = authenticator.get_auth_headers()
            response = requests.post(url, headers=headers, data=xml)
        """
        token = self.get_token()

        # SII uses different auth methods depending on endpoint:
        # - Some use Cookie: TOKEN=xxx
        # - Others use custom header
        # We include both for maximum compatibility

        return {
            'Cookie': f'TOKEN={token}',
            'TOKEN': token,
            'Content-Type': 'text/xml; charset=utf-8',
        }

    def __str__(self):
        """String representation"""
        return (
            f"SIIAuthenticator("
            f"company={self.company.name}, "
            f"env={self.environment}, "
            f"token_valid={self._is_token_valid()})"
        )
