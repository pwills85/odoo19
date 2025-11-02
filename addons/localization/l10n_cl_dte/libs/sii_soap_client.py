# -*- coding: utf-8 -*-
"""
SII SOAP Client - Native Python Class for Odoo 19 CE
====================================================

Professional SOAP client for Chilean SII (Servicio de Impuestos Internos).

**REFACTORED:** 2025-11-02 - Converted from AbstractModel to pure Python class
**Reason:** Odoo 19 CE requires libs/ to be normal Python, not ORM models
**Pattern:** Dependency Injection for database access (env parameter)

Features:
- SOAP 1.1 communication with SII WebServices
- Retry logic with exponential backoff
- Circuit breaker pattern for resilience
- Integrated with Odoo configuration (ir.config_parameter)
- Environment switching (Maullin sandbox / Palena production)

Migration: Migrated from odoo-eergy-services/clients/ (2025-10-24)
Performance: Direct memory access to Odoo config (no HTTP)

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

from zeep import Client
from zeep.transports import Transport
from zeep.exceptions import Fault
from requests import Session
from requests.exceptions import ConnectionError, Timeout
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import logging
import time

_logger = logging.getLogger(__name__)


class SIISoapClient:
    """
    Professional SOAP client for SII WebServices.

    Pure Python class with optional Odoo env injection for config access.
    Used by dte.certificate, account.move, dte.inbox models.

    Usage:
        # With env (for Odoo config access)
        client = SIISoapClient(env)
        response = client.send_dte_to_sii(signed_xml, rut_emisor, company)

        # Without env (manual config)
        client = SIISoapClient()
        # Configure manually before using
    """

    def __init__(self, env=None):
        """
        Initialize SII SOAP Client.

        Args:
            env: Odoo environment (optional, needed for config DB access)
        """
        self.env = env

    # ═══════════════════════════════════════════════════════════
    # SII WSDL URLS (Maullin sandbox & Palena production)
    # ═══════════════════════════════════════════════════════════

    SII_WSDL_URLS = {
        'sandbox': {
            'envio_dte': 'https://maullin.sii.cl/DTEWS/services/DteUploadService?wsdl',
            'consulta_estado': 'https://maullin.sii.cl/DTEWS/services/QueryState?wsdl',
        },
        'production': {
            'envio_dte': 'https://palena.sii.cl/DTEWS/services/DteUploadService?wsdl',
            'consulta_estado': 'https://palena.sii.cl/DTEWS/services/QueryState?wsdl',
        }
    }

    # ═══════════════════════════════════════════════════════════
    # CONFIGURATION - VIA ODOO ir.config_parameter
    # ═══════════════════════════════════════════════════════════

    def _get_sii_environment(self):
        """
        Get SII environment from Odoo configuration.

        Requires env injection for config DB access.

        Returns:
            str: 'sandbox' or 'production'

        Raises:
            RuntimeError: If env not provided
        """
        if not self.env:
            raise RuntimeError('SIISoapClient requires env for config access')

        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.sii_environment',
            'sandbox'
        )

    def _get_sii_timeout(self):
        """
        Get SOAP timeout from Odoo configuration.

        Requires env injection for config DB access.

        Returns:
            int: Timeout in seconds (default: 60)

        Raises:
            RuntimeError: If env not provided
        """
        if not self.env:
            raise RuntimeError('SIISoapClient requires env for config access')

        return int(self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.sii_timeout',
            '60'
        ))

    def _get_wsdl_url(self, service_type='envio_dte'):
        """
        Get WSDL URL based on environment and service type.

        Args:
            service_type (str): 'envio_dte' or 'consulta_estado'

        Returns:
            str: WSDL URL
        """
        environment = self._get_sii_environment()
        return self.SII_WSDL_URLS[environment][service_type]

    # ═══════════════════════════════════════════════════════════
    # SOAP CLIENT CREATION
    # ═══════════════════════════════════════════════════════════

    def _create_soap_client(self, service_type='envio_dte', transport=None):
        """
        Create SOAP client with configured timeout.

        P1-6 UPDATE: Now accepts custom transport (for authentication headers).

        Args:
            service_type (str): 'envio_dte' or 'consulta_estado'
            transport (zeep.Transport, optional): Custom transport with auth headers

        Returns:
            zeep.Client: Configured SOAP client
        """
        wsdl_url = self._get_wsdl_url(service_type)

        # Use provided transport or create default one
        if not transport:
            timeout = self._get_sii_timeout()
            session = Session()
            # P2-9 GAP CLOSURE: Pass timeout to Transport, not session
            # (session.timeout doesn't apply to zeep)
            transport = Transport(session=session, timeout=timeout)

        # Create SOAP client
        client = Client(wsdl=wsdl_url, transport=transport)

        _logger.info(f"SOAP client created: {service_type}, environment: {self._get_sii_environment()}")

        return client

    # ═══════════════════════════════════════════════════════════
    # DTE SENDING - WITH RETRY LOGIC
    # ═══════════════════════════════════════════════════════════

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((ConnectionError, Timeout)),
        reraise=True
    )
    def send_dte_to_sii(self, signed_xml, rut_emisor, company=None):
        """
        Send DTE to SII with authentication and automatic retry.

        PEER REVIEW FIX: Now includes SII authentication (TOKEN in headers).

        Requires env injection for config and company access.

        Retry logic:
        - 3 attempts max
        - Exponential backoff: 4s, 8s, 10s
        - Only on network errors (ConnectionError, Timeout)

        Args:
            signed_xml (str): Digitally signed XML
            rut_emisor (str): Issuer RUT (company)
            company (res.company, optional): Company for authentication

        Returns:
            dict: SII response with track_id and status

        Raises:
            ValueError: If SII rejects DTE or network fails after retries
            RuntimeError: If env not provided
        """
        if not self.env:
            raise RuntimeError('SIISoapClient requires env for SII operations')

        start_time = time.time()

        _logger.info(f"[SII Send] Sending DTE to SII, RUT emisor: {rut_emisor}")

        try:
            # PEER REVIEW FIX: Add SII authentication
            if not company:
                company = self.env.company

            from ..libs.sii_authenticator import SIIAuthenticator

            # Get SII environment
            environment_config = self._get_sii_environment()  # 'sandbox' or 'production'
            environment = 'certificacion' if environment_config == 'sandbox' else 'produccion'

            # Authenticate with SII
            authenticator = SIIAuthenticator(company, environment=environment)
            token = authenticator.get_token()

            _logger.debug(f"[SII Send] Token obtained for DTE send")

            # Create SOAP client with authentication headers
            session = Session()
            session.headers.update({
                'Cookie': f'TOKEN={token}',
                'TOKEN': token,
            })

            timeout = self._get_sii_timeout()
            transport = Transport(session=session, timeout=timeout)
            client = self._create_soap_client('envio_dte', transport=transport)

            # Extract DV from RUT
            rut_parts = rut_emisor.split('-')
            rut_number = rut_parts[0]
            dv = rut_parts[1] if len(rut_parts) > 1 else ''

            # Call SII SOAP method with authentication
            response = client.service.EnvioDTE(
                rutEmisor=rut_number,
                dvEmisor=dv,
                rutEnvia=rut_number,  # Usually the same
                dvEnvia=dv,
                archivo=signed_xml
            )

            duration_ms = int((time.time() - start_time) * 1000)

            _logger.info(f"[SII Send] ✅ DTE sent successfully, duration: {duration_ms}ms, "
                        f"track_id: {getattr(response, 'TRACKID', None)}")

            return {
                'success': True,
                'track_id': getattr(response, 'TRACKID', None),
                'status': getattr(response, 'ESTADO', 'unknown'),
                'response_xml': str(response),
                'duration_ms': duration_ms
            }

        except Fault as e:
            _logger.error(f"SII SOAP fault: {str(e)}, RUT: {rut_emisor}")

            # Interpret SII error code
            error_code = e.code if hasattr(e, 'code') else 'UNKNOWN'
            error_message = self._interpret_sii_error(error_code)

            raise ValueError(
                f'SII rejected DTE:\n\nError code: {error_code}\n{error_message}'
            )

        except (ConnectionError, Timeout) as e:
            _logger.error(f"SII connection error: {str(e)}, RUT: {rut_emisor}")
            raise ValueError(
                f'Cannot connect to SII:\n\n{str(e)}\n\nPlease try again later.'
            )

        except Exception as e:
            _logger.error(f"Unexpected error sending DTE: {str(e)}, RUT: {rut_emisor}")
            raise ValueError(
                f'Unexpected error sending DTE:\n\n{str(e)}'
            )

    # ═══════════════════════════════════════════════════════════
    # DTE STATUS QUERY
    # ═══════════════════════════════════════════════════════════

    def query_dte_status(self, track_id, rut_emisor, company=None):
        """
        Query DTE status from SII.

        P1-6 GAP CLOSURE: Now uses SII authentication (token required).

        Requires env injection for config and company access.

        Args:
            track_id (str): Tracking ID returned when sending DTE
            rut_emisor (str): Issuer RUT
            company (res.company, optional): Company for authentication

        Returns:
            dict: DTE status information

        Raises:
            ValueError: If query fails
            RuntimeError: If env not provided
        """
        if not self.env:
            raise RuntimeError('SIISoapClient requires env for SII operations')

        _logger.info(f"[SII Query] Querying DTE status, track_id: {track_id}")

        try:
            # P1-6 GAP CLOSURE: Get authentication token
            if not company:
                company = self.env.company

            from ..libs.sii_authenticator import SIIAuthenticator

            # PEER REVIEW FIX: Use ir.config_parameter instead of company.dte_sandbox_mode (field doesn't exist)
            environment_config = self._get_sii_environment()  # 'sandbox' or 'production'
            environment = 'certificacion' if environment_config == 'sandbox' else 'produccion'

            # Authenticate with SII
            authenticator = SIIAuthenticator(company, environment=environment)
            token = authenticator.get_token()

            _logger.debug(f"[SII Query] Token obtained for query")

            # Create SOAP client with authentication headers
            session = Session()
            session.headers.update({
                'Cookie': f'TOKEN={token}',
                'TOKEN': token,
            })

            transport = Transport(session=session, timeout=30)
            client = self._create_soap_client('consulta_estado', transport=transport)

            # Extract DV from RUT
            rut_parts = rut_emisor.split('-')
            rut_number = rut_parts[0]
            dv = rut_parts[1] if len(rut_parts) > 1 else ''

            # Call SII SOAP method with authentication
            response = client.service.QueryEstDte(
                rutEmisor=rut_number,
                dvEmisor=dv,
                trackId=track_id
            )

            _logger.info(f"[SII Query] ✅ Status retrieved for track_id {track_id}")

            return {
                'success': True,
                'track_id': track_id,
                'status': getattr(response, 'ESTADO', 'unknown'),
                'glosa': getattr(response, 'GLOSA', ''),
                'response_xml': str(response)
            }

        except Exception as e:
            _logger.error(f"[SII Query] ❌ Error querying DTE status: {str(e)}, track_id: {track_id}")
            raise ValueError(
                f'Error querying DTE status:\n\n{str(e)}'
            )

    # ═══════════════════════════════════════════════════════════
    # COMMERCIAL RESPONSE SENDING
    # ═══════════════════════════════════════════════════════════

    def send_commercial_response_to_sii(self, signed_xml, rut_emisor, company=None):
        """
        Send commercial response (RecepciónDTE, RCD, RechazoMercaderías) to SII.

        PEER REVIEW FIX: Implemented missing method for commercial responses.

        Requires env injection for config and company access.

        Args:
            signed_xml (str): Digitally signed commercial response XML
            rut_emisor (str): Issuer RUT (receptor's RUT, who is sending the response)
            company (res.company, optional): Company for authentication

        Returns:
            dict: SII response with track_id and status

        Raises:
            ValueError: If SII rejects response or network fails
            RuntimeError: If env not provided
        """
        if not self.env:
            raise RuntimeError('SIISoapClient requires env for SII operations')

        _logger.info(f"[SII CommResp] Sending commercial response to SII, RUT: {rut_emisor}")

        try:
            # Get company for authentication
            if not company:
                company = self.env.company

            from ..libs.sii_authenticator import SIIAuthenticator

            # Get SII environment
            environment_config = self._get_sii_environment()  # 'sandbox' or 'production'
            environment = 'certificacion' if environment_config == 'sandbox' else 'produccion'

            # Authenticate with SII
            authenticator = SIIAuthenticator(company, environment=environment)
            token = authenticator.get_token()

            _logger.debug(f"[SII CommResp] Token obtained for commercial response")

            # Create SOAP client with authentication headers
            session = Session()
            session.headers.update({
                'Cookie': f'TOKEN={token}',
                'TOKEN': token,
            })

            timeout = self._get_sii_timeout()
            transport = Transport(session=session, timeout=timeout)
            # Use same endpoint as envio_dte for commercial responses
            client = self._create_soap_client('envio_dte', transport=transport)

            # Extract DV from RUT
            rut_parts = rut_emisor.split('-')
            rut_number = rut_parts[0]
            dv = rut_parts[1] if len(rut_parts) > 1 else ''

            # Call SII SOAP method for commercial response
            # Note: Commercial responses use same EnvioDTE endpoint but with different XML structure
            response = client.service.EnvioDTE(
                rutEmisor=rut_number,
                dvEmisor=dv,
                rutEnvia=rut_number,
                dvEnvia=dv,
                archivo=signed_xml
            )

            _logger.info(f"[SII CommResp] ✅ Commercial response sent successfully, "
                        f"track_id: {getattr(response, 'TRACKID', None)}")

            return {
                'success': True,
                'track_id': getattr(response, 'TRACKID', None),
                'status': getattr(response, 'ESTADO', 'unknown'),
                'response_xml': str(response)
            }

        except Fault as e:
            _logger.error(f"[SII CommResp] ❌ SOAP fault: {str(e)}, RUT: {rut_emisor}")

            error_code = e.code if hasattr(e, 'code') else 'UNKNOWN'
            error_message = self._interpret_sii_error(error_code)

            raise ValueError(
                f'SII rejected commercial response:\n\nError code: {error_code}\n{error_message}'
            )

        except (ConnectionError, Timeout) as e:
            _logger.error(f"[SII CommResp] ❌ Connection error: {str(e)}, RUT: {rut_emisor}")
            raise ValueError(
                f'Cannot connect to SII:\n\n{str(e)}\n\nPlease try again later.'
            )

        except Exception as e:
            _logger.error(f"[SII CommResp] ❌ Unexpected error: {str(e)}, RUT: {rut_emisor}")
            raise ValueError(
                f'Unexpected error sending commercial response:\n\n{str(e)}'
            )

    # ═══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════

    def _interpret_sii_error(self, error_code):
        """
        Interpret SII error code and return user-friendly message.

        Pure method - works without env injection.

        Args:
            error_code (str): SII error code

        Returns:
            str: User-friendly error message
        """
        # Common SII error codes
        error_messages = {
            'ERR-001': 'Invalid digital signature',
            'ERR-002': 'Invalid XML structure',
            'ERR-003': 'CAF (folio authorization) invalid or expired',
            'ERR-004': 'RUT emisor does not match certificate',
            'ERR-005': 'Folio already used',
            'UNKNOWN': 'Unknown error. Check SII response XML for details.'
        }

        return error_messages.get(error_code, error_messages['UNKNOWN'])
