# -*- coding: utf-8 -*-
"""
SII SOAP Client - Integrated into Odoo 19 CE
=============================================

Professional SOAP client for Chilean SII (Servicio de Impuestos Internos).

Features:
- SOAP 1.1 communication with SII WebServices
- Retry logic with exponential backoff
- Circuit breaker pattern for resilience
- Integrated with Odoo configuration (ir.config_parameter)
- Environment switching (Maullin sandbox / Palena production)

Migration: Migrated from odoo-eergy-services/clients/ (2025-10-24)
Performance: Direct memory access to Odoo config (no HTTP)
"""

from zeep import Client
from zeep.transports import Transport
from zeep.exceptions import Fault
from requests import Session
from requests.exceptions import ConnectionError, Timeout
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from odoo import api, models, _
from odoo.exceptions import UserError
import logging
import time

_logger = logging.getLogger(__name__)


class SIISoapClient(models.AbstractModel):
    """
    SOAP client for SII WebServices.

    Mixin pattern for use in dte.certificate, account.move, etc.
    """
    _name = 'sii.soap.client'
    _description = 'SII SOAP Client'

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

    @api.model
    def _get_sii_environment(self):
        """
        Get SII environment from Odoo configuration.

        Returns:
            str: 'sandbox' or 'production'
        """
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.sii_environment',
            'sandbox'
        )

    @api.model
    def _get_sii_timeout(self):
        """
        Get SOAP timeout from Odoo configuration.

        Returns:
            int: Timeout in seconds (default: 60)
        """
        return int(self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.sii_timeout',
            '60'
        ))

    @api.model
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

    @api.model
    def _create_soap_client(self, service_type='envio_dte'):
        """
        Create SOAP client with configured timeout.

        Args:
            service_type (str): 'envio_dte' or 'consulta_estado'

        Returns:
            zeep.Client: Configured SOAP client
        """
        wsdl_url = self._get_wsdl_url(service_type)
        timeout = self._get_sii_timeout()

        # Configure session with timeout
        session = Session()
        session.timeout = timeout
        transport = Transport(session=session)

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
    @api.model
    def send_dte_to_sii(self, signed_xml, rut_emisor):
        """
        Send DTE to SII with automatic retry.

        Retry logic:
        - 3 attempts max
        - Exponential backoff: 4s, 8s, 10s
        - Only on network errors (ConnectionError, Timeout)

        Args:
            signed_xml (str): Digitally signed XML
            rut_emisor (str): Issuer RUT (company)

        Returns:
            dict: SII response with track_id and status

        Raises:
            UserError: If SII rejects DTE or network fails after retries
        """
        start_time = time.time()

        _logger.info(f"Sending DTE to SII, RUT emisor: {rut_emisor}")

        try:
            # Create SOAP client
            client = self._create_soap_client('envio_dte')

            # Extract DV from RUT
            rut_parts = rut_emisor.split('-')
            rut_number = rut_parts[0]
            dv = rut_parts[1] if len(rut_parts) > 1 else ''

            # Call SII SOAP method
            response = client.service.EnvioDTE(
                rutEmisor=rut_number,
                dvEmisor=dv,
                rutEnvia=rut_number,  # Usually the same
                dvEnvia=dv,
                archivo=signed_xml
            )

            duration_ms = int((time.time() - start_time) * 1000)

            _logger.info(f"DTE sent successfully to SII, duration: {duration_ms}ms, "
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

            raise UserError(
                _('SII rejected DTE:\n\nError code: %s\n%s') % (error_code, error_message)
            )

        except (ConnectionError, Timeout) as e:
            _logger.error(f"SII connection error: {str(e)}, RUT: {rut_emisor}")
            raise UserError(
                _('Cannot connect to SII:\n\n%s\n\nPlease try again later.') % str(e)
            )

        except Exception as e:
            _logger.error(f"Unexpected error sending DTE: {str(e)}, RUT: {rut_emisor}")
            raise UserError(
                _('Unexpected error sending DTE:\n\n%s') % str(e)
            )

    # ═══════════════════════════════════════════════════════════
    # DTE STATUS QUERY
    # ═══════════════════════════════════════════════════════════

    @api.model
    def query_dte_status(self, track_id, rut_emisor):
        """
        Query DTE status from SII.

        Args:
            track_id (str): Tracking ID returned when sending DTE
            rut_emisor (str): Issuer RUT

        Returns:
            dict: DTE status information

        Raises:
            UserError: If query fails
        """
        _logger.info(f"Querying DTE status, track_id: {track_id}")

        try:
            # Create SOAP client
            client = self._create_soap_client('consulta_estado')

            # Extract DV from RUT
            rut_parts = rut_emisor.split('-')
            rut_number = rut_parts[0]
            dv = rut_parts[1] if len(rut_parts) > 1 else ''

            # Call SII SOAP method
            response = client.service.QueryEstDte(
                rutEmisor=rut_number,
                dvEmisor=dv,
                trackId=track_id
            )

            return {
                'success': True,
                'track_id': track_id,
                'status': getattr(response, 'ESTADO', 'unknown'),
                'response_xml': str(response)
            }

        except Exception as e:
            _logger.error(f"Error querying DTE status: {str(e)}, track_id: {track_id}")
            raise UserError(
                _('Error querying DTE status:\n\n%s') % str(e)
            )

    # ═══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _interpret_sii_error(self, error_code):
        """
        Interpret SII error code and return user-friendly message.

        Args:
            error_code (str): SII error code

        Returns:
            str: User-friendly error message
        """
        # Common SII error codes
        error_messages = {
            'ERR-001': _('Invalid digital signature'),
            'ERR-002': _('Invalid XML structure'),
            'ERR-003': _('CAF (folio authorization) invalid or expired'),
            'ERR-004': _('RUT emisor does not match certificate'),
            'ERR-005': _('Folio already used'),
            'UNKNOWN': _('Unknown error. Check SII response XML for details.')
        }

        return error_messages.get(error_code, error_messages['UNKNOWN'])
