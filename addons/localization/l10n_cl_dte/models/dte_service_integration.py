# -*- coding: utf-8 -*-
"""
DTE Service Integration
========================

Professional integration layer between Odoo and DTE Microservice.
Handles API calls, error handling, retries, and graceful degradation.

Architecture principles:
- Single responsibility: Only API communication
- Error resilience: Graceful handling of service unavailability
- User feedback: Clear error messages
- Logging: Comprehensive audit trail
- Timeout management: Prevent hanging operations
"""

from odoo import models, api, _
from odoo.exceptions import UserError
import requests
import logging
import base64
from datetime import datetime

_logger = logging.getLogger(__name__)


class DTEServiceIntegration(models.AbstractModel):
    """
    Abstract model for DTE Service integration.
    Mixin pattern for reusability across different models.
    """
    _name = 'dte.service.integration'
    _description = 'DTE Service Integration Layer'

    # ═══════════════════════════════════════════════════════════
    # CONFIGURATION
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _get_dte_service_url(self):
        """Get DTE Service URL from system parameters."""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_url',
            'http://odoo-eergy-services:8001'
        )

    @api.model
    def _get_dte_service_api_key(self):
        """Get DTE Service API key from system parameters."""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_api_key',
            ''
        )

    @api.model
    def _get_dte_service_timeout(self):
        """Get request timeout in seconds."""
        return int(self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_timeout',
            '60'
        ))

    @api.model
    def _get_request_headers(self):
        """Build request headers with API key."""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Odoo-19-l10n_cl_dte/1.0',
        }

        api_key = self._get_dte_service_api_key()
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'

        return headers

    # ═══════════════════════════════════════════════════════════
    # HEALTH CHECK
    # ═══════════════════════════════════════════════════════════

    @api.model
    def check_dte_service_health(self):
        """
        Check DTE Service health and availability.

        Returns:
            dict: Health status with details
        """
        try:
            base_url = self._get_dte_service_url()
            timeout = self._get_dte_service_timeout()

            response = requests.get(
                f"{base_url}/health",
                timeout=min(timeout, 10)  # Max 10s for health check
            )

            if response.status_code == 200:
                health_data = response.json()

                return {
                    'available': True,
                    'status': health_data.get('status'),
                    'sii_available': health_data.get('sii_available'),
                    'circuit_breakers': health_data.get('circuit_breakers', {}),
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'available': False,
                    'error': f'HTTP {response.status_code}',
                    'timestamp': datetime.now().isoformat()
                }

        except requests.exceptions.Timeout:
            _logger.warning("DTE Service health check timeout")
            return {
                'available': False,
                'error': 'Timeout',
                'timestamp': datetime.now().isoformat()
            }
        except requests.exceptions.ConnectionError:
            _logger.warning("DTE Service connection error")
            return {
                'available': False,
                'error': 'Connection error',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            _logger.error(f"DTE Service health check failed: {e}")
            return {
                'available': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    # ═══════════════════════════════════════════════════════════
    # DTE GENERATION
    # ═══════════════════════════════════════════════════════════

    @api.model
    def generate_and_send_dte(self, dte_data, certificate_data, environment='sandbox'):
        """
        Generate and send DTE to SII via DTE Service.

        Args:
            dte_data (dict): Invoice data structured for DTE
            certificate_data (dict): Certificate data (cert_file, password)
            environment (str): 'sandbox' or 'production'

        Returns:
            dict: Result from DTE Service with success status, track_id, XML, etc

        Raises:
            UserError: If DTE Service unavailable or request fails
        """
        try:
            base_url = self._get_dte_service_url()
            timeout = self._get_dte_service_timeout()
            headers = self._get_request_headers()

            # Prepare request payload
            payload = {
                'dte_type': dte_data['dte_type'],
                'invoice_data': dte_data,
                'certificate': certificate_data,
                'environment': environment
            }

            _logger.info(f"Sending DTE generation request: DTE {dte_data['dte_type']}, Folio {dte_data.get('folio', 'N/A')}")

            # Call DTE Service
            response = requests.post(
                f"{base_url}/api/dte/generate-and-send",
                json=payload,
                headers=headers,
                timeout=timeout
            )

            # Handle response
            if response.status_code == 200:
                result = response.json()

                _logger.info(f"DTE generation successful: Track ID {result.get('track_id', 'N/A')}")

                return {
                    'success': result.get('success', False),
                    'folio': result.get('folio'),
                    'track_id': result.get('track_id'),
                    'xml_b64': result.get('xml_b64'),
                    'qr_image_b64': result.get('qr_image_b64'),
                    'response_xml': result.get('response_xml'),
                    'error_message': result.get('error_message'),
                }

            elif response.status_code == 400:
                # Validation error
                error_detail = response.json().get('detail', 'Validation error')
                _logger.error(f"DTE validation error: {error_detail}")

                raise UserError(
                    _('DTE Validation Error:\n\n%s') % error_detail
                )

            elif response.status_code == 503:
                # Service unavailable
                _logger.error("DTE Service unavailable")

                raise UserError(
                    _('DTE Service is temporarily unavailable.\n\n'
                      'Please try again in a few moments or contact support.')
                )

            else:
                # Other error
                error_msg = response.text[:500]  # Limit error message length
                _logger.error(f"DTE generation failed: HTTP {response.status_code}, {error_msg}")

                raise UserError(
                    _('DTE Generation Failed:\n\n'
                      'HTTP %s: %s') % (response.status_code, error_msg)
                )

        except requests.exceptions.Timeout:
            _logger.error("DTE generation timeout")
            raise UserError(
                _('DTE generation request timed out.\n\n'
                  'The operation is taking longer than expected. '
                  'Please check DTE status later.')
            )

        except requests.exceptions.ConnectionError:
            _logger.error("Cannot connect to DTE Service")
            raise UserError(
                _('Cannot connect to DTE Service.\n\n'
                  'Please verify network connectivity or contact support.')
            )

        except UserError:
            raise

        except Exception as e:
            _logger.error(f"Unexpected error in DTE generation: {e}", exc_info=True)
            raise UserError(
                _('Unexpected error during DTE generation:\n\n%s') % str(e)
            )

    # ═══════════════════════════════════════════════════════════
    # DTE STATUS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def query_dte_status(self, track_id):
        """
        Query DTE status from SII via DTE Service.

        Args:
            track_id (str): SII track ID

        Returns:
            dict: Status information

        Raises:
            UserError: If query fails
        """
        try:
            base_url = self._get_dte_service_url()
            timeout = self._get_dte_service_timeout()
            headers = self._get_request_headers()

            response = requests.get(
                f"{base_url}/api/dte/status/{track_id}",
                headers=headers,
                timeout=min(timeout, 30)  # Max 30s for status query
            )

            if response.status_code == 200:
                return response.json()
            else:
                raise UserError(
                    _('Failed to query DTE status: HTTP %s') % response.status_code
                )

        except requests.exceptions.RequestException as e:
            _logger.error(f"DTE status query failed: {e}")
            raise UserError(
                _('Could not query DTE status:\n\n%s') % str(e)
            )

    # ═══════════════════════════════════════════════════════════
    # CONTINGENCY MODE
    # ═══════════════════════════════════════════════════════════

    @api.model
    def get_contingency_status(self):
        """
        Get contingency mode status from DTE Service.

        Returns:
            dict: Contingency status
        """
        try:
            base_url = self._get_dte_service_url()
            headers = self._get_request_headers()

            response = requests.get(
                f"{base_url}/api/v1/contingency/status",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('data', {})
            else:
                return {'enabled': False, 'error': 'Query failed'}

        except Exception as e:
            _logger.warning(f"Failed to get contingency status: {e}")
            return {'enabled': False, 'error': str(e)}

    @api.model
    def enable_contingency(self, reason='MANUAL', comment=None):
        """
        Enable contingency mode.

        Args:
            reason (str): Reason for enabling ('MANUAL', 'SII_UNAVAILABLE', etc)
            comment (str): Additional comment

        Returns:
            dict: Result
        """
        try:
            base_url = self._get_dte_service_url()
            headers = self._get_request_headers()

            payload = {
                'reason': reason,
                'comment': comment
            }

            response = requests.post(
                f"{base_url}/api/v1/contingency/enable",
                json=payload,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                return response.json()
            else:
                raise UserError(
                    _('Failed to enable contingency mode: %s') % response.text
                )

        except requests.exceptions.RequestException as e:
            _logger.error(f"Failed to enable contingency: {e}")
            raise UserError(
                _('Could not enable contingency mode:\n\n%s') % str(e)
            )

    # ═══════════════════════════════════════════════════════════
    # CERTIFICATES
    # ═══════════════════════════════════════════════════════════

    @api.model
    def encrypt_certificate(self, cert_data_b64, password):
        """
        Encrypt certificate using DTE Service.

        Args:
            cert_data_b64 (str): Certificate in base64
            password (str): Password for encryption

        Returns:
            dict: Encrypted certificate and salt
        """
        try:
            base_url = self._get_dte_service_url()
            headers = self._get_request_headers()

            payload = {
                'cert_data_b64': cert_data_b64,
                'password': password
            }

            response = requests.post(
                f"{base_url}/api/v1/certificates/encrypt",
                json=payload,
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                raise UserError(
                    _('Certificate encryption failed: %s') % response.text
                )

        except requests.exceptions.RequestException as e:
            _logger.error(f"Certificate encryption failed: {e}")
            raise UserError(
                _('Could not encrypt certificate:\n\n%s') % str(e)
            )

    @api.model
    def validate_certificate(self, cert_data_b64, password):
        """
        Validate certificate using DTE Service.

        Args:
            cert_data_b64 (str): Certificate in base64
            password (str): Certificate password

        Returns:
            dict: Validation result with certificate info
        """
        try:
            base_url = self._get_dte_service_url()
            headers = self._get_request_headers()

            payload = {
                'cert_data_b64': cert_data_b64,
                'password': password
            }

            response = requests.post(
                f"{base_url}/api/v1/certificates/validate",
                json=payload,
                headers=headers,
                timeout=15
            )

            if response.status_code == 200:
                return response.json()
            else:
                error_detail = response.json().get('detail', 'Validation failed')
                raise UserError(
                    _('Certificate validation failed:\n\n%s') % error_detail
                )

        except requests.exceptions.RequestException as e:
            _logger.error(f"Certificate validation failed: {e}")
            raise UserError(
                _('Could not validate certificate:\n\n%s') % str(e)
            )
