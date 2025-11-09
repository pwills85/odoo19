"""
SII Client Wrapper with Circuit Breaker
========================================

Wrapper del SII SOAP Client que integra Circuit Breaker pattern.
Protege llamadas al SII evitando saturación durante caídas.

Based on Odoo 18: l10n_cl_fe/models/sii_client_wrapper.py
"""

import logging
from typing import Dict, Optional
from clients.sii_soap_client import SIISoapClient
from resilience.circuit_breaker import (
    get_circuit_breaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState
)

logger = logging.getLogger(__name__)


class SIIClientWrapper:
    """
    Wrapper del SII SOAP Client con Circuit Breaker protection.

    Features:
    - Circuit breaker por operación SII
    - Fail-fast cuando SII no disponible
    - Automatic recovery attempts
    - Fallback to queue en caso de circuit OPEN
    """

    def __init__(
        self,
        sii_client: SIISoapClient,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None
    ):
        """
        Inicializa wrapper.

        Args:
            sii_client: Cliente SII SOAP
            circuit_breaker_config: Configuración del circuit breaker (opcional)
        """
        self.sii_client = sii_client
        self.circuit_config = circuit_breaker_config or CircuitBreakerConfig(
            failure_threshold=5,      # 5 fallos antes de abrir
            success_threshold=2,      # 2 éxitos para cerrar
            timeout_seconds=60,       # 60s antes de probar recovery
            half_open_max_calls=1     # 1 llamada de prueba en half-open
        )

        # Circuit breakers por operación
        self.cb_send_dte = get_circuit_breaker('sii_send_dte', self.circuit_config)
        self.cb_query_status = get_circuit_breaker('sii_query_status', self.circuit_config)
        self.cb_get_received_dte = get_circuit_breaker('sii_get_received_dte', self.circuit_config)
        self.cb_send_response = get_circuit_breaker('sii_send_response', self.circuit_config)

        logger.info("SII client wrapper initialized with circuit breaker protection")

    def send_dte(self, signed_xml: str, rut_emisor: str) -> Dict:
        """
        Envía DTE al SII con circuit breaker protection.

        Args:
            signed_xml: XML firmado digitalmente
            rut_emisor: RUT del emisor

        Returns:
            Dict con resultado del envío

        Raises:
            CircuitBreakerOpenError: Si circuit está OPEN (SII no disponible)
        """
        try:
            # Execute con circuit breaker
            result = self.cb_send_dte.call(
                self.sii_client.send_dte,
                signed_xml=signed_xml,
                rut_emisor=rut_emisor
            )

            logger.info("dte_sent_via_circuit_breaker",
                       rut_emisor=rut_emisor,
                       circuit_state=self.cb_send_dte.get_state().value)

            return result

        except CircuitBreakerOpenError as e:
            logger.warning("circuit_breaker_open_send_dte", error=str(e))

            # Return failure con flag de circuit open
            return {
                'success': False,
                'error_message': str(e),
                'error_type': 'CIRCUIT_BREAKER_OPEN',
                'should_queue': True,  # Indica que debe ir a failed queue
                'circuit_state': CircuitState.OPEN.value
            }

        except Exception as e:
            logger.error("send_dte_error", error=str(e), rut_emisor=rut_emisor)

            return {
                'success': False,
                'error_message': str(e),
                'error_type': 'UNKNOWN_ERROR',
                'should_queue': True
            }

    def query_dte_status(self, track_id: str, rut_emisor: str) -> Dict:
        """
        Consulta estado de DTE en SII con circuit breaker protection.

        Args:
            track_id: ID de seguimiento del SII
            rut_emisor: RUT del emisor

        Returns:
            Dict con estado del DTE

        Raises:
            CircuitBreakerOpenError: Si circuit está OPEN
        """
        try:
            result = self.cb_query_status.call(
                self.sii_client.query_dte_status,
                track_id=track_id,
                rut_emisor=rut_emisor
            )

            return result

        except CircuitBreakerOpenError as e:
            logger.warning("circuit_breaker_open_query_status", track_id=track_id)

            return {
                'success': False,
                'error_message': str(e),
                'error_type': 'CIRCUIT_BREAKER_OPEN',
                'circuit_state': CircuitState.OPEN.value
            }

        except Exception as e:
            logger.error("query_status_error", error=str(e), track_id=track_id)

            return {
                'success': False,
                'error_message': str(e),
                'error_type': 'UNKNOWN_ERROR'
            }

    def get_received_dte(
        self,
        rut_receptor: str,
        dte_type: Optional[str] = None,
        fecha_desde: Optional[str] = None
    ) -> Dict:
        """
        Descarga DTEs recibidos desde SII con circuit breaker protection.

        Args:
            rut_receptor: RUT del receptor (nuestra empresa)
            dte_type: Tipo de DTE (opcional)
            fecha_desde: Fecha desde (opcional)

        Returns:
            Dict con DTEs recibidos

        Raises:
            CircuitBreakerOpenError: Si circuit está OPEN
        """
        try:
            result = self.cb_get_received_dte.call(
                self.sii_client.get_received_dte,
                rut_receptor=rut_receptor,
                dte_type=dte_type,
                fecha_desde=fecha_desde
            )

            return result

        except CircuitBreakerOpenError as e:
            logger.warning("circuit_breaker_open_get_received_dte")

            return {
                'success': False,
                'error_message': str(e),
                'error_type': 'CIRCUIT_BREAKER_OPEN',
                'circuit_state': CircuitState.OPEN.value
            }

        except Exception as e:
            logger.error("get_received_dte_error", error=str(e))

            return {
                'success': False,
                'error_message': str(e),
                'error_type': 'UNKNOWN_ERROR'
            }

    def send_commercial_response(
        self,
        dte_type: str,
        folio: str,
        emisor_rut: str,
        receptor_rut: str,
        response_code: str,
        reason: Optional[str] = None
    ) -> Dict:
        """
        Envía respuesta comercial al SII con circuit breaker protection.

        Args:
            dte_type: Tipo de DTE
            folio: Folio del DTE
            emisor_rut: RUT del emisor
            receptor_rut: RUT del receptor (nosotros)
            response_code: Código respuesta ('0'=Accept, '1'=Reject, '2'=Claim)
            reason: Razón (opcional)

        Returns:
            Dict con resultado del envío

        Raises:
            CircuitBreakerOpenError: Si circuit está OPEN
        """
        try:
            result = self.cb_send_response.call(
                self.sii_client.send_commercial_response,
                dte_type=dte_type,
                folio=folio,
                emisor_rut=emisor_rut,
                receptor_rut=receptor_rut,
                response_code=response_code,
                reason=reason
            )

            return result

        except CircuitBreakerOpenError as e:
            logger.warning("circuit_breaker_open_send_response", folio=folio)

            return {
                'success': False,
                'error_message': str(e),
                'error_type': 'CIRCUIT_BREAKER_OPEN',
                'should_queue': True,
                'circuit_state': CircuitState.OPEN.value
            }

        except Exception as e:
            logger.error("send_response_error", error=str(e), folio=folio)

            return {
                'success': False,
                'error_message': str(e),
                'error_type': 'UNKNOWN_ERROR',
                'should_queue': True
            }

    def get_circuit_states(self) -> Dict:
        """
        Obtiene estado de todos los circuit breakers.

        Returns:
            Dict con estados de circuit breakers
        """
        return {
            'send_dte': {
                'state': self.cb_send_dte.get_state().value,
                'stats': self.cb_send_dte.get_stats()
            },
            'query_status': {
                'state': self.cb_query_status.get_state().value,
                'stats': self.cb_query_status.get_stats()
            },
            'get_received_dte': {
                'state': self.cb_get_received_dte.get_state().value,
                'stats': self.cb_get_received_dte.get_stats()
            },
            'send_response': {
                'state': self.cb_send_response.get_state().value,
                'stats': self.cb_send_response.get_stats()
            }
        }

    def is_sii_available(self) -> bool:
        """
        Verifica si SII está disponible (circuit cerrado).

        Returns:
            True si SII está disponible
        """
        # Si al menos send_dte está CLOSED, consideramos SII disponible
        return self.cb_send_dte.get_state() == CircuitState.CLOSED

    def reset_all_circuits(self):
        """Reset manual de todos los circuit breakers."""
        self.cb_send_dte.reset()
        self.cb_query_status.reset()
        self.cb_get_received_dte.reset()
        self.cb_send_response.reset()

        logger.info("all_circuit_breakers_reset")


# Singleton instance
_sii_client_wrapper = None


def init_sii_client_wrapper(
    sii_client: SIISoapClient,
    circuit_config: Optional[CircuitBreakerConfig] = None
) -> SIIClientWrapper:
    """
    Inicializa SII client wrapper (singleton).

    Args:
        sii_client: Cliente SII SOAP
        circuit_config: Configuración circuit breaker (opcional)

    Returns:
        SIIClientWrapper instance
    """
    global _sii_client_wrapper

    if _sii_client_wrapper is None:
        _sii_client_wrapper = SIIClientWrapper(sii_client, circuit_config)

    return _sii_client_wrapper


def get_sii_client_wrapper() -> Optional[SIIClientWrapper]:
    """Obtiene SII client wrapper singleton."""
    return _sii_client_wrapper
