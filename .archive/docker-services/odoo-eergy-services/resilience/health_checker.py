"""
Health Checker
==============

Monitorea salud del SII y servicios externos.
Informa al circuit breaker sobre disponibilidad.

Based on Odoo 18: l10n_cl_fe/models/health_checker.py
"""

import logging
from datetime import datetime
from typing import Dict, Optional
import requests
from enum import Enum

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Estado de salud de un servicio."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


class HealthChecker:
    """
    Verifica salud de servicios externos.

    Features:
    - Check SII availability
    - Check Redis availability
    - Check RabbitMQ availability
    - Aggregate health status
    """

    def __init__(self):
        """Inicializa health checker."""
        self.last_check_time = None
        self.last_results = {}

    def check_sii_health(
        self,
        sii_wsdl_url: str,
        timeout: int = 10
    ) -> Dict:
        """
        Verifica disponibilidad del SII.

        Args:
            sii_wsdl_url: URL del WSDL del SII
            timeout: Timeout en segundos

        Returns:
            Dict con resultado del check
        """
        try:
            # Intentar acceder al WSDL del SII
            response = requests.get(
                sii_wsdl_url,
                timeout=timeout,
                verify=True
            )

            if response.status_code == 200:
                return {
                    'service': 'SII',
                    'status': HealthStatus.HEALTHY.value,
                    'message': 'SII is reachable',
                    'response_time_ms': int(response.elapsed.total_seconds() * 1000),
                    'checked_at': datetime.now().isoformat()
                }
            else:
                return {
                    'service': 'SII',
                    'status': HealthStatus.DEGRADED.value,
                    'message': f'SII returned {response.status_code}',
                    'response_time_ms': int(response.elapsed.total_seconds() * 1000),
                    'checked_at': datetime.now().isoformat()
                }

        except requests.exceptions.Timeout:
            return {
                'service': 'SII',
                'status': HealthStatus.UNHEALTHY.value,
                'message': 'SII timeout',
                'checked_at': datetime.now().isoformat()
            }

        except requests.exceptions.ConnectionError as e:
            return {
                'service': 'SII',
                'status': HealthStatus.UNHEALTHY.value,
                'message': f'SII connection error: {str(e)}',
                'checked_at': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"SII health check failed: {e}")
            return {
                'service': 'SII',
                'status': HealthStatus.UNKNOWN.value,
                'message': f'Error: {str(e)}',
                'checked_at': datetime.now().isoformat()
            }

    def check_redis_health(
        self,
        redis_host: str = 'redis',
        redis_port: int = 6379,
        timeout: int = 5
    ) -> Dict:
        """
        Verifica disponibilidad de Redis.

        Args:
            redis_host: Host de Redis
            redis_port: Puerto de Redis
            timeout: Timeout en segundos

        Returns:
            Dict con resultado del check
        """
        try:
            import redis as redis_lib
            from datetime import datetime

            start_time = datetime.now()

            client = redis_lib.Redis(
                host=redis_host,
                port=redis_port,
                db=0,
                socket_connect_timeout=timeout
            )

            # Ping Redis
            client.ping()

            response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)

            return {
                'service': 'Redis',
                'status': HealthStatus.HEALTHY.value,
                'message': 'Redis is reachable',
                'response_time_ms': response_time_ms,
                'checked_at': datetime.now().isoformat()
            }

        except redis_lib.ConnectionError:
            return {
                'service': 'Redis',
                'status': HealthStatus.UNHEALTHY.value,
                'message': 'Redis connection error',
                'checked_at': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                'service': 'Redis',
                'status': HealthStatus.UNKNOWN.value,
                'message': f'Error: {str(e)}',
                'checked_at': datetime.now().isoformat()
            }

    def check_rabbitmq_health(
        self,
        rabbitmq_host: str = 'rabbitmq',
        rabbitmq_port: int = 5672,
        timeout: int = 5
    ) -> Dict:
        """
        Verifica disponibilidad de RabbitMQ.

        Args:
            rabbitmq_host: Host de RabbitMQ
            rabbitmq_port: Puerto de RabbitMQ
            timeout: Timeout en segundos

        Returns:
            Dict con resultado del check
        """
        try:
            import socket
            from datetime import datetime

            start_time = datetime.now()

            # Check si puerto está abierto
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((rabbitmq_host, rabbitmq_port))
            sock.close()

            response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)

            if result == 0:
                return {
                    'service': 'RabbitMQ',
                    'status': HealthStatus.HEALTHY.value,
                    'message': 'RabbitMQ is reachable',
                    'response_time_ms': response_time_ms,
                    'checked_at': datetime.now().isoformat()
                }
            else:
                return {
                    'service': 'RabbitMQ',
                    'status': HealthStatus.UNHEALTHY.value,
                    'message': f'RabbitMQ port closed (code {result})',
                    'checked_at': datetime.now().isoformat()
                }

        except Exception as e:
            logger.error(f"RabbitMQ health check failed: {e}")
            return {
                'service': 'RabbitMQ',
                'status': HealthStatus.UNKNOWN.value,
                'message': f'Error: {str(e)}',
                'checked_at': datetime.now().isoformat()
            }

    def check_all(
        self,
        sii_wsdl_url: str,
        redis_host: str = 'redis',
        rabbitmq_host: str = 'rabbitmq'
    ) -> Dict:
        """
        Verifica salud de todos los servicios.

        Args:
            sii_wsdl_url: URL del WSDL del SII
            redis_host: Host de Redis
            rabbitmq_host: Host de RabbitMQ

        Returns:
            Dict con resultado agregado
        """
        results = {
            'sii': self.check_sii_health(sii_wsdl_url),
            'redis': self.check_redis_health(redis_host),
            'rabbitmq': self.check_rabbitmq_health(rabbitmq_host)
        }

        # Agregar resultado general
        unhealthy_count = sum(
            1 for r in results.values()
            if r['status'] in [HealthStatus.UNHEALTHY.value, HealthStatus.UNKNOWN.value]
        )

        degraded_count = sum(
            1 for r in results.values()
            if r['status'] == HealthStatus.DEGRADED.value
        )

        if unhealthy_count > 0:
            overall_status = HealthStatus.UNHEALTHY.value
        elif degraded_count > 0:
            overall_status = HealthStatus.DEGRADED.value
        else:
            overall_status = HealthStatus.HEALTHY.value

        self.last_check_time = datetime.now().isoformat()
        self.last_results = results

        return {
            'overall_status': overall_status,
            'checked_at': self.last_check_time,
            'services': results
        }


# Singleton instance
_health_checker = None


def get_health_checker() -> HealthChecker:
    """Obtiene health checker singleton."""
    global _health_checker

    if _health_checker is None:
        _health_checker = HealthChecker()

    return _health_checker
