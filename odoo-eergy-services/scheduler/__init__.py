# -*- coding: utf-8 -*-
"""
DTE Service Scheduler Module

Tareas programadas para el servicio DTE:
- Polling automático de estado de DTEs (cada 15 minutos)
- Retry de DTEs fallidos (cada 5 minutos) - Disaster Recovery
"""

from .dte_status_poller import DTEStatusPoller
from .retry_scheduler import RetryScheduler

# Global instances
_dte_status_poller = None
_retry_scheduler = None


def init_poller(sii_client, redis_url, poll_interval_minutes=15):
    """
    Inicializa DTE Status Poller.

    Args:
        sii_client: Cliente SII SOAP
        redis_url: URL de Redis
        poll_interval_minutes: Intervalo de polling en minutos
    """
    global _dte_status_poller

    if _dte_status_poller is not None:
        return

    _dte_status_poller = DTEStatusPoller(
        sii_client=sii_client,
        redis_url=redis_url,
        poll_interval_minutes=poll_interval_minutes
    )

    _dte_status_poller.start()


def shutdown_poller():
    """Shutdown DTE Status Poller."""
    global _dte_status_poller

    if _dte_status_poller:
        _dte_status_poller.stop()
        _dte_status_poller = None


def init_retry_scheduler(retry_manager, interval_minutes=5, batch_size=10):
    """
    Inicializa Retry Scheduler for Disaster Recovery.

    Args:
        retry_manager: Manager de reintentos
        interval_minutes: Intervalo de ejecución en minutos
        batch_size: Número de DTEs a procesar por batch
    """
    global _retry_scheduler

    if _retry_scheduler is not None:
        return

    _retry_scheduler = RetryScheduler(
        retry_manager=retry_manager,
        interval_minutes=interval_minutes,
        batch_size=batch_size
    )

    _retry_scheduler.start()


def shutdown_retry_scheduler():
    """Shutdown Retry Scheduler."""
    global _retry_scheduler

    if _retry_scheduler:
        _retry_scheduler.stop()
        _retry_scheduler = None


def get_poller_stats():
    """Obtiene estadísticas del poller."""
    if _dte_status_poller:
        return _dte_status_poller.get_stats()
    return None


def get_retry_stats():
    """Obtiene estadísticas del retry scheduler."""
    if _retry_scheduler:
        return _retry_scheduler.get_stats()
    return None


__all__ = [
    'DTEStatusPoller',
    'RetryScheduler',
    'init_poller',
    'shutdown_poller',
    'init_retry_scheduler',
    'shutdown_retry_scheduler',
    'get_poller_stats',
    'get_retry_stats'
]
