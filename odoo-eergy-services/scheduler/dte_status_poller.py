# -*- coding: utf-8 -*-
"""
DTE Status Poller - Polling Automático de Estado de DTEs

Este módulo implementa polling automático para consultar el estado
de DTEs enviados al SII que están pendientes de confirmación.

Características:
- Polling cada 15 minutos (configurable)
- Solo consulta DTEs en estado 'sent'
- Actualiza estado automáticamente
- Retry logic incluido
- Logging estructurado
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime, timedelta
import structlog
import os
import redis
import json

logger = structlog.get_logger()


class DTEStatusPoller:
    """
    Polling automático de estado de DTEs en el SII.

    Consulta periódicamente el estado de DTEs enviados al SII
    que están en estado 'sent' y actualiza su estado en la base de datos.
    """

    def __init__(self, sii_client, redis_url: str, poll_interval_minutes: int = 15):
        """
        Inicializa el poller.

        Args:
            sii_client: Cliente SOAP del SII
            redis_url: URL de conexión a Redis
            poll_interval_minutes: Intervalo de polling en minutos (default: 15)
        """
        self.sii_client = sii_client
        self.poll_interval = poll_interval_minutes
        self.redis_url = redis_url

        # Conectar a Redis
        self.redis_client = redis.from_url(redis_url, decode_responses=True)

        # Inicializar scheduler
        self.scheduler = BackgroundScheduler()

        logger.info("dte_status_poller_initialized",
                   poll_interval_minutes=poll_interval_minutes)

    def start(self):
        """
        Inicia el polling automático.

        Ejecuta el job de polling cada X minutos según configuración.
        """
        # Agregar job de polling
        self.scheduler.add_job(
            func=self.poll_pending_dtes,
            trigger=IntervalTrigger(minutes=self.poll_interval),
            id='dte_status_polling',
            name='Poll DTE Status from SII',
            replace_existing=True,
            max_instances=1  # Solo una instancia a la vez
        )

        # Iniciar scheduler
        self.scheduler.start()

        logger.info("dte_status_poller_started",
                   poll_interval_minutes=self.poll_interval)

    def stop(self):
        """Detiene el polling automático."""
        self.scheduler.shutdown(wait=True)
        logger.info("dte_status_poller_stopped")

    def poll_pending_dtes(self):
        """
        Job principal: Consulta estado de DTEs pendientes.

        Workflow:
        1. Obtener DTEs en estado 'sent' desde Redis
        2. Para cada DTE, consultar estado en SII
        3. Si estado cambió, actualizar en Redis
        4. Notificar a Odoo del cambio (webhook)
        """
        start_time = datetime.now()

        logger.info("dte_polling_job_started")

        try:
            # 1. Obtener DTEs pendientes desde Redis
            pending_dtes = self._get_pending_dtes()

            if not pending_dtes:
                logger.info("no_pending_dtes_found")
                return

            logger.info("pending_dtes_found", count=len(pending_dtes))

            # 2. Consultar estado de cada DTE
            updated_count = 0
            error_count = 0

            for dte in pending_dtes:
                try:
                    # Consultar estado en SII
                    result = self._poll_dte_status(dte)

                    if result['updated']:
                        updated_count += 1

                except Exception as e:
                    logger.error("error_polling_dte",
                                dte_id=dte.get('id'),
                                track_id=dte.get('track_id'),
                                error=str(e))
                    error_count += 1

            # 3. Log resultados
            duration = (datetime.now() - start_time).total_seconds()

            logger.info("dte_polling_job_completed",
                       total_dtes=len(pending_dtes),
                       updated=updated_count,
                       errors=error_count,
                       duration_seconds=duration)

        except Exception as e:
            logger.error("dte_polling_job_failed", error=str(e))

    def _get_pending_dtes(self) -> list:
        """
        Obtiene DTEs pendientes desde Redis.

        Returns:
            list: Lista de DTEs en estado 'sent'
        """
        try:
            # Buscar keys de DTEs pendientes
            # Formato de key: dte:pending:{track_id}
            pending_keys = self.redis_client.keys('dte:pending:*')

            dtes = []

            for key in pending_keys:
                dte_data = self.redis_client.get(key)

                if dte_data:
                    dte = json.loads(dte_data)

                    # Verificar que no sea muy antiguo (más de 7 días)
                    if 'timestamp' in dte:
                        dte_timestamp = datetime.fromisoformat(dte['timestamp'])
                        age_days = (datetime.now() - dte_timestamp).days

                        if age_days > 7:
                            # DTE muy antiguo, marcar como 'timeout'
                            logger.warning("dte_timeout",
                                          track_id=dte.get('track_id'),
                                          age_days=age_days)
                            self._mark_dte_timeout(dte)
                            continue

                    dtes.append(dte)

            return dtes

        except Exception as e:
            logger.error("error_getting_pending_dtes", error=str(e))
            return []

    def _poll_dte_status(self, dte: dict) -> dict:
        """
        Consulta estado de un DTE específico en el SII.

        Args:
            dte: Dict con información del DTE

        Returns:
            dict: {'updated': bool, 'new_status': str}
        """
        track_id = dte.get('track_id')
        rut_emisor = dte.get('rut_emisor')
        dte_id = dte.get('id')

        logger.info("polling_dte_status",
                   dte_id=dte_id,
                   track_id=track_id)

        try:
            # Consultar estado en SII
            response = self.sii_client.query_status(track_id, rut_emisor)

            if not response['success']:
                logger.warning("sii_status_query_failed",
                              track_id=track_id,
                              error=response.get('error_message'))
                return {'updated': False}

            new_status = response.get('status', 'unknown')
            old_status = dte.get('status', 'sent')

            # Verificar si cambió el estado
            if new_status != old_status and new_status != 'unknown':
                logger.info("dte_status_changed",
                           dte_id=dte_id,
                           track_id=track_id,
                           old_status=old_status,
                           new_status=new_status)

                # Actualizar en Redis
                self._update_dte_status(dte, new_status, response)

                # Notificar a Odoo
                self._notify_odoo(dte, new_status, response)

                return {'updated': True, 'new_status': new_status}

            # Sin cambios
            return {'updated': False}

        except Exception as e:
            logger.error("error_polling_dte_status",
                        dte_id=dte_id,
                        track_id=track_id,
                        error=str(e))
            return {'updated': False}

    def _update_dte_status(self, dte: dict, new_status: str, sii_response: dict):
        """
        Actualiza estado del DTE en Redis.

        Args:
            dte: Dict con información del DTE
            new_status: Nuevo estado
            sii_response: Respuesta completa del SII
        """
        try:
            track_id = dte.get('track_id')
            key = f'dte:pending:{track_id}'

            # Actualizar datos
            dte['status'] = new_status
            dte['last_poll'] = datetime.now().isoformat()
            dte['sii_response'] = sii_response

            # Si estado es final (aceptado/rechazado), mover a otro key
            if new_status in ['accepted', 'rejected', 'expired']:
                # Guardar en completed
                completed_key = f'dte:completed:{track_id}'
                self.redis_client.setex(
                    completed_key,
                    timedelta(days=30),  # Guardar 30 días
                    json.dumps(dte)
                )

                # Eliminar de pending
                self.redis_client.delete(key)

                logger.info("dte_moved_to_completed",
                           track_id=track_id,
                           status=new_status)
            else:
                # Actualizar en pending
                self.redis_client.setex(
                    key,
                    timedelta(days=7),  # TTL 7 días
                    json.dumps(dte)
                )

        except Exception as e:
            logger.error("error_updating_dte_status",
                        track_id=dte.get('track_id'),
                        error=str(e))

    def _notify_odoo(self, dte: dict, new_status: str, sii_response: dict):
        """
        Notifica a Odoo del cambio de estado.

        Envía webhook a Odoo con información del DTE actualizado.

        Args:
            dte: Dict con información del DTE
            new_status: Nuevo estado
            sii_response: Respuesta del SII
        """
        try:
            import requests

            odoo_url = os.getenv('ODOO_URL', 'http://odoo:8069')
            webhook_url = f'{odoo_url}/dte/webhook/status_update'

            payload = {
                'dte_id': dte.get('id'),
                'track_id': dte.get('track_id'),
                'old_status': dte.get('status'),
                'new_status': new_status,
                'sii_response': sii_response,
                'timestamp': datetime.now().isoformat()
            }

            # Enviar webhook (timeout corto para no bloquear)
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=5
            )

            if response.status_code == 200:
                logger.info("odoo_notified_successfully",
                           dte_id=dte.get('id'),
                           new_status=new_status)
            else:
                logger.warning("odoo_notification_failed",
                              status_code=response.status_code,
                              dte_id=dte.get('id'))

        except Exception as e:
            logger.error("error_notifying_odoo",
                        dte_id=dte.get('id'),
                        error=str(e))

    def _mark_dte_timeout(self, dte: dict):
        """
        Marca DTE como timeout si es muy antiguo.

        Args:
            dte: Dict con información del DTE
        """
        track_id = dte.get('track_id')

        # Mover a timeout
        timeout_key = f'dte:timeout:{track_id}'
        self.redis_client.setex(
            timeout_key,
            timedelta(days=90),  # Guardar 90 días
            json.dumps(dte)
        )

        # Eliminar de pending
        pending_key = f'dte:pending:{track_id}'
        self.redis_client.delete(pending_key)

        logger.warning("dte_marked_as_timeout", track_id=track_id)


# Instancia global del poller (se inicializa en main.py)
dte_poller = None


def init_poller(sii_client, redis_url: str, poll_interval_minutes: int = 15):
    """
    Inicializa el poller global.

    Args:
        sii_client: Cliente SOAP del SII
        redis_url: URL de Redis
        poll_interval_minutes: Intervalo de polling

    Returns:
        DTEStatusPoller: Instancia del poller
    """
    global dte_poller

    dte_poller = DTEStatusPoller(sii_client, redis_url, poll_interval_minutes)
    dte_poller.start()

    return dte_poller


def shutdown_poller():
    """Detiene el poller global."""
    global dte_poller

    if dte_poller:
        dte_poller.stop()
        dte_poller = None
