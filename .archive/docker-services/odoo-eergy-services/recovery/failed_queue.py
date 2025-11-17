"""
Failed Queue Manager
====================

Gestiona cola de DTEs que fallaron al enviar a SII.
Usa Redis para persistencia y tracking de reintentos.

Based on Odoo 18: l10n_cl_fe/models/failed_queue.py
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import redis

logger = logging.getLogger(__name__)


class FailedQueueManager:
    """
    Gestiona cola de DTEs fallidos con reintentos exponenciales.

    Features:
    - Almacenamiento persistente en Redis
    - Tracking de número de reintentos
    - Backoff exponencial (5min, 10min, 20min, 40min, 80min)
    - Máximo 5 reintentos antes de intervención manual
    - Clasificación de errores (retriable vs non-retriable)
    - Alertas para DTEs en review manual
    """

    # Redis keys
    QUEUE_KEY = "dte:failed_queue"
    METADATA_KEY_PREFIX = "dte:failed_metadata:"

    # Retry configuration
    MAX_RETRIES = 5
    INITIAL_RETRY_DELAY = 300  # 5 minutes
    BACKOFF_MULTIPLIER = 2

    # Error classification
    RETRIABLE_ERRORS = {
        'TIMEOUT', 'CONNECTION_ERROR', 'SII_TIMEOUT',
        'SII_UNAVAILABLE', 'RATE_LIMIT'
    }

    NON_RETRIABLE_ERRORS = {
        'INVALID_SIGNATURE', 'INVALID_RUT', 'INVALID_CAF',
        'FOLIO_ALREADY_USED', 'EXPIRED_CERTIFICATE'
    }

    def __init__(
        self,
        redis_host: str = 'redis',
        redis_port: int = 6379,
        redis_db: int = 0
    ):
        """
        Inicializa failed queue manager.

        Args:
            redis_host: Host de Redis
            redis_port: Puerto de Redis
            redis_db: Base de datos Redis
        """
        try:
            self.redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                decode_responses=True,
                socket_connect_timeout=5
            )
            # Test connection
            self.redis_client.ping()
            logger.info("Failed queue manager initialized")
        except redis.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}")
            raise

    def add_failed_dte(
        self,
        dte_type: str,
        folio: str,
        rut_emisor: str,
        xml_content: str,
        error_type: str,
        error_message: str,
        company_id: Optional[int] = None,
        odoo_record_id: Optional[int] = None
    ) -> bool:
        """
        Agrega DTE fallido a la cola.

        Args:
            dte_type: Tipo de DTE
            folio: Folio del DTE
            rut_emisor: RUT del emisor
            xml_content: XML del DTE
            error_type: Tipo de error (ej: 'TIMEOUT', 'INVALID_SIGNATURE')
            error_message: Mensaje de error detallado
            company_id: ID de compañía en Odoo (opcional)
            odoo_record_id: ID del registro en Odoo (opcional)

        Returns:
            True si se agregó exitosamente
        """
        try:
            # Generar ID único
            queue_id = f"DTE{dte_type}_{folio}_{rut_emisor}_{int(datetime.now().timestamp())}"

            # Verificar si es retriable
            is_retriable = error_type in self.RETRIABLE_ERRORS

            if not is_retriable and error_type in self.NON_RETRIABLE_ERRORS:
                logger.warning(f"Non-retriable error for {queue_id}: {error_type}")
                # Agregar a cola de revisión manual directamente
                return self._add_to_manual_review(
                    queue_id, dte_type, folio, rut_emisor,
                    error_type, error_message
                )

            # Calcular próximo reintento (5 minutos)
            next_retry = datetime.now() + timedelta(seconds=self.INITIAL_RETRY_DELAY)

            # Metadata del DTE fallido
            metadata = {
                'queue_id': queue_id,
                'dte_type': dte_type,
                'folio': folio,
                'rut_emisor': rut_emisor,
                'xml_content': xml_content,
                'error_type': error_type,
                'error_message': error_message,
                'company_id': company_id,
                'odoo_record_id': odoo_record_id,
                'retry_count': 0,
                'max_retries': self.MAX_RETRIES,
                'next_retry_timestamp': next_retry.isoformat(),
                'first_failed_timestamp': datetime.now().isoformat(),
                'last_attempt_timestamp': datetime.now().isoformat(),
                'is_retriable': is_retriable,
                'status': 'pending_retry'
            }

            # Guardar metadata en Redis
            metadata_key = f"{self.METADATA_KEY_PREFIX}{queue_id}"
            self.redis_client.set(
                metadata_key,
                json.dumps(metadata),
                ex=86400 * 30  # 30 días de expiración
            )

            # Agregar a sorted set con score = timestamp de próximo reintento
            self.redis_client.zadd(
                self.QUEUE_KEY,
                {queue_id: next_retry.timestamp()}
            )

            logger.info(f"DTE added to failed queue: {queue_id}, next retry: {next_retry}")
            return True

        except Exception as e:
            logger.error(f"Failed to add DTE to queue: {e}")
            return False

    def get_ready_for_retry(self, limit: int = 10) -> List[Dict]:
        """
        Obtiene DTEs listos para reintentar.

        Args:
            limit: Número máximo de DTEs a retornar

        Returns:
            Lista de DTEs listos para reintento
        """
        try:
            now = datetime.now().timestamp()

            # Obtener DTEs cuyo next_retry_timestamp <= now
            queue_ids = self.redis_client.zrangebyscore(
                self.QUEUE_KEY,
                0,
                now,
                start=0,
                num=limit
            )

            dtes = []
            for queue_id in queue_ids:
                metadata_key = f"{self.METADATA_KEY_PREFIX}{queue_id}"
                metadata_json = self.redis_client.get(metadata_key)

                if metadata_json:
                    metadata = json.loads(metadata_json)
                    dtes.append(metadata)

            return dtes

        except Exception as e:
            logger.error(f"Failed to get DTEs ready for retry: {e}")
            return []

    def update_retry_attempt(
        self,
        queue_id: str,
        success: bool,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Actualiza estado después de reintento.

        Args:
            queue_id: ID del DTE en cola
            success: True si el reintento fue exitoso
            error_type: Tipo de error si falló (opcional)
            error_message: Mensaje de error si falló (opcional)

        Returns:
            True si se actualizó exitosamente
        """
        try:
            metadata_key = f"{self.METADATA_KEY_PREFIX}{queue_id}"
            metadata_json = self.redis_client.get(metadata_key)

            if not metadata_json:
                logger.warning(f"Queue ID not found: {queue_id}")
                return False

            metadata = json.loads(metadata_json)

            if success:
                # Eliminar de cola de fallidos
                self.redis_client.zrem(self.QUEUE_KEY, queue_id)
                self.redis_client.delete(metadata_key)
                logger.info(f"DTE successfully retried and removed from queue: {queue_id}")
                return True

            # Incrementar contador de reintentos
            metadata['retry_count'] += 1
            metadata['last_attempt_timestamp'] = datetime.now().isoformat()

            if error_type:
                metadata['error_type'] = error_type
            if error_message:
                metadata['error_message'] = error_message

            # Verificar si alcanzó máximo de reintentos
            if metadata['retry_count'] >= self.MAX_RETRIES:
                logger.warning(f"Max retries reached for {queue_id}, moving to manual review")
                return self._move_to_manual_review(queue_id, metadata)

            # Calcular próximo reintento con backoff exponencial
            delay_seconds = self.INITIAL_RETRY_DELAY * (
                self.BACKOFF_MULTIPLIER ** metadata['retry_count']
            )
            next_retry = datetime.now() + timedelta(seconds=delay_seconds)
            metadata['next_retry_timestamp'] = next_retry.isoformat()

            # Actualizar metadata
            self.redis_client.set(
                metadata_key,
                json.dumps(metadata),
                ex=86400 * 30
            )

            # Actualizar score en sorted set
            self.redis_client.zadd(
                self.QUEUE_KEY,
                {queue_id: next_retry.timestamp()}
            )

            logger.info(f"Retry attempt updated for {queue_id}, next retry: {next_retry}")
            return True

        except Exception as e:
            logger.error(f"Failed to update retry attempt: {e}")
            return False

    def _add_to_manual_review(
        self,
        queue_id: str,
        dte_type: str,
        folio: str,
        rut_emisor: str,
        error_type: str,
        error_message: str
    ) -> bool:
        """
        Agrega DTE directamente a revisión manual (error no retriable).
        """
        try:
            review_key = "dte:manual_review"

            review_data = {
                'queue_id': queue_id,
                'dte_type': dte_type,
                'folio': folio,
                'rut_emisor': rut_emisor,
                'error_type': error_type,
                'error_message': error_message,
                'added_timestamp': datetime.now().isoformat(),
                'reason': 'non_retriable_error'
            }

            self.redis_client.zadd(
                review_key,
                {queue_id: datetime.now().timestamp()}
            )

            self.redis_client.set(
                f"dte:review_metadata:{queue_id}",
                json.dumps(review_data),
                ex=86400 * 90  # 90 días
            )

            logger.warning(f"DTE added to manual review: {queue_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add to manual review: {e}")
            return False

    def _move_to_manual_review(self, queue_id: str, metadata: Dict) -> bool:
        """
        Mueve DTE a revisión manual después de agotar reintentos.
        """
        try:
            # Agregar a cola de revisión manual
            review_key = "dte:manual_review"

            review_data = {
                'queue_id': queue_id,
                'dte_type': metadata['dte_type'],
                'folio': metadata['folio'],
                'rut_emisor': metadata['rut_emisor'],
                'error_type': metadata['error_type'],
                'error_message': metadata['error_message'],
                'retry_count': metadata['retry_count'],
                'added_timestamp': datetime.now().isoformat(),
                'reason': 'max_retries_exceeded'
            }

            self.redis_client.zadd(
                review_key,
                {queue_id: datetime.now().timestamp()}
            )

            self.redis_client.set(
                f"dte:review_metadata:{queue_id}",
                json.dumps(review_data),
                ex=86400 * 90
            )

            # Eliminar de cola de reintentos
            self.redis_client.zrem(self.QUEUE_KEY, queue_id)

            # Mantener metadata original para referencia
            metadata['status'] = 'manual_review'
            metadata_key = f"{self.METADATA_KEY_PREFIX}{queue_id}"
            self.redis_client.set(
                metadata_key,
                json.dumps(metadata),
                ex=86400 * 90
            )

            logger.warning(f"DTE moved to manual review: {queue_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to move to manual review: {e}")
            return False

    def get_queue_stats(self) -> Dict:
        """
        Obtiene estadísticas de la cola.

        Returns:
            Diccionario con estadísticas
        """
        try:
            total_pending = self.redis_client.zcard(self.QUEUE_KEY)
            total_manual_review = self.redis_client.zcard("dte:manual_review")

            now = datetime.now().timestamp()
            ready_for_retry = self.redis_client.zcount(self.QUEUE_KEY, 0, now)

            return {
                'total_pending_retry': total_pending,
                'ready_for_retry_now': ready_for_retry,
                'total_manual_review': total_manual_review,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get queue stats: {e}")
            return {}
