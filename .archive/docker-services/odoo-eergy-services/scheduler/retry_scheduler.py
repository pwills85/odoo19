"""
Retry Scheduler
===============

Scheduler para procesar automáticamente DTEs fallidos.
Ejecuta cada 5 minutos usando APScheduler.

Based on Odoo 18: l10n_cl_fe/models/retry_scheduler.py
"""

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime

from recovery.retry_manager import RetryManager

logger = logging.getLogger(__name__)


class RetryScheduler:
    """
    Scheduler para reintentos automáticos de DTEs.

    Features:
    - Job cada 5 minutos
    - Procesa hasta 10 DTEs por ejecución
    - Tracking de ejecuciones y errores
    - Graceful shutdown
    """

    def __init__(
        self,
        retry_manager: RetryManager,
        interval_minutes: int = 5,
        batch_size: int = 10
    ):
        """
        Inicializa retry scheduler.

        Args:
            retry_manager: Manager de reintentos
            interval_minutes: Intervalo de ejecución en minutos
            batch_size: Número de DTEs a procesar por batch
        """
        self.retry_manager = retry_manager
        self.interval_minutes = interval_minutes
        self.batch_size = batch_size

        self.scheduler = BackgroundScheduler()
        self.is_running = False

        # Stats
        self.total_runs = 0
        self.total_processed = 0
        self.total_successful = 0
        self.total_failed = 0
        self.last_run_timestamp = None
        self.last_run_result = None

        logger.info(f"Retry scheduler initialized (interval: {interval_minutes} min)")

    def start(self):
        """Inicia el scheduler."""
        if self.is_running:
            logger.warning("Scheduler already running")
            return

        try:
            # Agregar job
            self.scheduler.add_job(
                func=self._retry_job,
                trigger=IntervalTrigger(minutes=self.interval_minutes),
                id='retry_failed_dtes',
                name='Retry Failed DTEs',
                replace_existing=True,
                max_instances=1  # No permitir ejecuciones concurrentes
            )

            # Iniciar scheduler
            self.scheduler.start()
            self.is_running = True

            logger.info("Retry scheduler started")

        except Exception as e:
            logger.error(f"Failed to start retry scheduler: {e}")
            raise

    def stop(self):
        """Detiene el scheduler."""
        if not self.is_running:
            return

        try:
            self.scheduler.shutdown(wait=True)
            self.is_running = False
            logger.info("Retry scheduler stopped")

        except Exception as e:
            logger.error(f"Failed to stop retry scheduler: {e}")

    def _retry_job(self):
        """
        Job ejecutado periódicamente para procesar DTEs fallidos.
        """
        try:
            logger.info("Starting retry job")

            # Procesar batch
            result = self.retry_manager.process_retry_queue(
                batch_size=self.batch_size
            )

            # Actualizar stats
            self.total_runs += 1
            self.total_processed += result['processed']
            self.total_successful += result['successful']
            self.total_failed += result['failed']
            self.last_run_timestamp = datetime.now().isoformat()
            self.last_run_result = result

            logger.info(
                f"Retry job complete: {result['processed']} processed, "
                f"{result['successful']} success, {result['failed']} failed"
            )

            # Log errors si hay
            if result['errors']:
                for error in result['errors']:
                    logger.error(f"Retry job error: {error}")

        except Exception as e:
            logger.error(f"Retry job failed with exception: {e}")

    def get_stats(self) -> dict:
        """
        Obtiene estadísticas del scheduler.

        Returns:
            Diccionario con estadísticas
        """
        return {
            'is_running': self.is_running,
            'interval_minutes': self.interval_minutes,
            'batch_size': self.batch_size,
            'total_runs': self.total_runs,
            'total_processed': self.total_processed,
            'total_successful': self.total_successful,
            'total_failed': self.total_failed,
            'success_rate': (
                self.total_successful / self.total_processed * 100
                if self.total_processed > 0 else 0
            ),
            'last_run_timestamp': self.last_run_timestamp,
            'last_run_result': self.last_run_result,
            'next_run_time': (
                self.scheduler.get_job('retry_failed_dtes').next_run_time.isoformat()
                if self.is_running and self.scheduler.get_job('retry_failed_dtes')
                else None
            )
        }

    def trigger_immediate_run(self):
        """
        Ejecuta job inmediatamente (fuera de schedule).
        """
        if not self.is_running:
            logger.warning("Cannot trigger immediate run: scheduler not running")
            return

        try:
            logger.info("Triggering immediate retry job")
            self._retry_job()

        except Exception as e:
            logger.error(f"Immediate run failed: {e}")
