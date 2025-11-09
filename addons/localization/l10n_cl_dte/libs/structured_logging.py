# -*- coding: utf-8 -*-
"""
Structured Logging - P3.1 GAP CLOSURE
======================================

Conditional JSON logging for DTE operations.

MODES:
- JSON mode (DTE_LOG_LEVEL=json): Structured JSON logs for analysis
- Standard mode (default): Human-readable Odoo logs

USAGE:
    from odoo.addons.l10n_cl_dte.libs.structured_logging import get_dte_logger

    _logger = get_dte_logger(__name__)
    _logger.info("DTE generated", extra={
        "dte_type": 33,
        "folio": 12345,
        "rut_emisor": "76123456-7"
    })

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    P3.1 GAP CLOSURE: Emits logs in JSON format for external analysis tools.
    """

    def format(self, record):
        """
        Format log record as JSON.

        Args:
            record: logging.LogRecord

        Returns:
            str: JSON-formatted log entry
        """
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add extra fields if present
        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, ensure_ascii=False)


class DTELoggerAdapter(logging.LoggerAdapter):
    """
    Adapter that conditionally formats logs as JSON.

    P3.1 GAP CLOSURE: Switches between JSON and standard logging based on environment.
    """

    def __init__(self, logger, extra=None):
        super().__init__(logger, extra or {})
        self.json_mode = self._is_json_mode_enabled()

    def _is_json_mode_enabled(self) -> bool:
        """
        Check if JSON logging mode is enabled.

        Returns:
            bool: True if DTE_LOG_LEVEL=json
        """
        log_level = os.environ.get('DTE_LOG_LEVEL', '').lower()
        return log_level == 'json'

    def process(self, msg, kwargs):
        """
        Process log message and add extra data.

        Args:
            msg: Log message
            kwargs: Keyword arguments (may contain 'extra')

        Returns:
            tuple: (message, kwargs)
        """
        # Extract extra data for JSON mode
        if self.json_mode and 'extra' in kwargs:
            # Store extra data in the record for JSON formatter
            if 'extra' not in kwargs:
                kwargs['extra'] = {}

            # Merge adapter's extra with call's extra
            extra_data = dict(self.extra)
            extra_data.update(kwargs.get('extra', {}))

            # Create a custom attribute for the formatter
            kwargs['extra']['extra_data'] = extra_data

        return msg, kwargs

    def info(self, msg, *args, **kwargs):
        """Log info with conditional JSON formatting"""
        if self.json_mode:
            self._log_json(logging.INFO, msg, kwargs)
        else:
            super().info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """Log warning with conditional JSON formatting"""
        if self.json_mode:
            self._log_json(logging.WARNING, msg, kwargs)
        else:
            super().warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """Log error with conditional JSON formatting"""
        if self.json_mode:
            self._log_json(logging.ERROR, msg, kwargs)
        else:
            super().error(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        """Log debug with conditional JSON formatting"""
        if self.json_mode:
            self._log_json(logging.DEBUG, msg, kwargs)
        else:
            super().debug(msg, *args, **kwargs)

    def _log_json(self, level, msg, kwargs):
        """
        Log in JSON format.

        Args:
            level: Log level (logging.INFO, etc.)
            msg: Message string
            kwargs: Keyword arguments with optional 'extra' dict
        """
        # Add JSON formatter to handler if not already present
        for handler in self.logger.handlers:
            if not isinstance(handler.formatter, StructuredFormatter):
                handler.setFormatter(StructuredFormatter())

        # Log with extra data
        self.logger.log(level, msg, extra=kwargs.get('extra', {}))


def get_dte_logger(name: str, extra: Optional[Dict[str, Any]] = None) -> DTELoggerAdapter:
    """
    Get a DTE logger with conditional JSON formatting.

    P3.1 GAP CLOSURE: Factory function for structured loggers.

    Usage:
        _logger = get_dte_logger(__name__)
        _logger.info("DTE sent", extra={"folio": 123, "track_id": "abc"})

    Args:
        name: Logger name (typically __name__)
        extra: Default extra fields to include in all logs

    Returns:
        DTELoggerAdapter: Logger with conditional JSON support
    """
    base_logger = logging.getLogger(name)
    return DTELoggerAdapter(base_logger, extra=extra)


def log_dte_operation(
    logger: DTELoggerAdapter,
    operation: str,
    level: str = "info",
    **kwargs
):
    """
    Log a DTE operation with standardized fields.

    P3.1 GAP CLOSURE: Convenience function for consistent DTE logging.

    Usage:
        log_dte_operation(
            _logger,
            "dte_generation",
            level="info",
            dte_type=33,
            folio=12345,
            rut_emisor="76123456-7",
            duration_ms=150
        )

    Args:
        logger: DTELoggerAdapter instance
        operation: Operation name (e.g., "dte_generation", "dte_signing")
        level: Log level ("info", "warning", "error", "debug")
        **kwargs: Additional fields to log
    """
    extra = {
        "operation": operation,
        **kwargs
    }

    log_method = getattr(logger, level.lower(), logger.info)
    log_method(f"DTE operation: {operation}", extra=extra)
