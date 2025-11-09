# -*- coding: utf-8 -*-
"""
Redis Helper - Singleton Client
================================

Provides singleton Redis client for the application.

Architecture:
- Single Redis connection pool
- Lazy initialization
- Thread-safe
- Configurable via environment variables
"""

import redis
import os
import structlog
from typing import Optional

logger = structlog.get_logger(__name__)

# Global singleton instance
_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    """
    Get or create Redis client singleton.

    Configuration from environment:
    - REDIS_HOST: Redis server host (default: 'redis')
    - REDIS_PORT: Redis server port (default: 6379)
    - REDIS_DB: Redis database number (default: 1)
    - REDIS_PASSWORD: Redis password (optional)

    Returns:
        Redis client instance

    Raises:
        redis.ConnectionError: If cannot connect to Redis
    """
    global _redis_client

    if _redis_client is None:
        host = os.getenv('REDIS_HOST', 'redis')
        port = int(os.getenv('REDIS_PORT', '6379'))
        db = int(os.getenv('REDIS_DB', '1'))
        password = os.getenv('REDIS_PASSWORD')

        logger.info("redis_client_initializing",
                   host=host,
                   port=port,
                   db=db,
                   has_password=bool(password))

        try:
            _redis_client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password if password else None,
                decode_responses=False,  # Binary mode for flexibility
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )

            # Test connection
            _redis_client.ping()

            logger.info("redis_client_initialized",
                       host=host,
                       port=port,
                       db=db)

        except redis.ConnectionError as e:
            logger.error("redis_connection_failed",
                        host=host,
                        port=port,
                        error=str(e))
            raise

        except Exception as e:
            logger.error("redis_initialization_failed",
                        error=str(e))
            raise

    return _redis_client


def reset_redis_client():
    """
    Reset Redis client (for testing purposes).

    Warning: Only use in tests!
    """
    global _redis_client

    if _redis_client:
        try:
            _redis_client.close()
        except Exception as e:
            logger.warning("redis_close_error", error=str(e))

    _redis_client = None
    logger.info("redis_client_reset")
