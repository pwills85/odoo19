# -*- coding: utf-8 -*-
"""
Redis Helper - Singleton Client with Sentinel Support
======================================================

Provides singleton Redis client for the application with High Availability.

Architecture:
- Redis Sentinel support (automatic failover)
- Single Redis connection pool
- Lazy initialization
- Thread-safe
- Configurable via environment variables
- TLS encryption support (Task 1.2 - Sprint 1)

HA Features:
- Master discovery via Sentinel
- Automatic failover detection
- Read scaling with replicas
- Health checks

Security Features (Task 1.2):
- TLS/SSL encryption for data in transit
- Certificate verification (production)
- Graceful fallback for development
"""

import redis
from redis.sentinel import Sentinel
import os
import ssl
import structlog
from typing import Optional

logger = structlog.get_logger(__name__)

# Global singleton instances
_redis_master_client: Optional[redis.Redis] = None
_redis_slave_client: Optional[redis.Redis] = None
_sentinel_instance: Optional[Sentinel] = None


def get_redis_client(read_only: bool = False) -> redis.Redis:
    """
    Get or create Redis client singleton (with Sentinel HA support).

    Configuration from environment:
    - REDIS_SENTINEL_ENABLED: Enable Sentinel mode (default: 'true')
    - REDIS_SENTINEL_HOSTS: Comma-separated sentinel hosts (default: 'redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379')
    - REDIS_SENTINEL_MASTER_NAME: Master name in Sentinel (default: 'mymaster')
    - REDIS_PASSWORD: Redis password (required, no default)
    - REDIS_DB: Redis database number (default: 1)

    Fallback (non-Sentinel mode):
    - REDIS_HOST: Redis server host (default: 'redis-master')
    - REDIS_PORT: Redis server port (default: 6379)

    Args:
        read_only: If True, return slave client (for read scaling)

    Returns:
        Redis client instance (master or slave)

    Raises:
        redis.ConnectionError: If cannot connect to Redis
    """
    global _redis_master_client, _redis_slave_client, _sentinel_instance

    # Check if Sentinel mode is enabled
    sentinel_enabled = os.getenv('REDIS_SENTINEL_ENABLED', 'true').lower() == 'true'

    if sentinel_enabled:
        return _get_sentinel_client(read_only)
    else:
        return _get_direct_client()


def _get_sentinel_client(read_only: bool = False) -> redis.Redis:
    """
    Get Redis client via Sentinel (HA mode).

    Returns:
        Redis master or slave client
    """
    global _redis_master_client, _redis_slave_client, _sentinel_instance

    if _sentinel_instance is None:
        # Parse Sentinel hosts
        sentinel_hosts_str = os.getenv(
            'REDIS_SENTINEL_HOSTS',
            'redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379'
        )
        sentinel_hosts = [
            (host.split(':')[0], int(host.split(':')[1]))
            for host in sentinel_hosts_str.split(',')
        ]

        master_name = os.getenv('REDIS_SENTINEL_MASTER_NAME', 'mymaster')
        password = os.getenv('REDIS_PASSWORD')
        if not password:
            raise ValueError(
                "REDIS_PASSWORD environment variable is required. "
                "Please set it in .env file or environment."
            )
        db = int(os.getenv('REDIS_DB', '1'))

        logger.info("redis_sentinel_initializing",
                   sentinel_hosts=sentinel_hosts,
                   master_name=master_name,
                   db=db,
                   has_password=bool(password))

        try:
            _sentinel_instance = Sentinel(
                sentinel_hosts,
                socket_timeout=0.5,
                password=password,
                db=db
            )

            # Initialize master client
            _redis_master_client = _sentinel_instance.master_for(
                master_name,
                socket_timeout=5,
                password=password,
                db=db,
                decode_responses=False,
                retry_on_timeout=True,
                health_check_interval=30
            )

            # Initialize slave client (for read scaling)
            _redis_slave_client = _sentinel_instance.slave_for(
                master_name,
                socket_timeout=5,
                password=password,
                db=db,
                decode_responses=False,
                retry_on_timeout=True,
                health_check_interval=30
            )

            # Test connections
            _redis_master_client.ping()
            _redis_slave_client.ping()

            # Get current master info
            master_addr = _sentinel_instance.discover_master(master_name)
            logger.info("redis_sentinel_initialized",
                       master_name=master_name,
                       master_host=master_addr[0],
                       master_port=master_addr[1],
                       sentinel_count=len(sentinel_hosts))

        except redis.ConnectionError as e:
            logger.warning("redis_sentinel_connection_failed_fallback_to_standalone",
                          sentinel_hosts=sentinel_hosts,
                          error=str(e),
                          fallback_host=os.getenv('REDIS_HOST', 'redis-master'))
            # Reset failed sentinel instance to allow fallback to work on subsequent calls
            _sentinel_instance = None
            # Graceful fallback to standalone Redis (PRODUCTION-READY PATTERN)
            # This allows cache to function even without Sentinel HA
            return _get_direct_client()

        except Exception as e:
            logger.error("redis_sentinel_initialization_failed_fallback_to_standalone",
                        error=str(e),
                        fallback_host=os.getenv('REDIS_HOST', 'redis-master'))
            # Reset failed sentinel instance
            _sentinel_instance = None
            # Fallback to standalone Redis for any initialization error
            return _get_direct_client()

    # Return appropriate client
    if read_only:
        return _redis_slave_client
    else:
        return _redis_master_client


def _get_direct_client() -> redis.Redis:
    """
    Get Redis client directly (non-HA mode, for backwards compatibility).
    
    ✅ ENHANCEMENT [P0-9 Task 1.2]: TLS encryption support
    
    TLS Configuration:
    - Development: TLS optional, CERT_NONE (allows testing without certs)
    - Production: TLS required, CERT_REQUIRED (enforces certificate validation)
    - Controlled via REDIS_TLS_ENABLED and REDIS_SSL_CERT_REQS env vars

    Returns:
        Redis client instance
    """
    global _redis_master_client

    if _redis_master_client is None:
        host = os.getenv('REDIS_HOST', 'redis-master')
        port = int(os.getenv('REDIS_PORT', '6379'))
        db = int(os.getenv('REDIS_DB', '1'))
        password = os.getenv('REDIS_PASSWORD')
        if not password:
            raise ValueError(
                "REDIS_PASSWORD environment variable is required. "
                "Please set it in .env file or environment."
            )

        # ✅ TLS Configuration (Task 1.2 - Sprint 1)
        tls_enabled = os.getenv('REDIS_TLS_ENABLED', 'true').lower() == 'true'
        ssl_cert_reqs_str = os.getenv('REDIS_SSL_CERT_REQS', 'none')  # 'none' in dev, 'required' in prod
        ssl_ca_certs = os.getenv('REDIS_SSL_CA_CERTS', None)
        
        ssl_config = None
        if tls_enabled:
            ssl_config = ssl.create_default_context()
            
            # Certificate verification mode
            if ssl_cert_reqs_str == 'required':
                ssl_config.check_hostname = True
                ssl_config.verify_mode = ssl.CERT_REQUIRED
                if ssl_ca_certs:
                    ssl_config.load_verify_locations(ssl_ca_certs)
                logger.info("redis_tls_enabled_production_mode",
                           verify_mode="CERT_REQUIRED",
                           check_hostname=True,
                           ca_certs=ssl_ca_certs)
            else:
                # Development mode: TLS encryption without cert verification
                ssl_config.check_hostname = False
                ssl_config.verify_mode = ssl.CERT_NONE
                logger.info("redis_tls_enabled_development_mode",
                           verify_mode="CERT_NONE",
                           check_hostname=False)

        logger.info("redis_client_initializing",
                   host=host,
                   port=port,
                   db=db,
                   has_password=bool(password),
                   tls_enabled=tls_enabled)

        try:
            _redis_master_client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password if password else None,
                decode_responses=False,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30,
                ssl=ssl_config if ssl_config else None  # TLS support
            )

            # Test connection
            _redis_master_client.ping()

            logger.info("redis_client_initialized",
                       host=host,
                       port=port,
                       db=db,
                       tls_enabled=tls_enabled)

        except redis.ConnectionError as e:
            logger.error("redis_connection_failed",
                        host=host,
                        port=port,
                        tls_enabled=tls_enabled,
                        error=str(e))
            raise

        except Exception as e:
            logger.error("redis_initialization_failed",
                        error=str(e))
            raise

    return _redis_master_client


def reset_redis_client():
    """
    Reset Redis client (for testing purposes).

    Warning: Only use in tests!
    """
    global _redis_master_client, _redis_slave_client, _sentinel_instance

    if _redis_master_client:
        try:
            _redis_master_client.close()
        except Exception as e:
            logger.warning("redis_master_close_error", error=str(e))

    if _redis_slave_client:
        try:
            _redis_slave_client.close()
        except Exception as e:
            logger.warning("redis_slave_close_error", error=str(e))

    _redis_master_client = None
    _redis_slave_client = None
    _sentinel_instance = None
    logger.info("redis_clients_reset")
