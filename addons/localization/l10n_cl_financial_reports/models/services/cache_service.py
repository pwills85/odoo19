
# -*- coding: utf-8 -*-
'''Advanced Cache Service with Redis support'''

import json
import hashlib
import logging
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)

class CacheService:
    '''High-performance cache service'''

    def __init__(self):
        self.redis_client = self._init_redis()
        self.memory_cache = {}
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'writes': 0
        }

    def _init_redis(self):
        '''Initialize Redis connection'''
        try:
            import redis
            client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            client.ping()
            _logger.info("Redis cache connected successfully")
            return client
        except Exception as e:
            _logger.warning(f"Redis not available, using memory cache: {e}")
            return None

    def _build_key(self, key, company_id=None):
        '''Build namespaced cache key'''
        if company_id:
            return f"finrep:{company_id}:{key}"
        return f"finrep:global:{key}"

    def get(self, key, company_id=None):
        '''Get value from cache with company namespacing'''
        namespaced_key = self._build_key(key, company_id)

        # Try Redis first
        if self.redis_client:
            try:
                value = self.redis_client.get(namespaced_key)
                if value:
                    self.cache_stats['hits'] += 1
                    return json.loads(value)
            except Exception as e:
                _logger.debug(f"Redis get error: {e}")

        # Fallback to memory cache
        if namespaced_key in self.memory_cache:
            entry = self.memory_cache[namespaced_key]
            if entry['expires'] > datetime.now():
                self.cache_stats['hits'] += 1
                return entry['value']
            else:
                del self.memory_cache[namespaced_key]

        self.cache_stats['misses'] += 1
        return None

    def set(self, key, value, ttl=900, company_id=None):
        '''Set value in cache with TTL and company namespacing (default TTL: 15min)'''
        namespaced_key = self._build_key(key, company_id)
        self.cache_stats['writes'] += 1

        # Store in Redis
        if self.redis_client:
            try:
                self.redis_client.setex(
                    namespaced_key,
                    ttl,
                    json.dumps(value)
                )
            except Exception as e:
                _logger.debug(f"Redis set error: {e}")

        # Also store in memory cache
        self.memory_cache[namespaced_key] = {
            'value': value,
            'expires': datetime.now() + timedelta(seconds=ttl)
        }

    def invalidate(self, pattern=None):
        '''Invalidate cache entries by pattern (e.g., "finrep:1:*" or "finrep:*:f29_*")'''
        if pattern:
            # Ensure pattern includes finrep namespace
            if not pattern.startswith('finrep:'):
                pattern = f'finrep:*:{pattern}'

            # Pattern-based invalidation
            if self.redis_client:
                try:
                    for key in self.redis_client.scan_iter(pattern):
                        self.redis_client.delete(key)
                except Exception as e:
                    _logger.debug(f"Redis invalidate error: {e}")

            # Memory cache invalidation
            keys_to_delete = [k for k in self.memory_cache if pattern.replace('*', '') in k]
            for key in keys_to_delete:
                del self.memory_cache[key]
        else:
            # Clear all finrep cache
            if self.redis_client:
                try:
                    for key in self.redis_client.scan_iter('finrep:*'):
                        self.redis_client.delete(key)
                except Exception as e:
                    _logger.debug(f"Redis flush error: {e}")

            # Clear only finrep entries in memory
            keys_to_delete = [k for k in self.memory_cache if k.startswith('finrep:')]
            for key in keys_to_delete:
                del self.memory_cache[key]

    def get_stats(self):
        '''Get cache statistics'''
        total = self.cache_stats['hits'] + self.cache_stats['misses']
        hit_ratio = (self.cache_stats['hits'] / total * 100) if total > 0 else 0

        return {
            'hit_ratio': hit_ratio,
            'hits': self.cache_stats['hits'],
            'misses': self.cache_stats['misses'],
            'writes': self.cache_stats['writes'],
            'memory_entries': len(self.memory_cache),
            'redis_available': bool(self.redis_client)
        }

    def warm_cache(self, models_to_warm):
        '''Pre-warm cache with frequently accessed data'''
        _logger.info("Starting cache warming...")

        warm_configs = {
            'l10n_cl_f29': {
                'method': '_get_recent_f29_data',
                'ttl': 7200
            },
            'l10n_cl_f22': {
                'method': '_get_recent_f22_data',
                'ttl': 86400
            },
            'financial.dashboard': {
                'method': '_get_dashboard_configs',
                'ttl': 3600
            }
        }

        for model_name, config in warm_configs.items():
            try:
                model = self.env[model_name]
                if hasattr(model, config['method']):
                    data = getattr(model, config['method'])()
                    cache_key = f"{model_name}_warm_{hashlib.md5(str(data).encode()).hexdigest()}"
                    self.set(cache_key, data, config['ttl'])
                    _logger.info(f"Cache warmed for {model_name}")
            except Exception as e:
                _logger.warning(f"Cache warming failed for {model_name}: {e}")

# Global cache instance
_cache_service = None

def get_cache_service():
    '''Get or create cache service instance'''
    global _cache_service
    if _cache_service is None:
        _cache_service = CacheService()
    return _cache_service
