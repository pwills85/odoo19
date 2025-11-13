"""
Cache module for caching audit results and reducing API costs.

This module provides CacheManager for caching audit results based on
content hashes to avoid redundant API calls.
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Any, Dict
from pathlib import Path


class CacheManager:
    """
    Manage cache for audit results.

    Example:
        >>> cache = CacheManager()
        >>> cache_key = cache.get_cache_key("addons/l10n_cl_dte", "compliance")
        >>> if cache.has_valid_cache(cache_key):
        ...     result = cache.get(cache_key)
        ... else:
        ...     result = run_audit()
        ...     cache.set(cache_key, result)
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        ttl_hours: int = 24,
    ):
        """
        Initialize cache manager.

        Args:
            cache_dir: Directory to store cache files (default: ./.cache)
            ttl_hours: Cache time-to-live in hours (default: 24)
        """
        self.cache_dir = cache_dir or ".cache"
        self.ttl_hours = ttl_hours
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Ensure cache directory exists."""
        os.makedirs(self.cache_dir, exist_ok=True)

    def get_cache_key(
        self,
        module_path: str,
        dimension: str,
        model: str = "default",
        additional_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate cache key based on module content and parameters.

        Args:
            module_path: Path to module
            dimension: Audit dimension
            model: Model name
            additional_context: Additional context to include in hash

        Returns:
            Cache key (hex digest)
        """
        # Compute hash of module files
        module_hash = self._compute_module_hash(module_path)

        # Combine with parameters
        key_data = {
            "module_hash": module_hash,
            "dimension": dimension,
            "model": model,
            "context": additional_context or {},
        }

        # Generate cache key
        key_str = json.dumps(key_data, sort_keys=True)
        cache_key = hashlib.sha256(key_str.encode()).hexdigest()

        return cache_key

    def _compute_module_hash(self, module_path: str) -> str:
        """
        Compute hash of module files.

        Args:
            module_path: Path to module

        Returns:
            Hash of module contents
        """
        if not os.path.exists(module_path):
            return "not_found"

        # Collect all Python and XML files
        hasher = hashlib.sha256()
        file_count = 0

        for root, dirs, files in os.walk(module_path):
            # Skip __pycache__ and .git
            dirs[:] = [d for d in dirs if d not in ["__pycache__", ".git", ".pytest_cache"]]

            for file in sorted(files):
                if file.endswith((".py", ".xml")):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "rb") as f:
                            hasher.update(f.read())
                        file_count += 1
                    except Exception:
                        continue

        # Include file count in hash to detect additions/deletions
        hasher.update(str(file_count).encode())

        return hasher.hexdigest()

    def has_valid_cache(self, cache_key: str) -> bool:
        """
        Check if valid cache exists for key.

        Args:
            cache_key: Cache key

        Returns:
            True if valid cache exists
        """
        cache_path = self._get_cache_path(cache_key)

        if not os.path.exists(cache_path):
            return False

        # Check TTL
        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
                cached_at = datetime.fromisoformat(data["cached_at"])
                expires_at = cached_at + timedelta(hours=self.ttl_hours)

                if datetime.now() > expires_at:
                    # Cache expired
                    return False

                return True
        except Exception:
            return False

    def get(self, cache_key: str) -> Optional[Any]:
        """
        Get cached result.

        Args:
            cache_key: Cache key

        Returns:
            Cached result or None if not found/expired
        """
        if not self.has_valid_cache(cache_key):
            return None

        cache_path = self._get_cache_path(cache_key)

        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
                return data["result"]
        except Exception:
            return None

    def set(
        self,
        cache_key: str,
        result: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Store result in cache.

        Args:
            cache_key: Cache key
            result: Result to cache
            metadata: Additional metadata
        """
        cache_path = self._get_cache_path(cache_key)

        cache_data = {
            "cached_at": datetime.now().isoformat(),
            "cache_key": cache_key,
            "result": result,
            "metadata": metadata or {},
        }

        with open(cache_path, "w") as f:
            json.dump(cache_data, f, indent=2)

    def invalidate(self, cache_key: str) -> None:
        """
        Invalidate cache entry.

        Args:
            cache_key: Cache key
        """
        cache_path = self._get_cache_path(cache_key)

        if os.path.exists(cache_path):
            os.remove(cache_path)

    def clear_expired(self) -> int:
        """
        Clear all expired cache entries.

        Returns:
            Number of entries cleared
        """
        cleared = 0

        for filename in os.listdir(self.cache_dir):
            if not filename.endswith(".json"):
                continue

            cache_path = os.path.join(self.cache_dir, filename)

            try:
                with open(cache_path, "r") as f:
                    data = json.load(f)
                    cached_at = datetime.fromisoformat(data["cached_at"])
                    expires_at = cached_at + timedelta(hours=self.ttl_hours)

                    if datetime.now() > expires_at:
                        os.remove(cache_path)
                        cleared += 1
            except Exception:
                # Invalid cache file, remove it
                os.remove(cache_path)
                cleared += 1

        return cleared

    def clear_all(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries cleared
        """
        cleared = 0

        for filename in os.listdir(self.cache_dir):
            if filename.endswith(".json"):
                cache_path = os.path.join(self.cache_dir, filename)
                os.remove(cache_path)
                cleared += 1

        return cleared

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict with cache stats
        """
        total_entries = 0
        valid_entries = 0
        expired_entries = 0
        total_size_bytes = 0

        for filename in os.listdir(self.cache_dir):
            if not filename.endswith(".json"):
                continue

            cache_path = os.path.join(self.cache_dir, filename)
            total_entries += 1
            total_size_bytes += os.path.getsize(cache_path)

            try:
                with open(cache_path, "r") as f:
                    data = json.load(f)
                    cached_at = datetime.fromisoformat(data["cached_at"])
                    expires_at = cached_at + timedelta(hours=self.ttl_hours)

                    if datetime.now() > expires_at:
                        expired_entries += 1
                    else:
                        valid_entries += 1
            except Exception:
                expired_entries += 1

        return {
            "total_entries": total_entries,
            "valid_entries": valid_entries,
            "expired_entries": expired_entries,
            "total_size_mb": total_size_bytes / (1024 * 1024),
            "cache_dir": self.cache_dir,
            "ttl_hours": self.ttl_hours,
        }

    def _get_cache_path(self, cache_key: str) -> str:
        """Get file path for cache key."""
        return os.path.join(self.cache_dir, f"{cache_key}.json")
