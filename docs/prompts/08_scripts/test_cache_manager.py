#!/usr/bin/env python3
"""
Unit Tests for Cache Manager
=============================

Comprehensive test suite with Git mock fixtures.

Tests:
- Cache key generation (SHA256 hashing)
- Cache storage and retrieval
- Compression effectiveness
- TTL expiration
- Git SHA invalidation
- Stats tracking
- Performance benchmarks

Author: Claude Code
Version: 1.0.0
Date: 2025-11-12
"""

import unittest
import tempfile
import shutil
import json
import gzip
import time
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import subprocess
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cache_manager import CacheManager, CacheMetadata, CacheEntry


class TestCacheKeyGeneration(unittest.TestCase):
    """Test cache key generation and hashing."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache_manager = CacheManager(cache_dir=self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_cache_key_deterministic(self, mock_git_sha):
        """Cache keys should be deterministic for same inputs."""
        mock_git_sha.return_value = "abc123def456"

        key1 = self.cache_manager._generate_cache_key("l10n_cl_dte", "v2.2")
        key2 = self.cache_manager._generate_cache_key("l10n_cl_dte", "v2.2")

        self.assertEqual(key1, key2)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_cache_key_different_modules(self, mock_git_sha):
        """Different modules should generate different keys."""
        mock_git_sha.return_value = "abc123def456"

        key1 = self.cache_manager._generate_cache_key("l10n_cl_dte", "v2.2")
        key2 = self.cache_manager._generate_cache_key("l10n_cl_fe", "v2.2")

        self.assertNotEqual(key1, key2)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_cache_key_different_versions(self, mock_git_sha):
        """Different template versions should generate different keys."""
        mock_git_sha.return_value = "abc123def456"

        key1 = self.cache_manager._generate_cache_key("l10n_cl_dte", "v2.2")
        key2 = self.cache_manager._generate_cache_key("l10n_cl_dte", "v2.3")

        self.assertNotEqual(key1, key2)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_cache_key_different_git_sha(self, mock_git_sha):
        """Different Git SHAs should generate different keys."""
        mock_git_sha.return_value = "abc123def456"
        key1 = self.cache_manager._generate_cache_key("l10n_cl_dte", "v2.2")

        mock_git_sha.return_value = "xyz789uvw012"
        key2 = self.cache_manager._generate_cache_key("l10n_cl_dte", "v2.2")

        self.assertNotEqual(key1, key2)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_cache_key_length(self, mock_git_sha):
        """Cache keys should be 16 characters (truncated SHA256)."""
        mock_git_sha.return_value = "abc123def456"
        key = self.cache_manager._generate_cache_key("l10n_cl_dte", "v2.2")

        self.assertEqual(len(key), 16)
        self.assertTrue(key.isalnum())


class TestCacheStorageRetrieval(unittest.TestCase):
    """Test cache storage and retrieval operations."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache_manager = CacheManager(cache_dir=self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_basic_storage_retrieval(self, mock_git_sha):
        """Should store and retrieve results correctly."""
        mock_git_sha.return_value = "abc123def456"

        result = {
            "findings": ["Issue 1", "Issue 2"],
            "score": 85,
            "status": "completed"
        }

        # Store
        success = self.cache_manager.set(
            "l10n_cl_dte",
            "v2.2",
            result,
            agent_used="test-agent",
            cost_usd=3.50,
            execution_time=120.5
        )

        self.assertTrue(success)

        # Retrieve
        cached = self.cache_manager.get("l10n_cl_dte", "v2.2")

        self.assertIsNotNone(cached)
        self.assertEqual(cached["findings"], result["findings"])
        self.assertEqual(cached["score"], result["score"])

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_cache_miss_nonexistent(self, mock_git_sha):
        """Should return None for nonexistent cache entry."""
        mock_git_sha.return_value = "abc123def456"

        cached = self.cache_manager.get("nonexistent_module", "v1.0")

        self.assertIsNone(cached)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_multiple_modules_isolated(self, mock_git_sha):
        """Different modules should have isolated cache entries."""
        mock_git_sha.return_value = "abc123def456"

        result1 = {"module": "module1"}
        result2 = {"module": "module2"}

        self.cache_manager.set("module1", "v2.2", result1)
        self.cache_manager.set("module2", "v2.2", result2)

        cached1 = self.cache_manager.get("module1", "v2.2")
        cached2 = self.cache_manager.get("module2", "v2.2")

        self.assertEqual(cached1["module"], "module1")
        self.assertEqual(cached2["module"], "module2")


class TestCacheCompression(unittest.TestCase):
    """Test compression effectiveness."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache_manager = CacheManager(cache_dir=self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_compression_ratio(self, mock_git_sha):
        """Compression ratio should be > 70% for typical JSON data."""
        mock_git_sha.return_value = "abc123def456"

        # Create large result with repetitive data (compresses well)
        result = {
            "findings": [
                {
                    "id": i,
                    "title": f"Finding {i}",
                    "description": "A" * 200,  # Repetitive data
                    "severity": "high"
                }
                for i in range(100)
            ],
            "metadata": {
                "timestamp": "2025-11-12T10:00:00",
                "module": "l10n_cl_dte"
            }
        }

        # Calculate original size
        original_json = json.dumps(result)
        original_size = len(original_json.encode('utf-8'))

        # Store in cache
        self.cache_manager.set("l10n_cl_dte", "v2.2", result)

        # Get compressed size
        cache_files = list(self.cache_dir.glob("cache_*.json.gz"))
        self.assertEqual(len(cache_files), 1)

        compressed_size = cache_files[0].stat().st_size

        # Calculate compression ratio
        compression_ratio = compressed_size / original_size

        print(f"\n  Original: {original_size / 1024:.2f} KB")
        print(f"  Compressed: {compressed_size / 1024:.2f} KB")
        print(f"  Ratio: {compression_ratio * 100:.1f}%")

        # Should compress to < 30% of original (70%+ compression)
        self.assertLess(compression_ratio, 0.30)


class TestCacheTTL(unittest.TestCase):
    """Test cache TTL and expiration."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache_manager = CacheManager(cache_dir=self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_expired_entry_returns_none(self, mock_git_sha):
        """Expired cache entries should return None."""
        mock_git_sha.return_value = "abc123def456"

        result = {"data": "test"}

        # Store entry
        self.cache_manager.set("l10n_cl_dte", "v2.2", result)

        # Manually modify timestamp to simulate expiration
        cache_files = list(self.cache_dir.glob("cache_*.json.gz"))
        self.assertEqual(len(cache_files), 1)

        # Load, modify timestamp, and re-save
        with gzip.open(cache_files[0], 'rt', encoding='utf-8') as f:
            data = json.load(f)

        # Set timestamp to 8 days ago (TTL is 7 days)
        old_timestamp = (datetime.now() - timedelta(days=8)).isoformat()
        data["metadata"]["timestamp"] = old_timestamp

        with gzip.open(cache_files[0], 'wt', encoding='utf-8') as f:
            json.dump(data, f)

        # Try to retrieve - should return None and delete file
        cached = self.cache_manager.get("l10n_cl_dte", "v2.2")

        self.assertIsNone(cached)

        # File should be deleted
        cache_files = list(self.cache_dir.glob("cache_*.json.gz"))
        self.assertEqual(len(cache_files), 0)


class TestGitInvalidation(unittest.TestCase):
    """Test Git SHA-based invalidation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache_manager = CacheManager(cache_dir=self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_git_sha_change_invalidates(self, mock_git_sha):
        """Changing Git SHA should invalidate cache."""
        # Store with first SHA
        mock_git_sha.return_value = "abc123def456"
        result = {"data": "test"}
        self.cache_manager.set("l10n_cl_dte", "v2.2", result)

        # Try to retrieve with different SHA
        mock_git_sha.return_value = "xyz789uvw012"
        cached = self.cache_manager.get("l10n_cl_dte", "v2.2")

        # Should return None (SHA mismatch)
        self.assertIsNone(cached)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_manual_invalidation(self, mock_git_sha):
        """Manual invalidation should delete all entries for module."""
        mock_git_sha.return_value = "abc123def456"

        # Store multiple versions
        self.cache_manager.set("l10n_cl_dte", "v2.2", {"v": "2.2"})
        self.cache_manager.set("l10n_cl_dte", "v2.3", {"v": "2.3"})

        # Verify stored
        self.assertIsNotNone(self.cache_manager.get("l10n_cl_dte", "v2.2"))

        # Invalidate
        success = self.cache_manager.invalidate("l10n_cl_dte")

        self.assertTrue(success)

        # Both should be gone
        self.assertIsNone(self.cache_manager.get("l10n_cl_dte", "v2.2"))
        self.assertIsNone(self.cache_manager.get("l10n_cl_dte", "v2.3"))


class TestCacheStats(unittest.TestCase):
    """Test statistics tracking."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache_manager = CacheManager(cache_dir=self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_hit_miss_tracking(self, mock_git_sha):
        """Should track cache hits and misses."""
        mock_git_sha.return_value = "abc123def456"

        # Initial stats
        stats = self.cache_manager.stats()
        self.assertEqual(stats.hit_count, 0)
        self.assertEqual(stats.miss_count, 0)

        # Generate miss
        self.cache_manager.get("l10n_cl_dte", "v2.2")
        stats = self.cache_manager.stats()
        self.assertEqual(stats.miss_count, 1)

        # Store and generate hit
        result = {"data": "test"}
        self.cache_manager.set("l10n_cl_dte", "v2.2", result, cost_usd=3.50)
        self.cache_manager.get("l10n_cl_dte", "v2.2")

        stats = self.cache_manager.stats()
        self.assertEqual(stats.hit_count, 1)
        self.assertEqual(stats.miss_count, 1)
        self.assertEqual(stats.hit_rate, 50.0)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_savings_tracking(self, mock_git_sha):
        """Should track cost savings."""
        mock_git_sha.return_value = "abc123def456"

        result = {"data": "test"}
        cost = 3.50

        # Store
        self.cache_manager.set("l10n_cl_dte", "v2.2", result, cost_usd=cost)

        # Generate hits
        for _ in range(5):
            self.cache_manager.get("l10n_cl_dte", "v2.2")

        stats = self.cache_manager.stats()

        # Should have saved 5 * $3.50 = $17.50
        self.assertEqual(stats.total_savings_usd, 5 * cost)


class TestCachePerformance(unittest.TestCase):
    """Test performance benchmarks."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache_manager = CacheManager(cache_dir=self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_cache_operation_overhead(self, mock_git_sha):
        """Cache operations should have < 50ms overhead."""
        mock_git_sha.return_value = "abc123def456"

        result = {"data": "test" * 100}

        # Test SET performance
        start = time.time()
        self.cache_manager.set("l10n_cl_dte", "v2.2", result)
        set_time = (time.time() - start) * 1000  # ms

        print(f"\n  SET time: {set_time:.2f} ms")
        self.assertLess(set_time, 50)

        # Test GET performance
        start = time.time()
        self.cache_manager.get("l10n_cl_dte", "v2.2")
        get_time = (time.time() - start) * 1000  # ms

        print(f"  GET time: {get_time:.2f} ms")
        self.assertLess(get_time, 50)


class TestCachePruning(unittest.TestCase):
    """Test cache pruning functionality."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.temp_dir) / "cache"
        self.cache_manager = CacheManager(cache_dir=self.cache_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch('cache_manager.CacheManager._get_git_sha')
    def test_prune_expired_entries(self, mock_git_sha):
        """Prune should delete expired entries."""
        mock_git_sha.return_value = "abc123def456"

        # Store multiple entries
        for i in range(5):
            self.cache_manager.set(f"module_{i}", "v2.2", {"data": i})

        # Manually age some entries
        cache_files = list(self.cache_dir.glob("cache_*.json.gz"))
        self.assertEqual(len(cache_files), 5)

        # Age first 3 entries
        for cache_file in cache_files[:3]:
            with gzip.open(cache_file, 'rt', encoding='utf-8') as f:
                data = json.load(f)

            old_timestamp = (datetime.now() - timedelta(days=8)).isoformat()
            data["metadata"]["timestamp"] = old_timestamp

            with gzip.open(cache_file, 'wt', encoding='utf-8') as f:
                json.dump(data, f)

        # Prune with 7-day TTL
        deleted = self.cache_manager.prune(days=7)

        self.assertEqual(deleted, 3)

        # Should have 2 entries left
        remaining = list(self.cache_dir.glob("cache_*.json.gz"))
        self.assertEqual(len(remaining), 2)


def run_tests():
    """Run all tests with verbose output."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCacheKeyGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestCacheStorageRetrieval))
    suite.addTests(loader.loadTestsFromTestCase(TestCacheCompression))
    suite.addTests(loader.loadTestsFromTestCase(TestCacheTTL))
    suite.addTests(loader.loadTestsFromTestCase(TestGitInvalidation))
    suite.addTests(loader.loadTestsFromTestCase(TestCacheStats))
    suite.addTests(loader.loadTestsFromTestCase(TestCachePerformance))
    suite.addTests(loader.loadTestsFromTestCase(TestCachePruning))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
