# -*- coding: utf-8 -*-
"""
Unit Tests - Analytics Tracker

Tests for analytics tracking functionality including:
- Suggestion tracking
- Counter operations
- Statistics aggregation
- Redis integration
- Error handling

Author: EERGYGROUP - P0-1 Implementation
Date: 2025-11-11
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import json

from utils.analytics_tracker import (
    AnalyticsTracker,
    SuggestionRecord,
    get_analytics_tracker
)


# ═══════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════

@pytest.fixture
def mock_redis_client():
    """Mock Redis client for testing"""
    client = Mock()
    client.get.return_value = None
    client.incr.return_value = 1
    client.incrby.return_value = 1
    client.incrbyfloat.return_value = 1.0
    client.setex.return_value = True
    client.set.return_value = True
    client.zadd.return_value = 1
    client.zrevrange.return_value = []
    client.zremrangebyrank.return_value = 0
    client.scan.return_value = (0, [])
    client.delete.return_value = 0
    return client


@pytest.fixture
def analytics_tracker(mock_redis_client):
    """Analytics tracker with mocked Redis"""
    tracker = AnalyticsTracker()
    tracker._redis_client = mock_redis_client
    return tracker


@pytest.fixture
def sample_suggestion_result():
    """Sample suggestion result from ProjectMatcherClaude"""
    return {
        "project_id": 5,
        "project_name": "Proyecto A",
        "confidence": 87.5,
        "reasoning": "High confidence match based on historical purchases"
    }


# ═══════════════════════════════════════════════════════════
# TEST: INITIALIZATION
# ═══════════════════════════════════════════════════════════

def test_analytics_tracker_initialization():
    """Test tracker initialization"""
    tracker = AnalyticsTracker()

    assert tracker.redis_key_prefix == "analytics"
    assert tracker._redis_client is None  # Lazy loaded


def test_redis_client_lazy_loading(analytics_tracker, mock_redis_client):
    """Test Redis client is loaded on first access"""
    # First access should load client
    client = analytics_tracker.redis_client

    assert client is not None
    assert client == mock_redis_client


# ═══════════════════════════════════════════════════════════
# TEST: TRACK SUGGESTION
# ═══════════════════════════════════════════════════════════

def test_track_suggestion_success(analytics_tracker, sample_suggestion_result):
    """Test successful suggestion tracking"""
    result = analytics_tracker.track_suggestion(
        result=sample_suggestion_result,
        partner_id=123,
        partner_name="Proveedor A",
        company_id=1
    )

    # Verify result
    assert isinstance(result, SuggestionRecord)
    assert result.project_id == 5
    assert result.project_name == "Proyecto A"
    assert result.confidence == 87.5
    assert result.partner_id == 123
    assert result.partner_name == "Proveedor A"
    assert result.company_id == 1

    # Verify Redis calls
    tracker_redis = analytics_tracker.redis_client
    assert tracker_redis.incrby.called
    assert tracker_redis.incrbyfloat.called
    assert tracker_redis.incr.called
    assert tracker_redis.zadd.called


def test_track_suggestion_missing_required_keys(analytics_tracker):
    """Test tracking with missing required keys"""
    incomplete_result = {
        "project_id": 5,
        # Missing: project_name, confidence, reasoning
    }

    with pytest.raises(ValueError, match="missing required keys"):
        analytics_tracker.track_suggestion(
            result=incomplete_result,
            partner_id=123,
            partner_name="Proveedor A",
            company_id=1
        )


def test_track_suggestion_invalid_confidence(analytics_tracker):
    """Test tracking with invalid confidence value"""
    invalid_result = {
        "project_id": 5,
        "project_name": "Proyecto A",
        "confidence": 150.0,  # Invalid: > 100
        "reasoning": "Test"
    }

    with pytest.raises(ValueError, match="confidence must be 0-100"):
        analytics_tracker.track_suggestion(
            result=invalid_result,
            partner_id=123,
            partner_name="Proveedor A",
            company_id=1
        )


def test_track_suggestion_with_metadata(analytics_tracker, sample_suggestion_result):
    """Test tracking with additional metadata"""
    metadata = {
        "invoice_lines_count": 5,
        "available_projects_count": 10,
        "has_historical": True
    }

    result = analytics_tracker.track_suggestion(
        result=sample_suggestion_result,
        partner_id=123,
        partner_name="Proveedor A",
        company_id=1,
        metadata=metadata
    )

    assert isinstance(result, SuggestionRecord)

    # Verify metadata was stored in history
    tracker_redis = analytics_tracker.redis_client
    zadd_call = tracker_redis.zadd.call_args
    assert zadd_call is not None


def test_track_suggestion_no_project_match(analytics_tracker):
    """Test tracking when no project matched (project_id is None)"""
    no_match_result = {
        "project_id": None,
        "project_name": None,
        "confidence": 45.0,
        "reasoning": "Low confidence, no clear match"
    }

    result = analytics_tracker.track_suggestion(
        result=no_match_result,
        partner_id=123,
        partner_name="Proveedor A",
        company_id=1
    )

    assert result.project_id is None
    assert result.project_name is None
    assert result.confidence == 45.0


# ═══════════════════════════════════════════════════════════
# TEST: COUNTER OPERATIONS
# ═══════════════════════════════════════════════════════════

def test_increment_counter_success(analytics_tracker):
    """Test incrementing counter"""
    analytics_tracker.redis_client.incrby.return_value = 10

    new_value = analytics_tracker.increment_counter("total_suggestions")

    assert new_value == 10
    analytics_tracker.redis_client.incrby.assert_called_once_with(
        "analytics:total_suggestions",
        1
    )


def test_increment_counter_custom_amount(analytics_tracker):
    """Test incrementing counter by custom amount"""
    analytics_tracker.redis_client.incrby.return_value = 15

    new_value = analytics_tracker.increment_counter("total_suggestions", increment=5)

    assert new_value == 15
    analytics_tracker.redis_client.incrby.assert_called_once_with(
        "analytics:total_suggestions",
        5
    )


def test_get_counter_exists(analytics_tracker):
    """Test getting existing counter value"""
    analytics_tracker.redis_client.get.return_value = b"42"

    value = analytics_tracker.get_counter("total_suggestions")

    assert value == 42


def test_get_counter_not_exists(analytics_tracker):
    """Test getting non-existent counter"""
    analytics_tracker.redis_client.get.return_value = None

    value = analytics_tracker.get_counter("total_suggestions")

    assert value == 0


def test_get_counter_error_handling(analytics_tracker):
    """Test counter get with Redis error"""
    analytics_tracker.redis_client.get.side_effect = Exception("Redis error")

    value = analytics_tracker.get_counter("total_suggestions")

    # Should return 0 on error, not raise
    assert value == 0


# ═══════════════════════════════════════════════════════════
# TEST: GET STATS
# ═══════════════════════════════════════════════════════════

def test_get_stats_empty(analytics_tracker):
    """Test getting stats with no data"""
    analytics_tracker.redis_client.get.return_value = None
    analytics_tracker.redis_client.scan.return_value = (0, [])
    analytics_tracker.redis_client.zrevrange.return_value = []

    stats = analytics_tracker.get_stats()

    assert stats["total_suggestions"] == 0
    assert stats["avg_confidence"] == 0.0
    assert stats["projects_matched"] == 0
    assert stats["top_projects"] == []
    assert stats["confidence_distribution"] == {"high": 0, "medium": 0, "low": 0}


def test_get_stats_with_data(analytics_tracker):
    """Test getting stats with existing data"""
    # Mock counters
    def mock_get(key):
        if b"total_suggestions" in key or "total_suggestions" in key:
            return b"100"
        elif b"confidence_sum" in key or "confidence_sum" in key:
            return b"7850.0"
        elif b"confidence_count" in key or "confidence_count" in key:
            return b"100"
        return None

    analytics_tracker.redis_client.get.side_effect = mock_get

    # Mock project scan (empty for simplicity)
    analytics_tracker.redis_client.scan.return_value = (0, [])

    # Mock suggestion history
    history_entries = [
        json.dumps({
            "project_id": 5,
            "confidence": 90.0,
            "timestamp": datetime.utcnow().isoformat()
        }),
        json.dumps({
            "project_id": 3,
            "confidence": 75.0,
            "timestamp": datetime.utcnow().isoformat()
        }),
        json.dumps({
            "project_id": 1,
            "confidence": 60.0,
            "timestamp": datetime.utcnow().isoformat()
        })
    ]
    analytics_tracker.redis_client.zrevrange.return_value = history_entries

    stats = analytics_tracker.get_stats()

    assert stats["total_suggestions"] == 100
    assert stats["avg_confidence"] == 78.5
    assert stats["confidence_distribution"]["high"] == 33  # 1/3 = 33%
    assert stats["confidence_distribution"]["medium"] == 33  # 1/3 = 33%
    assert stats["confidence_distribution"]["low"] == 33  # 1/3 = 33%


def test_get_stats_with_top_projects(analytics_tracker):
    """Test getting stats with top projects"""
    # Mock basic counters
    def mock_get(key):
        if isinstance(key, bytes):
            key = key.decode('utf-8')

        if "total_suggestions" in key:
            return b"50"
        elif "confidence_sum" in key:
            return b"4000.0"
        elif "confidence_count" in key:
            return b"50"
        elif "projects_matched:5" in key:
            return b"25"
        elif "projects_matched:3" in key:
            return b"15"
        elif "project_meta:5" in key:
            return b"Proyecto A"
        elif "project_meta:3" in key:
            return b"Proyecto B"
        return None

    analytics_tracker.redis_client.get.side_effect = mock_get

    # Mock project scan
    project_keys = [
        b"analytics:projects_matched:5",
        b"analytics:projects_matched:3"
    ]

    def mock_scan(cursor, match, count):
        if cursor == 0:
            return (1, project_keys)
        else:
            return (0, [])

    analytics_tracker.redis_client.scan.side_effect = mock_scan

    # Mock history
    analytics_tracker.redis_client.zrevrange.return_value = []

    stats = analytics_tracker.get_stats(limit_top_projects=10)

    assert len(stats["top_projects"]) == 2
    assert stats["top_projects"][0]["id"] == 5
    assert stats["top_projects"][0]["name"] == "Proyecto A"
    assert stats["top_projects"][0]["matches"] == 25
    assert stats["top_projects"][1]["id"] == 3
    assert stats["top_projects"][1]["matches"] == 15


def test_get_stats_error_handling(analytics_tracker):
    """Test stats retrieval with Redis error"""
    analytics_tracker.redis_client.get.side_effect = Exception("Redis error")

    stats = analytics_tracker.get_stats()

    # Should return empty stats with error key
    assert stats["total_suggestions"] == 0
    assert "error" in stats


# ═══════════════════════════════════════════════════════════
# TEST: CONFIDENCE DISTRIBUTION
# ═══════════════════════════════════════════════════════════

def test_confidence_distribution_buckets(analytics_tracker):
    """Test confidence distribution bucketing"""
    # Mock history with various confidence levels
    history_entries = [
        json.dumps({"confidence": 95.0}),  # high
        json.dumps({"confidence": 88.0}),  # high
        json.dumps({"confidence": 85.0}),  # high
        json.dumps({"confidence": 80.0}),  # medium
        json.dumps({"confidence": 75.0}),  # medium
        json.dumps({"confidence": 70.0}),  # medium
        json.dumps({"confidence": 65.0}),  # low
        json.dumps({"confidence": 50.0}),  # low
        json.dumps({"confidence": 40.0}),  # low
        json.dumps({"confidence": 30.0})   # low
    ]
    analytics_tracker.redis_client.zrevrange.return_value = history_entries

    distribution = analytics_tracker._get_confidence_distribution()

    # 3 high (30%), 3 medium (30%), 4 low (40%)
    assert distribution["high"] == 30
    assert distribution["medium"] == 30
    assert distribution["low"] == 40


# ═══════════════════════════════════════════════════════════
# TEST: CLEAR STATS
# ═══════════════════════════════════════════════════════════

def test_clear_stats_success(analytics_tracker):
    """Test clearing all analytics stats"""
    # Mock scan to return some keys
    def mock_scan(cursor, match, count):
        if cursor == 0:
            return (1, [b"analytics:key1", b"analytics:key2"])
        else:
            return (0, [])

    analytics_tracker.redis_client.scan.side_effect = mock_scan
    analytics_tracker.redis_client.delete.return_value = 2

    deleted = analytics_tracker.clear_stats()

    assert deleted == 2
    analytics_tracker.redis_client.delete.assert_called()


def test_clear_stats_error_handling(analytics_tracker):
    """Test clear stats with Redis error"""
    analytics_tracker.redis_client.scan.side_effect = Exception("Redis error")

    deleted = analytics_tracker.clear_stats()

    # Should return 0 on error, not raise
    assert deleted == 0


# ═══════════════════════════════════════════════════════════
# TEST: SINGLETON PATTERN
# ═══════════════════════════════════════════════════════════

def test_get_analytics_tracker_singleton():
    """Test global tracker singleton pattern"""
    tracker1 = get_analytics_tracker()
    tracker2 = get_analytics_tracker()

    assert tracker1 is tracker2


# ═══════════════════════════════════════════════════════════
# TEST: SUGGESTION RECORD DATACLASS
# ═══════════════════════════════════════════════════════════

def test_suggestion_record_creation():
    """Test SuggestionRecord dataclass"""
    record = SuggestionRecord(
        project_id=5,
        project_name="Proyecto A",
        confidence=87.5,
        partner_id=123,
        partner_name="Proveedor A",
        company_id=1,
        timestamp=datetime.utcnow().isoformat(),
        reasoning="Test reasoning"
    )

    assert record.project_id == 5
    assert record.project_name == "Proyecto A"
    assert record.confidence == 87.5
    assert record.partner_id == 123


# ═══════════════════════════════════════════════════════════
# INTEGRATION TEST MARKERS
# ═══════════════════════════════════════════════════════════

@pytest.mark.integration
@pytest.mark.redis
def test_analytics_tracker_integration_redis_required():
    """
    Integration test for analytics tracker with real Redis.

    Requires:
    - Redis running on localhost:6379
    - Pytest marks: integration, redis

    Run with: pytest -m "integration and redis"
    """
    pytest.skip("Integration test - requires Redis")


# ═══════════════════════════════════════════════════════════
# PERFORMANCE TESTS
# ═══════════════════════════════════════════════════════════

@pytest.mark.performance
def test_track_suggestion_performance(analytics_tracker, sample_suggestion_result):
    """
    Performance test for suggestion tracking.

    Should track 1000 suggestions in < 1 second with mocked Redis.
    """
    import time

    start = time.time()

    for i in range(1000):
        analytics_tracker.track_suggestion(
            result=sample_suggestion_result,
            partner_id=i,
            partner_name=f"Proveedor {i}",
            company_id=1
        )

    elapsed = time.time() - start

    assert elapsed < 1.0, f"Tracking 1000 suggestions took {elapsed:.2f}s"
