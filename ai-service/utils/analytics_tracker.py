# -*- coding: utf-8 -*-
"""
Analytics Tracker - Project Matching & Analytics Metrics
=========================================================

Tracks analytics metrics for AI-powered features like project matching.
Provides real-time statistics and insights into AI service usage.

Features:
- Real-time suggestion tracking
- Confidence score aggregation
- Project matching statistics
- Top projects ranking
- Redis-backed persistence
- Prometheus metrics integration

Author: EERGYGROUP - P0-1 Implementation
Date: 2025-11-11
"""

import structlog
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import json

logger = structlog.get_logger(__name__)


@dataclass
class SuggestionRecord:
    """Record of a single project suggestion"""
    project_id: Optional[int]
    project_name: Optional[str]
    confidence: float
    partner_id: int
    partner_name: str
    company_id: int
    timestamp: str
    reasoning: str


class AnalyticsTracker:
    """
    Tracks analytics metrics for AI-powered project matching.

    Metrics tracked:
    - Total suggestions made
    - Average confidence score
    - Total projects matched
    - Top matched projects
    - Confidence distribution (high/medium/low)

    Redis keys:
    - analytics:total_suggestions (int)
    - analytics:confidence_sum (float)
    - analytics:confidence_count (int)
    - analytics:projects_matched:{project_id} (int)
    - analytics:suggestion_history:{timestamp} (json)

    Usage:
        tracker = AnalyticsTracker()

        # Track a suggestion
        result = {
            "project_id": 5,
            "project_name": "Proyecto A",
            "confidence": 87.5,
            "reasoning": "High confidence match..."
        }
        tracker.track_suggestion(result, partner_id=123, company_id=1)

        # Get stats
        stats = tracker.get_stats()
        print(f"Total suggestions: {stats['total_suggestions']}")
        print(f"Avg confidence: {stats['avg_confidence']:.2f}%")
    """

    def __init__(self):
        """Initialize analytics tracker with Redis backend"""
        self.redis_key_prefix = "analytics"
        self._redis_client = None

    @property
    def redis_client(self):
        """Lazy load Redis client to avoid import issues"""
        if self._redis_client is None:
            from utils.redis_helper import get_redis_client
            self._redis_client = get_redis_client()
        return self._redis_client

    def track_suggestion(
        self,
        result: Dict[str, Any],
        partner_id: int,
        partner_name: str,
        company_id: int,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SuggestionRecord:
        """
        Track a project suggestion made by the AI.

        Args:
            result: Suggestion result from ProjectMatcherClaude
                Expected keys: project_id, project_name, confidence, reasoning
            partner_id: Partner/vendor ID from Odoo
            partner_name: Partner/vendor name
            company_id: Company ID from Odoo
            metadata: Optional metadata (invoice lines, etc.)

        Returns:
            SuggestionRecord with tracked data

        Raises:
            ValueError: If result missing required keys
            redis.RedisError: If Redis operation fails
        """
        # Validate input
        if not isinstance(result, dict):
            raise ValueError("result must be a dictionary")

        required_keys = ["project_id", "project_name", "confidence", "reasoning"]
        missing_keys = [key for key in required_keys if key not in result]
        if missing_keys:
            raise ValueError(f"result missing required keys: {missing_keys}")

        confidence = float(result["confidence"])
        if not (0 <= confidence <= 100):
            raise ValueError(f"confidence must be 0-100, got {confidence}")

        try:
            # Create suggestion record
            suggestion = SuggestionRecord(
                project_id=result["project_id"],
                project_name=result["project_name"],
                confidence=confidence,
                partner_id=partner_id,
                partner_name=partner_name,
                company_id=company_id,
                timestamp=datetime.utcnow().isoformat(),
                reasoning=result["reasoning"]
            )

            # Increment total suggestions counter
            self.increment_counter("total_suggestions")

            # Track confidence score
            self._track_confidence(confidence)

            # Track project match (if project was suggested)
            if suggestion.project_id is not None:
                self._track_project_match(suggestion.project_id, suggestion.project_name)

            # Store suggestion in history (for audit/analysis)
            self._store_suggestion_history(suggestion, metadata)

            logger.info(
                "analytics_suggestion_tracked",
                project_id=suggestion.project_id,
                project_name=suggestion.project_name,
                confidence=confidence,
                partner_id=partner_id,
                company_id=company_id
            )

            return suggestion

        except Exception as e:
            logger.error(
                "analytics_tracking_failed",
                error=str(e),
                error_type=type(e).__name__,
                partner_id=partner_id,
                company_id=company_id
            )
            raise

    def increment_counter(self, counter_name: str, increment: int = 1) -> int:
        """
        Increment a counter in Redis.

        Args:
            counter_name: Name of counter (e.g., "total_suggestions")
            increment: Amount to increment by (default: 1)

        Returns:
            New counter value

        Raises:
            redis.RedisError: If Redis operation fails
        """
        key = f"{self.redis_key_prefix}:{counter_name}"
        try:
            new_value = self.redis_client.incrby(key, increment)
            logger.debug(
                "analytics_counter_incremented",
                counter=counter_name,
                new_value=new_value,
                increment=increment
            )
            return new_value
        except Exception as e:
            logger.error(
                "analytics_counter_increment_failed",
                counter=counter_name,
                error=str(e)
            )
            raise

    def get_counter(self, counter_name: str) -> int:
        """
        Get current counter value.

        Args:
            counter_name: Name of counter

        Returns:
            Current counter value (0 if not exists)
        """
        key = f"{self.redis_key_prefix}:{counter_name}"
        try:
            value = self.redis_client.get(key)
            return int(value) if value else 0
        except Exception as e:
            logger.error(
                "analytics_counter_get_failed",
                counter=counter_name,
                error=str(e)
            )
            return 0

    def _track_confidence(self, confidence: float) -> None:
        """
        Track confidence score for averaging.

        Uses sum + count pattern for efficient averaging without storing all values.

        Args:
            confidence: Confidence score (0-100)
        """
        # Increment confidence sum
        sum_key = f"{self.redis_key_prefix}:confidence_sum"
        self.redis_client.incrbyfloat(sum_key, confidence)

        # Increment confidence count
        count_key = f"{self.redis_key_prefix}:confidence_count"
        self.redis_client.incr(count_key)

    def _track_project_match(self, project_id: int, project_name: str) -> None:
        """
        Track a project match.

        Increments counter for specific project and stores project metadata.

        Args:
            project_id: Project ID from Odoo
            project_name: Project name
        """
        # Increment project-specific counter
        match_key = f"{self.redis_key_prefix}:projects_matched:{project_id}"
        self.redis_client.incr(match_key)

        # Store project metadata (for display in stats)
        meta_key = f"{self.redis_key_prefix}:project_meta:{project_id}"
        self.redis_client.set(meta_key, project_name)

    def _store_suggestion_history(
        self,
        suggestion: SuggestionRecord,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store suggestion in history for audit/analysis.

        Uses Redis sorted set with timestamp as score for time-based queries.

        Args:
            suggestion: Suggestion record
            metadata: Optional metadata to store
        """
        history_key = f"{self.redis_key_prefix}:suggestion_history"

        # Create history entry
        entry = asdict(suggestion)
        if metadata:
            entry["metadata"] = metadata

        # Add to sorted set (timestamp as score)
        timestamp_score = datetime.fromisoformat(suggestion.timestamp).timestamp()
        self.redis_client.zadd(
            history_key,
            {json.dumps(entry, default=str): timestamp_score}
        )

        # Keep only last 10,000 suggestions (to prevent unbounded growth)
        self.redis_client.zremrangebyrank(history_key, 0, -10001)

    def get_stats(
        self,
        limit_top_projects: int = 10
    ) -> Dict[str, Any]:
        """
        Get aggregated analytics statistics.

        Args:
            limit_top_projects: Number of top projects to return (default: 10)

        Returns:
            Dictionary with analytics stats:
            {
                "total_suggestions": 1523,
                "avg_confidence": 78.5,
                "projects_matched": 342,
                "top_projects": [
                    {"id": 5, "name": "Proyecto A", "matches": 89},
                    {"id": 12, "name": "Proyecto B", "matches": 67},
                    ...
                ],
                "confidence_distribution": {
                    "high": 45,    # ≥85%
                    "medium": 40,  # 70-84%
                    "low": 15      # <70%
                }
            }
        """
        try:
            # Get total suggestions
            total_suggestions = self.get_counter("total_suggestions")

            # Calculate average confidence
            confidence_sum = float(self.redis_client.get(
                f"{self.redis_key_prefix}:confidence_sum"
            ) or 0)
            confidence_count = int(self.redis_client.get(
                f"{self.redis_key_prefix}:confidence_count"
            ) or 0)
            avg_confidence = (
                confidence_sum / confidence_count
                if confidence_count > 0
                else 0.0
            )

            # Get top matched projects
            top_projects = self._get_top_projects(limit_top_projects)

            # Calculate total unique projects matched
            projects_matched = len(self._get_all_matched_projects())

            # Get confidence distribution
            confidence_distribution = self._get_confidence_distribution()

            stats = {
                "total_suggestions": total_suggestions,
                "avg_confidence": round(avg_confidence, 2),
                "projects_matched": projects_matched,
                "top_projects": top_projects,
                "confidence_distribution": confidence_distribution
            }

            logger.info(
                "analytics_stats_retrieved",
                total_suggestions=total_suggestions,
                avg_confidence=avg_confidence,
                projects_matched=projects_matched
            )

            return stats

        except Exception as e:
            logger.error("analytics_stats_retrieval_failed", error=str(e))
            # Return empty stats on error
            return {
                "total_suggestions": 0,
                "avg_confidence": 0.0,
                "projects_matched": 0,
                "top_projects": [],
                "confidence_distribution": {"high": 0, "medium": 0, "low": 0},
                "error": str(e)
            }

    def _get_top_projects(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get top N matched projects sorted by match count.

        Args:
            limit: Number of top projects to return

        Returns:
            List of dicts with project info and match count
        """
        try:
            # Get all project match keys
            pattern = f"{self.redis_key_prefix}:projects_matched:*"
            cursor = 0
            project_counts = []

            # Scan for all project match keys
            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor,
                    match=pattern,
                    count=100
                )

                for key in keys:
                    # Extract project ID from key
                    project_id = int(key.decode('utf-8').split(':')[-1])

                    # Get match count
                    match_count = int(self.redis_client.get(key) or 0)

                    # Get project name
                    meta_key = f"{self.redis_key_prefix}:project_meta:{project_id}"
                    project_name = self.redis_client.get(meta_key)
                    if isinstance(project_name, bytes):
                        project_name = project_name.decode('utf-8')

                    project_counts.append({
                        "id": project_id,
                        "name": project_name or f"Project {project_id}",
                        "matches": match_count
                    })

                if cursor == 0:
                    break

            # Sort by match count descending and limit
            top_projects = sorted(
                project_counts,
                key=lambda x: x["matches"],
                reverse=True
            )[:limit]

            return top_projects

        except Exception as e:
            logger.error("analytics_top_projects_failed", error=str(e))
            return []

    def _get_all_matched_projects(self) -> List[int]:
        """
        Get list of all project IDs that have been matched.

        Returns:
            List of project IDs
        """
        try:
            pattern = f"{self.redis_key_prefix}:projects_matched:*"
            cursor = 0
            project_ids = []

            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor,
                    match=pattern,
                    count=100
                )

                for key in keys:
                    project_id = int(key.decode('utf-8').split(':')[-1])
                    project_ids.append(project_id)

                if cursor == 0:
                    break

            return project_ids

        except Exception as e:
            logger.error("analytics_all_projects_failed", error=str(e))
            return []

    def _get_confidence_distribution(self) -> Dict[str, int]:
        """
        Get distribution of confidence levels from recent suggestions.

        Confidence buckets:
        - high: ≥85%
        - medium: 70-84%
        - low: <70%

        Returns:
            Dict with counts per bucket
        """
        try:
            # Get recent suggestions from history (last 1000)
            history_key = f"{self.redis_key_prefix}:suggestion_history"
            recent_suggestions = self.redis_client.zrevrange(
                history_key,
                0,
                999,
                withscores=False
            )

            distribution = {"high": 0, "medium": 0, "low": 0}

            for suggestion_json in recent_suggestions:
                try:
                    if isinstance(suggestion_json, bytes):
                        suggestion_json = suggestion_json.decode('utf-8')

                    suggestion = json.loads(suggestion_json)
                    confidence = suggestion.get("confidence", 0)

                    if confidence >= 85:
                        distribution["high"] += 1
                    elif confidence >= 70:
                        distribution["medium"] += 1
                    else:
                        distribution["low"] += 1

                except Exception as e:
                    logger.warning(
                        "analytics_distribution_parse_failed",
                        error=str(e)
                    )
                    continue

            # Convert to percentages if we have data
            total = sum(distribution.values())
            if total > 0:
                distribution = {
                    k: round(v / total * 100)
                    for k, v in distribution.items()
                }

            return distribution

        except Exception as e:
            logger.error("analytics_distribution_failed", error=str(e))
            return {"high": 0, "medium": 0, "low": 0}

    def clear_stats(self) -> int:
        """
        Clear all analytics statistics (for testing or reset).

        Returns:
            Number of keys deleted

        Warning:
            This will delete all analytics data. Use with caution.
        """
        try:
            pattern = f"{self.redis_key_prefix}:*"
            cursor = 0
            deleted = 0

            while True:
                cursor, keys = self.redis_client.scan(
                    cursor=cursor,
                    match=pattern,
                    count=100
                )

                if keys:
                    deleted += self.redis_client.delete(*keys)

                if cursor == 0:
                    break

            logger.info(
                "analytics_stats_cleared",
                keys_deleted=deleted
            )

            return deleted

        except Exception as e:
            logger.error("analytics_clear_failed", error=str(e))
            return 0


import threading

# ✅ FIX [H4 CICLO3]: Thread-safe singleton with Lock
_analytics_lock = threading.Lock()

def get_analytics_tracker() -> AnalyticsTracker:
    """
    Get global analytics tracker instance (thread-safe singleton pattern).

    Returns:
        AnalyticsTracker instance
    """
    if not hasattr(get_analytics_tracker, "_instance"):
        with _analytics_lock:  # ✅ Thread-safe double-check locking
            if not hasattr(get_analytics_tracker, "_instance"):
                get_analytics_tracker._instance = AnalyticsTracker()
    return get_analytics_tracker._instance
