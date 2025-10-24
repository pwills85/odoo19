# -*- coding: utf-8 -*-
"""
Cost Tracker - Claude API Usage & Cost Monitoring
===================================================

Tracks token usage and costs for Anthropic Claude API calls.
Critical for production LLM services to monitor spend.

Features:
- Token usage tracking (input/output)
- Cost calculation per request
- Aggregated metrics
- Redis-backed persistence
- Prometheus metrics integration

Author: EERGYGROUP - Gap Closure Sprint
Date: 2025-10-23
"""

import structlog
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import json

logger = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════
# CLAUDE API PRICING (as of 2025-10-23)
# ═══════════════════════════════════════════════════════════

CLAUDE_PRICING = {
    # Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
    "claude-sonnet-4-5-20250929": {
        "input": 3.00 / 1_000_000,   # $3.00 per 1M input tokens
        "output": 15.00 / 1_000_000,  # $15.00 per 1M output tokens
    },
    # Claude 3.5 Sonnet (previous version)
    "claude-3-5-sonnet-20241022": {
        "input": 3.00 / 1_000_000,
        "output": 15.00 / 1_000_000,
    },
    # Fallback for unknown models
    "default": {
        "input": 3.00 / 1_000_000,
        "output": 15.00 / 1_000_000,
    }
}


@dataclass
class TokenUsage:
    """Token usage for a single API call"""
    input_tokens: int
    output_tokens: int
    total_tokens: int
    model: str
    cost_usd: float
    timestamp: str
    endpoint: str
    operation: str  # e.g., "dte_validation", "chat", "project_matching"


class CostTracker:
    """
    Tracks Claude API costs and token usage.

    Usage:
        tracker = CostTracker()

        # Record usage
        tracker.record_usage(
            input_tokens=150,
            output_tokens=450,
            model="claude-sonnet-4-5-20250929",
            endpoint="/api/dte/validate",
            operation="dte_validation"
        )

        # Get aggregated stats
        stats = tracker.get_stats(period="today")
        print(f"Today's cost: ${stats['total_cost_usd']:.4f}")
    """

    def __init__(self):
        """Initialize cost tracker with Redis backend"""
        self.redis_key_prefix = "cost_tracker"

    def record_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        model: str,
        endpoint: str,
        operation: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TokenUsage:
        """
        Record API usage and calculate cost.

        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            model: Model ID (e.g., "claude-sonnet-4-5-20250929")
            endpoint: API endpoint called
            operation: Operation type (e.g., "dte_validation")
            metadata: Optional additional context

        Returns:
            TokenUsage object with cost calculation
        """
        # Calculate cost
        pricing = CLAUDE_PRICING.get(model, CLAUDE_PRICING["default"])
        cost_usd = (
            input_tokens * pricing["input"] +
            output_tokens * pricing["output"]
        )

        total_tokens = input_tokens + output_tokens

        usage = TokenUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            model=model,
            cost_usd=cost_usd,
            timestamp=datetime.utcnow().isoformat(),
            endpoint=endpoint,
            operation=operation
        )

        # Log structured
        logger.info(
            "claude_api_usage",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cost_usd=round(cost_usd, 6),
            model=model,
            endpoint=endpoint,
            operation=operation,
            metadata=metadata or {}
        )

        # Persist to Redis
        self._persist_usage(usage)

        return usage

    def _persist_usage(self, usage: TokenUsage) -> None:
        """
        Persist usage to Redis for aggregation.

        Stores in multiple keys for different time periods:
        - cost_tracker:daily:{YYYY-MM-DD}
        - cost_tracker:monthly:{YYYY-MM}
        - cost_tracker:all_time
        """
        try:
            from utils.redis_helper import get_redis_client
            redis = get_redis_client()

            usage_dict = asdict(usage)
            timestamp = datetime.fromisoformat(usage.timestamp)

            # Daily key
            daily_key = f"{self.redis_key_prefix}:daily:{timestamp.strftime('%Y-%m-%d')}"
            redis.lpush(daily_key, json.dumps(usage_dict))
            redis.expire(daily_key, 86400 * 90)  # Keep 90 days

            # Monthly key
            monthly_key = f"{self.redis_key_prefix}:monthly:{timestamp.strftime('%Y-%m')}"
            redis.lpush(monthly_key, json.dumps(usage_dict))
            redis.expire(monthly_key, 86400 * 365)  # Keep 1 year

            # All-time counter
            counter_key = f"{self.redis_key_prefix}:counters"
            redis.hincrby(counter_key, "total_tokens", usage.total_tokens)
            redis.hincrby(counter_key, "total_calls", 1)
            redis.hincrbyfloat(counter_key, "total_cost_usd", usage.cost_usd)

        except Exception as e:
            logger.warning("cost_tracker_persist_failed", error=str(e))
            # Non-blocking: don't fail request if Redis unavailable

    def get_stats(self, period: str = "today") -> Dict[str, Any]:
        """
        Get aggregated statistics for a time period.

        Args:
            period: "today", "yesterday", "this_month", "all_time"

        Returns:
            Dict with aggregated stats:
            {
                "total_calls": int,
                "total_tokens": int,
                "total_input_tokens": int,
                "total_output_tokens": int,
                "total_cost_usd": float,
                "avg_tokens_per_call": float,
                "avg_cost_per_call": float,
                "by_operation": {...},
                "by_model": {...}
            }
        """
        try:
            from utils.redis_helper import get_redis_client
            redis = get_redis_client()

            # Determine Redis key
            now = datetime.utcnow()
            if period == "today":
                key = f"{self.redis_key_prefix}:daily:{now.strftime('%Y-%m-%d')}"
            elif period == "yesterday":
                yesterday = now - timedelta(days=1)
                key = f"{self.redis_key_prefix}:daily:{yesterday.strftime('%Y-%m-%d')}"
            elif period == "this_month":
                key = f"{self.redis_key_prefix}:monthly:{now.strftime('%Y-%m')}"
            elif period == "all_time":
                # Use counters for all-time
                counters = redis.hgetall(f"{self.redis_key_prefix}:counters")
                return {
                    "total_calls": int(counters.get(b"total_calls", 0)),
                    "total_tokens": int(counters.get(b"total_tokens", 0)),
                    "total_cost_usd": float(counters.get(b"total_cost_usd", 0.0))
                }
            else:
                raise ValueError(f"Invalid period: {period}")

            # Fetch all entries for period
            entries_raw = redis.lrange(key, 0, -1)
            entries = [json.loads(e) for e in entries_raw]

            if not entries:
                return {
                    "total_calls": 0,
                    "total_tokens": 0,
                    "total_input_tokens": 0,
                    "total_output_tokens": 0,
                    "total_cost_usd": 0.0,
                    "avg_tokens_per_call": 0.0,
                    "avg_cost_per_call": 0.0
                }

            # Aggregate
            total_calls = len(entries)
            total_tokens = sum(e["total_tokens"] for e in entries)
            total_input = sum(e["input_tokens"] for e in entries)
            total_output = sum(e["output_tokens"] for e in entries)
            total_cost = sum(e["cost_usd"] for e in entries)

            # By operation
            by_operation = {}
            for entry in entries:
                op = entry["operation"]
                if op not in by_operation:
                    by_operation[op] = {"calls": 0, "tokens": 0, "cost_usd": 0.0}
                by_operation[op]["calls"] += 1
                by_operation[op]["tokens"] += entry["total_tokens"]
                by_operation[op]["cost_usd"] += entry["cost_usd"]

            # By model
            by_model = {}
            for entry in entries:
                model = entry["model"]
                if model not in by_model:
                    by_model[model] = {"calls": 0, "tokens": 0, "cost_usd": 0.0}
                by_model[model]["calls"] += 1
                by_model[model]["tokens"] += entry["total_tokens"]
                by_model[model]["cost_usd"] += entry["cost_usd"]

            return {
                "total_calls": total_calls,
                "total_tokens": total_tokens,
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
                "total_cost_usd": round(total_cost, 6),
                "avg_tokens_per_call": round(total_tokens / total_calls, 2),
                "avg_cost_per_call": round(total_cost / total_calls, 6),
                "by_operation": by_operation,
                "by_model": by_model
            }

        except Exception as e:
            logger.error("cost_tracker_stats_failed", error=str(e))
            return {
                "error": str(e),
                "total_calls": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0
            }


# Global singleton
_tracker: Optional[CostTracker] = None


def get_cost_tracker() -> CostTracker:
    """Get global CostTracker instance"""
    global _tracker
    if _tracker is None:
        _tracker = CostTracker()
    return _tracker
