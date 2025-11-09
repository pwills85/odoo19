# -*- coding: utf-8 -*-
"""
Unit Tests - Cost Tracker
==========================

Tests for Claude API cost tracking.

Author: EERGYGROUP - Gap Closure Sprint
Date: 2025-10-23
"""

import pytest
from utils.cost_tracker import CostTracker, TokenUsage, CLAUDE_PRICING


class TestCostTracker:
    """Tests for CostTracker"""

    @pytest.fixture
    def tracker(self):
        """Fixture: CostTracker instance"""
        return CostTracker()

    def test_record_usage_calculation(self, tracker):
        """Test token usage recording and cost calculation"""
        usage = tracker.record_usage(
            input_tokens=100,
            output_tokens=200,
            model="claude-sonnet-4-5-20250929",
            endpoint="/api/dte/validate",
            operation="dte_validation"
        )

        assert usage.input_tokens == 100
        assert usage.output_tokens == 200
        assert usage.total_tokens == 300
        assert usage.model == "claude-sonnet-4-5-20250929"
        assert usage.operation == "dte_validation"

        # Check cost calculation
        expected_cost = (
            100 * CLAUDE_PRICING["claude-sonnet-4-5-20250929"]["input"] +
            200 * CLAUDE_PRICING["claude-sonnet-4-5-20250929"]["output"]
        )
        assert abs(usage.cost_usd - expected_cost) < 0.000001

    def test_record_usage_unknown_model(self, tracker):
        """Test recording usage for unknown model (should use default pricing)"""
        usage = tracker.record_usage(
            input_tokens=100,
            output_tokens=100,
            model="unknown-model",
            endpoint="/test",
            operation="test"
        )

        # Should not crash, should use default pricing
        assert usage.cost_usd > 0

    def test_token_usage_dataclass(self):
        """Test TokenUsage dataclass creation"""
        usage = TokenUsage(
            input_tokens=50,
            output_tokens=150,
            total_tokens=200,
            model="test-model",
            cost_usd=0.01,
            timestamp="2025-10-23T00:00:00",
            endpoint="/test",
            operation="test_op"
        )

        assert usage.input_tokens == 50
        assert usage.output_tokens == 150
        assert usage.total_tokens == 200


class TestPricing:
    """Tests for pricing constants"""

    def test_pricing_structure(self):
        """Test that pricing dict has correct structure"""
        assert "claude-sonnet-4-5-20250929" in CLAUDE_PRICING
        assert "default" in CLAUDE_PRICING

        model_pricing = CLAUDE_PRICING["claude-sonnet-4-5-20250929"]
        assert "input" in model_pricing
        assert "output" in model_pricing

        # Input should be cheaper than output
        assert model_pricing["input"] < model_pricing["output"]

    def test_cost_calculation_accuracy(self):
        """Test that cost calculation is accurate"""
        # 1M input tokens + 1M output tokens for Sonnet 4.5
        pricing = CLAUDE_PRICING["claude-sonnet-4-5-20250929"]

        input_cost = 1_000_000 * pricing["input"]
        output_cost = 1_000_000 * pricing["output"]

        # Should be $3.00 for input
        assert abs(input_cost - 3.0) < 0.01

        # Should be $15.00 for output
        assert abs(output_cost - 15.0) < 0.01
