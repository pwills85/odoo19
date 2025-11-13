# -*- coding: utf-8 -*-
"""
Integration Tests Package (PHASE 1)
==================================

Comprehensive integration test suite for AI Microservice PHASE 1 features:

Test Modules:
- test_prompt_caching.py: Ephemeral cache, cost reduction, cache metrics
- test_streaming_sse.py: Server-Sent Events, progressive tokens, error handling
- test_token_precounting.py: Token estimation, cost validation, limit enforcement

Features Tested:
✅ Prompt Caching: ephemeral cache_control, cache_creation/read metrics
✅ Streaming SSE: real-time tokens, SSE format, [DONE] signal
✅ Token Pre-counting: estimate_tokens endpoint, cost prevention

Author: EERGYGROUP - Test Automation Sprint 2025-11-09
Markers: @pytest.mark.integration, @pytest.mark.api, @pytest.mark.async, @pytest.mark.slow
"""

