---
name: API Cost Report
description: Detailed cost analysis for Claude API and other external services
---

Format responses as comprehensive cost analysis:

## Cost Summary

**Period**: [Date range]
**Total Cost**: $XXX.XX
**Budget**: $XXX.XX
**Status**: ✅ Within budget / ⚠️ Over budget

## Cost Breakdown by Operation

| Operation | Calls | Input Tokens | Output Tokens | Cache Read | Cost |
|-----------|-------|--------------|---------------|------------|------|
| chat_stream | 1,247 | 3.2M | 850K | 2.7M (85%) | $12.45 |
| dte_validation | 320 | 420K | 48K | 380K (90%) | $0.96 |
| project_matching | 180 | 145K | 36K | 98K (68%) | $0.67 |
| **Total** | **1,747** | **3.8M** | **934K** | **3.2M (84%)** | **$14.08** |

## Cache Performance

**Cache Hit Rate**: 84.2% ✅
**Cache Read Tokens**: 3,178,293
**Cache Write Tokens**: 628,150
**Savings from Caching**: $9.53 (90% reduction)

## Cost Optimization Opportunities

### 1. Implement Batch API (HIGH PRIORITY)
**Impact**: -50% cost on bulk operations
**Effort**: 2 days
**Savings**: ~$6/month on DTE validations

### 2. Reduce Output Tokens (MEDIUM PRIORITY)
**Current avg**: 534 tokens/response
**Target**: 300 tokens/response (-44%)
**Method**: More compact JSON format
**Savings**: ~$2.50/month

### 3. Increase Cache TTL (LOW PRIORITY)
**Current**: 5 minutes
**Proposed**: 15 minutes
**Risk**: Slightly stale responses
**Savings**: ~$1/month

## Cost Trends

```
Week 1: $78.50  (baseline)
Week 2: $8.45   (after caching) ↓ 89%
Week 3: $7.92   (streaming added)
Week 4: $14.08  (2x traffic) ✅ Still under budget
```

## Token Usage Analysis

### By Model
| Model | Calls | Tokens | Avg/Call | Cost |
|-------|-------|--------|----------|------|
| Claude Sonnet 4.5 | 1,747 | 4.7M | 2,692 | $14.08 |

### By Token Type
- Input tokens: 3,765,293 (80%)
- Output tokens: 934,150 (20%)
- Cache read tokens: 3,178,293 (don't count toward rate limit)

## Budget Forecast

**Current burn rate**: $14/day
**Monthly projection**: $420
**Annual projection**: $5,040
**vs. Pre-optimization**: $50,400 (90% savings maintained)

## Recommendations

1. **Immediate**: Monitor cache hit rate daily
2. **This week**: Implement batch API for DTE validations
3. **This month**: Optimize output token usage
4. **Next quarter**: Explore Haiku model for simpler tasks

## Alert Thresholds

- Daily cost > $20: ⚠️ Warning
- Daily cost > $50: 🚨 Alert (stop non-critical operations)
- Cache hit rate < 70%: ⚠️ Warning (investigate)
- Avg tokens/call > 4,000: ⚠️ Review prompt efficiency
