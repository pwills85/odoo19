---
name: ML System Report
description: Technical reports for ML systems, model performance, and AI features
---

When responding in this style, format as technical ML documentation:

## System Overview
- **Model**: [Model name and version]
- **Task**: [Classification/Generation/Matching/etc.]
- **Architecture**: [System design]
- **Status**: [Development/Staging/Production]

## Performance Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Accuracy | 92.5% | ≥90% | ✅ Pass |
| Confidence (avg) | 87.3% | ≥80% | ✅ Pass |
| Latency (p95) | 2.1s | <3s | ✅ Pass |
| Cost per request | $0.003 | <$0.01 | ✅ Pass |

## Model Details

### Input Schema
```python
{
  "field1": "value",
  "field2": 123,
  "context": {...}
}
```

### Output Schema
```python
{
  "result": "prediction",
  "confidence": 85.0,
  "reasoning": "explanation"
}
```

### Confidence Thresholds
- ≥85%: Auto-apply prediction
- 70-84%: Suggest (require confirmation)
- <70%: Flag for manual review

## Implementation

**File**: `ai-service/path/to/file.py:line`

```python
# Code implementation with comments
async def predict(data: Dict) -> Dict:
    """Model prediction logic"""
    ...
```

## Optimization Opportunities

1. **Prompt Caching**: [Specific recommendations]
2. **Token Reduction**: [Output format improvements]
3. **Batch Processing**: [Bulk operation opportunities]

## Testing Strategy

### Unit Tests
- Test data validation
- Test edge cases
- Mock LLM responses

### Integration Tests
- End-to-end flow
- Error handling
- Performance benchmarks

### Evaluation Metrics
- Precision/Recall/F1
- Confusion matrix
- Cost per prediction
- Latency distribution

## Deployment Checklist

- [ ] Model performance meets thresholds
- [ ] Cost per request validated
- [ ] Error handling implemented
- [ ] Monitoring and alerting configured
- [ ] Documentation updated
- [ ] Rollback plan defined

## Cost Analysis

| Component | Monthly Cost | Optimization |
|-----------|--------------|--------------|
| Claude API calls | $X | Prompt caching |
| Redis cache | $Y | TTL tuning |
| Compute | $Z | Autoscaling |
| **Total** | **$XXX** | **Target: $XXX** |

## Monitoring

### Prometheus Metrics
```prometheus
model_predictions_total{model, outcome}
model_confidence_score{model}
model_latency_seconds{model}
model_cost_usd{model}
```

### Alerts
- Confidence drops below 70% (1 hour avg)
- Latency exceeds 5s (p95)
- Cost exceeds $X/day
- Error rate above 5%

## References
- Model documentation: [link]
- API endpoint: [link]
- Training data: [link]
- Evaluation results: [link]
