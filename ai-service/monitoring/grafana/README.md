# Grafana Dashboards for AI Microservice

Complete monitoring and observability setup for the AI microservice.

## 📊 Dashboard Overview

This setup provides 4 comprehensive dashboards:
1. **Cost Overview** - Claude API costs and optimization metrics
2. **Performance** - Latency, throughput, and system health
3. **Model Accuracy** - AI model performance and confidence
4. **System Health** - Infrastructure and dependencies

## 🚀 Quick Setup

### Prerequisites
```bash
# Already in docker-compose.yml (verify)
docker-compose ps | grep -E 'prometheus|grafana'
```

### Access Dashboards
- **Grafana**: http://localhost:3000
- **Prometheus**: http://localhost:9090
- **AI Service Metrics**: http://localhost:8002/metrics

### Default Credentials
- Username: `admin`
- Password: `admin` (change on first login)

## 📈 Dashboard 1: Cost Overview

### Metrics Tracked
- Daily/weekly/monthly Claude API costs
- Cost breakdown by operation type
- Cache hit rate and savings
- Token usage (input/output/cache read)
- Cost per request trends
- Budget utilization

### Key Panels

**Panel 1: Total Daily Cost**
```promql
sum(increase(claude_api_cost_usd_total[24h]))
```

**Panel 2: Cost by Operation**
```promql
sum by (operation) (increase(claude_api_cost_usd_total[24h]))
```

**Panel 3: Cache Hit Rate**
```promql
sum(rate(claude_api_cache_hits_total[5m])) /
sum(rate(claude_api_calls_total[5m])) * 100
```

**Panel 4: Token Usage Breakdown**
```promql
sum by (type) (increase(claude_api_tokens_total[1h]))
```

**Panel 5: Cost Savings from Caching**
```promql
# Calculate savings (cache read vs full input cost)
(sum(increase(claude_api_cache_read_tokens_total[24h])) * 0.003 * 0.90) / 1000
```

### Alerts
- ⚠️ Daily cost > $20
- 🚨 Daily cost > $50
- ⚠️ Cache hit rate < 70%

## ⚡ Dashboard 2: Performance

### Metrics Tracked
- API latency (p50, p95, p99)
- Requests per second
- Error rates
- Circuit breaker state
- Active sessions
- Response times by endpoint

### Key Panels

**Panel 1: API Latency (p95)**
```promql
histogram_quantile(0.95,
  sum by (le, operation) (
    rate(claude_api_latency_seconds_bucket[5m])
  )
)
```

**Panel 2: Requests per Second**
```promql
sum(rate(claude_api_calls_total[1m]))
```

**Panel 3: Error Rate**
```promql
sum(rate(claude_api_calls_total{status="error"}[5m])) /
sum(rate(claude_api_calls_total[5m])) * 100
```

**Panel 4: Circuit Breaker State**
```promql
circuit_breaker_state{name="anthropic"}
```

**Panel 5: Time to First Token (Streaming)**
```promql
histogram_quantile(0.95,
  rate(streaming_first_token_seconds_bucket[5m])
)
```

### Alerts
- 🚨 p95 latency > 5s
- ⚠️ Error rate > 1%
- 🚨 Circuit breaker open

## 🎯 Dashboard 3: Model Accuracy

### Metrics Tracked
- Confidence score distribution
- Validation outcomes (approve/reject/review)
- Model accuracy trends
- Low confidence alerts
- Plugin selection accuracy

### Key Panels

**Panel 1: Average Confidence Score**
```promql
avg(ai_service_confidence_score)
```

**Panel 2: Confidence Distribution**
```promql
histogram_quantile(0.5,
  rate(ai_service_confidence_score_bucket[5m])
)
```

**Panel 3: DTE Validation Outcomes**
```promql
sum by (recommendation) (
  increase(ai_service_dte_validations_total[1h])
)
```

**Panel 4: Low Confidence Predictions**
```promql
count(ai_service_confidence_score < 70)
```

**Panel 5: Plugin Selection Frequency**
```promql
sum by (plugin) (
  increase(ai_service_plugin_selected_total[1h])
)
```

### Alerts
- ⚠️ Average confidence < 70% (1h)
- ⚠️ High rejection rate (>30%)

## 🏥 Dashboard 4: System Health

### Metrics Tracked
- Redis connection status
- Memory usage
- CPU usage
- Active sessions
- Queue depths
- Database connections

### Key Panels

**Panel 1: Redis Connection**
```promql
redis_connection_status
```

**Panel 2: Memory Usage**
```promql
process_resident_memory_bytes
```

**Panel 3: Active Sessions**
```promql
ai_service_active_sessions
```

**Panel 4: Request Queue Depth**
```promql
ai_service_queue_depth
```

### Alerts
- 🚨 Redis connection lost
- ⚠️ Memory usage > 2GB
- ⚠️ Queue depth > 100

## 🔧 Installation

### Step 1: Import Dashboards

1. Access Grafana: http://localhost:3000
2. Navigate to: Dashboards → Import
3. Import JSON files from `./dashboards/` directory:
   - `cost-overview.json`
   - `performance.json`
   - `model-accuracy.json`
   - `system-health.json`

### Step 2: Configure Data Source

```yaml
# datasource.yml (auto-configured in docker-compose)
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    url: http://prometheus:9090
    access: proxy
    isDefault: true
```

### Step 3: Configure Alerts

```yaml
# alert-rules.yml
groups:
  - name: ai_service_alerts
    interval: 1m
    rules:
      # Cost alerts
      - alert: DailyCostExceeded
        expr: sum(increase(claude_api_cost_usd_total[24h])) > 50
        for: 1h
        annotations:
          summary: "Daily AI cost exceeded $50"
          description: "Current cost: {{ $value }}"

      # Performance alerts
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(claude_api_latency_seconds_bucket[5m])) > 5
        for: 5m
        annotations:
          summary: "Claude API p95 latency > 5s"

      # Accuracy alerts
      - alert: LowConfidence
        expr: avg(ai_service_confidence_score) < 70
        for: 1h
        annotations:
          summary: "Average confidence dropped below 70%"

      # Cache alerts
      - alert: LowCacheHitRate
        expr: sum(rate(claude_api_cache_hits_total[5m])) / sum(rate(claude_api_calls_total[5m])) < 0.7
        for: 15m
        annotations:
          summary: "Cache hit rate below 70%"
```

## 📧 Alert Notifications

### Slack Integration
```yaml
# alertmanager.yml
route:
  receiver: 'slack-notifications'
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h

receivers:
  - name: 'slack-notifications'
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK_URL'
        channel: '#ai-service-alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}\n{{ end }}'
```

### Email Integration
```yaml
receivers:
  - name: 'email-notifications'
    email_configs:
      - to: 'your-email@example.com'
        from: 'alerts@example.com'
        smarthost: 'smtp.gmail.com:587'
        auth_username: 'your-email@example.com'
        auth_password: 'your-app-password'
```

## 🎨 Customization

### Adding Custom Panels

1. Edit Dashboard → Add Panel
2. Select Visualization type
3. Add PromQL query
4. Configure display options
5. Save dashboard

### Example Custom Panel: Cost per DTE Validation
```promql
sum(increase(claude_api_cost_usd_total{operation="dte_validation"}[24h])) /
sum(increase(ai_service_dte_validations_total[24h]))
```

## 📱 Mobile Access

Grafana dashboards are mobile-responsive. Access via:
- iOS: Grafana Mobile App
- Android: Grafana Mobile App
- Browser: http://localhost:3000

## 🔍 Troubleshooting

### Dashboard not loading
```bash
# Check Prometheus is scraping metrics
curl http://localhost:9090/api/v1/targets

# Verify AI service metrics endpoint
curl http://localhost:8002/metrics | grep claude_api
```

### No data in panels
```bash
# Check Prometheus data source configuration
# Grafana → Configuration → Data Sources → Prometheus
# Test connection

# Verify metrics are being exported
docker logs ai-service | grep "metrics"
```

### Alerts not firing
```bash
# Check alert rules loaded
curl http://localhost:9090/api/v1/rules

# Check Alertmanager status
curl http://localhost:9093/api/v2/status
```

## 📊 Best Practices

### Dashboard Design
1. **Group related metrics** - Keep cost, performance, accuracy separate
2. **Use colors consistently** - Green (good), Yellow (warning), Red (critical)
3. **Set reasonable time ranges** - Default to 1h, allow 24h/7d/30d
4. **Add descriptions** - Explain what each panel shows

### Query Optimization
1. **Use recording rules** - Pre-compute expensive queries
2. **Limit time ranges** - Don't query months of data
3. **Use rate() for counters** - Calculate per-second rates
4. **Aggregate before visualizing** - Reduce data points

### Alert Management
1. **Set appropriate thresholds** - Based on actual usage patterns
2. **Use 'for' clause** - Avoid alert flapping
3. **Group related alerts** - Don't spam with individual alerts
4. **Test alerts** - Manually trigger to verify delivery

## 🚀 Next Steps

1. ✅ Import all 4 dashboards
2. ✅ Configure Slack/Email notifications
3. ✅ Test alerts by triggering thresholds
4. ✅ Customize panels for your use case
5. ✅ Set up mobile access
6. ✅ Create runbook for alert responses

## 📚 Resources

- [Grafana Documentation](https://grafana.com/docs/)
- [PromQL Tutorial](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Best Practices](https://prometheus.io/docs/practices/)
- AI Service Metrics: `/ai-service/metrics.py`

## 🎯 Success Metrics

After setup, you should have:
- ✅ 4 working dashboards with live data
- ✅ Alerts configured and tested
- ✅ Notifications delivered to Slack/Email
- ✅ Mobile access configured
- ✅ Team trained on dashboard usage

**Monitoring is live!** 🎉
