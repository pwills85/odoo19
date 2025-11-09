# Grafana Dashboard JSON Files

## 📊 Available Dashboards

This directory will contain 4 pre-configured Grafana dashboards:

1. **cost-overview.json** - Claude API costs and optimization
2. **performance.json** - Latency, throughput, errors
3. **model-accuracy.json** - AI model performance
4. **system-health.json** - Infrastructure monitoring

## 🚀 How to Import

### Method 1: Grafana UI
1. Open Grafana: http://localhost:3000
2. Navigate to: **Dashboards** → **Import**
3. Click **Upload JSON file**
4. Select a dashboard JSON file
5. Select **Prometheus** as data source
6. Click **Import**

### Method 2: API
```bash
# Import dashboard via API
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @cost-overview.json
```

### Method 3: Provisioning (Automatic)
Add to docker-compose.yml:

```yaml
grafana:
  volumes:
    - ./ai-service/monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    - ./ai-service/monitoring/grafana/datasource.yml:/etc/grafana/provisioning/datasources/datasource.yml:ro
```

Restart Grafana:
```bash
docker-compose restart grafana
```

## 🎨 Creating Dashboard JSONs

To create the dashboard JSON files, you have two options:

### Option 1: Export from Grafana
1. Create dashboard manually in Grafana UI
2. Click **Dashboard settings** (gear icon)
3. Select **JSON Model**
4. Copy JSON
5. Save to this directory

### Option 2: Use Template Generator

We've provided a Python script to generate dashboard JSONs:

```bash
python3 ../scripts/generate_dashboards.py
```

This will create all 4 dashboard JSON files based on the metrics defined in the AI service.

## 📋 Dashboard Specifications

### Cost Overview Dashboard

**Panels:**
- Total Daily Cost (Single Stat)
- Cost Trend (Line Chart)
- Cost by Operation (Pie Chart)
- Cache Hit Rate (Gauge)
- Token Usage (Bar Chart)
- Cache Savings (Single Stat)

**Time Range:** Last 24 hours (default)

### Performance Dashboard

**Panels:**
- API Latency p95 (Line Chart)
- Requests per Second (Graph)
- Error Rate (Graph)
- Circuit Breaker State (Indicator)
- Time to First Token (Histogram)
- Active Sessions (Single Stat)

**Time Range:** Last 1 hour (default)

### Model Accuracy Dashboard

**Panels:**
- Average Confidence (Gauge)
- Confidence Distribution (Histogram)
- Validation Outcomes (Pie Chart)
- Low Confidence Count (Single Stat)
- Plugin Selection Frequency (Bar Chart)
- Accuracy Trend (Line Chart)

**Time Range:** Last 6 hours (default)

### System Health Dashboard

**Panels:**
- Redis Status (Indicator)
- Memory Usage (Graph)
- CPU Usage (Graph)
- Active Sessions (Graph)
- Queue Depth (Graph)
- Service Uptime (Single Stat)

**Time Range:** Last 30 minutes (default)

## 🔧 Customization

After importing, you can customize:
- Panel positions and sizes
- Color schemes
- Alert thresholds
- Time ranges
- Refresh intervals

## 📚 Panel Query Examples

### Cost Panel
```promql
sum(increase(claude_api_cost_usd_total[24h]))
```

### Latency Panel
```promql
histogram_quantile(0.95,
  sum by (le) (rate(claude_api_latency_seconds_bucket[5m]))
)
```

### Cache Hit Rate Panel
```promql
sum(rate(claude_api_cache_hits_total[5m])) /
sum(rate(claude_api_calls_total[5m])) * 100
```

### Confidence Score Panel
```promql
avg(ai_service_confidence_score)
```

## 🎯 Next Steps

1. Import all 4 dashboards
2. Verify data is displaying correctly
3. Configure alert thresholds
4. Set up Slack/Email notifications
5. Share dashboard URLs with team

## 📖 Resources

- [Grafana Dashboard Documentation](https://grafana.com/docs/grafana/latest/dashboards/)
- [PromQL Queries](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- AI Service Metrics: `http://localhost:8002/metrics`
- Prometheus: `http://localhost:9090`

---

**Note**: Dashboard JSON files are large (typically 50-200 KB each). For now, create them using the Grafana UI and export, or use the dashboard generator script.
