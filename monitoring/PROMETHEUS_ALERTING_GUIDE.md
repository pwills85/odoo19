# Prometheus Alerting Guide

**Project:** Odoo 19 - Chilean Localization Stack
**Component:** Monitoring & Alerting
**Created:** 2025-11-09
**Version:** 1.0.0

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Alert Rules Reference](#alert-rules-reference)
3. [Alert Severity Levels](#alert-severity-levels)
4. [Deployment Guide](#deployment-guide)
5. [Testing Alerts](#testing-alerts)
6. [Troubleshooting](#troubleshooting)
7. [Runbooks](#runbooks)

---

## Architecture Overview

```
┌──────────────────────────────────────────┐
│          Prometheus Server               │
│  (Scraping + Evaluation + Alerting)     │
│                                          │
│  ┌─────────────┐      ┌──────────────┐  │
│  │ Scraping    │      │ Alert Rules  │  │
│  │ (15s)       │─────▶│ Evaluation   │  │
│  └─────────────┘      └──────────────┘  │
│         │                     │          │
│         ▼                     ▼          │
│  ┌─────────────┐      ┌──────────────┐  │
│  │ Targets     │      │ Alertmanager │  │
│  │ - ai-service│      │ (Routing)    │  │
│  │ - redis-*   │      └──────────────┘  │
│  │ - odoo      │             │          │
│  │ - postgres  │             ▼          │
│  └─────────────┘      ┌──────────────┐  │
│                       │ Receivers    │  │
│                       │ - Slack      │  │
│                       │ - Email      │  │
│                       │ - PagerDuty  │  │
│                       └──────────────┘  │
└──────────────────────────────────────────┘
```

### Components

**Prometheus:**
- Scraping: Collects metrics from targets every 15s
- Evaluation: Evaluates alert rules every 15s
- TSDB: 15 days retention, 10GB max size
- Port: 9090

**Alertmanager:**
- Routing: Routes alerts to correct receivers
- Grouping: Groups related alerts together
- Inhibition: Prevents alert spam
- Port: 9093

**Scrape Targets:**
- `ai-service:8002/metrics` - AI microservice
- `redis-master:6379` - Redis master
- `redis-replica-1:6379`, `redis-replica-2:6379` - Replicas
- `redis-sentinel-1:26379`, `sentinel-2`, `sentinel-3` - Sentinels
- `odoo:8069/metrics` - Odoo (if exposed)
- `db:5432/metrics` - PostgreSQL (if exposed)

---

## Alert Rules Reference

### Critical Alerts (Severity: critical)

#### 1. RedisDown
**Description:** Redis master is unreachable
**Threshold:** `up{job="redis-master"} == 0`
**For:** 1 minute
**Impact:** All AI requests bypass cache → 3-5x latency & cost increase
**Runbook:** [Redis Down](#runbook-redis-down)

#### 2. AnthropicAPIDown
**Description:** Anthropic API unreachable or erroring
**Threshold:** `>10 errors in 2 minutes`
**For:** 2 minutes
**Impact:** All AI chat requests fail → Business continuity affected
**Runbook:** [Anthropic API Down](#runbook-anthropic-api-down)

### Warning Alerts (Severity: warning)

#### 3. RedisReplicaDown
**Description:** At least one Redis replica is down
**Threshold:** `count(up{job="redis-replica"} == 0) >= 1`
**For:** 5 minutes
**Impact:** Reduced redundancy → Manual intervention if master fails
**Runbook:** [Redis Replica Down](#runbook-redis-replica-down)

#### 4. HighErrorRate
**Description:** HTTP 5xx error rate >10%
**Threshold:** `(5xx / total) * 100 > 10`
**For:** 2 minutes
**Impact:** User experience degraded
**Runbook:** [High Error Rate](#runbook-high-error-rate)

#### 5. DailyCostExceeded
**Description:** Daily AI cost exceeded $50 budget
**Threshold:** `ai_service_daily_cost_usd > 50`
**For:** 5 minutes
**Impact:** Budget overrun → Review usage patterns
**Runbook:** [Daily Cost Exceeded](#runbook-daily-cost-exceeded)

#### 6. HighLatency
**Description:** P95 latency >1 second
**Threshold:** `histogram_quantile(0.95, ...) > 1.0`
**For:** 5 minutes
**Impact:** User experience degraded
**Runbook:** [High Latency](#runbook-high-latency)

#### 7. PluginLoadFailure
**Description:** One or more plugins failed to load
**Threshold:** `ai_service_plugin_load_failures_total > 0`
**For:** 1 minute
**Impact:** Reduced AI capabilities
**Runbook:** [Plugin Load Failure](#runbook-plugin-load-failure)

#### 8. RedisSentinelDegraded
**Description:** Less than 2 Sentinels available
**Threshold:** `redis_sentinel_known_sentinels < 2`
**For:** 3 minutes
**Impact:** Automatic failover at risk
**Runbook:** [Sentinel Degraded](#runbook-sentinel-degraded)

#### 9. KnowledgeBaseEmpty
**Description:** Knowledge base has no documents loaded
**Threshold:** `ai_service_knowledge_base_documents == 0`
**For:** 5 minutes
**Impact:** AI responses lack domain context (SII, DTE, payroll)
**Runbook:** [Knowledge Base Empty](#runbook-knowledge-base-empty)

### Info Alerts (Severity: info)

#### 10. LowCacheHitRate
**Description:** Cache hit rate below 50%
**Threshold:** `(hits / total) * 100 < 50`
**For:** 10 minutes
**Impact:** Increased latency and cost
**Runbook:** [Low Cache Hit Rate](#runbook-low-cache-hit-rate)

---

## Alert Severity Levels

### CRITICAL (severity: critical)
**Response Time:** Immediate (5s group wait)
**Notification:** Slack #critical-alerts + PagerDuty
**Repeat Interval:** Every 4 hours if not resolved
**Expected Action:** Incident response, rollback if needed

**Alerts:**
- RedisDown
- AnthropicAPIDown

### WARNING (severity: warning)
**Response Time:** 30 seconds
**Notification:** Slack #ai-service-alerts
**Repeat Interval:** Every 24 hours
**Expected Action:** Investigate, fix within 24h

**Alerts:**
- RedisReplicaDown
- HighErrorRate
- DailyCostExceeded
- HighLatency
- PluginLoadFailure
- RedisSentinelDegraded
- KnowledgeBaseEmpty

### INFO (severity: info)
**Response Time:** 5 minutes
**Notification:** Email only
**Repeat Interval:** Every 7 days
**Expected Action:** Monitor trends, optimize if needed

**Alerts:**
- LowCacheHitRate
- HighRequestRateDuringBusinessHours

---

## Deployment Guide

### Initial Setup

1. **Create monitoring directories:**
   ```bash
   mkdir -p monitoring/prometheus
   mkdir -p monitoring/alertmanager
   mkdir -p monitoring/grafana/dashboards
   ```

2. **Deploy Prometheus stack:**
   ```bash
   docker-compose up -d prometheus alertmanager
   ```

3. **Verify deployment:**
   ```bash
   # Check containers
   docker ps | grep -E "(prometheus|alertmanager)"

   # Check Prometheus targets
   curl http://localhost:9090/api/v1/targets

   # Check alert rules loaded
   curl http://localhost:9090/api/v1/rules

   # Check Alertmanager
   curl http://localhost:9093/api/v2/status
   ```

### Configuration Files

**Prometheus:**
- `monitoring/prometheus/prometheus.yml` - Scrape config
- `monitoring/prometheus/alerts.yml` - Alert rules

**Alertmanager:**
- `monitoring/alertmanager/alertmanager.yml` - Routing & receivers

**Docker Compose:**
- Added `prometheus` service (port 9090)
- Added `alertmanager` service (port 9093)
- Added volumes: `prometheus_data`, `alertmanager_data`

### Environment Variables

**Required:**
```bash
# .env file
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/HERE
SMTP_PASSWORD=your_smtp_password
PAGERDUTY_SERVICE_KEY=your_pagerduty_key  # Optional
```

**Update Alertmanager config:**
```bash
# Edit monitoring/alertmanager/alertmanager.yml
# Replace placeholders:
#   - CHANGE_ME (SMTP password)
#   - YOUR/SLACK/WEBHOOK (Slack webhook URL)
#   - YOUR_PAGERDUTY_SERVICE_KEY (PagerDuty key)
```

### Restart to Apply Changes

```bash
# Reload Prometheus config (no downtime)
curl -X POST http://localhost:9090/-/reload

# Reload Alertmanager config (no downtime)
curl -X POST http://localhost:9093/-/reload

# OR restart containers
docker-compose restart prometheus alertmanager
```

---

## Testing Alerts

### Manual Alert Testing

#### 1. Test RedisDown Alert

```bash
# Stop Redis master
docker-compose stop redis-master

# Wait 1 minute for alert to fire
# Check Alertmanager UI: http://localhost:9093

# Verify alert in Prometheus
curl -s http://localhost:9090/api/v1/alerts | jq '.data.alerts[] | select(.labels.alertname=="RedisDown")'

# Restore Redis
docker-compose start redis-master
```

#### 2. Test HighErrorRate Alert

```bash
# Generate 5xx errors (requires authentication)
for i in {1..20}; do
  curl -X POST http://localhost:8002/chat \
    -H "Authorization: Bearer INVALID_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"message": "test"}'
done

# Wait 2 minutes for alert
# Check Prometheus: http://localhost:9090/alerts
```

#### 3. Test DailyCostExceeded Alert

```bash
# Manually update metric (requires code change)
# In ai-service, add:
from utils.metrics import daily_cost_usd
daily_cost_usd.set(51.0)  # Trigger alert

# Restart ai-service
docker-compose restart ai-service

# Wait 5 minutes for alert
```

### Alert Validation Checklist

- [ ] Alert fires at correct threshold
- [ ] Alert appears in Prometheus UI (http://localhost:9090/alerts)
- [ ] Alert appears in Alertmanager UI (http://localhost:9093)
- [ ] Slack notification received (if configured)
- [ ] Email notification received (if configured)
- [ ] Alert resolves when condition clears
- [ ] Resolved notification sent

---

## Troubleshooting

### Alerts Not Firing

**Symptom:** Alert condition met, but no alert in Prometheus

**Diagnosis:**
```bash
# Check Prometheus scraping target
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="ai-service")'

# Check if metric exists
curl http://localhost:8002/metrics | grep ai_service_daily_cost_usd

# Check alert rules loaded
curl http://localhost:9090/api/v1/rules
```

**Solutions:**
1. Verify metric exposed by target
2. Check alert rule syntax: `promtool check rules alerts.yml`
3. Restart Prometheus: `docker-compose restart prometheus`

### Alerts Firing But Not Routing

**Symptom:** Alert in Prometheus, but not in Alertmanager

**Diagnosis:**
```bash
# Check Alertmanager connectivity
docker exec odoo19_prometheus wget -O- -q http://alertmanager:9093/-/healthy

# Check Prometheus config
docker exec odoo19_prometheus cat /etc/prometheus/prometheus.yml | grep alertmanager

# Check Alertmanager logs
docker logs odoo19_alertmanager
```

**Solutions:**
1. Verify alertmanager target in prometheus.yml
2. Check network connectivity
3. Restart both services

### Notifications Not Sending

**Symptom:** Alerts in Alertmanager, but no Slack/email

**Diagnosis:**
```bash
# Check Alertmanager config
docker exec odoo19_alertmanager cat /etc/alertmanager/alertmanager.yml

# Test Slack webhook manually
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK \
  -H 'Content-Type: application/json' \
  -d '{"text":"Test message"}'

# Check Alertmanager logs
docker logs odoo19_alertmanager | grep -i error
```

**Solutions:**
1. Verify Slack webhook URL is correct
2. Verify SMTP credentials
3. Check receiver routing in alertmanager.yml
4. Test receivers with `amtool`

### Too Many Alerts (Alert Fatigue)

**Symptom:** Receiving duplicate/redundant alerts

**Solutions:**
1. **Increase `for` duration:** Alert must be active longer before firing
2. **Add inhibition rules:** Prevent downstream alerts when root cause fires
3. **Adjust `repeat_interval`:** Reduce notification frequency
4. **Group related alerts:** Use `group_by` in routing

**Example inhibition rule:**
```yaml
inhibit_rules:
  - source_match:
      alertname: 'RedisDown'
    target_match:
      alertname: 'LowCacheHitRate'
    equal: ['cluster']
```

---

## Runbooks

### Runbook: Redis Down

**Alert:** RedisDown
**Severity:** CRITICAL
**Impact:** All AI requests bypass cache (3-5x latency & cost)

**Diagnosis:**
```bash
# 1. Check container status
docker ps | grep redis-master

# 2. Check logs
docker logs redis-master --tail=100

# 3. Verify network connectivity
docker exec ai-service ping redis-master
```

**Solutions:**

**If container stopped:**
```bash
docker-compose start redis-master
```

**If container crashed:**
```bash
# Check exit code
docker inspect redis-master | jq '.[0].State'

# Restart with logs
docker-compose restart redis-master
docker logs -f redis-master
```

**If OOM killed:**
```bash
# Increase memory limit in docker-compose.yml
# redis-master:
#   deploy:
#     resources:
#       limits:
#         memory: 1GB

docker-compose up -d redis-master
```

**If Redis data corrupted:**
```bash
# Restore from backup
docker-compose stop redis-master
docker volume rm odoo19_redis_master_data
docker volume create odoo19_redis_master_data
# Restore backup...
docker-compose start redis-master
```

---

### Runbook: Anthropic API Down

**Alert:** AnthropicAPIDown
**Severity:** CRITICAL
**Impact:** All AI chat requests fail

**Diagnosis:**
```bash
# 1. Check Anthropic status page
curl https://status.anthropic.com/api/v2/status.json

# 2. Test API key
docker exec ai-service curl -X POST https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-5-sonnet-20250929","max_tokens":1024,"messages":[{"role":"user","content":"test"}]}'

# 3. Check network connectivity
docker exec ai-service ping api.anthropic.com
```

**Solutions:**

**If Anthropic outage (external):**
1. Monitor https://status.anthropic.com
2. Enable fallback mode (if implemented)
3. Notify users of degraded service
4. Wait for Anthropic to restore service

**If API key invalid:**
```bash
# Verify API key in .env
cat .env | grep ANTHROPIC_API_KEY

# Update key
docker-compose restart ai-service
```

**If rate limited:**
```bash
# Check rate limit headers in logs
docker logs ai-service | grep "rate_limit"

# Wait for rate limit reset
# OR upgrade Anthropic plan
```

**If network issue:**
```bash
# Check DNS
docker exec ai-service nslookup api.anthropic.com

# Check firewall
# Ensure outbound HTTPS (443) allowed

# Test from host
curl https://api.anthropic.com/v1/messages
```

---

### Runbook: High Error Rate

**Alert:** HighErrorRate
**Severity:** WARNING
**Impact:** User experience degraded

**Diagnosis:**
```bash
# 1. Check error logs
docker logs ai-service --tail=100 | grep ERROR

# 2. Query error breakdown
curl -s http://localhost:9090/api/v1/query \
  --data-urlencode 'query=sum(rate(http_requests_total{status=~"5..",job="ai-service"}[5m])) by (endpoint)' \
  | jq '.data.result'

# 3. Sample failing requests
curl http://localhost:8002/health  # Should return 200
```

**Solutions:**

**If specific endpoint failing:**
```bash
# Check endpoint logs
docker logs ai-service | grep "POST /chat"

# Restart service
docker-compose restart ai-service
```

**If Redis connection errors:**
```bash
# Verify Redis connectivity
docker exec ai-service redis-cli -h redis-master ping

# Check Redis password
docker exec ai-service env | grep REDIS_PASSWORD
```

**If Anthropic API errors:**
```bash
# Check Anthropic error rate
curl http://localhost:8002/metrics | grep anthropic_api_errors

# See Anthropic API Down runbook
```

**If out of memory:**
```bash
# Check container memory
docker stats ai-service

# Increase memory limit
# docker-compose.yml:
#   ai-service:
#     deploy:
#       resources:
#         limits:
#           memory: 2GB
```

---

### Runbook: Daily Cost Exceeded

**Alert:** DailyCostExceeded
**Severity:** WARNING
**Impact:** Budget overrun

**Diagnosis:**
```bash
# 1. Check cost metrics
curl http://localhost:8002/metrics/costs?period=daily \
  -H "Authorization: Bearer $AI_SERVICE_API_KEY"

# 2. Query top token consumers
curl -s http://localhost:9090/api/v1/query \
  --data-urlencode 'query=topk(5, sum(rate(ai_service_claude_api_tokens_total[1h])) by (operation))' \
  | jq '.data.result'

# 3. Check cache hit rate
curl http://localhost:8002/metrics | grep cache_hits
```

**Solutions:**

**If excessive chat usage:**
```bash
# Enable rate limiting
# config.py:
#   RATE_LIMIT_CHAT = "10/minute"

# Restart service
docker-compose restart ai-service
```

**If low cache hit rate:**
```bash
# Increase cache TTL
# .env:
#   REDIS_CACHE_TTL=7200  # 2 hours

# Restart service
docker-compose restart ai-service
```

**If large token usage:**
```bash
# Reduce max_tokens per operation
# .env:
#   ANTHROPIC_MAX_TOKENS_CHAT=8192  # Down from 16384

# Restart service
docker-compose restart ai-service
```

**If unexpected usage spike:**
```bash
# Review recent requests
docker logs ai-service | grep "claude_api_call"

# Check for automated scripts/bots
# Add authentication checks
```

---

### Runbook: High Latency

**Alert:** HighLatency
**Severity:** WARNING
**Impact:** User experience degraded

**Diagnosis:**
```bash
# 1. Check P95 latency by endpoint
curl -s http://localhost:9090/api/v1/query \
  --data-urlencode 'query=histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (endpoint, le))' \
  | jq '.data.result'

# 2. Check Redis latency
docker exec redis-master redis-cli --latency

# 3. Check Anthropic API latency
curl http://localhost:8002/metrics | grep claude_api_duration
```

**Solutions:**

**If Redis latency high:**
```bash
# Check Redis slow log
docker exec redis-master redis-cli slowlog get 10

# Check Redis memory
docker exec redis-master redis-cli info memory

# If fragmented, restart Redis
docker-compose restart redis-master
```

**If Anthropic API slow:**
```bash
# Check Anthropic status
curl https://status.anthropic.com/api/v2/status.json

# Use smaller max_tokens if possible
# Enable streaming for better UX
```

**If low cache hit rate:**
```bash
# See "Daily Cost Exceeded" runbook
# Increase cache TTL
# Pre-warm cache for common queries
```

**If CPU/memory constrained:**
```bash
# Check resource usage
docker stats ai-service

# Increase limits in docker-compose.yml
# Scale horizontally (add replicas)
```

---

### Runbook: Plugin Load Failure

**Alert:** PluginLoadFailure
**Severity:** WARNING
**Impact:** Reduced AI capabilities

**Diagnosis:**
```bash
# 1. Check plugin logs
docker logs ai-service | grep -i "plugin"

# 2. List loaded plugins
curl http://localhost:8002/health | jq '.plugins'

# 3. Check plugin directory
docker exec ai-service ls -la /app/plugins/
```

**Solutions:**

**If plugin file missing:**
```bash
# Verify plugin files exist
docker exec ai-service find /app/plugins/ -name "*.py"

# Re-deploy plugins
# git pull or copy plugin files

# Restart service
docker-compose restart ai-service
```

**If plugin syntax error:**
```bash
# Check Python syntax
docker exec ai-service python -m py_compile /app/plugins/dte_plugin.py

# Fix syntax errors
# Restart service
```

**If plugin dependency missing:**
```bash
# Check requirements.txt
docker exec ai-service cat /app/requirements.txt

# Install missing dependency
docker exec ai-service pip install missing-package

# OR rebuild container
docker-compose build ai-service
docker-compose up -d ai-service
```

**If plugin incompatible:**
```bash
# Disable problematic plugin
# .env:
#   ENABLE_PLUGIN_SYSTEM=false

# OR remove plugin file
docker exec ai-service rm /app/plugins/broken_plugin.py

# Restart service
docker-compose restart ai-service
```

---

### Runbook: Sentinel Degraded

**Alert:** RedisSentinelDegraded
**Severity:** WARNING
**Impact:** Automatic failover at risk

**Diagnosis:**
```bash
# 1. Check Sentinel status
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL masters

# 2. Check Sentinel logs
docker logs redis-sentinel-1
docker logs redis-sentinel-2
docker logs redis-sentinel-3

# 3. Check Sentinel connectivity
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL sentinels mymaster
```

**Solutions:**

**If Sentinel container stopped:**
```bash
# Start stopped Sentinel
docker-compose start redis-sentinel-1
docker-compose start redis-sentinel-2
docker-compose start redis-sentinel-3
```

**If Sentinel crashed:**
```bash
# Check exit code
docker inspect redis-sentinel-1 | jq '.[0].State'

# Restart Sentinel
docker-compose restart redis-sentinel-1
docker logs -f redis-sentinel-1
```

**If network partition:**
```bash
# Check connectivity between Sentinels
docker exec redis-sentinel-1 ping redis-sentinel-2
docker exec redis-sentinel-1 ping redis-sentinel-3

# Recreate network if needed
docker-compose down
docker-compose up -d
```

**If config issue:**
```bash
# Verify sentinel.conf
docker exec redis-sentinel-1 cat /tmp/sentinel.conf

# Check master configured correctly
docker exec redis-sentinel-1 redis-cli -p 26379 SENTINEL get-master-addr-by-name mymaster

# Should return: redis-master:6379
```

---

### Runbook: Knowledge Base Empty

**Alert:** KnowledgeBaseEmpty
**Severity:** WARNING
**Impact:** AI responses lack domain context (SII, DTE, payroll)

**Diagnosis:**
```bash
# 1. Check knowledge base directory
docker exec ai-service ls -la /app/.claude/agents/knowledge/

# 2. Check loaded documents metric
curl http://localhost:8002/metrics | grep knowledge_base_documents

# 3. Check AI service logs
docker logs ai-service | grep "knowledge_base"
```

**Solutions:**

**If knowledge base directory empty:**
```bash
# Verify files exist on host
ls -la /Users/pedro/Documents/odoo19/.claude/agents/knowledge/

# If missing, restore from git
cd /Users/pedro/Documents/odoo19
git checkout .claude/agents/knowledge/

# Restart service (bind mount should reflect changes)
docker-compose restart ai-service
```

**If volume mount issue:**
```bash
# Check docker-compose.yml volumes
docker-compose config | grep -A5 "ai-service:" | grep volumes

# Should see bind mount for .claude/
# If not, add:
#   volumes:
#     - ./.claude:/app/.claude:ro

# Restart service
docker-compose up -d ai-service
```

**If knowledge base loader failing:**
```bash
# Check Python errors
docker logs ai-service | grep -i "error.*knowledge"

# Test knowledge base loading manually
docker exec ai-service python -c "from chat.knowledge_base import knowledge_base; print(len(knowledge_base.documents))"

# If fails, check file permissions
docker exec ai-service ls -la /app/.claude/agents/knowledge/
```

**If files corrupted:**
```bash
# Validate markdown syntax
docker exec ai-service find /app/.claude/agents/knowledge/ -name "*.md" -exec head -1 {} \;

# Restore from backup/git
cd /Users/pedro/Documents/odoo19
git checkout .claude/agents/knowledge/
docker-compose restart ai-service
```

---

### Runbook: Low Cache Hit Rate

**Alert:** LowCacheHitRate
**Severity:** INFO
**Impact:** Increased latency and cost

**Diagnosis:**
```bash
# 1. Check cache metrics
curl http://localhost:8002/metrics | grep cache

# 2. Calculate hit rate
curl -s http://localhost:9090/api/v1/query \
  --data-urlencode 'query=(rate(ai_service_cache_hits_total[10m]) / (rate(ai_service_cache_hits_total[10m]) + rate(ai_service_cache_misses_total[10m]))) * 100' \
  | jq '.data.result[0].value[1]'

# 3. Check Redis memory usage
docker exec redis-master redis-cli info memory
```

**Solutions:**

**If cache TTL too short:**
```bash
# Increase cache TTL
# .env:
#   REDIS_CACHE_TTL=7200  # 2 hours (from 3600)

# Restart service
docker-compose restart ai-service
```

**If Redis memory full (evictions):**
```bash
# Check evictions
docker exec redis-master redis-cli info stats | grep evicted_keys

# Increase Redis maxmemory
# redis/redis-master.conf:
#   maxmemory 512mb  # Increase from 256mb

# Restart Redis
docker-compose restart redis-master
```

**If high query variance (unique queries):**
```bash
# Expected behavior - many unique DTE validations
# Consider:
#   - Prompt caching (already enabled)
#   - Reduce max_tokens to fit more in cache
#   - Group similar queries
```

**If cache warming needed:**
```bash
# Pre-warm cache with common queries
# Create warmup script:
#   /app/scripts/cache_warmup.py

# Run on startup or cron
docker exec ai-service python /app/scripts/cache_warmup.py
```

---

## Appendix

### Useful Commands

**Prometheus:**
```bash
# Reload config (no restart)
curl -X POST http://localhost:9090/-/reload

# Query metric
curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=up{job="ai-service"}' | jq

# List all metrics
curl http://localhost:8002/metrics

# Check rule syntax
docker run -v $(pwd)/monitoring/prometheus:/config prom/prometheus:latest promtool check rules /config/alerts.yml
```

**Alertmanager:**
```bash
# Reload config (no restart)
curl -X POST http://localhost:9093/-/reload

# Silence alert
curl -XPOST http://localhost:9093/api/v2/silences -H "Content-Type: application/json" -d '{
  "matchers": [{"name": "alertname", "value": "RedisDown"}],
  "startsAt": "2025-11-09T12:00:00Z",
  "endsAt": "2025-11-09T13:00:00Z",
  "createdBy": "admin",
  "comment": "Maintenance window"
}'

# List silences
curl http://localhost:9093/api/v2/silences

# Delete silence
curl -XDELETE http://localhost:9093/api/v2/silence/{silenceID}
```

**Docker:**
```bash
# View logs
docker logs -f odoo19_prometheus
docker logs -f odoo19_alertmanager

# Restart services
docker-compose restart prometheus alertmanager

# Check container health
docker inspect odoo19_prometheus | jq '.[0].State.Health'
```

### Metrics Cardinality

**High Cardinality Metrics (>1000 series):**
- None expected (small deployment)

**Medium Cardinality Metrics (100-1000 series):**
- `http_requests_total` (method × endpoint × status)
- `claude_api_tokens_total` (model × operation × type)

**Low Cardinality Metrics (<100 series):**
- Most other metrics

**Best Practices:**
- Avoid labels with unbounded values (user IDs, timestamps)
- Use labels for aggregation (endpoint, status, model)
- Limit label count per metric (<10)

### Performance Tuning

**Prometheus:**
```yaml
# Adjust scrape interval based on needs
scrape_interval: 15s  # Default
# OR
scrape_interval: 30s  # Reduce load
```

**Alertmanager:**
```yaml
# Reduce notification frequency
repeat_interval: 24h  # Default for warnings
# OR
repeat_interval: 12h  # More frequent
```

**Storage:**
```bash
# Monitor TSDB size
du -sh /var/lib/docker/volumes/odoo19_prometheus_data/

# Adjust retention
# prometheus.yml:
#   --storage.tsdb.retention.time=15d  # Default
#   --storage.tsdb.retention.size=10GB
```

---

## Support

**Documentation:**
- Prometheus: https://prometheus.io/docs/
- Alertmanager: https://prometheus.io/docs/alerting/latest/alertmanager/
- PromQL: https://prometheus.io/docs/prometheus/latest/querying/basics/

**Project:**
- Repository: /Users/pedro/Documents/odoo19
- CLAUDE.md: Project documentation
- Monitoring configs: /Users/pedro/Documents/odoo19/monitoring/

**Contact:**
- Team: EERGYGROUP
- Slack: #ai-service-alerts

---

*Generated: 2025-11-09*
*Version: 1.0.0*
*Author: Claude (DevOps Agent)*
