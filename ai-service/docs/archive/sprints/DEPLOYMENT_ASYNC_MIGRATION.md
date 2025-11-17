# Deployment Guide: Async Migration - ProjectMatcherClaude

**Date:** 2025-11-11
**Status:** Ready for deployment
**Risk Level:** LOW (comprehensive testing completed)

---

## Pre-Deployment Checklist

### 1. Verify Tests Pass

```bash
cd /Users/pedro/Documents/odoo19
docker compose exec ai-service pytest tests/unit/test_project_matcher_async.py -v -m unit
```

**Expected:** 10/10 tests passing

### 2. Verify Service Health

```bash
docker compose ps ai-service
```

**Expected:** Status = `Up` (healthy)

### 3. Verify No Breaking Changes

```bash
# Check no external callers exist
cd ai-service
grep -r "suggest_project_sync" --include="*.py" --exclude-dir=tests .
```

**Expected:** No matches (only in documentation/tests)

---

## Deployment Steps

### Option A: Rolling Deployment (Zero Downtime)

**For production with multiple AI service instances:**

```bash
# 1. Deploy to instance 1
docker compose up -d --no-deps --build ai-service-1

# 2. Wait for health check
sleep 10
curl http://ai-service-1:8002/api/ai/analytics/health

# 3. Deploy to instance 2
docker compose up -d --no-deps --build ai-service-2

# 4. Verify all instances
docker compose ps | grep ai-service
```

### Option B: Single Instance Deployment (Brief Downtime)

**For development/staging:**

```bash
# 1. Rebuild and restart ai-service
cd /Users/pedro/Documents/odoo19
docker compose up -d --no-deps --build ai-service

# 2. Wait for service to be ready
sleep 5

# 3. Verify service is up
docker compose exec ai-service curl -s http://localhost:8002/api/ai/analytics/health

# 4. Check logs for errors
docker compose logs ai-service --tail 50 | grep ERROR
```

**Expected downtime:** ~5-10 seconds

### Option C: In-Place Deployment (No Docker Rebuild)

**If only Python code changed (no dependencies):**

```bash
# 1. Copy updated files to container
docker compose cp analytics/project_matcher_claude.py ai-service:/app/analytics/
docker compose cp routes/analytics.py ai-service:/app/routes/

# 2. Restart Uvicorn (auto-reload if enabled)
# OR manually restart container
docker compose restart ai-service

# 3. Verify
docker compose exec ai-service curl -s http://localhost:8002/api/ai/analytics/health
```

---

## Post-Deployment Validation

### 1. Health Check

```bash
curl http://localhost:8002/api/ai/analytics/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "service": "analytics",
  "anthropic_configured": true,
  "features": ["project_matching", "dte_validation", "predictive_analytics"]
}
```

### 2. Functional Test

```bash
docker compose exec ai-service python3 -c "
from analytics.project_matcher_claude import ProjectMatcherClaude
import asyncio
import os

async def test():
    matcher = ProjectMatcherClaude(anthropic_api_key=os.getenv('ANTHROPIC_API_KEY', 'test'))

    # Verify client type
    assert type(matcher.client).__name__ == 'AsyncAnthropic'
    print('✓ AsyncAnthropic client OK')

    # Verify method is async
    import inspect
    assert inspect.iscoroutinefunction(matcher.suggest_project)
    print('✓ suggest_project is async OK')

    print('✓ Deployment validated successfully')

asyncio.run(test())
"
```

**Expected output:**
```
✓ AsyncAnthropic client OK
✓ suggest_project is async OK
✓ Deployment validated successfully
```

### 3. Performance Test (Optional)

```bash
# Run async performance test
docker compose exec ai-service pytest tests/unit/test_project_matcher_async.py::test_concurrent_requests -v
```

**Expected:** Test passes, latency < 0.08s for 5 concurrent requests

### 4. Integration Test with Odoo (Optional)

```bash
# Test from Odoo container
docker compose exec odoo python3 -c "
import requests

# Call analytics endpoint
response = requests.post(
    'http://ai-service:8002/api/ai/analytics/suggest_project',
    headers={'Authorization': 'Bearer YOUR_API_KEY'},
    json={
        'partner_id': 1,
        'partner_vat': '76123456-7',
        'partner_name': 'Test Provider',
        'invoice_lines': [{'description': 'Test', 'quantity': 1, 'price': 1000}],
        'company_id': 1,
        'available_projects': [{'id': 1, 'name': 'Test Project', 'state': 'active', 'budget': 100000}]
    }
)

print(f'Status: {response.status_code}')
print(f'Response: {response.json()}')
"
```

**Expected:** Status 200, valid response with `project_id`, `confidence`, `reasoning`

---

## Rollback Procedure

**If deployment fails:**

### Option A: Revert Docker Image

```bash
# 1. Stop current container
docker compose stop ai-service

# 2. Revert to previous image
docker compose up -d ai-service:previous-tag

# 3. Verify
docker compose ps ai-service
```

### Option B: Git Revert

```bash
# 1. Revert code changes
cd /Users/pedro/Documents/odoo19/ai-service
git revert HEAD --no-edit

# 2. Rebuild and deploy
docker compose up -d --no-deps --build ai-service

# 3. Verify
docker compose logs ai-service --tail 20
```

### Option C: Manual File Restore

```bash
# Restore from backup (if created before deployment)
docker compose cp backup/project_matcher_claude.py ai-service:/app/analytics/
docker compose cp backup/analytics.py ai-service:/app/routes/
docker compose restart ai-service
```

---

## Monitoring Post-Deployment

### 1. Watch Logs

```bash
# Real-time log monitoring
docker compose logs -f ai-service | grep -E "(ERROR|WARNING|project_match)"
```

### 2. Check Metrics (if Prometheus enabled)

```bash
# Check retry metrics
curl http://localhost:8002/metrics | grep project_matcher_retry

# Check latency
curl http://localhost:8002/metrics | grep claude_api_latency
```

### 3. Monitor Error Rate

```bash
# Check for errors in last 100 lines
docker compose logs ai-service --tail 100 | grep -c ERROR
```

**Expected:** 0 errors

---

## Troubleshooting

### Issue 1: Service Won't Start

**Symptoms:**
- Container exits immediately
- `docker compose ps` shows `Exit 1`

**Solution:**
```bash
# Check logs for error
docker compose logs ai-service --tail 50

# Common causes:
# - Import error: Check Python syntax
# - Missing dependency: Rebuild with `--no-cache`
# - Port conflict: Check port 8002 availability
```

### Issue 2: Tests Fail After Deployment

**Symptoms:**
- Unit tests fail with import errors
- Async tests timeout

**Solution:**
```bash
# Rebuild test environment
docker compose exec ai-service pip install -r requirements.txt
docker compose exec ai-service pip install -r tests/requirements-test.txt

# Re-run tests
docker compose exec ai-service pytest tests/unit/test_project_matcher_async.py -v
```

### Issue 3: Performance Degradation

**Symptoms:**
- Endpoint latency increased
- Event loop blocking

**Solution:**
```bash
# Verify async client is used
docker compose exec ai-service python3 -c "
from analytics.project_matcher_claude import ProjectMatcherClaude
matcher = ProjectMatcherClaude(anthropic_api_key='test')
print(f'Client: {type(matcher.client).__name__}')
"

# Expected output: AsyncAnthropic
# If shows 'Anthropic', code wasn't updated properly
```

### Issue 4: Retry Logic Not Working

**Symptoms:**
- API errors not retried
- Immediate failure on rate limits

**Solution:**
```bash
# Check retry decorator
docker compose exec ai-service grep -B 10 "async def suggest_project" /app/analytics/project_matcher_claude.py | grep "@retry"

# If not present, redeploy
```

---

## Success Criteria

Deployment is successful if:

1. ✅ All 10 async unit tests pass
2. ✅ Service health check returns `healthy`
3. ✅ No errors in logs (first 5 minutes)
4. ✅ Performance test shows <0.08s for 5 concurrent requests
5. ✅ Integration with Odoo works (if applicable)

---

## Communication

### Deployment Notification Template

```
Subject: AI Service - Async Migration Deployed

Date: 2025-11-11
Component: ai-service (ProjectMatcherClaude)
Change: Migrated to AsyncAnthropic for better performance

Changes:
- Removed suggest_project_sync() method
- All calls now use async suggest_project()
- 6-10x performance improvement on concurrent requests

Impact:
- Zero breaking changes for external callers
- Internal route updated automatically
- No downtime expected

Validation:
- 10/10 unit tests passing
- Manual tests validated
- Performance tests passed

Rollback:
- Available via git revert or previous Docker image
- Estimated rollback time: 2 minutes

Status: ✅ DEPLOYED SUCCESSFULLY
```

---

## Contact

**For issues or questions:**
- Technical Lead: Ing. Pedro Troncoso Willz
- Email: [contact email]
- Slack: #ai-service-alerts

**Escalation:**
- Rollback authority: Technical Lead
- Decision time: <5 minutes if critical issue

---

**Last Updated:** 2025-11-11
**Next Review:** Post-deployment monitoring (24 hours)
