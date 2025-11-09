# 🚀 AI Microservice - Guía Operacional

**Documento:** 06 de 06  
**Fecha:** 2025-10-25  
**Audiencia:** DevOps, SRE, Soporte

---

## 🎯 Deployment

### Requisitos Previos

**Infraestructura:**
- Docker 20.10+
- Docker Compose 2.0+
- Redis 7+
- 1 CPU, 1GB RAM mínimo

**Configuración:**
- API Key de Anthropic Claude
- API Key del AI Service (generada)
- Acceso a red interna Docker

### Variables de Entorno Requeridas

```bash
# .env en project root
ANTHROPIC_API_KEY=sk-ant-api03-...  # ⚠️ CRÍTICO
AI_SERVICE_API_KEY=<generated>      # openssl rand -hex 32
```

### Deployment Paso a Paso

#### 1. Verificar Configuración

```bash
cd /Users/pedro/Documents/odoo19

# Verificar .env existe
ls -la .env

# Verificar variables críticas
grep ANTHROPIC_API_KEY .env
grep AI_SERVICE_API_KEY .env
```

#### 2. Build Image (si hay cambios)

```bash
# Build imagen
docker-compose build ai-service

# Verificar imagen
docker images | grep ai-service
```

#### 3. Start Service

```bash
# Start AI service
docker-compose up -d ai-service

# Verificar logs
docker-compose logs -f ai-service
```

#### 4. Health Check

```bash
# Verificar health
curl http://localhost:8002/health

# Esperado:
# {
#   "status": "healthy",
#   "service": "AI Microservice - DTE Intelligence",
#   "version": "1.2.0",
#   "dependencies": {
#     "redis": {"status": "up"},
#     "anthropic": {"status": "configured"}
#   }
# }
```

#### 5. Test Endpoint

```bash
# Test validación DTE
curl -X POST http://localhost:8002/api/ai/validate \
  -H "Authorization: Bearer ${AI_SERVICE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "dte_data": {
      "tipo_dte": "33",
      "folio": 12345,
      "rut_emisor": "12345678-9",
      "rut_receptor": "98765432-1",
      "monto_total": 119000
    },
    "company_id": 1,
    "history": []
  }'
```

---

## 🔍 Monitoring

### Health Checks

```bash
# Health endpoint (público)
curl http://localhost:8002/health

# Metrics endpoint (público - Prometheus)
curl http://localhost:8002/metrics

# Cost metrics (autenticado)
curl -H "Authorization: Bearer ${AI_SERVICE_API_KEY}" \
  http://localhost:8002/metrics/costs?period=today
```

### Logs

```bash
# Real-time logs
docker logs -f odoo19_ai_service

# Last 100 lines
docker logs --tail 100 odoo19_ai_service

# With timestamps
docker logs -t odoo19_ai_service

# Filter by level
docker logs odoo19_ai_service 2>&1 | grep ERROR
```

### Resource Usage

```bash
# Container stats
docker stats odoo19_ai_service

# Disk usage
docker exec odoo19_ai_service du -sh /app/cache
docker exec odoo19_ai_service du -sh /app/uploads
```

### Redis Monitoring

```bash
# Connect to Redis
docker exec -it odoo19_redis redis-cli

# Check keys
redis-cli> KEYS chat:session:*
redis-cli> KEYS cost_tracker:*
redis-cli> KEYS sii:*

# Check memory
redis-cli> INFO memory

# Check connected clients
redis-cli> CLIENT LIST
```

---

## 🐛 Troubleshooting

### Problema 1: Service Won't Start

**Síntomas:**
```bash
docker-compose up -d ai-service
# Container exits immediately
```

**Diagnóstico:**
```bash
# Check logs
docker-compose logs ai-service

# Common errors:
# - "ANTHROPIC_API_KEY not set"
# - "Redis connection failed"
# - "Port 8002 already in use"
```

**Soluciones:**

1. **API Key missing:**
```bash
# Verify .env
grep ANTHROPIC_API_KEY .env

# If missing, add:
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env

# Restart
docker-compose restart ai-service
```

2. **Redis not available:**
```bash
# Check Redis
docker-compose ps redis

# If not running:
docker-compose up -d redis

# Wait 10s, then restart AI service
docker-compose restart ai-service
```

3. **Port conflict:**
```bash
# Check port usage
lsof -i :8002

# Change port in docker-compose.yml:
# expose:
#   - "8003"  # Changed from 8002
```

---

### Problema 2: High Latency

**Síntomas:**
- Requests taking > 5s
- Timeouts en Odoo

**Diagnóstico:**
```bash
# Check metrics
curl http://localhost:8002/metrics | grep claude_api_request_duration

# Check Redis latency
docker exec odoo19_redis redis-cli --latency

# Check network
docker exec odoo19_ai_service ping -c 3 api.anthropic.com
```

**Soluciones:**

1. **Redis slow:**
```bash
# Check Redis memory
docker exec odoo19_redis redis-cli INFO memory

# If memory > 90%, clear old keys
docker exec odoo19_redis redis-cli FLUSHDB
```

2. **Anthropic API slow:**
```bash
# Check rate limits
curl http://localhost:8002/metrics | grep claude_api_rate_limit

# If rate limited, wait or increase limits with Anthropic
```

3. **Prompt too large:**
```bash
# Check token usage
curl -H "Authorization: Bearer ${AI_SERVICE_API_KEY}" \
  http://localhost:8002/metrics/costs?period=today

# If avg_tokens_per_call > 50K, optimize prompts
```

---

### Problema 3: High Costs

**Síntomas:**
- Daily cost > $10
- Unexpected billing from Anthropic

**Diagnóstico:**
```bash
# Check cost breakdown
curl -H "Authorization: Bearer ${AI_SERVICE_API_KEY}" \
  http://localhost:8002/metrics/costs?period=today

# Check by operation
curl -H "Authorization: Bearer ${AI_SERVICE_API_KEY}" \
  http://localhost:8002/metrics/costs?period=today | jq '.by_operation'
```

**Soluciones:**

1. **Identify expensive operation:**
```json
{
  "by_operation": {
    "dte_validation": {"calls": 1000, "cost_usd": 2.50},
    "chat": {"calls": 500, "cost_usd": 1.50},
    "sii_monitoring": {"calls": 4, "cost_usd": 8.00}  // ⚠️ Expensive!
  }
}
```

2. **Optimize expensive operation:**
```python
# Example: Reduce SII monitoring frequency
# From: Every 6 hours
# To: Every 12 hours

# Edit Odoo cron:
# interval_number: 12 (was 6)
```

3. **Enable cost limits:**
```python
# config.py
max_estimated_cost_per_request: float = 0.50  # Lower from 1.0
```

---

### Problema 4: Cache Not Working

**Síntomas:**
- Cache hit rate < 50%
- High costs despite caching enabled

**Diagnóstico:**
```bash
# Check cache metrics
docker logs odoo19_ai_service | grep cache_hit_rate

# Expected: 90%+
# If < 50%: cache not working
```

**Soluciones:**

1. **Verify caching enabled:**
```bash
docker exec odoo19_ai_service python -c "
from config import settings
print('Caching enabled:', settings.enable_prompt_caching)
"
```

2. **Check prompt stability:**
```python
# Prompts must be IDENTICAL for caching
# Bad: f"Analyze this DTE from {datetime.now()}"  # Changes every time
# Good: "Analyze this DTE"  # Static
```

3. **Verify cache TTL:**
```bash
# Ephemeral cache: 5 minutes
# If requests > 5 min apart, cache expires
```

---

### Problema 5: Plugin Not Selected

**Síntomas:**
- Chat always uses default plugin
- Specialized knowledge not applied

**Diagnóstico:**
```bash
# Check plugin registry
docker logs odoo19_ai_service | grep plugin_selected

# Expected: "plugin_selected", module="l10n_cl_dte"
# If "plugin_fallback_to_default": keywords not matching
```

**Soluciones:**

1. **Add missing keywords:**
```python
# plugins/dte/plugin.py
def get_keywords(self) -> List[str]:
    return [
        'dte', 'factura', 'boleta',
        'guía', 'guia',  # Add variations
        'nota de crédito', 'nota de credito',  # With/without accent
        # ...
    ]
```

2. **Use explicit context:**
```python
# Odoo code
response = requests.post(
    '/api/chat/message',
    json={
        'message': user_message,
        'user_context': {
            'module': 'l10n_cl_dte'  # ✅ Explicit hint
        }
    }
)
```

---

## 🔄 Maintenance

### Daily Tasks

```bash
# 1. Check health
curl http://localhost:8002/health

# 2. Check costs
curl -H "Authorization: Bearer ${AI_SERVICE_API_KEY}" \
  http://localhost:8002/metrics/costs?period=today

# 3. Check logs for errors
docker logs --since 24h odoo19_ai_service 2>&1 | grep ERROR
```

### Weekly Tasks

```bash
# 1. Review cost trends
curl -H "Authorization: Bearer ${AI_SERVICE_API_KEY}" \
  http://localhost:8002/metrics/costs?period=this_month

# 2. Clean old cache
docker exec odoo19_redis redis-cli --scan --pattern "cache:*" | \
  xargs docker exec odoo19_redis redis-cli DEL

# 3. Check disk usage
docker exec odoo19_ai_service df -h
```

### Monthly Tasks

```bash
# 1. Update dependencies
cd /Users/pedro/Documents/odoo19/ai-service
pip list --outdated

# 2. Review Anthropic pricing
# Check: https://www.anthropic.com/pricing

# 3. Backup Redis data
docker exec odoo19_redis redis-cli SAVE
docker cp odoo19_redis:/data/dump.rdb ./backups/redis-$(date +%Y%m%d).rdb

# 4. Review plugin performance
docker logs odoo19_ai_service | grep plugin_selected | \
  awk '{print $NF}' | sort | uniq -c
```

---

## 🔐 Security

### API Key Rotation

```bash
# 1. Generate new key
NEW_KEY=$(openssl rand -hex 32)

# 2. Update .env
sed -i '' "s/AI_SERVICE_API_KEY=.*/AI_SERVICE_API_KEY=${NEW_KEY}/" .env

# 3. Update Odoo config
# Settings > Technical > System Parameters
# Key: ai_service.api_key
# Value: <NEW_KEY>

# 4. Restart service
docker-compose restart ai-service

# 5. Test
curl -H "Authorization: Bearer ${NEW_KEY}" \
  http://localhost:8002/health
```

### Anthropic API Key Rotation

```bash
# 1. Get new key from console.anthropic.com

# 2. Update .env
sed -i '' "s/ANTHROPIC_API_KEY=.*/ANTHROPIC_API_KEY=${NEW_KEY}/" .env

# 3. Restart service
docker-compose restart ai-service

# 4. Verify
docker logs odoo19_ai_service | grep "anthropic_client_initialized"
```

### Security Audit

```bash
# 1. Check exposed ports
docker port odoo19_ai_service

# Expected: Empty (no external ports)
# If ports exposed: Remove from docker-compose.yml

# 2. Check network isolation
docker inspect odoo19_ai_service | jq '.[0].NetworkSettings.Networks'

# Expected: Only "stack_network"

# 3. Check file permissions
docker exec odoo19_ai_service ls -la /app/.env

# Expected: File NOT found (no local .env)
```

---

## 📊 Performance Tuning

### Optimize Redis

```bash
# 1. Enable persistence
docker exec odoo19_redis redis-cli CONFIG SET save "900 1 300 10"

# 2. Set max memory
docker exec odoo19_redis redis-cli CONFIG SET maxmemory 512mb
docker exec odoo19_redis redis-cli CONFIG SET maxmemory-policy allkeys-lru

# 3. Disable slow commands
docker exec odoo19_redis redis-cli CONFIG SET rename-command FLUSHDB ""
```

### Optimize FastAPI

```python
# main.py
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url=None,  # Disable in production
    redoc_url=None,  # Disable in production
)
```

### Optimize Docker

```yaml
# docker-compose.yml
ai-service:
  deploy:
    resources:
      limits:
        cpus: '1.0'
        memory: 1G
      reservations:
        cpus: '0.5'
        memory: 512M
```

---

## 🔄 Backup & Recovery

### Backup Redis Data

```bash
# Manual backup
docker exec odoo19_redis redis-cli BGSAVE

# Wait for completion
docker exec odoo19_redis redis-cli LASTSAVE

# Copy backup
docker cp odoo19_redis:/data/dump.rdb \
  ./backups/redis-backup-$(date +%Y%m%d-%H%M%S).rdb
```

### Restore Redis Data

```bash
# 1. Stop AI service
docker-compose stop ai-service

# 2. Stop Redis
docker-compose stop redis

# 3. Restore backup
docker cp ./backups/redis-backup-20251025.rdb \
  odoo19_redis:/data/dump.rdb

# 4. Start Redis
docker-compose start redis

# 5. Start AI service
docker-compose start ai-service

# 6. Verify
curl http://localhost:8002/health
```

### Disaster Recovery

```bash
# Complete rebuild from scratch

# 1. Stop services
docker-compose down

# 2. Remove volumes (⚠️ DATA LOSS)
docker volume rm odoo19_ai_cache
docker volume rm odoo19_ai_uploads

# 3. Rebuild
docker-compose build ai-service

# 4. Start
docker-compose up -d ai-service redis

# 5. Verify
curl http://localhost:8002/health
```

---

## 📞 Support Contacts

### Internal Team

- **Tech Lead:** @tech-lead (Slack)
- **DevOps:** @devops-team (Slack)
- **On-call:** PagerDuty rotation

### External Vendors

- **Anthropic Support:** support@anthropic.com
- **Redis Support:** Community forums

### Escalation Path

1. **L1:** Check logs, restart service
2. **L2:** DevOps team (Slack #ai-service-support)
3. **L3:** Tech Lead (critical issues only)
4. **L4:** Anthropic support (API issues)

---

## 📚 Additional Resources

### Documentation

- [Anthropic API Docs](https://docs.anthropic.com/)
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [Redis Docs](https://redis.io/docs/)

### Internal Docs

- `01_RESUMEN_EJECUTIVO.md` - Overview
- `02_ARQUITECTURA_DETALLADA.md` - Architecture
- `03_COMPONENTES_PRINCIPALES.md` - Components
- `04_OPTIMIZACIONES_TECNICAS.md` - Optimizations
- `05_INTEGRACIONES_ODOO.md` - Odoo integration

---

**Última Actualización:** 2025-10-25  
**Mantenido por:** EERGYGROUP Development Team  
**Versión:** 1.0
