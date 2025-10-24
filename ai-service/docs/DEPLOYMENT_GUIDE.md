# 🚀 GUÍA DE DEPLOYMENT - AI-SERVICE v1.2.0

**Última actualización:** 23 de Octubre, 2025  
**Versión:** 1.1.0 → 1.2.0  
**Cambios críticos:** Sí  
**Requires rebuild:** Sí  
**Downtime esperado:** ~30 segundos  

---

## ⚠️ PRE-REQUISITOS

Antes de deployar, verificar:

- [ ] ✅ Git commit de código actual (backup)
- [ ] ✅ Docker Compose funcionando
- [ ] ✅ Redis corriendo (dependency)
- [ ] ✅ Variables de entorno configuradas (.env)
- [ ] ✅ Ventana de mantenimiento (off-peak hours)

---

## 📋 CHECKLIST RÁPIDO

```bash
# 1. Backup actual
cd /Users/pedro/Documents/odoo19
git add -A
git commit -m "Pre-deploy backup - ai-service v1.2.0"

# 2. Rebuild
docker-compose build ai-service

# 3. Deploy
docker-compose up -d ai-service

# 4. Health check
docker-compose exec ai-service curl http://localhost:8002/health

# 5. Monitor
./ai-service/scripts/monitor_ai_service.sh
```

**Tiempo total:** 3-5 minutos

---

## 🔧 DEPLOYMENT PASO A PASO

### PASO 1: Backup y Verificación (2 min)

```bash
cd /Users/pedro/Documents/odoo19

# Ver cambios pendientes
git status

# Ver archivos modificados
git diff --name-only

# Commit backup
git add ai-service/
git commit -m "Deploy ai-service v1.2.0 - Fixes críticos + rate limiting + cache"

# Tag de versión
git tag -a v1.2.0-ai-service -m "AI Service: Rate limiting, cache Redis, retry logic"

# Verificar servicios actuales
docker-compose ps | grep ai-service
# Debe mostrar: odoo19_ai_service    Up (healthy)
```

---

### PASO 2: Rebuild Imagen (2 min)

```bash
# Rebuild con optimizaciones Dockerfile
docker-compose build --no-cache ai-service

# Verificar tamaño imagen (debe ser menor)
docker images | grep ai-service
# Antes: ~1.74 GB
# Después: ~1.54 GB (-200MB)
```

**Nota:** `--no-cache` asegura que dependencias se instalen fresh (incluye tenacity).

---

### PASO 3: Deploy (30 segundos)

```bash
# Restart con nueva imagen
docker-compose up -d ai-service

# Ver logs de startup
docker-compose logs -f ai-service

# Esperar mensaje:
# "ai_service_starting" version=1.2.0
# "anthropic_client_initialized"
# "chat_engine_initialized"
```

**Downtime:** ~5-10 segundos (restart)

---

### PASO 4: Verificación Health (1 min)

```bash
# 1. Health endpoint
docker-compose exec ai-service curl -s http://localhost:8002/health | python3 -m json.tool

# Debe retornar:
# {
#   "status": "healthy",
#   "service": "AI Microservice - DTE Intelligence",
#   "version": "1.0.0",
#   "anthropic_configured": true,
#   "openai_configured": false
# }

# 2. Verificar rate limiting activo
curl -X POST http://localhost:8002/api/ai/validate \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d '{"dte_data": {"tipo_dte": "33"}, "company_id": 1}' \
  -w "\nStatus: %{http_code}\n"

# Debe retornar 200 (o 500 si falta data, pero NO 404)

# 3. Test rate limiting
for i in {1..25}; do
  echo "Request $i:"
  curl -X POST http://localhost:8002/api/ai/validate \
    -H "Authorization: Bearer default_ai_api_key" \
    -H "Content-Type: application/json" \
    -d '{"dte_data": {"tipo_dte": "33"}, "company_id": 1}' \
    -w " Status: %{http_code}\n" \
    -s -o /dev/null
done

# Debe ver: primeros 20 = 200, siguientes 5 = 429 (rate limited)
```

---

### PASO 5: Verificación Funcional (3 min)

#### 5.1. Test desde Odoo (Manual)

```bash
# 1. Abrir Odoo web: http://localhost:8169
# 2. Ir a: Contabilidad → Facturas de Cliente
# 3. Crear factura de prueba
# 4. Click botón "Generate DTE"
# 5. Verificar que wizard abre correctamente
# 6. Verificar que no hay errores en logs:

docker-compose logs odoo --since 5m | grep -i "ai.*service"
docker-compose logs ai-service --since 5m | grep -i error
```

#### 5.2. Test Cache (Automatizado)

```bash
# Hacer 2 requests idénticos
echo "Request 1 (cache miss):"
time curl -X POST http://localhost:8002/api/ai/validate \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d '{"dte_data": {"tipo_dte": "33", "folio": "12345"}, "company_id": 1}' \
  -s -o /dev/null

sleep 1

echo "Request 2 (cache hit esperado):"
time curl -X POST http://localhost:8002/api/ai/validate \
  -H "Authorization: Bearer default_ai_api_key" \
  -H "Content-Type: application/json" \
  -d '{"dte_data": {"tipo_dte": "33", "folio": "12345"}, "company_id": 1}' \
  -s -o /dev/null

# Request 2 debe ser MUCHO más rápido (50ms vs 2000ms)

# Verificar en logs
docker-compose logs ai-service --tail 20 | grep "llm_cache"
# Debe ver: "llm_cache_miss" luego "llm_cache_hit"
```

---

### PASO 6: Monitoreo Post-Deploy (15 min)

```bash
# Ejecutar script monitor cada 5 minutos durante 15 min
for i in {1..3}; do
  echo "===== Monitor Run $i/3 ====="
  ./ai-service/scripts/monitor_ai_service.sh
  echo ""
  sleep 300  # 5 minutos
done

# Verificar:
# ✅ Error count < 5
# ✅ Cache hit rate > 0% (si hay requests)
# ✅ No rate limit violations (o muy pocos)
# ✅ Requests procesándose correctamente
```

---

## 🚨 ROLLBACK (Si algo falla)

### Opción A: Rollback Git (Recomendado)

```bash
# 1. Ver commits recientes
git log --oneline | head -5

# 2. Rollback al commit anterior
git checkout <commit_hash_anterior>

# 3. Rebuild imagen anterior
docker-compose build ai-service

# 4. Deploy versión anterior
docker-compose up -d ai-service

# 5. Verificar
docker-compose logs ai-service --tail 50
curl http://localhost:8002/health
```

**Tiempo:** 3-4 minutos

---

### Opción B: Rollback Docker Image (Rápido)

```bash
# 1. Ver imágenes disponibles
docker images | grep ai-service

# 2. Tag imagen anterior (si guardaste)
docker tag <image_id_anterior> eergygroup/ai-service:latest

# 3. Restart
docker-compose up -d ai-service
```

**Tiempo:** 30 segundos

---

## 📊 MÉTRICAS DE ÉXITO

### Baseline (Antes del Deploy)

Capturar estas métricas ANTES:

```bash
# Guardar en archivo
echo "=== BASELINE PRE-DEPLOY ===" > /tmp/ai_service_baseline.txt
date >> /tmp/ai_service_baseline.txt

# Requests última hora
echo "Requests:" >> /tmp/ai_service_baseline.txt
docker-compose logs ai-service --since 1h | grep -cE "validation|chat_message" >> /tmp/ai_service_baseline.txt

# Errores última hora
echo "Errors:" >> /tmp/ai_service_baseline.txt
docker-compose logs ai-service --since 1h | grep -c ERROR >> /tmp/ai_service_baseline.txt

# Tokens consumidos (si disponible)
echo "Tokens:" >> /tmp/ai_service_baseline.txt
docker-compose logs ai-service --since 1h | grep "total_tokens" | awk '{sum+=$NF} END {print sum}' >> /tmp/ai_service_baseline.txt
```

### Post-Deploy (24h después)

Comparar:

```bash
# Ejecutar mismo script 24h después
./ai-service/scripts/monitor_ai_service.sh > /tmp/ai_service_post_deploy.txt

# Comparar
diff /tmp/ai_service_baseline.txt /tmp/ai_service_post_deploy.txt
```

**Métricas esperadas:**
- ✅ Error rate: -80% o más
- ✅ Cache hit rate: 20-40% (después de calentamiento)
- ✅ Rate limit violations: <10 en 24h
- ✅ Sin crashes/restarts inesperados

---

## 🔍 TROUBLESHOOTING

### Problema 1: Servicio no arranca

```bash
# Ver logs detallados
docker-compose logs ai-service --tail 100

# Errores comunes:
# - "ModuleNotFoundError: tenacity" → rebuild con --no-cache
# - "Redis connection failed" → verificar redis running
# - "Import error" → verificar sintaxis Python
```

**Solución:**
```bash
docker-compose build --no-cache ai-service
docker-compose up -d ai-service
```

---

### Problema 2: Rate limiting muy estricto

```bash
# Síntoma: Muchos 429 errors
docker-compose logs ai-service | grep "429\|rate_limit_exceeded" | wc -l

# Solución temporal: Aumentar límites en main.py
# @limiter.limit("20/minute") → @limiter.limit("50/minute")

# Rebuild
docker-compose restart ai-service  # No necesita rebuild para cambios Python
```

---

### Problema 3: Cache no funciona

```bash
# Verificar Redis
docker-compose exec redis redis-cli ping
# Debe retornar: PONG

# Ver cache keys
docker-compose exec redis redis-cli --scan --pattern "llm_cache:*" | head -10

# Si no hay keys, verificar logs
docker-compose logs ai-service | grep "cache"
```

---

### Problema 4: Errores JSON parse

```bash
# Ver errores específicos
docker-compose logs ai-service | grep "json_parse_error"

# Verificar que utils/llm_helpers.py se importa correctamente
docker-compose exec ai-service python3 -c "from utils.llm_helpers import extract_json_from_llm_response; print('OK')"
```

---

## ✅ CHECKLIST FINAL

Antes de cerrar deployment:

- [ ] ✅ Health check retorna 200
- [ ] ✅ No errores en logs (últimos 15 min)
- [ ] ✅ Rate limiting funciona (test con 25 requests)
- [ ] ✅ Cache hit detectado en logs
- [ ] ✅ Odoo puede llamar a ai-service sin errores
- [ ] ✅ Script monitor ejecutado y sin alertas críticas
- [ ] ✅ Métricas baseline capturadas
- [ ] ✅ Git commit/tag creado
- [ ] ✅ Equipo notificado de deployment exitoso

---

## 📞 CONTACTO

**Si hay problemas críticos:**

1. **Rollback inmediato** (ver sección arriba)
2. **Capturar logs:**
```bash
docker-compose logs ai-service --since 30m > /tmp/ai_service_error.log
docker-compose ps > /tmp/containers_status.txt
```
3. **Notificar al equipo** con logs adjuntos
4. **Revisar:** `PLAN_MITIGACION_URGENTE.md` para detalles

---

**Deployment guide v1.0**  
**Última revisión:** 23 Oct 2025  
**Próxima revisión:** Después de primer deploy exitoso

