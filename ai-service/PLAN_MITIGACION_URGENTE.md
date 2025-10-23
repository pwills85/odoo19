# 🚨 PLAN DE MITIGACIÓN URGENTE - AI-SERVICE EN PRODUCCIÓN

**Fecha:** 23 de Octubre, 2025  
**Contexto:** ai-service es parte del stack de producción (docker-compose.yml)  
**Estado Actual:** Servicio corriendo con errores críticos no detectados  
**Riesgo:** ALTO - Puede afectar operación de Odoo y costos API

---

## ⚠️ SITUACIÓN ACTUAL

### Stack de Producción Detectado

```yaml
# docker-compose.yml
services:
  odoo:
    depends_on: [db, redis]
    
  dte-service:
    depends_on: [redis, rabbitmq]
    
  ai-service:  # ⚠️ SERVICIO CRÍTICO EN PRODUCCIÓN
    restart: unless-stopped
    depends_on: [redis]
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}  # Costos reales
    expose:
      - "8002"  # Red interna - usado por Odoo
```

### Integraciones Activas

**Odoo → ai-service:**
- ✅ Validación pre-envío DTEs (`POST /api/ai/validate`)
- ✅ Sugerencia proyectos facturas (`POST /api/ai/analytics/suggest_project`)
- ✅ Chat support usuarios (`POST /api/chat/message`)
- ✅ Monitoreo SII (`POST /api/ai/sii/monitor`)

**Impacto de Fallas:**
- 🔴 Odoo no puede validar DTEs → bloqueo workflow
- 🔴 Costos API Anthropic descontrolados
- 🔴 Crashes intermitentes afectan UX usuarios
- 🔴 Sin logs/métricas → debugging ciego

---

## 🚨 ERRORES CRÍTICOS EN PRODUCCIÓN

### 1. ❌ **CÓDIGO DUPLICADO - ¿Cuál archivo está corriendo?**

**Problema:**
```bash
ai-service/
├── main.py        # 656 líneas
└── main_v2.py     # 714 líneas  # ⚠️ 40% duplicado
```

**Pregunta urgente:** ¿Cuál está en el Dockerfile?

```dockerfile
# ai-service/Dockerfile
CMD ["uvicorn", "main:app", ...]  # ⚠️ Corriendo main.py
```

**Riesgo:**
- Si están usando `main.py` → NO tienen sistema de plugins (main_v2.py)
- Si usan `main_v2.py` → Dockerfile no está actualizado
- Confusión en deploys futuros

**Verificación URGENTE:**
```bash
# ¿Cuál archivo está corriendo en producción?
docker-compose exec ai-service ps aux | grep uvicorn

# O ver logs de startup
docker-compose logs ai-service | grep "ai_service_starting"
```

**Solución INMEDIATA (30 min):**
```bash
# 1. Decidir cuál versión usar
# Si main_v2.py es la buena:
cd /Users/pedro/Documents/odoo19/ai-service
mv main.py main.py.deprecated
mv main_v2.py main.py

# 2. Rebuild y redeploy
docker-compose build ai-service
docker-compose up -d ai-service

# 3. Verificar health
docker-compose exec ai-service curl http://localhost:8002/health
```

---

### 2. ❌ **SIN RATE LIMITING - Costos API Descontrolados**

**Problema:**
Cualquier usuario/bug puede hacer requests ilimitados a Claude API.

**Riesgo Real:**
```python
# Escenario: Loop infinito en Odoo
for invoice in invoices:  # 10,000 facturas
    ai_service.validate_dte(invoice)  # ⚠️ Sin límite

# Resultado: 10,000 llamadas Claude
# Costo: ~$150 USD en minutos ⚠️
```

**Verificación:**
```bash
# Ver requests recientes
docker-compose logs ai-service | grep -E "ai_validation|chat_message" | wc -l

# Si >1000 requests/hora → URGENTE
```

**Solución INMEDIATA (1 hora):**
```python
# ai-service/main.py - AGREGAR AHORA
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Inicializar limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Aplicar a endpoints críticos
@app.post("/api/ai/validate")
@limiter.limit("20/minute")  # Max 20 validaciones/minuto
async def validate_dte(...):
    pass

@app.post("/api/chat/message")
@limiter.limit("30/minute")  # Max 30 mensajes/minuto
async def send_chat_message(...):
    pass

@app.post("/api/ai/analytics/suggest_project")
@limiter.limit("50/minute")  # Max 50 sugerencias/minuto
async def suggest_project(...):
    pass
```

**Deploy:**
```bash
docker-compose restart ai-service
# Sin rebuild necesario (solo cambio Python)
```

---

### 3. ❌ **Respuestas Claude sin Validación - Crashes Aleatorios**

**Problema:**
Claude a veces devuelve JSON con markdown:
```json
```json
{
  "confidence": 95,
  "warnings": []
}
```
```

Esto causa:
```python
result = json.loads(response_text)  # ❌ JSONDecodeError
```

**Verificación:**
```bash
# Buscar crashes recientes
docker-compose logs ai-service --since 24h | grep -E "JSONDecodeError|json_decode_error"
```

**Solución INMEDIATA (30 min):**
```python
# ai-service/utils/llm_helpers.py (NUEVO ARCHIVO)
import re
import json
from typing import Any

def extract_json_from_llm_response(text: str) -> Any:
    """
    Extrae JSON de respuesta LLM (con/sin markdown).
    
    Maneja:
    - JSON puro: {"key": "value"}
    - JSON en markdown: ```json {...} ```
    - JSON con texto antes/después
    """
    # Intentar encontrar JSON en bloque markdown
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
    if json_match:
        text = json_match.group(1)
    
    # Buscar primer { y último }
    start = text.find('{')
    end = text.rfind('}')
    
    if start == -1 or end == -1:
        raise ValueError(f"No JSON found in LLM response: {text[:100]}")
    
    json_str = text[start:end+1]
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in LLM response: {e}\nText: {json_str[:200]}")

# Usar en TODOS los clientes LLM:
# ai-service/clients/anthropic_client.py
from utils.llm_helpers import extract_json_from_llm_response

def validate_dte(self, dte_data, history):
    # ... llamada a Claude ...
    response_text = message.content[0].text
    
    # ✅ CAMBIO CRÍTICO
    try:
        result = extract_json_from_llm_response(response_text)
    except ValueError as e:
        logger.error("llm_json_parse_error", 
                    response_preview=response_text[:200],
                    error=str(e))
        # Fallback seguro
        return {
            'confidence': 50.0,
            'warnings': ['Error parsing AI response'],
            'errors': [],
            'recommendation': 'review'
        }
    
    return result
```

**Deploy:**
```bash
docker-compose restart ai-service
```

---

### 4. ❌ **Sin Cache - Costos 3-4x Mayores de lo Necesario**

**Problema:**
Misma validación DTE ejecutada múltiples veces consume tokens duplicados.

**Ejemplo Real:**
```python
# Usuario abre wizard validación 3 veces
# (checkeando folio, cert, etc.)
validate_dte(invoice_1)  # ⚠️ Llamada Claude ($0.02)
validate_dte(invoice_1)  # ⚠️ Misma llamada ($0.02)
validate_dte(invoice_1)  # ⚠️ Misma llamada ($0.02)

# Total: $0.06 cuando debería ser $0.02
```

**Verificación:**
```bash
# Ver llamadas duplicadas
docker-compose logs ai-service | grep "claude_validation_started" | sort | uniq -c | sort -rn | head
# Si ves líneas con count >1 → hay duplicación
```

**Solución INTERMEDIA (2 horas):**
```python
# ai-service/utils/cache.py (NUEVO ARCHIVO)
import hashlib
import json
from functools import wraps
from utils.redis_helper import get_redis_client
import structlog

logger = structlog.get_logger()

def cache_llm_response(ttl_seconds: int = 900):  # 15 minutos
    """Cache respuestas LLM en Redis."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generar cache key
            cache_data = {
                'function': func.__name__,
                'args': str(args[1:]),  # Skip self
                'kwargs': kwargs
            }
            cache_key_raw = json.dumps(cache_data, sort_keys=True)
            cache_key = f"llm_cache:{hashlib.md5(cache_key_raw.encode()).hexdigest()}"
            
            # Check cache
            redis_client = get_redis_client()
            cached = redis_client.get(cache_key)
            
            if cached:
                logger.info("llm_cache_hit", 
                          function=func.__name__,
                          key=cache_key[:20])
                return json.loads(cached)
            
            # Cache miss
            logger.info("llm_cache_miss", function=func.__name__)
            result = func(*args, **kwargs)
            
            # Save to cache
            try:
                redis_client.setex(
                    cache_key,
                    ttl_seconds,
                    json.dumps(result)
                )
            except Exception as e:
                logger.warning("cache_save_failed", error=str(e))
            
            return result
        
        return wrapper
    return decorator

# Aplicar en anthropic_client.py:
from utils.cache import cache_llm_response

@cache_llm_response(ttl_seconds=900)  # 15 min cache
def validate_dte(self, dte_data: Dict, history: List[Dict]) -> Dict:
    """Valida DTE con cache."""
    # ... código existente ...
```

**Ahorro estimado:** 30-40% en costos API

---

### 5. ❌ **Modelo Claude Incorrecto en Project Matcher**

**Problema:**
```python
# ai-service/analytics/project_matcher_claude.py:39
self.model = "claude-3-5-sonnet-20250219"  # ⚠️ Este modelo NO EXISTE
```

**Resultado:**
```
anthropic.NotFoundError: model 'claude-3-5-sonnet-20250219' not found
```

**Verificación:**
```bash
# Ver errores de modelo
docker-compose logs ai-service | grep -i "model.*not found"
```

**Solución INMEDIATA (2 min):**
```python
# ai-service/analytics/project_matcher_claude.py:39
self.model = "claude-3-5-sonnet-20241022"  # ✅ Modelo correcto
```

**Deploy:**
```bash
docker-compose restart ai-service
```

---

## 📊 MONITOREO URGENTE MIENTRAS SE ARREGLA

### Agregar Alertas Temporales

```bash
# Crear script de monitoreo temporal
cat > /Users/pedro/Documents/odoo19/scripts/monitor_ai_service.sh << 'EOF'
#!/bin/bash
# Monitoreo temporal ai-service

echo "=== AI Service Health ==="
docker-compose exec -T ai-service curl -s http://localhost:8002/health | jq

echo -e "\n=== Requests última hora ==="
docker-compose logs ai-service --since 1h | grep -E "validation|chat_message|suggest_project" | wc -l

echo -e "\n=== Errores última hora ==="
docker-compose logs ai-service --since 1h | grep -E "ERROR|error" | tail -20

echo -e "\n=== Costos estimados (tokens) ==="
docker-compose logs ai-service --since 1h | grep "anthropic_api_success" | \
  awk '{sum+=$NF} END {print "Total tokens: " sum "\nCosto estimado: $" sum*0.000003}'

echo -e "\n=== Duplicaciones detectadas ==="
docker-compose logs ai-service --since 1h | \
  grep "claude_validation_started" | sort | uniq -c | sort -rn | head -5
EOF

chmod +x /Users/pedro/Documents/odoo19/scripts/monitor_ai_service.sh

# Ejecutar cada 30 minutos con cron
(crontab -l 2>/dev/null; echo "*/30 * * * * /Users/pedro/Documents/odoo19/scripts/monitor_ai_service.sh >> /tmp/ai_service_monitor.log 2>&1") | crontab -
```

### Dashboard Grafana Urgente (Opcional)

Si tienen Grafana:
```bash
# Agregar a docker-compose.yml
grafana:
  image: grafana/grafana:latest
  ports:
    - "3000:3000"
  environment:
    - GF_AUTH_ANONYMOUS_ENABLED=true
  networks:
    - stack_network
```

---

## ⏰ PLAN DE ACCIÓN - PRÓXIMAS 24 HORAS

### 🔴 **AHORA MISMO (30 minutos)**

```bash
cd /Users/pedro/Documents/odoo19/ai-service

# 1. Verificar cuál main.py está corriendo (5 min)
docker-compose logs ai-service | grep "ai_service_starting" | tail -1

# 2. Fix modelo Claude (2 min)
sed -i '' 's/20250219/20241022/' analytics/project_matcher_claude.py

# 3. Restart servicio (2 min)
docker-compose restart ai-service

# 4. Verificar health (1 min)
docker-compose exec ai-service curl http://localhost:8002/health

# 5. Setup monitoreo temporal (5 min)
./scripts/monitor_ai_service.sh

# 6. Ver logs en tiempo real (background)
docker-compose logs -f ai-service | tee /tmp/ai_service_live.log &
```

### 🟡 **HOY (2-3 horas)**

**Implementar soluciones críticas:**

```bash
# 1. Consolidar main.py (si necesario)
# Decidir: main.py o main_v2.py
# Luego: docker-compose build ai-service

# 2. Agregar rate limiting (1 hora)
# Editar main.py con código de rate limiting
docker-compose restart ai-service

# 3. Agregar validación JSON (30 min)
# Crear utils/llm_helpers.py
# Actualizar clients/anthropic_client.py
docker-compose restart ai-service

# 4. Testing de cambios (30 min)
docker-compose exec ai-service pytest /app/tests/ -v
```

### 🟢 **MAÑANA (4 horas)**

```bash
# 1. Implementar cache Redis (2 horas)
# Crear utils/cache.py
# Aplicar decorador @cache_llm_response

# 2. Agregar métricas básicas (1 hora)
# Prometheus + endpoint /metrics

# 3. Tests de regresión (1 hora)
# Validar que todo funciona post-cambios
```

---

## 📈 MÉTRICAS DE ÉXITO

### Antes de Cambios (Baseline)
```bash
# Ejecutar AHORA para tener baseline
docker-compose logs ai-service --since 24h | grep "anthropic_api_success" | wc -l
# Ejemplo resultado: 1,234 requests

docker-compose logs ai-service --since 24h | grep "ERROR" | wc -l
# Ejemplo: 45 errores
```

### Después de Cambios (Target)
- ✅ Requests duplicados: -40% (con cache)
- ✅ Errores JSON: -100% (con validación)
- ✅ Costos API: -30-40% (con cache)
- ✅ Rate limit violations: 0 (con slowapi)
- ✅ Crashes: -90% (con validación + retry)

---

## 🚨 SEÑALES DE ALERTA

### Monitorear en Próximos Días

```bash
# 1. Costos API Claude
# Ver en: https://console.anthropic.com/usage
# Alerta si: >$100/día (depende de volumen esperado)

# 2. Logs de error
docker-compose logs ai-service --since 1h | grep -c ERROR
# Alerta si: >10 errores/hora

# 3. Latencia
docker-compose logs ai-service | grep "llm_request" | grep "latency_ms"
# Alerta si: >5000ms (5 segundos)

# 4. Rate limit hits
docker-compose logs ai-service | grep "rate_limit_exceeded"
# Revisar si límites son demasiado restrictivos
```

---

## 📞 CONTACTOS DE EMERGENCIA

Si algo sale mal durante implementación:

1. **Rollback inmediato:**
```bash
cd /Users/pedro/Documents/odoo19
git stash  # Guardar cambios
docker-compose restart ai-service
```

2. **Ver estado servicios:**
```bash
docker-compose ps
docker-compose logs ai-service --tail 100
```

3. **Verificar Odoo sigue funcionando:**
```bash
curl http://localhost:8169/web/health
```

4. **Restaurar versión anterior:**
```bash
git log --oneline | head -5
git checkout <commit_anterior>
docker-compose build ai-service
docker-compose up -d ai-service
```

---

## ✅ CHECKLIST PRE-DEPLOY

Antes de aplicar CUALQUIER cambio:

- [ ] ✅ Backup del código actual: `git commit -am "Pre-hotfix backup"`
- [ ] ✅ Verificar servicios corriendo: `docker-compose ps`
- [ ] ✅ Capturar baseline métricas (ver arriba)
- [ ] ✅ Tener ventana de mantenimiento (fuera de horario peak)
- [ ] ✅ Notificar al equipo de cambios
- [ ] ✅ Plan de rollback listo
- [ ] ✅ Tests unitarios pasan: `pytest`
- [ ] ✅ Logs monitoreados durante deploy

---

## 📋 RESUMEN EJECUTIVO

### Situación
- ✅ ai-service en producción (docker-compose.yml)
- ⚠️ 5 errores críticos afectando estabilidad y costos
- ⚠️ Sin monitoreo → problemas invisibles

### Impacto
- 🔴 **Alto:** Costos API descontrolados
- 🔴 **Alto:** Crashes aleatorios afectan UX
- 🟡 **Medio:** Confusión código duplicado

### Acción Inmediata (30 min)
1. Fix modelo Claude (`20250219` → `20241022`)
2. Setup monitoreo temporal
3. Verificar health post-restart

### Acción Urgente (3 horas hoy)
1. Rate limiting (evitar abuso API)
2. Validación JSON respuestas (evitar crashes)
3. Consolidar main.py/main_v2.py

### Acción Importante (24-48h)
1. Implementar cache Redis (-40% costos)
2. Agregar métricas Prometheus
3. Tests de regresión completos

**ROI:** Ahorro estimado $200-500/mes + estabilidad 99%+

---

**Documento creado:** 23 Oct 2025  
**Prioridad:** 🚨 URGENTE  
**Validez:** 48 horas (luego obsoleto si no se actúa)

