# 🚀 Checklist de Despliegue - DTE Status Poller

**Fecha:** 2025-10-21
**Componente:** Polling Automático de Estado DTEs (Gap #9)
**Estado:** ✅ Código Completo - Listo para Despliegue

---

## 📋 PRE-REQUISITOS

### 1. Dependencias Python
- [x] `apscheduler>=3.10.4` agregado a `requirements.txt`
- [x] `redis>=5.0.1` ya presente en requirements.txt

### 2. Servicios Externos Requeridos
- [ ] Redis server ejecutándose (puerto 6379)
- [ ] RabbitMQ ejecutándose (opcional, no bloquea poller)
- [ ] Acceso a SII SOAP services (Maullin o Palena)

### 3. Variables de Entorno
```bash
# Ya configuradas en .env o config.py
REDIS_URL=redis://redis:6379/0
SII_WSDL_URL=https://maullin.sii.cl/...  # o Palena
SII_TIMEOUT=60
DTE_POLL_INTERVAL_MINUTES=15  # Opcional, default: 15
ODOO_URL=http://odoo:8069  # Para webhooks
```

---

## 🔨 PASOS DE DESPLIEGUE

### Paso 1: Rebuild Docker Image

```bash
cd /Users/pedro/Documents/odoo19
docker-compose build dte-service
```

**Verificación:**
```bash
# Ver que apscheduler se instaló correctamente
docker-compose run --rm dte-service pip list | grep -i apscheduler
# Debe mostrar: APScheduler    3.10.4 (o superior)
```

---

### Paso 2: Restart DTE Service

```bash
docker-compose restart dte-service
```

**Verificación:**
```bash
# Ver logs de startup
docker-compose logs -f dte-service

# Buscar líneas de éxito:
# ✅ "dte_status_poller_initialized" con poll_interval_minutes=15
# ✅ "dte_service_starting" con version y environment
```

---

### Paso 3: Verificar Poller Activo

```bash
# Verificar logs de inicialización del poller
docker-compose logs dte-service | grep -E "poller_initialized|poller_started"

# Esperado:
# {"event": "dte_status_poller_initialized", "poll_interval_minutes": 15}
```

---

### Paso 4: Testing Manual

#### 4.1 Crear DTE Pendiente en Redis (Simulación)

```bash
# Conectar a Redis
docker-compose exec redis redis-cli

# Crear DTE de prueba pendiente
SET dte:pending:TEST_TRACK_12345 '{
  "id": "999",
  "track_id": "TEST_TRACK_12345",
  "rut_emisor": "12345678-9",
  "status": "sent",
  "timestamp": "2025-10-21T10:00:00"
}'

# Verificar creación
GET dte:pending:TEST_TRACK_12345

# Salir
exit
```

#### 4.2 Esperar Polling Job (15 minutos o forzar manualmente)

**Opción A: Esperar ciclo natural (15 min)**
```bash
# Monitorear logs en tiempo real
docker-compose logs -f dte-service | grep -E "polling_job|polling_dte_status"

# Esperar hasta ver:
# {"event": "dte_polling_job_started"}
# {"event": "polling_dte_status", "track_id": "TEST_TRACK_12345"}
# {"event": "dte_polling_job_completed", "total_dtes": 1, "updated": 0}
```

**Opción B: Reducir intervalo temporalmente (para testing rápido)**
```python
# Editar temporalmente config.py o .env
DTE_POLL_INTERVAL_MINUTES=1  # 1 minuto en vez de 15

# Restart
docker-compose restart dte-service
```

#### 4.3 Verificar Logs del Polling

```bash
# Ver todas las ejecuciones del job
docker-compose logs dte-service | grep "polling_job"

# Esperado cada 15 minutos:
# ✅ "dte_polling_job_started"
# ✅ "pending_dtes_found" con count
# ✅ "dte_polling_job_completed" con total_dtes, updated, errors, duration_seconds
```

---

### Paso 5: Verificar Estado Final en Redis

```bash
docker-compose exec redis redis-cli

# Verificar si DTE sigue en pending (sin cambios del SII)
GET dte:pending:TEST_TRACK_12345

# O si fue movido a completed (si SII retornó estado final)
GET dte:completed:TEST_TRACK_12345

# Ver todas las keys de DTEs
KEYS dte:*

# Salir
exit
```

---

### Paso 6: Testing con DTE Real

**Una vez que tengas un DTE enviado al SII:**

1. Enviar DTE desde Odoo (método normal)
2. Verificar que se creó en Redis:
   ```bash
   docker-compose exec redis redis-cli
   KEYS dte:pending:*
   ```
3. Esperar 15 minutos (o reducir poll_interval)
4. Verificar logs:
   ```bash
   docker-compose logs dte-service | grep "track_id.*TU_TRACK_ID_REAL"
   ```
5. Verificar estado actualizado en Odoo (si webhook funcionó)

---

## ✅ CRITERIOS DE ÉXITO

### Logs Esperados (Sin Errores)

```json
// Startup
{"event": "dte_service_starting", "version": "1.0.0", "environment": "sandbox"}
{"event": "rabbitmq_startup_success"}
{"event": "dte_status_poller_initialized", "poll_interval_minutes": 15}
{"event": "xsd_schemas_loaded", "schemas": ["DTE"]}

// Cada 15 minutos
{"event": "dte_polling_job_started"}
{"event": "pending_dtes_found", "count": 5}
{"event": "polling_dte_status", "dte_id": "123", "track_id": "ABC123"}
{"event": "dte_polling_job_completed", "total_dtes": 5, "updated": 2, "errors": 0, "duration_seconds": 3.5}

// Si cambió estado
{"event": "dte_status_changed", "dte_id": "123", "track_id": "ABC123", "old_status": "sent", "new_status": "accepted"}
{"event": "dte_moved_to_completed", "track_id": "ABC123", "status": "accepted"}
{"event": "odoo_notified_successfully", "dte_id": "123", "new_status": "accepted"}

// Shutdown
{"event": "dte_service_shutting_down"}
{"event": "dte_status_poller_shutdown_success"}
{"event": "rabbitmq_shutdown_success"}
```

---

## 🐛 TROUBLESHOOTING

### Error: "dte_poller_startup_error"

**Causa:** Fallo al inicializar el poller

**Soluciones:**
1. Verificar que Redis está corriendo:
   ```bash
   docker-compose ps redis
   docker-compose logs redis
   ```

2. Verificar que SII client se puede inicializar:
   ```bash
   docker-compose logs dte-service | grep -i sii
   ```

3. Verificar imports:
   ```bash
   docker-compose exec dte-service python -c "from scheduler import init_poller; print('OK')"
   ```

---

### Error: "no_pending_dtes_found" (siempre)

**Causa:** No hay DTEs en Redis con estado 'sent'

**Soluciones:**
1. Verificar patrón de keys en Redis:
   ```bash
   docker-compose exec redis redis-cli KEYS "dte:pending:*"
   ```

2. Si no hay DTEs reales, crear uno de prueba (ver Paso 4.1)

3. Verificar que el código de envío de DTEs está creando las keys correctamente

---

### Warning: "dte_timeout"

**Causa:** DTE tiene más de 7 días en estado 'sent' (probablemente perdido)

**Acción:**
- Es comportamiento esperado
- El DTE se mueve automáticamente a `dte:timeout:{track_id}`
- Revisar manualmente en SII si es necesario

---

### Error: "sii_status_query_failed"

**Causa:** Fallo al consultar SII (timeout, conexión, o track_id inválido)

**Soluciones:**
1. Verificar conectividad a SII:
   ```bash
   docker-compose exec dte-service curl -I https://maullin.sii.cl
   ```

2. Verificar que track_id es válido (lo retornó el SII originalmente)

3. Revisar logs de errores SII:
   ```bash
   docker-compose logs dte-service | grep -i "sii.*error"
   ```

---

### Warning: "odoo_notification_failed"

**Causa:** Webhook a Odoo falló (timeout, URL incorrecta, Odoo caído)

**Soluciones:**
1. Verificar que Odoo está corriendo:
   ```bash
   docker-compose ps odoo
   ```

2. Verificar ODOO_URL en config:
   ```bash
   docker-compose exec dte-service env | grep ODOO_URL
   ```

3. Verificar endpoint existe en Odoo:
   ```bash
   curl -X POST http://odoo:8069/dte/webhook/status_update \
     -H "Content-Type: application/json" \
     -d '{"test": true}'
   ```

**Nota:** El poller NO falla si webhook falla (solo warning), el estado se actualiza en Redis de todas formas.

---

## 📊 MONITOREO EN PRODUCCIÓN

### Métricas a Monitorear

1. **Frecuencia de Ejecución:**
   ```bash
   # Debe ejecutarse cada 15 minutos
   docker-compose logs --since 2h dte-service | grep "polling_job_started" | wc -l
   # Esperado: 8 (en 2 horas)
   ```

2. **Tasa de Updates:**
   ```bash
   # Ver cuántos DTEs se actualizaron en última ejecución
   docker-compose logs dte-service | grep "polling_job_completed" | tail -1
   # Ver campo: "updated": X
   ```

3. **Errores:**
   ```bash
   # Buscar errores en polling
   docker-compose logs dte-service | grep -E "error.*poll|poll.*error"
   ```

4. **Performance:**
   ```bash
   # Ver duración de cada job
   docker-compose logs dte-service | grep "polling_job_completed" | jq '.duration_seconds'
   # Esperado: < 10 segundos para pocos DTEs
   ```

---

## 🎯 CONFIGURACIÓN AVANZADA

### Cambiar Intervalo de Polling

**Opción 1: Variable de Entorno**
```bash
# En .env o docker-compose.yml
DTE_POLL_INTERVAL_MINUTES=10  # Cada 10 minutos

# Restart
docker-compose restart dte-service
```

**Opción 2: Modificar config.py**
```python
# dte-service/config.py
class Settings(BaseSettings):
    # ...
    dte_poll_interval_minutes: int = 10  # Cambiar de 15 a 10
```

**Recomendaciones SII:**
- **Producción:** 15-30 minutos (evitar sobrecarga)
- **Testing:** 5-10 minutos (feedback más rápido)
- **NO usar < 5 minutos** (puede ser considerado abuso por SII)

---

### Timeout de DTEs Antiguos

Cambiar de 7 días a otro valor:

```python
# dte-service/scheduler/dte_status_poller.py:164
if age_days > 7:  # Cambiar a 14 para 2 semanas
```

---

### TTL de DTEs Completados

Cambiar de 30 días a otro valor:

```python
# dte-service/scheduler/dte_status_poller.py:261
self.redis_client.setex(
    completed_key,
    timedelta(days=30),  # Cambiar a 90 para 3 meses
    json.dumps(dte)
)
```

---

## ✅ SIGN-OFF

- [ ] Docker image rebuilt con apscheduler
- [ ] DTE service reiniciado
- [ ] Logs muestran "dte_status_poller_initialized"
- [ ] Redis accesible desde container
- [ ] Polling job ejecutándose cada 15 minutos
- [ ] DTEs de prueba procesados correctamente
- [ ] Webhooks a Odoo funcionando (opcional)
- [ ] No hay errores en logs de poller
- [ ] Métricas de performance < 10 segundos
- [ ] Documentación leída y comprendida

**Responsable:** _________________
**Fecha:** _________________
**Firma:** _________________

---

**Documento:** DEPLOYMENT_CHECKLIST_POLLER.md
**Versión:** 1.0
**Última Actualización:** 2025-10-21
**Autor:** Claude Code (Gap Closure Task)
