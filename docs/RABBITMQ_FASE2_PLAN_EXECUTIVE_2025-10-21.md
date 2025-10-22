# 🚀 PLAN EJECUTIVO: RABBITMQ FASE 2 - IMPLEMENTACIÓN

**Fecha:** 2025-10-21 22:41 UTC-03:00  
**Estado Actual:** 60/100 (Aceptable)  
**Objetivo:** 85/100 (Profesional)  
**Duración:** 1-2 días (8-16 horas)

---

## 📊 RESUMEN

### Brechas a Cerrar: 5/11

- 🔴 **Brecha 3:** Sin Implementación Real → RabbitMQClient profesional
- 🔴 **Brecha 4:** Sin Librería Python → Instalar aio-pika
- 🟡 **Brecha 5:** Sin Config Custom → rabbitmq.conf + definitions.json
- 🟡 **Brecha 7:** Sin Dead Letter Queues → 3 DLQ implementadas
- 🟢 **Brecha 10:** Sin Message TTL → TTL por queue
- 🟢 **Brecha 11:** Sin Priority Queues → Priority 0-10

### Arquitectura Objetivo

**Exchanges:** 3 (direct, topic, dlx)  
**Queues:** 6 principales + 3 DLQ  
**Features:** TTL, Priority, DLQ, Retry

---

## 📋 PLAN DE 5 ETAPAS

### ETAPA 1: Preparación (30 min)

**Acciones:**
1. Instalar aio-pika==9.3.0
2. Crear estructura directorios
3. Crear archivos base

**Comandos:**
```bash
cd dte-service
echo "aio-pika==9.3.0" >> requirements.txt
pip install aio-pika==9.3.0

mkdir -p ../config/rabbitmq
mkdir -p messaging
touch messaging/{__init__,models,rabbitmq_client,consumers}.py
```

---

### ETAPA 2: Configuración (1 hora)

**Archivos a crear:**

1. `config/rabbitmq/rabbitmq.conf` (15 min)
   - Memory watermark: 0.6
   - Disk limit: 2GB
   - Heartbeat: 60s
   - Logging configurado

2. `config/rabbitmq/definitions.json` (30 min)
   - 2 usuarios (admin, dte_service)
   - 1 vhost (/odoo)
   - 3 exchanges (dte.direct, dte.topic, dte.dlx)
   - 6 queues + 3 DLQ
   - Bindings configurados
   - Políticas HA

3. `docker-compose.yml` (15 min)
   - Montar rabbitmq.conf
   - Montar definitions.json

---

### ETAPA 3: Implementación Python (4-6 horas)

**Archivos a crear:**

1. `messaging/models.py` (30 min)
   - DTEMessage model
   - DTEAction enum
   - Validaciones Pydantic

2. `messaging/rabbitmq_client.py` (2 horas)
   - RabbitMQClient class
   - connect() con retry
   - publish() con priority
   - consume() con DLQ
   - Logging estructurado

3. `messaging/consumers.py` (1 hora)
   - generate_consumer()
   - validate_consumer()
   - send_consumer()

4. Integrar en `main.py` (1 hora)
   - Startup event
   - Shutdown event
   - Global client

---

### ETAPA 4: Testing (2 horas)

**Tests a crear:**

1. `tests/test_rabbitmq_client.py`
   - test_connect()
   - test_publish()
   - test_consume()
   - test_dlq()
   - test_retry()

2. `tests/test_consumers.py`
   - test_generate_consumer()
   - test_validate_consumer()
   - test_send_consumer()

---

### ETAPA 5: Verificación (30 min)

**Checklist:**
- [ ] aio-pika instalado
- [ ] Exchanges creados (3)
- [ ] Queues creadas (9 total)
- [ ] Publish funciona
- [ ] Consume funciona
- [ ] DLQ funciona
- [ ] Tests pasan (>80%)

---

## 📊 MEJORA ESPERADA

| Aspecto | Antes | Después | Mejora |
|---------|-------|---------|--------|
| Implementación | 20/100 | 95/100 | +75 pts |
| Config Custom | 0/100 | 100/100 | +100 pts |
| Dead Letter Queue | 0/100 | 100/100 | +100 pts |
| **TOTAL** | **60/100** | **85/100** | **+25 pts** |

---

## 🎯 ENTREGABLES

1. ✅ aio-pika instalado
2. ✅ rabbitmq.conf configurado
3. ✅ definitions.json con 3 exchanges, 9 queues
4. ✅ RabbitMQClient profesional (200+ líneas)
5. ✅ 3 consumers implementados
6. ✅ Tests completos (>80% cobertura)
7. ✅ Documentación

---

## 📅 CRONOGRAMA

**Día 1 (4-6 horas):**
- Etapa 1: Preparación (30 min)
- Etapa 2: Configuración (1 hora)
- Etapa 3: Implementación (2.5-4.5 horas)

**Día 2 (4-6 horas):**
- Etapa 3: Finalizar implementación (2-4 horas)
- Etapa 4: Testing (2 horas)
- Etapa 5: Verificación (30 min)

---

## ✅ PRÓXIMOS PASOS

1. Revisar y aprobar plan
2. Comenzar Etapa 1 (Preparación)
3. Ejecutar secuencialmente
4. Commit por etapa

**Tiempo total:** 8-16 horas  
**Resultado:** RabbitMQ Profesional (85/100)

---

**Plan creado:** 2025-10-21 22:41  
**Documento detallado:** Ver plan completo en repositorio  
**Estado:** ✅ LISTO PARA EJECUTAR
