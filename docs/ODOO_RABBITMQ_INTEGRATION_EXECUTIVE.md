# 🔗 PLAN EJECUTIVO: INTEGRACIÓN ODOO ↔ RABBITMQ

**Fecha:** 2025-10-21 23:05 UTC-03:00  
**Objetivo:** Cerrar brechas de integración asíncrona  
**Duración:** 16-24 horas  
**Estado actual:** 40% → Objetivo: 100%

---

## 🎯 BRECHAS A CERRAR

| # | Brecha | Impacto | Esfuerzo | Estado |
|---|--------|---------|----------|--------|
| 1 | Odoo no publica a RabbitMQ | 🔴 CRÍTICO | 3-4h | 0% |
| 2 | Consumers inactivos | 🔴 CRÍTICO | 30min | 50% |
| 3 | Sin webhook callback | 🔴 CRÍTICO | 2-3h | 0% |
| 4 | Sin tests integración | 🟡 ALTO | 3-4h | 0% |
| 5 | Sin manejo errores | 🟡 MEDIO | 2h | 0% |

---

## 📋 PLAN DE 5 FASES

### FASE 1: Preparación Odoo (1h)
- Instalar pika en contenedor Odoo
- Crear rabbitmq_helper.py
- Configurar parámetros sistema

### FASE 2: Odoo → RabbitMQ (3-4h)
- Modificar account_move_dte.py
- Agregar campos dte_async_status
- Crear action_send_dte_async()
- Actualizar vista XML

### FASE 3: Webhook Odoo (2-3h)
- Crear controllers/dte_webhook.py
- Endpoint /api/dte/callback
- Actualizar estado facturas

### FASE 4: DTE Service (2-3h)
- Activar consumers
- Implementar _notify_odoo()
- Actualizar config.py

### FASE 5: Testing (3-4h)
- Tests unitarios
- Tests integración
- Test end-to-end

---

## 🚀 FLUJO COMPLETO

```
1. Usuario en Odoo → Crea factura → Valida
2. Usuario → Click "Enviar DTE (Async)"
3. Odoo → Publica mensaje a RabbitMQ (dte.direct)
4. Odoo → Estado: "En Cola"
5. DTE Service → Consumer recibe mensaje
6. DTE Service → Genera XML, valida, firma
7. DTE Service → Envía al SII
8. DTE Service → Notifica a Odoo (webhook)
9. Odoo → Actualiza estado: "Enviado al SII"
10. Odoo → Registra en chatter
```

---

## ✅ ENTREGABLES

1. **Código Odoo:**
   - rabbitmq_helper.py (150 líneas)
   - account_move_dte.py modificado (+200 líneas)
   - dte_webhook.py (150 líneas)
   - Vista XML actualizada

2. **Código DTE Service:**
   - main.py (consumers activos)
   - consumers.py (+100 líneas notificación)
   - config.py actualizado

3. **Tests:**
   - test_rabbitmq_integration.py (8 tests)
   - test_webhook.py (6 tests)
   - test_end_to_end.py (4 tests)

4. **Documentación:**
   - Guía de uso
   - Troubleshooting
   - Diagramas de flujo

---

## 📊 RESULTADO ESPERADO

**Antes:** HTTP síncrono, usuario espera 10-30s  
**Después:** RabbitMQ asíncrono, usuario espera <1s

**Mejoras:**
- ✅ Usuario no bloqueado
- ✅ Retry automático (3 intentos)
- ✅ Dead Letter Queue para errores
- ✅ Escalabilidad horizontal
- ✅ Monitoreo en tiempo real

---

**¿Procedemos con la implementación?**
