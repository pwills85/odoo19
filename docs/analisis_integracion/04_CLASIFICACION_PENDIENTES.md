# 📋 CLASIFICACIÓN DE PENDIENTES POR ÁMBITO

**Fecha:** 2025-10-22  
**Versión:** 1.0  
**Documento:** 4 de 6

---

## 📋 OBJETIVO

Clasificar **TODOS los pendientes identificados** en el análisis previo, asignándolos con precisión al ámbito correcto:

1. **Módulo Odoo** (`l10n_cl_dte`)
2. **Microservicio DTE** (`dte-service`)
3. **Microservicio IA** (`ai-service`)
4. **Infraestructura** (RabbitMQ, Docker, etc.)

---

## 🎯 METODOLOGÍA DE CLASIFICACIÓN

### **Criterios de Asignación:**

| Criterio | Módulo Odoo | Microservicio DTE | Microservicio IA |
|----------|-------------|-------------------|------------------|
| **Persistencia de datos** | ✅ | - | - |
| **UI/UX** | ✅ | - | - |
| **Validaciones negocio** | ✅ | - | - |
| **Generación XML** | - | ✅ | - |
| **Firma digital** | - | ✅ | - |
| **SOAP SII** | - | ✅ | - |
| **Validación semántica** | - | - | ✅ |
| **Procesamiento cognitivo** | - | - | ✅ |

---

## 📊 CATEGORÍA 1: PENDIENTES CRÍTICOS (Certificación SII)

### **1.1 Obtener Certificado Digital SII**

**Ámbito:** 🏢 **MÓDULO ODOO** + 🚀 **MICROSERVICIO DTE**

**Tareas Módulo Odoo:**
```python
✅ Crear modelo dte.certificate (YA EXISTE)
✅ Vista form para importar certificado
✅ Validar vigencia del certificado
✅ Encriptar contraseña en base de datos
✅ Configurar certificado activo por compañía
```

**Tareas Microservicio DTE:**
```python
✅ Recibir certificado vía API
✅ Cargar certificado .pfx/.p12
✅ Validar certificado con OpenSSL
✅ Usar certificado para firma XMLDsig
```

**Estado Actual:** ✅ Implementado (falta certificado real)

**Acción Requerida:** 🔴 **EXTERNA** - Solicitar certificado a autoridad certificadora

---

### **1.2 Obtener CAF (Folios Autorizados)**

**Ámbito:** 🏢 **MÓDULO ODOO**

**Tareas:**
```python
✅ Crear modelo dte.caf (YA EXISTE)
✅ Vista form para importar CAF XML
✅ Parsear XML CAF y extraer rangos
✅ Validar firma del CAF
✅ Asignar folios secuencialmente
✅ Alertar cuando quedan <10% folios
```

**Estado Actual:** ✅ Implementado (falta CAF real)

**Acción Requerida:** 🔴 **EXTERNA** - Solicitar CAF en portal Maullin

---

### **1.3 Testing con SII Real (Maullin)**

**Ámbito:** 🚀 **MICROSERVICIO DTE** + 🏢 **MÓDULO ODOO**

**Tareas Microservicio DTE:**
```python
✅ Configurar URL Maullin (sandbox)
✅ Generar XML DTE válido
✅ Firmar con certificado real
✅ Enviar vía SOAP a Maullin
✅ Parsear respuesta SII
✅ Manejar errores SII
```

**Tareas Módulo Odoo:**
```python
✅ Crear facturas de prueba
✅ Enviar DTEs a Maullin
✅ Almacenar respuestas SII
✅ Mostrar errores en UI
✅ Corregir y reenviar
```

**Estado Actual:** ⚠️ Parcial (falta certificado + CAF real)

**Acción Requerida:** 🟡 Ejecutar cuando tengamos certificado + CAF

---

## 📊 CATEGORÍA 2: PENDIENTES INTEGRACIÓN ODOO (Fases 5-7)

### **2.1 Fase 5: Actualizar Vistas XML**

**Ámbito:** 🏢 **MÓDULO ODOO**

**Tareas:**
```xml
✅ Actualizar account_move_dte_views.xml
   - Verificar referencias a dte_code (related field)
   - Actualizar attrs y domains
   - Agregar campos faltantes en form view

✅ Actualizar dte_certificate_views.xml
   - Agregar indicador de vigencia
   - Mejorar UX de importación

✅ Verificar herencias xpath
   - Asegurar compatibilidad con l10n_cl
   - No romper vistas base
```

**Archivos Afectados:**
- `views/account_move_dte_views.xml`
- `views/dte_certificate_views.xml`
- `views/dte_caf_views.xml`

**Tiempo Estimado:** 1 hora

**Estado Actual:** ⚠️ Pendiente

---

### **2.2 Fase 6: Testing Completo Integración**

**Ámbito:** 🏢 **MÓDULO ODOO** + 🚀 **MICROSERVICIO DTE**

**Tareas:**
```python
✅ Test flujo completo: Factura → DTE → SII
   - Crear factura en Odoo
   - Confirmar factura
   - Enviar DTE
   - Verificar respuesta SII
   - Validar estado actualizado

✅ Test sincronización CAF ↔ l10n_latam
   - Verificar relación con l10n_latam.document.type
   - Validar consumo de folios
   - Probar alerta de folios bajos

✅ Test validaciones RUT
   - RUT válido (módulo 11)
   - RUT inválido
   - RUT sin dígito verificador

✅ Test casos edge
   - Factura sin productos
   - Factura con descuentos
   - Factura con múltiples impuestos
   - Notas de crédito
```

**Tiempo Estimado:** 1.5 horas

**Estado Actual:** ⚠️ Pendiente

---

### **2.3 Fase 7: Validación SII**

**Ámbito:** 🚀 **MICROSERVICIO DTE**

**Tareas:**
```python
✅ Implementar API GetEstadoDTE
   - Cliente SOAP para consulta
   - Parsear respuesta SII
   - Mapear estados SII

✅ Verificación RUT online
   - Integrar con API SII
   - Validar existencia RUT
   - Obtener razón social

✅ Validación giros comerciales
   - Consultar giros en SII
   - Validar coherencia

✅ Status tracking automático
   - Polling periódico de estado
   - Actualizar en Odoo vía webhook
```

**Archivos Afectados:**
- `dte-service/clients/sii_api_client.py` (nuevo)
- `dte-service/main.py` (endpoint /api/dte/status)

**Tiempo Estimado:** 3 horas

**Estado Actual:** ⚠️ Pendiente

---

## 📊 CATEGORÍA 3: PENDIENTES RABBITMQ FASE 2

### **3.1 Profesionalización RabbitMQ**

**Ámbito:** 🚀 **MICROSERVICIO DTE** + 🐰 **INFRAESTRUCTURA**

**Tareas Infraestructura:**
```yaml
✅ Configurar rabbitmq.conf
   - Memory limits
   - Disk limits
   - Heartbeat
   - Channel max

✅ Configurar definitions.json
   - Exchanges (dte.direct, dte.topic)
   - Queues (dte.generate, dte.validate, dte.send)
   - Bindings
   - Policies (TTL, DLQ, Priority)

✅ Configurar Dead Letter Queues
   - dte.dlq.generate
   - dte.dlq.validate
   - dte.dlq.send
```

**Tareas Microservicio:**
```python
✅ Instalar aio-pika
   - Reemplazar pika por aio-pika
   - Implementar async/await

✅ Implementar RabbitMQClient profesional
   - Connection pooling
   - Automatic reconnection
   - Prefetch control
   - Confirm mode

✅ Implementar TTL por queue
   - dte.generate: 5 min
   - dte.validate: 3 min
   - dte.send: 10 min

✅ Implementar Priority queues
   - Prioridad 0-10
   - DTEs urgentes prioridad 10

✅ Testing completo
   - Test DLQ
   - Test TTL
   - Test Priority
   - Test reconexión
```

**Archivos Afectados:**
- `config/rabbitmq/rabbitmq.conf`
- `config/rabbitmq/definitions.json`
- `dte-service/messaging/rabbitmq_client.py`
- `dte-service/requirements.txt`

**Tiempo Estimado:** 8-16 horas

**Estado Actual:** ⚠️ Pendiente

---

## 📊 CATEGORÍA 4: PENDIENTES MONITOREO SII UI

### **4.1 Integración UI en Odoo**

**Ámbito:** 🏢 **MÓDULO ODOO**

**Tareas:**
```python
✅ Crear modelo dte.sii.news
   - tipo (Resolución, Circular, Aviso)
   - numero
   - fecha
   - vigencia
   - titulo
   - resumen
   - prioridad (1-10)
   - state (new, reviewed, archived)

✅ Crear modelo dte.sii.monitoring.config
   - enabled
   - frequency (horas)
   - slack_webhook
   - email_recipients

✅ Crear vistas
   - Tree view con filtros
   - Form view detallada
   - Search view avanzada
   - Dashboard con KPIs

✅ Crear wizard de revisión
   - Marcar como revisada
   - Agregar notas
   - Asignar responsable

✅ Configurar cron automático
   - Ejecutar cada 6h
   - Llamar AI Service
   - Crear registros automáticamente
```

**Archivos Afectados:**
- `models/dte_sii_news.py` (nuevo)
- `models/dte_sii_monitoring_config.py` (nuevo)
- `views/dte_sii_news_views.xml` (nuevo)
- `wizard/review_sii_news.py` (nuevo)
- `data/ir_cron.xml` (nuevo)

**Tiempo Estimado:** 2-3 días

**Estado Actual:** ⚠️ Pendiente (backend 100% completo)

---

## 📊 CATEGORÍA 5: PENDIENTES CHAT IA

### **5.1 Backend Chat IA**

**Ámbito:** 🤖 **MICROSERVICIO IA**

**Tareas:**
```python
✅ Endpoint /api/ai/sii/chat
   - Recibir mensaje usuario
   - Mantener contexto conversación
   - Generar respuesta con Claude
   - Buscar en documentación (RAG)

✅ Context management
   - Almacenar historial en Redis
   - Sliding window (últimos 10 mensajes)
   - Embeddings para búsqueda

✅ Comandos especiales
   - /help - Ayuda
   - /status - Estado sistema
   - /search [query] - Buscar docs
   - /clear - Limpiar contexto
```

**Archivos Afectados:**
- `ai-service/main.py` (endpoint nuevo)
- `ai-service/chat/context_manager.py` (nuevo)
- `ai-service/chat/rag_engine.py` (nuevo)

**Tiempo Estimado:** 2 días

**Estado Actual:** ⚠️ Pendiente

---

### **5.2 Frontend Chat IA**

**Ámbito:** 🏢 **MÓDULO ODOO**

**Tareas:**
```javascript
✅ Widget JavaScript
   - Chat UI responsive
   - Markdown support
   - Code highlighting
   - Auto-scroll

✅ Integraciones
   - Buscar DTEs
   - Consultar estado
   - Generar reportes

✅ Persistencia
   - Modelo chat.conversation
   - Guardar historial
   - Recuperar conversaciones
```

**Archivos Afectados:**
- `static/src/js/sii_chat_widget.js` (nuevo)
- `static/src/xml/sii_chat_widget.xml` (nuevo)
- `static/src/css/sii_chat_widget.css` (nuevo)
- `models/chat_conversation.py` (nuevo)

**Tiempo Estimado:** 3 días

**Estado Actual:** ⚠️ Pendiente

---

## 📊 CATEGORÍA 6: PENDIENTES REPORTES AVANZADOS

### **6.1 Libro de Compras y Ventas**

**Ámbito:** 🏢 **MÓDULO ODOO**

**Tareas:**
```python
✅ Modelo dte.libro
   - tipo (compra/venta)
   - periodo (mes/año)
   - state (draft, generated, sent)
   - xml_file

✅ Generador Libro Compras
   - Filtrar facturas de compra
   - Generar XML según formato SII
   - Validar contra XSD

✅ Generador Libro Ventas
   - Filtrar facturas de venta
   - Generar XML según formato SII
   - Validar contra XSD

✅ Wizard de generación
   - Seleccionar periodo
   - Preview antes de generar
   - Export Excel

✅ Envío a SII
   - Integrar con DTE Service
   - Firmar XML
   - Enviar vía SOAP
```

**Archivos Afectados:**
- `models/dte_libro.py` (actualizar)
- `wizard/generate_libro.py` (implementar)
- `views/dte_libro_views.xml` (actualizar)

**Tiempo Estimado:** 2 días

**Estado Actual:** ⚠️ Stub (pendiente implementación)

---

### **6.2 Dashboard Ejecutivo**

**Ámbito:** 🏢 **MÓDULO ODOO**

**Tareas:**
```python
✅ KPIs principales
   - DTEs enviados (hoy/semana/mes)
   - Tasa de aceptación SII
   - Tiempo promedio respuesta
   - Folios disponibles

✅ Gráficos
   - DTEs por tipo (pie chart)
   - Tendencia temporal (line chart)
   - Estados DTE (bar chart)

✅ Drill-down
   - Click en gráfico → Lista facturas
   - Filtros dinámicos
```

**Archivos Afectados:**
- `views/dte_dashboard.xml` (nuevo)
- `static/src/js/dte_dashboard.js` (nuevo)

**Tiempo Estimado:** 1 día

**Estado Actual:** ⚠️ Pendiente

---

## 📊 CATEGORÍA 7: TODOs EN CÓDIGO

### **7.1 TODOs Microservicio DTE**

**Ámbito:** 🚀 **MICROSERVICIO DTE**

| TODO | Archivo | Línea | Prioridad | Acción |
|------|---------|-------|-----------|--------|
| Implementar consulta real SII | main.py | 470 | 🔴 Alta | Fase 7 |
| Implementar generación real XML | consumers.py | 135 | 🟡 Media | Refactor |
| Implementar validación real SII | consumers.py | 248 | 🟡 Media | Fase 7 |
| Implementar envío real SII | consumers.py | 351 | 🔴 Alta | Ya funciona |
| Verificación con xmlsec | dte_signer.py | 167 | 🟢 Baja | Mejora futura |
| Load user from DB | auth/routes.py | 64 | 🟢 Baja | Mejora futura |
| Token blacklist Redis | auth/routes.py | 215 | 🟢 Baja | Mejora futura |

**Clasificación:**
- 🔴 **Alta:** Implementar en Fase 7 (Validación SII)
- 🟡 **Media:** Refactorizar cuando sea necesario
- 🟢 **Baja:** Mejoras futuras opcionales

---

### **7.2 TODOs Módulo Odoo**

**Ámbito:** 🏢 **MÓDULO ODOO**

| TODO | Archivo | Línea | Prioridad | Acción |
|------|---------|-------|-----------|--------|
| Implementar DTE 34 | purchase_order_dte.py | 194 | 🟡 Media | Fase posterior |
| Implementar DTE 52 | stock_picking_dte.py | 112 | 🟡 Media | Fase posterior |
| Implementar consumo folios | dte_consumo_folios.py | 212 | 🟢 Baja | Opcional |
| Implementar reporte retenciones | retencion_iue.py | 149 | 🟢 Baja | Opcional |
| Implementar libro electrónico | generate_libro.py | 22 | 🟡 Media | Categoría 6.1 |

**Clasificación:**
- 🟡 **Media:** Implementar según prioridad negocio
- 🟢 **Baja:** Features secundarios opcionales

---

### **7.3 TODOs Microservicio IA**

**Ámbito:** 🤖 **MICROSERVICIO IA**

| TODO | Archivo | Línea | Prioridad | Acción |
|------|---------|-------|-----------|--------|
| Métricas reales Redis | main.py | 353 | 🟢 Baja | Mejora futura |
| Last execution Redis | main.py | 357 | 🟢 Baja | Mejora futura |
| News count Redis | main.py | 358 | 🟢 Baja | Mejora futura |

**Clasificación:**
- 🟢 **Baja:** Mejoras de monitoreo, no críticas

---

## 📊 RESUMEN POR ÁMBITO

### **🏢 MÓDULO ODOO (l10n_cl_dte)**

**Pendientes Críticos:**
- ✅ Modelo CAF (implementado, falta CAF real)
- ✅ Modelo Certificado (implementado, falta certificado real)

**Pendientes Importantes:**
- ⚠️ Fase 5: Actualizar vistas XML (1h)
- ⚠️ Fase 6: Testing integración (1.5h)
- ⚠️ Monitoreo SII UI (2-3 días)
- ⚠️ Chat IA Frontend (3 días)
- ⚠️ Libro Compras/Ventas (2 días)
- ⚠️ Dashboard Ejecutivo (1 día)

**Total Estimado:** 8-10 días

---

### **🚀 MICROSERVICIO DTE (dte-service)**

**Pendientes Críticos:**
- ⚠️ Testing con SII real (requiere certificado + CAF)

**Pendientes Importantes:**
- ⚠️ Fase 7: API GetEstadoDTE (3h)
- ⚠️ RabbitMQ Fase 2 (8-16h)

**Pendientes Opcionales:**
- 🟢 Refactor consumers (simulados → reales)
- 🟢 Verificación xmlsec
- 🟢 User DB + Token blacklist

**Total Estimado:** 2-4 días

---

### **🤖 MICROSERVICIO IA (ai-service)**

**Pendientes Importantes:**
- ⚠️ Chat IA Backend (2 días)

**Pendientes Opcionales:**
- 🟢 Métricas Redis (mejora futura)

**Total Estimado:** 2 días

---

### **🐰 INFRAESTRUCTURA**

**Pendientes Importantes:**
- ⚠️ RabbitMQ configuración profesional (1 día)
- ⚠️ Certificado SII real (externo, 3-5 días)
- ⚠️ CAF real (externo, 1 día)

**Total Estimado:** 5-7 días (incluye trámites)

---

## ✅ CONCLUSIONES

### **Priorización Recomendada:**

**SPRINT 1 (1-2 semanas) - PRODUCCIÓN MÍNIMA:**
1. 🔴 Obtener certificado SII (externo)
2. 🔴 Obtener CAF Maullin (externo)
3. 🔴 Testing con SII real
4. 🟡 Fase 5-7 Integración Odoo (5.5h)

**SPRINT 2 (2-3 semanas) - PRODUCCIÓN COMPLETA:**
5. 🟡 RabbitMQ Fase 2 (2 días)
6. 🟡 Libro Compras/Ventas (2 días)
7. 🟡 Dashboard Ejecutivo (1 día)

**SPRINT 3 (1 mes) - EXCELENCIA:**
8. 🟢 Monitoreo SII UI (2-3 días)
9. 🟢 Chat IA (5 días)

---

**Próximo Documento:** `05_FUNDAMENTOS_TECNICOS.md`
