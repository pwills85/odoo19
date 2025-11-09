# 🎯 PLAN MAESTRO DE CIERRE DE BRECHAS - ODOO 19 CE + FE CHILE

**Fecha:** 2025-10-22  
**Versión:** 1.0  
**Arquitecto Lead:** Análisis Técnico Senior

---

## 📋 RESUMEN EJECUTIVO

**Objetivo:** Cierre total de brechas para Facturación Electrónica Chilena (SII) integrada nativamente con Odoo 19 CE.

**Estado Actual:** 73% completo
- Módulo Odoo: 85% (falta certificación real)
- Microservicios: 90% (falta profesionalización RabbitMQ)
- Agente IA: 80% (falta UI integrada)
- Certificación SII: 0% (bloqueante crítico)

**Documentos Consultados:**
- `/docs/analisis_integracion/` (6 documentos)
- `/docs/odoo19_official/` (INDEX.md, manifests, models)
- `/docs/GAP_ANALYSIS_TO_100.md`
- `/addons/localization/l10n_cl_dte/__manifest__.py`
- `/dte-service/main.py`, `/ai-service/main.py`

---

## 🗺️ MAPA DE BRECHAS

### **Críticas (Bloqueantes):**
1. 🔴 Certificado SII real (3-5 días trámite)
2. 🔴 CAF real (1 día trámite)
3. 🔴 Testing SII real Maullin

### **Importantes:**
4. 🟡 Vistas XML actualización (1h)
5. 🟡 Testing integración completo (1.5h)
6. 🟡 API GetEstadoDTE (3h)
7. 🟡 RabbitMQ profesionalización (8-16h)
8. 🟡 Libro Compras/Ventas (2 días)
9. 🟡 CI/CD pipeline (2 días)
10. 🟡 Observabilidad completa (1-2 días)

### **Opcionales:**
11. 🟢 Dashboard ejecutivo (1 día)
12. 🟢 Monitoreo SII UI (2-3 días)
13. 🟢 Chat IA frontend (3 días)

**Total Estimado:** 17-23 días (3-5 semanas)

---

## 🏗️ ARQUITECTURA - PUNTOS DE INTEGRACIÓN

### **Módulos Odoo Base Reutilizados:**
- `l10n_latam_base` → Tipos identificación (RUT)
- `l10n_latam_invoice_document` → Tipos DTE (33, 52, 56, 61)
- `l10n_cl` → Validación RUT, tipo contribuyente
- `account` → Facturas, diarios, impuestos

### **Extensiones l10n_cl_dte:**
- `account.move` (_inherit) → +dte_status, +dte_folio, +dte_xml
- `res.partner` (_inherit) → +dte_email, +dte_reception_enabled
- `dte.caf` (_name nuevo) → Gestión folios SII
- `dte.certificate` (_name nuevo) → Certificados digitales

### **Microservicios:**
- **DTE Service:** XML, firma XMLDsig, SOAP SII, RabbitMQ
- **AI Service:** Validación semántica, monitoreo SII, chat

### **Integraciones:**
- Odoo → DTE Service: HTTP POST `/api/dte/generate-and-send`
- DTE Service → Odoo: Webhook `/dte/webhook`
- DTE Service → AI Service: HTTP POST `/api/ai/validate-dte`
- DTE Service ↔ RabbitMQ: AMQP (dte.generate → dte.validate → dte.send)

---

## 📅 PLAN POR FASES

### **F0 - Baseline & Evidencia (1 día)**
**Objetivos:**
- Inventario completo de artefactos
- Validación de supuestos
- Diagramas actuales

**Actividades:**
1. Revisar 6 documentos análisis técnico
2. Validar estado código actual
3. Confirmar dependencias Odoo 19 CE
4. Documentar gaps de información

**Criterios Aceptación:**
- ✅ Inventario completo documentado
- ✅ Supuestos validados o marcados
- ✅ Diagrama arquitectura actualizado

---

### **F1 - Arquitectura de Integración (2 días)**
**Objetivos:**
- Diseño detallado puntos extensión Odoo
- Definición contratos microservicios
- Límites responsabilidad IA

**Actividades:**
1. Documentar todos los `_inherit` y `super()`
2. Definir schemas API (OpenAPI)
3. Diseñar flujo DTE end-to-end
4. Especificar contratos RabbitMQ (queues, TTL, DLQ)

**Salidas:**
- Documento arquitectura detallada
- Schemas OpenAPI (DTE Service, AI Service)
- Diagrama secuencia DTE completo

**Criterios Aceptación:**
- ✅ Todos los puntos extensión documentados
- ✅ Contratos API validados
- ✅ Flujo DTE sin ambigüedades

---

### **F2 - Datos & Configuración (5-7 días)**
**Objetivos:**
- Obtener certificado SII real
- Obtener CAF Maullin
- Configurar ambiente sandbox

**Actividades:**
1. **Solicitar certificado SII** (3-5 días trámite externo)
2. **Crear cuenta Maullin** (1 día)
3. **Solicitar CAF sandbox** (1 día)
4. Descargar XSD oficiales SII
5. Configurar diarios Odoo
6. Importar certificado en `dte.certificate`
7. Importar CAF en `dte.caf`

**Insumos:**
- RUT empresa
- Documentación legal empresa
- Acceso portal SII

**Salidas:**
- Certificado .pfx instalado
- CAF XML importado
- Ambiente Maullin configurado

**Riesgos:**
- Demora trámite certificado (mitigación: iniciar HOY)
- Rechazo solicitud CAF (mitigación: validar requisitos previos)

**Criterios Aceptación:**
- ✅ Certificado válido en `dte.certificate`
- ✅ CAF con folios disponibles en `dte.caf`
- ✅ Conexión exitosa a Maullin

---

### **F3 - Implementación Núcleo (2 días)**
**Objetivos:**
- Actualizar vistas XML
- Testing unitario completo
- Contratos firmes

**Actividades:**
1. Actualizar `account_move_dte_views.xml` (1h)
2. Actualizar `dte_certificate_views.xml` (30min)
3. Verificar herencias `_inherit` con `super()`
4. Tests unitarios modelos (dte.caf, dte.certificate)
5. Tests unitarios extensiones (account.move)
6. Validar campos `related` funcionan

**Criterios Aceptación:**
- ✅ Vistas XML sin errores
- ✅ Tests unitarios >80% coverage
- ✅ Herencia Odoo sin conflictos

---

### **F4 - Flujo DTE E2E (3-4 días)**
**Objetivos:**
- Testing con SII real (Maullin)
- Flujo completo funcional
- Telemetría inicial

**Actividades:**
1. **Testing Maullin:**
   - Enviar DTE 33 (Factura)
   - Enviar DTE 61 (Nota Crédito)
   - Enviar DTE 56 (Nota Débito)
   - Validar respuestas SII
2. **Implementar GetEstadoDTE** (3h)
3. **Testing integración:**
   - Odoo → DTE Service → SII
   - Webhook callback → Odoo
   - Actualización estados
4. **Logs estructurados** (structlog)

**Criterios Aceptación:**
- ✅ 3+ DTEs aceptados en Maullin
- ✅ Estados SII parseados correctamente
- ✅ Webhook funcional
- ✅ Logs trazables por RUT/folio

---

### **F5 - Reportes & IA Asistiva (5-7 días)**
**Objetivos:**
- Libro Compras/Ventas
- Dashboard ejecutivo
- Monitoreo SII UI (opcional)
- Chat IA (opcional)

**Actividades:**
1. **Libro Compras/Ventas** (2 días):
   - Modelo `dte.libro`
   - Generador XML según formato SII
   - Wizard generación
2. **Dashboard** (1 día):
   - KPIs (DTEs enviados, tasa aceptación)
   - Gráficos JS
3. **Monitoreo SII UI** (2-3 días, opcional):
   - Modelo `dte.sii.news`
   - Vistas, wizard revisión
   - Cron cada 6h
4. **Chat IA** (3 días, opcional):
   - Widget JavaScript
   - Integración AI Service

**Criterios Aceptación:**
- ✅ Libro Compras/Ventas genera XML válido
- ✅ Dashboard muestra KPIs en tiempo real
- 🟢 (Opcional) Monitoreo SII funcional
- 🟢 (Opcional) Chat IA responde preguntas

---

### **F6 - Hardening & Performance (3-5 días)**
**Objetivos:**
- RabbitMQ profesional
- Pruebas de carga
- Tuning performance
- Seguridad

**Actividades:**
1. **RabbitMQ Fase 2** (1-2 días):
   - Migrar a `aio-pika`
   - Configurar DLQ, TTL, Priority
   - Connection pooling
   - Retry exponencial
2. **Pruebas de carga** (1 día):
   - Locust: 1000+ DTEs/hora
   - Identificar cuellos de botella
3. **Tuning** (1 día):
   - Postgres: índices, vacuum
   - Redis: eviction policies
   - Workers: ajustar concurrencia
4. **Seguridad** (1 día):
   - Secretos en variables entorno
   - Cifrado TLS
   - Validación input

**Criterios Aceptación:**
- ✅ RabbitMQ con DLQ funcional
- ✅ Throughput >1000 DTEs/hora
- ✅ Latencia p95 <500ms
- ✅ Secretos no en código

---

### **F7 - Despliegue & Operación (3-4 días)**
**Objetivos:**
- CI/CD pipeline
- Observabilidad completa
- Runbooks
- Go-live

**Actividades:**
1. **CI/CD** (2 días):
   - GitHub Actions / GitLab CI
   - Gates: tests, linting, security scan
   - Deploy automático staging
2. **Observabilidad** (1-2 días):
   - Prometheus + Grafana
   - Alertas (rechazo masivo, timeout SII)
   - Dashboards operativos
3. **Runbooks** (1 día):
   - Procedimientos operativos
   - Troubleshooting común
   - Escalamiento

**Criterios Aceptación:**
- ✅ Pipeline CI/CD funcional
- ✅ Alertas configuradas
- ✅ Runbooks documentados
- ✅ Criterios go-live cumplidos

---

## ✅ MATRIZ ANTI-REDUNDANCIAS

| Función Odoo Base | Extensión Nuestra | Decisión | Justificación |
|-------------------|-------------------|----------|---------------|
| `res.partner.vat` | - | ✅ Reusar | Validación RUT ya existe en `l10n_cl` |
| `l10n_latam.document.type` | Relacionar en `dte.caf` | ✅ Extender | Tipos DTE ya definidos |
| `l10n_cl_sii_taxpayer_type` | - | ✅ Reusar | Tipo contribuyente ya existe |
| `account.move` | `_inherit` + campos DTE | ✅ Extender | Herencia controlada con `super()` |
| Generación XML | Microservicio DTE | ✅ Crear | No existe en Odoo CE |
| Firma digital | Microservicio DTE | ✅ Crear | No existe en Odoo CE |
| Gestión CAF | Modelo `dte.caf` | ✅ Crear | No existe en Odoo CE |

---

## 📊 CALIDAD & SEGURIDAD

### **Pruebas:**
- **Unitarias:** >80% coverage (pytest)
- **Integración:** Flujo completo Odoo ↔ DTE ↔ SII
- **E2E:** Casos reales con Maullin
- **Contract Testing:** Schemas OpenAPI validados

### **Performance:**
- **Objetivo:** p95 <500ms, throughput >1000 DTEs/hora
- **Herramientas:** Locust, Prometheus

### **Seguridad:**
- **Secretos:** Variables entorno (no en código)
- **Cifrado:** TLS en tránsito, encriptación passwords
- **Acceso:** Grupos Odoo, RBAC microservicios

### **Observabilidad:**
- **Logs:** structlog (JSON)
- **Métricas:** tasa_exito_dte, latencia_envio_ms, reintentos
- **Alertas:** rechazo_masivo_sii, cola_crescendo, timeout_sii

---

## 🎯 BACKLOG PRIORIZADO

### **Sprint 1 (Semana 1-2): Certificación**
1. F2: Solicitar certificado SII
2. F2: Obtener CAF Maullin
3. F3: Actualizar vistas XML
4. F4: Testing Maullin

### **Sprint 2 (Semana 3-4): Producción**
5. F4: GetEstadoDTE
6. F5: Libro Compras/Ventas
7. F6: RabbitMQ Fase 2

### **Sprint 3 (Semana 5-8): Excelencia**
8. F5: Dashboard + Monitoreo SII
9. F6: Performance tuning
10. F7: CI/CD + Observabilidad

---

## 📞 PRÓXIMOS PASOS INMEDIATOS

1. ✅ **HOY:** Solicitar certificado SII
2. ✅ **HOY:** Crear cuenta Maullin
3. ⚠️ **Mañana:** Iniciar F1 (Arquitectura detallada)
4. ⚠️ **Esta semana:** Completar F2 (Certificado + CAF)

**Fecha Objetivo Go-Live:** 4-6 semanas desde HOY
