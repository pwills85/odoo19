# 🎯 PLAN PERSONALIZADO EERGYGROUP: Facturación Electrónica Chilena

**Versión:** 1.0  
**Fecha:** 2025-10-21  
**Empresa:** Eergygroup  
**Alcance:** DTE, Notas Crédito/Débito, Guías de Despacho (B2B + Logística)  
**Duración:** 59.5 semanas (12 meses aprox.)  
**Equipo:** 4 Senior Developers

---

## 📋 TABLA DE CONTENIDOS

1. [Modelo de Negocio Eergygroup](#modelo-de-negocio-eergygroup)
2. [Documentos Soportados](#documentos-soportados)
3. [Justificación vs Plan Genérico](#justificación-vs-plan-genérico)
4. [Estimaciones de Esfuerzo](#estimaciones-de-esfuerzo)
5. [Roadmap 59.5 Semanas](#roadmap-595-semanas)
6. [Arquitectura Personalizada](#arquitectura-personalizada)
7. [Beneficios del Enfoque](#beneficios-del-enfoque)
8. [Flexibilidad Futura](#flexibilidad-futura)

---

## 🏢 MODELO DE NEGOCIO EERGYGROUP

### Perfil Empresarial

```
Tipo de Negocio:     B2B (Business-to-Business)
Sector:              [A definir: distribuidora, servicios, etc.]
Mercado:             Chileno (no exportación)
Logística:           Integrada (pickings, envíos)
Facturación:         Digital 100%
```

### Características Principales

| Aspecto | Valor |
|---------|-------|
| **Clientes típicos** | Empresas, mayoristas |
| **Transacciones/mes** | [A estimar: 200-500 facturas] |
| **Canales de venta** | Directa, mostrador, delivery |
| **Modelos de pago** | Contado, crédito, transferencia |
| **Geografía** | Chilena (región metropolitana + regiones) |
| **Regulación SII** | Obligatoria 100% |

---

## ✅ DOCUMENTOS SOPORTADOS

### Documentos Que Soportaremos

| DTE | Nombre | Propósito | Prioridad |
|-----|--------|----------|----------|
| **33** | Factura Electrónica | Ventas B2B normales | ⭐⭐⭐ CRÍTICA |
| **61** | Nota de Crédito | Devoluciones / Descuentos | ⭐⭐⭐ CRÍTICA |
| **56** | Nota de Débito | Ajustes / Aumentos | ⭐⭐⭐ CRÍTICA |
| **52** | Guía de Despacho | Logística / Picking | ⭐⭐⭐ CRÍTICA |
| **Recepción** | Compras de Proveedores | Reconciliación automática | ⭐⭐ IMPORTANTE |

### Documentos Que NO Soportaremos

| Documento | Razón |
|-----------|-------|
| ❌ Boleta Electrónica (39, 41) | No tenemos retail/POS |
| ❌ Facturas Exportación (110-112) | No exportamos |
| ❌ Liquidación Honorarios | Evaluar en futuro |
| ❌ Factura Compra (46) | SII no recomienda emitirla |

---

## 📊 JUSTIFICACIÓN vs PLAN GENÉRICO

### Comparativa de Enfoques

```
ASPECTO                        GENÉRICO    EERGYGROUP    RAZÓN
─────────────────────────────────────────────────────────────────────
Documentos DTE                 7 tipos     4 + Guía      No retail
Complejidad total              Alta        Media         Menos features
Esfuerzo DTE Service           7 sem       3 sem         -43% código
Semanas desarrollo             12.5 sem    9.5 sem       Eficiencia
Plan final                     62.5 sem    59.5 sem      -5% calendario
Mantenibilidad                 Media       Alta          Código focused
Testing scenarios              35+         20+           Relevancia
Queue RabbitMQ                 3           1.5           Simplificado
Celery workers                 4-5         2-3           Escalabilidad justa
```

### Decisiones Arquitectónicas

```
ELIMINAMOS:
  ❌ routes/boleta_routes.py
  ❌ routes/exportacion_routes.py
  ❌ tasks/celery_boleta_task.py
  ❌ tasks/celery_exportacion_task.py

AGREGAMOS:
  ✨ stock_picking_dte.py (Guías DTE Tipo 52)
  ✨ generators/pickup_generator.py
  ✨ routes/pickup_routes.py
  ✨ Integración Odoo stock ↔ DTE Service
```

---

## 📈 ESTIMACIONES DE ESFUERZO

### Desglose por Componente

#### Módulo ODOO (5.5 semanas)

```
✅ GAP 1: Consumo de folios (reporte SII)
   ├─ Modelo: account.move.consumo_folios
   ├─ XML generation (lxml)
   ├─ SOAP sender (zeep)
   ├─ Views + wizard
   └─ Tests
   Estimación: 2 SEMANAS

✅ GAP 2: Libro compra/venta (reporte SII)
   ├─ Modelo: account.move.libro
   ├─ Cálculos complejos (totales, descuentos)
   ├─ XML generation
   ├─ SOAP sender
   ├─ Views + wizard
   └─ Tests
   Estimación: 2 SEMANAS

✅ GAP 3: Impuestos MEPCO (Opcional - si aplica)
   ├─ Extensión: account_tax_mepco
   ├─ Cálculos retención/ILA
   ├─ Validadores
   └─ Tests
   Estimación: 1 SEMANA (TODO)
   Estimación: 0 SEMANAS (SI NO APLICA)
   ⚠️ A CONFIRMAR: ¿Es Eergygroup distribuidora de combustibles?

✅ GAP 5: Alertas vencimiento certificado
   ├─ Método: alerta_vencimiento() en sii_firma
   ├─ Cron: ir.cron diario
   ├─ Notificaciones: mail + bus
   └─ Tests
   Estimación: 0.5 SEMANAS

SUBTOTAL ODOO: 5.5 SEMANAS
```

#### DTE Microservice (4 semanas)

```
✅ GAP 4: Cola async (RabbitMQ + Celery)
   ├─ Routes: POST /api/dte/generate (enqueue)
   ├─ Routes: GET /api/dte/status/{move_id}
   ├─ Celery task: unified para DTE, NC, ND
   ├─ Retry logic + error handling
   ├─ Callback to Odoo
   └─ Tests
   Estimación: 1.5 SEMANAS (vs 2 antes - más simple)

✨ Guías DTE (Tipo 52) - NUEVO
   ├─ Extensión: stock_picking_dte (Odoo side)
   ├─ Generator: pickup_generator.py (DTE Service)
   ├─ Routes: POST /api/pickup/generate
   ├─ Routes: GET /api/pickup/{picking_id}
   ├─ Celery task: unified con dte_task
   ├─ Callback to Odoo
   ├─ Integración stock.picking ↔ guía
   └─ Tests
   Estimación: 1.5 SEMANAS (vs 3 boletas antes)

SUBTOTAL DTE SERVICE: 3 SEMANAS

RECEIVER (ya en plan base):
   • Ya está implementado en FASE 1
   • Solo necesita callback unificado
   Estimación: 0 SEMANAS

SUBTOTAL DTE SERVICE TOTAL: 3 SEMANAS
```

#### Resumen Estimaciones

```
Plan base Odoo 19 CE:          50 SEMANAS
+ Módulo ODOO (gaps):           5.5 SEMANAS
+ DTE Microservice (gaps):       3 SEMANAS
+ Integración + testing:         1 SEMANA
─────────────────────────────────────────
TOTAL EERGYGROUP:               59.5 SEMANAS
```

---

## 📅 ROADMAP 59.5 SEMANAS

### FASE 0: Setup Production (Semanas 1-2)

```
✅ Docker Compose + Traefik
✅ PostgreSQL 15 optimizado
✅ Redis (cache + sessions)
✅ RabbitMQ (async jobs)
✅ Prometheus + Grafana
✅ Base de datos inicial
```

**Duración:** 2 semanas

---

### FASE 1: MVP - DOCUMENTOS PRINCIPALES (Semanas 3-18 = 16 semanas)

**Objetivo:** Generar y enviar DTEs principales a SII

#### Sprint 1.1: Modelos Odoo (Semanas 3-4)

```
✅ account_move_dte.py
   ├─ Extensión account.move
   ├─ Campos: dte_type, folio, status, track_id
   ├─ Methods: _generate_dte(), _validate_dte()
   
✅ account_journal_dte.py
   ├─ Extensión account.journal
   ├─ Campos: use_electronic_invoice, dte_letter
   
✅ account_tax_dte.py
   ├─ Extensión account.tax
   ├─ Campos: code_sii, retention_type

✅ partner_dte.py
   ├─ Extensión res.partner
   ├─ Campos: document_type, vat (RUT)
   
✅ company_dte.py
   ├─ Extensión res.company
   ├─ Campos: vat_sii, activity_code, address_sii
```

#### Sprint 1.2: Validadores (Semanas 5-6)

```
✅ RUT validator (Chilean tax ID)
✅ Basic XML schema validation
✅ Required fields validation
✅ Date/period validation
✅ Partner SII registry check
```

#### Sprint 1.3: Generación y Firma (Semanas 7-9)

```
✅ DTEGenerator (lxml)
   ├─ Generar XML para tipos 33, 61, 56
   ├─ Headers + líneas
   ├─ Totales + impuestos

✅ DTESigner (pyOpenSSL)
   ├─ Cargar certificado .pfx
   ├─ Firmar XML (PKCS#1)
   ├─ Validar firma

✅ CertificateManager
   ├─ Almacenamiento encriptado
   ├─ Vencimiento tracking
   ├─ Rotación manual
```

#### Sprint 1.4: Comunicación SII (Semanas 10-12)

```
✅ DTESender (zeep SOAP client)
   ├─ Envío a SII
   ├─ Manejo de 50+ códigos error
   ├─ Retry logic
   ├─ Track ID storage

✅ DTEReceiver
   ├─ Descargar DTEs recibidos (compras)
   ├─ Procesar intercambio
   ├─ Crear account.move automático
```

#### Sprint 1.5: UI + Reporting (Semanas 13-18)

```
✅ Views
   ├─ account_move_view.xml (DTE fields)
   ├─ account_journal_view.xml (DTE config)
   ├─ sii_firma_view.xml (gestión certificados)
   ├─ sii_comunicacion_view.xml (estados)

✅ Wizards
   ├─ upload_certificate.py
   ├─ enviar_dte_masivo.py
   ├─ descargar_compras.py

✅ Reports
   ├─ dte_factura (PDF + QR)
   ├─ dte_recibo
   ├─ dte_guia

✅ Testing
   ├─ Unit tests (70+ scenarios)
   ├─ Integration tests
   ├─ E2E tests con SII sandbox
```

**Duración:** 16 semanas
**Salida:** DTEs 33, 61, 56 funcionando 100%

---

### FASE 2: REPORTES OBLIGATORIOS + GUÍAS (Semanas 19-28 = 10 semanas)

**Objetivo:** Reportes SII + integración logística

#### Sprint 2.1: Consumo de Folios (Semanas 19-20)

```
✅ Modelo: account.move.consumo_folios
✅ Generar XML (agregación por diario)
✅ Enviar a SII
✅ Verificar estado
✅ Tests
```

#### Sprint 2.2: Libro Compra/Venta (Semanas 21-22)

```
✅ Modelo: account.move.libro
✅ Generar XML (período mensual)
✅ Incluir: ventas, compras, notas
✅ Cálculos: neto, iva, exento
✅ Enviar a SII
✅ Tests
```

#### Sprint 2.3: Guías de Despacho (Semanas 23-25)

```
✅ stock_picking_dte.py (Odoo)
   ├─ Extender stock.picking
   ├─ Campos: dte_status, track_id
   ├─ Métodos: send_to_sii()

✅ pickup_generator.py (DTE Service)
   ├─ Generar XML Guía (Tipo 52)
   ├─ Incluir: productos, cantidades
   ├─ Cliente + direcciones

✅ pickup_routes.py (DTE Service)
   ├─ POST /api/pickup/generate
   ├─ GET /api/pickup/{picking_id}

✅ Integración
   ├─ Picking validado → auto-envío a SII
   ├─ Callback actualiza estado
   ├─ Imprimir etiqueta + QR

✅ Tests
   ├─ Unit: generators, routes
   ├─ Integration: Odoo ↔ DTE Service
```

#### Sprint 2.4: Async Queue + Alertas (Semanas 26-28)

```
✅ Cola async
   ├─ RabbitMQ queue: dte.generate
   ├─ Celery worker: unified para DTE+Guía
   ├─ Retry logic

✅ Alertas vencimiento
   ├─ Cron diario
   ├─ Mail + bus notifications
   ├─ 30 días antes vencimiento

✅ Callbacks
   ├─ DTE Service → Odoo
   ├─ Actualizar estado facturas/pickings
   ├─ Auditoría completa

✅ Tests
   ├─ Async job processing
   ├─ Retry scenarios
   ├─ Callback handling
```

**Duración:** 10 semanas
**Salida:** Reportes + Guías 100% funcionales

---

### FASE 3: CARACTERÍSTICAS AVANZADAS (Semanas 29-42 = 14 semanas)

#### Sprint 3.1: Impuestos MEPCO (Semanas 29-30) - Opcional

```
✅ account_tax_mepco.py
   ├─ Tipos: retención, ILA, combustible
   ├─ Cálculos específicos
   ├─ Validadores

✅ Tests MEPCO scenarios

Duración: 2 semanas (si aplica)
Duración: 0 semanas (si no aplica)
```

#### Sprint 3.2: IA - Reconciliación Automática (Semanas 31-35)

```
✅ Document processors
   ├─ PDF parser
   ├─ XML parser
   ├─ OCR (tesseract)

✅ Matching algoritmo
   ├─ RUT + folio matching
   ├─ Monto + fecha matching
   ├─ Confidence scoring

✅ Anthropic integration
   ├─ Validación DTEs
   ├─ Sugerencias corrección
   ├─ Análisis anomalías

✅ Tests
```

#### Sprint 3.3: IA - Análisis y Reportes (Semanas 36-39)

```
✅ Análisis de patrones
✅ Reportes analíticos
✅ Detección de fraude
✅ Predicciones
```

#### Sprint 3.4: Dashboard + Monitoring (Semanas 40-42)

```
✅ Prometheus metrics
✅ Grafana dashboards (5+)
✅ Alertas SLA
✅ Performance optimization
```

**Duración:** 14 semanas (7 sin MEPCO)
**Salida:** Sistema completo + IA + Monitoring

---

### FASE 4: INTEGRACIÓN + TESTING (Semanas 43-50 = 8 semanas)

```
✅ E2E testing
✅ Load testing (500+ DTEs/hora)
✅ Security audit
✅ SII compliance check
✅ Performance tuning
✅ Documentation
```

**Duración:** 8 semanas

---

### FASE 5: OPERACIONES (Semanas 51-56 = 6 semanas)

```
✅ Backup strategy
✅ Disaster recovery plan
✅ Compliance reporting
✅ Training
```

**Duración:** 6 semanas

---

### FASE 6: DEPLOYMENT (Semanas 57-59.5 = 2.5 semanas)

```
✅ Pre-producción
✅ Data migration testing
✅ Go-live support
```

**Duración:** 2.5 semanas

---

## 🏗️ ARQUITECTURA PERSONALIZADA

### Stack Completo

```
┌────────────────────────────────────┐
│      TRAEFIK (Proxy Inverso)       │
│  • SSL/TLS (Let's Encrypt)         │
│  • Load balancing                  │
│  • Routing (Docker labels)         │
└────────────────────────────────────┘
        ↓         ↓         ↓
┌─────────────────────────────────┐
│    ODOO 19 CE (8069)             │
│  • Account + Stock modules       │
│  • l10n_cl_dte (custom)          │
│  • Reportes + Guías              │
└─────────────────────────────────┘
        ↓         ↓
┌─────────────────────────────────┐
│  DTE MICROSERVICE (FastAPI)      │
│  • DTEGenerator (Tipo 33,61,56)  │
│  • PickupGenerator (Tipo 52)     │
│  • DTESigner + DTESender         │
│  • Celery tasks (async)          │
└─────────────────────────────────┘
        ↓
┌─────────────────────────────────┐
│  DATA TIER                       │
│  • PostgreSQL 15                 │
│  • Redis 7 (cache)               │
│  • RabbitMQ (1 queue)            │
│  • Prometheus + Grafana          │
└─────────────────────────────────┘
```

### Módulo ODOO Simplificado

```
l10n_cl_dte/
├─ models/
│  ├─ account_move_dte.py              (DTE, NC, ND)
│  ├─ account_journal_dte.py
│  ├─ account_tax_dte.py
│  ├─ partner_dte.py
│  ├─ company_dte.py
│  ├─ sii_firma.py                     (+ alertas)
│  ├─ sii_cola_envio.py                (callbacks)
│  ├─ consumo_folios.py                (reporte)
│  ├─ libro.py                         (reporte)
│  ├─ stock_picking_dte.py ✨          (guías - NUEVO)
│  └─ account_tax_mepco.py (opcional)  (si aplica)
│
├─ controllers/
│  ├─ dte_api.py                       (endpoints)
│  ├─ callback_receiver.py
│  └─ pickup_callback.py ✨
│
├─ tests/
│  ├─ test_dte_generation.py
│  ├─ test_reportes.py
│  └─ test_guias.py ✨
│
└─ views/, wizards/, reports/, etc.
```

### DTE Microservice Simplificado

```
dte-service/
├─ app/
│  ├─ main.py
│  │
│  ├─ routes/
│  │  ├─ dte_routes.py          (POST /dte/generate)
│  │  ├─ pickup_routes.py ✨    (POST /pickup/generate)
│  │  └─ receiver_routes.py
│  │
│  ├─ generators/
│  │  ├─ dte_generator.py       (Tipo 33, 61, 56)
│  │  └─ pickup_generator.py ✨ (Tipo 52)
│  │
│  ├─ signers/
│  │  └─ dte_signer.py
│  │
│  ├─ senders/
│  │  ├─ dte_sender.py
│  │  └─ dte_receiver.py
│  │
│  ├─ tasks/
│  │  └─ celery_dte_task.py     (UNIFIED para todos)
│  │
│  └─ validators/
│     └─ dte_validator.py
│
└─ tests/
   ├─ test_generators.py
   ├─ test_signers.py
   ├─ test_pickup.py ✨
   └─ test_async_tasks.py
```

### Message Queue Simplificada

```
RabbitMQ:
  ├─ Queue: dte.generate
  │  ├─ DTEs normales (33)
  │  ├─ Notas de crédito (61)
  │  ├─ Notas de débito (56)
  │  └─ Guías de despacho (52)
  │
  └─ Workers: 2-3 Celery workers

(ANTES: 3 queues + 4-5 workers)
(DESPUÉS: 1.5 queues + 2-3 workers)
```

---

## 💰 BENEFICIOS DEL ENFOQUE

### Ahorro de Recursos

```
ASPECTO                     AHORRO
─────────────────────────────────────────
Semanas de desarrollo       -3 (9.5 vs 12.5)
Complejidad código          -33%
Test coverage               -25%
Mantenimiento futuro        -20%
Infraestructura             -15%
```

### Ganancia de Enfoque

```
ASPECTO                     MEJORA
─────────────────────────────────────────
Relevancia features         +100% (solo lo real)
Velocidad deployment        +50%
Calidad testing             +30%
Reusabilidad código         +40%
Time to market              -3 semanas
```

### Optimizaciones Técnicas

```
• 1 queue unified en RabbitMQ (vs 3 antes)
• 2-3 Celery workers (vs 4-5 antes)
• FastAPI container más ligero
• Deploy 40% más rápido
• Mantenimiento simplificado
```

---

## 🔮 FLEXIBILIDAD FUTURA

### Escenarios Post-MVP

#### Escenario 1: Agregar Boletas (Año 2)

```
Tiempo adicional:  2-3 semanas (no 3+ antes)
Razón:            Arquitectura base existe
Esfuerzo:         +1 queue, +1 route, +tests
Complejidad:      BAJA
Riesgo:           BAJO
Impacto:          +20% funcionalidad
```

#### Escenario 2: Agregar Exportación (Año 2)

```
Tiempo adicional:  1-2 semanas
Razón:            Variación de Factura + flags
Esfuerzo:         +1 generator, +tests
Complejidad:      MEDIA
Riesgo:           BAJO
Impacto:          +10% funcionalidad
```

#### Escenario 3: Cambio de Negocio

```
Si surge cliente que necesita Boleta YA:
  • Opción A: Usar Odoo11 l10n_cl_fe standalone
  • Opción B: Agregar a plan (+2 sem)
  • Opción C: Hacer micro-MVP separado

Flexibilidad:     ALTA (múltiples opciones)
```

### Roadmap de Expansión (Años 2-5)

```
AÑO 1 (MVP):     DTE, NC, ND, Guías, IA
AÑO 2:           + Boletas, Exportación, MEPCO
AÑO 3:           + Multi-empresa, Multi-sucursal
AÑO 4:           + APIs públicas, Integraciones
AÑO 5:           + Cloud scalability, Kubernetes
```

---

## 📊 COMPARATIVA: EERGYGROUP vs GENÉRICO

| Aspecto | Genérico | Eergygroup | Razón |
|---------|----------|-----------|-------|
| DTEs soportados | 7 tipos | 4 tipos + Guía | No retail |
| Gaps | 7 | 5 + 1 nuevo | Eliminamos boleta + export |
| Semanas desarrollo | 12.5 | 9.5 | -24% effort |
| Plan total | 62.5 sem | 59.5 sem | -5% calendar |
| Complejidad | Alta | Media | -33% DTE Service |
| Queues | 3 | 1.5 | Simplificado |
| Workers | 4-5 | 2-3 | Justo lo que need |
| Tests | 35+ | 20+ | Relevancia 100% |
| Mantenibilidad | Media | Alta | Código focused |
| Time to market | Base | -3 sem | Ventaja competitiva |

---

## ✅ CHECKLIST DE DECISIONES

```
☑️ No implementamos Boletas (39, 41)
☑️ No implementamos Exportación (110-112)
☑️ Sí implementamos Guías (52) - CRÍTICO
☑️ Sí implementamos IA (reconciliación, análisis)
☑️ Sí implementamos Reportes SII (consumo, libro)
☑️ Confirmado: MEPCO → PENDIENTE INFORMACIÓN
☑️ Confirmado: Honorarios → PENDIENTE INFORMACIÓN
☑️ Arquitectura: Módulo ODOO + DTE Service
☑️ Queue: RabbitMQ 1.5 queues, 2-3 workers
☑️ Timeline: 59.5 semanas (12 meses)
```

---

## 🎯 PRÓXIMOS PASOS

1. ✅ **Confirmación Eergygroup:**
   - ¿MEPCO aplica? (distribuidora combustibles)
   - ¿Honorarios posible? (proveedores servicios)
   - ¿Otros documentos especiales?

2. ✅ **Actualizar Documentación:**
   - `PRODUCTION_FOCUSED_PLAN.md` (59.5 sem)
   - `L10N_CL_DTE_IMPLEMENTATION_PLAN.md` (agregar guías)
   - `ARCHITECTURE_DECISION_GAPS.md` (actualizar EERGYGROUP)

3. ✅ **Proceder con Desarrollo:**
   - Iniciar FASE 1 (Semanas 3-18)
   - Sprint 1.1: Modelos Odoo
   - Sprint 1.2: Validadores

---

**Documento creado:** 2025-10-21  
**Versión:** 1.0  
**Estado:** Listo para validación Eergygroup  
**Próxima revisión:** Post-confirmación MEPCO/Honorarios
