# 🎯 Plan de Implementación por Fases Concretas

**Documento:** Plan optimizado para múltiples sesiones  
**Diseño:** Considerando limitaciones de memoria y contexto  
**Fecha:** 2025-10-21  
**Versión:** 1.0

---

## 📋 FILOSOFÍA DEL PLAN

### Principios de Diseño

1. **Fases Atómicas:** Cada fase es auto-contenida y verificable
2. **Checkpoints:** Al final de cada fase, el sistema es testeable
3. **Documentación Continua:** Cada fase genera su propia documentación
4. **Rollback Posible:** Cada fase puede revertirse si hay problemas
5. **Progreso Visible:** Cada fase entrega valor funcional

### Límites por Sesión

- **Tiempo óptimo:** 2-3 horas por sesión
- **Archivos por sesión:** 8-12 archivos máximo
- **Líneas por sesión:** 800-1,200 líneas
- **Complejidad:** 1-2 componentes complejos por sesión

---

## 📊 ESTADO ACTUAL (Checkpoint Sesión 1)

### Completado: 45 archivos (~3,730 líneas) - 54%

**Módulo Odoo:**
- ✅ 12 modelos Python (completos)
- ✅ 5 vistas XML básicas
- ✅ Security completa
- ✅ Config completa
- ✅ Dependencias corregidas
- ✅ Sin errores de junior

**Microservicios:**
- ✅ DTE Service estructura base (7 archivos)
- ✅ AI Service estructura base (7 archivos)
- ✅ Docker Compose actualizado

---

## 🚀 FASE 2: Módulo Instalable (PRÓXIMA SESIÓN)

**Objetivo:** Hacer que el módulo se pueda instalar en Odoo sin errores

**Duración:** 2-3 horas  
**Complejidad:** MEDIA  
**Archivos:** 12 archivos (~850 líneas)

### Tareas Específicas

#### 2.1. Actualizar Security (15 min)
```
Archivo: security/ir.model.access.csv
Agregar permisos para:
  - dte.caf
  - purchase.order (DTE 34)
  - stock.picking (DTE 52)
  - retencion.iue

Líneas: +8
```

#### 2.2. Crear Vistas Básicas (2 horas)

**Vista 1: dte_caf_views.xml (30 min)**
```xml
Contenido:
  - Form view (campos: name, dte_type, folio_desde, folio_hasta)
  - Tree view (lista de CAFs)
  - Search view (filtros)
  - Action window
  
Referencia: Copiar estructura de dte_certificate_views.xml
Líneas: ~80
```

**Vista 2: account_journal_dte_views.xml (20 min)**
```xml
Contenido:
  - Extensión de vista de diario (xpath)
  - Agregar campos DTE (is_dte_journal, dte_certificate_id, folios)
  - Pestaña "DTE" en notebook
  
Referencia: account.view_account_journal_form
Líneas: ~60
```

**Vista 3: purchase_order_dte_views.xml (25 min)**
```xml
Contenido:
  - Extensión purchase.order form
  - Página "Liquidación Honorarios"
  - Campos: profesional_rut, retencion_iue, montos
  - Botón "Generar DTE 34"
  
Referencia: purchase.purchase_order_form
Líneas: ~90
```

**Vista 4: stock_picking_dte_views.xml (20 min)**
```xml
Contenido:
  - Extensión stock.picking form
  - Checkbox "Genera DTE 52"
  - Campos DTE 52
  - Botón "Generar Guía Electrónica"
  
Referencia: stock.view_picking_form
Líneas: ~80
```

**Vista 5: retencion_iue_views.xml (20 min)**
```xml
Contenido:
  - Form view retenciones
  - Tree view (periodo, profesional, montos)
  - Search view
  - Action
  
Referencia: Copiar estructura de dte_communication_views.xml
Líneas: ~70
```

**Vistas 6-7: Wizards básicos (stubs) (25 min)**
```xml
4 wizards con forms mínimos:
  - upload_certificate_views.xml (~40)
  - send_dte_batch_views.xml (~50)
  - generate_consumo_folios_views.xml (~40)
  - generate_libro_views.xml (~40)

Total: ~170 líneas
```

**Vistas 8-9: Reports básicos (stubs) (20 min)**
```xml
2 reportes con templates mínimos:
  - dte_invoice_report.xml (~80)
  - dte_receipt_report.xml (~60)

Total: ~140 líneas
```

#### 2.3. Data File (10 min)
```
Archivo: data/sii_activity_codes.xml
Contenido: Códigos de actividad económica SII (básicos)
Líneas: ~50
```

#### 2.4. Wizards Python (stubs) (30 min)
```
4 wizards mínimos (TransientModel):
  - upload_certificate.py (~60)
  - send_dte_batch.py (~70)
  - generate_consumo_folios.py (~60)
  - generate_libro.py (~70)

Total: ~260 líneas
```

### Checkpoint Fase 2
- ✅ Módulo instalable en Odoo
- ✅ Sin errores de instalación
- ✅ UI visible y navegable
- ⚠️ Botones no funcionales aún (stubs)

**Comando para verificar:**
```bash
# En Odoo:
Apps → Update Apps List → Search "Chilean" → Install

# No debe dar errores
```

---

## 🚀 FASE 3: CAF + TED + Firma Real (Sesión 3)

**Objetivo:** DTEs aceptados por SII sandbox

**Duración:** 3-4 horas  
**Complejidad:** ALTA  
**Archivos:** 5 archivos críticos (~650 líneas)

### Tareas Específicas

#### 3.1. TED Generator (1.5 horas)
```python
Archivo: dte-service/generators/ted_generator.py

Implementar:
  1. Cálculo de DD (hash SHA-1 del documento)
     - Campos: RUT emisor, tipo DTE, folio, fecha, monto
     - Algoritmo: SHA-1
  
  2. Generación XML TED
     - Estructura según norma SII
     - Firma RSA del TED (FRMT)
  
  3. Generación QR code
     - qrcode library
     - Codificar TED en QR
     - Retornar base64

Referencia: Especificación técnica SII (Anexo TED)
Líneas: ~200
```

#### 3.2. CAF Handler (30 min)
```python
Archivo: dte-service/generators/caf_handler.py

Implementar:
  - Parsear CAF recibido desde Odoo
  - Extraer elemento <CAF> del XML
  - Incluir en XML DTE (dentro de <Documento>)
  - Validar que folio esté en rango CAF

Líneas: ~100
```

#### 3.3. Firma Digital Real (1.5 horas)
```python
Archivo: dte-service/signers/xmldsig_signer.py

Implementar:
  - Firma XMLDsig usando xmlsec library
  - Canonicalización C14N
  - DigestValue (SHA-1 del documento)
  - SignatureValue (RSA-SHA1 de SignedInfo)
  - X509Certificate incluido

Referencia: xmlsec documentation + código l10n_cl si existe
Líneas: ~180
```

#### 3.4. Validación XSD (30 min)
```python
Archivo: dte-service/validators/xsd_validator.py

Implementar:
  - Cargar XSD del SII
  - Validar XML contra XSD
  - Retornar errores detallados

Descargar: Esquemas XSD del SII
Líneas: ~120
```

#### 3.5. Integrar en main.py (30 min)
```python
Actualizar: dte-service/main.py

Cambiar de mock a lógica real:
  - Llamar DTEGenerator33 real
  - Incluir CAF
  - Generar TED
  - Validar XSD
  - Firmar con xmldsig_signer
  - Enviar a SII

Líneas: +100 (modificaciones)
```

### Checkpoint Fase 3
- ✅ DTE 33 genera XML válido
- ✅ XML incluye CAF y TED
- ✅ XML firmado digitalmente
- ✅ XML valida contra XSD
- ✅ Primer envío exitoso a SII sandbox

**Comando para verificar:**
```bash
# Crear factura en Odoo
# Click "Enviar a SII"
# Verificar respuesta: "Aceptado" (no "Rechazado")
```

---

## 🚀 FASE 4: DTEs Adicionales (Sesión 4)

**Objetivo:** DTE 34, 52, 56, 61 operativos

**Duración:** 2-3 horas  
**Complejidad:** MEDIA  
**Archivos:** 4 generadores (~620 líneas)

### Tareas

#### 4.1. DTE 34 - Liquidación Honorarios (45 min)
```python
Archivo: dte-service/generators/dte_generator_34.py

Estructura similar a DTE 33 pero:
  - Campo <Retencion> (IUE)
  - Cálculo de retención
  - Monto neto a pagar

Líneas: ~180
```

#### 4.2. DTE 52 - Guía Despacho (40 min)
```python
Archivo: dte-service/generators/dte_generator_52.py

Campos adicionales:
  - Tipo de traslado
  - Patente vehículo
  - Referencia a factura (opcional)

Líneas: ~150
```

#### 4.3. DTE 56, 61 - NC/ND (30 min c/u)
```python
Archivos:
  - dte_generator_56.py (Nota Débito)
  - dte_generator_61.py (Nota Crédito)

Similar a DTE 33 con:
  - Referencia a documento original
  - Motivo de NC/ND

Líneas: ~120 cada uno
```

#### 4.4. Actualizar main.py (20 min)
```python
Agregar endpoints para DTEs adicionales
Líneas: +70
```

### Checkpoint Fase 4
- ✅ Todos los DTEs generan XML
- ✅ Pueden enviarse a SII
- ✅ UI en Odoo funcional para cada tipo

---

## 🚀 FASE 5: Libros Electrónicos (Sesión 5)

**Objetivo:** Reportes SII operativos

**Duración:** 2 horas  
**Complejidad:** MEDIA  
**Archivos:** 6 archivos (~520 líneas)

### Tareas

#### 5.1. Modelos Odoo (45 min)
```python
Archivos:
  - models/dte_consumo_folios.py (~120)
  - models/dte_libro.py (~150)

Funcionalidad:
  - Agregación de datos desde account.move
  - Cálculos de totales
  - UI básica
```

#### 5.2. Generadores XML (45 min)
```python
Archivos:
  - generators/consumo_generator.py (~100)
  - generators/libro_generator.py (~120)

Funcionalidad:
  - XML según formato SII
  - Totalización correcta
```

#### 5.3. Vistas (30 min)
```xml
Archivos:
  - views/dte_consumo_folios_views.xml
  - views/dte_libro_views.xml
```

### Checkpoint Fase 5
- ✅ Consumo de folios mensual generado
- ✅ Libro compra/venta generado
- ✅ Envío a SII exitoso

---

## 🚀 FASE 6: Recepción de Compras + IA (Sesión 6)

**Objetivo:** Recepción automática y reconciliación IA

**Duración:** 2-3 horas  
**Complejidad:** ALTA  
**Archivos:** 4 archivos (~550 líneas)

### Tareas

#### 6.1. Receiver DTE Service (1 hora)
```python
Archivos:
  - receivers/dte_receiver.py (~150)
  - receivers/xml_parser.py (~120)

Funcionalidad:
  - Polling SII cada 30 min
  - Descarga DTEs recibidos
  - Parseo XML
```

#### 6.2. Reconciliación IA (1 hora)
```python
Archivo: ai-service/reconciliation/invoice_matcher.py

Implementar:
  - Embeddings con sentence-transformers
  - ChromaDB para vectores
  - Cosine similarity
  - Matching > 85%

Líneas: ~200
```

#### 6.3. Crear Factura en Odoo (30 min)
```python
Extender: models/account_move_dte.py

Método:
  def create_from_received_dte(self, dte_data, matched_po_id):
      # Crear account.move desde DTE
      # Link con PO
      # Validar

Líneas: +80
```

### Checkpoint Fase 6
- ✅ DTEs recibidos descargados automáticamente
- ✅ Matching IA con 90%+ accuracy
- ✅ Facturas creadas automáticamente

---

## 📋 RESUMEN DEL PLAN COMPLETO

| Fase | Objetivo | Archivos | Líneas | Tiempo | Sesión |
|------|----------|----------|--------|--------|--------|
| **1** | Base + Correcciones | 45 | 3,730 | 3h | ✅ COMPLETA |
| **2** | Módulo Instalable | 12 | 850 | 2-3h | ⏳ PRÓXIMA |
| **3** | CAF + TED + Firma | 5 | 650 | 3-4h | ⏳ Sesión 3 |
| **4** | DTEs Adicionales | 4 | 620 | 2-3h | ⏳ Sesión 4 |
| **5** | Libros Electrónicos | 6 | 520 | 2h | ⏳ Sesión 5 |
| **6** | Recepción + IA | 4 | 550 | 2-3h | ⏳ Sesión 6 |
| **TOTAL** | Sistema Completo | **76** | **~6,920** | **14-18h** | **6 sesiones** |

---

## 🎯 CHECKPOINT SYSTEM

### Al Final de Cada Fase

**Generar automáticamente:**

1. **CHECKPOINT_FASE_N.md**
   - Qué se completó
   - Qué archivos se crearon
   - Cómo verificar
   - Estado del sistema

2. **TODO_FASE_N+1.md**
   - Lista exacta de archivos a crear
   - Templates de código
   - Referencias a documentación
   - Orden de implementación

3. **Actualizar IMPLEMENTATION_PROGRESS.md**
   - Porcentaje completado
   - Archivos nuevos
   - Próximos pasos

---

## 📁 ESTRUCTURA DE DOCUMENTACIÓN POR FASE

```
docs/
├── phase_checkpoints/
│   ├── CHECKPOINT_FASE_1.md  ✅ (esta sesión)
│   ├── CHECKPOINT_FASE_2.md  (próxima)
│   ├── CHECKPOINT_FASE_3.md
│   └── ...
│
├── phase_todos/
│   ├── TODO_FASE_2.md  ✅ (crear ahora)
│   ├── TODO_FASE_3.md  (crear al finalizar fase 2)
│   └── ...
│
└── PHASED_IMPLEMENTATION_PLAN.md  ✅ (este documento)
```

---

## 🔄 PROCESO ENTRE SESIONES

### Al Finalizar Cada Sesión

```bash
1. Generar checkpoint de la fase completada
2. Crear TODO detallado de la siguiente fase
3. Commit de código (si hay git)
4. Documentar estado actual
```

### Al Iniciar Nueva Sesión

```bash
1. Leer CHECKPOINT_FASE_N.md (qué se completó)
2. Leer TODO_FASE_N+1.md (qué hacer ahora)
3. Verificar que fase anterior funcione
4. Iniciar implementación
```

---

## 🎯 FASE 2 DETALLADA (PRÓXIMA SESIÓN)

### Preparación Pre-Sesión

**Leer estos documentos:**
1. `docs/CURRENT_STATUS_AND_NEXT_STEPS.md` (estado actual)
2. `docs/phase_todos/TODO_FASE_2.md` (lista detallada)
3. `docs/odoo19_official/CHEATSHEET.md` (referencia rápida)

### Orden de Implementación Fase 2

**Paso 1: Security (15 min)**
```
1. Abrir security/ir.model.access.csv
2. Agregar 8 líneas (permisos nuevos modelos)
3. Guardar
```

**Paso 2: Vistas Críticas (1.5 horas)**
```
Orden sugerido:
  1. dte_caf_views.xml (más importante)
  2. purchase_order_dte_views.xml (DTE 34)
  3. stock_picking_dte_views.xml (DTE 52)
  4. account_journal_dte_views.xml
  5. retencion_iue_views.xml
```

**Paso 3: Wizards Stubs (45 min)**
```
Crear 4 wizards con UI mínima
```

**Paso 4: Reports Stubs (30 min)**
```
Crear 2 reportes con templates básicos
```

**Paso 5: Data File (10 min)**
```
sii_activity_codes.xml básico
```

**Paso 6: Verificación (15 min)**
```
1. Actualizar lista apps
2. Instalar módulo
3. Verificar que no da errores
4. Navegar por menús
```

### Tiempo Total Fase 2: 2.5-3 horas

---

## 📊 ESTIMACIÓN POR FASES

### Resumen de Esfuerzo

```
Fase 1 (Completa):      3 horas   ✅
Fase 2 (Instalable):    2.5 horas ⏳ PRÓXIMA
Fase 3 (CAF+TED+Firma): 3.5 horas
Fase 4 (DTEs 34,52...): 2.5 horas
Fase 5 (Libros):        2 horas
Fase 6 (Recepción+IA):  2.5 horas
────────────────────────────────
TOTAL:                  16 horas  (6 sesiones de 2-3h cada una)
```

---

## 🎯 VENTAJAS DE ESTE PLAN

### 1. Gestión de Memoria
- ✅ Cada fase es auto-contenida
- ✅ Checkpoints claros
- ✅ Documentación de continuidad
- ✅ Sin pérdida de contexto entre sesiones

### 2. Verificación Continua
- ✅ Cada fase es testeable
- ✅ Progreso visible
- ✅ Rollback posible si hay errores

### 3. Flexibilidad
- ✅ Puedes pausar entre fases
- ✅ Puedes revisar código entre sesiones
- ✅ Puedes ajustar prioridades

### 4. Calidad
- ✅ Menos fatiga = menos errores
- ✅ Más tiempo para verificar
- ✅ Código más limpio

---

## 📝 PRÓXIMO PASO INMEDIATO

### Crear TODO Detallado Fase 2

Voy a generar ahora:
- `docs/phase_todos/TODO_FASE_2.md` con especificación exacta
- `docs/phase_checkpoints/CHECKPOINT_FASE_1.md` con lo completado

**Luego:** Iniciar Fase 2 o pausar según tu decisión

---

**Fecha:** 2025-10-21  
**Sistema:** Optimizado para continuidad entre sesiones  
**Progreso Actual:** 54% (Fase 1 completada)

