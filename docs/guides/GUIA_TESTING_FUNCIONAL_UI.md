# 🧪 GUÍA TESTING FUNCIONAL UI - P0-1 & P0-2

**Fecha:** 2025-10-23 12:35 UTC
**Objetivo:** Validar funcionalidad completa P0-1 (PDF Reports) y P0-2 (Recepción DTEs) via UI
**Duración Estimada:** 2 horas
**URL Odoo:** http://localhost:8169

---

## ✅ PRE-REQUISITOS

**Stack Status:**
```bash
docker-compose ps
# Expected: 6/6 services healthy ✅
```

**Module Status:**
```bash
# ✅ l10n_cl_dte: installed (v19.0.1.0.0)
# ✅ Update: 932 queries, 0.49s
# ⚠️ Warnings: 8 (non-blocking)
```

**Credentials:**
- URL: http://localhost:8169
- User: admin
- Password: (configurado durante instalación)

---

## 🧪 TEST SUITE 1: P0-1 PDF REPORTS (45 min)

### Objetivo
Validar generación de PDF con TED (Timbre Electrónico) barcode

### Test 1.1: Verificar Report Action Visible

**Steps:**
1. Login a Odoo: http://localhost:8169
2. Navegar a: **Contabilidad → Clientes → Facturas**
3. Abrir cualquier invoice existente (o crear una test)
4. Click botón **"Imprimir"** (top-right)
5. Buscar opción **"DTE - Factura Electrónica"** en dropdown

**Expected Result:**
```
✅ Opción "DTE - Factura Electrónica" visible en menú Imprimir
✅ Opción NO arroja error al hacer hover
```

**Screenshot:** `/tmp/test_1.1_report_action.png` (opcional)

**Status:** [ ] PASS / [ ] FAIL

**Notes:**
_______________________________________________________________________________

---

### Test 1.2: Crear Invoice Test

**Steps:**
1. Navegar a: **Contabilidad → Clientes → Facturas**
2. Click **"Crear"**
3. Completar campos:
   ```
   Cliente: Seleccionar partner con RUT chileno
   Fecha Factura: Hoy
   Diario: Seleccionar journal con folios CAF
   ```
4. Agregar línea invoice:
   ```
   Producto: Cualquiera
   Cantidad: 1
   Precio Unitario: 100000
   ```
5. Click **"Guardar"**
6. **NO confirmar** invoice todavía

**Expected Result:**
```
✅ Invoice creada en estado "Draft"
✅ Campos visibles correctamente
✅ Total calculado: $119,000 (incluye 19% IVA)
```

**Invoice ID Created:** _______________

**Status:** [ ] PASS / [ ] FAIL

**Notes:**
_______________________________________________________________________________

---

### Test 1.3: Generar DTE para Invoice

**IMPORTANTE:** Este test requiere DTE Service operacional

**Pre-check DTE Service:**
```bash
docker-compose logs -f dte-service | grep "Application startup complete"
# Expected: "Application startup complete" visible
```

**Steps:**
1. Abrir invoice creada en Test 1.2
2. Buscar botón **"Generar DTE"** (custom button)
3. Si NO existe botón:
   - **SKIP** este test
   - Marcar como **SKIP** (DTE generation wizard no configurado)
   - Proceder a Test 1.4 con mock data

4. Si existe botón:
   - Click **"Generar DTE"**
   - Esperar ~5-10 segundos
   - Verificar cambio de estado

**Expected Result (si wizard existe):**
```
✅ Estado DTE cambia a "Enviado a SII" o "Aceptado"
✅ Campo dte_xml poblado
✅ Campo dte_ted_xml poblado
✅ Campo dte_folio poblado
```

**Expected Result (si wizard NO existe):**
```
⏭️  TEST SKIPPED
Razón: DTE generation wizard pendiente configuración
Action: Proceder con Test 1.4 usando mock XML
```

**Status:** [ ] PASS / [ ] FAIL / [ ] SKIP

**Notes:**
_______________________________________________________________________________

---

### Test 1.4: Imprimir PDF Report

**Steps:**
1. Abrir invoice (con o sin DTE generado)
2. Click botón **"Imprimir"**
3. Seleccionar **"DTE - Factura Electrónica"**
4. Esperar descarga PDF

**Expected Result:**
```
✅ PDF se descarga automáticamente
✅ Nombre archivo: similar a "DTE-33-XXXXX.pdf"
✅ Tamaño: ~100-300 KB
✅ PDF abre sin errores
```

**PDF Downloaded:** [ ] YES / [ ] NO

**Status:** [ ] PASS / [ ] FAIL

**Notes:**
_______________________________________________________________________________

---

### Test 1.5: Visual QA - Contenido PDF

**Steps:**
1. Abrir PDF descargado en Test 1.4
2. Verificar checklist visual:

**HEADER:**
- [ ] Logo empresa visible (si configurado)
- [ ] Recuadro DTE con tipo documento ("Factura Electrónica")
- [ ] Recuadro DTE con folio (o "N/A" si no generado)

**COMPANY INFO:**
- [ ] Razón social empresa
- [ ] RUT empresa (formato XX.XXX.XXX-X)
- [ ] Dirección completa
- [ ] Teléfono y email presentes

**CUSTOMER INFO:**
- [ ] Nombre cliente correcto
- [ ] RUT cliente correcto
- [ ] Dirección cliente

**INVOICE LINES:**
- [ ] Descripción producto visible
- [ ] Cantidad: 1
- [ ] Precio unitario: $100,000
- [ ] Total línea: $100,000

**TOTALS:**
- [ ] Subtotal (Neto): $100,000
- [ ] IVA 19%: $19,000
- [ ] Total (bold): $119,000

**TED SECTION (CRÍTICO):**
- [ ] Título "TIMBRE ELECTRÓNICO SII" visible
- [ ] Barcode presente (PDF417 o QR Code)
- [ ] Barcode NO pixelado
- [ ] Texto legal SII:
  - "Resolución N° 80 del 22-08-2014"
  - "Verifique autenticidad en www.sii.cl"

**FOOTER:**
- [ ] Números de página
- [ ] Legal disclaimers

**OVERALL SCORE:** ___/15

**Status:** [ ] PASS (13+ checks) / [ ] PARTIAL (10-12 checks) / [ ] FAIL (< 10 checks)

**Notes:**
_______________________________________________________________________________

---

### Test 1.6: Scannable TED Barcode (OPCIONAL)

**Pre-requisitos:**
- App SII oficial en smartphone (Android/iOS)
- O app genérica QR scanner

**Steps:**
1. Imprimir PDF en papel (o mostrar en pantalla)
2. Abrir app scanner en smartphone
3. Apuntar cámara al TED barcode
4. Intentar escanear

**Expected Result (si DTE generado):**
```
✅ Barcode se reconoce inmediatamente
✅ Datos DTE se visualizan (RUT, folio, fecha, monto)
✅ No errores de lectura
```

**Expected Result (si mock DTE):**
```
⚠️  Barcode puede no ser válido (mock data)
✅ Barcode debe ser reconocible visualmente
```

**Status:** [ ] PASS / [ ] FAIL / [ ] SKIP

**Notes:**
_______________________________________________________________________________

---

## 🧪 TEST SUITE 2: P0-2 RECEPCIÓN DTEs (1 hora)

### Objetivo
Validar workflow completo de recepción de DTEs de proveedores

### Test 2.1: Verificar Menú DTE Inbox

**Steps:**
1. Login a Odoo
2. Buscar menú: **Compras → Recepción DTEs** (o similar)
3. Si NO existe:
   - Buscar en **Contabilidad → Proveedores → DTEs Recibidos**
4. Si NO existe:
   - Verificar en Settings → Technical → Menu Items
   - Buscar "DTE Inbox" o "dte.inbox"

**Expected Result:**
```
✅ Menú "Recepción DTEs" o similar visible
✅ Click en menú abre vista tree de dte.inbox
```

**Menu Path Found:** _______________

**Status:** [ ] PASS / [ ] FAIL

**Notes:**
_______________________________________________________________________________

---

### Test 2.2: Crear DTE Inbox Manual

**Steps:**
1. Abrir vista dte.inbox (desde menú Test 2.1)
2. Click **"Crear"**
3. Completar campos mínimos:
   ```
   Tipo DTE: 33 (Factura Electrónica)
   Folio: 12345
   RUT Proveedor: 76.123.456-7
   Nombre Proveedor: Test Supplier SA
   Fecha Emisión: Hoy
   Monto Total: 500000
   XML DTE: <pegar XML test o dejar vacío>
   ```
4. Click **"Guardar"**

**Expected Result:**
```
✅ Registro dte.inbox creado
✅ Estado: "New" o "Borrador"
✅ Nombre auto-generado: "DTE 33 - 12345"
```

**DTE Inbox ID Created:** _______________

**Status:** [ ] PASS / [ ] FAIL

**Notes:**
_______________________________________________________________________________

---

### Test 2.3: Validar DTE (Integration Test)

**IMPORTANTE:** Requiere DTE Service operacional

**Pre-check:**
```bash
docker-compose logs -f dte-service | grep "startup complete"
# Expected: Service running ✅
```

**Steps:**
1. Abrir DTE Inbox creado en Test 2.2
2. Buscar botón **"Validate"** (header)
3. Click **"Validate"**
4. Esperar ~5-10 segundos
5. Verificar cambio de estado

**Expected Result (con XML válido):**
```
✅ Estado cambia a "Validated" o "Validado"
✅ Campo validation_status: "valid"
✅ No errores en validation_errors
```

**Expected Result (sin XML o XML inválido):**
```
⚠️  Estado cambia a "Error"
✅ Campo validation_errors poblado con mensaje
```

**Expected Result (DTE Service down):**
```
❌ Error: "Error al conectar con servicio DTE"
✅ Error handling correcto (no crash)
```

**Status:** [ ] PASS / [ ] FAIL / [ ] SKIP

**Notes:**
_______________________________________________________________________________

---

### Test 2.4: Auto-Match con PO (AI Integration)

**IMPORTANTE:** Requiere AI Service operacional + PO existente

**Pre-check:**
```bash
docker-compose logs -f ai-service | grep "startup complete"
# Expected: Service running ✅
```

**Pre-requisito:** Crear Purchase Order test:
1. Navegar: **Compras → Órdenes → Crear**
2. Proveedor: Test Supplier SA (mismo RUT Test 2.2)
3. Producto: Cualquiera, Cantidad: 1, Precio: 500000
4. Confirmar PO

**Steps:**
1. Abrir DTE Inbox validado (Test 2.3)
2. Verificar campo **"purchase_order_id"**
3. Verificar campo **"po_match_confidence"**

**Expected Result (AI Service OK):**
```
✅ Campo purchase_order_id poblado automáticamente
✅ Confidence score > 80%
✅ Estado: "Matched with PO"
```

**Expected Result (AI Service down o no match):**
```
⚠️  purchase_order_id vacío
⚠️  Confidence: 0
✅ Estado: "Validated" (sin match)
```

**Status:** [ ] PASS / [ ] FAIL / [ ] SKIP

**Notes:**
_______________________________________________________________________________

---

### Test 2.5: Crear Invoice desde DTE

**Steps:**
1. Abrir DTE Inbox validado (Test 2.3)
2. Click botón **"Create Invoice"** (header)
3. Esperar ~2-3 segundos
4. Verificar redirección a invoice form

**Expected Result:**
```
✅ Invoice draft creada
✅ Partner: Test Supplier SA
✅ Monto total: $500,000
✅ Referencia: "DTE 33 - 12345"
✅ Campo invoice_id en DTE Inbox poblado
✅ Estado DTE Inbox: "Invoiced" o "Procesado"
```

**Invoice Created ID:** _______________

**Status:** [ ] PASS / [ ] FAIL

**Notes:**
_______________________________________________________________________________

---

### Test 2.6: Send Commercial Response (OPCIONAL)

**IMPORTANTE:** Requiere configuración SII + certificado

**Steps:**
1. Abrir DTE Inbox validado
2. Click botón **"Send Response to SII"**
3. Si abre wizard:
   - Seleccionar: **"Accept Document"**
   - Click **"Send"**
4. Si NO abre wizard:
   - SKIP test

**Expected Result (configuración OK):**
```
✅ Response enviada a SII
✅ Campo response_sent: True
✅ Campo response_code: "0" (Accept)
✅ Chatter muestra mensaje "Response sent"
```

**Expected Result (sin configuración):**
```
⏭️  TEST SKIPPED
Razón: Certificado SII no configurado
```

**Status:** [ ] PASS / [ ] FAIL / [ ] SKIP

**Notes:**
_______________________________________________________________________________

---

## 🧪 TEST SUITE 3: PERFORMANCE BENCHMARKING (15 min)

### Test 3.1: PDF Generation Time

**Steps:**
1. Abrir invoice con DTE generado
2. Medir tiempo desde click "Imprimir" hasta descarga completa
3. Repetir 3 veces, calcular promedio

**Measurements:**
- Try 1: _____ ms
- Try 2: _____ ms
- Try 3: _____ ms
- **Average:** _____ ms

**Expected Result:**
```
✅ Average < 2000ms (2 seconds)
🎯 Target: < 1000ms (1 second)
```

**Status:** [ ] PASS (< 2000ms) / [ ] WARN (2000-3000ms) / [ ] FAIL (> 3000ms)

**Notes:**
_______________________________________________________________________________

---

### Test 3.2: DTE Validation Time

**Steps:**
1. Crear nuevo DTE Inbox con XML válido
2. Medir tiempo desde click "Validate" hasta estado "Validated"
3. Repetir 3 veces

**Measurements:**
- Try 1: _____ ms
- Try 2: _____ ms
- Try 3: _____ ms
- **Average:** _____ ms

**Expected Result:**
```
✅ Average < 5000ms (5 seconds)
🎯 Target: < 3000ms (3 seconds)
```

**Status:** [ ] PASS (< 5000ms) / [ ] WARN (5000-7000ms) / [ ] FAIL (> 7000ms)

**Notes:**
_______________________________________________________________________________

---

### Test 3.3: Invoice Creation Time

**Steps:**
1. Abrir DTE Inbox validado
2. Medir tiempo desde click "Create Invoice" hasta invoice form abierta
3. Repetir 3 veces

**Measurements:**
- Try 1: _____ ms
- Try 2: _____ ms
- Try 3: _____ ms
- **Average:** _____ ms

**Expected Result:**
```
✅ Average < 3000ms (3 seconds)
🎯 Target: < 2000ms (2 seconds)
```

**Status:** [ ] PASS (< 3000ms) / [ ] WARN (3000-5000ms) / [ ] FAIL (> 5000ms)

**Notes:**
_______________________________________________________________________________

---

## 📊 TEST RESULTS SUMMARY

### P0-1 PDF Reports

| Test | Description | Status | Notes |
|------|-------------|--------|-------|
| 1.1 | Report action visible | [ ] | |
| 1.2 | Create invoice test | [ ] | |
| 1.3 | Generate DTE | [ ] | |
| 1.4 | Print PDF report | [ ] | |
| 1.5 | Visual QA PDF | [ ] | Score: ___/15 |
| 1.6 | Scannable barcode | [ ] | |

**Overall P0-1:** [ ] PASS / [ ] PARTIAL / [ ] FAIL

**Pass Criteria:** 4/6 tests PASS (excluding optional tests)

---

### P0-2 Recepción DTEs

| Test | Description | Status | Notes |
|------|-------------|--------|-------|
| 2.1 | Menu visible | [ ] | |
| 2.2 | Create DTE inbox | [ ] | |
| 2.3 | Validate DTE | [ ] | |
| 2.4 | Auto-match PO | [ ] | |
| 2.5 | Create invoice | [ ] | |
| 2.6 | Send response SII | [ ] | |

**Overall P0-2:** [ ] PASS / [ ] PARTIAL / [ ] FAIL

**Pass Criteria:** 4/6 tests PASS (excluding optional tests)

---

### Performance Benchmarking

| Test | Target | Result | Status |
|------|--------|--------|--------|
| 3.1 PDF generation | < 2000ms | ___ms | [ ] |
| 3.2 DTE validation | < 5000ms | ___ms | [ ] |
| 3.3 Invoice creation | < 3000ms | ___ms | [ ] |

**Overall Performance:** [ ] PASS / [ ] WARN / [ ] FAIL

**Pass Criteria:** All 3 tests meet target

---

## ✅ FINAL DECISION

### Criteria for Production Deployment

- [ ] P0-1: At least 4/6 tests PASS
- [ ] P0-2: At least 4/6 tests PASS
- [ ] Performance: At least 2/3 tests PASS
- [ ] No critical errors during testing
- [ ] Stack stable (no crashes)

**Overall Assessment:** [ ] READY / [ ] NOT READY / [ ] PARTIAL

**Recommendation:**
_______________________________________________________________________________
_______________________________________________________________________________
_______________________________________________________________________________

**Blocker Issues (if any):**
_______________________________________________________________________________
_______________________________________________________________________________
_______________________________________________________________________________

**Nice-to-Have Improvements:**
_______________________________________________________________________________
_______________________________________________________________________________
_______________________________________________________________________________

---

## 📋 POST-TESTING ACTIONS

### If READY ✅
1. [ ] Mark P0-1 as production-ready
2. [ ] Mark P0-2 as production-ready
3. [ ] Document test results in final report
4. [ ] Proceder con P1 gaps o P0-3 completion

### If NOT READY ❌
1. [ ] Document blocker issues
2. [ ] Create fix plan
3. [ ] Re-test after fixes
4. [ ] Do NOT deploy to production

### If PARTIAL ⚠️
1. [ ] Document partial results
2. [ ] Identify critical vs nice-to-have fixes
3. [ ] Create prioritized fix backlog
4. [ ] Deploy with documented limitations

---

**Tester:** _______________
**Date:** 2025-10-23
**Duration:** _____h _____min
**Overall Result:** [ ] PASS / [ ] FAIL / [ ] PARTIAL

---

**Firma:** _______________

---
