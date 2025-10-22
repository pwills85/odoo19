# 🏗️ Matriz de Decisiones de Implementación

**Documento:** Dónde Implementar Cada Componente Faltante  
**Versión:** 1.0  
**Fecha:** 2025-10-21  
**Criterio:** Arquitectura de 3 Capas + Principios SOLID

---

## 🎯 CRITERIOS DE DECISIÓN

### Implementar en ODOO MODULE si:
- ✅ Requiere acceso directo a BD Odoo
- ✅ Requiere UI/formularios
- ✅ Es gestión de datos (CRUD)
- ✅ Es validación simple/rápida
- ✅ Es workflow de estados
- ✅ Es lógica de negocio core

### Implementar en DTE MICROSERVICE si:
- ✅ Es generación/procesamiento XML (CPU intensivo)
- ✅ Es firma digital/criptografía (CPU intensivo)
- ✅ Es comunicación SOAP con SII (I/O bloqueante)
- ✅ Es procesamiento pesado
- ✅ Requiere cola asíncrona
- ✅ Es reutilizable entre múltiples instancias Odoo

### Implementar en AI SERVICE si:
- ✅ Requiere ML/IA
- ✅ Es análisis de patrones
- ✅ Es matching/similarity
- ✅ Es clasificación automática
- ✅ Genera insights

---

## 📊 MATRIZ COMPLETA DE DECISIONES

| Componente Faltante | Odoo | DTE | AI | Razón Principal | Archivos |
|---------------------|------|-----|-----|-----------------|----------|
| **1. CAF (Código Autorización Folios)** | | | | | |
| Modelo dte.caf | ✅ | ❌ | ❌ | BD + UI | models/dte_caf.py |
| Wizard upload CAF | ✅ | ❌ | ❌ | UI Odoo | wizard/upload_caf.py |
| Inclusión CAF en XML | ❌ | ✅ | ❌ | Generación XML | generators/caf_handler.py |
| Validación folio en CAF | ✅ | ❌ | ❌ | Lógica negocio | account_journal_dte.py |
| **2. TED (Timbre Electrónico)** | | | | | |
| Cálculo hash DD | ❌ | ✅ | ❌ | Criptografía | generators/ted_generator.py |
| Generación XML TED | ❌ | ✅ | ❌ | Generación XML | generators/ted_generator.py |
| Generación QR code | ❌ | ✅ | ❌ | Procesamiento imagen | generators/ted_generator.py |
| Inclusión TED en XML | ❌ | ✅ | ❌ | Generación XML | dte_generator_33.py |
| QR en PDF | ✅ | ❌ | ❌ | QWeb report | reports/dte_invoice_report.xml |
| **3. Firma Digital** | | | | | |
| Firma XMLDsig real | ❌ | ✅ | ❌ | Criptografía + xmlsec | signers/xmldsig_signer.py |
| Cálculo DigestValue | ❌ | ✅ | ❌ | Criptográfico | signers/xmldsig_signer.py |
| Cálculo SignatureValue | ❌ | ✅ | ❌ | Firma digital | signers/xmldsig_signer.py |
| **4. Validación XSD** | | | | | |
| Descarga XSD schemas | ❌ | ✅ | ❌ | Archivos estáticos | schemas/*.xsd |
| Validación XML vs XSD | ❌ | ✅ | ❌ | Procesamiento XML | validators/xsd_validator.py |
| **5. Libros Electrónicos** | | | | | |
| Modelo consumo.folios | ✅ | ❌ | ❌ | BD + UI | models/dte_consumo_folios.py |
| Modelo dte.libro | ✅ | ❌ | ❌ | BD + UI | models/dte_libro.py |
| Agregación datos | ✅ | ❌ | ❌ | Query ORM | dte_libro.py |
| Generación XML Consumo | ❌ | ✅ | ❌ | Generación XML | generators/consumo_generator.py |
| Generación XML Libro | ❌ | ✅ | ❌ | Generación XML | generators/libro_generator.py |
| Envío a SII | ❌ | ✅ | ❌ | SOAP | clients/sii_soap_client.py |
| **6. Recepción Compras** | | | | | |
| Polling DTEs recibidos | ❌ | ✅ | ❌ | SOAP polling | receivers/dte_receiver.py |
| Descarga XML | ❌ | ✅ | ❌ | SOAP download | receivers/dte_receiver.py |
| Parseo XML | ❌ | ✅ | ❌ | Procesamiento XML | receivers/xml_parser.py |
| Reconciliación PO | ⚠️ | ❌ | ✅ | IA matching | reconciliation/invoice_matcher.py |
| Crear factura compra | ✅ | ❌ | ❌ | ORM Odoo | account_move_dte.py |
| **7. Modelos Faltantes** | | | | | |
| account_tax_dte.py | ✅ | ❌ | ❌ | Extensión tax | models/account_tax_dte.py |
| purchase_order_dte.py | ✅ | ❌ | ❌ | Extensión PO | models/purchase_order_dte.py |
| stock_picking_dte.py | ✅ | ❌ | ❌ | Extensión picking | models/stock_picking_dte.py |
| retencion_iue.py | ✅ | ❌ | ❌ | Modelo negocio | models/retencion_iue.py |
| **8. Vistas Faltantes (11)** | ✅ | ❌ | ❌ | UI Odoo | views/*.xml |
| **9. Generadores DTE** | | | | | |
| DTE 34 generator | ❌ | ✅ | ❌ | Generación XML | generators/dte_generator_34.py |
| DTE 52 generator | ❌ | ✅ | ❌ | Generación XML | generators/dte_generator_52.py |
| DTE 56 generator | ❌ | ✅ | ❌ | Generación XML | generators/dte_generator_56.py |
| DTE 61 generator | ❌ | ✅ | ❌ | Generación XML | generators/dte_generator_61.py |

---

## 📊 RESUMEN POR CAPA

### ODOO MODULE (30 componentes)

**Modelos (9):**
1. `models/dte_caf.py` - Gestión CAF
2. `models/dte_consumo_folios.py` - Consumo de folios
3. `models/dte_libro.py` - Libro compra/venta
4. `models/account_tax_dte.py` - Códigos SII en impuestos
5. `models/purchase_order_dte.py` - DTE 34 (Honorarios)
6. `models/stock_picking_dte.py` - DTE 52 (Guías)
7. `models/retencion_iue.py` - Retenciones
8. Extender: `account_journal_dte.py` - Validación CAF
9. Extender: `account_move_dte.py` - Crear desde DTE recibido

**Vistas (15):**
1. `views/dte_caf_views.xml`
2. `views/dte_consumo_folios_views.xml`
3. `views/dte_libro_views.xml`
4. `views/account_journal_dte_views.xml`
5. `views/purchase_order_dte_views.xml`
6. `views/stock_picking_dte_views.xml`
7. `views/retencion_iue_views.xml`
8-11. `wizard/*.xml` (4 wizards)
12-13. `reports/*.xml` (2 reportes)
14. `data/sii_activity_codes.xml`

**Wizards (4):**
1. `wizard/upload_caf.py` + vista
2. `wizard/send_dte_batch.py` + vista
3. `wizard/generate_consumo_folios.py` + vista
4. `wizard/generate_libro.py` + vista

**Reportes (2):**
1. `reports/dte_invoice_report.xml` (PDF con QR)
2. `reports/dte_receipt_report.xml` (Recibo)

**Total Odoo:** ~21 archivos (~1,800 líneas)

---

### DTE MICROSERVICE (13 componentes)

**Generadores (7):**
1. `generators/caf_handler.py` - Inclusión CAF en XML
2. `generators/ted_generator.py` - TED completo (hash + XML + QR)
3. Completar: `generators/dte_generator_33.py` - Incluir CAF + TED
4. `generators/dte_generator_34.py` - Honorarios
5. `generators/dte_generator_52.py` - Guías
6. `generators/dte_generator_56.py` - Notas Débito
7. `generators/dte_generator_61.py` - Notas Crédito

**Generadores Libros (2):**
1. `generators/consumo_generator.py` - XML Consumo Folios
2. `generators/libro_generator.py` - XML Libro Compra/Venta

**Firmador (1):**
1. `signers/xmldsig_signer.py` - Firma real con xmlsec

**Validadores (1):**
1. `validators/xsd_validator.py` - Validación contra XSD

**Receivers (2):**
1. `receivers/dte_receiver.py` - Polling + descarga
2. `receivers/xml_parser.py` - Parseo DTEs recibidos

**Total DTE:** ~13 archivos (~1,200 líneas)

---

### AI SERVICE (1 componente)

**Reconciliación (1):**
1. Completar: `reconciliation/invoice_matcher.py` - Embeddings + matching real

**Total AI:** ~1 archivo (~200 líneas)

---

## 🔄 FLUJOS DE INTEGRACIÓN

### Flujo 1: Emisión DTE con CAF + TED

```
Usuario crea factura en Odoo
  ↓
Odoo valida:
  • RUT cliente ✅
  • Monto > 0 ✅
  • Certificado válido ✅
  • Folio en rango CAF ✅ (NUEVO - Odoo)
  ↓
Odoo prepara datos y envía a DTE Service:
  • invoice_data
  • certificate
  • caf_xml ✅ (NUEVO - Odoo extrae de BD)
  ↓
DTE Service:
  1. Genera XML DTE ✅
  2. Incluye CAF en XML ✅ (NUEVO)
  3. Calcula TED (hash DD) ✅ (NUEVO)
  4. Genera QR del TED ✅ (NUEVO)
  5. Incluye TED en XML ✅ (NUEVO)
  6. Valida contra XSD ✅ (NUEVO)
  7. Firma con xmlsec ✅ (NUEVO)
  8. Envía a SII via SOAP ✅
  ↓
DTE Service retorna a Odoo:
  • folio, track_id, xml_firmado
  • qr_image_b64 ✅ (NUEVO)
  ↓
Odoo guarda:
  • DTE en BD
  • Genera PDF con QR ✅ (NUEVO - QWeb)
```

### Flujo 2: Generación Libro de Ventas

```
Usuario solicita "Libro Ventas Octubre" en Odoo
  ↓
Odoo (modelo dte.libro):
  1. Query account.move (facturas del mes) ✅
  2. Agregar totales ✅
  3. Preparar datos
  ↓
Odoo envía datos a DTE Service
  ↓
DTE Service:
  1. Genera XML Libro ✅ (NUEVO)
  2. Firma XML ✅
  3. Envía a SII ✅ (NUEVO)
  ↓
DTE Service retorna resultado
  ↓
Odoo guarda constancia
```

### Flujo 3: Recepción de Compras

```
DTE Service (cron cada 30 min):
  1. Polling SII (DTEs recibidos) ✅ (NUEVO)
  2. Descarga XML de nuevos DTEs ✅ (NUEVO)
  3. Parsea XML ✅ (NUEVO)
  ↓
DTE Service llama AI Service:
  • Reconciliar con POs pendientes ✅ (NUEVO)
  ↓
AI Service:
  • Embeddings de líneas
  • Matching semántico
  • Retorna PO con 92% confidence ✅ (NUEVO)
  ↓
DTE Service callback a Odoo:
  • DTE data + matched_po_id
  ↓
Odoo:
  1. Crea account.move ✅ (NUEVO)
  2. Link con PO
  3. Notifica usuario
```

---

## 🎯 RESUMEN EJECUTIVO

### Distribución de Trabajo Restante

| Capa | Archivos | Líneas | Tiempo |
|------|----------|--------|--------|
| **Odoo Module** | 21 | ~1,800 | 2-3 sem |
| **DTE Microservice** | 13 | ~1,200 | 2-3 sem |
| **AI Service** | 1 | ~200 | 3-5 días |
| **TOTAL** | **35** | **~3,200** | **4-6 sem** |

---

## 🚀 PLAN DE IMPLEMENTACIÓN RECOMENDADO

### Fase A: Hacer Módulo Instalable (1 semana)

**Odoo Module:**
- Crear 4 modelos faltantes (stubs básicos)
- Crear 11 vistas faltantes (básicas)
- Corregir __manifest__.py

**Resultado:** Módulo instalable, sin funcionalidad DTE real

---

### Fase B: CAF + TED + Firma (2 semanas)

**Odoo Module (1 semana):**
- Implementar dte.caf completo
- Wizard upload CAF
- Validación folio en CAF
- Reporte PDF con QR

**DTE Microservice (1 semana):**
- CAF handler (inclusión en XML)
- TED generator completo (hash + XML TED + QR)
- Firma real con xmlsec
- Validación XSD

**Resultado:** DTE 33 funcional, aceptado por SII sandbox

---

### Fase C: Libros + DTEs Adicionales (2 semanas)

**Odoo Module (1 semana):**
- Modelos consumo.folios y dte.libro
- Vistas y wizards
- purchase_order_dte.py (DTE 34)
- stock_picking_dte.py (DTE 52)

**DTE Microservice (1 semana):**
- Generadores: 34, 52, 56, 61
- Generadores: Consumo, Libro
- Extensión SOAP client

**Resultado:** Todos los DTEs + reportes SII funcionando

---

### Fase D: Recepción + IA (1 semana)

**DTE Microservice:**
- Receiver (polling + descarga)
- XML parser

**AI Service:**
- Reconciliación real con embeddings

**Odoo Module:**
- Método create_from_received_dte

**Resultado:** Sistema completo funcional

---

## 📋 CHECKLIST DE PRIORIDADES

### Prioridad 1 - CRÍTICO (Sin esto, no funciona con SII)

- [ ] Modelo dte.caf (Odoo)
- [ ] Inclusión CAF en XML (DTE Service)
- [ ] TED generator completo (DTE Service)
- [ ] Firma real con xmlsec (DTE Service)
- [ ] Validación XSD (DTE Service)
- [ ] 15 archivos faltantes para instalación (Odoo)

**Tiempo:** 2-3 semanas  
**Resultado:** DTE 33 funcional con SII

---

### Prioridad 2 - ALTO (Cumplimiento SII)

- [ ] Libros electrónicos (Odoo + DTE Service)
- [ ] Consumo de folios (Odoo + DTE Service)
- [ ] DTEs adicionales: 34, 52 (Odoo + DTE Service)

**Tiempo:** 2 semanas  
**Resultado:** Cumplimiento completo SII

---

### Prioridad 3 - MEDIO (Funcionalidad completa)

- [ ] Recepción de compras (DTE Service)
- [ ] Reconciliación IA (AI Service)
- [ ] DTEs: 56, 61 (DTE Service)

**Tiempo:** 1 semana  
**Resultado:** Sistema completo

---

## ✅ DECISIÓN FINAL

### ¿Dónde implementar lo faltante?

**DISTRIBUCIÓN RECOMENDADA:**

```
ODOO MODULE (60%):
  • 21 archivos
  • Modelos, vistas, wizards, reportes
  • Lógica de negocio, UI, workflow
  • ~1,800 líneas

DTE MICROSERVICE (38%):
  • 13 archivos
  • Generadores XML, firma, SOAP, validadores
  • Procesamiento pesado, I/O bloqueante
  • ~1,200 líneas

AI SERVICE (2%):
  • 1 archivo
  • Reconciliación real con embeddings
  • ~200 líneas
```

**Razón:** Respetar separación de responsabilidades definida en arquitectura de 3 capas.

---

**Próximo Paso:** Decidir si continuar con implementación completa o ajustar alcance del MVP

---

**Fecha:** 2025-10-21  
**Autor:** AI Assistant (Experto Odoo 19 CE + SII Chile)

