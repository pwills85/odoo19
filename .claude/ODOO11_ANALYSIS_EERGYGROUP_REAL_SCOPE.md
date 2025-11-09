# 🔍 Análisis Odoo 11 EERGYGROUP - Scope Real

**Fecha:** 2025-11-08
**Fuente:** Base de datos producción Odoo 11 (EERGYGROUP)
**Análisis:** 7,609 facturas + 646 stock pickings (2024-2025)

---

## 📊 HALLAZGOS CRÍTICOS

### ❌ ERROR EN INVESTIGACIÓN PREVIA

**ASUMIDO INCORRECTAMENTE:**
- Boletas Electrónicas 39/41 (retail B2C) como P0 crítico
- DTEs Exportación 110/111/112 como P0 para exportadores
- No se consideró migración Odoo 11 → 19 como feature crítica

**REALIDAD EERGYGROUP:**
- ✅ Empresa de INGENIERÍA (proyectos eléctricos industriales + generación)
- ✅ B2B únicamente (NO retail)
- ✅ Migración Odoo 11 → 19 es CRÍTICA (7,609 facturas + datos históricos)

---

## 📈 DTEs REALMENTE USADOS (Análisis 2024-2025)

### Datos Extraídos de Producción

```sql
-- Query ejecutada:
SELECT dc.sii_code, dc.name, COUNT(ai.id) as count,
       MIN(ai.date_invoice) as first_used,
       MAX(ai.date_invoice) as last_used
FROM account_invoice ai
JOIN sii_document_class dc ON ai.document_class_id = dc.id
WHERE ai.date_invoice >= '2024-01-01'
GROUP BY dc.sii_code, dc.name
ORDER BY count DESC;
```

**Resultados:**

| SII Code | Nombre | Count | % | First Used | Last Used | Prioridad |
|----------|--------|-------|---|------------|-----------|-----------|
| **33** | Factura Electrónica | 7,261 | 95.4% | 2024-01-02 | 2025-08-18 | **CORE** |
| **61** | Nota de Crédito Electrónica | 144 | 1.9% | 2024-01-02 | 2025-08-06 | **CORE** |
| **34** | Factura Exenta Electrónica | 60 | 0.8% | 2024-03-11 | 2025-07-17 | **CORE** |
| **71** | Boleta Honorarios Electrónica | 3 | 0.04% | 2024-10-10 | 2025-03-27 | **P1** |
| **56** | Nota de Débito Electrónica | 2 | 0.03% | 2024-05-22 | 2024-06-04 | **P1** |

**TOTAL:** 7,470 documentos tributarios en 20 meses

---

## ✅ SCOPE CORRECTO EERGYGROUP

### VENTA (Customer Invoices)
1. ✅ **DTE 33** - Factura Electrónica (7,261 - 95.4%) - **CORE**
2. ✅ **DTE 34** - Factura Exenta (60 - 0.8%) - **CORE**
3. ✅ **DTE 56** - Nota Débito (2 - 0.03%) - **P1**
4. ✅ **DTE 61** - Nota Crédito (144 - 1.9%) - **CORE**
5. ⚠️ **DTE 52** - Guía Despacho (0 DTEs generados) - **P0 IMPLEMENTAR**

### COMPRA (Supplier Invoices)
1. ✅ **Recepción DTEs** 33, 34, 56, 61 (via email/IMAP)
2. ✅ **DTE 71** - Boleta Honorarios Electrónica (3 usadas, recepción) - **P1**
3. ⚠️ **Boletas Honorarios Papel** (entrada manual) - **P2**

### LOGÍSTICA (Stock Pickings)
- **646 stock pickings** en 2024-2025
- **0 con DTE generado** (sii_xml_dte IS NULL)
- **Usuario indica:** Necesitan DTE 52 (Guía Despacho) para mover equipos a obras
- **Status:** ⚠️ **NO IMPLEMENTADO** en Odoo 11 actual

---

## ❌ DTEs NO USADOS (Eliminar de Prioridad)

### Retail (B2C) - NO APLICA EERGYGROUP
- ❌ **DTE 39** - Boleta Electrónica (0 usadas) - **ELIMINAR de roadmap**
- ❌ **DTE 41** - Boleta Exenta (0 usadas) - **ELIMINAR de roadmap**
- ❌ **Res. 44/2025** - Boletas >135 UF (NO aplica) - **ELIMINAR**

### Exportación - VERIFICAR SI APLICA
- ❓ **DTE 110** - Factura Exportación (0 usadas)
- ❓ **DTE 111** - ND Exportación (0 usadas)
- ❓ **DTE 112** - NC Exportación (0 usadas)

**Pregunta para usuario:** ¿EERGYGROUP exporta equipos/servicios al extranjero?
- Si SÍ → Mantener como P1 (on-demand)
- Si NO → ELIMINAR de roadmap

---

## 🚨 FEATURE CRÍTICA NO CONSIDERADA: MIGRACIÓN ODOO 11 → 19

### Datos a Migrar

**Account Invoices:**
- **7,609 facturas** desde 2024-01-01
- **Campos DTE específicos:**
  - `sii_xml_dte` (TEXT) - XML completo del DTE
  - `sii_code` (INTEGER) - Código tipo documento (33, 34, 56, 61, 71)
  - `sii_document_number` (BIGINT) - Folio del DTE
  - `sii_barcode` (VARCHAR) - Timbre electrónico
  - `sii_result`, `sii_message` - Respuesta SII
  - `estado_recep_dte` - Estado recepción
  - `document_class_id` - FK a sii_document_class

**Stock Pickings:**
- **646 transferencias** desde 2024-01-01
- **Campos DTE:** Estructura similar pero sin DTEs generados

**Partners (Contactos):**
- Query pendiente - estructura RUT, activity codes, responsabilidad tributaria

**DTE Configuration:**
- **CAFs (Folios autorizados):** Tabla `dte_caf`
- **Firmas digitales:** `sii_firma`
- **Document classes:** `sii_document_class`
- **Journal configurations:** `account_journal_sii_document_class`

### Complejidad Migración

**ALTA:**
- Schema Odoo 11 vs Odoo 19 tiene cambios significativos
- DTEs generados (XML, firmas) deben preservarse para auditoría SII (7 años)
- Folios deben mantener secuencia
- Configuración CAF debe migrarse

**Estimación Esfuerzo:** XL (6-8 semanas)
**Prioridad:** **P0 CRÍTICO**
**Deadline:** Antes de go-live Odoo 19

---

## 📋 FEATURE MATRIX CORREGIDA

### Módulo 1: l10n_cl_dte

#### ✅ COMPLETO (Production Ready)
1. DTE 33 (Factura) - 7,261 usadas ✅
2. DTE 34 (Factura Exenta) - 60 usadas ✅
3. DTE 56 (Nota Débito) - 2 usadas ✅
4. DTE 61 (Nota Crédito) - 144 usadas ✅
5. CAF Management ✅
6. Firma Digital XMLDSig ✅
7. Integración SII SOAP ✅
8. Recepción DTEs (Email/IMAP) ✅
9. RCV (Registro Compras/Ventas) ✅

#### ⚠️ GAPS CRÍTICOS

**P0 - BLOQUEANTE:**
1. **DTE 52 (Guía de Despacho)** - NOT IMPLEMENTED
   - Uso: Mover equipos a obras/oficina
   - Stock pickings: 646 sin DTE
   - Effort: L (4-5 weeks)
   - Legal: OPCIONAL pero requerido para trazabilidad

2. **Migración Odoo 11 → 19** - NOT PLANNED
   - Scope: 7,609 facturas + configuración
   - Effort: XL (6-8 weeks)
   - Risk: Pérdida datos históricos, auditoría SII
   - Deadline: Antes go-live

**P1 - COMPLIANCE:**
3. **Boletas Honorarios (DTE 71) - Recepción** - PARTIAL
   - Status: 3 usadas en Odoo 11 (recepción)
   - Emission: Verificar si necesitan emitir
   - Effort: M (2-3 weeks)

**P2 - ENHANCEMENT:**
4. **Boletas Honorarios Papel** - Manual entry
   - Effort: S (1 week)

#### ❌ ELIMINAR DE ROADMAP
- DTE 39/41 (Boletas retail) - NO APLICA
- Res. 44/2025 (Boletas >135 UF) - NO APLICA
- DTE 110/111/112 (Export) - VERIFICAR con usuario

---

## 🗓️ ROADMAP CORREGIDO

### Q1 2025 (SUPERVIVENCIA)
**No cambia - Payroll P0 sigue siendo urgente:**
- Reforma Previsional 2025 (10h) - Deadline: 2025-01-15
- Wizard Previred (13h)
- Tope AFP 87.8 UF (3h)

### Q2 2025 (MIGRACIÓN + GUÍAS)
**NUEVO - CRÍTICO:**
- **Week 1-8:** Migración Odoo 11 → 19 (XL 6-8w) **P0**
  - Análisis schema differences
  - ETL data migration
  - Validación DTEs preservados
  - Testing exhaustivo

- **Week 9-12:** DTE 52 Guía Despacho (L 4-5w) **P0**
  - Integración stock.picking
  - Generación XML DTE 52
  - Testing con mover equipos

### Q3 2025 (ENHANCEMENT)
- Boletas Honorarios 71 (emisión si aplica) - M (2-3w) **P1**
- Form 22 Renta completo - M (8h) **P1**

### Q4 2025 (OPCIONALES)
- Dashboard Nómina - M (8h) **P2**
- PDF417 barcode visual - S (1w) **P2**

### ❌ ELIMINADO
- Boletas 39/41 (retail) - NO APLICA
- Res. 44/2025 - NO APLICA
- DTEs Export 110/111/112 - PENDIENTE confirmación usuario

---

## 📊 ANÁLISIS SCHEMA ODOO 11

### Tablas DTE Clave

```
sii_document_class           - 10 tipos configurados (33,34,39,41,52,56,61,110,111,112)
dte_caf                      - Folios autorizados SII
dte_caf_apicaf              - API CAF integration
account_journal_sii_document_class - Journal + DTE config
account_invoice (7,609 rows) - Facturas con campos DTE
  ├─ sii_xml_dte             - XML completo
  ├─ document_class_id       - FK sii_document_class
  ├─ sii_document_number     - Folio
  └─ sii_barcode             - Timbre
stock_picking (646 rows)     - Transferencias SIN DTEs
  └─ sii_xml_dte             - NULL (no implementado)
mail_message_dte_document    - Recepción DTEs proveedores
```

### Models Honorarios

```
account.move.book.honorarios     - Libro Honorarios
account.move.book.honorarios.tax - Impuestos BHE
```

---

## 🎯 PRÓXIMOS PASOS INMEDIATOS

**1. Validar con usuario:**
- ¿Exportan equipos/servicios? → DTEs 110/111/112
- ¿Emiten Boletas Honorarios o solo reciben? → DTE 71
- ¿Deadline migración Odoo 11 → 19?

**2. Corregir Feature Matrix:**
- Eliminar Boletas 39/41 y Res. 44/2025
- Agregar Migración Odoo 11 → 19 como P0
- Elevar DTE 52 Guía Despacho a P0

**3. Actualizar Agentes:**
- odoo-dev.md: Scope correcto, migración plan
- dte-compliance.md: Eliminar retail compliance
- test-automation.md: Tests migración
- docker-devops.md: Deployment migración

**4. Análisis Profundo Schema:**
- Comparar account_invoice Odoo 11 vs account_move Odoo 19
- Mapear campos DTE específicos
- Identificar breaking changes

---

## 📈 MÉTRICAS REALES EERGYGROUP

**Volumen Anual Estimado:**
- Facturas: ~4,350/año (7,261 en 20 meses = 4,357/año)
- Notas Crédito: ~86/año
- Facturas Exentas: ~36/año
- Stock Pickings: ~387/año

**Composición:**
- 95.4% Facturas afectas IVA (DTE 33)
- 1.9% Notas Crédito (DTE 61)
- 0.8% Facturas Exentas (DTE 34)
- 0.3% Otros (56, 71)

**Conclusión:** Volumen B2B moderado, facturación concentrada en DTE 33.

---

**Estado:** ✅ **ANÁLISIS COMPLETO**
**Próximo:** Corregir agentes con scope real
**Urgencia:** Payroll P0 (54 días) + Planificar migración

