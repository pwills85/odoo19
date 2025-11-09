# MATRIZ DE REPORTES: ODOO 19 CE vs REQUERIMIENTOS SII

**Versión:** 1.0  
**Fecha:** 2025-10-23  
**Proyecto:** Odoo 19 CE - Localización Chile  
**Actualización:** Resultado de análisis profundo de módulos contables  

---

## 1. MATRIZ COMPLETA DE REPORTES

### 1.1 Reportes Obligatorios SII

| Reporte | Código | Tipo | Odoo 19 CE | l10n_cl | l10n_cl_dte | Status | Observaciones |
|---------|--------|------|-----------|---------|-----------|--------|---|
| **Factura Electrónica** | DTE 33 | Documento | account.move | ✓ | ✓ PDF QWeb | ✓ LISTO | Motor: QWeb + wkhtmltopdf |
| **Guía Despacho** | DTE 52 | Documento | stock.picking | ✓ | Parcial | ⚠ EN DEV | Requiere integración stock |
| **Nota Débito** | DTE 56 | Documento | account.move | ✓ | ✓ PDF QWeb | ✓ LISTO | Usa mismo template que DTE 33 |
| **Nota Crédito** | DTE 61 | Documento | account.move | ✓ | ✓ PDF QWeb | ✓ LISTO | Usa mismo template que DTE 33 |
| **Libro Venta Electrónico** | N/A | Reporte | - | - | ✓ dte.libro | ✓ LISTO | XML + Consumo folios |
| **Libro Compra Electrónico** | N/A | Reporte | - | - | ✓ dte.libro | ✓ LISTO | XML + Consumo folios |
| **Consumo Folios (DIN)** | N/A | Reporte | - | - | ✓ dte.consumo_folios | ⚠ PARCIAL | Integración con libros |
| **Reporte Impuestos Mensuales** | F29-F40 | Reporte | account.report | ✓ tax_tags | - | ✓ LISTO | Motor: tax_tags (40+ líneas) |

### 1.2 Reportes de Análisis Financiero (Nativo Odoo)

| Reporte | Odoo 19 CE | Motor | Período | Tipo | Status |
|---------|-----------|-------|---------|------|--------|
| **Balance General** | ✓ | aml | Acumulado | Jerárquico | ✓ NATIVO |
| **Estado de Resultados (P&L)** | ✓ | aml | Variable | Jerárquico | ✓ NATIVO |
| **Libro Mayor** | ✓ | aml | Variable | Detallado | ✓ NATIVO |
| **Balance de Prueba** | ✓ | aml | Variable | Jerárquico | ✓ NATIVO |
| **Libro Diario** | ✓ | aml | Variable | Detallado | ✓ NATIVO |
| **Antigüedad Cobranzas** | ✓ | aml | Variable | Analítico | ✓ NATIVO |
| **Antigüedad Pagos** | ✓ | aml | Variable | Analítico | ✓ NATIVO |
| **Flujo de Caja** | ✓ | aml | Variable | Flujo | ✓ NATIVO |

### 1.3 Reportes Complementarios (Custom/Parcial)

| Reporte | Requerimiento | Odoo 19 CE | Implementado | Prioridad |
|---------|---|---|---|---|
| **Libro Ingresos/Egresos (BHE)** | SII (empresas específicas) | - | Parcial (modelo l10n_cl_bhe_book) | Media |
| **Retenciones IUE** | SII (constructoras) | - | Parcial (modelo retencion_iue) | Media |
| **Declaración Impuesto Renta (F22)** | SII | - | No | Post-MVP |
| **Anexo Accionistas** | SII | - | No | Post-MVP |
| **Certificado Retención** | Informativo | - | No | Baja |

---

## 2. DESGLOSE POR TIPO DE REPORTE

### 2.1 Reportes DTE (Documentos Tributarios Electrónicos)

```
CATEGORÍA: DOCUMENTOS (Generan folio SII)
├── DTE 33 - Factura Electrónica
│   ├── Base: account.move (out_invoice)
│   ├── Template: report_invoice_dte_document.xml
│   ├── Motor: QWeb → PDF
│   ├── Includes: TED (PDF417 + QR)
│   ├── Status: ✓ IMPLEMENTADO
│   └── SII: Obligatorio
│
├── DTE 34 - Factura Exenta Electrónica
│   ├── Base: account.move (out_invoice)
│   ├── Variante: Sin IVA
│   ├── Status: ⚠ EN DESARROLLO
│   └── SII: Opcional (empresas activas)
│
├── DTE 52 - Guía de Despacho Electrónica
│   ├── Base: stock.picking
│   ├── Status: ⚠ PARCIAL
│   ├── Pendiente: Integración con stock
│   └── SII: Obligatorio para transporte
│
├── DTE 56 - Nota de Débito Electrónica
│   ├── Base: account.move (debit_note)
│   ├── Template: report_invoice_dte_document.xml
│   ├── Status: ✓ IMPLEMENTADO
│   └── SII: Obligatorio
│
└── DTE 61 - Nota de Crédito Electrónica
    ├── Base: account.move (credit_note)
    ├── Template: report_invoice_dte_document.xml
    ├── Status: ✓ IMPLEMENTADO
    └── SII: Obligatorio
```

### 2.2 Reportes Libros Electrónicos

```
CATEGORÍA: LIBROS (Reportes consolidados mensuales)
├── Libro de Venta Electrónico (LIBRO_V)
│   ├── Base: account.move (move_type=out_invoice/out_refund)
│   ├── Modelo: dte.libro
│   ├── Período: Mensual
│   ├── Incluye: DTE 33, 34, 56, 61
│   ├── Formato: XML
│   ├── Status: ✓ IMPLEMENTADO
│   └── SII: Obligatorio
│
├── Libro de Compra Electrónico (LIBRO_C)
│   ├── Base: account.move (move_type=in_invoice/in_refund)
│   ├── Modelo: dte.libro
│   ├── Período: Mensual
│   ├── Incluye: DTE 33, 34, 56, 61, 46
│   ├── Formato: XML
│   ├── Status: ✓ IMPLEMENTADO
│   └── SII: Obligatorio
│
├── Libro de Guías Electrónico (LIBRO_G)
│   ├── Base: stock.picking (DTE 52)
│   ├── Modelo: dte.libro_guias
│   ├── Período: Mensual
│   ├── Formato: XML
│   ├── Status: ✓ IMPLEMENTADO
│   └── SII: Opcional (solo transporte)
│
└── Consumo de Folios (DIN)
    ├── Base: DTEConsumoFolios
    ├── Documento: Comprobante IEC/REC
    ├── Período: Mensual
    ├── Status: ⚠ PARCIAL
    └── SII: Informativo
```

### 2.3 Reportes de Impuestos SII

```
CATEGORÍA: IMPUESTOS (Cálculo y declaración)
├── Reporte Impuesto General (account.report)
│   ├── Motor: tax_tags
│   ├── País: Chile (l10n_cl)
│   ├── Líneas: 40+
│   ├── Status: ✓ IMPLEMENTADO
│   ├── Integración: Automática con facturas
│   ├── Campos Principales:
│   │  ├── F23: Impuesto Renta 1ª Categoría
│   │  ├── F24: PPM
│   │  ├── F25: IVA Débito Fiscal
│   │  ├── F26: IVA Crédito Fiscal
│   │  ├── F27: Compras Gravadas IVA
│   │  ├── F29: Base Imponible Ventas
│   │  ├── F30: Ventas Exentas
│   │  ├── F38: Retención Segunda Categoría
│   │  ├── F39: Retención ILA (Compras)
│   │  └── F40: Retención ILA (Ventas)
│   └── Período: Mensual/Trimestral
│
├── Retenciones IUE (empresas constructoras)
│   ├── Base: retencion_iue (modelo)
│   ├── Status: ⚠ PARCIAL
│   ├── Pendiente: Integración con reportes
│   └── SII: Obligatorio (constructoras)
│
├── Libro Ingresos/Egresos (BHE)
│   ├── Base: l10n_cl_bhe_book (modelo)
│   ├── Status: ⚠ PARCIAL
│   ├── Pendiente: Testing y validación
│   └── SII: Específico (empresas)
│
└── Declaración Impuesto Renta (F22)
    ├── Modelo: No implementado
    ├── Status: ❌ PENDIENTE
    ├── Requisito: Análisis profundo F22
    └── Prioridad: Post-MVP
```

### 2.4 Reportes Financieros Nativo Odoo

```
CATEGORÍA: ANÁLISIS FINANCIERO (Nativo account.report)
├── Balance General (Balance Sheet)
│   ├── Motor: aml (account.move.line)
│   ├── Estructura: Activos | Pasivos | Patrimonio
│   ├── Período: Acumulado desde inicio
│   ├── Columnas: Balance
│   ├── Status: ✓ NATIVO
│   ├── Integración: Automática con Contabilidad
│   └── Uso: Análisis financiero, SII
│
├── Estado de Resultados (P&L)
│   ├── Motor: aml
│   ├── Estructura: Ingresos - Gastos = Utilidad/Pérdida
│   ├── Período: Variable (mes/trimestre/año)
│   ├── Status: ✓ NATIVO
│   └── Uso: Análisis rentabilidad, SII
│
├── Libro Mayor (General Ledger)
│   ├── Motor: aml
│   ├── Formato: Detallado (línea por línea)
│   ├── Período: Variable
│   ├── Filtros: Cuenta, diario, período
│   ├── Status: ✓ NATIVO
│   └── Uso: Auditoría contable
│
├── Balance de Prueba (Trial Balance)
│   ├── Motor: aml
│   ├── Columnas: Debe | Haber | Saldo
│   ├── Período: Variable
│   ├── Status: ✓ NATIVO
│   └── Uso: Verificación cuadre
│
├── Libro Diario (Journal Ledger)
│   ├── Motor: aml
│   ├── Estructura: Por diario
│   ├── Período: Variable
│   ├── Status: ✓ NATIVO
│   └── Uso: Detalle por diario (caja, banco, etc)
│
├── Antigüedad Cobranzas (AR Aging)
│   ├── Motor: aml + date analysis
│   ├── Columnas: 30, 60, 90+ días
│   ├── Período: Variable
│   ├── Status: ✓ NATIVO
│   └── Uso: Análisis cobranza
│
├── Antigüedad Pagos (AP Aging)
│   ├── Motor: aml + date analysis
│   ├── Columnas: 30, 60, 90+ días
│   ├── Status: ✓ NATIVO
│   └── Uso: Análisis pagos
│
└── Flujo de Caja (Cash Flow)
    ├── Motor: aml + account.payment
    ├── Período: Variable
    ├── Estructura: Entradas | Salidas | Saldo
    ├── Status: ✓ NATIVO
    └── Uso: Proyección liquidez
```

---

## 3. CAMPOS DISPONIBLES PARA REPORTERÍA

### 3.1 Campos Clave - account.move

```
IDENTIFICACIÓN:
  name                          # Número documento (INV/2025/0001)
  dte_code                      # Código DTE (33, 52, 56, 61)
  dte_folio                     # Folio SII
  
FECHAS:
  date                          # Fecha contable
  invoice_date                  # Fecha emisión
  invoice_date_due              # Fecha vencimiento
  
MONTOS:
  amount_untaxed                # Subtotal sin impuestos
  amount_tax                    # Total impuestos
  amount_total                  # Total documento
  amount_by_group               # Desglose por grupo impuesto
  
PARTES:
  partner_id                    # Cliente/Proveedor
  partner_id.vat                # RUT cliente
  company_id                    # Empresa
  
CONTABILIDAD:
  journal_id                    # Diario
  line_ids                      # Líneas (account.move.line)
  
LOCALIZACIÓN CHILE:
  l10n_latam_document_type_id   # Tipo documento
  l10n_latam_use_documents      # Usar docs localización
  
DTE ESPECÍFICO:
  dte_status                    # Estado DTE (draft, sent, accepted)
  dte_xml                       # XML firmado
  dte_timestamp                 # Fecha envío SII
```

### 3.2 Campos Clave - account.move.line

```
CONTABILIDAD:
  account_id                    # Cuenta contable
  debit                         # Debe
  credit                        # Haber
  balance                       # Saldo (debit - credit)
  
PRODUCTOS/SERVICIOS:
  product_id                    # Producto
  name                          # Descripción
  quantity                      # Cantidad
  price_unit                    # Precio unitario
  
IMPUESTOS:
  tax_ids                       # Impuestos aplicados
  tax_tag_ids                   # Etiquetas impuesto (reportes)
  
ANALÍTICA:
  analytic_distribution         # Distribución analítica (costos)
```

### 3.3 Campos Clave - account.tax

```
IDENTIFICACIÓN:
  name                          # Nombre (IVA, Retención, etc)
  type_tax_use                  # sale, purchase, none
  
CONFIGURACIÓN:
  amount                        # % o monto
  amount_type                   # percent, fixed, group, division
  l10n_cl_sii_code             # Código SII (si existe)
  
REPORTERÍA:
  tax_group_id                  # Grupo impuesto (para reportes)
  tag_ids                       # Tags (para account.report)
  country_id                    # País (Chile)
```

---

## 4. MOTORES DE CÁLCULO DISPONIBLES

### 4.1 Motor: tax_tags (Etiquetas de Impuestos)

**Uso:** Reportes de impuestos

**Características:**
- Basado en etiquetas asignadas a impuestos
- Flexible: agrupa por tags
- Ejemplo: "Base Imponible Ventas", "IVA Débito"

**Implementación Chile:**
```xml
<!-- account_tax_report_data.xml (l10n_cl) -->
<record id="tax_report" model="account.report">
    <field name="engine">tax_tags</field>
    <field name="country_id" ref="base.cl"/>
</record>
```

### 4.2 Motor: aml (Account Move Line)

**Uso:** Reportes financieros (Balance, P&L, Ledger, etc)

**Características:**
- Basado en líneas de asientos (account.move.line)
- Detallado: acceso a cada línea
- Rápido: usa índices de base de datos

**Implementación:**
```python
# Acceso directo en reportes
moves = self.env['account.move'].search([...])
for move in moves:
    for line in move.line_ids:
        account = line.account_id
        debit = line.debit
```

### 4.3 Motor: custom (Fórmulas Personalizadas)

**Uso:** Reportes específicos del negocio

**Características:**
- Permite lógica personalizada
- Acceso a todas las APIs de Odoo
- Más flexible pero más complejo

**Implementación:**
```python
class CustomReport(models.AbstractModel):
    _name = 'report.custom.report_name'
    
    @api.model
    def _get_report_values(self, docids, data):
        # Lógica custom aquí
        return {'result': ...}
```

---

## 5. MATRIZ DE INTEGRACIÓN

### 5.1 Cómo los Modelos Generan Reportes

```
FLUJO DE DATOS:
┌─────────────────────────────────────────────────────────┐
│ USUARIO CREA FACTURA                                    │
│ (account.move, move_type=out_invoice)                   │
└────────┬────────────────────────────────────────────────┘
         │
         ├─→ CÁLCULO AUTOMÁTICO ODOO
         │   ├─ amount_untaxed (suma líneas)
         │   ├─ amount_tax (suma impuestos)
         │   ├─ amount_total (total)
         │   └─ amount_by_group (desglose)
         │
         ├─→ ETIQUETAS DE IMPUESTOS (tax_tags)
         │   ├─ "Base Imponible Ventas" (de tax.tag_ids)
         │   ├─ "IVA Débito Fiscal"
         │   └─ Otros tags según cuenta
         │
         ├─→ REPORTES AUTOMÁTICOS ACTUALIZAN
         │   ├─ Reporte de Impuestos (account.report)
         │   ├─ Balance General
         │   ├─ Estado de Resultados
         │   └─ Libro Mayor
         │
         └─→ EXPORTACIÓN DTE (NUESTRO MÓDULO)
             ├─ dte.status = "to_send"
             ├─ Genera XML según RES 80/2014 SII
             ├─ PDF con QWeb template
             └─ Incluye TED (PDF417 + QR)
```

### 5.2 Flujo DTE Específico (l10n_cl_dte)

```
FACTURA (account.move)
├─ Extensión DTE campos
│  ├─ dte_code
│  ├─ dte_folio
│  ├─ dte_status
│  ├─ dte_xml
│  └─ dte_timestamp
│
├─ GENERACIÓN PDF
│  ├─ Template: report_invoice_dte_document.xml
│  ├─ Motor: QWeb → wkhtmltopdf
│  ├─ Secciones:
│  │  ├─ Header (logo, tipo DTE, número)
│  │  ├─ Empresa y Cliente
│  │  ├─ Líneas del documento
│  │  ├─ Totales y desglose impuestos
│  │  └─ TED (Timbre Electrónico)
│  │
│  └─ Helpers (account_move_dte_report.py)
│     ├─ get_ted_pdf417() → Código de barras
│     ├─ get_ted_qrcode() → QR
│     ├─ format_vat() → Formatea RUT
│     └─ get_payment_term_lines() → Términos pago
│
└─ INTEGRACIÓN CON LIBROS
   ├─ dte.libro (monthly summary)
   ├─ Consumo de folios (DIN)
   └─ XML consolidado para SII
```

---

## 6. CHECKLIST DE REPORTES

### 6.1 Reportes Implementados

```
DOCUMENTOS DTE:
✓ DTE 33 - Factura Electrónica
✓ DTE 56 - Nota de Débito
✓ DTE 61 - Nota de Crédito
⚠ DTE 34 - Factura Exenta (EN DESARROLLO)
⚠ DTE 52 - Guía Despacho (PARCIAL)

LIBROS ELECTRÓNICOS:
✓ Libro de Venta
✓ Libro de Compra
✓ Libro de Guías (Despacho)
⚠ Consumo Folios (PARCIAL)

IMPUESTOS:
✓ Reporte Impuestos General (40+ líneas)
⚠ Retenciones IUE (PARCIAL)
⚠ Libro BHE (PARCIAL)
❌ Declaración Renta F22 (PENDIENTE)

FINANCIEROS (NATIVO ODOO):
✓ Balance General
✓ Estado de Resultados
✓ Libro Mayor
✓ Balance de Prueba
✓ Libro Diario
✓ Antigüedad Cobranzas
✓ Antigüedad Pagos
✓ Flujo de Caja
```

### 6.2 Próximas Prioridades

```
INMEDIATO (Esta semana):
- [ ] Completar DTE 34 (Factura Exenta)
- [ ] Testing XML vs XSD SII
- [ ] Integración DTE 52 con stock

PRÓXIMO SPRINT:
- [ ] Retenciones IUE completo
- [ ] Libro BHE validation
- [ ] Testing contra API SII

LARGO PLAZO:
- [ ] Declaración Renta F22
- [ ] Exportación Excel reportes
- [ ] Dashboards BI
```

---

## 7. REFERENCIAS RÁPIDAS

### 7.1 Rutas de Archivos

```
ODOO 19 CE BASE:
  /addons/account/                      # Módulo account
  └─ models/account_move.py
  └─ models/account_tax.py
  └─ views/account_report.xml
  └─ data/account_reports_data.xml

LOCALIZACIÓN CHILE:
  /addons/l10n_cl/                      # Localización oficial
  └─ data/account_tax_report_data.xml   # Reportes impuestos Chile
  └─ models/account_move.py             # Extensión para Chile

NUESTRO MÓDULO:
  /addons/localization/l10n_cl_dte/
  ├─ models/
  │  ├─ account_move_dte.py             # Extensión DTE
  │  ├─ dte_libro.py                    # Libro electrónico
  │  ├─ retencion_iue.py                # Retenciones IUE
  │  └─ l10n_cl_bhe_book.py             # Libro ingresos/egresos
  │
  ├─ report/
  │  ├─ report_invoice_dte_document.xml # Template factura
  │  └─ account_move_dte_report.py      # Helper class
  │
  └─ data/                              # Datos DTE
```

### 7.2 Documentación

```
COMPLETA (Este análisis):
  /docs/ANALISIS_MODULOS_CONTABLES_FINANCIEROS_COMPLETO.md
  
MATRIZ (Este documento):
  /docs/MATRIZ_REPORTES_FINANCIEROS_ODOO19_SII.md
  
OFICIAL ODOO:
  /docs/odoo19_official/02_models_base/account_manifest.py
  /docs/odoo19_official/02_models_base/account_move.py
  /docs/odoo19_official/02_models_base/account_tax.py
  /docs/odoo19_official/03_localization/l10n_cl/
```

---

**Documento Generado:** 2025-10-23  
**Nivel de Detalle:** Completo  
**Próxima Actualización:** Post-implementación sprints siguientes

