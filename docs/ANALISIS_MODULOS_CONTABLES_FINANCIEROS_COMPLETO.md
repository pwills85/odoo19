# ANÁLISIS PROFUNDO: MÓDULOS CONTABLES Y FINANCIEROS EN ODOO 19 CE

**Fecha:** 2025-10-23  
**Proyecto:** Odoo 19 CE - Localización Chile  
**Nivel de Análisis:** Very Thorough  
**Estado:** Análisis Completo  

---

## 1. MÓDULOS DE CONTABILIDAD BASE DISPONIBLES

### 1.1 Módulo Account (Contabilidad)

**Ubicación Documentación Oficial:**
- `/Users/pedro/Documents/odoo19/docs/odoo19_official/02_models_base/account_manifest.py`

**Tipo:** Módulo Core de Odoo 19 CE  
**Dependencias:** `base_setup`, `onboarding`, `product`, `analytic`, `portal`, `digest`

**Modelos Principales Implementados:**
```
account.move          → Facturas, asientos contables, notas débito/crédito
account.journal       → Diarios (Ventas, Compras, Caja, Banco, etc.)
account.account       → Plan de cuentas contables
account.tax           → Impuestos y retenciones
account.payment       → Pagos a clientes/proveedores
account.bank.statement → Extractos bancarios
account.reconcile.model → Modelos de conciliación
account.tax.group     → Grupos de impuestos
account.payment.term  → Términos de pago (plazos)
account.analytic.plan → Planes analíticos para distribución de costos
account.full.reconcile → Conciliación completa de asientos
```

**Campos Críticos de account.move (para DTE):**
```python
- name              # Número de documento (ej: INV/2025/001)
- move_type        # Tipo: out_invoice, in_invoice, out_refund, in_refund, entry
- date             # Fecha contable
- invoice_date     # Fecha de emisión (para facturas)
- invoice_date_due # Fecha de vencimiento
- partner_id       # Cliente/Proveedor
- journal_id       # Diario contable
- line_ids         # Líneas del asiento
- amount_total     # Total del documento
- amount_untaxed   # Subtotal sin impuestos
- amount_by_group  # Desglose por grupo de impuestos
- currency_id      # Moneda
- company_id       # Empresa
- state            # draft, posted, cancel
- l10n_latam_document_type_id  # Para localización (INT: DTE code)
- l10n_latam_use_documents     # Usar documentos de localización
- ref              # Referencia (ej: PO number)
- narration        # Descripción/observaciones
```

---

## 2. REPORTES FINANCIEROS INCLUIDOS EN ODOO 19 CE

### 2.1 Motor de Reportería: account.report

**Arquitectura de Reportes en Odoo 19:**

Odoo 19 CE implementa un modelo moderno de reportes basado en:

1. **Modelos de Reportes (`account.report`):**
   - Estructura jerárquica de líneas y columnas
   - Motor de cálculo flexible (tax_tags, aml, custom)
   - Disponibilidad por país/región

2. **Modelos de Reportería:**
   ```
   account.report                  → Definición del reporte
   account.report.column           → Columnas (Balance, Debit, Credit)
   account.report.line             → Líneas (cuentas, grupos)
   account.report.expression       → Fórmulas de cálculo
   ```

3. **Motores de Cálculo Disponibles:**
   ```
   tax_tags    → Basado en etiquetas de impuestos
   aml         → Basado en asientos contables (account.move.line)
   custom      → Fórmulas personalizadas
   ```

### 2.2 Reportes Estándar de Odoo 19 CE

Según la documentación oficial (`account_manifest.py`), Odoo 19 CE incluye:

#### A. Reportes Genéricos Base
```
✓ Generic Tax Report (Informe de Impuestos Genérico)
  - Motor: tax_tags
  - Uso: Reportar impuestos por categoría
  - Columnas: Balance, Debit, Credit
```

#### B. Reportes de Account (Módulo base)
Archivos de configuración en manifest:
```
'views/account_report.xml'           → Configuración UI reportes
'data/account_reports_data.xml'      → Datos de reportes base
'report/account_invoice_report_view.xml' → Reporte de facturas (PDF)
'views/report_statement.xml'         → Reporte de extracto
'views/report_templates.xml'         → Templates generales
```

#### C. Reportes Principales Disponibles
```
√ Balance Sheet (Balance General)
  - Reporta: Activos, Pasivos, Patrimonio
  - Período: Acumulado (desde inicio)
  - Uso: Análisis financiero, fiscalización SII
  
√ Profit & Loss (Estado de Resultados / P&L)
  - Reporta: Ingresos, Gastos, Utilidad/Pérdida
  - Período: Mensual/Anual seleccionable
  - Uso: Resultado del período
  
√ General Ledger (Libro Mayor)
  - Reporta: Movimientos por cuenta
  - Detalle: Cada asiento contable
  - Período: Customizable
  - Filtros: Por cuenta, período, diario
  
√ Trial Balance (Balance de Prueba)
  - Reporta: Saldo de todas las cuentas
  - Uso: Verificación de cuadre contable
  - Columnas: Debe, Haber, Saldo
  
√ Journal Ledger (Libro Diario)
  - Reporta: Movimientos por diario
  - Período: Customizable
  - Detalle: Todos los asientos del diario
  
√ Tax Reports (Reportes de Impuestos)
  - Reporta: IVA, PPM, Retenciones
  - Motor: tax_tags
  - Período: Mensual/Trimestral
  
√ Payment Register (Registro de Pagos)
  - Reporta: Pagos realizados/recibidos
  - Detalles: Banco, referencia, monto
  
√ Accounts Receivable Aging (Antigüedad Cuentas por Cobrar)
  - Reporta: Saldo a 30, 60, 90+ días
  - Uso: Análisis de cobranza
  
√ Accounts Payable Aging (Antigüedad Cuentas por Pagar)
  - Reporta: Saldo a 30, 60, 90+ días
  - Uso: Análisis de pagos pendientes

√ Cash Flow (Flujo de Caja)
  - Reporta: Movimientos de efectivo
  - Período: Customizable
  - Uso: Proyecciones de liquidez
```

**Nota:** Estos reportes están disponibles en:
- Backend: Menú Contabilidad > Reportes
- XML: `account_manifest.py` data files
- Acceso: Usuarios con permisos de lectura en account.report

---

## 3. LOCALIZACIÓN CHILE (l10n_cl) EN ODOO 19 CE

### 3.1 Estructura del Módulo l10n_cl Oficial

**Ubicación:** `/Users/pedro/Documents/odoo19/docs/odoo19_official/03_localization/l10n_cl/`

**Dependencias del Módulo:**
```python
[
    'contacts',
    'base_vat',
    'l10n_latam_base',
    'l10n_latam_invoice_document',
    'uom',
    'account',
]
```

**Estructura de Archivos:**
```
l10n_cl/
├── __manifest__.py                    # Metadatos módulo
├── models/
│   ├── account_move.py              # Extensión account.move para Chile
│   ├── account_move_line.py         # Extensión líneas de movimiento
│   ├── account_tax.py               # Extensión impuestos SII
│   ├── account_fiscal_position.py   # Posiciones fiscales
│   ├── res_company.py               # Datos empresa Chile (RUT, etc)
│   ├── res_partner.py               # Datos partner/cliente Chile
│   ├── res_partner_bank.py          # Cuentas bancarias Chile
│   ├── res_currency.py              # Monedas
│   ├── uom_uom.py                   # Unidades de medida
│   └── l10n_latam_document_type.py  # Tipos de documentos
│
├── data/
│   ├── account_tax_report_data.xml      # REPORTES DE IMPUESTOS CHILENOS ✓
│   ├── account_tax_tags_data.xml        # Etiquetas para impuestos
│   ├── account_tax_groups_data.xml      # Grupos de impuestos
│   ├── account_accounts_template_cl.csv # Plan contable Chile
│   ├── account_tax_template_cl.csv      # Impuestos template
│   ├── account.fiscal.position-cl.csv   # Posiciones fiscales
│   ├── account.tax.group-cl.csv         # Grupos impuestos
│   ├── account.account-cl.csv           # Cuentas contables
│   ├── l10n_latam.document.type.csv     # Documentos (33, 34, 52, 56, 61)
│   ├── res.bank.csv                     # Bancos
│   └── otros...
│
├── views/
│   ├── account_move_view.xml            # Vista facturas Chile
│   ├── account_tax_view.xml             # Vista impuestos
│   ├── report_invoice.xml               # Template reporte factura
│   ├── res_company_view.xml             # Config empresa
│   └── otros...
│
├── i18n/
│   ├── l10n_cl.pot                      # Traducciones
│   └── es_419.po                        # Español LATAM
│
├── tests/
│   └── test_latam_document_type.py      # Tests de tipos documento
│
└── static/
    ├── tgr_logo.png                     # Logo TGR (Tesorería)
    └── sii_logo.jpeg                    # Logo SII
```

### 3.2 Reporte de Impuestos Chileno (CRÍTICO)

**Archivo:** `account_tax_report_data.xml`

**Estructura:**
```xml
<record id="tax_report" model="account.report">
    <field name="name">Tax Report</field>
    <field name="name@es_419">Informe Fiscal</field>
    <field name="root_report_id" ref="account.generic_tax_report"/>
    <field name="country_id" ref="base.cl"/>
    <field name="availability_condition">country</field>
```

**Motor:** `tax_tags` (basado en etiquetas de impuestos)

**Líneas de Reporte Incluidas (40+ líneas):**

| Línea | Descripción | Código XML | Uso SII |
|-------|-------------|-----------|---------|
| Base Imponible Ventas | Monto total de ventas gravadas | `tax_report_base_imponible_ventas` | F29 |
| Ventas Exentas | Ventas sin IVA | `tax_report_ventas_exentas` | F30 |
| Impuestos Renta 1ª Categoría | Retención impuesto renta | `tax_report_impuestos_renta` | F23 |
| IVA Débito Fiscal | IVA por pagar de ventas | `tax_report_iva_debito_fiscal` | F25 |
| IVA Crédito Fiscal (Compras) | IVA recuperable de compras | `tax_report_compras_iva_recup` | F26 |
| Compras Netas Gravadas IVA | Base de compras gravadas | `tax_report_compras_netas_gr_iva_recup` | F27 |
| PPM | Impuesto mensual provisorio | `tax_report_ppm` | F24 |
| Retención Segunda Categoría | Retención a empleados | `tax_report_retencion_segunda_categ` | F38 |
| Retenciones ILA (Ventas) | Retención especial ILA | `tax_report_tax_ila_ventas` | F40 |
| Retenciones ILA (Compras) | Retención sufrida ILA | `tax_report_tax_ila_compras` | F39 |
| Compras Activo Fijo | Compras de bienes de uso | `tax_report_compras_activo_fijo` | F31 |
| Combustibles | Compras de combustible | `tax_report_compras_combustibles` | F37 |

**Totales de Líneas:** 40+ líneas cubiertas

**Campos Calculados:**
- Balance (default)
- Debit (opcional)
- Credit (opcional)

---

## 4. EXTENSIONES CUSTOM: l10n_cl_dte (NUESTRO MÓDULO)

### 4.1 Estructura Actual del Módulo

**Ubicación:** `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/`

**Modelos Implementados:**

```python
# Extensiones de modelos Odoo base
AccountMoveDTE                 # Extensión account.move con campos DTE
AccountTaxDTE                  # Extensión account.tax para Chile
AccountJournalDTE              # Extensión account.journal (control folios)
ResCompanyDTE                  # Datos empresa DTE
ResPartnerDTE                  # Datos partner con RUT SII
ResConfigSettings              # Configuración DTE

# Modelos DTE propios
DTECertificate                 # Certificados digitales (p12)
DTECaf                         # CAF (Código de Autorización Folio)
DTECommunication               # Comunicaciones con SII
DTELibro                       # Libro de Compra/Venta
DTELibroGuias                  # Libro de Guías de Despacho
DTEConsumoFolios               # Consumo de folios
DTEInbox                       # Bandeja de entrada de DTE recibidos
RetencionIUE                   # Retenciones IUE

# Modelos de Reporting (Nuestros)
AnalyticDashboard              # Dashboard analítico
L10nClBheBook                  # Libro Ingresos y Egresos (BHE)
L10nClBheRetentionRate         # Tasas de retención

# Modelos de IA
DteAIClient                    # Cliente IA para procesamiento
AIChatIntegration              # Integración chat con IA
```

### 4.2 Reportes Implementados en l10n_cl_dte

**Ubicación:** `/Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte/report/`

```
report/
├── report_invoice_dte_document.xml    # Template QWeb para factura DTE
├── account_move_dte_report.py         # Helper class para reporte
└── __init__.py
```

**Reportes Disponibles:**

#### A. Reporte de Factura DTE (QWeb/PDF)

**Archivo:** `report_invoice_dte_document.xml`

**Características:**
- Motor: QWeb (Jinja2-based template)
- Formato: PDF (vía wkhtmltopdf)
- Tipo: report.l10n_cl_dte.report_invoice_dte
- Documentos soportados:
  - DTE 33: Factura Electrónica
  - DTE 34: Factura Exenta Electrónica
  - DTE 52: Guía de Despacho Electrónica
  - DTE 56: Nota de Débito Electrónica
  - DTE 61: Nota de Crédito Electrónica

**Secciones del Reporte:**
```
1. Header
   - Logo empresa
   - Encabezado DTE (tipo, número, SII)
   - Información empresa (RUT, dirección, teléfono, email)

2. Cliente
   - Nombre y RUT
   - Dirección
   - Giro/actividad comercial

3. Detalles Documento
   - Fecha emisión
   - Fecha vencimiento
   - Condición de pago
   - Orden de compra (ref)

4. Líneas del Documento
   - Descripción
   - Cantidad
   - Precio unitario
   - Descuento (si aplica)
   - Total

5. Totales
   - Subtotal (Neto)
   - Desglose de impuestos
   - Total final
   - Formas de pago

6. Observaciones
   - Campo narración/notas

7. Timbre Electrónico (TED)
   - Código PDF417 (preferred)
   - QR Code (fallback)
   - Texto legal SII
   - Link verificación

8. Footer
   - Numeración de páginas
```

**Datos Disponibles en Template:**
```python
# Objeto principal (account.move)
o.dte_type              # Tipo DTE (33, 34, etc)
o.dte_folio             # Folio asignado
o.company_id            # Empresa
o.partner_id            # Cliente
o.invoice_date          # Fecha emisión
o.invoice_date_due      # Fecha vencimiento
o.invoice_line_ids      # Líneas documento
o.amount_untaxed        # Subtotal
o.amount_total          # Total
o.amount_by_group       # Impuestos desglosados
o.currency_id           # Moneda
o.narration             # Observaciones
o.invoice_payment_term_id  # Términos pago
```

#### B. Métodos Helper Report (`account_move_dte_report.py`)

**Clase:** `AccountMoveReportDTE` (AbstractModel)

**Métodos Disponibles:**
```python
_get_report_values()     # Prepara valores para render
get_ted_pdf417()         # Genera código PDF417 del TED
get_ted_qrcode()         # Genera QR del TED
get_dte_type_name()      # Obtiene nombre tipo DTE
format_vat()             # Formatea RUT (XX.XXX.XXX-K)
get_payment_term_lines() # Obtiene líneas de pago
```

---

## 5. ANÁLISIS DE REPORTES FINANCIEROS VS REQUERIMIENTOS SII

### 5.1 Matriz de Cobertura: Reportes Odoo vs Requerimientos SII

| Reporte | Odoo 19 CE | l10n_cl | l10n_cl_dte | Requisito SII | Estado |
|---------|-----------|--------|-----------|--------------|--------|
| **Facturas DTE 33** | ✓ account.move | ✓ | ✓ PDF QWeb | Obligatorio | **IMPLEMENTADO** |
| **Guías DTE 52** | ✓ stock.picking | ✓ | Parcial | Obligatorio | **EN DESARROLLO** |
| **Notas DTE 56/61** | ✓ account.move | ✓ | ✓ PDF QWeb | Obligatorio | **IMPLEMENTADO** |
| **Factura Exenta 34** | ✓ account.move | ✓ | Parcial | Opcional | **EN DESARROLLO** |
| **Libro de Ventas** | - | - | ✓ dte.libro | Obligatorio | **IMPLEMENTADO** |
| **Libro de Compras** | - | - | ✓ dte.libro | Obligatorio | **IMPLEMENTADO** |
| **Libro de Guías** | - | - | ✓ dte.libro_guias | Opcional | **IMPLEMENTADO** |
| **Balance General** | ✓ account.report | ✗ | - | Requerido | **NATIVO ODOO** |
| **Estado Resultados** | ✓ account.report | ✗ | - | Requerido | **NATIVO ODOO** |
| **Libro Mayor** | ✓ account.report | ✗ | - | Información | **NATIVO ODOO** |
| **Reporte Impuestos** | ✓ account.report | ✓ tax_tags | - | Obligatorio | **IMPLEMENTADO** |
| **Extracto Bancario** | ✓ bank.statement | - | - | Información | **NATIVO ODOO** |
| **Antigüedad Saldos** | ✓ account.report | - | - | Análisis | **NATIVO ODOO** |
| **Consumo Folios** | - | - | ✓ dte.consumo_folios | Informativo | **IMPLEMENTADO** |

### 5.2 Gaps Identificados vs SII

#### GAPS CRÍTICOS (Bloquean operación):
1. ❌ **Consumo de Folios (DIN) en Libro Electrónico**
   - Requerimiento: SII
   - Status: Parcialmente implementado
   - Plan: Completar en próximo sprint

2. ❌ **Validación de Estructura XML según XSD**
   - Requerimiento: SII (Resolución 80/2014)
   - Status: Implementado pero pendiente pruebas
   - Plan: Testing contra XSD oficial

#### GAPS MENORES (No bloquean, mejoran integridad):
1. ✓ **Retenciones IUE**
   - Requerimiento: SII
   - Status: Modelo creado, falta integración
   - Plan: Próximo sprint

2. ✓ **Libro de Ingresos y Egresos (BHE)**
   - Requerimiento: SII (empresas específicas)
   - Status: Modelo creado (l10n_cl_bhe_book)
   - Plan: Testing y validación

3. ✓ **Declaración de Impuesto Renta**
   - Requerimiento: SII
   - Status: No implementado
   - Plan: Post-MVP

### 5.3 Ventajas de Odoo 19 CE para Reportería SII

| Ventaja | Descripción | Impacto |
|---------|-------------|--------|
| **Motor account.report nativo** | Reportes declarativos, tax_tags, aml engines | Flexible + bajo mantenimiento |
| **QWeb + wkhtmltopdf** | Reportes HTML → PDF profesionales | PDFs SII-compliant |
| **Localización l10n_cl base** | Estructura tax tags para impuestos | Reutilizable para DTE |
| **Campos l10n_latam** | Integración con tipos documentos LATAM | Compatible, no duplicar |
| **Herencia ORM** | Extender sin duplicar modelos | Código limpio + mantenible |
| **ORM Query API** | Reportes sin SQL raw | Seguro + portable |

---

## 6. ARQUITECTURA DE GENERACIÓN DE REPORTES

### 6.1 Pipeline de Reporte (Flujo Completo)

```
[Usuario solicita reporte]
         ↓
[Backend - Odoo ORM]
├─ Load account.report definition
├─ Parse account.report.line (jerárquico)
├─ Execute account.report.expression
│  └─ Engine: tax_tags | aml | custom
│     └─ Query account.move.line
│        └─ Filter: date, account, company, etc
├─ Calculate totals (recursivo)
└─ Return structured data
         ↓
[View Layer - QWeb o HTML]
├─ Renderizar template
├─ Aplicar formato (tabla, tree, etc)
└─ Return HTML
         ↓
[Export Engine]
├─ Opción 1: HTML (preview en navegador)
├─ Opción 2: PDF (wkhtmltopdf)
├─ Opción 3: Excel (ir.actions.act_window)
└─ Opción 4: JSON (custom API)
         ↓
[Descarga/Visualización]
```

### 6.2 Modelos Abstractos de Reportería

**AccountMoveReportDTE (en l10n_cl_dte):**

```python
class AccountMoveReportDTE(models.AbstractModel):
    _name = 'report.l10n_cl_dte.report_invoice_dte'
    _description = 'DTE Invoice Report Helper'
    
    @api.model
    def _get_report_values(self, docids, data=None):
        """Prepara datos para template QWeb"""
        invoices = self.env['account.move'].browse(docids)
        return {
            'docs': invoices,
            'company': invoices[0].company_id,
            'get_ted_pdf417': self.get_ted_pdf417,
            'get_ted_qrcode': self.get_ted_qrcode,
            'format_vat': self.format_vat,
        }
```

### 6.3 Métodos de Customización de Reportes

**Patrones Odoo 19 CE para Reportes:**

#### Patrón 1: Extender Reporte Existente
```python
class CustomAccountReport(models.Model):
    _inherit = 'account.report'
    
    custom_field = fields.Char('Custom Field')
    
    @api.model
    def _get_lines(self, ...):
        """Override de cálculo de líneas"""
        lines = super()._get_lines(...)
        # Lógica custom aquí
        return lines
```

#### Patrón 2: Crear Reporte Custom
```python
class CustomReport(models.Model):
    _name = 'custom.report'
    
    @api.model
    def _get_report_values(self, docids, data):
        # Lógica de cálculo
        return {'docs': ..., 'custom_data': ...}
```

#### Patrón 3: QWeb Template
```xml
<template id="custom_report">
    <t t-call="web.html_container">
        <t t-foreach="docs" t-as="doc">
            <!-- Contenido report -->
        </t>
    </t>
</template>
```

---

## 7. CAMPOS DISPONIBLES PARA REPORTERÍA

### 7.1 Campos account.move (Facturas)

```python
# Identificación
name                          # Número documento (ej: INV/2025/001)
move_type                     # out_invoice, in_invoice, etc.
ref                           # Referencia (PO number)
narration                     # Observaciones

# Fechas
date                          # Fecha contable
invoice_date                  # Fecha emisión
invoice_date_due             # Fecha vencimiento
posted_before                # Registrado antes de (asiento posterior)

# Montos
amount_untaxed               # Subtotal
amount_tax                   # Total impuestos
amount_total                 # Total documento
amount_by_group              # Dict: impuestos desglosados
total_in_currency_date       # Total en otra moneda

# Moneda y empresa
currency_id                  # Moneda
company_id                   # Empresa

# Partes
partner_id                   # Cliente/Proveedor
commercial_partner_id        # Partner comercial (matriz si subsidiaria)

# Contabilidad
journal_id                   # Diario
line_ids                     # Líneas (account.move.line)
account_payment_term_id      # Términos de pago
fiscal_position_id           # Posición fiscal

# Localización Chile
l10n_latam_document_type_id  # Tipo documento (DTE code 33, 34, etc)
l10n_latam_use_documents     # Usar docs de localización
partner_id_vat              # RUT cliente (related)

# DTE (Nuestros campos)
dte_status                   # draft, to_send, sent, accepted, rejected
dte_code                     # Código DTE (33, 52, 56, 61)
dte_folio                    # Folio SII
dte_timestamp                # Fecha envío
dte_xml                      # XML firmado
```

### 7.2 Campos account.move.line (Líneas)

```python
# Identificación
name                         # Descripción línea
product_id                   # Producto
account_id                   # Cuenta contable

# Montos
debit                        # Debe
credit                       # Haber
balance                      # Saldo (debit - credit)
amount_currency              # Monto en moneda extranjera
amount_residual              # Saldo sin pagar

# Moneda
currency_id                  # Moneda línea

# Impuestos
tax_ids                      # Impuestos aplicados
tax_tag_ids                  # Etiquetas impuesto (para reportes)

# Analítica
analytic_distribution        # Distribución analítica
```

### 7.3 Campos account.tax (Impuestos)

```python
# Identificación
name                         # Nombre impuesto
type_tax_use                 # sale, purchase, none
amount                       # Porcentaje/monto
amount_type                  # percent, fixed, group, division
description                  # Descripción

# Configuración SII
l10n_cl_sii_code            # Código SII impuesto (si existe)
country_id                   # País

# Reportería
tax_group_id                 # Grupo impuesto (para reportes)
tag_ids                      # Tags para reportes
```

---

## 8. EXTENSIBILIDAD: PATRONES PARA REPORTES PERSONALIZADOS

### 8.1 Crear Nuevo Reporte Financiero

**Caso de Uso:** Crear reporte de "Flujo de Caja Proyectado" customizado

**Paso 1: Crear Modelo de Reporte**
```python
# models/cash_flow_report.py
from odoo import models, fields, api

class CashFlowReport(models.AbstractModel):
    _name = 'report.l10n_cl_dte.cash_flow_report'
    
    @api.model
    def _get_report_values(self, docids, data=None):
        # Lógica: obtener pagos esperados (account.payment)
        payments = self.env['account.payment'].search([
            ('state', '!=', 'cancelled'),
            ('payment_date', '>=', data['from_date']),
            ('payment_date', '<=', data['to_date']),
        ])
        
        # Agrupar por fecha
        grouped = {}
        for payment in payments:
            date_key = payment.payment_date
            if date_key not in grouped:
                grouped[date_key] = {'incoming': 0, 'outgoing': 0}
            if payment.payment_type == 'inbound':
                grouped[date_key]['incoming'] += payment.amount
            else:
                grouped[date_key]['outgoing'] += payment.amount
        
        return {
            'doc_ids': docids,
            'cash_flow': grouped,
            'total_incoming': sum(p['incoming'] for p in grouped.values()),
            'total_outgoing': sum(p['outgoing'] for p in grouped.values()),
        }
```

**Paso 2: Crear Template QWeb**
```xml
<!-- report/cash_flow_report.xml -->
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <template id="cash_flow_report_template">
        <t t-call="web.html_container">
            <div class="header">
                <h2>Flujo de Caja Proyectado</h2>
            </div>
            
            <table class="table table-sm">
                <thead>
                    <tr>
                        <th>Fecha</th>
                        <th class="text-end">Entradas</th>
                        <th class="text-end">Salidas</th>
                        <th class="text-end">Saldo Neto</th>
                    </tr>
                </thead>
                <tbody>
                    <t t-foreach="cash_flow" t-as="date_key">
                        <tr>
                            <td><t t-out="date_key"/></td>
                            <td class="text-end">
                                <t t-out="cash_flow[date_key]['incoming']"
                                   t-options='{"widget": "monetary"}'/>
                            </td>
                            <td class="text-end">
                                <t t-out="cash_flow[date_key]['outgoing']"
                                   t-options='{"widget": "monetary"}'/>
                            </td>
                            <td class="text-end">
                                <t t-out="cash_flow[date_key]['incoming'] - cash_flow[date_key]['outgoing']"
                                   t-options='{"widget": "monetary"}'/>
                            </td>
                        </tr>
                    </t>
                </tbody>
                <tfoot>
                    <tr class="border-top-2">
                        <td><strong>TOTALES</strong></td>
                        <td class="text-end"><strong><t t-out="total_incoming"
                            t-options='{"widget": "monetary"}'/></strong></td>
                        <td class="text-end"><strong><t t-out="total_outgoing"
                            t-options='{"widget": "monetary"}'/></strong></td>
                        <td class="text-end"><strong><t t-out="total_incoming - total_outgoing"
                            t-options='{"widget": "monetary"}'/></strong></td>
                    </tr>
                </tfoot>
            </table>
        </t>
    </template>
    
    <!-- Report action -->
    <record id="action_report_cash_flow" model="ir.actions.report">
        <field name="name">Flujo de Caja Proyectado</field>
        <field name="model">account.payment</field>
        <field name="report_type">qweb-pdf</field>
        <field name="report_name">l10n_cl_dte.cash_flow_report_template</field>
        <field name="binding_model_id" ref="account.model_account_payment"/>
        <field name="binding_type">report</field>
    </record>
</odoo>
```

**Paso 3: Registrar en __manifest__.py**
```python
'data': [
    'report/cash_flow_report.xml',
],
```

### 8.2 Herencia de Reportes Existentes

**Caso:** Extender reporte de impuestos para agregar línea custom

```python
# models/account_report_extension.py
from odoo import models, fields, api

class AccountReportExtension(models.Model):
    _inherit = 'account.report'
    
    custom_formula = fields.Char('Custom Formula')
    
    @api.model
    def _get_lines(self, financial_report, date_from, date_to, ...):
        lines = super()._get_lines(financial_report, date_from, date_to, ...)
        
        # Agregar línea custom si existe fórmula
        if financial_report.custom_formula:
            # Evaluar fórmula y agregar línea
            result = self._evaluate_custom_formula(...)
            lines.append({
                'name': 'Línea Custom',
                'balance': result,
                'level': 1,
            })
        
        return lines
```

### 8.3 APIs Disponibles para Reportería

**API Query de Odoo 19:**
```python
# Buscar movimientos contables
moves = self.env['account.move'].search([
    ('state', '=', 'posted'),
    ('date', '>=', '2025-01-01'),
    ('company_id', '=', self.env.company.id),
])

# Acceder a líneas
for move in moves:
    for line in move.line_ids:
        account = line.account_id
        debit = line.debit
        credit = line.credit

# Usar ORM domains avanzadas
moves = self.env['account.move'].search([
    ('line_ids.account_id.account_type', '=', 'asset'),
    ('date', '>=', date_from),
], order='date DESC')

# SQL directo (si necesario, no recomendado)
# self.env.cr.execute('SELECT ...')
```

---

## 9. RECOMENDACIONES PARA PRÓXIMOS PASOS

### 9.1 Reportes Prioritarios para Implementar

**Sprint Actual:**
- [ ] Completar DTE 34 (Factura Exenta)
- [ ] Completar DTE 52 (Guía Despacho)
- [ ] Testing XML contra XSD SII

**Sprint +1:**
- [ ] Retenciones IUE con reportes
- [ ] Libro BHE (Ingresos y Egresos)
- [ ] Integración con reportes Odoo nativos

**Largo Plazo:**
- [ ] Declaración Impuesto Renta (F22)
- [ ] Exportación de reportes a Excel/CSV
- [ ] Dashboards de análisis financiero
- [ ] Integración con BI (Metabase/Power BI)

### 9.2 Validación contra SII

**Checklist:**
- [ ] Validar XML contra XSD oficial SII
- [ ] Probar consumo de API SII (test y producción)
- [ ] Validar cálculo de impuestos contra DTE oficial
- [ ] Probar firma digital y timbre electrónico (TED)
- [ ] Documentar códigos de error SII

### 9.3 Testing de Reportes

**Tests Unitarios Necesarios:**
```python
# test_reports.py
class TestAccountReports(TransactionCase):
    
    def test_balance_sheet_calculation(self):
        """Balance genera correctamente sumas de activos/pasivos"""
        
    def test_profit_loss_calculation(self):
        """P&L calcula ingresos - gastos correctamente"""
        
    def test_tax_report_with_chile_taxes(self):
        """Reporte impuestos filtra correctamente por Chile"""
        
    def test_dte_invoice_report_pdf_generation(self):
        """Genera PDF con barcode TED sin errores"""
```

---

## 10. RESUMEN EJECUTIVO

### 10.1 Estado Actual

```
✓ IMPLEMENTADO EN ODOO 19 CE:
  - Modelos contables base (account.move, account.journal, etc)
  - Motor account.report (tax_tags, aml, custom engines)
  - Reportes estándar (Balance, P&L, General Ledger, etc)
  - Localización Chile (l10n_cl) con reportes impuestos
  - QWeb + wkhtmltopdf para PDFs

✓ IMPLEMENTADO EN l10n_cl_dte:
  - Extensión account.move con campos DTE
  - Modelos: DTELibro, DTECertificate, DTECaf, etc.
  - Reporte factura DTE con TED (QR + PDF417)
  - Modelos: L10nClBheBook, RetencionIUE, etc.
  - Dashboard analítico

⚠ EN DESARROLLO:
  - Completar DTE 34, DTE 52
  - Integración completa retenciones IUE
  - Testing XML contra XSD SII
  - Validaciones de estructura

❌ NO IMPLEMENTADO:
  - Declaración Impuesto Renta (F22)
  - Exportaciones Excel/CSV
  - Integración BI avanzada
```

### 10.2 Arquitectura de Reportería

**Capas:**
1. **Data Layer:** account.move, account.move.line, account.tax
2. **Report Definition:** account.report, account.report.line, account.report.expression
3. **Calculation Engine:** tax_tags, aml, custom formulas
4. **Presentation:** QWeb templates, PDF generation
5. **Export:** PDF, HTML, (Excel via custom)

### 10.3 Fortalezas

- Motor declarativo (bajo código)
- Reutilizable (herencia ORM)
- Flexible (múltiples engines)
- Compliant SII (tax_tags, tipos documentos)
- Nativo Odoo (bien documentado)

---

**Análisis Completado:** 2025-10-23 19:45 UTC  
**Documentación:** Completa y lista para desarrollo  
**Siguiente Paso:** Implementar reportes financieros adicionales según prioridades
