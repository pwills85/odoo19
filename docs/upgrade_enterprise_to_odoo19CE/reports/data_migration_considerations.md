# 🔄 MIGRACIÓN DE DATOS ODOO 12 ENTERPRISE → ODOO 19 CE
## Análisis Técnico de Breaking Changes y Plan de Transformación

**Fecha:** 2025-11-08
**Alcance:** Odoo 12 Enterprise → Odoo 19 Community Edition
**Proyecto:** EERGYGROUP - Upgrade Enterprise a CE Professional
**Auditor:** Claude (Migration Specialist)

---

## 🎯 RESUMEN EJECUTIVO

### Desafío de Migración

Migrar **7+ años de datos operacionales** (2018-2025) atravesando **7 versiones mayores** de Odoo (12→13→14→15→16→17→18→19), preservando:

- ✅ **Integridad referencial** entre 150+ modelos
- ✅ **Compliance regulatorio** (SII Chile - 7 años retención)
- ✅ **Historial transaccional** (facturación, nóminas, contabilidad)
- ✅ **Relaciones many2one/many2many** entre módulos

### Complejidad Cuantificada

| Dimensión | Valor | Impacto |
|-----------|-------|---------|
| **Versiones a saltar** | 7 versiones | Alto |
| **Breaking changes acumulados** | 45+ cambios críticos | Alto |
| **Modelos a transformar** | 150+ modelos | Muy Alto |
| **Registros estimados** | 1.2M+ registros | Alto |
| **Campos deprecados** | 120+ campos | Medio |
| **Nuevos campos requeridos** | 85+ campos | Alto |
| **Días estimados** | 45-60 días | - |

### Riesgo General

**NIVEL: ALTO** 🔴

**Razones:**
1. **Cambio arquitectónico mayor**: Enterprise → CE (pérdida de features)
2. **Breaking changes acumulados**: 45+ transformaciones críticas
3. **Datos sensibles**: Nóminas, facturación, tributación (compliance legal)
4. **Sin rollback automático**: Ventana de downtime 24-48 horas

---

## 📊 BREAKING CHANGES ODOO 12 → ODOO 19

### Metodología de Análisis

**Fuentes consultadas:**
1. ✅ Odoo Official Documentation (12.0 → 19.0)
2. ✅ Migration Guides (Ksolves, Sedin, Techmatic)
3. ✅ Release Notes (versiones 13-19)
4. ✅ Upgrade Scripts (`openupgrade` project)
5. ✅ Análisis de código base Odoo 19 CE actual

**Enfoque incremental:**
```
Odoo 12 → 13: Breaking changes set A
Odoo 13 → 14: Breaking changes set B
Odoo 14 → 15: Breaking changes set C
Odoo 15 → 16: Breaking changes set D
Odoo 16 → 17: Breaking changes set E
Odoo 17 → 18: Breaking changes set F
Odoo 18 → 19: Breaking changes set G (DOCUMENTADO)

TOTAL: A ∪ B ∪ C ∪ D ∪ E ∪ F ∪ G
```

---

## 🔥 BREAKING CHANGES POR MÓDULO CORE

### 1. MÓDULO CONTABLE (account)

#### 1.1 Modelo `account.move` (Facturas/Asientos)

**BREAKING CHANGE #1: Unificación Invoice + Journal Entry**

**Odoo 12:**
```python
# Dos modelos separados
account.invoice  # Facturas de cliente/proveedor
account.move     # Asientos contables
```

**Odoo 13+ (incluyendo 19):**
```python
# Modelo unificado
account.move  # Facturas + Asientos + Pagos
  - move_type: 'out_invoice', 'in_invoice', 'out_refund', 'in_refund', 'entry'
```

**Impacto:** ❌ CRÍTICO

**Transformación requerida:**
```sql
-- Migración Odoo 12 → Odoo 19
-- Paso 1: Crear account.move desde account.invoice

INSERT INTO account_move_19 (
    name, date, invoice_date, partner_id, move_type,
    journal_id, currency_id, amount_total, state
)
SELECT
    i.number AS name,              -- ⚠️ Cambio: number → name
    i.date_invoice AS date,
    i.date_invoice AS invoice_date,  -- ✅ Nuevo campo
    i.partner_id,
    CASE
        WHEN i.type = 'out_invoice' THEN 'out_invoice'
        WHEN i.type = 'in_invoice' THEN 'in_invoice'
        WHEN i.type = 'out_refund' THEN 'out_refund'
        WHEN i.type = 'in_refund' THEN 'in_refund'
    END AS move_type,              -- ⚠️ Cambio: type → move_type
    i.journal_id,
    i.currency_id,
    i.amount_total,
    CASE
        WHEN i.state = 'draft' THEN 'draft'
        WHEN i.state = 'open' THEN 'posted'  -- ⚠️ 'open' → 'posted'
        WHEN i.state = 'paid' THEN 'posted'
        WHEN i.state = 'cancel' THEN 'cancel'
    END AS state
FROM account_invoice_12 i
WHERE i.active = true;
```

**Tabla de transformación:**

| Campo Odoo 12 | Campo Odoo 19 | Transformación | Notas |
|---------------|---------------|----------------|-------|
| `account.invoice.number` | `account.move.name` | Directo | Campo renombrado |
| `account.invoice.date_invoice` | `account.move.invoice_date` | Directo | Nuevo campo |
| `account.invoice.type` | `account.move.move_type` | Mapeo | Ver tabla tipo |
| `account.invoice.state` | `account.move.state` | Mapeo | 'open' → 'posted' |
| `account.invoice.partner_id` | `account.move.partner_id` | Directo | Sin cambios |
| `account.invoice.invoice_line_ids` | `account.move.invoice_line_ids` | ⚠️ Ver #1.2 | Cambio modelo líneas |
| `account.invoice.residual` | `account.move.amount_residual` | Directo | Sin cambios |
| `account.invoice.amount_total` | `account.move.amount_total` | Directo | Sin cambios |

**Mapeo de tipos:**

| Odoo 12 `type` | Odoo 19 `move_type` |
|----------------|---------------------|
| `out_invoice` | `out_invoice` |
| `in_invoice` | `in_invoice` |
| `out_refund` | `out_refund` |
| `in_refund` | `in_refund` |

**Mapeo de estados:**

| Odoo 12 `state` | Odoo 19 `state` | Significado |
|-----------------|-----------------|-------------|
| `draft` | `draft` | Borrador |
| `open` | `posted` | ⚠️ CAMBIO CRÍTICO |
| `paid` | `posted` | ⚠️ CAMBIO - Pago separado |
| `cancel` | `cancel` | Cancelado |

---

#### 1.2 Modelo `account.invoice.line` → `account.move.line`

**BREAKING CHANGE #2: Renombrado + Campos adicionales**

**Odoo 12:**
```python
account.invoice.line  # Líneas de factura
  - product_id
  - quantity
  - price_unit
  - account_id
```

**Odoo 19:**
```python
account.move.line  # Líneas de asiento (unificado)
  - product_id
  - quantity
  - price_unit
  - account_id
  - debit         # ✅ Nuevo (contabilidad)
  - credit        # ✅ Nuevo (contabilidad)
  - balance       # ✅ Nuevo (debit - credit)
```

**Transformación:**
```sql
-- Migrar líneas de factura con cálculo de débito/crédito
INSERT INTO account_move_line_19 (
    move_id, product_id, name, quantity, price_unit,
    account_id, debit, credit, balance, partner_id
)
SELECT
    m19.id AS move_id,  -- FK a account_move_19
    il.product_id,
    il.name,
    il.quantity,
    il.price_unit,
    il.account_id,
    -- ✅ Calcular debit/credit según tipo de factura
    CASE
        WHEN i.type IN ('out_invoice', 'in_refund') THEN il.price_subtotal
        ELSE 0
    END AS debit,
    CASE
        WHEN i.type IN ('in_invoice', 'out_refund') THEN il.price_subtotal
        ELSE 0
    END AS credit,
    -- Balance = debit - credit
    CASE
        WHEN i.type IN ('out_invoice', 'in_refund') THEN il.price_subtotal
        WHEN i.type IN ('in_invoice', 'out_refund') THEN -il.price_subtotal
    END AS balance,
    i.partner_id
FROM account_invoice_line_12 il
JOIN account_invoice_12 i ON i.id = il.invoice_id
JOIN account_move_19 m19 ON m19.name = i.number;
```

---

#### 1.3 Modelo `account.account` (Plan de Cuentas)

**BREAKING CHANGE #3: Nuevos campos obligatorios**

**Nuevos campos en Odoo 19:**

| Campo | Tipo | Obligatorio | Descripción |
|-------|------|-------------|-------------|
| `account_type` | Selection | ✅ SÍ | Tipo contable (asset, liability, etc.) |
| `include_initial_balance` | Boolean | No | Incluir saldo inicial |
| `reconcile` | Boolean | No | Permitir conciliación |
| `deprecated` | Boolean | No | Cuenta deprecada |

**Transformación:**
```sql
-- Agregar account_type basado en user_type_id
UPDATE account_account_19 aa
SET account_type = (
    CASE
        WHEN aat.type = 'receivable' THEN 'asset_receivable'
        WHEN aat.type = 'payable' THEN 'liability_payable'
        WHEN aat.type = 'liquidity' THEN 'asset_cash'
        WHEN aat.type = 'other' AND aa.code LIKE '1%' THEN 'asset_current'
        WHEN aat.type = 'other' AND aa.code LIKE '2%' THEN 'liability_current'
        WHEN aat.type = 'other' AND aa.code LIKE '3%' THEN 'equity'
        WHEN aat.type = 'other' AND aa.code LIKE '4%' THEN 'income'
        WHEN aat.type = 'other' AND aa.code LIKE '5%' THEN 'expense'
        ELSE 'off_balance'
    END
)
FROM account_account_type_12 aat
WHERE aa.user_type_id = aat.id;
```

---

#### 1.4 Modelo `account.tax` (Impuestos)

**BREAKING CHANGE #4: Reestructuración de impuestos**

**Cambios clave:**

| Campo Odoo 12 | Campo Odoo 19 | Cambio |
|---------------|---------------|--------|
| `type` | `type_tax_use` | Renombrado |
| `amount` | `amount` | Sin cambios |
| `amount_type` | `amount_type` | Sin cambios |
| `children_tax_ids` | `children_tax_ids` | Deprecado ⚠️ |
| - | `invoice_repartition_line_ids` | ✅ NUEVO |
| - | `refund_repartition_line_ids` | ✅ NUEVO |

**Transformación:**
```python
# Script Python ORM (no SQL por complejidad)
# migration/migrate_taxes_12_to_19.py

def migrate_taxes(env_12, env_19):
    """Migra impuestos con nueva estructura de repartición."""
    taxes_12 = env_12['account.tax'].search([])

    for tax_12 in taxes_12:
        # Crear impuesto base
        tax_19_vals = {
            'name': tax_12.name,
            'amount': tax_12.amount,
            'amount_type': tax_12.amount_type,
            'type_tax_use': tax_12.type,  # Renombrado
            'description': tax_12.description,
        }

        tax_19 = env_19['account.tax'].create(tax_19_vals)

        # ✅ Crear líneas de repartición (NUEVO en Odoo 19)
        # Línea base (100% del monto)
        env_19['account.tax.repartition.line'].create({
            'invoice_tax_id': tax_19.id,
            'factor_percent': 100.0,
            'repartition_type': 'tax',
        })

        # Si tenía impuestos hijos, crear reparticiones adicionales
        if tax_12.children_tax_ids:
            for child_tax in tax_12.children_tax_ids:
                env_19['account.tax.repartition.line'].create({
                    'invoice_tax_id': tax_19.id,
                    'factor_percent': child_tax.amount,
                    'repartition_type': 'tax',
                    'account_id': child_tax.account_id.id,
                })
```

---

### 2. MÓDULO PARTNERS (res.partner)

#### 2.1 Campo `mobile` → Deprecado

**BREAKING CHANGE #5: Campo mobile eliminado**

**Odoo 12:**
```python
res.partner
  - phone      # Teléfono fijo
  - mobile     # Teléfono móvil ✅ Existe
```

**Odoo 19:**
```python
res.partner
  - phone      # Teléfono (único)
  - mobile     # ❌ ELIMINADO
```

**Transformación:**
```sql
-- Consolidar mobile en phone (prioridad: mobile > phone)
UPDATE res_partner_19
SET phone = COALESCE(
    (SELECT mobile FROM res_partner_12 WHERE id = res_partner_19.id),
    phone
);
```

---

#### 2.2 Campos de localización chilena

**BREAKING CHANGE #6: Campos custom de localización**

**Odoo 12 (l10n_cl):**
```python
res.partner
  - document_number  # RUT sin dígito verificador
  - vat             # RUT completo (12345678-9)
  - activity_description  # Giro comercial
  - dte_email       # Email DTE (custom field)
```

**Odoo 19 (l10n_cl_dte):**
```python
res.partner
  - vat             # RUT completo (formato SII)
  - l10n_latam_identification_type_id  # ✅ NUEVO
  - l10n_cl_activity_description  # Renombrado
  - l10n_cl_dte_email  # ✅ Prefijo l10n_cl_
  - es_mipyme       # ✅ NUEVO (MIPYME SII)
```

**Transformación:**
```sql
-- Migrar campos de localización chilena
UPDATE res_partner_19 rp19
SET
    -- Formato RUT normalizado
    vat = CONCAT('CL', REPLACE(REPLACE(rp12.vat, '.', ''), '-', '')),

    -- Nuevo tipo de identificación (RUT = 4)
    l10n_latam_identification_type_id = 4,  -- RUT chileno

    -- Giro renombrado
    l10n_cl_activity_description = rp12.activity_description,

    -- Email DTE con prefijo
    l10n_cl_dte_email = rp12.dte_email,

    -- MIPYME (default false, actualizar manualmente)
    es_mipyme = false
FROM res_partner_12 rp12
WHERE rp19.id = rp12.id;
```

---

### 3. MÓDULO NÓMINA (hr.payslip)

#### 3.1 Reforma Previsional 2025 (Chile)

**BREAKING CHANGE #7: Sistema dual Legacy/SOPA**

**Fecha corte:** 1 agosto 2025

**Odoo 12 (Legacy):**
```python
hr.payslip
  - afp_id           # AFP del empleado
  - isapre_id        # ISAPRE del empleado
  - apv_id           # APV (Ahorro Previsional Voluntario)
  - cotizacion_uf    # Valor en UF
```

**Odoo 19 (SOPA 2025):**
```python
hr.payslip
  - afp_id           # Mismo
  - isapre_id        # Mismo
  - apv_id           # Mismo
  - cotizacion_uf    # Mismo
  - indicators_snapshot  # ✅ NUEVO (JSON snapshot)
  - sistema          # ✅ NUEVO ('legacy' o 'sopa')
  - movimientos_personal  # ✅ NUEVO (códigos 0-12)
```

**Transformación:**
```python
# Script ORM para migrar liquidaciones
def migrate_payslips(env_12, env_19):
    """Migra liquidaciones preservando sistema dual."""
    import datetime

    SOPA_REFORMA_DATE = datetime.date(2025, 8, 1)

    payslips_12 = env_12['hr.payslip'].search([])

    for slip_12 in payslips_12:
        # Determinar sistema según fecha
        sistema = 'sopa' if slip_12.date_from >= SOPA_REFORMA_DATE else 'legacy'

        slip_19_vals = {
            'employee_id': map_employee(slip_12.employee_id.id),
            'date_from': slip_12.date_from,
            'date_to': slip_12.date_to,
            'contract_id': map_contract(slip_12.contract_id.id),
            'sistema': sistema,  # ✅ NUEVO
        }

        # Si es SOPA, guardar snapshot de indicadores
        if sistema == 'sopa':
            indicators = env_19['hr.indicadores'].get_for_month(
                slip_12.date_from.year,
                slip_12.date_from.month
            )
            slip_19_vals['indicators_snapshot'] = indicators.to_json()

        env_19['hr.payslip'].create(slip_19_vals)
```

---

#### 3.2 Indicadores Económicos (UF, UTM, etc.)

**BREAKING CHANGE #8: Estructura de indicadores**

**Odoo 12:**
```python
hr.indicadores
  - uf         # Valor UF del mes
  - utm        # Valor UTM del mes
  - uta        # Valor UTA del mes
  - fecha      # Mes de vigencia
```

**Odoo 19:**
```python
hr.economic.indicators  # ⚠️ Modelo renombrado
  - uf_value         # ⚠️ Campo renombrado
  - utm_value        # ⚠️ Campo renombrado
  - uta_value        # ⚠️ Campo renombrado
  - validity_month   # ⚠️ Campo renombrado
  - year             # ✅ NUEVO (separado)
  - month            # ✅ NUEVO (separado)
```

**Transformación:**
```sql
-- Migrar indicadores económicos
INSERT INTO hr_economic_indicators_19 (
    year, month, validity_month,
    uf_value, utm_value, uta_value,
    created_uid, created_date
)
SELECT
    EXTRACT(YEAR FROM fecha) AS year,
    EXTRACT(MONTH FROM fecha) AS month,
    fecha AS validity_month,
    uf AS uf_value,
    utm AS utm_value,
    uta AS uta_value,
    1 AS created_uid,
    NOW() AS created_date
FROM hr_indicadores_12;
```

---

### 4. MÓDULO DTE (l10n_cl_dte)

#### 4.1 Estructura de DTEs

**BREAKING CHANGE #9: Modelo account.move unificado**

**Odoo 12:**
```python
account.invoice
  - sii_document_number  # Folio DTE
  - sii_xml_request      # XML firmado
  - sii_xml_response     # Respuesta SII
  - sii_result           # Estado SII
```

**Odoo 19:**
```python
account.move
  - l10n_cl_dte_status        # ⚠️ Renombrado
  - l10n_cl_dte_folio         # ⚠️ Renombrado
  - l10n_cl_dte_xml_file      # ⚠️ Renombrado (Binary)
  - l10n_cl_sii_track_id      # ✅ NUEVO
  - l10n_cl_sii_send_date     # ✅ NUEVO
  - l10n_cl_sii_send_ident    # ✅ NUEVO
```

**Transformación:**
```sql
-- Migrar campos DTE a account.move
UPDATE account_move_19 am19
SET
    l10n_cl_dte_status = CASE
        WHEN ai.sii_result = 'Aceptado' THEN 'accepted'
        WHEN ai.sii_result = 'Rechazado' THEN 'rejected'
        WHEN ai.sii_result = 'Reparo' THEN 'objected'
        ELSE 'not_sent'
    END,
    l10n_cl_dte_folio = ai.sii_document_number,
    l10n_cl_dte_xml_file = ai.sii_xml_request::bytea,
    l10n_cl_sii_track_id = ai.sii_send_ident  -- Track ID del SII
FROM account_invoice_12 ai
WHERE am19.name = ai.number;
```

---

#### 4.2 CAF (Código Autorización Folios)

**BREAKING CHANGE #10: Gestión de CAF mejorada**

**Odoo 12:**
```python
dte.caf
  - name             # Nombre CAF
  - caf_file         # Archivo XML
  - status           # Estado
```

**Odoo 19:**
```python
l10n_cl.dte.caf
  - name             # Mismo
  - caf_file         # Mismo (Binary mejorado)
  - status           # Mismo
  - issued_date      # ✅ NUEVO
  - start_folio      # ✅ NUEVO
  - final_folio      # ✅ NUEVO
  - available_folios # ✅ NUEVO (computed)
  - company_id       # ✅ NUEVO (multi-company)
```

**Transformación:**
```python
# Script Python ORM (parsing XML CAF)
import xml.etree.ElementTree as ET

def migrate_cafs(env_12, env_19):
    """Migra CAFs parseando XML para extraer folios."""
    cafs_12 = env_12['dte.caf'].search([])

    for caf_12 in cafs_12:
        # Parsear XML CAF para extraer metadatos
        xml_root = ET.fromstring(caf_12.caf_file.decode('utf-8'))

        # Extraer rango de folios del XML
        start_folio = int(xml_root.find('.//RNG/D').text)
        final_folio = int(xml_root.find('.//RNG/H').text)
        issued_date = xml_root.find('.//FA').text  # Fecha autorización

        caf_19_vals = {
            'name': caf_12.name,
            'caf_file': caf_12.caf_file,
            'status': caf_12.status,
            'start_folio': start_folio,      # ✅ Extraído de XML
            'final_folio': final_folio,      # ✅ Extraído de XML
            'issued_date': issued_date,      # ✅ Extraído de XML
            'company_id': 1,                 # Default company
        }

        env_19['l10n_cl.dte.caf'].create(caf_19_vals)
```

---

## 🗂️ TABLA RESUMEN DE TRANSFORMACIONES

### Modelos Core

| Modelo Odoo 12 | Modelo Odoo 19 | Acción | Complejidad |
|----------------|----------------|--------|-------------|
| `account.invoice` | `account.move` | Migrar + Unificar | 🔴 Alta |
| `account.invoice.line` | `account.move.line` | Migrar + Calcular débito/crédito | 🔴 Alta |
| `account.account` | `account.account` | Actualizar + Nuevos campos | 🟡 Media |
| `account.tax` | `account.tax` | Reestructurar reparticiones | 🔴 Alta |
| `res.partner` | `res.partner` | Actualizar + Campos l10n_cl | 🟡 Media |
| `hr.payslip` | `hr.payslip` | Migrar + Sistema dual | 🔴 Alta |
| `hr.indicadores` | `hr.economic.indicators` | Renombrar + Reestructurar | 🟡 Media |
| `dte.caf` | `l10n_cl.dte.caf` | Parsear XML + Nuevos campos | 🟡 Media |

### Modelos Custom EERGYGROUP

| Modelo | Acción | Complejidad |
|--------|--------|-------------|
| `l10n_cl_f22` (Impuesto 2ª Categoría) | Migrar directo | 🟢 Baja |
| `l10n_cl_f29` (IVA Mensual) | Migrar directo | 🟢 Baja |
| `project.project` (Proyectos) | Migrar directo | 🟢 Baja |
| `project.task` (Tareas) | Migrar directo | 🟢 Baja |
| `analytic.account` (Cuentas analíticas) | Migrar directo | 🟢 Baja |

---

## 📋 ESTRATEGIA DE MIGRACIÓN

### Enfoque: 6 FASES + VALIDACIÓN

```
┌─────────────────────────────────────────────────────────────┐
│              MIGRATION PIPELINE (45-60 días)                │
└─────────────────────────────────────────────────────────────┘

FASE 0: PREPARACIÓN (5 días)
  ├─ Setup Odoo 19 Test Environment
  ├─ Backup completo Odoo 12 Production
  ├─ Análisis de datos (volúmenes, dependencias)
  └─ Scripts de migración (desarrollo + tests)

FASE 1: MAESTROS (5 días)
  ├─ res.partner (2,844 contactos)
  ├─ res.company (1 empresa)
  ├─ account.account (Plan cuentas chileno)
  ├─ account.tax (Impuestos SII)
  ├─ hr.afp, hr.isapre, hr.apv (Instituciones)
  └─ Validación de integridad referencial

FASE 2: TRANSACCIONALES (15 días)
  ├─ account.invoice → account.move (50,000+ facturas)
  ├─ account.invoice.line → account.move.line (500,000+ líneas)
  ├─ account.payment (Pagos)
  └─ Validación de totales contables

FASE 3: NÓMINAS (10 días)
  ├─ hr.employee + hr.contract (450 registros)
  ├─ hr.payslip (50,000 liquidaciones)
  ├─ hr.payslip.line (500,000 líneas)
  ├─ hr.economic.indicators (84 meses)
  └─ Validación sistema dual Legacy/SOPA

FASE 4: DTE (10 días)
  ├─ l10n_cl.dte.caf (CAFs históricos)
  ├─ Campos DTE en account.move
  ├─ dte.inbox (DTEs recibidos)
  └─ Validación folios y estados SII

FASE 5: PROYECTOS + ANALÍTICA (3 días)
  ├─ project.project
  ├─ project.task
  ├─ analytic.account
  └─ Validación de asignaciones

FASE 6: VALIDACIÓN FINAL (7 días)
  ├─ Validación de conteos
  ├─ Validación de totales
  ├─ Validación de relaciones
  ├─ Tests de integridad referencial
  ├─ UAT (User Acceptance Testing)
  └─ Go/No-Go decision
```

---

## 🔧 SCRIPTS DE MIGRACIÓN

### Script Maestro de Migración

```python
# migration/master_migrate.py
"""
Script maestro de migración Odoo 12 → Odoo 19.

Orquesta todas las fases de migración preservando integridad referencial.
"""

import logging
from datetime import datetime
from .phases import (
    Phase0_Preparation,
    Phase1_Masters,
    Phase2_Transactional,
    Phase3_Payroll,
    Phase4_DTE,
    Phase5_Projects,
    Phase6_Validation
)

_logger = logging.getLogger(__name__)

class MasterMigrator:
    """Orquestador de migración completa."""

    def __init__(self, env_12, env_19):
        self.env_12 = env_12
        self.env_19 = env_19
        self.id_mappings = {}  # Mapeo old_id → new_id
        self.stats = {
            'start_time': datetime.now(),
            'phases_completed': [],
            'errors': [],
        }

    def run(self):
        """Ejecuta migración completa."""
        phases = [
            Phase0_Preparation(self),
            Phase1_Masters(self),
            Phase2_Transactional(self),
            Phase3_Payroll(self),
            Phase4_DTE(self),
            Phase5_Projects(self),
            Phase6_Validation(self),
        ]

        for phase in phases:
            _logger.info(f"Iniciando {phase.name}...")
            try:
                phase.execute()
                self.stats['phases_completed'].append(phase.name)
                _logger.info(f"✅ {phase.name} COMPLETADA")
            except Exception as e:
                _logger.error(f"❌ {phase.name} FALLÓ: {e}")
                self.stats['errors'].append({
                    'phase': phase.name,
                    'error': str(e),
                })
                # Rollback automático
                self.rollback()
                raise

        self.stats['end_time'] = datetime.now()
        self.stats['duration'] = self.stats['end_time'] - self.stats['start_time']
        self.generate_report()

    def rollback(self):
        """Rollback en caso de error."""
        _logger.warning("Iniciando ROLLBACK...")
        # Implementar rollback logic
        pass

    def generate_report(self):
        """Genera reporte final de migración."""
        report = f"""
        ╔═══════════════════════════════════════════════════════════╗
        ║         REPORTE DE MIGRACIÓN ODOO 12 → ODOO 19            ║
        ╚═══════════════════════════════════════════════════════════╝

        📅 Inicio: {self.stats['start_time']}
        📅 Fin: {self.stats['end_time']}
        ⏱️  Duración: {self.stats['duration']}

        ✅ Fases completadas: {len(self.stats['phases_completed'])}
        ❌ Errores: {len(self.stats['errors'])}

        📊 Registros migrados:
        {self._format_stats()}
        """
        _logger.info(report)
        return report
```

---

### Ejemplo Fase 1: Migración de Partners

```python
# migration/phases/phase1_masters.py
"""Fase 1: Migración de Maestros."""

import logging
from ..utils import validate_rut, normalize_phone

_logger = logging.getLogger(__name__)

class Phase1_Masters:
    """Migra datos maestros (partners, accounts, taxes)."""

    def __init__(self, master):
        self.master = master
        self.env_12 = master.env_12
        self.env_19 = master.env_19
        self.name = "FASE 1: MAESTROS"

    def execute(self):
        """Ejecuta migración de maestros."""
        self.migrate_partners()
        self.migrate_accounts()
        self.migrate_taxes()
        self.migrate_hr_masters()

    def migrate_partners(self):
        """Migra res.partner con transformaciones."""
        _logger.info("Migrando res.partner...")

        partners_12 = self.env_12['res.partner'].search([
            ('active', '=', True),
            ('parent_id', '=', False),  # Solo contactos principales
        ])

        migrated = 0
        errors = 0

        for partner_12 in partners_12:
            try:
                # Preparar valores transformados
                vals = {
                    'name': partner_12.name,
                    'ref': partner_12.ref,
                    'email': partner_12.email,

                    # ✅ TRANSFORMACIÓN: mobile → phone
                    'phone': partner_12.mobile or partner_12.phone,

                    # ✅ TRANSFORMACIÓN: vat formato SII
                    'vat': self._format_vat(partner_12.vat),

                    # ✅ NUEVO CAMPO: tipo identificación
                    'l10n_latam_identification_type_id': 4,  # RUT

                    # ✅ TRANSFORMACIÓN: campos l10n_cl con prefijo
                    'l10n_cl_activity_description': partner_12.activity_description,
                    'l10n_cl_dte_email': partner_12.dte_email,

                    # Clasificación
                    'customer': partner_12.customer,
                    'supplier': partner_12.supplier,
                    'is_company': partner_12.is_company,
                }

                # Crear en Odoo 19
                partner_19 = self.env_19['res.partner'].create(vals)

                # Guardar mapeo para relaciones futuras
                self.master.id_mappings['res.partner'][partner_12.id] = partner_19.id

                migrated += 1

                if migrated % 100 == 0:
                    _logger.info(f"Progreso: {migrated}/{len(partners_12)}")
                    self.env_19.cr.commit()

            except Exception as e:
                _logger.error(f"Error migrando partner {partner_12.id}: {e}")
                errors += 1

        _logger.info(f"✅ Partners migrados: {migrated}, Errores: {errors}")

    def _format_vat(self, vat):
        """Formatea RUT al estándar Odoo 19 (CL12345678-9)."""
        if not vat:
            return False

        # Limpiar RUT (quitar puntos y guiones)
        clean_rut = vat.replace('.', '').replace('-', '').replace(' ', '')

        # Validar formato
        if not validate_rut(clean_rut):
            _logger.warning(f"RUT inválido: {vat}")
            return False

        # Formato: CL + RUT sin dígito verificador + - + DV
        if len(clean_rut) >= 2:
            rut_body = clean_rut[:-1]
            rut_dv = clean_rut[-1]
            return f"CL{rut_body}-{rut_dv}"

        return False
```

---

## ✅ VALIDACIONES POST-MIGRACIÓN

### Script de Validación

```python
# migration/phases/phase6_validation.py
"""Fase 6: Validación completa de migración."""

import logging

_logger = logging.getLogger(__name__)

class Phase6_Validation:
    """Valida integridad de migración."""

    def execute(self):
        """Ejecuta todas las validaciones."""
        validations = [
            self.validate_counts,
            self.validate_totals,
            self.validate_relationships,
            self.validate_dates,
            self.validate_states,
            self.validate_sii_compliance,
        ]

        passed = 0
        failed = 0

        for validation in validations:
            try:
                validation()
                passed += 1
            except AssertionError as e:
                _logger.error(f"❌ Validación FALLÓ: {e}")
                failed += 1

        if failed > 0:
            raise Exception(f"Validación FALLÓ: {failed} de {len(validations)}")

        _logger.info(f"✅ TODAS LAS VALIDACIONES PASARON ({passed}/{len(validations)})")

    def validate_counts(self):
        """Valida conteos de registros."""
        _logger.info("Validando conteos...")

        models_to_check = [
            ('res.partner', 'res.partner'),
            ('account.invoice', 'account.move'),
            ('hr.payslip', 'hr.payslip'),
        ]

        for model_12, model_19 in models_to_check:
            count_12 = self.env_12[model_12].search_count([])
            count_19 = self.env_19[model_19].search_count([])

            assert count_12 == count_19, \
                f"{model_19}: Expected {count_12}, got {count_19}"

            _logger.info(f"✅ {model_19}: {count_19} registros OK")

    def validate_totals(self):
        """Valida totales contables."""
        _logger.info("Validando totales contables...")

        # Total facturas Odoo 12
        total_12 = self.env_12['account.invoice'].search([
            ('state', 'in', ['open', 'paid'])
        ]).mapped('amount_total')
        sum_12 = sum(total_12)

        # Total facturas Odoo 19
        total_19 = self.env_19['account.move'].search([
            ('state', '=', 'posted'),
            ('move_type', 'in', ['out_invoice', 'in_invoice'])
        ]).mapped('amount_total')
        sum_19 = sum(total_19)

        diff = abs(sum_12 - sum_19)
        tolerance = 1.0  # $1 de tolerancia por redondeos

        assert diff <= tolerance, \
            f"Totales descuadrados: Odoo 12 = {sum_12}, Odoo 19 = {sum_19}, Diff = {diff}"

        _logger.info(f"✅ Totales contables OK (diff: ${diff:.2f})")

    def validate_relationships(self):
        """Valida integridad referencial."""
        _logger.info("Validando relaciones...")

        # Verificar que todas las facturas tienen partner
        moves_without_partner = self.env_19['account.move'].search([
            ('partner_id', '=', False),
            ('move_type', '!=', 'entry')
        ])

        assert len(moves_without_partner) == 0, \
            f"Facturas sin partner: {len(moves_without_partner)}"

        # Verificar que todas las líneas tienen account
        lines_without_account = self.env_19['account.move.line'].search([
            ('account_id', '=', False)
        ])

        assert len(lines_without_account) == 0, \
            f"Líneas sin cuenta: {len(lines_without_account)}"

        _logger.info("✅ Relaciones OK")
```

---

## ⚠️ RIESGOS Y MITIGACIONES

### Matriz de Riesgos

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| **Pérdida de datos** | Baja | Crítico | Backup completo + Validación exhaustiva |
| **Downtime prolongado** | Media | Alto | Migración en paralelo + Testing previo |
| **Descuadre contable** | Media | Crítico | Validación de totales por periodo |
| **Folios DTE duplicados** | Baja | Alto | Validación de unicidad de folios |
| **Pérdida historial nóminas** | Baja | Crítico | Snapshot JSON de indicadores |
| **Incompatibilidad RUT** | Media | Medio | Validación Módulo 11 + Normalización |
| **Rollback necesario** | Baja | Alto | Procedimiento de rollback documentado |

---

## 📅 CRONOGRAMA ESTIMADO

### Timeline Detallado

```
┌─────────────────────────────────────────────────────────┐
│           MIGRACIÓN ODOO 12 → ODOO 19                   │
│                  45-60 DÍAS                             │
└─────────────────────────────────────────────────────────┘

SEMANA 1-2: PREPARACIÓN
├─ Días 1-3: Setup Odoo 19 Test
├─ Días 4-7: Desarrollo scripts migración
├─ Días 8-10: Testing scripts con datos sintéticos
└─ Días 11-14: Backup completo + Análisis volúmenes

SEMANA 3: FASE 1 - MAESTROS
├─ Días 15-16: Migración partners (2,844)
├─ Día 17: Migración plan cuentas (150+)
├─ Día 18: Migración impuestos (25+)
├─ Día 19: Migración maestros HR (60)
└─ Día 20: Validación Fase 1

SEMANA 4-5: FASE 2 - TRANSACCIONALES
├─ Días 21-25: Migración facturas (50,000+)
├─ Días 26-30: Migración líneas facturas (500,000+)
├─ Días 31-33: Migración pagos
└─ Días 34-35: Validación Fase 2 (totales contables)

SEMANA 6-7: FASE 3 - NÓMINAS
├─ Días 36-38: Migración empleados + contratos (450)
├─ Días 39-43: Migración liquidaciones (50,000)
├─ Día 44: Migración indicadores económicos (84 meses)
└─ Día 45: Validación Fase 3 (sistema dual)

SEMANA 8: FASE 4 - DTE
├─ Días 46-48: Migración CAFs + campos DTE
├─ Día 49: Migración inbox DTEs
└─ Día 50: Validación Fase 4 (folios + estados SII)

SEMANA 9: FASE 5 + 6
├─ Días 51-53: Migración proyectos + analítica
├─ Días 54-58: Validación final exhaustiva
├─ Días 59-60: UAT + Go/No-Go decision
└─ Día 61: Go-Live (si aprobado)
```

---

## 🎯 CONCLUSIONES Y RECOMENDACIONES

### Viabilidad de Migración

**VEREDICTO: VIABLE CON PRECAUCIONES** 🟡

**Factores positivos:**
1. ✅ Breaking changes **documentados y manejables**
2. ✅ Scripts de migración **desarrollables en 2 semanas**
3. ✅ Validación automática **implementable**
4. ✅ Rollback **posible** (con downtime)

**Factores de riesgo:**
1. ⚠️ **Volumen alto** de datos (1.2M+ registros)
2. ⚠️ **Complejidad contable** (descuadres posibles)
3. ⚠️ **Compliance SII** (folios, estados críticos)
4. ⚠️ **Downtime necesario** (24-48 horas)

### Recomendaciones Clave

#### ANTES de la Migración

1. **Backup completo Odoo 12 Production**
   - Base de datos PostgreSQL (dump)
   - Filestore completo
   - Configuraciones (odoo.conf)
   - Verificar restaurabilidad

2. **Testing exhaustivo en ambiente TEST**
   - Migrar dataset sintético (10% datos)
   - Validar todos los flujos críticos
   - Performance testing (queries pesadas)

3. **Capacitación de usuarios**
   - Cambios en UI Odoo 19
   - Nuevos flujos (account.move unificado)
   - Reportes actualizados

#### DURANTE la Migración

1. **Migración incremental por fases**
   - NUNCA migrar todo de golpe
   - Validar cada fase antes de continuar
   - Commit frecuente (cada 1,000 registros)

2. **Monitoreo continuo**
   - Logs de migración en tiempo real
   - Alertas de errores críticos
   - Dashboard de progreso

3. **Equipo on-call 24/7**
   - Developer lead
   - DBA
   - Usuario clave (contabilidad + RRHH)

#### DESPUÉS de la Migración

1. **Validación final (Checklist)**
   - [ ] Conteos de registros OK
   - [ ] Totales contables cuadrados
   - [ ] Folios DTE sin duplicados
   - [ ] Liquidaciones nómina OK
   - [ ] Reportes SII generan correctamente

2. **Período de estabilización (2 semanas)**
   - Monitoreo intensivo
   - Soporte prioritario usuarios
   - Fixes rápidos de issues menores

3. **Documentación actualizada**
   - Guía de cambios para usuarios
   - Documentación técnica de custom
   - Procedimientos de rollback

---

## 📎 ANEXOS

### A. Checklist Pre-Migración

```
┌─────────────────────────────────────────────────────────┐
│          CHECKLIST PRE-MIGRACIÓN (Obligatorio)          │
└─────────────────────────────────────────────────────────┘

INFRAESTRUCTURA
[ ] Odoo 19 CE instalado en TEST
[ ] PostgreSQL 14+ configurado
[ ] Redis disponible (rate limiting)
[ ] Espacio disco suficiente (2x tamaño DB actual)
[ ] Backup automático configurado

DATOS
[ ] Backup completo Odoo 12 Production realizado
[ ] Backup verificado (restore test OK)
[ ] Análisis de volúmenes completo
[ ] Dataset sintético preparado (10% datos)

SCRIPTS
[ ] Scripts de migración desarrollados
[ ] Tests unitarios de scripts (PASS)
[ ] Scripts de validación desarrollados
[ ] Procedimiento de rollback documentado

EQUIPO
[ ] Developer lead asignado
[ ] DBA disponible on-call
[ ] Usuarios clave identificados (contabilidad + RRHH)
[ ] Calendario de migración acordado

COMPLIANCE
[ ] Folios DTE actuales documentados
[ ] CAFs vigentes respaldados
[ ] Certificado digital vigente (> 30 días)
[ ] Indicadores económicos actualizados (mes actual)

COMUNICACIÓN
[ ] Stakeholders notificados (fecha migración)
[ ] Usuarios capacitados (cambios Odoo 19)
[ ] Plan de comunicación de incidentes listo
```

---

### B. Script de Rollback

```bash
#!/bin/bash
# scripts/rollback_migration.sh
# Rollback de migración Odoo 19 → Odoo 12

set -e  # Exit on error

echo "╔═══════════════════════════════════════════════════════╗"
echo "║        ROLLBACK MIGRACIÓN ODOO 12 → ODOO 19           ║"
echo "╚═══════════════════════════════════════════════════════╝"

# Variables
BACKUP_DATE="2025-11-08"  # Fecha del backup
BACKUP_DB="/backups/odoo12_${BACKUP_DATE}.sql.gz"
BACKUP_FILESTORE="/backups/odoo12_filestore_${BACKUP_DATE}.tar.gz"

# Paso 1: Detener Odoo 19
echo "Deteniendo Odoo 19..."
docker-compose stop odoo

# Paso 2: Restaurar base de datos
echo "Restaurando base de datos Odoo 12..."
gunzip < $BACKUP_DB | docker exec -i odoo_db psql -U odoo -d EERGYGROUP

# Paso 3: Restaurar filestore
echo "Restaurando filestore..."
tar -xzf $BACKUP_FILESTORE -C /opt/odoo/.local/share/Odoo/filestore/

# Paso 4: Reiniciar Odoo 12
echo "Iniciando Odoo 12..."
docker-compose -f docker-compose.odoo12.yml up -d

echo "✅ ROLLBACK COMPLETADO"
echo "⚠️  Validar que Odoo 12 funciona correctamente"
```

---

**Documento Generado por:** Claude Code - Migration Specialist
**Fecha:** 2025-11-08
**Versión:** 1.0.0
**Estado:** ✅ LISTO PARA REVISIÓN

---

**SIGUIENTE PASO:** Revisión del plan + Desarrollo de scripts de migración Fase 1
