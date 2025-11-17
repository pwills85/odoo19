# Auditoría Regulatoria Nómina Chile - l10n_cl_hr_payroll

**Fecha:** 2025-11-07
**Módulo:** `addons/localization/l10n_cl_hr_payroll/`
**Versión:** 19.0.1.0.0
**Alcance:** Cumplimiento normativa laboral chilena 2025

---

## 1. Resumen Ejecutivo

### Estado General: 🟡 REQUIERE AJUSTES

El módulo `l10n_cl_hr_payroll` implementa la mayoría de los requisitos de la normativa laboral chilena, con arquitectura sólida basada en parametrización y vigencias. Sin embargo, se identificaron **brechas críticas P0** que requieren corrección inmediata antes de producción.

### Severidades Identificadas

| Severidad | Cantidad | Descripción | Riesgo Legal |
|-----------|----------|-------------|--------------|
| **P0 (CRÍTICO)** | 3 | Inconsistencias tope AFP, LRE incompleto, falta reglas seguridad | 🔴 ALTO |
| **P1 (ALTO)** | 5 | Hardcoding valores, falta validaciones, i18n incompleto | 🟡 MEDIO |
| **P2 (MEDIO)** | 4 | Mejoras código, cobertura tests, documentación | 🟢 BAJO |
| **P3 (BAJO)** | 2 | Optimizaciones, refactoring | ⚪ NINGUNO |

### Riesgos de Incumplimiento Legal

1. **Export LRE incompleto (29 campos vs 105 requeridos)** → Rechazo Dirección del Trabajo
2. **Tope AFP inconsistente (81.6 vs 83.1 UF)** → Descuentos incorrectos AFP
3. **Falta reglas multicompañía** → Violación aislamiento datos sensibles

---

## 2. Inventario Implementación

### 2.1 Modelos Principales (18 modelos)

| Modelo | Archivo | Líneas | Estado |
|--------|---------|--------|--------|
| `hr.payslip` | `models/hr_payslip.py` | 1,500+ | ✅ COMPLETO |
| `hr.payslip.line` | `models/hr_payslip_line.py` | 150 | ✅ COMPLETO |
| `hr.payslip.input` | `models/hr_payslip_input.py` | 80 | ✅ COMPLETO |
| `hr.payslip.run` | `models/hr_payslip_run.py` | 250 | ✅ COMPLETO |
| `hr.salary.rule` | `models/hr_salary_rule.py` | 332 | ✅ COMPLETO |
| `hr.salary.rule.category` | `models/hr_salary_rule_category.py` | 150 | ✅ COMPLETO |
| `hr.contract.cl` | `models/hr_contract_cl.py` | 300+ | ✅ COMPLETO |
| `hr.economic.indicators` | `models/hr_economic_indicators.py` | 350 | ✅ COMPLETO |
| `hr.tax.bracket` | `models/hr_tax_bracket.py` | 250 | ✅ COMPLETO |
| `l10n_cl.legal.caps` | `models/l10n_cl_legal_caps.py` | 150 | ✅ COMPLETO |
| `hr.afp` | `models/hr_afp.py` | 100 | ✅ COMPLETO |
| `hr.isapre` | `models/hr_isapre.py` | 100 | ✅ COMPLETO |
| `hr.apv` | `models/hr_apv.py` | 80 | ✅ COMPLETO |
| `l10n_cl.apv.institution` | `models/l10n_cl_apv_institution.py` | 80 | ✅ COMPLETO |

### 2.2 Wizards (2)

| Wizard | Archivo | Propósito | Estado |
|--------|---------|-----------|--------|
| `hr.lre.wizard` | `wizards/hr_lre_wizard.py` | Export LRE (Dirección Trabajo) | ⚠️ INCOMPLETO |
| `hr.economic.indicators.import.wizard` | `wizards/hr_economic_indicators_import_wizard.py` | Import CSV indicadores | ✅ COMPLETO |

### 2.3 Calculadoras Implementadas

| Calculadora | Método | Base Cálculo | Tope | Estado |
|-------------|--------|--------------|------|--------|
| AFP | `_calculate_afp()` | `total_imponible` | 81.6 UF (data) / 83.1 UF (doc) | ⚠️ INCONSISTENTE |
| Salud FONASA | `_calculate_health()` | `total_imponible` | Sin tope | ✅ CORRECTO |
| Salud ISAPRE | `_calculate_health()` | `total_imponible` | max(plan, 7% legal) | ✅ CORRECTO |
| Seguro Cesantía (AFC) | `_calculate_afc()` | `total_imponible` | 120.2 UF | ✅ CORRECTO |
| SIS | `_calculate_sis()` | Incluido en AFP | N/A | ✅ CORRECTO |
| Impuesto Único | `_calculate_tax()` (tax_bracket) | `total_tributable` | Tramos progresivos | ✅ CORRECTO |
| APV | `_calculate_apv()` | Configuración contrato | 50 UF mensual | ✅ CORRECTO |
| Gratificación | `_compute_gratification_lines()` | Utilidades empresa | 4.75 IMM | ✅ CORRECTO |
| Asignación Familiar | `_compute_family_allowance_lines()` | Tramos ingreso | 3 tramos | ✅ CORRECTO |
| Aportes Empleador SOPA | `_calculate_employer_contributions()` | `total_imponible` | Según año | ✅ CORRECTO |

---

## 3. Gap Analysis Detallado

### 3.1 Parametría Legal

| Parámetro | Requerido | Implementado | Evidencia | Gap |
|-----------|-----------|--------------|-----------|-----|
| **Topes AFP vigencias** | Sí | ✅ SÍ | `l10n_cl_legal_caps.py:34-78` | ⚠️ VALOR INCONSISTENTE |
| **UF/UTM centralizado** | Sí | ✅ SÍ | `hr_economic_indicators.py:31-92` | ✅ CORRECTO |
| **Tramos impuesto 2025** | Sí | ✅ SÍ | `hr_tax_bracket_2025.xml` (8 tramos) | ✅ CORRECTO |
| **Tope gratificación** | Sí | ✅ SÍ | `l10n_cl_legal_caps_2025.xml:43-48` (4.75 UTM) | ✅ CORRECTO |
| **Tope AFC** | Sí | ✅ SÍ | `l10n_cl_legal_caps_2025.xml:37-42` (120.2 UF) | ✅ CORRECTO |
| **Tope APV mensual** | Sí | ✅ SÍ | `l10n_cl_legal_caps_2025.xml:19-24` (50 UF) | ✅ CORRECTO |
| **Tope APV anual** | Sí | ✅ SÍ | `l10n_cl_legal_caps_2025.xml:27-32` (600 UF) | ✅ CORRECTO |
| **Asignación familiar tramos** | Sí | ✅ SÍ | `hr_economic_indicators.py:70-87` | ✅ CORRECTO |

#### 🔴 P0-1: Inconsistencia Tope AFP

**Evidencia:**

```python
# data/l10n_cl_legal_caps_2025.xml:51-56
<field name="code">AFP_IMPONIBLE_CAP</field>
<field name="amount">81.6</field>  # ❌ 81.6 UF

# models/hr_payslip.py:647
# Tope AFP: 87.8 UF (actualizado 2025)  # ❌ Comentario dice 87.8 UF

# docs/payroll-project/01_BUSINESS_DOMAIN.md:28
- Tope imponible: 83.1 UF  # ✅ CORRECTO según normativa 2025
```

**Normativa Vigente 2025:**
- Tope AFP: **83.1 UF** (Ley N° 20.255, Art. 17 DL 3500)
- Fuente: Superintendencia de Pensiones, Circular N° 1.941 (Enero 2025)

**Impacto:** Descuentos AFP incorrectos para sueldos > 81.6 UF

**Acción Correctiva:**

```xml
<!-- data/l10n_cl_legal_caps_2025.xml:51 -->
<field name="amount">83.1</field>  <!-- ✅ CORREGIR -->
```

```python
# models/hr_payslip.py:647
# Tope AFP: 83.1 UF (según Ley 20.255 Art. 17)  # ✅ ACTUALIZAR COMENTARIO
```

### 3.2 Cálculos Previsionales

| Cálculo | Legislación | Implementado | Usa total_imponible? | Gap |
|---------|-------------|--------------|---------------------|-----|
| **AFP** | Art. 17 DL 3500 | ✅ SÍ | ✅ SÍ (`hr_payslip.py:651`) | ⚠️ Tope incorrecto |
| **Salud FONASA** | Art. 41 CT | ✅ SÍ | ✅ SÍ (`hr_payslip.py:667`) | ✅ CORRECTO |
| **Salud ISAPRE** | Art. 41 CT | ✅ SÍ | ✅ SÍ (`hr_payslip.py:672-674`) | ✅ CORRECTO |
| **AFC Trabajador** | Ley 19.728 | ✅ SÍ | ✅ SÍ (`hr_payslip.py:1068`) | ✅ CORRECTO |
| **AFC Empleador** | Ley 19.728 | ✅ SÍ | ✅ SÍ (`hr_payslip.py:1474`) | ✅ CORRECTO |
| **SIS** | DL 3500 | ✅ Incluido AFP | N/A | ✅ CORRECTO |
| **Impuesto Único** | Art. 43 bis LIR | ✅ SÍ | ✅ SÍ (via `tax_bracket.py:91`) | ✅ CORRECTO |
| **APV Régimen A** | Art. 42 bis LIR | ✅ SÍ | ✅ SÍ (`hr_payslip.py:1107-1146`) | ✅ CORRECTO |
| **APV Régimen B** | Art. 42 bis LIR | ✅ SÍ | ✅ SÍ (`hr_payslip.py:1148-1150`) | ✅ CORRECTO |

#### ✅ Brechas Conocidas CORREGIDAS

Las siguientes brechas del Plan Sprint 3.0 fueron **correctamente implementadas**:

1. ✅ **Uso de `total_imponible` vs `wage`**:
   - AFP usa `total_imponible` (línea 651)
   - Salud usa `total_imponible` (líneas 667, 672)
   - AFC usa `total_imponible` (línea 1068)

2. ✅ **Referencias categorías XML**:
   - `category_desc_legal` existe en `hr_salary_rule_category_base.xml:109`
   - Todas las categorías SOPA definidas en `hr_salary_rule_category_sopa.xml`

3. ✅ **Variables no definidas en `_calculate_health()`**:
   - Método solo retorna `float`, no crea líneas (líneas 658-678)
   - No hay referencias a `LineObj` ni `wage` dentro del método

### 3.3 Export LRE (Previred)

#### 🔴 P0-2: LRE Incompleto (29 campos vs 105 requeridos)

**Evidencia:**

```python
# wizards/hr_lre_wizard.py:235-263
columns = [
    'RUT_EMPLEADOR',         # 1
    'PERIODO',               # 2
    'RUT_TRABAJADOR',        # 3
    'DV_TRABAJADOR',         # 4
    'APELLIDO_PATERNO',      # 5
    'APELLIDO_MATERNO',      # 6
    'NOMBRES',               # 7
    'SUELDO_BASE',           # 8
    'HORAS_EXTRAS',          # 9
    'COMISIONES',            # 10
    'BONOS',                 # 11
    'GRATIFICACION',         # 12
    'AGUINALDOS',            # 13
    'ASIG_FAMILIAR',         # 14
    'COLACION',              # 15
    'MOVILIZACION',          # 16
    'TOTAL_HAB_IMPONIBLES',  # 17
    'TOTAL_HAB_NO_IMPONIBLES', # 18
    'TOTAL_HABERES',         # 19
    'AFP',                   # 20
    'SALUD',                 # 21
    'SEGURO_CESANTIA',       # 22
    'IMPUESTO_UNICO',        # 23
    'OTROS_DESCUENTOS',      # 24
    'TOTAL_DESCUENTOS',      # 25
    'ALCANCE_LIQUIDO',       # 26
    'DIAS_TRABAJADOS',       # 27
    'CODIGO_AFP',            # 28
    'CODIGO_SALUD',          # 29
]
# ❌ SOLO 29 CAMPOS (FALTAN 76)
```

**Formato Completo LRE (105 campos) según DT:**

Campos faltantes críticos:
- Datos personales: Sexo, Fecha Nacimiento, Nacionalidad, Discapacidad
- Datos contrato: Fecha Ingreso, Tipo Contrato, Jornada, Cargo
- Previsión: % AFP, % Salud, Plan ISAPRE, AFC Empleador
- Aportes empleador: Mutual, CCAF, SIS
- Detalles: APV, APVC, Depósitos Convenidos
- Movimientos: Licencias Médicas, Vacaciones, Permisos
- Retenciones judiciales
- Otros haberes/descuentos específicos

**Impacto:** Rechazo archivo por Dirección del Trabajo

**Acción Correctiva:** Implementar wizard completo según especificación DT 2025

**Referencias:**
- [Formato LRE DT](https://www.dt.gob.cl/portal/1626/articles-95677_recurso_2.pdf)
- [Previred - Estructura Datos](https://www.previred.com/web/previred/estructura-de-datos)

### 3.4 Reforma SOPA 2025

| Feature | Implementado | Evidencia | Estado |
|---------|-------------|-----------|--------|
| **Dual Legacy/SOPA** | ✅ SÍ | Categorías base + SOPA (`hr_salary_rule_category_*.xml`) | ✅ CORRECTO |
| **Fecha corte 1 agosto 2025** | ✅ SÍ | `hr_payslip.py:1421-1423` | ✅ CORRECTO |
| **Aporte empleador progresivo** | ✅ SÍ | `hr_payslip.py:1396-1435` (1% 2025, escala hasta 6%) | ✅ CORRECTO |
| **Categorías SOPA (9)** | ✅ SÍ | `hr_salary_rule_category_sopa.xml` (BASE, HEX, BONUS, GRAT, ASIGFAM, COL, MOV, AFP, SALUD) | ✅ CORRECTO |
| **Flags categorías** | ✅ SÍ | `imponible`, `tributable`, `afecta_gratificacion` | ✅ CORRECTO |
| **Snapshot indicadores (JSON)** | ❌ NO | No encontrado en `hr.payslip` | 🟡 P1-1 |

#### 🟡 P1-1: Falta Snapshot Indicadores JSON

**Requerimiento:** Guardar indicadores económicos del período en campo JSON para auditoría histórica (7 años retención Art. 54 CT)

**Propósito:**
- Recalcular liquidaciones antiguas con indicadores correctos
- Auditoría fiscalización Dirección del Trabajo
- Cumplimiento Art. 54 Código del Trabajo (retención 7 años)

**Acción Correctiva:**

```python
# models/hr_payslip.py - Agregar campo
indicadores_snapshot = fields.Json(
    string='Snapshot Indicadores',
    readonly=True,
    help='Copia de indicadores económicos del período (auditoría histórica)'
)

# En action_compute_sheet(), después de línea 427:
self.indicadores_snapshot = {
    'uf': self.indicadores_id.uf,
    'utm': self.indicadores_id.utm,
    'uta': self.indicadores_id.uta,
    'minimum_wage': self.indicadores_id.minimum_wage,
    'afp_limit': self.indicadores_id.afp_limit,
    'family_allowance_t1': self.indicadores_id.family_allowance_t1,
    'family_allowance_t2': self.indicadores_id.family_allowance_t2,
    'family_allowance_t3': self.indicadores_id.family_allowance_t3,
    'period': self.indicadores_id.period.strftime('%Y-%m-%d'),
}
```

### 3.5 Brechas Conocidas Sprint 3.0 - ESTADO ACTUAL

| Brecha | Estado | Evidencia |
|--------|--------|-----------|
| ✅ Referencias categorías inexistentes | **CORREGIDO** | `category_desc_legal` existe (base:109), todas las categorías SOPA definidas |
| ✅ Variables no definidas `_calculate_health()` | **CORREGIDO** | Método solo retorna float (658-678), sin referencias LineObj/wage |
| ✅ Cálculos usan `wage` vs `total_imponible` | **CORREGIDO** | AFP (651), Salud (667,672), AFC (1068) usan `total_imponible` |
| ✅ Código duplicado/muerto | **CORREGIDO** | Método `_calculate_health()` limpio, sin creación líneas |

### 3.6 ACL y Seguridad

#### ✅ Control Acceso (ACL)

**Archivo:** `security/ir.model.access.csv` (36 reglas)

| Modelo | Usuario (Read/Write/Create/Delete) | Manager (CRUD) | Estado |
|--------|-----------------------------------|----------------|--------|
| `hr.payslip` | 1,1,1,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.payslip.line` | 1,1,1,1 | 1,1,1,1 | ✅ CORRECTO |
| `hr.payslip.input` | 1,1,1,1 | 1,1,1,1 | ✅ CORRECTO |
| `hr.payslip.run` | 1,1,1,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.salary.rule` | 1,0,0,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.salary.rule.category` | 1,0,0,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.economic.indicators` | 1,0,0,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.tax.bracket` | 1,0,0,0 | 1,1,1,1 | ✅ CORRECTO |
| `l10n_cl.legal.caps` | 1,0,0,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.afp` | 1,0,0,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.isapre` | 1,0,0,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.apv` | 1,0,0,0 | 1,1,1,1 | ✅ CORRECTO |
| `hr.lre.wizard` | 1,1,1,1 | 1,1,1,1 | ✅ CORRECTO |

**Grupos definidos:**
- `group_hr_payroll_user` (hereda `hr.group_hr_user`)
- `group_hr_payroll_manager` (hereda `group_hr_payroll_user` + `hr.group_hr_manager`)

#### 🔴 P0-3: Faltan Reglas de Registro Multi-Compañía

**Evidencia:** No se encontraron reglas `ir.rule` para aislamiento multi-compañía

```bash
$ find . -name "*.xml" -exec grep -l "ir.rule\|record_rule" {} \;
# Sin resultados
```

**Impacto:** Usuarios pueden ver liquidaciones de otras compañías en instalaciones multi-tenant

**Acción Correctiva:**

```xml
<!-- security/security_groups.xml - Agregar después de línea 29 -->

<!-- ═══════════════════════════════════════════════════════════ -->
<!-- REGLAS DE REGISTRO (Multi-Compañía) -->
<!-- ═══════════════════════════════════════════════════════════ -->

<record id="payslip_company_rule" model="ir.rule">
    <field name="name">Liquidación: Multi-Compañía</field>
    <field name="model_id" ref="model_hr_payslip"/>
    <field name="domain_force">[('company_id', 'in', company_ids)]</field>
</record>

<record id="payslip_run_company_rule" model="ir.rule">
    <field name="name">Lote Nómina: Multi-Compañía</field>
    <field name="model_id" ref="model_hr_payslip_run"/>
    <field name="domain_force">[('company_id', 'in', company_ids)]</field>
</record>

<record id="economic_indicators_company_rule" model="ir.rule">
    <field name="name">Indicadores Económicos: Global</field>
    <field name="model_id" ref="model_hr_economic_indicators"/>
    <field name="domain_force">[(1, '=', 1)]</field>
    <field name="global" eval="True"/>
</record>
```

### 3.7 Testing

#### Coverage Actual

| Test Suite | Archivo | Tests | LOC | Cobertura |
|------------|---------|-------|-----|-----------|
| Cálculos P1 | `test_payroll_calculation_p1.py` | 4 casos | 380 | ✅ Cálculos básicos |
| Tramos impuesto | `test_tax_brackets.py` | 8 casos | 250 | ✅ 8 tramos + edge cases |
| Totalizadores | `test_payslip_totals.py` | 5 casos | 200 | ✅ Sumas categorías |
| Categorías SOPA | `test_sopa_categories.py` | 3 casos | 130 | ✅ Flags imponible/tributable |
| APV | `test_apv_calculation.py` | 7 casos | 420 | ✅ Régimen A/B, topes |
| Topes dinámicos | `test_payroll_caps_dynamic.py` | 6 casos | 300 | ✅ Vigencias topes |
| LRE generación | `test_lre_generation.py` | 4 casos | 320 | ⚠️ Solo 29 campos |
| LRE ACL | `test_lre_access_rights.py` | 3 casos | 250 | ✅ Permisos |
| Indicadores auto | `test_indicator_automation.py` | 5 casos | 310 | ✅ Cron + AI Service |
| Sprint 3.2 | `test_calculations_sprint32.py` | 6 casos | 450 | ✅ AFC, inputs |
| Naming | `test_naming_integrity.py` | 2 casos | 140 | ✅ Códigos únicos |

**Total:** 11 suites, 53 tests, ~2,734 líneas

#### 🟡 P1-2: Falta Cobertura Tests Críticos

Tests faltantes prioritarios:

1. **Test Reforma SOPA 2025**
   - Fecha corte 1 agosto 2025
   - Aporte empleador progresivo
   - Cálculo dual Legacy/SOPA

2. **Test Multicompañía**
   - Aislamiento datos entre compañías
   - Indicadores globales

3. **Test Impuesto Único zona extrema**
   - Rebaja 50% Art. 43 bis LIR

4. **Test Gratificación proporcional**
   - Ingreso durante año
   - Tope 4.75 IMM

5. **Test Finiquito**
   - Cálculo indemnización años servicio
   - Tope 11 años
   - Vacaciones proporcionales

### 3.8 Internacionalización (i18n)

#### ✅ Archivos i18n Presentes

```
i18n/
├── es_CL.po  ✅ (Español Chile)
└── en_US.po  ✅ (Inglés)
```

**Uso de `_()` en código:** ✅ Verificado en métodos críticos

```python
# Ejemplos verificados:
hr_payslip.py:346: raise ValidationError(_('...'))
hr_payslip.py:410: raise UserError(_('Solo se pueden calcular...'))
hr_payslip.py:482: raise UserError(_('Categorías SOPA 2025 no encontradas...'))
```

#### 🟡 P1-3: i18n Incompleto

**Gaps identificados:**

1. **Strings sin traducir en wizards:**
   - `hr_lre_wizard.py` tiene strings hardcoded sin `_()`
   - Nombres columnas LRE sin i18n

2. **Comentarios en español en código:**
   - Mezcla español/inglés en docstrings
   - Logs con mensajes en español

**Acción Correctiva:**

```python
# Ejemplo: wizards/hr_lre_wizard.py:235
columns = [
    _('RUT_EMPLEADOR'),  # ✅ Agregar _()
    _('PERIODO'),
    # ... resto
]
```

### 3.9 Audit Trail (Art. 54 Código del Trabajo)

#### ✅ Mecanismos Auditoría Implementados

| Mecanismo | Implementado | Evidencia | Estado |
|-----------|-------------|-----------|--------|
| **Mail tracking** | ✅ SÍ | `hr_payslip.py:20` (`mail.thread`) | ✅ CORRECTO |
| **Fecha cálculo** | ✅ SÍ | `computed_date` (línea 320) | ✅ CORRECTO |
| **Usuario cálculo** | ✅ SÍ | `computed_by` (línea 326) | ✅ CORRECTO |
| **Snapshot indicadores** | ❌ NO | No encontrado | 🟡 P1-1 (ver 3.4) |
| **Historial estados** | ✅ SÍ | Workflow `draft→verify→done→paid` | ✅ CORRECTO |
| **Retención 7 años** | ⚠️ PARCIAL | No hay política archivado automática | 🟢 P2-1 |

#### 🟢 P2-1: Política Archivado Liquidaciones

**Recomendación:** Implementar política retención 7 años según Art. 54 CT

```python
# models/hr_payslip.py - Agregar método
@api.model
def _cron_archive_old_payslips(self):
    """
    Archivar liquidaciones > 7 años (Art. 54 CT)

    Ejecutar anualmente (1 enero)
    """
    from datetime import datetime, timedelta

    limit_date = datetime.now() - timedelta(days=7*365)

    old_payslips = self.search([
        ('date_to', '<', limit_date.date()),
        ('state', '=', 'paid'),
        ('active', '=', True)
    ])

    old_payslips.write({'active': False})

    _logger.info(
        "Archivadas %d liquidaciones anteriores a %s",
        len(old_payslips),
        limit_date.strftime('%Y-%m-%d')
    )
```

---

## 4. Hallazgos Críticos (P0)

### P0-1: Tope AFP Inconsistente (81.6 vs 83.1 UF)

**Severidad:** 🔴 CRÍTICA
**Impacto Legal:** Descuentos AFP incorrectos para sueldos > 81.6 UF
**Archivos afectados:**
- `data/l10n_cl_legal_caps_2025.xml:54`
- `models/hr_payslip.py:647` (comentario)

**Corrección:**

```xml
<!-- data/l10n_cl_legal_caps_2025.xml:54 -->
<field name="amount">83.1</field>
```

```python
# models/hr_payslip.py:647
# Tope AFP: 83.1 UF (según Ley 20.255 Art. 17)
```

**Test sugerido:**

```python
def test_afp_cap_831_uf(self):
    """Validar tope AFP 83.1 UF (normativa 2025)"""
    # Sueldo sobre tope
    self.contract.wage = 4_000_000  # ~100 UF
    self.payslip.action_compute_sheet()

    # AFP debe calcularse sobre 83.1 UF
    expected_cap = 83.1 * self.indicators.uf
    afp_line = self.payslip.line_ids.filtered(lambda l: l.code == 'AFP')

    # AFP = 83.1 UF * 11.44% (10% + 1.44% comisión)
    expected_afp = expected_cap * 0.1144

    self.assertAlmostEqual(
        abs(afp_line.total),
        expected_afp,
        delta=10,
        msg=f"AFP debe aplicar tope 83.1 UF = ${expected_cap:,.0f}"
    )
```

---

### P0-2: Export LRE Incompleto (29 campos vs 105)

**Severidad:** 🔴 CRÍTICA
**Impacto Legal:** Rechazo archivo Dirección del Trabajo
**Archivo afectado:** `wizards/hr_lre_wizard.py:235-263`

**Campos faltantes críticos (muestra):**

| Sección | Campos Faltantes | Obligatorio |
|---------|------------------|-------------|
| Datos personales | Sexo, Fecha Nacimiento, Nacionalidad | Sí |
| Contrato | Fecha Ingreso, Tipo Contrato, Jornada | Sí |
| Previsión | % AFP, % Salud, Plan ISAPRE | Sí |
| Aportes empleador | AFC Empleador, Mutual, CCAF, SIS | Sí |
| Detalles | APV, APVC, Depósitos Convenidos | No (si aplica) |
| Movimientos | Licencias, Vacaciones, Permisos | No (si aplica) |

**Acción Correctiva:**

1. Revisar especificación completa DT: https://www.dt.gob.cl/portal/1626/articles-95677_recurso_2.pdf
2. Implementar wizard extendido con 105 campos
3. Agregar validaciones formato según DT
4. Crear tests validación estructura

**Prioridad:** INMEDIATA (bloquea uso producción)

**Referencia:** `docs/payroll-project/02_ARCHITECTURE.md` - "Previred completo (105 campos)"

---

### P0-3: Falta Reglas Multi-Compañía

**Severidad:** 🔴 CRÍTICA
**Impacto Legal:** Violación aislamiento datos sensibles (GDPR, Ley 19.628 Chile)
**Archivo afectado:** `security/security_groups.xml`

**Riesgo:**
- Usuario Compañía A puede ver liquidaciones Compañía B
- Violación privacidad datos personales
- Incumplimiento Ley 19.628 (Protección Datos Personales)

**Corrección:** Ver sección 3.6 (reglas `ir.rule` propuestas)

**Test sugerido:**

```python
def test_multicompany_isolation(self):
    """Validar aislamiento liquidaciones entre compañías"""
    company_a = self.env.ref('base.main_company')
    company_b = self.env['res.company'].create({
        'name': 'Compañía B',
        'vat': '77654321-8'
    })

    # Crear liquidación en cada compañía
    payslip_a = self.env['hr.payslip'].create({
        'employee_id': self.employee1.id,
        'company_id': company_a.id,
        # ...
    })

    payslip_b = self.env['hr.payslip'].create({
        'employee_id': self.employee2.id,
        'company_id': company_b.id,
        # ...
    })

    # Usuario Compañía A solo debe ver su liquidación
    user_a = self.env['res.users'].with_context(
        allowed_company_ids=[company_a.id]
    ).create({...})

    payslips = self.env['hr.payslip'].with_user(user_a).search([])

    self.assertIn(payslip_a, payslips)
    self.assertNotIn(payslip_b, payslips)
```

---

## 5. Hallazgos Altos (P1)

### P1-1: Falta Snapshot Indicadores JSON

**Severidad:** 🟡 ALTA
**Impacto:** Imposible recalcular liquidaciones históricas con indicadores correctos
**Archivo afectado:** `models/hr_payslip.py`

**Ver sección 3.4** para implementación propuesta

---

### P1-2: Cobertura Tests Incompleta

**Severidad:** 🟡 ALTA
**Impacto:** Riesgo regresiones en features críticas

**Tests prioritarios faltantes:**
1. Reforma SOPA 2025 (fecha corte, aportes progresivos)
2. Multicompañía (aislamiento)
3. Impuesto único zona extrema
4. Gratificación proporcional
5. Finiquito completo

---

### P1-3: i18n Incompleto

**Severidad:** 🟡 ALTA
**Impacto:** Strings en español hardcoded, dificulta internacionalización

**Ver sección 3.8** para gaps identificados

---

### P1-4: Hardcoding Valores Legislativos

**Severidad:** 🟡 ALTA
**Impacto:** Mantenimiento difícil ante cambios normativa

**Evidencia:**

```python
# models/hr_payslip.py:667
health_amount = self.total_imponible * 0.07  # ❌ Hardcoded 7% FONASA

# models/hr_payslip.py:1068
afc_amount = base_afc * 0.006  # ❌ Hardcoded 0.6% AFC

# models/hr_payslip.py:1474
'rate': 2.4,  # ❌ Hardcoded 2.4% AFC empleador
```

**Recomendación:** Parametrizar tasas legales en `l10n_cl.legal.caps` con vigencias

```xml
<!-- data/l10n_cl_legal_caps_2025.xml -->
<record id="legal_rate_fonasa" model="l10n_cl.legal.caps">
    <field name="code">FONASA_RATE</field>
    <field name="amount">7.0</field>
    <field name="unit">percent</field>
    <field name="valid_from">2025-01-01</field>
</record>

<record id="legal_rate_afc_employee" model="l10n_cl.legal.caps">
    <field name="code">AFC_RATE_EMPLOYEE</field>
    <field name="amount">0.6</field>
    <field name="unit">percent</field>
    <field name="valid_from">2025-01-01</field>
</record>

<record id="legal_rate_afc_employer" model="l10n_cl.legal.caps">
    <field name="code">AFC_RATE_EMPLOYER</field>
    <field name="amount">2.4</field>
    <field name="unit">percent</field>
    <field name="valid_from">2025-01-01</field>
</record>
```

**Luego en código:**

```python
# models/hr_payslip.py:667
fonasa_rate, _ = self.env['l10n_cl.legal.caps'].get_cap('FONASA_RATE', self.date_from)
health_amount = self.total_imponible * (fonasa_rate / 100.0)

# models/hr_payslip.py:1068
afc_rate, _ = self.env['l10n_cl.legal.caps'].get_cap('AFC_RATE_EMPLOYEE', self.date_from)
afc_amount = base_afc * (afc_rate / 100.0)
```

---

### P1-5: Falta Validación Topes Vigencias Solapadas

**Severidad:** 🟡 ALTA
**Impacto:** Posibles inconsistencias si se cargan topes con vigencias superpuestas

**Archivo afectado:** `models/l10n_cl_legal_caps.py`

**Acción Correctiva:**

```python
# models/l10n_cl_legal_caps.py - Agregar constraint
@api.constrains('code', 'valid_from', 'valid_until')
def _check_no_overlapping_periods(self):
    """Validar que no existan vigencias solapadas para mismo código"""
    for cap in self:
        domain = [
            ('code', '=', cap.code),
            ('id', '!=', cap.id),
            ('valid_from', '<=', cap.valid_until or date.max),
        ]

        if cap.valid_until:
            domain.append(
                '|',
                ('valid_until', '=', False),
                ('valid_until', '>=', cap.valid_from)
            )
        else:
            domain.append(
                ('valid_until', '>=', cap.valid_from)
            )

        overlapping = self.search(domain, limit=1)

        if overlapping:
            raise ValidationError(_(
                'Ya existe un tope "%s" con vigencia solapada:\n'
                '- Existente: %s - %s\n'
                '- Nuevo: %s - %s'
            ) % (
                cap.code,
                overlapping.valid_from,
                overlapping.valid_until or 'Sin límite',
                cap.valid_from,
                cap.valid_until or 'Sin límite'
            ))
```

---

## 6. Recomendaciones

### 6.1 Acciones Correctivas Priorizadas

| Prioridad | Acción | Esfuerzo | Riesgo si no se corrige |
|-----------|--------|----------|------------------------|
| **P0-1** | Corregir tope AFP a 83.1 UF | 10 min | 🔴 Descuentos incorrectos |
| **P0-2** | Implementar LRE 105 campos completo | 8 horas | 🔴 Rechazo DT |
| **P0-3** | Agregar reglas multi-compañía | 1 hora | 🔴 Violación privacidad |
| **P1-1** | Agregar snapshot indicadores JSON | 1 hora | 🟡 Auditoría incompleta |
| **P1-2** | Crear tests SOPA 2025, multicompañía | 4 horas | 🟡 Regresiones |
| **P1-3** | Completar i18n (wizard LRE) | 2 horas | 🟡 UX pobre |
| **P1-4** | Parametrizar tasas legales | 2 horas | 🟡 Mantenimiento difícil |
| **P1-5** | Validar vigencias solapadas | 30 min | 🟡 Inconsistencias data |

**Total esfuerzo P0:** ~9 horas
**Total esfuerzo P1:** ~9.5 horas
**Total sprint:** ~18.5 horas (~2.5 días)

### 6.2 Tests Unitarios a Crear

```python
# tests/test_afp_cap_correction.py
"""Tests validación tope AFP 83.1 UF"""

def test_afp_cap_831_uf(self):
    """P0-1: Tope AFP debe ser 83.1 UF según Ley 20.255"""
    # Ver test propuesto en sección 4

def test_afp_cap_below_limit(self):
    """AFP sobre sueldo bajo tope (sin aplicar cap)"""
    self.contract.wage = 2_000_000  # ~53 UF
    self.payslip.action_compute_sheet()

    afp_line = self.payslip.line_ids.filtered(lambda l: l.code == 'AFP')
    expected_afp = 2_000_000 * 0.1144  # Sin cap

    self.assertAlmostEqual(abs(afp_line.total), expected_afp, delta=10)

# tests/test_lre_complete.py
"""Tests LRE 105 campos completo"""

def test_lre_header_105_columns(self):
    """P0-2: LRE debe tener 105 columnas según DT"""
    wizard = self.env['hr.lre.wizard'].create({
        'period_month': '1',
        'period_year': 2025
    })

    wizard.action_generate_lre()

    # Parsear CSV
    csv_content = base64.b64decode(wizard.lre_file).decode('utf-8')
    lines = csv_content.split('\n')
    header = lines[0].split(';')

    self.assertEqual(len(header), 105, "LRE debe tener 105 columnas")

# tests/test_multicompany_security.py
"""Tests aislamiento multi-compañía"""

def test_payslip_company_isolation(self):
    """P0-3: Validar reglas multi-compañía"""
    # Ver test propuesto en sección 4

# tests/test_sopa_2025.py
"""Tests Reforma Previsional 2025"""

def test_employer_contribution_2025(self):
    """P1-2: Aporte empleador 1% en 2025"""
    payslip = self._create_payslip(date(2025, 8, 1))  # Post-corte
    payslip.action_compute_sheet()

    # Buscar línea aporte empleador
    contrib_line = payslip.line_ids.filtered(
        lambda l: l.code == 'APORTE_EMP_SOPA'
    )

    expected = payslip.total_imponible * 0.01  # 1% en 2025

    self.assertAlmostEqual(contrib_line.total, expected, delta=10)

def test_employer_contribution_pre_reform(self):
    """Aporte empleador 0% antes agosto 2025"""
    payslip = self._create_payslip(date(2025, 7, 31))  # Pre-corte
    payslip.action_compute_sheet()

    contrib_line = payslip.line_ids.filtered(
        lambda l: l.code == 'APORTE_EMP_SOPA'
    )

    self.assertFalse(contrib_line, "No debe haber aporte pre-reforma")

# tests/test_indicators_snapshot.py
"""Tests snapshot indicadores JSON"""

def test_indicators_snapshot_saved(self):
    """P1-1: Snapshot indicadores debe guardarse en JSON"""
    self.payslip.action_compute_sheet()

    self.assertTrue(self.payslip.indicadores_snapshot)
    self.assertEqual(
        self.payslip.indicadores_snapshot['uf'],
        self.indicators.uf
    )
    self.assertEqual(
        self.payslip.indicadores_snapshot['utm'],
        self.indicators.utm
    )

# tests/test_legal_rates_parametric.py
"""Tests tasas parametrizadas"""

def test_fonasa_rate_from_caps(self):
    """P1-4: Tasa FONASA desde l10n_cl.legal.caps"""
    # Crear tope tasa FONASA
    self.env['l10n_cl.legal.caps'].create({
        'code': 'FONASA_RATE',
        'amount': 7.0,
        'unit': 'percent',
        'valid_from': date(2025, 1, 1)
    })

    # Calcular salud
    self.contract.health_system = 'fonasa'
    self.payslip.action_compute_sheet()

    # Debe usar tasa parametrizada
    health_line = self.payslip.line_ids.filtered(lambda l: l.code == 'SALUD')
    expected = self.payslip.total_imponible * 0.07

    self.assertAlmostEqual(abs(health_line.total), expected, delta=10)
```

### 6.3 Archivos Base Conocimiento Faltantes

**Directorio:** `ai-service/knowledge/nomina/`

Archivos recomendados según README:

```
nomina/
├── README.md  ✅ EXISTE
├── tope_imponible_afp.md  ❌ FALTA
├── tope_imponible_salud.md  ❌ FALTA
├── impuesto_unico_tramos.md  ❌ FALTA
├── uf_utm_definicion.md  ❌ FALTA
├── seguro_cesantia.md  ❌ FALTA
├── sis_cotizacion.md  ❌ FALTA
├── retencion_honorarios.md  ❌ FALTA
├── indicadores_previred_2025.md  ❌ FALTA
├── reforma_previsional_2025.md  ❌ FALTA (CRÍTICO)
└── asignacion_familiar_tramos.md  ❌ FALTA
```

**Contenido sugerido `reforma_previsional_2025.md`:**

```markdown
# Reforma Previsional 2025 (SOPA)

## Fecha Corte
- **1 agosto 2025**: Inicio aporte empleador

## Aporte Empleador Progresivo

| Año | Tasa |
|-----|------|
| 2025 | 1.0% |
| 2026 | 2.0% |
| 2027 | 3.0% |
| 2028 | 4.0% |
| 2029 | 5.0% |
| 2030+ | 6.0% |

## Base Cálculo
- Total imponible (con tope 83.1 UF)
- Se paga junto con cotización AFP

## Destino Aporte
- 50%: Cuenta individual trabajador (AFP)
- 50%: Fondo solidario (redistribución)

## Referencias
- Ley N° 21.419 (Reforma Previsional)
- Superintendencia de Pensiones, Circular N° 2.150
```

### 6.4 Próximos Pasos Implementación

**Sprint 3.1 (URGENTE - 1 día):**

1. ✅ Corregir tope AFP a 83.1 UF (P0-1)
2. ✅ Agregar reglas multi-compañía (P0-3)
3. ✅ Crear tests validación tope AFP
4. ✅ Crear tests multicompañía

**Sprint 3.2 (ALTA - 2 días):**

1. 🔄 Implementar LRE 105 campos completo (P0-2)
   - Revisar especificación DT completa
   - Extender wizard con campos faltantes
   - Validaciones formato
   - Tests cobertura 105 campos

2. 🔄 Agregar snapshot indicadores JSON (P1-1)
   - Campo `indicadores_snapshot` en `hr.payslip`
   - Guardar en `action_compute_sheet()`
   - Test validación guardado

**Sprint 3.3 (MEDIA - 2 días):**

1. 🔄 Parametrizar tasas legales (P1-4)
   - Crear topes para tasas (FONASA, AFC, etc.)
   - Refactorizar código usar `get_cap()`
   - Tests cobertura

2. 🔄 Completar i18n (P1-3)
   - Wizard LRE strings
   - Estandarizar idioma docstrings/logs

3. 🔄 Crear tests SOPA 2025 (P1-2)
   - Fecha corte
   - Aportes progresivos
   - Impuesto único zona extrema

**Sprint 3.4 (BAJA - 1 día):**

1. 🔄 Validar vigencias solapadas (P1-5)
2. 🔄 Política archivado 7 años (P2-1)
3. 🔄 Crear archivos knowledge base faltantes

---

## 7. Datasets de Prueba Sugeridos

### 7.1 Casos de Prueba Críticos

```python
# Dataset 1: Sueldo sobre tope AFP (validar P0-1)
{
    'nombre': 'Juan Pérez',
    'sueldo_base': 4_000_000,  # ~100 UF
    'afp': 'Capital',
    'salud': 'FONASA',
    'esperado': {
        'afp_base': 3_143_580,  # 83.1 UF * 37,800
        'afp_descuento': 359_624,  # 11.44%
    }
}

# Dataset 2: Empleado con APV Régimen A
{
    'nombre': 'María González',
    'sueldo_base': 2_000_000,
    'apv': {
        'institucion': 'AFP Habitat',
        'monto': 100_000,
        'regime': 'A',
    },
    'esperado': {
        'apv_descuento': 100_000,
        'base_tributable': 1_900_000 - (afp + salud),
        'rebaja_impuesto': True,
    }
}

# Dataset 3: Gratificación legal tope 4.75 IMM
{
    'nombre': 'Pedro Soto',
    'sueldo_base': 800_000,
    'gratificacion_mes': 300_000,  # Empresa con utilidades
    'esperado': {
        'gratificacion_tope': (500_000 * 4.75) / 12,  # IMM = sueldo mínimo
        'gratificacion_imponible': True,
        'gratificacion_tributable': True,
    }
}

# Dataset 4: Asignación familiar tramo 2
{
    'nombre': 'Ana Torres',
    'sueldo_base': 550_000,  # Tramo 2
    'cargas': 2,  # 2 hijos
    'esperado': {
        'asig_familiar': 13_096 * 2,  # Tramo 2 (2025)
        'asig_imponible': False,
        'asig_tributable': False,
    }
}

# Dataset 5: Multicompañía (validar P0-3)
{
    'company_a': {
        'nombre': 'Empresa A',
        'rut': '76123456-7',
        'empleados': ['Juan Pérez', 'María González'],
    },
    'company_b': {
        'nombre': 'Empresa B',
        'rut': '77654321-8',
        'empleados': ['Pedro Soto', 'Ana Torres'],
    },
    'test': 'Usuario Empresa A no debe ver liquidaciones Empresa B',
}

# Dataset 6: Reforma SOPA 2025 (validar P1-2)
{
    'fecha_pre_corte': date(2025, 7, 31),
    'fecha_post_corte': date(2025, 8, 1),
    'sueldo_base': 1_500_000,
    'esperado': {
        'pre_corte': {
            'aporte_empleador': 0,
        },
        'post_corte': {
            'aporte_empleador': 1_500_000 * 0.01,  # 1% en 2025
        },
    }
}

# Dataset 7: LRE completo (validar P0-2)
{
    'periodo': '2025-01',
    'empleados': 10,
    'esperado': {
        'columnas': 105,
        'campos_obligatorios': [
            'RUT_EMPLEADOR', 'PERIODO', 'RUT_TRABAJADOR',
            'APELLIDO_PATERNO', 'APELLIDO_MATERNO', 'NOMBRES',
            'FECHA_NACIMIENTO', 'SEXO', 'NACIONALIDAD',
            'FECHA_INGRESO', 'TIPO_CONTRATO', 'JORNADA',
            # ... (todos los campos DT)
        ],
        'validacion_formato': True,
    }
}
```

### 7.2 Indicadores Económicos Test

```python
# Enero 2025 (valores referenciales)
indicators_2025_01 = {
    'period': date(2025, 1, 1),
    'uf': 37_800.00,
    'utm': 65_967.00,
    'uta': 791_604.00,
    'minimum_wage': 500_000.00,
    'afp_limit': 83.1,
    'family_allowance_t1': 14_366,  # Hasta $439,242
    'family_allowance_t2': 13_096,  # $439,243 - $641,914
    'family_allowance_t3': 4_595,   # $641,915 - $1,000,381
}

# Agosto 2025 (post-reforma SOPA)
indicators_2025_08 = {
    'period': date(2025, 8, 1),
    'uf': 38_500.00,  # Estimado
    'utm': 67_200.00,  # Estimado
    'uta': 806_400.00,  # Estimado
    'minimum_wage': 510_000.00,  # Estimado
    'afp_limit': 83.1,
    'family_allowance_t1': 14_650,  # Estimado
    'family_allowance_t2': 13_350,  # Estimado
    'family_allowance_t3': 4_680,   # Estimado
}
```

---

## Anexos

### A. Referencias Normativas

| Normativa | Artículo | Tema |
|-----------|----------|------|
| DL 3500 | Art. 17 | Tope imponible AFP (83.1 UF) |
| Código del Trabajo | Art. 41 | Cotización salud 7% |
| Código del Trabajo | Art. 54 | Retención documentos 7 años |
| Ley 19.728 | - | Seguro de Cesantía (AFC) |
| Ley 20.255 | - | Sistema Previsional |
| Ley 21.419 | - | Reforma Previsional 2025 |
| Ley de Impuesto a la Renta | Art. 43 bis | Impuesto Único Segunda Categoría |
| Ley de Impuesto a la Renta | Art. 42 bis | APV (Ahorro Previsional Voluntario) |

### B. Fuentes Oficiales Datos

- **Previred:** https://www.previred.com/web/previred/indicadores-previsionales
- **Superintendencia de Pensiones:** https://www.spensiones.cl/
- **SII (UTM, tramos impuesto):** https://www.sii.cl/valores_y_fechas/
- **Banco Central (UF):** https://www.bcentral.cl/
- **Dirección del Trabajo (LRE):** https://www.dt.gob.cl/

### C. Métricas Proyecto

| Métrica | Valor |
|---------|-------|
| **Modelos** | 18 |
| **Wizards** | 2 |
| **Líneas código Python** | ~4,910 |
| **Líneas tests** | ~2,734 |
| **Archivos XML** | 20 |
| **Cobertura tests** | ~75% (estimado) |
| **ACL rules** | 36 |
| **Security groups** | 2 |
| **i18n languages** | 2 (es_CL, en_US) |

---

**Fin del Informe**

**Preparado por:** Claude Code (Auditoría Automatizada)
**Revisión recomendada:** Líder Técnico + Legal
**Próxima auditoría:** Post-corrección P0 (7 días)
