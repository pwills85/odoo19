# 🎯 PROMPT PROFESIONAL - CIERRE TOTAL DE BRECHAS V3
## Ejecución Máxima Precisión | Evidence-Based | Zero Improvisation | Enterprise-Grade

---

## 📋 METADATA Y CONTEXTO

| Campo | Valor |
|-------|-------|
| **Fecha Emisión** | 2025-11-09 02:00 CLT |
| **Versión** | 3.0 (Professional Grade) |
| **Branch Target** | `feat/cierre_total_brechas_profesional` |
| **Agente Ejecutor** | @odoo-dev (Sonnet) + Multi-Agent Support |
| **Coordinador** | Senior Engineer (Orchestrator) |
| **Prioridad** | 🔴 CRÍTICA - P0/P1 |
| **Metodología** | Evidence-based, Test-driven, Rollback-safe |
| **Timeline** | 3-5 sprints (1-2 semanas) |
| **Status** | 📋 READY FOR EXECUTION |

---

## 🎓 CONTEXTO DEL PROYECTO

### Arquitectura EERGYGROUP

**Stack Tecnológico:**
- **Framework:** Odoo 19 Community Edition (19.0)
- **Localización:** Chile (l10n_cl_*)
- **Módulos Core:** DTE, Nómina, Reportes Financieros, AI Microservice
- **Patrón:** Modular inheritance (`_inherit`), OCA standards
- **Testing:** pytest-odoo, TransactionCase, ≥80% coverage target
- **CI/CD:** GitHub Actions (lint, tests, coverage)

**Módulos Críticos Bajo Scope:**

| Módulo | LOC | Estado Actual | Coverage |
|--------|-----|---------------|----------|
| **l10n_cl_dte** | ~8,500 | Production-Ready | 75% |
| **l10n_cl_hr_payroll** | ~6,200 | ✅ P0/P1 Complete | 92% |
| **l10n_cl_financial_reports** | ~4,800 | Lint 503→279 errors | 70% |
| **ai-service** (FastAPI) | ~9,674 | ⭐⭐⭐⭐ (4/5) | 0% |

### Decisiones Arquitectónicas Clave

```python
# ✅ SIEMPRE usar _inherit (NO modificar core)
class AccountMove(models.Model):
    _inherit = 'account.move'
    
# ✅ SIEMPRE validar permisos
@api.model
def create(self, vals):
    self.check_access_rights('create')
    
# ✅ SIEMPRE usar computed fields con @api.depends
@api.depends('invoice_line_ids.price_subtotal')
def _compute_amount_total(self):
    
# ✅ SIEMPRE implementar _check methods para validaciones complejas
@api.constrains('vat')
def _check_vat_chile(self):
    
# ✅ SIEMPRE usar libs/ pure Python (NO ORM dependencies)
# libs/dte_xml_builder.py (pure Python)
# libs/rut_validator.py (pure Python + stdnum)
```

---

## 📊 ESTADO ACTUAL Y BRECHAS CONFIRMADAS

### Hallazgos Ratificados (Evidence-Based)

**Fuentes de Evidencia:**
- `.codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md` (842 líneas)
- `AUDITORIA_NOMINA_VERIFICACION_P0_P1_2025-11-07.md` (717 líneas)
- `docs/ai-service/ANALISIS_MEJORAS_MICROSERVICIO_AI_SENIOR_2025-11-09.md` (1,150 líneas)
- Auditorías exhaustivas enterprise (2025-11-07)

### Matriz de Brechas Priorizadas

#### 🔴 PRIORIDAD P0 (CRÍTICO - BLOQUEA PRODUCCIÓN)

| ID | Módulo | Brecha | Evidencia | Impacto | Esfuerzo |
|----|--------|--------|-----------|---------|----------|
| **P0-001** | l10n_cl_dte | **Alcance DTE Incorrecto** | `libs/dte_structure_validator.py:42` incluye tipos 39,41,46,70 (BHE fuera de scope B2B) | 🔴 Riesgo regulatorio SII | 2h |
| **P0-002** | l10n_cl_hr_payroll | **Fallback Hardcoded Tope AFP** | `data/hr_salary_rules_p1.xml:91` usa `81.6 * 38000` en lugar de indicador dinámico | 🔴 Incumplimiento legal | 1h |
| **P0-003** | l10n_cl_hr_payroll | **Missing ir.model.access LRE Wizard** | `security/ir.model.access.csv` falta `access_hr_lre_wizard_user` | 🔴 Security breach | 30min |
| **P0-004** | l10n_cl_dte | **Dashboard KPIs Hardcoded** | `models/dte_dashboard.py` usa días hardcoded vs parámetros sistema | 🟡 Rigidez operativa | 1h |

#### 🟡 PRIORIDAD P1 (IMPORTANTE - MEJORA CALIDAD)

| ID | Módulo | Brecha | Evidencia | Impacto | Esfuerzo |
|----|--------|--------|-----------|---------|----------|
| **P1-001** | l10n_cl_hr_payroll | **Missing i18n Translations** | Carpeta `i18n/` no existe; wizard LRE solo español | 🟡 UX degradada | 2h |
| **P1-002** | l10n_cl_dte | **RUT Validator Inconsistente** | `wizards/hr_lre_wizard.py` NO usa `stdnum.cl.rut` como DTE | 🟡 Inconsistencia | 1h |
| **P1-003** | l10n_cl_financial_reports | **Duplicate Methods** | `create_monthly_f29` duplicado en múltiples clases | 🟡 Mantenibilidad | 3h |
| **P1-004** | l10n_cl_dte | **Missing Tests Dashboard** | Dashboard DTE sin tests (0% coverage) | 🟡 Regresión futura | 4h |

#### 🟢 PRIORIDAD P2 (OPCIONAL - REFINAMIENTO)

| ID | Módulo | Brecha | Impacto | Esfuerzo |
|----|--------|--------|---------|----------|
| **P2-001** | ai-service | **Redis SPOF** | 🟢 Escalabilidad limitada | 2 días |
| **P2-002** | ai-service | **Testing 0% Coverage** | 🟢 Confianza deployment | 5 días |
| **P2-003** | l10n_cl_financial_reports | **Lint 279 errors remaining** | 🟢 Code quality | 1 día |

---

## 🚀 PLAN DE EJECUCIÓN DETALLADO

### SPRINT 0: Preparación y Backup (OBLIGATORIO)

**Duración:** 30 minutos  
**Agente:** @docker-devops  
**Objetivo:** Garantizar rollback seguro

#### Checklist Pre-Ejecución

```bash
# 1. Verificar rama actual
git branch --show-current  # Debe ser: feat/cierre_total_brechas_profesional

# 2. Crear backup SQL (desarrollo)
docker exec odoo19_db_1 pg_dump -U odoo -d odoo19 > \
  .backup_consolidation/pre_sprint_$(date +%Y%m%d_%H%M%S).sql

# 3. Verificar espacio en disco
df -h  # Mínimo 5GB libres

# 4. Crear checkpoint Git
git add -A
git commit -m "chore(sprint0): checkpoint before P0/P1 gap closure

- Backup created: .backup_consolidation/pre_sprint_YYYYMMDD_HHMMSS.sql
- Current state: l10n_cl_hr_payroll P0/P1 complete (92% coverage)
- Pending: DTE scope fix, hardcoded fallbacks, security gaps

References:
- .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md
- AUDITORIA_NOMINA_VERIFICACION_P0_P1_2025-11-07.md"

# 5. Crear tag de rollback
git tag -a sprint0_backup_$(date +%Y%m%d) -m "Backup before P0/P1 closure"

# 6. Verificar módulos instalables
docker exec -it odoo19_web_1 odoo -c /etc/odoo/odoo.conf \
  --test-enable --stop-after-init \
  -d odoo19_test_sprint0 \
  -i l10n_cl_dte,l10n_cl_hr_payroll,l10n_cl_financial_reports
```

**Criterio de Éxito:**
- ✅ Backup SQL creado y verificado (>100MB)
- ✅ Checkpoint Git con mensaje descriptivo
- ✅ Tag de rollback creado
- ✅ Módulos instalan sin errores en DB test

---

### SPRINT 1: P0-001 - Alcance DTE Correcto (CRÍTICO)

**Duración:** 2 horas  
**Agente:** @odoo-dev (ejecutor) + @dte-compliance (validador)  
**Prioridad:** 🔴 P0 - CRÍTICO  
**Riesgo:** Regulatorio SII

#### Contexto del Problema

```
PROBLEMA:
- Contrato EERGYGROUP B2B autoriza solo: 33, 34, 52, 56, 61
- Código actual incluye: 39, 41, 46, 70 (Boletas Honorarios/Venta)
- Violación: Máxima de Correctitud Legal (MAXIMAS_AUDITORIA.md §6)

EVIDENCIA:
libs/dte_structure_validator.py:42-48
models/dte_inbox.py:62-72
__manifest__.py:16-22
```

#### Archivos a Modificar

**1. `addons/localization/l10n_cl_dte/libs/dte_structure_validator.py`**

```python
# LÍNEA 42-48 (ANTES):
DTE_TYPES_VALID = [
    '33','34','39','41','46','52','56','61','70'
]

# LÍNEA 42-48 (DESPUÉS):
# EERGYGROUP B2B Scope - SII authorized DTE types only
# Contract dated: 2024-Q4
# Excluded: 39,41,46,70 (Boletas Honorarios/Venta - out of scope)
DTE_TYPES_VALID = [
    '33',  # Factura Electrónica
    '34',  # Factura Exenta Electrónica
    '52',  # Guía de Despacho Electrónica
    '56',  # Nota de Débito Electrónica
    '61',  # Nota de Crédito Electrónica
]
```

**2. `addons/localization/l10n_cl_dte/models/dte_inbox.py`**

```python
# LÍNEA 62-72 (ANTES):
dte_type = fields.Selection(
    selection=[
        ('33', 'Factura Electrónica'),
        ('34', 'Factura Exenta Electrónica'),
        ('39', 'Boleta Electrónica'),
        ('41', 'Boleta Exenta Electrónica'),
        ('46', 'Factura de Compra Electrónica'),
        ('52', 'Guía de Despacho Electrónica'),
        ('56', 'Nota de Débito Electrónica'),
        ('61', 'Nota de Crédito Electrónica'),
        ('70', 'Boleta de Honorarios Electrónica'),
    ],
    string='Tipo DTE',
    required=True,
)

# LÍNEA 62-72 (DESPUÉS):
dte_type = fields.Selection(
    selection=[
        ('33', 'Factura Electrónica'),
        ('34', 'Factura Exenta Electrónica'),
        ('52', 'Guía de Despacho Electrónica'),
        ('56', 'Nota de Débito Electrónica'),
        ('61', 'Nota de Crédito Electrónica'),
    ],
    string='Tipo DTE',
    required=True,
    help="EERGYGROUP B2B scope: Facturas, Guías y Notas asociadas. "
         "Boletas (39,41,70) y Factura Compra (46) excluidas por contrato."
)
```

**3. `addons/localization/l10n_cl_dte/__manifest__.py`**

```python
# LÍNEA 16-22 (ANTES):
'description': """
    Módulo de Documentos Tributarios Electrónicos para Chile
    - Emisión de Facturas Electrónicas
    - Recepción de DTEs
    - Recepción Boletas Honorarios Electrónicas (BHE)
    - Integración con SII
""",

# LÍNEA 16-22 (DESPUÉS):
'description': """
    Módulo de Documentos Tributarios Electrónicos para Chile (B2B)
    - Emisión de Facturas Electrónicas (33, 34)
    - Guías de Despacho (52)
    - Notas de Débito/Crédito (56, 61)
    - Integración con SII
    
    Alcance EERGYGROUP B2B: Excluye Boletas (39,41,70) y Factura Compra (46)
""",
```

#### Tests Obligatorios

**Archivo:** `addons/localization/l10n_cl_dte/tests/test_dte_scope_b2b.py`

```python
# -*- coding: utf-8 -*-
from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


@tagged('post_install', '-at_install', 'dte_scope')
class TestDTEScopeB2B(TransactionCase):
    """
    Test DTE types are limited to EERGYGROUP B2B scope.
    
    Contract scope: 33, 34, 52, 56, 61 only
    Excluded: 39, 41, 46, 70 (out of B2B scope)
    """

    def setUp(self):
        super().setUp()
        self.DteInbox = self.env['l10n_cl.dte.inbox']

    def test_valid_dte_types_b2b(self):
        """Valid B2B DTE types should be allowed."""
        valid_types = ['33', '34', '52', '56', '61']
        
        for dte_type in valid_types:
            with self.subTest(dte_type=dte_type):
                record = self.DteInbox.create({
                    'dte_type': dte_type,
                    'folio': 12345,
                    'emisor_rut': '76123456-7',
                    'receptor_rut': '77654321-8',
                    'monto_total': 100000,
                })
                self.assertEqual(record.dte_type, dte_type)

    def test_invalid_dte_types_excluded(self):
        """Out-of-scope DTE types (39,41,46,70) should be rejected."""
        invalid_types = ['39', '41', '46', '70']
        
        for dte_type in invalid_types:
            with self.subTest(dte_type=dte_type):
                with self.assertRaises(ValidationError):
                    self.DteInbox.create({
                        'dte_type': dte_type,
                        'folio': 12345,
                        'emisor_rut': '76123456-7',
                        'receptor_rut': '77654321-8',
                        'monto_total': 100000,
                    })

    def test_dte_structure_validator_scope(self):
        """DTE_TYPES_VALID constant should only include B2B types."""
        from addons.localization.l10n_cl_dte.libs.dte_structure_validator import DTE_TYPES_VALID
        
        expected = ['33', '34', '52', '56', '61']
        self.assertEqual(set(DTE_TYPES_VALID), set(expected),
                         "DTE_TYPES_VALID must match EERGYGROUP B2B scope")
        
        # Ensure excluded types are NOT present
        excluded = ['39', '41', '46', '70']
        for dte_type in excluded:
            self.assertNotIn(dte_type, DTE_TYPES_VALID,
                             f"DTE type {dte_type} should be excluded (out of B2B scope)")
```

#### Validación y Deployment

```bash
# 1. Ejecutar tests
docker exec -it odoo19_web_1 pytest \
  addons/localization/l10n_cl_dte/tests/test_dte_scope_b2b.py \
  -v --tb=short

# 2. Validar con @dte-compliance
# Verificar que tipos 39,41,46,70 NO estén accesibles en UI

# 3. Upgrade módulo en DB desarrollo
docker exec -it odoo19_web_1 odoo -c /etc/odoo/odoo.conf \
  -d odoo19 -u l10n_cl_dte --stop-after-init

# 4. Commit atómico
git add addons/localization/l10n_cl_dte/
git commit -m "fix(l10n_cl_dte): limit DTE scope to EERGYGROUP B2B authorized types

BREAKING CHANGE: Remove DTE types 39,41,46,70 (Boletas/Factura Compra)

- Align with EERGYGROUP B2B contract scope (33,34,52,56,61 only)
- Update DTE_TYPES_VALID constant in libs/dte_structure_validator.py
- Update dte_type Selection field in models/dte_inbox.py
- Update module description in __manifest__.py
- Add comprehensive tests: test_dte_scope_b2b.py (8 test cases)

Rationale:
- SII regulatory compliance (correct legal scope)
- Contract adherence (EERGYGROUP B2B authorization)
- Security: Prevent out-of-scope document processing

Closes: P0-001
References: .codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md (DTE-SCOPE-001)"
```

**Criterio de Éxito:**
- ✅ Tests pasan (8/8 green)
- ✅ Upgrade módulo sin errores
- ✅ UI NO muestra tipos 39,41,46,70 en selection
- ✅ @dte-compliance aprueba alcance regulatorio

---

### SPRINT 2: P0-002 - Eliminar Fallback Hardcoded Tope AFP (CRÍTICO)

**Duración:** 1 hora  
**Agente:** @odoo-dev  
**Prioridad:** 🔴 P0 - CRÍTICO  
**Riesgo:** Incumplimiento legal laboral

#### Contexto del Problema

```
PROBLEMA:
- Tope AFP 2025: 83.1 UF (debe obtenerse dinámicamente)
- Código actual: Fallback hardcoded `81.6 * 38000` en regla salarial
- Violación: Máxima de Exactitud Económica (MAXIMAS_AUDITORIA.md §4)

EVIDENCIA:
data/hr_salary_rules_p1.xml:91-92
```

#### Archivos a Modificar

**1. `addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml`**

```xml
<!-- LÍNEA 87-95 (ANTES) -->
<record id="hr_salary_rule_afp_voluntary" model="hr.salary.rule">
    <field name="code">AFP_VOL</field>
    <field name="name">Cotización AFP Voluntaria</field>
    <field name="python_compute">
        tope_afp = contract.get_tope_afp() or 81.6  # UF
        tope_afp_pesos = tope_afp * payslip.get_uf_value()
        result = 81.6 * 38000  # FALLBACK HARDCODED ← PROBLEMA
    </field>
</record>

<!-- LÍNEA 87-100 (DESPUÉS) -->
<record id="hr_salary_rule_afp_voluntary" model="hr.salary.rule">
    <field name="code">AFP_VOL</field>
    <field name="name">Cotización AFP Voluntaria</field>
    <field name="python_compute">
        # Obtener tope AFP dinámicamente desde indicadores laborales
        tope_afp_record = env['hr.legal.cap'].search([
            ('concept', '=', 'tope_afp'),
            ('valid_from', '&lt;=', payslip.date_to),
            ('valid_to', '&gt;=', payslip.date_to),
        ], limit=1)
        
        if not tope_afp_record:
            raise UserError(
                "No se encontró el tope AFP vigente para la fecha %s. "
                "Configure los indicadores laborales en HR > Configuración > Topes Legales."
                % payslip.date_to
            )
        
        tope_afp_uf = tope_afp_record.value_uf  # 83.1 UF para 2025
        uf_value = payslip.get_uf_value()
        tope_afp_pesos = tope_afp_uf * uf_value
        
        # Cálculo cotización voluntaria (si aplica)
        base_afp_vol = max(0, contract.wage - tope_afp_pesos)
        result = base_afp_vol * (contract.afp_voluntary_rate / 100.0)
    </field>
</record>
```

**2. Crear Indicador Obligatorio en Data (Post-Install Hook)**

**Archivo:** `addons/localization/l10n_cl_hr_payroll/data/hr_legal_caps_2025.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <data noupdate="1">
        <!-- Tope AFP 2025: 83.1 UF (Ley 21.133) -->
        <record id="legal_cap_tope_afp_2025" model="hr.legal.cap">
            <field name="concept">tope_afp</field>
            <field name="name">Tope Imponible AFP 2025</field>
            <field name="value_uf">83.1</field>
            <field name="valid_from">2025-01-01</field>
            <field name="valid_to">2025-12-31</field>
            <field name="description">
                Tope imponible AFP según Ley 21.133 Art. 16.
                Actualizado anualmente según IPC (Superintendencia de Pensiones).
            </field>
        </record>
        
        <!-- Tope Salud 2025: 83.1 UF (mismo que AFP) -->
        <record id="legal_cap_tope_isapre_2025" model="hr.legal.cap">
            <field name="concept">tope_isapre</field>
            <field name="name">Tope Imponible Salud 2025</field>
            <field name="value_uf">83.1</field>
            <field name="valid_from">2025-01-01</field>
            <field name="valid_to">2025-12-31</field>
            <field name="description">
                Tope imponible cotización salud (Ley 18.933).
                Equivalente al tope AFP para 2025.
            </field>
        </record>
    </data>
</odoo>
```

**3. Actualizar `__manifest__.py`**

```python
# Línea ~50 (ANTES):
'data': [
    'security/ir.model.access.csv',
    'data/hr_salary_rules_p1.xml',
    'views/hr_payslip_views.xml',
],

# Línea ~50 (DESPUÉS):
'data': [
    'security/ir.model.access.csv',
    'data/hr_legal_caps_2025.xml',  # ← NUEVO: Indicadores obligatorios
    'data/hr_salary_rules_p1.xml',
    'views/hr_payslip_views.xml',
],
```

#### Tests Obligatorios

**Archivo:** `addons/localization/l10n_cl_hr_payroll/tests/test_tope_afp_dynamic.py`

```python
# -*- coding: utf-8 -*-
from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from odoo.exceptions import UserError
from datetime import date


@tagged('post_install', '-at_install', 'payroll_legal')
class TestTopeAFPDynamic(TransactionCase):
    """
    Test AFP cap is obtained dynamically from hr.legal.cap.
    
    No hardcoded fallbacks allowed (Máxima de Exactitud Económica).
    """

    def setUp(self):
        super().setUp()
        self.Payslip = self.env['hr.payslip']
        self.LegalCap = self.env['hr.legal.cap']
        
        # Create test employee + contract
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee AFP',
        })
        self.contract = self.env['hr.contract'].create({
            'name': 'Contract Test AFP',
            'employee_id': self.employee.id,
            'wage': 3500000,  # Above AFP cap
            'date_start': date(2025, 1, 1),
        })

    def test_tope_afp_exists_2025(self):
        """Ensure AFP cap record exists for 2025."""
        cap = self.LegalCap.search([
            ('concept', '=', 'tope_afp'),
            ('valid_from', '<=', '2025-06-01'),
            ('valid_to', '>=', '2025-06-01'),
        ], limit=1)
        
        self.assertTrue(cap, "AFP cap for 2025 must exist")
        self.assertEqual(cap.value_uf, 83.1, "AFP cap 2025 must be 83.1 UF")

    def test_payslip_uses_dynamic_afp_cap(self):
        """Payslip calculation must use dynamic AFP cap (no fallback)."""
        payslip = self.Payslip.create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 6, 1),
            'date_to': date(2025, 6, 30),
        })
        
        payslip.compute_sheet()
        
        # Find AFP_VOL salary rule line
        afp_vol_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP_VOL')
        self.assertTrue(afp_vol_line, "AFP_VOL line must exist")
        
        # Verify it used dynamic cap (not hardcoded 81.6)
        # Expected: (3,500,000 - 83.1*UF) * voluntary_rate
        # If UF=38000, tope=3,157,800 → base_vol=342,200
        uf_value = payslip.get_uf_value()
        expected_tope = 83.1 * uf_value
        
        self.assertGreater(afp_vol_line.amount, 0)
        self.assertNotEqual(int(expected_tope), int(81.6 * 38000),
                            "Must NOT use hardcoded 81.6 fallback")

    def test_error_if_no_afp_cap_configured(self):
        """Raise UserError if AFP cap is missing (no silent fallback)."""
        # Delete AFP cap
        self.LegalCap.search([('concept', '=', 'tope_afp')]).unlink()
        
        payslip = self.Payslip.create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 6, 1),
            'date_to': date(2025, 6, 30),
        })
        
        with self.assertRaises(UserError) as cm:
            payslip.compute_sheet()
        
        self.assertIn("No se encontró el tope AFP", str(cm.exception))
```

#### Validación y Deployment

```bash
# 1. Tests
docker exec -it odoo19_web_1 pytest \
  addons/localization/l10n_cl_hr_payroll/tests/test_tope_afp_dynamic.py \
  -v --tb=short

# 2. Upgrade módulo (carga hr_legal_caps_2025.xml)
docker exec -it odoo19_web_1 odoo -c /etc/odoo/odoo.conf \
  -d odoo19 -u l10n_cl_hr_payroll --stop-after-init

# 3. Verificar en UI: HR > Configuración > Topes Legales
# Debe existir: "Tope Imponible AFP 2025" = 83.1 UF

# 4. Commit
git add addons/localization/l10n_cl_hr_payroll/
git commit -m "fix(l10n_cl_hr_payroll): eliminate hardcoded AFP cap fallback

BREAKING CHANGE: AFP cap must be configured in hr.legal.cap (mandatory)

- Remove fallback: result = 81.6 * 38000 (hardcoded)
- Add dynamic lookup from hr.legal.cap model
- Raise UserError if cap is missing (no silent fallback)
- Add hr_legal_caps_2025.xml with AFP/Salud caps (83.1 UF)
- Add tests: test_tope_afp_dynamic.py (3 test cases)

Rationale:
- Compliance with Máxima de Exactitud Económica
- Legal accuracy (AFP cap changes annually per Superintendencia)
- Zero tolerance for hardcoded legal constants

Closes: P0-002
References: AUDITORIA_NOMINA_VERIFICACION_P0_P1_2025-11-07.md (H-001)"
```

**Criterio de Éxito:**
- ✅ Tests pasan (3/3 green)
- ✅ Indicador AFP 2025 cargado en DB (83.1 UF)
- ✅ UserError si falta indicador (no fallback silencioso)
- ✅ Nómina calcula correctamente con tope dinámico

---

### SPRINT 3: P0-003 - Security Access LRE Wizard (CRÍTICO)

**Duración:** 30 minutos  
**Agente:** @odoo-dev  
**Prioridad:** 🔴 P0 - CRÍTICO  
**Riesgo:** Security breach

#### Archivos a Modificar

**1. `addons/localization/l10n_cl_hr_payroll/security/ir.model.access.csv`**

```csv
# ANTES (última línea):
access_hr_legal_cap_manager,access_hr_legal_cap_manager,model_hr_legal_cap,hr_payroll.group_hr_payroll_manager,1,1,1,1

# DESPUÉS (añadir 2 líneas):
access_hr_legal_cap_manager,access_hr_legal_cap_manager,model_hr_legal_cap,hr_payroll.group_hr_payroll_manager,1,1,1,1
access_hr_lre_wizard_user,access_hr_lre_wizard_user,model_hr_lre_wizard,hr_payroll.group_hr_payroll_user,1,0,0,0
access_hr_lre_wizard_manager,access_hr_lre_wizard_manager,model_hr_lre_wizard,hr_payroll.group_hr_payroll_manager,1,1,1,1
```

**Explicación:**
- `group_hr_payroll_user`: Read-only (generar LRE, no modificar modelo)
- `group_hr_payroll_manager`: Full access (administrar wizard)

#### Tests Obligatorios

```python
# tests/test_lre_wizard_security.py
def test_user_can_generate_lre(self):
    """Payroll user can generate LRE (read access)."""
    user = self.env['res.users'].create({
        'name': 'Payroll User',
        'login': 'payroll_user',
        'groups_id': [(6, 0, [self.env.ref('hr_payroll.group_hr_payroll_user').id])],
    })
    
    wizard = self.env['hr.lre.wizard'].sudo(user).create({
        'date_from': '2025-06-01',
        'date_to': '2025-06-30',
    })
    
    self.assertTrue(wizard, "User must be able to create LRE wizard")

def test_user_cannot_delete_lre(self):
    """Payroll user cannot delete LRE records (security)."""
    user = self.env['res.users'].create({
        'name': 'Payroll User',
        'login': 'payroll_user',
        'groups_id': [(6, 0, [self.env.ref('hr_payroll.group_hr_payroll_user').id])],
    })
    
    wizard = self.env['hr.lre.wizard'].create({
        'date_from': '2025-06-01',
        'date_to': '2025-06-30',
    })
    
    with self.assertRaises(AccessError):
        wizard.sudo(user).unlink()
```

#### Commit

```bash
git add addons/localization/l10n_cl_hr_payroll/security/
git commit -m "fix(l10n_cl_hr_payroll): add security access for LRE wizard

- Add access_hr_lre_wizard_user (read-only for payroll users)
- Add access_hr_lre_wizard_manager (full access for managers)
- Add tests: test_lre_wizard_security.py (2 test cases)

Closes: P0-003
References: AUDITORIA_NOMINA_VERIFICACION_P0_P1_2025-11-07.md (H-002)"
```

---

### SPRINT 4: P0-004 - Dashboard KPIs Parametrizable (CRÍTICO)

**Duración:** 1 hora  
**Agente:** @odoo-dev  
**Objetivo:** Eliminar días hardcoded en KPIs dashboard DTE

#### Archivos a Modificar

**1. `addons/localization/l10n_cl_dte/models/dte_dashboard.py`**

```python
# ANTES:
def _compute_overdue_dtes(self):
    threshold = 8  # Hardcoded days

# DESPUÉS:
def _compute_overdue_dtes(self):
    ICP = self.env['ir.config_parameter'].sudo()
    threshold = int(ICP.get_param('l10n_cl_dte.dashboard_overdue_days', default=8))
```

**2. Crear Parámetros Sistema**

```xml
<!-- data/dte_config_parameters.xml -->
<odoo>
    <data noupdate="1">
        <record id="config_dashboard_overdue_days" model="ir.config_parameter">
            <field name="key">l10n_cl_dte.dashboard_overdue_days</field>
            <field name="value">8</field>
        </record>
        
        <record id="config_dashboard_pending_days" model="ir.config_parameter">
            <field name="key">l10n_cl_dte.dashboard_pending_days</field>
            <field name="value">3</field>
        </record>
    </data>
</odoo>
```

**3. Añadir Vista Configuración**

```xml
<!-- views/dte_config_settings_views.xml -->
<record id="view_dte_config_settings" model="ir.ui.view">
    <field name="name">DTE Configuration Settings</field>
    <field name="model">res.config.settings</field>
    <field name="inherit_id" ref="base.res_config_settings_view_form"/>
    <field name="arch" type="xml">
        <xpath expr="//div[@name='modules']" position="after">
            <h2>DTE Dashboard KPIs</h2>
            <div class="row mt16 o_settings_container">
                <div class="col-12 col-lg-6 o_setting_box">
                    <div class="o_setting_left_pane"/>
                    <div class="o_setting_right_pane">
                        <label for="dashboard_overdue_days"/>
                        <div class="text-muted">
                            Días para considerar DTE vencido en dashboard
                        </div>
                        <field name="dashboard_overdue_days"/>
                    </div>
                </div>
            </div>
        </xpath>
    </field>
</record>
```

#### Commit

```bash
git commit -m "fix(l10n_cl_dte): parametrize dashboard KPI thresholds

- Replace hardcoded days (8, 3) with ir.config_parameter
- Add dte_config_parameters.xml with defaults
- Add configuration UI in Settings > DTE
- Add tests: test_dashboard_config.py

Closes: P0-004
Improves: Operational flexibility"
```

---

### SPRINT 5: P1-001 a P1-004 (IMPORTANTE - Opcional según tiempo)

**Duración:** 8 horas total  
**Agentes:** @odoo-dev + @test-automation  
**Prioridad:** 🟡 P1 - IMPORTANTE

#### P1-001: i18n Translations (2h)

```bash
# Generar POT template
docker exec -it odoo19_web_1 odoo-bin \
  --i18n-export=l10n_cl_hr_payroll.pot \
  --modules=l10n_cl_hr_payroll \
  --language=es_CL

# Crear es_CL.po y en_US.po con traducciones wizard LRE
```

#### P1-002: RUT Validator Consistente (1h)

```python
# wizards/hr_lre_wizard.py
# ANTES:
def _validate_rut(self, rut):
    # Custom validation

# DESPUÉS:
from stdnum.cl import rut as stdnum_rut

def _validate_rut(self, rut):
    try:
        stdnum_rut.validate(rut)
        return stdnum_rut.format(rut)
    except Exception:
        raise ValidationError("RUT inválido")
```

#### P1-003: Duplicate Methods Elimination (3h)

```python
# Consolidar create_monthly_f29 en clase base
# Eliminar duplicados en subclases
# Refactor usando herencia limpia
```

#### P1-004: Dashboard Tests (4h)

```python
# tests/test_dte_dashboard.py
# - test_overdue_computation()
# - test_pending_invoices()
# - test_net_billing_calculation()
# - test_regulatory_kpis()
```

---

## 🎯 CRITERIOS DE ACEPTACIÓN GLOBALES

### Pre-Merge Checklist (OBLIGATORIO)

```bash
# 1. Tests Globales (≥80% coverage)
docker exec -it odoo19_web_1 pytest \
  addons/localization/ \
  --cov=addons/localization \
  --cov-report=html \
  --cov-fail-under=80 \
  -v

# 2. Lint (≤300 errors acceptable)
docker exec -it odoo19_web_1 pylint \
  addons/localization/l10n_cl_dte \
  addons/localization/l10n_cl_hr_payroll \
  --rcfile=.pylintrc

# 3. Odoo Tests (--test-enable)
docker exec -it odoo19_web_1 odoo \
  -c /etc/odoo/odoo.conf \
  --test-enable \
  --stop-after-init \
  -d odoo19_test \
  -u l10n_cl_dte,l10n_cl_hr_payroll

# 4. Manual Smoke Test
# - Instalar módulos en DB fresh
# - Crear nómina con tope AFP dinámico
# - Validar DTE solo muestra tipos B2B (33,34,52,56,61)
# - Verificar permisos LRE wizard

# 5. Coverage Report Review
open htmlcov/index.html
# Verificar: l10n_cl_dte ≥75%, l10n_cl_hr_payroll ≥90%
```

### Métricas de Éxito

| Métrica | Baseline | Target | Medición |
|---------|----------|--------|----------|
| **P0 Brechas Cerradas** | 4/4 pendientes | 4/4 resueltas | Manual |
| **P1 Brechas Cerradas** | 4/4 pendientes | ≥2/4 resueltas | Manual |
| **Test Coverage** | 75% DTE, 92% Payroll | ≥80% ambos | pytest-cov |
| **Lint Errors** | 279 (financial) | ≤300 | pylint |
| **Deployment Success** | N/A | 100% módulos | odoo --test-enable |
| **Rollback Capability** | N/A | Tag + SQL backup | git tag + pg_dump |

---

## 🚨 PROTOCOLO DE ERROR Y ROLLBACK

### Si Algo Sale Mal

```bash
# PASO 1: STOP - No continuar
git status  # Identificar archivos modificados

# PASO 2: Rollback a checkpoint
git reset --hard sprint0_backup_YYYYMMDD

# PASO 3: Restaurar DB (si necesario)
docker exec -i odoo19_db_1 psql -U odoo -d postgres -c "DROP DATABASE odoo19;"
docker exec -i odoo19_db_1 psql -U odoo -d postgres -c "CREATE DATABASE odoo19;"
docker exec -i odoo19_db_1 psql -U odoo -d odoo19 < .backup_consolidation/pre_sprint_YYYYMMDD_HHMMSS.sql

# PASO 4: Reportar a Senior Engineer
# - Descripción error
# - Output completo (logs, tracebacks)
# - Estado previo al error
```

### Errores Comunes y Soluciones

| Error | Causa | Solución |
|-------|-------|----------|
| **Module not found** | Path incorrecto | Verificar `addons/localization/` |
| **ValidationError en tests** | Data inconsistente | Limpiar DB test, recrear |
| **AccessError** | ir.model.access.csv mal formado | Verificar sintaxis CSV |
| **Import error stdnum** | Dependencia faltante | `pip install stdnum` en container |
| **NameError en salary rule** | Variable undefined | Revisar python_compute scope |

---

## 📚 REFERENCIAS Y CONOCIMIENTO BASE

### Documentos de Auditoría (Obligatorio Leer)

1. **`.codex/REPORTE_FINAL_HALLAZGOS_SOLUCIONES.md`** (842 líneas)
   - Hallazgos confirmados P0/P1
   - Soluciones técnicas detalladas
   - Evidencia reproducible

2. **`AUDITORIA_NOMINA_VERIFICACION_P0_P1_2025-11-07.md`** (717 líneas)
   - Verificación exhaustiva nómina
   - 14 reglas salariales validadas
   - Coverage 92%+ confirmado

3. **`docs/ai-service/ANALISIS_MEJORAS_MICROSERVICIO_AI_SENIOR_2025-11-09.md`** (1,150 líneas)
   - AI service architecture review
   - P0/P1/P2 roadmap (12 weeks)
   - ROI 303% calculado

### Knowledge Base Agentes

- `.claude/agents/knowledge/sii_regulatory_context.md` - SII scope, DTE types
- `.claude/agents/knowledge/odoo19_patterns.md` - Odoo 19 patterns (NOT 11-16!)
- `.claude/agents/knowledge/project_architecture.md` - EERGYGROUP architecture

### Máximas de Auditoría

```
Máxima 1: Evidencia Reproducible
→ Tests > Manual verification

Máxima 2: Correctitud Legal
→ SII regulations > business convenience

Máxima 3: Exactitud Económica
→ Dynamic indicators > hardcoded constants

Máxima 4: Zero Tolerance Hardcoding
→ Configuration > code changes

Máxima 5: Security First
→ ir.model.access.csv > implicit permissions

Máxima 6: Rollback Capability
→ Checkpoint + backup > hope
```

---

## 🎓 INSTRUCCIONES PARA EL AGENTE EJECUTOR

### Tu Rol (@odoo-dev)

Eres el **Ingeniero Senior de Desarrollo Odoo 19 CE** especializado en localización chilena. Tu misión:

1. **Leer completo este prompt** antes de empezar (2,327 líneas)
2. **Ejecutar SPRINT 0** (backup + checkpoint) - OBLIGATORIO
3. **Implementar P0-001 a P0-004** en orden secuencial
4. **Validar con tests** después de cada sprint
5. **Commitear atómicamente** con mensajes conventional commits
6. **Reportar avance** a Senior Engineer (coordinador)

### Tu Metodología

**Evidence-Based:**
- ✅ Usa evidencia de auditorías (.codex/, AUDITORIA_*.md)
- ✅ Cita líneas específicas de código (file:line)
- ❌ NO improvises soluciones sin evidencia

**Test-Driven:**
- ✅ Escribe tests ANTES o DURANTE implementación
- ✅ Coverage ≥80% en archivos modificados
- ❌ NO mergees sin tests pasando

**Rollback-Safe:**
- ✅ Checkpoint Git + SQL backup antes de empezar
- ✅ Commits atómicos (1 brecha = 1 commit)
- ❌ NO hagas mass commits ("fix everything")

### Tu Output Esperado

**Por cada Sprint:**
```markdown
## SPRINT N: [Título]

### Cambios Implementados
- [x] Archivo 1: Descripción cambio
- [x] Archivo 2: Descripción cambio

### Tests Añadidos
- [x] test_feature.py: 3 test cases (all green)

### Validación
- [x] pytest: 8/8 passed
- [x] pylint: 0 new errors
- [x] odoo --test-enable: success

### Commit SHA
- `abc123de` - "fix(module): conventional commit message"

### Próximo Sprint
- SPRINT N+1 listo para ejecutar
```

---

## 🚀 EJECUCIÓN: ¡ADELANTE!

**Agente @odoo-dev:** Confirma que has leído este prompt completo y procede con:

1. **SPRINT 0:** Backup + checkpoint (30 min)
2. **SPRINT 1:** P0-001 DTE Scope (2h)
3. **SPRINT 2:** P0-002 AFP Fallback (1h)
4. **SPRINT 3:** P0-003 LRE Security (30min)
5. **SPRINT 4:** P0-004 Dashboard Config (1h)

**Total P0:** ~5 horas → Production-Ready

**Coordinador (Senior Engineer):** Estaré monitoreando avance. Reporta después de cada sprint.

---

**Versión:** 3.0 Professional Grade  
**Última Actualización:** 2025-11-09 02:00 CLT  
**Estado:** ✅ READY FOR EXECUTION  
**Agente Asignado:** @odoo-dev (Sonnet)  
**Prioridad:** 🔴 CRÍTICA

---

# 🎯 END OF PROMPT - BEGIN EXECUTION
