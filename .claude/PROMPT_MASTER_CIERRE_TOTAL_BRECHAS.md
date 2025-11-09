# 🎯 PROMPT MASTER - CIERRE TOTAL DE BRECHAS
## Orquestación Profesional Completa | Zero Improvisations | Enterprise-Grade

**Fecha Emisión:** 2025-11-09 00:20 CLT
**Ingeniero Senior:** Líder Técnico Orquestación
**Coordinador:** Senior Engineer (Orchestrator)
**Agentes Especializados:** 5 agents (orquestación multi-agente)
**Branch:** `feat/cierre_total_brechas_profesional`
**Prioridad:** 🔴 CRÍTICA
**Metodología:** Evidence-based, Zero patches, Full testing
**Timeline:** 5 sprints (2 semanas)
**Status:** 📋 READY FOR EXECUTION

---

## 🤖 ORQUESTACIÓN DE AGENTES ESPECIALIZADOS

### Equipo de Agentes Disponibles

Este proyecto cuenta con **5 agentes especializados** configurados en `.claude/agents/`:

| Agente | Modelo | Especialización | Herramientas |
|--------|--------|-----------------|--------------|
| **@odoo-dev** | Sonnet | Odoo 19 CE, l10n_cl_dte, Chilean localization | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch |
| **@dte-compliance** | Sonnet | SII regulations, DTE validation, tax compliance | Read, Grep, WebFetch, WebSearch, Glob |
| **@test-automation** | Haiku | Testing, CI/CD, quality assurance | Bash, Read, Write, Edit, Grep, Glob |
| **@docker-devops** | Sonnet | Docker, DevOps, production deployment | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch |
| **@ai-fastapi-dev** | Sonnet | AI/ML, FastAPI, Claude API, microservices | Read, Write, Edit, Bash, Glob, Grep, WebFetch, WebSearch |

### Base de Conocimiento Compartida

**CRÍTICO:** Todos los agentes tienen acceso a:
- `.claude/agents/knowledge/sii_regulatory_context.md` - SII compliance, DTE types scope
- `.claude/agents/knowledge/odoo19_patterns.md` - Odoo 19 patterns (NOT 11-16!)
- `.claude/agents/knowledge/project_architecture.md` - EERGYGROUP architecture

### Asignación de Agentes por Sprint

```yaml
sprint_0_preparacion:
  coordinador: Senior Engineer
  ejecutor: @docker-devops
  razon: Backup, branch creation, baseline setup

sprint_1_p0_bloqueantes:
  coordinador: Senior Engineer
  ejecutor_principal: @odoo-dev
  soporte_testing: @test-automation
  validador_compliance: @dte-compliance (validación final)
  razon: Fixes Odoo 19 CE compatibility (hr_contract stub, Monetary fields)

sprint_2_p1_quick_wins:
  coordinador: Senior Engineer
  ejecutor: @odoo-dev
  validador: @dte-compliance (scope DTE EERGYGROUP)
  razon: Dashboard fix + DTE scope alignment

sprint_3_validacion_rut:
  coordinador: Senior Engineer
  ejecutor: @odoo-dev
  validador_compliance: @dte-compliance (modulo 11, SII XML formats)
  ejecutor_tests: @test-automation
  razon: Helper RUT centralizado con validación SII

sprint_4_libs_pure_python:
  coordinador: Senior Engineer
  ejecutor: @odoo-dev
  validador_arquitectura: @docker-devops (dependency injection patterns)
  ejecutor_tests: @test-automation (Pure Python tests)
  razon: Refactorizar libs/ sin ORM dependencies

sprint_5_ci_cd_docs:
  coordinador: Senior Engineer
  ejecutor_ci_cd: @docker-devops (workflows, coverage)
  ejecutor_docs: @odoo-dev (actualizar docstrings)
  ejecutor_tests: @test-automation (coverage real)
  razon: CI/CD multi-módulo + docs Odoo 19
```

### Protocolo de Coordinación

**Senior Engineer (tú):**
1. Asigna sprint a agente especializado
2. Provee contexto específico del sprint
3. Valida deliverables vs DoD
4. Coordina handoff entre agentes si necesario
5. Aprueba commits antes de push

**Agentes Especializados:**
1. Consultan knowledge base ANTES de implementar
2. Ejecutan tasks según su especialización
3. Generan tests (con @test-automation si necesario)
4. Reportan al coordinador al completar
5. NO proceden a siguiente sprint sin aprobación

**Ejemplo Invocación:**
```
@odoo-dev ejecuta SPRINT 1 según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS.md
Contexto: Resolver 3 hallazgos P0 bloqueantes instalabilidad l10n_cl_hr_payroll
Knowledge base: Revisa odoo19_patterns.md para stub hr.contract CE compatible
DoD: Módulo state=installed, 8 tests PASS, commit estructurado
```

---

## 📊 RESUMEN EJECUTIVO

### Consolidación de Hallazgos Validados

Este PROMPT consolida **11 hallazgos críticos** identificados y validados por múltiples agentes:

**Fuente 1: Agente Desarrollador (FASE 0 - Ley 21.735)**
- 3 hallazgos P0 (bloqueantes instalabilidad Odoo 19 CE)

**Fuente 2: Agente Codex (Auditoría Calidad)**
- 6 hallazgos P1 (alta prioridad, no bloqueantes)
- 1 hallazgo P2 (mejora documental)

**Fuente 3: Ingeniero Senior (Validación Objetiva)**
- Rectificación Hallazgo #1 con scope real EERGYGROUP
- Eliminación Hallazgo H4 (_sql_constraints - refutado)

### Métricas Consolidadas

```yaml
hallazgos_total: 11
  p0_bloqueantes: 3      # Ley 21.735 instalabilidad
  p1_altos: 6            # Calidad código, validaciones
  p2_mejoras: 1          # Documentación
  refutados: 1           # _sql_constraints (correcto en Odoo 19)

esfuerzo_estimado: 48 horas
sprints: 5
timeline: 2 semanas
coverage_target: ">= 90%"
tests_nuevos: 40+
archivos_modificados: 25+
```

### Priorización Ejecutiva

| Prioridad | Hallazgos | Esfuerzo | Timeline |
|-----------|-----------|----------|----------|
| 🔴 **P0** | 3 | 4h | Sprint 1 (2 días) |
| 🟡 **P1** | 6 | 36h | Sprints 2-4 (8 días) |
| 🟢 **P2** | 1 | 2h | Sprint 5 (2 días) |
| **TOTAL** | **10** | **42h** | **12 días** |

---

## 🎯 OBJETIVOS DEL CIERRE TOTAL

### Objetivo General

**Cerrar el 100% de las brechas identificadas mediante fixes profesionales, robustos, testeados y sin improvisaciones, alcanzando estándares enterprise-grade para producción.**

### Objetivos Específicos Medibles

| ID | Objetivo | Métrica Éxito | Prioridad |
|---|---|---|---|
| OBJ-1 | Módulo l10n_cl_hr_payroll instalable Odoo 19 CE | state=installed, 0 errors | P0 |
| OBJ-2 | Alcance DTE alineado con scope EERGYGROUP | 6 tipos válidos (no 9) | P1 |
| OBJ-3 | Validación RUT normaliza prefijo CL | 100% RUTs válidos aceptados | P1 |
| OBJ-4 | Librerías libs/ Pure Python | 0 imports odoo en libs/ | P1 |
| OBJ-5 | Dashboard analytics sin errores runtime | 0 FieldNotFound exceptions | P1 |
| OBJ-6 | DTE 34 funcionalidad completa | Generación real, no placeholder | P1 |
| OBJ-7 | CI/CD cubre 3 módulos | Workflows extendidos | P1 |
| OBJ-8 | Documentación actualizada Odoo 19 | 0 referencias Odoo 18 | P2 |
| OBJ-9 | Coverage ≥ 90% | Todos los módulos | ALL |
| OBJ-10 | 0 warnings críticos | Pylint, Flake8 clean | ALL |

### Criterios Aceptación Global (Gate Review)

```yaml
codigo:
  syntax_errors: 0
  critical_warnings: 0
  deprecations_used: 0
  enterprise_dependencies_removed: TRUE
  pure_python_libs: TRUE

instalabilidad:
  l10n_cl_hr_payroll: INSTALLED
  l10n_cl_dte: INSTALLED
  l10n_cl_financial_reports: INSTALLED
  install_errors: 0
  upgrade_errors: 0

testing:
  tests_executed: ">= 100"
  tests_pass_rate: 100%
  tests_fail: 0
  tests_error: 0
  coverage_overall: ">= 90%"
  coverage_critical_paths: 100%

validaciones:
  rut_validation_cl_prefix: PASS
  dte_types_scope: PASS
  monetary_fields: PASS
  sql_constraints: VALID

ci_cd:
  workflows_extended: 3 modules
  jobs_per_module: TRUE
  coverage_real_generated: TRUE

documentacion:
  odoo_version_refs: "19.0"
  changelog_updated: TRUE
  readme_updated: TRUE
  tests_documented: TRUE
```

---

## 🏗️ ESTRUCTURA DE SPRINTS

### SPRINT 0: Preparación (2h)

**Agente Responsable:** `@docker-devops`
**Coordinador:** Senior Engineer
**Objetivo:** Crear branch, backup, setup entorno

**Invocación:**
```
@docker-devops ejecuta SPRINT 0 - Preparación según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS.md

Tasks:
1. Crear branch feat/cierre_total_brechas_profesional
2. Backup DB completo (pg_dump)
3. Generar baseline compliance pre-fixes
4. Setup coverage tracking
5. Documentar estado inicial

Knowledge base: Revisa project_architecture.md para estructura deployment
DoD: Branch creado, backup generado, baseline guardado
Timeline: 2h
```

**Tasks:**
1. Crear branch `feat/cierre_total_brechas_profesional`
2. Backup DB completo
3. Generar baseline compliance pre-fixes
4. Setup coverage tracking
5. Documentar estado inicial

**Deliverables:**
- ✅ Branch creado
- ✅ Backup: `.backup_consolidation/pre_cierre_brechas_$(date).sql`
- ✅ Baseline: `.compliance/baseline_pre_cierre_$(date).json`
- ✅ Coverage inicial medido

**DoD:**
```bash
# Verificar branch
git branch | grep "feat/cierre_total_brechas_profesional"

# Verificar backup
ls -lh .backup_consolidation/pre_cierre_brechas_*.sql

# Verificar baseline
cat .compliance/baseline_pre_cierre_*.json | jq '.modules | length'
# Expected: 3 (dte, payroll, financial_reports)
```

---

### SPRINT 1: P0 Bloqueantes - Ley 21.735 (4h)

**Agente Principal:** `@odoo-dev`
**Soporte Testing:** `@test-automation`
**Validador Final:** `@dte-compliance`
**Coordinador:** Senior Engineer

**Invocación:**
```
@odoo-dev ejecuta SPRINT 1 - P0 Bloqueantes según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS.md

Contexto: Resolver 3 hallazgos P0 bloqueantes instalabilidad l10n_cl_hr_payroll Odoo 19 CE
- H1: Campo company_currency_id inexistente (3 modelos)
- H2: 32 campos Monetary con currency_field incorrecto
- H3: Dependencia hr_contract Enterprise (crear stub CE)

Knowledge base:
- odoo19_patterns.md: Stub CE patterns, @api.constrains
- sii_regulatory_context.md: Chilean payroll compliance
- project_architecture.md: EERGYGROUP deployment

Tasks: Ver TASK 1.1-1.4 en PROMPT detallado
DoD: Módulo state=installed, 8 tests PASS, commit estructurado
Timeline: 4h

Colaboración:
- @test-automation: Generar tests stub CE + Monetary fields (Task 1.1, 1.2)
- @dte-compliance: Validar compliance Ley 21.735 post-instalación
```

**Objetivo:** Resolver 3 hallazgos P0 que bloquean instalabilidad l10n_cl_hr_payroll

#### TASK 1.1: Eliminar Dependencia hr_contract Enterprise (1.5h)

**Hallazgo:** H3 (Agente Desarrollador)
**Problema:** Módulo depende de `hr_contract` (Enterprise only)
**Solución:** Crear stub CE compatible

**Archivos:**
1. `addons/localization/l10n_cl_hr_payroll/__manifest__.py`
2. `addons/localization/l10n_cl_hr_payroll/models/hr_contract_stub_ce.py` (NEW)
3. `addons/localization/l10n_cl_hr_payroll/models/__init__.py`

**Implementación:**

**Paso 1.1.1: Actualizar manifest**
```python
# addons/localization/l10n_cl_hr_payroll/__manifest__.py

# ANTES (línea 61-68):
'depends': [
    'base',
    'hr',
    'hr_contract',  # ❌ Enterprise only
    'account',
    'l10n_cl',
],

# DESPUÉS:
'depends': [
    'base',
    'hr',                    # ✅ CE base
    # 'hr_contract' REMOVED - stub created in models/hr_contract_stub_ce.py
    'account',               # ✅ CE base
    'l10n_cl',               # ✅ Localización Chile
],
```

**Paso 1.1.2: Crear stub hr.contract CE**
```python
# addons/localization/l10n_cl_hr_payroll/models/hr_contract_stub_ce.py (NUEVO)

# -*- coding: utf-8 -*-
"""
hr.contract Stub for Odoo 19 Community Edition
==============================================

Stub mínimo de hr.contract para compatibilidad CE.

En Odoo Enterprise, hr_contract es módulo separado.
En CE, este stub provee funcionalidad básica requerida por nómina chilena.

IMPORTANTE: Solo campos mínimos para l10n_cl_hr_payroll.
            Para funcionalidad completa, usar Odoo Enterprise.

Author: EERGYGROUP
License: LGPL-3
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class HrContract(models.Model):
    """
    Stub básico hr.contract para Odoo 19 CE.

    Provee campos mínimos requeridos por nómina chilena.
    Compatible con l10n_cl_hr_payroll.
    """
    _name = 'hr.contract'
    _description = 'Contrato Laboral (CE Stub)'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'date_start desc, id desc'

    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════

    name = fields.Char(
        string='Nombre Contrato',
        required=True,
        tracking=True,
        help='Referencia del contrato (ej: "Contrato Ingeniero Civil 2025")'
    )

    active = fields.Boolean(
        string='Activo',
        default=True,
        help='Desactivar para archivar contrato sin eliminar'
    )

    employee_id = fields.Many2one(
        'hr.employee',
        string='Empleado',
        required=True,
        tracking=True,
        ondelete='restrict',
        index=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        tracking=True,
        index=True
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        required=True,
        default=lambda self: self.env.company.currency_id,
        tracking=True
    )

    # ═══════════════════════════════════════════════════════════
    # DATOS SALARIALES
    # ═══════════════════════════════════════════════════════════

    wage = fields.Monetary(
        string='Sueldo Base',
        required=True,
        currency_field='currency_id',
        tracking=True,
        help='Remuneración mensual bruta (base cálculo nómina)'
    )

    # ═══════════════════════════════════════════════════════════
    # PERÍODO CONTRACTUAL
    # ═══════════════════════════════════════════════════════════

    date_start = fields.Date(
        string='Fecha Inicio',
        required=True,
        tracking=True,
        default=fields.Date.today,
        index=True
    )

    date_end = fields.Date(
        string='Fecha Término',
        tracking=True,
        help='Dejar vacío para contrato indefinido',
        index=True
    )

    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('draft', 'Borrador'),
        ('open', 'Vigente'),
        ('pending', 'Pendiente'),
        ('close', 'Cerrado'),
        ('cancel', 'Cancelado'),
    ], string='Estado', default='draft', tracking=True, required=True, index=True)

    # ═══════════════════════════════════════════════════════════
    # RELACIONES
    # ═══════════════════════════════════════════════════════════

    payslip_ids = fields.One2many(
        'hr.payslip',
        'contract_id',
        string='Liquidaciones',
        readonly=True
    )

    payslip_count = fields.Integer(
        string='N° Liquidaciones',
        compute='_compute_payslip_count',
        store=True
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTES
    # ═══════════════════════════════════════════════════════════

    @api.depends('payslip_ids')
    def _compute_payslip_count(self):
        """Contar liquidaciones del contrato"""
        for contract in self:
            contract.payslip_count = len(contract.payslip_ids)

    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════

    @api.constrains('date_start', 'date_end')
    def _check_dates(self):
        """Validar coherencia de fechas"""
        for contract in self:
            if contract.date_end and contract.date_start:
                if contract.date_end < contract.date_start:
                    raise ValidationError(
                        _('La fecha de término debe ser posterior a la fecha de inicio.')
                    )

    @api.constrains('wage')
    def _check_wage_positive(self):
        """Validar sueldo positivo"""
        for contract in self:
            if contract.wage <= 0:
                raise ValidationError(
                    _('El sueldo base debe ser mayor a cero.')
                )

    @api.constrains('employee_id', 'date_start', 'date_end', 'state')
    def _check_overlap_contracts(self):
        """Validar que no haya contratos vigentes superpuestos para mismo empleado"""
        for contract in self:
            if contract.state not in ('open', 'pending'):
                continue

            domain = [
                ('employee_id', '=', contract.employee_id.id),
                ('state', 'in', ('open', 'pending')),
                ('id', '!=', contract.id),
            ]

            # Verificar superposición de fechas
            if contract.date_end:
                domain += [
                    '|',
                    '&',
                    ('date_start', '<=', contract.date_end),
                    '|',
                    ('date_end', '>=', contract.date_start),
                    ('date_end', '=', False),
                    '&',
                    ('date_start', '>=', contract.date_start),
                    ('date_start', '<=', contract.date_end),
                ]
            else:
                domain += [
                    '|',
                    ('date_end', '>=', contract.date_start),
                    ('date_end', '=', False),
                ]

            overlapping = self.search(domain, limit=1)
            if overlapping:
                raise ValidationError(_(
                    'Ya existe un contrato vigente para el empleado %s '
                    'en el período %s - %s que se superpone con este contrato.'
                ) % (
                    contract.employee_id.name,
                    contract.date_start,
                    contract.date_end or 'Indefinido'
                ))

    # ═══════════════════════════════════════════════════════════
    # MÉTODOS NEGOCIO
    # ═══════════════════════════════════════════════════════════

    def action_open(self):
        """Activar contrato"""
        self.ensure_one()
        self.write({'state': 'open'})
        _logger.info(f"Contrato {self.name} activado para empleado {self.employee_id.name}")
        return True

    def action_close(self):
        """Cerrar contrato"""
        self.ensure_one()
        self.write({
            'state': 'close',
            'date_end': fields.Date.today() if not self.date_end else self.date_end
        })
        _logger.info(f"Contrato {self.name} cerrado para empleado {self.employee_id.name}")
        return True

    @api.model_create_multi
    def create(self, vals_list):
        """Log creación contratos"""
        contracts = super(HrContract, self).create(vals_list)
        for contract in contracts:
            _logger.info(
                f"Contrato CE creado: {contract.name} "
                f"para empleado {contract.employee_id.name} "
                f"({contract.date_start} - {contract.date_end or 'Indefinido'})"
            )
        return contracts

    def write(self, vals):
        """Log modificaciones importantes"""
        result = super(HrContract, self).write(vals)
        if 'state' in vals or 'wage' in vals or 'date_end' in vals:
            for contract in self:
                _logger.info(
                    f"Contrato CE modificado: {contract.name} "
                    f"(Estado: {contract.state}, Sueldo: {contract.wage})"
                )
        return result
```

**Paso 1.1.3: Agregar import**
```python
# addons/localization/l10n_cl_hr_payroll/models/__init__.py

# Agregar al FINAL del archivo (después de otros imports):
from . import hr_contract_stub_ce  # CE compatibility stub
```

**Tests Task 1.1:**
```python
# tests/test_hr_contract_stub_ce.py (NUEVO)

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


class TestHrContractStubCE(TransactionCase):
    """Tests para stub hr.contract CE"""

    def setUp(self):
        super().setUp()
        self.Employee = self.env['hr.employee']
        self.Contract = self.env['hr.contract']

        self.employee = self.Employee.create({
            'name': 'Test Employee Contract Stub',
        })

    def test_contract_create_basic(self):
        """Test creación contrato básico"""
        contract = self.Contract.create({
            'name': 'Test Contract',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': '2025-01-01',
        })

        self.assertEqual(contract.state, 'draft')
        self.assertEqual(contract.wage, 1500000)
        self.assertTrue(contract.currency_id)

    def test_contract_wage_positive_constraint(self):
        """Test constraint sueldo positivo"""
        with self.assertRaises(ValidationError):
            self.Contract.create({
                'name': 'Invalid Contract',
                'employee_id': self.employee.id,
                'wage': -1000,
                'date_start': '2025-01-01',
            })

    def test_contract_dates_coherence(self):
        """Test coherencia fechas"""
        with self.assertRaises(ValidationError):
            self.Contract.create({
                'name': 'Invalid Dates Contract',
                'employee_id': self.employee.id,
                'wage': 1500000,
                'date_start': '2025-12-31',
                'date_end': '2025-01-01',
            })

    def test_contract_overlap_prevention(self):
        """Test prevención contratos superpuestos"""
        # Crear primer contrato vigente
        contract1 = self.Contract.create({
            'name': 'Contract 1',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': '2025-01-01',
            'date_end': '2025-12-31',
            'state': 'open',
        })

        # Intentar crear contrato superpuesto
        with self.assertRaises(ValidationError):
            self.Contract.create({
                'name': 'Overlapping Contract',
                'employee_id': self.employee.id,
                'wage': 1600000,
                'date_start': '2025-06-01',
                'date_end': '2026-06-01',
                'state': 'open',
            })

    def test_contract_actions(self):
        """Test acciones abrir/cerrar contrato"""
        contract = self.Contract.create({
            'name': 'Test Actions Contract',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': '2025-01-01',
        })

        # Activar
        contract.action_open()
        self.assertEqual(contract.state, 'open')

        # Cerrar
        contract.action_close()
        self.assertEqual(contract.state, 'close')
        self.assertTrue(contract.date_end)
```

**DoD Task 1.1:**
- ✅ Dependencia `hr_contract` eliminada del manifest
- ✅ Stub `hr_contract_stub_ce.py` creado (200+ LOC)
- ✅ Import agregado en `models/__init__.py`
- ✅ Tests stub CE: 5/5 PASS
- ✅ Syntax Python 100% válido

---

#### TASK 1.2: Crear Campo company_currency_id (1h)

**Hallazgo:** H1 (Agente Desarrollador)
**Problema:** 3 modelos usan `company_currency_id` que no existe
**Solución:** Agregar campo related en modelos afectados

**Archivos:**
1. `models/hr_salary_rule_aportes_empleador.py`
2. `models/hr_salary_rule_asignacion_familiar.py`
3. `models/hr_salary_rule_gratificacion.py`

**Implementación:**

**Paso 1.2.1: Agregar company_currency_id en modelo 1**
```python
# models/hr_salary_rule_aportes_empleador.py

# Buscar la definición de company_id (aproximadamente línea 35)
# Agregar DESPUÉS de company_id:

company_currency_id = fields.Many2one(
    'res.currency',
    string='Moneda Compañía',
    related='company_id.currency_id',
    store=True,
    readonly=True,
    help='Moneda de la compañía para campos Monetary'
)
```

**Paso 1.2.2: Repetir en modelo 2**
```python
# models/hr_salary_rule_asignacion_familiar.py

# Buscar company_id
# Agregar DESPUÉS:

company_currency_id = fields.Many2one(
    'res.currency',
    string='Moneda Compañía',
    related='company_id.currency_id',
    store=True,
    readonly=True,
    help='Moneda de la compañía para campos Monetary'
)
```

**Paso 1.2.3: Repetir en modelo 3**
```python
# models/hr_salary_rule_gratificacion.py

# Buscar company_id
# Agregar DESPUÉS:

company_currency_id = fields.Many2one(
    'res.currency',
    string='Moneda Compañía',
    related='company_id.currency_id',
    store=True,
    readonly=True,
    help='Moneda de la compañía para campos Monetary'
)
```

**Tests Task 1.2:**
```python
# tests/test_company_currency_id_fields.py (NUEVO)

from odoo.tests.common import TransactionCase


class TestCompanyCurrencyIdFields(TransactionCase):
    """Tests campo company_currency_id en modelos payroll"""

    def test_aportes_empleador_has_company_currency_id(self):
        """Verificar company_currency_id existe en hr.salary.rule.aportes.empleador"""
        model = self.env['hr.salary.rule.aportes.empleador']
        self.assertIn('company_currency_id', model._fields)
        field = model._fields['company_currency_id']
        self.assertEqual(field.related, 'company_id.currency_id')
        self.assertTrue(field.store)

    def test_asignacion_familiar_has_company_currency_id(self):
        """Verificar company_currency_id existe en hr.salary.rule.asignacion.familiar"""
        model = self.env['hr.salary.rule.asignacion.familiar']
        self.assertIn('company_currency_id', model._fields)
        field = model._fields['company_currency_id']
        self.assertEqual(field.related, 'company_id.currency_id')
        self.assertTrue(field.store)

    def test_gratificacion_has_company_currency_id(self):
        """Verificar company_currency_id existe en hr.salary.rule.gratificacion"""
        model = self.env['hr.salary.rule.gratificacion']
        self.assertIn('company_currency_id', model._fields)
        field = model._fields['company_currency_id']
        self.assertEqual(field.related, 'company_id.currency_id')
        self.assertTrue(field.store)
```

**DoD Task 1.2:**
- ✅ Campo `company_currency_id` agregado en 3 modelos
- ✅ Tests fields: 3/3 PASS
- ✅ No AssertionError al cargar modelos

---

#### TASK 1.3: Validar 32 Campos Monetary (1h)

**Hallazgo:** H2 (Agente Desarrollador)
**Problema:** 32 campos Monetary con `currency_field` potencialmente incorrectos
**Solución:** Verificar y corregir todos los campos Monetary

**Implementación:**

**Paso 1.3.1: Audit campos Monetary**
```bash
# Script de auditoría automática
cat > /tmp/audit_monetary_fields.sh <<'EOF'
#!/bin/bash
# Auditar campos Monetary en l10n_cl_hr_payroll

echo "🔍 Auditando campos Monetary..."
echo ""

cd /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_hr_payroll/models

# Buscar todos los campos Monetary
grep -n "fields.Monetary" *.py | while IFS=: read -r file line content; do
    # Buscar currency_field en las siguientes 5 líneas
    currency_field=$(sed -n "${line},$((line+5))p" "$file" | grep "currency_field")

    if [ -z "$currency_field" ]; then
        echo "⚠️  WARNING: $file:$line - Monetary sin currency_field"
        echo "   $content"
    else
        # Extraer el valor de currency_field
        currency_value=$(echo "$currency_field" | sed "s/.*currency_field=['\"]\([^'\"]*\)['\"].*/\1/")

        # Validar que el campo existe en el modelo
        if echo "$currency_value" | grep -q "currency_id"; then
            echo "✅ OK: $file:$line - currency_field='$currency_value'"
        elif echo "$currency_value" | grep -q "company_currency_id"; then
            echo "✅ OK: $file:$line - currency_field='$currency_value'"
        else
            echo "❌ ERROR: $file:$line - currency_field='$currency_value' (inválido)"
        fi
    fi
    echo ""
done

echo ""
echo "📊 Resumen:"
echo "Total Monetary fields: $(grep -c "fields.Monetary" *.py)"
echo ""
EOF

chmod +x /tmp/audit_monetary_fields.sh
bash /tmp/audit_monetary_fields.sh
```

**Paso 1.3.2: Corregir campos si necesario**

Basado en output del script, corregir cualquier campo con `currency_field` incorrecto.

**Patrón corrección:**
```python
# SI el modelo tiene currency_id:
some_amount = fields.Monetary(
    string='Monto',
    currency_field='currency_id',  # ✅ Usar este
)

# SI el modelo tiene company_currency_id:
some_amount = fields.Monetary(
    string='Monto',
    currency_field='company_currency_id',  # ✅ Usar este
)
```

**Tests Task 1.3:**
```bash
# Test carga modelos sin AssertionError
docker exec odoo19_app python3 <<'EOF'
import sys
sys.path.insert(0, '/mnt/extra-addons/localization')

try:
    from odoo import registry
    from odoo.tests.common import get_db_name

    db_name = get_db_name()
    reg = registry(db_name)

    with reg.cursor() as cr:
        env = reg['hr.salary.rule.aportes.empleador']
        env2 = reg['hr.salary.rule.asignacion.familiar']
        env3 = reg['hr.salary.rule.gratificacion']

        print("✅ Todos los modelos cargados sin AssertionError")
        print(f"   - hr.salary.rule.aportes.empleador: OK")
        print(f"   - hr.salary.rule.asignacion.familiar: OK")
        print(f"   - hr.salary.rule.gratificacion: OK")
except AssertionError as e:
    print(f"❌ AssertionError: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
EOF
```

**DoD Task 1.3:**
- ✅ Audit script ejecutado
- ✅ 32 campos Monetary verificados
- ✅ Correcciones aplicadas si necesario
- ✅ Modelos cargan sin AssertionError

---

#### TASK 1.4: Validar Instalabilidad l10n_cl_hr_payroll (30min)

**Objetivo:** Confirmar que módulo instala sin errores en Odoo 19 CE

**Implementación:**

**Paso 1.4.1: Restart container**
```bash
cd /Users/pedro/Documents/odoo19
docker-compose restart app

# Wait healthy
timeout 60 bash -c 'until docker ps --filter "name=odoo19_app" --filter "health=healthy" | grep -q odoo19_app; do sleep 2; done'
echo "✅ Container healthy"
```

**Paso 1.4.2: Install/Update módulo**
```bash
docker exec odoo19_app odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo19 \
  -u l10n_cl_hr_payroll \
  --stop-after-init \
  --log-level=info \
  --logfile=/var/log/odoo/upgrade_l10n_cl_hr_payroll_sprint1_$(date +%Y%m%d_%H%M%S).log

# Verificar exit code
if [ $? -eq 0 ]; then
    echo "✅ Módulo instalado correctamente"
else
    echo "❌ Error en instalación"
    exit 1
fi
```

**Paso 1.4.3: Verificar state=installed**
```bash
echo "SELECT name, state, latest_version FROM ir_module_module WHERE name='l10n_cl_hr_payroll';" | \
  docker exec -i odoo19_app psql -U odoo -d odoo19 -t

# Expected output:
# l10n_cl_hr_payroll | installed | 19.0.1.0.0
```

**Paso 1.4.4: Verificar salary rules Ley 21.735 cargadas**
```bash
docker exec odoo19_app odoo shell -d odoo19 -c /etc/odoo/odoo.conf <<'EOF'
# Verificar reglas salariales Ley 21.735
rules = env['hr.salary.rule'].search([
    ('code', 'in', ['COTADIC_CAP_INDIV', 'COTADIC_COMP_SOL'])
])

if len(rules) == 2:
    for rule in rules:
        print(f"✅ Rule: {rule.code} | {rule.name} | Rate: {rule.amount_percentage}%")
else:
    print(f"❌ ERROR: Expected 2 rules, found {len(rules)}")
    exit(1)
EOF
```

**DoD Task 1.4:**
- ✅ Módulo state=installed
- ✅ 0 errores en logs upgrade
- ✅ Salary rules Ley 21.735: 2/2 cargadas
- ✅ hr.contract stub funcional

---

### Sprint 1 - Consolidation & Commit

**Paso 1.5: Tests Sprint 1**
```bash
# Ejecutar suite tests P0
docker exec odoo19_app odoo \
  -c /etc/odoo/odoo.conf \
  -d odoo19 \
  --test-enable \
  --stop-after-init \
  --log-level=test \
  --test-tags=/l10n_cl_hr_payroll/test_hr_contract_stub_ce,/l10n_cl_hr_payroll/test_company_currency_id_fields \
  2>&1 | tee evidencias/sprint1_tests_p0.log

# Expected: 8 tests PASS (5 stub + 3 currency)
```

**Paso 1.6: Commit atómico Sprint 1**
```bash
git add addons/localization/l10n_cl_hr_payroll/

git commit -m "fix(l10n_cl_hr_payroll): resolve P0 blockers - Odoo 19 CE compatibility

SPRINT 1 - P0 Bloqueantes Instalabilidad

Resolves:
- H1: Add company_currency_id field in 3 models
- H2: Validate 32 Monetary fields currency_field
- H3: Remove hr_contract Enterprise dependency, create CE stub

Changes:
- __manifest__.py: Remove 'hr_contract' dependency
- models/hr_contract_stub_ce.py: NEW - 200+ LOC CE compatible stub
- models/hr_salary_rule_*.py: Add company_currency_id fields (3 files)
- tests/test_hr_contract_stub_ce.py: NEW - 5 tests
- tests/test_company_currency_id_fields.py: NEW - 3 tests

Tests: 8/8 PASS
Module: INSTALLED (state=installed verified)
Odoo Version: 19.0 CE

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS.md SPRINT 1
"
```

**DoD Sprint 1:**
- ✅ 3 hallazgos P0 resueltos
- ✅ Módulo l10n_cl_hr_payroll instalable
- ✅ 8 tests nuevos PASS
- ✅ Commit profesional con mensaje estructurado
- ✅ Evidencias archivadas

---

### SPRINT 2: P1 Triviales - Quick Wins (4h)

**Agente Principal:** `@odoo-dev`
**Validador Compliance:** `@dte-compliance`
**Coordinador:** Senior Engineer

**Invocación:**
```
@odoo-dev ejecuta SPRINT 2 - P1 Quick Wins según PROMPT_MASTER_CIERRE_TOTAL_BRECHAS.md

Contexto: Resolver 2 hallazgos P1 triviales (fixes rápidos)
- #4: Fix dominio project_id → analytic_account_id (1 línea)
- #1 Rectificado: Limitar scope DTE a EERGYGROUP (remover 39,41,46; mantener 70 BHE)

Knowledge base:
- sii_regulatory_context.md: Scope EERGYGROUP (Empresa Ingeniería)
  * Emisión: 33,34,52,56,61
  * Recepción: 33,34,52,56,61,70 (BHE para compras profesionales)
- odoo19_patterns.md: Selection fields, domain filters

Tasks: Ver TASK 2.1-2.2 en PROMPT detallado
DoD: 2 hallazgos resueltos, 6 tests PASS, commit estructurado
Timeline: 4h

Validación:
- @dte-compliance: Confirmar scope DTE alineado con SII regulations EERGYGROUP
```

**Objetivo:** Resolver 2 hallazgos P1 triviales (<1h cada uno)

#### TASK 2.1: Fix Dominio project_id → analytic_account_id (15min)

**Hallazgo:** #4 (Codex)
**Problema:** `analytic_dashboard.py:489` usa `project_id` que no existe sin módulo `project`
**Solución:** 1 línea fix

**Archivo:** `addons/localization/l10n_cl_dte/models/analytic_dashboard.py`

**Implementación:**
```python
# analytic_dashboard.py:489

# ANTES:
def action_view_purchases(self):
    return {
        'name': _('Compras'),
        'type': 'ir.actions.act_window',
        'res_model': 'purchase.order',
        'view_mode': 'tree,form',
        'domain': [('project_id', '=', self.analytic_account_id.id)],  # ❌ ERROR
        'context': {'default_analytic_account_id': self.analytic_account_id.id},
    }

# DESPUÉS:
def action_view_purchases(self):
    return {
        'name': _('Compras'),
        'type': 'ir.actions.act_window',
        'res_model': 'purchase.order',
        'view_mode': 'tree,form',
        'domain': [('analytic_account_id', '=', self.analytic_account_id.id)],  # ✅ FIX
        'context': {'default_analytic_account_id': self.analytic_account_id.id},
    }
```

**Tests:**
```python
# tests/test_analytic_dashboard_actions.py (NUEVO)

from odoo.tests.common import TransactionCase


class TestAnalyticDashboardActions(TransactionCase):
    """Tests acciones analytic dashboard"""

    def setUp(self):
        super().setUp()
        self.AnalyticAccount = self.env['account.analytic.account']
        self.Dashboard = self.env['analytic.dashboard']

        self.analytic_account = self.AnalyticAccount.create({
            'name': 'Test Project Analytics',
        })

    def test_action_view_purchases_uses_analytic_account_id(self):
        """Verificar que action usa analytic_account_id (no project_id)"""
        dashboard = self.Dashboard.create({
            'analytic_account_id': self.analytic_account.id,
        })

        action = dashboard.action_view_purchases()

        self.assertEqual(action['res_model'], 'purchase.order')
        self.assertIn('domain', action)

        # Verificar dominio usa analytic_account_id
        domain = action['domain']
        self.assertEqual(len(domain), 1)
        self.assertEqual(domain[0][0], 'analytic_account_id')
        self.assertEqual(domain[0][2], self.analytic_account.id)
```

**DoD Task 2.1:**
- ✅ Dominio corregido (1 línea)
- ✅ Test action: 1/1 PASS
- ✅ Funciona sin módulo `project` instalado

---

#### TASK 2.2: Limitar Alcance DTE - Scope EERGYGROUP (30min)

**Hallazgo:** #1 (Codex - Rectificado)
**Problema:** DTE incluye tipos 39, 41, 46 fuera de scope EERGYGROUP
**Solución:** Remover 3 tipos, mantener 70 (BHE compras)

**Archivos:**
1. `addons/localization/l10n_cl_dte/libs/dte_structure_validator.py`
2. `addons/localization/l10n_cl_dte/models/dte_inbox.py`

**Implementación:**

**Paso 2.2.1: Actualizar DTE_TYPES_VALID**
```python
# libs/dte_structure_validator.py:46-54

# ANTES:
DTE_TYPES_VALID = ['33', '34', '39', '41', '46', '52', '56', '61', '70']

# DESPUÉS:
# ═══════════════════════════════════════════════════════════════════════
# CONSTANTES - SCOPE EERGYGROUP (Empresa Ingeniería)
# ═══════════════════════════════════════════════════════════════════════

# Tipos DTE para EMISIÓN (ventas)
DTE_TYPES_EMISSION = ['33', '34', '52', '56', '61']

# Tipos DTE para RECEPCIÓN (compras) - incluye BHE
DTE_TYPES_RECEPTION = ['33', '34', '52', '56', '61', '70']

# Compatibilidad: todos los tipos válidos (emisión + recepción únicos)
DTE_TYPES_VALID = sorted(set(DTE_TYPES_EMISSION + DTE_TYPES_RECEPTION))
# Result: ['33', '34', '52', '56', '61', '70']
```

**Paso 2.2.2: Actualizar dte_inbox selection**
```python
# models/dte_inbox.py:62-72

# ANTES:
dte_type = fields.Selection([
    ('33', 'Factura Electrónica'),
    ('34', 'Liquidación Honorarios'),
    ('39', 'Boleta Electrónica'),
    ('41', 'Boleta Exenta'),
    ('46', 'Factura Compra Electrónica'),
    ('52', 'Guía de Despacho'),
    ('56', 'Nota de Débito'),
    ('61', 'Nota de Crédito'),
    ('70', 'Boleta Honorarios Electrónica'),
], string='DTE Type', required=True, tracking=True)

# DESPUÉS:
dte_type = fields.Selection([
    # ═══════════════════════════════════════════════════════════
    # TIPOS DTE RECEPCIÓN - EERGYGROUP (Empresa Ingeniería)
    # ═══════════════════════════════════════════════════════════
    ('33', 'Factura Electrónica'),
    ('34', 'Factura Exenta Electrónica'),
    ('52', 'Guía de Despacho Electrónica'),
    ('56', 'Nota de Débito Electrónica'),
    ('61', 'Nota de Crédito Electrónica'),
    ('70', 'Boleta Honorarios Electrónica (BHE)'),
    # ═══════════════════════════════════════════════════════════
    # REMOVIDOS (fuera de scope EERGYGROUP):
    # ('39', 'Boleta Electrónica')          - Retail (no aplica)
    # ('41', 'Boleta Exenta')               - Retail (no aplica)
    # ('46', 'Factura Compra Electrónica')  - No utilizado
    # ═══════════════════════════════════════════════════════════
], string='DTE Type', required=True, tracking=True,
   help='Tipos DTE para recepción según alcance EERGYGROUP (Empresa Ingeniería)')
```

**Tests:**
```python
# tests/test_dte_types_scope_eergygroup.py (NUEVO)

from odoo.tests.common import TransactionCase
from odoo.addons.l10n_cl_dte.libs.dte_structure_validator import DTEStructureValidator


class TestDTETypesScopeEERGYGROUP(TransactionCase):
    """Tests alcance tipos DTE según scope EERGYGROUP"""

    def test_dte_types_valid_count(self):
        """Verificar que solo 6 tipos DTE están permitidos"""
        self.assertEqual(len(DTEStructureValidator.DTE_TYPES_VALID), 6)

    def test_dte_types_emission_scope(self):
        """Verificar tipos emisión (ventas)"""
        expected_emission = {'33', '34', '52', '56', '61'}
        actual_emission = set(DTEStructureValidator.DTE_TYPES_EMISSION)
        self.assertEqual(actual_emission, expected_emission)

    def test_dte_types_reception_scope(self):
        """Verificar tipos recepción (compras) incluye BHE"""
        expected_reception = {'33', '34', '52', '56', '61', '70'}
        actual_reception = set(DTEStructureValidator.DTE_TYPES_RECEPTION)
        self.assertEqual(actual_reception, expected_reception)

    def test_retail_types_not_in_scope(self):
        """Verificar tipos retail (39, 41, 46) NO están en scope"""
        retail_types = ['39', '41', '46']
        for dte_type in retail_types:
            self.assertNotIn(dte_type, DTEStructureValidator.DTE_TYPES_VALID,
                           f"DTE tipo {dte_type} NO debe estar en scope EERGYGROUP")

    def test_bhe_type_in_scope_reception(self):
        """Verificar BHE (70) SÍ está en scope recepción"""
        self.assertIn('70', DTEStructureValidator.DTE_TYPES_RECEPTION)
        self.assertIn('70', DTEStructureValidator.DTE_TYPES_VALID)
```

**DoD Task 2.2:**
- ✅ Tipos removidos: 39, 41, 46
- ✅ Tipo 70 (BHE) mantenido
- ✅ Arquitectura emisión/recepción implementada
- ✅ Tests scope: 5/5 PASS

---

#### Sprint 2 - Commit

```bash
git add addons/localization/l10n_cl_dte/

git commit -m "fix(l10n_cl_dte): P1 quick wins - dashboard + DTE scope EERGYGROUP

SPRINT 2 - P1 Triviales

Resolves:
- #4 (Codex): Fix analytic_dashboard.py project_id → analytic_account_id
- #1 (Codex Rectificado): Limitar scope DTE a EERGYGROUP (remover 39,41,46; mantener 70 BHE)

Changes:
- models/analytic_dashboard.py:489: Fix dominio (1 línea)
- libs/dte_structure_validator.py: Arquitectura emisión/recepción (15 líneas)
- models/dte_inbox.py: Selection actualizada scope EERGYGROUP (6 tipos)
- tests/test_analytic_dashboard_actions.py: NEW - 1 test
- tests/test_dte_types_scope_eergygroup.py: NEW - 5 tests

Tests: 6/6 PASS
Scope: EERGYGROUP (Empresa Ingeniería)
  - Emisión: 33,34,52,56,61
  - Recepción: 33,34,52,56,61,70 (incluye BHE)

Ref: .claude/PROMPT_MASTER_CIERRE_TOTAL_BRECHAS.md SPRINT 2
Ref: .claude/RECTIFICACION_HALLAZGO1_SCOPE_NEGOCIO.md
"
```

**DoD Sprint 2:**
- ✅ 2 hallazgos P1 resueltos
- ✅ 6 tests nuevos PASS
- ✅ Commit profesional

---

## 📄 CONTINUACIÓN EN SIGUIENTE MENSAJE

Este PROMPT es extremadamente extenso. Continuaré con SPRINTS 3-5 en el siguiente bloque para mantener la calidad y detalle profesional.

**Estructura pendiente:**
- SPRINT 3: Validación RUT centralizada (4h)
- SPRINT 4: libs/ Pure Python + DTE 34 completo (16h)
- SPRINT 5: CI/CD + Documentación (8h)

**¿Deseas que continúe generando los SPRINTS 3-5 con el mismo nivel de detalle profesional?**
