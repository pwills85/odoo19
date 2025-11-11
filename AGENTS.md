# AGENTS.md - Odoo 19 CE Chilean Localization
**Standard:** AGENTS.md Convention 2025
**Compatible:** Claude Code, GitHub Copilot CLI, OpenAI Codex CLI, Cursor, Windsurf
**Project:** Odoo19 Enterprise-to-CE Migration + Chilean Localization
**Version:** 2.0.0 - Armonizado Multi-CLI

---

## 🎯 Global Principles (Inherited from SuperClaude)

This project follows **SuperClaude** efficiency principles for consistent output across all AI coding assistants:

### Output Economy & Token Optimization
- **Concise over Verbose**: Use tables, headers, and structured markdown
- **Reference over Repetition**: Use `file:line` notation instead of duplicating code
- **Smart Context**: Include only necessary imports and context
- **Structured Data**: Tables > Long lists for comparisons and metrics

### Professional Standards
- **Evidence-Based**: Always validate against official documentation
- **Security-First**: OWASP Top 10 awareness, no hardcoded credentials
- **Test-Driven**: Include test cases for critical functionality
- **Performance-Aware**: Consider cost/performance tradeoffs

### Communication Style
- **Professional objectivity**: Facts over validation
- **Clear hierarchy**: Use status indicators (✅⚠️❌🔴🟡🟢)
- **Actionable**: Always provide next steps
- **NO emojis** unless explicitly requested

---

## 📋 Project Context: Odoo19 Chilean Localization

### Tech Stack
```yaml
Framework: Odoo 19 CE (migrated from Enterprise)
Python: 3.11+
Database: PostgreSQL 16
Cache: Redis 7.4
Container: Docker + Docker Compose
AI Service: FastAPI + Claude API (Sonnet 4.5)

Modules:
  - l10n_cl_dte (Electronic Invoicing - DTE)
  - l10n_cl_hr_payroll (Chilean Payroll)
  - l10n_cl_financial_reports (Financial Reporting)
```

### Architecture Principles

#### Odoo Design Patterns
1. **Model Inheritance**: Use `_inherit` instead of modifying core
2. **Security**: Always use `@api.model` decorator for permission validation
3. **Computed Fields**: Prefer computed over stored when data changes frequently
4. **Dependencies**: Use `@api.depends()` for efficient field computation
5. **Validation**: Implement `@api.constrains` for complex business rules

### ⚠️ CRITICAL: Odoo 19 CE Deprecations (MUST AVOID)

**System migrado exitosamente - 137 deprecaciones corregidas (2025-11-11)**  
**Compliance: 80.4% P0 cerradas | 27 manuales pendientes**

**🔴 P0 (Breaking Changes - Deadline: 2025-03-01):**
1. **QWeb Templates:** `t-esc` → `t-out` ✅ FIXED (85 occurrences)
2. **HTTP Controllers:** `type='json'` → `type='jsonrpc'` + `csrf=False` ✅ FIXED (26 routes)
3. **XML Views:** `attrs=` → Python expressions ⚠️ 24 MANUAL PENDING (6 files)
4. **ORM:** `_sql_constraints` → `models.Constraint` ⚠️ 3 MANUAL PENDING (2 files)

**🟡 P1 (High Priority - Deadline: 2025-06-01):**
5. **Database Access:** `self._cr` → `self.env.cr` ✅ FIXED (119 occurrences)
6. **View Methods:** `fields_view_get()` → `get_view()` (1 occurrence)
7. **Decorators:** `@api.depends` now cumulative in inheritance (184 audit only)

**🟢 P2 (Best Practices):**
8. **i18n:** Use `_lt()` for lazy translations (659 audit only)

**📋 Reference:** `/scripts/odoo19_migration/config/deprecations.yaml`  
**📊 Status:** `/CIERRE_BRECHAS_ODOO19_INFORME_FINAL.md`  
**🔧 System:** `/scripts/odoo19_migration/README.md`

**Cuando escribas código Odoo 19:**
- ✅ USAR: `t-out`, `type='jsonrpc'`, `self.env.cr`, `models.Constraint`
- ❌ EVITAR: `t-esc`, `type='json'`, `self._cr`, `_sql_constraints`, `attrs=`

#### Module Structure
```
addons/localization/<module_name>/
├── __init__.py
├── __manifest__.py
├── models/           # Business logic (ORM models)
├── views/            # XML views (forms, trees, search)
├── security/         # ir.model.access.csv, record rules
├── data/             # Master data, sequences
├── reports/          # QWeb reports, PDF generation
└── tests/            # Unit tests (pytest + Odoo test framework)
```

### Chilean Localization Specifics

#### DTE (Documentos Tributarios Electrónicos)
- **DTE 33**: Factura Electrónica (Invoice)
- **DTE 34**: Factura Exenta (Exempt Invoice)
- **DTE 52**: Guía de Despacho (Delivery Guide)
- **DTE 56**: Nota de Débito (Debit Note)
- **DTE 61**: Nota de Crédito (Credit Note)

**SII Integration:**
- SOAP webservices for DTE validation
- XMLDSig digital signatures (xmlsec)
- CAF (Folios Authorization) management
- Daily sales book (Libro de Ventas)

#### Payroll (Nóminas)
- **Economic Indicators**: UF, UTM, IPC, minimum wage (auto-sync from external APIs)
- **Pension Funds**: AFP (10% mandatory contribution)
- **Health Insurance**: ISAPRE, FONASA (7% mandatory)
- **Voluntary Savings**: APV (tax benefits, calculation complexity)
- **Previred Integration**: Monthly file submission (TXT format)

### Naming Conventions
```python
# Modules
l10n_cl_dte                    # Chilean localization - DTE
l10n_cl_hr_payroll             # Chilean localization - HR Payroll

# Models
account.move.l10n_cl_dte       # Inheritance pattern
hr.economic.indicators         # Descriptive naming

# Fields
l10n_cl_dte_type_id           # Prefixed with module
l10n_cl_sii_barcode           # System identifier prefix

# Methods
_compute_l10n_cl_dte_amount   # Computed field pattern
_validate_sii_response        # Private method convention
```

---

## 💻 Code Generation Guidelines

### Python (Odoo Models)
```python
# ALWAYS include necessary imports
from odoo import models, fields, api
from odoo.exceptions import UserError, ValidationError

class HrPayslip(models.Model):
    _inherit = 'hr.payslip'  # ✅ Inheritance pattern

    # Field definition with proper attributes
    l10n_cl_total_imponible = fields.Monetary(
        string='Total Imponible',
        compute='_compute_l10n_cl_total_imponible',
        store=True,  # Only if needed for reporting/search
        currency_field='currency_id',
        help="Base salary for social security calculations"
    )

    @api.depends('line_ids.total')  # ✅ Explicit dependencies
    def _compute_l10n_cl_total_imponible(self):
        """Compute total taxable amount for Chilean payroll."""
        for payslip in self:
            imponible_lines = payslip.line_ids.filtered(
                lambda l: l.salary_rule_id.l10n_cl_is_imponible
            )
            payslip.l10n_cl_total_imponible = sum(imponible_lines.mapped('total'))

    @api.constrains('l10n_cl_previred_file')  # ✅ Validation
    def _check_previred_format(self):
        """Validate Previred file format before submission."""
        for record in self:
            if record.l10n_cl_previred_file:
                # Validation logic
                if not self._validate_previred_structure(record.l10n_cl_previred_file):
                    raise ValidationError("Invalid Previred file format")
```

### XML (Views)
```xml
<!-- views/hr_payslip_views.xml -->
<odoo>
    <record id="view_hr_payslip_form_l10n_cl" model="ir.ui.view">
        <field name="name">hr.payslip.form.l10n_cl</field>
        <field name="model">hr.payslip</field>
        <field name="inherit_id" ref="hr_payroll.view_hr_payslip_form"/>
        <field name="arch" type="xml">
            <xpath expr="//notebook" position="inside">
                <page string="Chilean Localization" name="l10n_cl">
                    <group>
                        <field name="l10n_cl_total_imponible"/>
                        <field name="l10n_cl_afp_amount"/>
                        <field name="l10n_cl_isapre_amount"/>
                    </group>
                </page>
            </xpath>
        </field>
    </record>
</odoo>
```

### Testing
```python
# tests/test_payslip_calculations.py
from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError

@tagged('post_install', '-at_install', 'l10n_cl')
class TestPayslipCalculations(TransactionCase):

    def setUp(self):
        super().setUp()
        # Setup test data
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Employee',
            'l10n_cl_afp_id': self.env.ref('l10n_cl_hr_payroll.afp_capital').id,
        })

    def test_total_imponible_calculation(self):
        """Test total imponible calculation matches SII requirements."""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            # ... payslip data
        })
        payslip.compute_sheet()

        # Validation
        self.assertEqual(payslip.l10n_cl_total_imponible, 1000000,
                        "Total imponible should match base salary")
```

---

## 📊 Analysis & Reporting Format

### Code Analysis
When analyzing code, ALWAYS use this format:

```markdown
## Analysis: <Component Name>

**File:** `addons/localization/l10n_cl_dte/models/account_move.py:125`

**Current Implementation:**
- Uses inheritance pattern ✅
- Missing error handling ⚠️
- Performance concern: N+1 query 🔴

**Code Reference:**
```python
# Line 125-130
def _validate_dte(self):
    for move in self:  # ⚠️ Potential N+1 if called in loop
        move.l10n_cl_dte_status = self._call_sii_webservice()
```

**Recommendations:**
1. 🔴 **CRITICAL**: Batch SII webservice calls
2. 🟡 **MEDIUM**: Add retry logic with exponential backoff
3. 🟢 **NICE-TO-HAVE**: Cache SII responses for 5 minutes
```

### Technical Reports
Use this structure for professional reports:

```markdown
# 🎯 REPORT TITLE

**Date:** YYYY-MM-DD
**Scope:** <What was analyzed>
**Status:** ✅ Success / ⚠️ Warning / ❌ Critical

---

## Executive Summary

<2-3 sentence overview of findings>

| Metric | Baseline | Current | Delta | Status |
|--------|----------|---------|-------|--------|
| Tests Passing | 180/200 | 195/200 | +15 | ✅ |
| Coverage | 75% | 82% | +7% | ✅ |

---

## Detailed Analysis

### Critical Issues 🔴

1. **Issue Title** (`file:line`)
   - **Problem**: Description
   - **Impact**: Business/technical impact
   - **Solution**: Specific fix

### Warnings ⚠️

### Observations 💡

---

## Recommendations

**Immediate (P0):**
1. Action 1
2. Action 2

**Short-term (P1):**
1. Action 1

**Long-term (P2):**
1. Action 1
```

---

## 🔗 File References & Navigation

### Key Project Files
```
Documentation:
  - /Users/pedro/Documents/odoo19/CLAUDE.md (Project README)
  - /Users/pedro/Documents/odoo19/AGENTS.md (This file)
  - .claude/project/*.md (Modular documentation)

DTE Module:
  - addons/localization/l10n_cl_dte/__manifest__.py
  - addons/localization/l10n_cl_dte/models/account_move.py
  - addons/localization/l10n_cl_dte/models/l10n_cl_dte_type.py
  - addons/localization/l10n_cl_dte/wizards/validate_dte.py

Payroll Module:
  - addons/localization/l10n_cl_hr_payroll/__manifest__.py
  - addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
  - addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py
  - addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule.py

AI Service:
  - ai-service/app/main.py
  - ai-service/app/engine.py
  - ai-service/app/knowledge_base.py

Infrastructure:
  - docker-compose.yml
  - config/odoo.conf
  - .env (DO NOT commit - contains secrets)
```

### Reference Format
When referencing code, use: `file_path:line_number`

**Examples:**
- `addons/localization/l10n_cl_dte/models/account_move.py:125`
- `ai-service/app/main.py:45-60` (range)
- `docker-compose.yml:12` (config files)

---

## 🚨 Security & Compliance

### OWASP Top 10 Awareness
- **SQL Injection**: Use ORM methods, NEVER raw SQL with user input
- **XSS**: Sanitize all user inputs in views (`t-esc` in QWeb)
- **Authentication**: Use Odoo's `@api.model` decorator
- **Sensitive Data**: NO credentials in code (use environment variables)
- **XML External Entities**: Validate XML strictly (DTE signatures)

### Chilean Legal Compliance
- **SII Resolution 80/2014**: DTE XML schema validation
- **DL 824 Art. 54**: Electronic invoicing requirements
- **Previred Circular 1/2018**: Payroll file format
- **Labor Code Art. 42**: Payroll calculation rules

---

## 🛠️ Development Workflow

### Before Coding
1. Read relevant CLAUDE.md sections in `.claude/project/`
2. Check existing tests in `tests/` directory
3. Validate against SII/Previred documentation if applicable
4. Review related code for patterns to follow

### During Coding
1. Follow PEP8 strictly (use linters)
2. Add docstrings to all public methods
3. Include inline comments for complex logic
4. Use type hints when appropriate
5. Test locally with `pytest` before committing

### After Coding
1. Run full test suite: `pytest addons/localization/<module>/tests/`
2. Check code coverage: `pytest --cov`
3. Validate XML syntax: `xmllint --noout views/*.xml`
4. Update documentation if API changed
5. Create meaningful git commit messages

---

## 📚 External References

### Official Documentation
- **Odoo 19 CE**: https://www.odoo.com/documentation/19.0/
- **SII Chile**: https://www.sii.cl/servicios_online/1039-.html
- **Previred**: https://www.previred.com/web/previred/home
- **Chilean Labor Law**: https://www.bcn.cl/leychile/navegar?idNorma=207436

### Chilean Compliance
- SII Webservices: https://maullin.sii.cl/DTEWS/
- DTE Schema: https://www.sii.cl/factura_electronica/formato_dte.pdf
- Previred API: https://www.previred.com/web/previred/documentacion-tecnica

---

## ⚙️ CLI-Specific Notes

### For Claude Code Users
This file is read automatically by Claude Code alongside `~/.claude/CLAUDE.md` (SuperClaude global config). Both sets of instructions are combined.

**Comandos Docker + Odoo**: Ver `.github/agents/knowledge/docker_odoo_command_reference.md`

### For Copilot CLI Users
This file is loaded automatically by Copilot CLI (as of August 2025). Use `--no-custom-instructions` flag to disable if needed.

**Configuración autónoma**: `.github/copilot-instructions.md` (sección AUTONOMOUS DEVELOPMENT MODE)  
**Comandos Docker + Odoo**: Ver `.github/agents/knowledge/docker_odoo_command_reference.md`

### For Codex CLI Users
Codex CLI does NOT read this file automatically.

**Configuración manual**: `.codex/autonomous_instructions.md`  
**Comandos Docker + Odoo**: Ver `.github/agents/knowledge/docker_odoo_command_reference.md`

### For Gemini CLI Users
Gemini CLI requires manual configuration.

**Configuración manual**: `.gemini/autonomous_instructions.md`  
**Comandos Docker + Odoo**: Ver `.github/agents/knowledge/docker_odoo_command_reference.md`

---

**Last Updated:** 2025-11-09
**Maintainer:** Pedro Troncoso Willz (@pwills85)
**License:** LGPL-3 (Odoo modules)

---

*This AGENTS.md file follows the 2025 multi-CLI convention for maximum compatibility across Claude Code, GitHub Copilot CLI, OpenAI Codex CLI, Cursor, Windsurf, and other AI coding assistants.*
