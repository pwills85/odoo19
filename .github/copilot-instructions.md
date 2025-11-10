# Copilot Instructions - Odoo19 Chilean Localization

## Project Context

**Framework**: Odoo 19 Community Edition  
**Focus**: Chilean localization (DTE Electronic Invoicing, Payroll, Financial Reports)  
**Standards**: OCA guidelines, SII Resolution 80/2014, Chilean Labor Code  
**Architecture**: Modular design with pure Python validators in `libs/` directory

---

## 🎯 Core Principles

1. **Extend, Don't Duplicate**: Use `_inherit` to extend existing Odoo models
2. **Regulatory First**: All DTE features must comply with SII requirements
3. **Pure Python Utilities**: Validators and utilities go in `libs/` (no ORM dependencies)
4. **Multi-Company Aware**: Transactional data is company-specific, master data can be shared
5. **Test Everything**: 80% coverage for DTE, 100% for critical validators

---

## 📚 Knowledge Base (MANDATORY)

All implementations MUST reference these knowledge base files:

### `.github/agents/knowledge/sii_regulatory_context.md`
- SII regulations and DTE requirements
- Document types in scope (33, 34, 52, 56, 61 only)
- RUT validation rules (modulo 11, 3 formats)
- CAF signature requirements
- XML schema validation

### `.github/agents/knowledge/odoo19_patterns.md`
- Odoo 19 patterns (NOT Odoo 11-16!)
- Model inheritance patterns (`_inherit`, mixins)
- Decorators: `@api.depends`, `@api.constrains`, `@api.onchange`
- Testing patterns: TransactionCase, @tagged
- Pure Python classes in `libs/`

### `.github/agents/knowledge/project_architecture.md`
- EERGYGROUP architecture decisions
- Multi-company strategy
- Module dependencies
- Naming conventions

---

## 🏗️ Code Conventions

### Naming
```python
# Models
class AccountMove(models.Model):
    _inherit = 'account.move'  # Extend existing model

# Fields - prefix with l10n_cl_
l10n_cl_dte_type_id = fields.Many2one('l10n_cl.dte.type', 'DTE Type')
l10n_cl_dte_status = fields.Selection([...], 'DTE Status')
l10n_cl_sii_barcode = fields.Text('SII Barcode (TED)')

# Methods - descriptive names
def _compute_l10n_cl_total_imponible(self):
def _validate_l10n_cl_rut(self):
def _generate_l10n_cl_dte_xml(self):
```

### File Structure
```
addons/localization/l10n_cl_<module>/
├── models/          # ORM models (extend Odoo)
├── libs/            # Pure Python (no ORM)
├── views/           # XML views
├── security/        # Access rights, record rules
├── data/            # Master data, sequences
├── wizards/         # Transient models
├── reports/         # QWeb reports
└── tests/           # Unit tests
```

### Model Patterns
```python
# Computed field with dependencies
@api.depends('line_ids.total', 'line_ids.salary_rule_id.is_imponible')
def _compute_l10n_cl_total_imponible(self):
    """Compute total imponible for Chilean payroll."""
    for record in self:
        imponible_lines = record.line_ids.filtered(
            lambda l: l.salary_rule_id.is_imponible
        )
        record.l10n_cl_total_imponible = sum(imponible_lines.mapped('total'))

# Validation constraint
@api.constrains('l10n_cl_folio', 'l10n_cl_dte_type_id')
def _check_l10n_cl_folio_unique(self):
    """Ensure folio is unique per DTE type."""
    for record in self:
        if record.l10n_cl_folio:
            duplicate = self.search([
                ('id', '!=', record.id),
                ('l10n_cl_folio', '=', record.l10n_cl_folio),
                ('l10n_cl_dte_type_id', '=', record.l10n_cl_dte_type_id.id),
            ], limit=1)
            if duplicate:
                raise ValidationError("Folio already exists")
```

### Testing Patterns
```python
from odoo.tests import TransactionCase, tagged

@tagged('post_install', '-at_install', 'l10n_cl')
class TestDTEValidation(TransactionCase):
    """Test DTE validation logic."""

    def setUp(self):
        super().setUp()
        self.company = self.env['res.company'].create({
            'name': 'Test Company',
            'vat': '76876876-8',
        })

    def test_rut_validation(self):
        """Test RUT modulo 11 validation."""
        from ..libs.rut_validator import RUTValidator
        self.assertTrue(RUTValidator.validate('76876876-8'))
        self.assertFalse(RUTValidator.validate('76876876-9'))
```

---

## 🔐 Security Guidelines

1. **No SQL Injection**: Use ORM, never raw SQL with user input
2. **XSS Prevention**: Use `t-esc` in QWeb, not `t-raw`
3. **Authentication**: Use `@api.model` decorator for permission checks
4. **XXE Protection**: Configure XML parser to disable external entities
5. **Sensitive Data**: Use environment variables, never hardcode credentials

### Secure XML Parsing (DTE)
```python
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,  # Disable XXE
    no_network=True,         # Block network access
    dtd_validation=False,    # Disable DTD
)
tree = etree.fromstring(xml_content.encode(), parser)
```

---

## 🇨🇱 Chilean Localization Specifics

### DTE Document Types (EERGYGROUP Scope)
- **33**: Factura Electrónica (Invoice)
- **34**: Factura Exenta (Exempt Invoice)
- **52**: Guía de Despacho (Delivery Guide)
- **56**: Nota de Débito (Debit Note)
- **61**: Nota de Crédito (Credit Note)

**NOT in scope**: Boletas (39, 41)

### RUT Validation
```python
# Format: 12.345.678-9 (display) → 12345678-9 (storage) → 123456789 (SII XML)
# Validation: Modulo 11 algorithm
from ..libs.rut_validator import RUTValidator

if not RUTValidator.validate(partner.vat):
    raise ValidationError("Invalid RUT")
```

### Payroll Calculations
```python
# AFP: 10% of Total Imponible (max 90.3 UF)
afp_amount = min(total_imponible, tope_imponible_afp) * 0.10

# ISAPRE: 7% minimum of Total Imponible (max 90.3 UF)
isapre_amount = min(total_imponible, tope_imponible_isapre) * isapre_rate
```

---

## 🤖 Using Custom Agents

Invoke specialized agents for specific tasks:

```bash
# DTE compliance validation
copilot /agent dte-specialist

# Payroll calculations review
copilot /agent payroll-compliance

# Test automation
copilot /agent test-automation

# Security audit
copilot /agent security-auditor

# Architecture review
copilot /agent odoo-architect
```

---

## 📁 Key Project Files

### DTE Module
- `addons/localization/l10n_cl_dte/models/account_move.py` - Invoice DTE extension
- `addons/localization/l10n_cl_dte/models/l10n_cl_dte_caf.py` - CAF management
- `addons/localization/l10n_cl_dte/libs/dte_validator.py` - DTE validation
- `addons/localization/l10n_cl_dte/libs/rut_validator.py` - RUT validation
- `addons/localization/l10n_cl_dte/libs/sii_connector.py` - SII webservice

### Payroll Module
- `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py` - Payslip extension
- `addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule.py` - Salary rules
- `addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py` - UF/UTM/IPC
- `addons/localization/l10n_cl_hr_payroll/wizards/previred_export.py` - Previred file

### Configuration
- `config/odoo.conf` - Odoo configuration
- `docker-compose.yml` - Docker services
- `.env` - Environment variables (secrets)
- `pytest.ini` - Test configuration

---

## 🚨 Common Pitfalls

1. **Using Odoo 11-16 patterns**: ❌ Old `@api.one` decorator → ✅ Use `@api.depends`
2. **Ignoring multi-company**: ❌ Hardcoded company → ✅ Use `self.env.company`
3. **Raw SQL with user input**: ❌ SQL injection risk → ✅ Use ORM
4. **Missing @api.depends**: ❌ Computed field not updating → ✅ Declare dependencies
5. **Testing with real SII API**: ❌ Slow, unreliable → ✅ Mock external calls

---

## 📖 References

- **Odoo 19 Docs**: https://www.odoo.com/documentation/19.0/
- **SII Chile**: https://www.sii.cl/servicios_online/1039-.html
- **Previred**: https://www.previred.com/web/previred/home
- **Chilean Labor Code**: https://www.bcn.cl/leychile/navegar?idNorma=207436

---

**Last Updated**: 2025-11-10  
**Maintainer**: Pedro Troncoso (@pwills85)
