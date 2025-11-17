# 🤝 Contributing to Odoo19 Chilean Localization

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Chilean Localization Specifics](#chilean-localization-specifics)

---

## 📜 Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Expected Behavior

- Use welcoming and inclusive language
- Be respectful of differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other members

### Unacceptable Behavior

- Trolling, insulting comments, or personal attacks
- Public or private harassment
- Publishing others' private information
- Other conduct which could be considered inappropriate

---

## 🚀 Getting Started

### Prerequisites

1. **Read Documentation**:
   - [README.md](../README.md) - Project overview
   - [DEPLOYMENT.md](./DEPLOYMENT.md) - Setup instructions
   - [GIT_STRATEGY.md](./GIT_STRATEGY.md) - Git workflow
   - [AGENTS.md](../AGENTS.md) - AI agent instructions

2. **Technical Requirements**:
   - Python 3.11+
   - Docker & Docker Compose
   - Git 2.40+
   - Code editor (VS Code recommended)

3. **Knowledge Areas**:
   - Odoo 19 framework
   - Chilean tax regulations (SII)
   - Chilean payroll law (if contributing to HR)
   - XML, Python, PostgreSQL

### Fork & Clone

```bash
# Fork on GitHub
# Click "Fork" button at https://github.com/pwills85/odoo19

# Clone your fork
git clone https://github.com/YOUR_USERNAME/odoo19.git
cd odoo19

# Add upstream remote
git remote add upstream https://github.com/pwills85/odoo19.git

# Verify remotes
git remote -v
```

### Setup Development Environment

```bash
# Copy environment file
cp .env.example .env

# Edit with your settings
nano .env

# Start stack
docker compose up -d

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

---

## 🔄 Development Workflow

### Branching Strategy

```
main (production)
  ↓
develop (staging)
  ↓
feature/your-feature-name (work here)
```

### Create Feature Branch

```bash
# Update develop branch
git checkout develop
git pull upstream develop

# Create feature branch
git checkout -b feature/dte-validation-improvements

# Branch naming conventions:
# feature/dte-*          - DTE module changes
# feature/payroll-*      - Payroll module changes
# feature/financial-*    - Financial reports
# feature/ai-*           - AI service changes
# fix/bug-description    - Bug fixes
# docs/documentation     - Documentation only
# refactor/component     - Code refactoring
# test/test-description  - Test additions
```

### Make Changes

```bash
# Create/modify files
# Follow code standards below

# Run tests locally
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v

# Check code quality
docker compose exec odoo pylint /mnt/extra-addons/localization/l10n_cl_dte/
docker compose exec odoo black --check /mnt/extra-addons/localization/
```

### Commit Changes

```bash
# Stage changes
git add addons/localization/l10n_cl_dte/models/account_move.py

# Commit with conventional commit format
git commit -m "feat(dte): add folio validation for DTE 33"

# Commit message format:
# <type>(<scope>): <description>
#
# Types: feat, fix, docs, style, refactor, test, chore, perf, ci, build
# Scopes: dte, payroll, financial, ai-service, infra, docs
# Description: imperative mood, lowercase, no period
```

**Conventional Commit Examples:**

```bash
# New feature
git commit -m "feat(dte): implement CAF signature validation"

# Bug fix
git commit -m "fix(payroll): correct AFP calculation for edge cases"

# Documentation
git commit -m "docs(readme): update installation instructions"

# Refactoring
git commit -m "refactor(dte): extract XML validation to separate class"

# Tests
git commit -m "test(payroll): add unit tests for ISAPRE calculation"

# Performance
git commit -m "perf(dte): optimize SII webservice batch calls"

# Breaking change
git commit -m "feat(dte)!: change CAF storage to binary field

BREAKING CHANGE: CAF files now stored as binary instead of text"
```

### Push Changes

```bash
# Push to your fork
git push origin feature/dte-validation-improvements

# If branch doesn't exist on remote yet
git push --set-upstream origin feature/dte-validation-improvements
```

---

## 📐 Code Standards

### Python (Odoo Models)

**PEP8 + Odoo Conventions:**

```python
# addons/localization/l10n_cl_dte/models/account_move.py
from odoo import models, fields, api
from odoo.exceptions import UserError, ValidationError

class AccountMove(models.Model):
    """Chilean DTE extension for account.move."""
    
    _inherit = 'account.move'
    
    # Field naming: l10n_cl_ prefix for Chilean localization
    l10n_cl_dte_type_id = fields.Many2one(
        'l10n_cl.dte.type',
        string='DTE Type',
        help="Chilean electronic document type (33, 34, 52, 56, 61)"
    )
    
    l10n_cl_folio = fields.Integer(
        string='Folio Number',
        readonly=True,
        help="Sequential folio from CAF authorization"
    )
    
    # Computed field with proper dependencies
    @api.depends('invoice_line_ids.price_subtotal', 'l10n_cl_dte_type_id')
    def _compute_l10n_cl_total_neto(self):
        """Compute 'Total Neto' for Chilean invoices."""
        for move in self:
            if move.l10n_cl_dte_type_id:
                move.l10n_cl_total_neto = sum(
                    line.price_subtotal 
                    for line in move.invoice_line_ids 
                    if not line.tax_ids
                )
            else:
                move.l10n_cl_total_neto = 0.0
    
    # Constraints with clear error messages
    @api.constrains('l10n_cl_folio', 'l10n_cl_dte_type_id')
    def _check_folio_unique(self):
        """Ensure folio is unique per DTE type."""
        for move in self:
            if move.l10n_cl_folio and move.l10n_cl_dte_type_id:
                duplicate = self.search([
                    ('id', '!=', move.id),
                    ('l10n_cl_folio', '=', move.l10n_cl_folio),
                    ('l10n_cl_dte_type_id', '=', move.l10n_cl_dte_type_id.id),
                    ('company_id', '=', move.company_id.id),
                ], limit=1)
                if duplicate:
                    raise ValidationError(
                        f"Folio {move.l10n_cl_folio} already exists for "
                        f"DTE type {move.l10n_cl_dte_type_id.name}"
                    )
    
    # Private methods with underscore prefix
    def _generate_dte_xml(self):
        """Generate DTE XML according to SII schema."""
        self.ensure_one()
        # Implementation...
```

**Key Principles:**

- ✅ Use `_inherit` instead of modifying core
- ✅ Prefix Chilean fields with `l10n_cl_`
- ✅ Add docstrings to all classes and methods
- ✅ Use `@api.depends()` for computed fields
- ✅ Validate with `@api.constrains()`
- ✅ Use `self.ensure_one()` in methods that operate on single records
- ✅ Handle multi-company with `company_id` filter
- ❌ NEVER use `self._cr.execute()` with user input (SQL injection)
- ❌ NEVER hardcode credentials or API keys

### XML (Views)

```xml
<!-- views/account_move_views.xml -->
<odoo>
    <record id="view_account_move_form_l10n_cl_dte" model="ir.ui.view">
        <field name="name">account.move.form.l10n.cl.dte</field>
        <field name="model">account.move</field>
        <field name="inherit_id" ref="account.view_move_form"/>
        <field name="arch" type="xml">
            <!-- Use t-out in Odoo 19 (NOT t-esc) -->
            <xpath expr="//field[@name='invoice_date']" position="after">
                <field name="l10n_cl_dte_type_id" 
                       groups="account.group_account_invoice"/>
                <field name="l10n_cl_folio" 
                       readonly="1"
                       groups="account.group_account_invoice"/>
            </xpath>
            
            <!-- Add new notebook page -->
            <xpath expr="//notebook" position="inside">
                <page string="Chilean DTE" name="l10n_cl_dte"
                      invisible="not l10n_cl_dte_type_id">
                    <group>
                        <group string="DTE Information">
                            <field name="l10n_cl_dte_status"/>
                            <field name="l10n_cl_sii_track_id"/>
                        </group>
                        <group string="SII Response">
                            <field name="l10n_cl_sii_response_date"/>
                            <field name="l10n_cl_sii_response_text"/>
                        </group>
                    </group>
                </page>
            </xpath>
        </field>
    </record>
</odoo>
```

**Key Principles:**

- ✅ Use `t-out` for Odoo 19 (deprecation of `t-esc`)
- ✅ Use explicit `xpath` expressions
- ✅ Group related fields logically
- ✅ Add `groups` attribute for access control
- ✅ Use `invisible` for conditional display
- ❌ NEVER use `t-raw` with user input (XSS)

### Testing

```python
# tests/test_dte_validation.py
from odoo.tests import tagged, TransactionCase
from odoo.exceptions import ValidationError

@tagged('post_install', '-at_install', 'l10n_cl')
class TestDTEValidation(TransactionCase):
    """Test DTE validation logic."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test data once for entire class."""
        super().setUpClass()
        
        cls.company = cls.env['res.company'].create({
            'name': 'Test Company CL',
            'vat': '76876876-8',
            'country_id': cls.env.ref('base.cl').id,
        })
        
        cls.dte_type_33 = cls.env['l10n_cl.dte.type'].create({
            'code': '33',
            'name': 'Factura Electrónica',
        })
    
    def test_rut_validation_valid(self):
        """Test valid RUT format and modulo 11 calculation."""
        partner = self.env['res.partner'].create({
            'name': 'Test Partner',
            'vat': '76876876-8',
            'country_id': self.env.ref('base.cl').id,
        })
        # Should not raise ValidationError
        self.assertTrue(partner.vat)
    
    def test_rut_validation_invalid(self):
        """Test invalid RUT checksum raises ValidationError."""
        with self.assertRaises(ValidationError):
            self.env['res.partner'].create({
                'name': 'Test Partner Invalid',
                'vat': '76876876-9',  # Invalid checksum
                'country_id': self.env.ref('base.cl').id,
            })
    
    def test_folio_unique_constraint(self):
        """Test folio uniqueness per DTE type."""
        # Create first invoice with folio
        invoice1 = self.env['account.move'].create({
            'company_id': self.company.id,
            'move_type': 'out_invoice',
            'l10n_cl_dte_type_id': self.dte_type_33.id,
            'l10n_cl_folio': 12345,
        })
        
        # Attempt to create duplicate folio should fail
        with self.assertRaises(ValidationError):
            self.env['account.move'].create({
                'company_id': self.company.id,
                'move_type': 'out_invoice',
                'l10n_cl_dte_type_id': self.dte_type_33.id,
                'l10n_cl_folio': 12345,  # Duplicate
            })
```

**Key Principles:**

- ✅ Use `@tagged` for test filtering
- ✅ Use `setUpClass` for expensive setup
- ✅ Test both positive and negative cases
- ✅ Use `self.assertRaises` for exception testing
- ✅ Aim for 80%+ code coverage
- ✅ Test edge cases (boundaries, nulls, empty strings)

---

## 🧪 Testing Guidelines

### Run Tests Locally

```bash
# All tests for module
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -v

# Specific test file
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_validation.py -v

# Specific test case
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/test_dte_validation.py::TestDTEValidation::test_rut_validation_valid -v

# With coverage
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ --cov=l10n_cl_dte --cov-report=term-missing

# Fast fail (stop on first failure)
docker compose exec odoo pytest /mnt/extra-addons/localization/l10n_cl_dte/tests/ -x
```

### Coverage Requirements

| Component | Minimum | Target |
|-----------|---------|--------|
| DTE Module | 75% | 85%+ |
| Payroll Module | 70% | 80%+ |
| Financial Reports | 65% | 75%+ |
| Critical validators | 90% | 100% |

### Test Data

Use realistic Chilean data for tests:

- **Valid RUTs**: 76.876.876-8, 12.345.678-5
- **Invalid RUTs**: 76.876.876-9 (wrong checksum)
- **DTE Types**: 33, 34, 52, 56, 61
- **UF Value**: ~36,000 CLP (update monthly)
- **Minimum Wage**: ~460,000 CLP (update annually)

---

## 🔀 Pull Request Process

### Before Creating PR

1. ✅ Sync with upstream develop
2. ✅ All tests pass locally
3. ✅ Code coverage meets requirements
4. ✅ No linting errors
5. ✅ Documentation updated if needed
6. ✅ Commits follow conventional format

```bash
# Sync with upstream
git fetch upstream
git rebase upstream/develop

# Run full test suite
docker compose exec odoo pytest /mnt/extra-addons/localization/ -v

# Check coverage
docker compose exec odoo pytest /mnt/extra-addons/localization/ --cov --cov-report=term-missing

# Lint check
docker compose exec odoo pylint /mnt/extra-addons/localization/
docker compose exec odoo black --check /mnt/extra-addons/localization/
```

### Create Pull Request

1. **Push to your fork**:
   ```bash
   git push origin feature/dte-validation-improvements
   ```

2. **Open PR on GitHub**:
   - Go to https://github.com/pwills85/odoo19
   - Click "New Pull Request"
   - Select: `base: develop` ← `compare: your-feature-branch`

3. **Fill PR template**:

```markdown
## 🎯 Description

Brief description of changes.

## 📝 Type of Change

- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change (fix or feature that breaks existing functionality)
- [ ] Documentation update
- [ ] Refactoring

## 🧪 Testing

- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing performed
- [ ] Coverage: 85%

## 📚 Chilean Localization Context

Relevant SII/Previred regulations:
- SII Resolution 80/2014 Article X
- DTE Schema v1.0 section Y

## ✅ Checklist

- [ ] Code follows project conventions
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings introduced
- [ ] Dependent changes merged
```

### PR Review Process

1. **Automated Checks**:
   - ✅ CI/CD pipeline passes
   - ✅ Tests pass (pytest)
   - ✅ Code quality (pylint, black)
   - ✅ Security scan (bandit)
   - ✅ Coverage maintained

2. **Code Review** (1-2 reviewers required):
   - Review code logic
   - Verify Chilean compliance
   - Check test coverage
   - Suggest improvements

3. **Author Response**:
   - Address review comments
   - Push fixes to same branch
   - Request re-review

4. **Merge**:
   - Squash and merge to develop
   - Delete feature branch
   - Celebrate! 🎉

### Review Response Time

- **P0 (Critical)**: 4 hours
- **P1 (High)**: 24 hours
- **P2 (Medium)**: 48 hours
- **P3 (Low)**: 1 week

---

## 🇨🇱 Chilean Localization Specifics

### SII Compliance

When working on DTE features:

1. **Validate XML Schema**: https://www.sii.cl/factura_electronica/formato_dte.pdf
2. **Test with SII Certification Environment**: https://maullin.sii.cl/
3. **Verify digital signatures**: Use `xmlsec1` command-line tool
4. **Check folio authorization**: CAF files must be valid

### Payroll Calculations

When modifying payroll:

1. **Economic Indicators**: Sync UF/UTM/IPC from official sources
2. **AFP**: 10% of base salary (max 90.3 UF)
3. **ISAPRE**: Minimum 7% (max 90.3 UF base)
4. **Previred Format**: Follow Circular 1/2018 specification

### Reference Documentation

- **SII**: https://www.sii.cl/servicios_online/1039-.html
- **Previred**: https://www.previred.com/web/previred/documentacion-tecnica
- **Labor Code**: https://www.bcn.cl/leychile/navegar?idNorma=207436
- **DTE Schema**: https://www.sii.cl/factura_electronica/

---

## 📞 Getting Help

- **Issues**: https://github.com/pwills85/odoo19/issues
- **Discussions**: https://github.com/pwills85/odoo19/discussions
- **Email**: pwills85@example.com (maintainer)

---

## 🏆 Recognition

Contributors are recognized in:

- CONTRIBUTORS.md file
- Release notes
- GitHub contributors page
- Annual acknowledgment post

Thank you for contributing! 🇨🇱✨

---

**Last Updated:** 2025-11-13  
**Maintainer:** Pedro Troncoso (@pwills85)
