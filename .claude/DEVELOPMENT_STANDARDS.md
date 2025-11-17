# 📋 DEVELOPMENT STANDARDS - EERGYGROUP Odoo 19 CE

**Status**: Production Standard v1.0
**Last Updated**: 2025-11-11
**Authority**: Senior Engineering Team
**Scope**: Code quality, testing, documentation, security
**Relationship**: Complements `.claude/DESIGN_MAXIMS.md` (architectural principles)

---

## 🎯 PURPOSE

This document defines **CODING STANDARDS** and **DEVELOPMENT PRACTICES** for EERGYGROUP Odoo 19 CE project.

**Relationship to Design Maxims**:
- **DESIGN_MAXIMS.md**: WHAT to build (architectural decisions)
- **DEVELOPMENT_STANDARDS.md**: HOW to build (code quality standards)

**Enforcement**:
- Pre-commit hooks validate standards automatically
- Code review checklist ensures compliance
- CI/CD pipeline blocks non-compliant code

---

## 1️⃣ PYTHON CODE STANDARDS

### PEP 8 Compliance (MANDATORY)

**Tools**: `black`, `flake8`, `isort`

```python
# ✅ CORRECT: PEP 8 compliant
class DTEValidator:
    """DTE validation for Chilean tax documents."""

    def validate_rut(self, rut: str) -> bool:
        """
        Validate Chilean RUT using modulo 11 algorithm.

        Args:
            rut: RUT string in format XX.XXX.XXX-Y or XXXXXXXXY

        Returns:
            True if RUT is valid, False otherwise

        Raises:
            ValueError: If RUT format is invalid
        """
        clean_rut = rut.replace('.', '').replace('-', '')
        if not clean_rut[:-1].isdigit():
            raise ValueError(f"Invalid RUT format: {rut}")

        return self._calculate_check_digit(clean_rut[:-1]) == clean_rut[-1]

    def _calculate_check_digit(self, digits: str) -> str:
        """Calculate RUT check digit using modulo 11."""
        # Implementation
        pass


# ❌ WRONG: Not PEP 8 compliant
class dteValidator:  # Class name should be CamelCase
    def ValidateRut(self,rut):  # Missing spaces, PascalCase for method
        cleanRut=rut.replace('.','').replace('-','')  # No spaces around =
        return True  # No type hints, no docstring
```

### Code Formatting Standards

**Line Length**: 88 characters (black default)
**Indentation**: 4 spaces (NO tabs)
**Quotes**: Double quotes `"` for strings (black default)
**Trailing Commas**: Yes for multiline structures

```python
# ✅ CORRECT: Proper formatting
invoice_data = {
    "partner_id": partner.id,
    "move_type": "out_invoice",
    "invoice_date": fields.Date.today(),
    "dte_type": "33",  # Trailing comma
}

# ❌ WRONG: No trailing comma, inconsistent quotes
invoice_data = {
    'partner_id': partner.id,
    'move_type': 'out_invoice',
    'invoice_date': fields.Date.today(),
    'dte_type': '33'  # Missing trailing comma
}
```

### Type Hints (STRONGLY RECOMMENDED)

**Status**: Recommended for new code, mandatory for libs/

```python
# ✅ CORRECT: Type hints for clarity
from typing import Optional, List, Dict, Any
from odoo import models, fields

def calculate_tax(
    amount: float,
    tax_rate: float,
    rounding: Optional[int] = 2,
) -> float:
    """Calculate tax with proper rounding."""
    tax = amount * tax_rate
    return round(tax, rounding)


def get_active_cafs(
    company_id: int,
    document_type: str,
) -> List[Dict[str, Any]]:
    """Get active CAF certificates for company and document type."""
    # Implementation
    pass


# ⚠️ ACCEPTABLE but not recommended: No type hints
def calculate_tax(amount, tax_rate, rounding=2):
    """Calculate tax with proper rounding."""
    return round(amount * tax_rate, rounding)
```

### Docstring Standards (MANDATORY)

**Format**: Google-style docstrings

```python
# ✅ CORRECT: Complete Google-style docstring
def send_dte_to_sii(
    self,
    dte_xml: str,
    company_id: int,
    environment: str = "certificacion",
) -> Dict[str, Any]:
    """
    Send DTE XML to SII webservice.

    This method submits a DTE (Electronic Tax Document) to the Chilean
    tax authority (SII) webservice. It handles authentication, XML signing,
    and response parsing.

    Args:
        dte_xml: DTE XML string (must be valid against SII XSD)
        company_id: Odoo company ID (for certificate lookup)
        environment: SII environment ("certificacion" or "produccion")

    Returns:
        Dictionary containing:
            - status: "success" or "error"
            - track_id: SII tracking ID (if successful)
            - error_code: SII error code (if failed)
            - message: Human-readable message

    Raises:
        ValueError: If XML is invalid or company has no certificate
        requests.RequestException: If SII webservice is unreachable

    Example:
        >>> result = send_dte_to_sii(
        ...     dte_xml="<DTE>...</DTE>",
        ...     company_id=1,
        ...     environment="certificacion",
        ... )
        >>> print(result["track_id"])
        "123456789"

    Note:
        This method requires valid SII credentials configured in
        company settings (RUT, password, certificate).

    SII Reference:
        - Res. Exenta 11/2014 (DTE framework)
        - https://www.sii.cl/factura_electronica/
    """
    # Implementation
    pass


# ❌ WRONG: Incomplete docstring
def send_dte_to_sii(self, dte_xml, company_id, environment="certificacion"):
    """Send DTE to SII."""  # Too brief, missing details
    pass
```

### Import Organization (MANDATORY)

**Tool**: `isort` with Odoo profile

```python
# ✅ CORRECT: Organized imports
# Standard library
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# Third-party
import requests
from lxml import etree

# Odoo
from odoo import _, api, fields, models
from odoo.exceptions import UserError, ValidationError

# Current module
from ..libs.dte_validator import DTEValidator
from ..libs.rut_validator import RUTValidator

_logger = logging.getLogger(__name__)


# ❌ WRONG: Unorganized imports
from odoo import models, api  # Out of order
import logging  # Should be first
from ..libs.dte_validator import DTEValidator
import requests  # Should be after stdlib
from datetime import datetime  # Should be with stdlib
from odoo.exceptions import UserError
```

---

## 2️⃣ ODOO-SPECIFIC STANDARDS

### Model Naming Conventions

**Rules**:
- Class names: CamelCase
- Model `_name`: lowercase with dots
- Inherit existing models when possible (see DESIGN_MAXIMS.md)

```python
# ✅ CORRECT: Proper naming
class AccountMoveDTE(models.Model):
    """Extends account.move with Chilean DTE functionality."""
    _inherit = 'account.move'  # Extend existing model
    _description = 'Account Move with DTE'

    dte_type = fields.Selection([...])  # Snake_case for fields
    dte_folio = fields.Integer()


class L10nClComuna(models.Model):
    """Chilean commune (administrative division)."""
    _name = 'l10n.cl.comuna'  # Lowercase with dots
    _description = 'Chilean Commune'

    code = fields.Char(required=True)
    name = fields.Char(required=True)


# ❌ WRONG: Improper naming
class accountMoveDTE(models.Model):  # Should be CamelCase
    _name = 'AccountMoveDTE'  # Should be lowercase with dots
    _description = 'Account Move DTE'  # Missing 'with' clarity

    DTEtype = fields.Selection([...])  # Should be snake_case
    DteFolio = fields.Integer()  # Should be snake_case
```

### Field Naming Conventions

**Rules**:
- Always use snake_case
- Use descriptive names (no abbreviations unless standard)
- Prefix with `l10n_cl_` for Chilean-specific fields

```python
# ✅ CORRECT: Descriptive field names
class ResPartner(models.Model):
    _inherit = 'res.partner'

    # Chilean-specific fields with l10n_cl_ prefix
    l10n_cl_activity_description = fields.Char(
        string='Activity Description',
        help='Business activity registered with SII',
    )

    l10n_cl_dte_email = fields.Char(
        string='DTE Email',
        help='Email for receiving electronic tax documents',
    )

    # Clear, descriptive names
    is_dte_enabled = fields.Boolean(
        string='DTE Enabled',
        default=False,
    )


# ❌ WRONG: Poor naming
class ResPartner(models.Model):
    _inherit = 'res.partner'

    # Missing l10n_cl_ prefix for Chilean fields
    activity_desc = fields.Char()  # Abbreviated, unclear

    # Unclear abbreviation
    dte_mail = fields.Char()  # Use 'email' not 'mail'

    # Unclear boolean
    dte = fields.Boolean()  # What about DTE? Use 'is_dte_enabled'
```

### Method Naming Conventions

**Rules**:
- Public methods: snake_case, descriptive
- Private methods: prefix with `_`
- Computed methods: `_compute_<field_name>`
- Constraint methods: `_check_<constraint_name>`

```python
# ✅ CORRECT: Proper method naming
class AccountMove(models.Model):
    _inherit = 'account.move'

    # Computed field method
    @api.depends('line_ids.price_subtotal')
    def _compute_dte_total(self):
        """Compute DTE total amount."""
        for record in self:
            record.dte_total = sum(record.line_ids.mapped('price_subtotal'))

    # Constraint method
    @api.constrains('dte_folio', 'caf_id')
    def _check_folio_range(self):
        """Validate folio is within CAF range."""
        for record in self:
            if not record.caf_id.is_folio_valid(record.dte_folio):
                raise ValidationError(_('Folio out of range'))

    # Public action method
    def action_send_to_sii(self):
        """Send DTE to SII webservice."""
        self.ensure_one()
        return self._send_dte_to_sii_internal()

    # Private helper method
    def _send_dte_to_sii_internal(self):
        """Internal method to send DTE to SII."""
        # Implementation
        pass


# ❌ WRONG: Improper naming
class AccountMove(models.Model):
    _inherit = 'account.move'

    # Missing _compute_ prefix
    @api.depends('line_ids.price_subtotal')
    def calculate_total(self):  # Should be _compute_dte_total
        pass

    # Missing _check_ prefix
    @api.constrains('dte_folio')
    def validate_folio(self):  # Should be _check_folio_range
        pass

    # Public method shouldn't have _ prefix
    def _send_to_sii(self):  # Should be action_send_to_sii (public)
        pass
```

### File Structure Standards

**Mandatory structure** for Odoo modules:

```
addons/localization/l10n_cl_dte/
├── __init__.py                     # Module initialization
├── __manifest__.py                 # Module manifest
├── models/                         # ORM models
│   ├── __init__.py
│   ├── account_move.py             # One class per file
│   ├── res_partner.py
│   └── dte_caf.py
├── libs/                           # Pure Python business logic
│   ├── __init__.py
│   ├── dte_validator.py            # No ORM dependencies
│   ├── rut_validator.py
│   └── xml_signer.py
├── wizards/                        # Transient models (wizards)
│   ├── __init__.py
│   └── dte_send_wizard.py
├── views/                          # XML views
│   ├── account_move_views.xml
│   ├── res_partner_views.xml
│   └── menus.xml
├── data/                           # Master data
│   ├── dte_document_types.xml
│   └── l10n_cl_comunas.xml
├── security/                       # Access control
│   ├── ir.model.access.csv
│   └── dte_security.xml
├── tests/                          # Automated tests
│   ├── __init__.py
│   ├── test_account_move_dte.py
│   └── test_dte_validator.py
├── static/                         # Static assets
│   └── src/
│       ├── js/
│       ├── css/
│       └── xml/
└── README.md                       # Module documentation
```

### `__manifest__.py` Standards

```python
# ✅ CORRECT: Complete manifest
{
    'name': 'Chilean Localization - DTE',
    'version': '19.0.1.0.0',  # Odoo_version.major.minor.patch
    'category': 'Accounting/Localizations',
    'summary': 'Electronic Tax Documents (DTE) for Chile',
    'description': """
Chilean Electronic Tax Documents (DTE)
=======================================

This module implements Chilean DTE (Documentos Tributarios Electrónicos)
compliance according to SII regulations.

Features:
- DTE types: 33, 34, 52, 56, 61
- CAF management
- Digital signature (XMLDSig)
- SII webservice integration

SII References:
- Res. Exenta 11/2014 (DTE framework)
- https://www.sii.cl/factura_electronica/
    """,
    'author': 'EERGYGROUP',
    'website': 'https://eergygroup.com',
    'license': 'LGPL-3',
    'depends': [
        'account',
        'l10n_cl',
    ],
    'data': [
        # Security (always first)
        'security/ir.model.access.csv',
        'security/dte_security.xml',

        # Data
        'data/dte_document_types.xml',

        # Wizards
        'wizards/dte_send_wizard_views.xml',

        # Views
        'views/account_move_views.xml',
        'views/res_partner_views.xml',

        # Menus (always last)
        'views/menus.xml',
    ],
    'demo': [
        'demo/demo_data.xml',
    ],
    'test': [],
    'installable': True,
    'application': False,
    'auto_install': False,
}


# ❌ WRONG: Incomplete manifest
{
    'name': 'DTE',  # Too brief
    'version': '1.0',  # Wrong version format
    'depends': ['base'],  # Missing 'account'
    'data': [
        'views/views.xml',  # Wrong order, no security
    ],
}
```

---

## 3️⃣ TESTING STANDARDS

### Test File Organization

**Rules**:
- One test file per model
- Test methods start with `test_`
- Use descriptive test names

```python
# ✅ CORRECT: Well-organized test file
# tests/test_account_move_dte.py

from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError


class TestAccountMoveDTE(TransactionCase):
    """Test suite for account.move DTE functionality."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.partner = self.env['res.partner'].create({
            'name': 'Test Partner',
            'vat': '76.123.456-7',
        })
        self.caf = self.env['dte.caf'].create({
            'document_type': '33',
            'folio_start': 1,
            'folio_end': 100,
        })

    def test_generate_dte_success(self):
        """Test successful DTE generation."""
        invoice = self.env['account.move'].create({
            'partner_id': self.partner.id,
            'move_type': 'out_invoice',
        })
        invoice.action_generate_dte()

        self.assertTrue(invoice.dte_xml)
        self.assertEqual(invoice.dte_type, '33')

    def test_generate_dte_without_caf_raises_error(self):
        """Test DTE generation fails without active CAF."""
        self.caf.unlink()  # Remove CAF

        invoice = self.env['account.move'].create({
            'partner_id': self.partner.id,
            'move_type': 'out_invoice',
        })

        with self.assertRaises(ValidationError):
            invoice.action_generate_dte()

    def test_validate_rut_modulo_11(self):
        """Test RUT validation using modulo 11 algorithm."""
        # Valid RUT
        self.assertTrue(self.partner._validate_rut('76.123.456-7'))

        # Invalid RUT (wrong check digit)
        with self.assertRaises(ValidationError):
            self.env['res.partner'].create({
                'name': 'Invalid Partner',
                'vat': '76.123.456-0',  # Invalid
            })
```

### Test Coverage Requirements

**Minimum coverage targets**:
- **Critical paths**: 100% (DTE signature, CAF validation, RUT validation)
- **Business logic**: 90% (models, libs/)
- **Controllers**: 80%
- **Views**: Not measured (use manual testing)

**Coverage command**:
```bash
coverage run --source=addons/localization/l10n_cl_dte \
    odoo -u l10n_cl_dte --test-enable --stop-after-init

coverage report -m
coverage html  # Generate HTML report
```

### Test Naming Convention

```python
# ✅ CORRECT: Descriptive test names
def test_generate_dte_with_valid_caf_succeeds(self):
    """Test DTE generation succeeds when valid CAF exists."""
    pass

def test_send_dte_to_sii_returns_track_id(self):
    """Test SII webservice returns tracking ID on success."""
    pass

def test_validate_rut_with_invalid_format_raises_error(self):
    """Test RUT validation raises ValueError for invalid format."""
    pass


# ❌ WRONG: Unclear test names
def test_dte(self):  # What about DTE?
    pass

def test_1(self):  # Meaningless name
    pass

def test_sii(self):  # What about SII?
    pass
```

---

## 4️⃣ DOCUMENTATION STANDARDS

### Code Comments

**Rules**:
- Explain WHY, not WHAT (code should be self-explanatory)
- Comment complex algorithms
- Reference regulatory requirements (SII resolutions)

```python
# ✅ CORRECT: Useful comments
def calculate_dte_totals(self):
    """Calculate DTE totals according to SII requirements."""
    # SII Res. 11/2014 requires rounding to 2 decimal places
    # BEFORE summing totals to avoid cumulative rounding errors
    subtotals = [round(line.amount, 2) for line in self.line_ids]
    total = sum(subtotals)

    # Exempt amount (tax-free products)
    exempt = sum(
        line.amount
        for line in self.line_ids
        if line.tax_ids.filtered(lambda t: t.amount == 0)
    )

    return {
        'total': total,
        'exempt': exempt,
        'taxable': total - exempt,
    }


# ❌ WRONG: Obvious comments
def calculate_dte_totals(self):
    # Calculate totals  (Obvious from method name)
    total = 0  # Initialize total to zero (Obvious)
    for line in self.line_ids:  # Loop through lines (Obvious)
        total += line.amount  # Add amount to total (Obvious)
    return total  # Return total (Obvious)
```

### README Standards

**Required sections** for modules:

```markdown
# Module Name

## Overview
Brief description (1-2 sentences).

## Features
- Feature 1
- Feature 2

## Installation
1. Step 1
2. Step 2

## Configuration
How to configure the module.

## Usage
How to use key features.

## Technical Details
- Model: account.move (extended)
- Dependencies: account, l10n_cl
- External APIs: SII webservice

## Compliance
- SII Res. Exenta 11/2014
- SII Res. Exenta 36/2024

## Testing
How to run tests.

## Known Issues
- Issue 1
- Issue 2

## Roadmap
- Future feature 1
- Future feature 2

## Contributing
How to contribute.

## License
LGPL-3

## Authors
EERGYGROUP

## References
- https://www.sii.cl/factura_electronica/
```

---

## 5️⃣ GIT & VERSION CONTROL STANDARDS

### Commit Message Format

**Format**: `<type>(<scope>): <subject>`

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code refactoring (no functional change)
- `perf`: Performance improvement
- `test`: Add/update tests
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `chore`: Maintenance (dependencies, build, etc.)

```bash
# ✅ CORRECT: Well-formatted commits
git commit -m "feat(dte): add DTE 39 (Boleta) support

- Implement Boleta Electrónica generation
- Add PDF417 barcode for TED
- Validate 135 UF threshold (Res. 44/2025)

Refs: #123
SII: Res. Exenta 44/2025"

git commit -m "fix(payroll): correct AFP cap to 87.8 UF

Previous hardcoded 83.1 UF caused Previred rejections.
Now uses dynamic UF value from economic indicators.

Refs: #456
Critical: P0"

git commit -m "refactor(dte): extract RUT validation to libs/

Moved RUT validation logic from models/ to libs/rut_validator.py
for better testability and reusability.

No functional changes."


# ❌ WRONG: Poor commit messages
git commit -m "fix bug"  # What bug?
git commit -m "update code"  # What code? Why?
git commit -m "changes"  # What changes?
git commit -m "WIP"  # Never commit WIP to main
```

### Branch Naming Convention

**Format**: `<type>/<ticket>-<short-description>`

```bash
# ✅ CORRECT: Descriptive branch names
git checkout -b feat/ODOO-123-dte-boleta-support
git checkout -b fix/ODOO-456-afp-cap-87-8-uf
git checkout -b refactor/ODOO-789-extract-rut-validation


# ❌ WRONG: Unclear branch names
git checkout -b my-branch
git checkout -b fix
git checkout -b test123
```

### Pull Request Standards

**Required sections**:

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] New feature
- [ ] Bug fix
- [ ] Refactoring
- [ ] Performance improvement
- [ ] Documentation update

## Checklist
- [ ] Code follows project standards
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] All tests pass
- [ ] No linting errors
- [ ] Design maxims validated

## Testing
How to test these changes.

## Screenshots (if applicable)
Before/after screenshots.

## Related Issues
Closes #123
Refs #456

## Compliance
SII Res. Exenta 44/2025
```

---

## 6️⃣ SECURITY STANDARDS

### Input Validation (MANDATORY)

```python
# ✅ CORRECT: Proper input validation
@api.constrains('vat')
def _check_vat_format(self):
    """Validate RUT format."""
    for partner in self:
        if partner.country_id.code == 'CL' and partner.vat:
            # Sanitize input
            clean_rut = re.sub(r'[^0-9Kk-]', '', partner.vat)

            # Validate format
            if not re.match(r'^\d{7,8}-[\dKk]$', clean_rut):
                raise ValidationError(_('Invalid RUT format'))

            # Validate check digit
            if not self._validate_rut_modulo_11(clean_rut):
                raise ValidationError(_('Invalid RUT check digit'))


# ❌ WRONG: No input validation
def process_rut(self, rut):
    # Direct use without validation (SQL injection risk)
    self.env.cr.execute(f"SELECT * FROM res_partner WHERE vat = '{rut}'")
```

### SQL Injection Prevention (MANDATORY)

```python
# ✅ CORRECT: Use ORM or parameterized queries
# Option 1: Use ORM (preferred)
partners = self.env['res.partner'].search([
    ('vat', '=', rut),
    ('country_id.code', '=', 'CL'),
])

# Option 2: Parameterized query (if ORM insufficient)
self.env.cr.execute(
    "SELECT * FROM res_partner WHERE vat = %s",
    (rut,)  # Parameters passed separately
)


# ❌ WRONG: String concatenation (SQL injection risk)
self.env.cr.execute(
    f"SELECT * FROM res_partner WHERE vat = '{rut}'"  # DANGEROUS!
)
```

### XSS Prevention (MANDATORY)

```python
# ✅ CORRECT: Use Odoo's escaping
from markupsafe import Markup

message = Markup(
    '<p>Invoice <strong>%s</strong> sent to SII.</p>'
) % (invoice.name,)  # Automatically escaped


# ❌ WRONG: Direct HTML concatenation
message = f'<p>Invoice <strong>{invoice.name}</strong> sent.</p>'  # XSS risk
```

### Secret Management (MANDATORY)

```python
# ✅ CORRECT: Secrets in environment variables or Odoo config
import os

SII_USERNAME = os.getenv('SII_USERNAME')
SII_PASSWORD = os.getenv('SII_PASSWORD')

# Or from Odoo config
sii_username = self.env['ir.config_parameter'].sudo().get_param('sii.username')


# ❌ WRONG: Hardcoded secrets
SII_USERNAME = 'myuser'  # NEVER hardcode secrets
SII_PASSWORD = 'mypassword123'  # NEVER commit passwords
```

---

## 7️⃣ PERFORMANCE STANDARDS

### ORM Optimization

```python
# ✅ CORRECT: Optimized ORM queries
# Batch read with 'in' operator
partner_ids = [1, 2, 3, 4, 5]
partners = self.env['res.partner'].browse(partner_ids)
names = partners.mapped('name')  # Single SQL query

# Prefetch related records
invoices = self.env['account.move'].search([
    ('state', '=', 'posted'),
])
# Prefetch partners (single query instead of N+1)
invoices.mapped('partner_id.name')


# ❌ WRONG: N+1 queries
for invoice in invoices:
    # Triggers separate SQL query for EACH invoice
    partner_name = invoice.partner_id.name  # N+1 problem!
```

### Computed Field Optimization

```python
# ✅ CORRECT: Efficient computed field
@api.depends('line_ids.price_subtotal')
def _compute_amount_total(self):
    """Compute total efficiently."""
    for record in self:
        # Single aggregation query
        record.amount_total = sum(record.line_ids.mapped('price_subtotal'))


# ❌ WRONG: Inefficient computed field
@api.depends('line_ids')
def _compute_amount_total(self):
    """Compute total inefficiently."""
    for record in self:
        total = 0
        for line in record.line_ids:
            # Triggers query for EACH line
            total += line.price_subtotal  # Inefficient!
        record.amount_total = total
```

---

## 8️⃣ LOGGING STANDARDS

### Logging Levels

```python
import logging

_logger = logging.getLogger(__name__)

# ✅ CORRECT: Appropriate logging levels
_logger.debug('DTE XML: %s', dte_xml)  # Debug info (verbose)
_logger.info('DTE sent to SII, track_id: %s', track_id)  # Important events
_logger.warning('CAF expires in 7 days')  # Warnings (not errors)
_logger.error('Failed to send DTE: %s', error_msg)  # Errors (recoverable)
_logger.critical('SII certificate expired')  # Critical (system failure)


# ❌ WRONG: Inappropriate logging
print('DTE sent')  # Never use print(), use _logger
_logger.info('Variable x = %s', x)  # Use debug() for variables
_logger.error('CAF will expire soon')  # Use warning() for non-errors
```

### Structured Logging

```python
# ✅ CORRECT: Structured logging with context
_logger.info(
    'DTE sent to SII',
    extra={
        'invoice_id': invoice.id,
        'partner_id': invoice.partner_id.id,
        'dte_type': invoice.dte_type,
        'track_id': track_id,
    }
)


# ❌ WRONG: Unstructured logging
_logger.info(f'DTE sent: {invoice.id}, partner: {invoice.partner_id.id}')
```

---

## 9️⃣ ERROR HANDLING STANDARDS

### Exception Handling

```python
# ✅ CORRECT: Specific exception handling
from odoo.exceptions import UserError, ValidationError
import requests

def send_dte_to_sii(self):
    """Send DTE to SII with proper error handling."""
    try:
        response = requests.post(
            'https://maullin.sii.cl/...',
            data={'xml': self.dte_xml},
            timeout=30,
        )
        response.raise_for_status()
        return self._parse_sii_response(response.text)

    except requests.Timeout:
        _logger.error('SII webservice timeout')
        raise UserError(_('SII service is unavailable. Please try again later.'))

    except requests.HTTPError as e:
        _logger.error('SII HTTP error: %s', e)
        raise UserError(_('SII rejected the request: %s') % e)

    except Exception as e:
        _logger.exception('Unexpected error sending DTE')
        raise UserError(_('Failed to send DTE: %s') % str(e))


# ❌ WRONG: Bare except or too broad
def send_dte_to_sii(self):
    try:
        response = requests.post('https://...')
        return response.text
    except:  # NEVER use bare except
        pass  # Silently fails, no logging
```

---

## 🔍 VALIDATION FRAMEWORK

### Pre-Commit Checklist

```bash
# Run these commands before committing

# 1. Format code
black addons/localization/l10n_cl_dte/
isort addons/localization/l10n_cl_dte/

# 2. Lint code
flake8 addons/localization/l10n_cl_dte/ --max-line-length=88

# 3. Run tests
docker-compose exec odoo odoo -u l10n_cl_dte --test-enable --stop-after-init

# 4. Check coverage
coverage report -m

# 5. Validate XML
xmllint --noout addons/localization/l10n_cl_dte/views/*.xml
```

### Code Review Checklist

**For code reviewers**:

```
□ Code Quality
  □ Follows PEP 8 (black formatted)
  □ Has type hints (for libs/)
  □ Has docstrings (Google style)
  □ Imports organized (isort)

□ Odoo Standards
  □ Proper model naming (_inherit vs _name)
  □ Field names with l10n_cl_ prefix
  □ Correct file structure
  □ Complete __manifest__.py

□ Design Maxims (CRITICAL)
  □ Maxim #1: Uses _inherit (not duplicate models)
  □ Maxim #2: Critical path in libs/ (not AI Service)

□ Testing
  □ Tests added/updated
  □ Coverage meets targets (80%+)
  □ Tests pass in CI/CD

□ Security
  □ Input validation present
  □ No SQL injection risks
  □ No XSS risks
  □ Secrets not hardcoded

□ Performance
  □ No N+1 queries
  □ Computed fields optimized
  □ Indexes added if needed

□ Documentation
  □ README updated
  □ Code comments for complex logic
  □ SII references cited

□ Git Standards
  □ Commit message formatted correctly
  □ Branch name follows convention
  □ PR description complete
```

---

## 📚 REFERENCES

### Internal Documentation
- **Design Maxims**: `.claude/DESIGN_MAXIMS.md` (architectural principles)
- **Project Architecture**: `.claude/agents/knowledge/project_architecture.md`
- **Odoo 19 Patterns**: `.claude/agents/knowledge/odoo19_patterns.md`

### External Standards
- **PEP 8**: https://peps.python.org/pep-0008/
- **Odoo Guidelines**: https://www.odoo.com/documentation/19.0/developer/reference/backend/guidelines.html
- **Google Python Style**: https://google.github.io/styleguide/pyguide.html

### Tools
- **black**: https://github.com/psf/black
- **flake8**: https://flake8.pycqa.org/
- **isort**: https://pycqa.github.io/isort/
- **coverage**: https://coverage.readthedocs.io/

---

## 🎯 SUCCESS CRITERIA

**Code meets development standards when**:

✅ **Code Quality**
- PEP 8 compliant (black formatted)
- Type hints present (for libs/)
- Complete docstrings (Google style)
- Organized imports (isort)

✅ **Odoo Standards**
- Proper naming conventions
- Correct file structure
- Complete manifest
- Follows inheritance patterns

✅ **Testing**
- Coverage ≥80% (≥90% for critical paths)
- All tests pass
- Tests are descriptive

✅ **Security**
- Input validated
- No injection risks
- Secrets managed properly

✅ **Documentation**
- README complete
- Code commented appropriately
- SII references cited

✅ **Design Maxims**
- Maxim #1 validated (Odoo integration)
- Maxim #2 validated (AI integration)

---

**Version**: 1.0.0
**Status**: Production Standard
**Authority**: EERGYGROUP Senior Engineering Team
**Last Review**: 2025-11-11
**Next Review**: 2025-12-11

---

*These standards ensure our codebase remains maintainable, secure, performant, and compliant with industry best practices.*
