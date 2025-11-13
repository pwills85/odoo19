# Odoo 19 Patterns & Best Practices

**For:** All agents working on Odoo 19 CE
**Purpose:** Odoo 19-specific patterns (NOT Odoo 11-16)

---

## CRITICAL: Odoo 19 Changes

Odoo 19 introduced breaking changes from previous versions. **DO NOT** suggest patterns from Odoo 11-16.

### What Changed in Odoo 19

```
Feature                   Odoo 11-16              Odoo 19
──────────────────────────────────────────────────────────────────
libs/ directory           AbstractModel OK        ❌ Pure Python ONLY
_sql_constraints          Used                    ❌ Deprecated → @api.constrains
XML views                 version="1.0"           No version attribute
Security                  <field eval/>           Direct eval= syntax
Workflow                  workflow.py             States in models
```

---

## 1. Pure Python libs/ Pattern (CRITICAL)

### ❌ OLD PATTERN (Odoo 11-16) - DO NOT USE

```python
# libs/xml_generator.py
from odoo import models, fields, api

class DTEXMLGenerator(models.AbstractModel):
    _name = 'dte.xml.generator'
    _description = 'DTE XML Generator'

    def generate_xml(self):
        self._logger.info('Generating XML')
        # Uses self.env, self._logger from AbstractModel
```

### ✅ NEW PATTERN (Odoo 19) - USE THIS

```python
# libs/xml_generator.py
# NO Odoo imports for pure business logic

class DTEXMLGenerator:
    """
    Pure Python class for DTE XML generation.

    Odoo 19 Requirement: libs/ MUST contain pure Python.
    No models.AbstractModel allowed.
    """

    def __init__(self):
        """No env dependency for pure logic"""
        pass

    def generate_xml(self, dte_data):
        """
        Pure function: data in, XML out.

        Args:
            dte_data (dict): DTE information

        Returns:
            str: Generated XML
        """
        # Uses lxml directly, no ORM
        # Returns result, no side effects
```

### Dependency Injection Pattern

For libs/ classes that NEED database access:

```python
# libs/xml_signer.py
class XMLSigner:
    """
    XML signing - needs env for certificate DB access.

    Pattern: Dependency Injection
    """

    def __init__(self, env=None):
        """
        Args:
            env: Odoo environment (optional, for DB access)
        """
        self.env = env

    def sign_xml_dte(self, xml_string, certificate_id):
        """
        Uses self.env to load certificate from database.

        Args:
            xml_string (str): XML to sign
            certificate_id (int): Certificate record ID

        Returns:
            str: Signed XML
        """
        if not self.env:
            raise ValueError('env required for certificate DB access')

        # Load from DB using injected env
        cert = self.env['dte.certificate'].browse(certificate_id)
        # ... signing logic


# Usage from models/:
from ..libs.xml_signer import XMLSigner

class AccountMoveDTE(models.Model):
    _inherit = 'account.move'

    def action_sign_dte(self):
        # Inject env when creating instance
        signer = XMLSigner(self.env)
        signed_xml = signer.sign_xml_dte(
            self.dte_xml,
            self.company_id.certificate_id.id
        )
```

**Key Rules:**
1. **libs/** = Pure Python classes (no models.AbstractModel)
2. **models/** = ORM integration layer (models.Model)
3. **Injection** = Pass env as argument when DB access needed
4. **Separation** = Business logic (libs) vs Data access (models)

---

## 2. Constraints Pattern

### ❌ OLD PATTERN (Deprecated)

```python
class DTECertificate(models.Model):
    _name = 'dte.certificate'

    # Deprecated in Odoo 19
    _sql_constraints = [
        ('unique_certificate_company',
         'UNIQUE(company_id)',
         'Only one certificate per company')
    ]
```

### ✅ NEW PATTERN (Odoo 19)

```python
class DTECertificate(models.Model):
    _name = 'dte.certificate'

    # Use @api.constrains decorator
    @api.constrains('company_id')
    def _check_unique_certificate_company(self):
        """
        Odoo 19 Pattern: Constraints via decorators.

        Replaces: _sql_constraints (deprecated)
        """
        for record in self:
            existing = self.search([
                ('company_id', '=', record.company_id.id),
                ('id', '!=', record.id),
            ])
            if existing:
                raise ValidationError(
                    _('Only one certificate allowed per company. '
                      'Found existing certificate: %s') % existing.name
                )
```

**Why Changed:**
- Better error messages
- Easier to test
- More flexible validation logic
- Database-agnostic (works with PostgreSQL, MySQL, etc.)

---

## 3. Computed Fields Pattern

### Best Practice: @api.depends with Store

```python
class DTECAF(models.Model):
    _name = 'dte.caf'

    folio_desde = fields.Integer('From Folio', required=True)
    folio_hasta = fields.Integer('To Folio', required=True)
    folio_current = fields.Integer('Current Folio', default=0)

    # Computed field with caching
    folio_remaining = fields.Integer(
        string='Remaining Folios',
        compute='_compute_folio_remaining',
        store=True,  # IMPORTANT: Store for performance
        help='Calculated: folio_hasta - folio_current'
    )

    @api.depends('folio_desde', 'folio_hasta', 'folio_current')
    def _compute_folio_remaining(self):
        """
        Odoo 19 Best Practice:
        - Use @api.depends for cache invalidation
        - Store=True for frequently accessed fields
        - Batch computation (for record in self)
        """
        for caf in self:
            caf.folio_remaining = caf.folio_hasta - caf.folio_current
```

**Benefits:**
- Automatic cache invalidation when dependencies change
- Reduced database queries
- Better performance

---

## 4. Batch Operations Pattern

### ❌ SLOW: One-by-one

```python
def create(self, vals):
    # Slow - creates one record at a time
    record = super().create(vals)
    # ... logic
    return record
```

### ✅ FAST: Batch

```python
@api.model_create_multi
def create(self, vals_list):
    """
    Odoo 19 Best Practice: Batch create.

    Args:
        vals_list (list): List of value dicts

    Returns:
        recordset: Created records
    """
    records = super().create(vals_list)

    # Batch processing
    for record in records:
        # Process each record
        pass

    return records
```

**Why:**
- Single database transaction
- Reduced overhead
- 10-100x faster for bulk operations

---

## 5. ORM Cache Pattern

### Use tools.ormcache for Expensive Operations

```python
from odoo import tools

class ResPartner(models.Model):
    _inherit = 'res.partner'

    @tools.ormcache('vat_number')
    def _format_rut_cached(self, vat_number):
        """
        Format RUT with ORM cache.

        Odoo 19 Pattern: Cache expensive formatting operations.

        Args:
            vat_number (str): Raw RUT

        Returns:
            str: Formatted RUT (XX.XXX.XXX-X)
        """
        # Expensive regex operations cached by vat_number
        clean_rut = re.sub(r'[.\-\s]', '', str(vat_number))
        # ... formatting logic
        return formatted_rut
```

**When to Use:**
- Formatting operations called frequently
- Complex calculations
- External API calls (with care)
- Static data lookups

**Cache Invalidation:**
```python
# Clear cache when data changes
self._format_rut_cached.clear_cache(self)
```

---

## 6. Security Pattern (Multi-Company)

### Record Rules for Multi-Company

```xml
<!-- security/multi_company_rules.xml -->
<record id="rule_dte_certificate_company" model="ir.rule">
    <field name="name">DTE Certificate: multi-company</field>
    <field name="model_id" ref="model_dte_certificate"/>
    <field name="domain_force">[('company_id', 'in', company_ids)]</field>
    <field name="global" eval="True"/>
</record>
```

### When to Add company_id

**✅ YES - Transactional Data:**
- dte.certificate (company-specific certificates)
- dte.caf (company-specific folios)
- account.move (invoices belong to company)
- All data that varies per company

**❌ NO - Master Data/Catalogs:**
- l10n_cl.comuna (347 Chilean communes - shared)
- sii.activity.code (SII catalog - shared)
- l10n_cl.retencion_iue.tasa (historical tax rates - shared)
- Any data that's identical across companies

**Decision Tree:**
```
Does this data vary per company?
  → YES: Add company_id + record rule
  → NO: Shared across companies (no company_id)
```

---

## 7. View Inheritance Pattern

### XPath Best Practices

```xml
<record id="view_account_move_form_inherit_dte" model="ir.ui.view">
    <field name="name">account.move.form.inherit.dte</field>
    <field name="model">account.move</field>
    <field name="inherit_id" ref="account.view_move_form"/>
    <field name="arch" type="xml">

        <!-- Pattern 1: Add field AFTER existing -->
        <xpath expr="//field[@name='partner_id']" position="after">
            <field name="dte_status" widget="badge"/>
        </xpath>

        <!-- Pattern 2: Add page to notebook -->
        <xpath expr="//notebook" position="inside">
            <page string="DTE Info" name="dte_info">
                <group>
                    <field name="dte_folio"/>
                    <field name="dte_track_id"/>
                </group>
            </page>
        </xpath>

        <!-- Pattern 3: Add button to button_box -->
        <xpath expr="//div[@name='button_box']" position="inside">
            <button name="action_send_dte" type="object"
                    class="oe_stat_button" icon="fa-paper-plane"
                    attrs="{'invisible': [('dte_status', '!=', 'draft')]}">
                <span>Send to SII</span>
            </button>
        </xpath>

        <!-- Pattern 4: Modify existing field -->
        <xpath expr="//field[@name='invoice_date']" position="attributes">
            <attribute name="required">1</attribute>
            <attribute name="help">Required for DTE emission</attribute>
        </xpath>

    </field>
</record>
```

**Key Rules:**
1. Always use `inherit_id` (don't replace original view)
2. Use specific XPath (don't use `//field[@name='']` without context)
3. Use `position="after"` for new fields (maintain layout)
4. Add `attrs` for conditional visibility
5. Use semantic names (not generic IDs)

---

## 8. Manifest Structure Pattern

### Standard manifest.py Structure

```python
{
    'name': 'Chilean Localization - DTE',
    'version': '19.0.1.0.0',  # ALWAYS start with 19.0
    'category': 'Accounting/Localizations',
    'author': 'EERGYGROUP - Ing. Pedro Troncoso Willz',
    'website': 'https://eergygroup.cl',
    'license': 'LGPL-3',  # or AGPL-3 for proprietary
    'summary': 'Chilean Electronic Tax Documents (DTE) for SII',

    # Dependencies in priority order
    'depends': [
        'base',                            # Required
        'account',                         # Core accounting
        'l10n_latam_base',                # LATAM foundation
        'l10n_latam_invoice_document',    # Fiscal documents
        'l10n_cl',                        # Chilean chart of accounts
        # ... feature-specific modules
    ],

    # External dependencies with comments
    'external_dependencies': {
        'python': [
            'lxml',          # XML generation
            'xmlsec',        # Digital signature
            'zeep',          # SOAP client for SII
            'cryptography',  # Certificate encryption
        ],
    },

    # CRITICAL: Data loading order
    'data': [
        # 1. Security ALWAYS FIRST
        'security/security_groups.xml',
        'security/multi_company_rules.xml',
        'security/ir.model.access.csv',

        # 2. Data/configuration
        'data/config_parameters.xml',
        'data/l10n_cl_comunas_data.xml',
        'data/sii_activity_codes.xml',

        # 3. Cron jobs
        'data/cron_jobs.xml',

        # 4. Wizards (define actions)
        'wizards/dte_send_wizard_views.xml',

        # 5. Views (define actions)
        'views/dte_certificate_views.xml',
        'views/dte_caf_views.xml',
        'views/account_move_views.xml',

        # 6. Menus LAST (reference actions)
        'views/menus.xml',
    ],

    # Optional hooks
    'post_init_hook': 'post_init_hook',

    # Installation flags
    'installable': True,
    'application': True,  # False for dependencies
    'auto_install': False,
}
```

**Data Loading Order (CRITICAL):**
```
1. security/          ← MUST be first (defines groups/rules)
2. data/              ← Master data
3. wizards/           ← Wizards before views (actions referenced)
4. views/             ← Views define actions
5. menus.xml          ← MUST be last (references actions)
```

**Why Order Matters:**
- Menus reference actions (must exist first)
- Actions reference views (must exist first)
- Views may reference wizards (must exist first)
- Everything needs security groups (must be first)

---

## 9. Testing Pattern

### Standard Test Class

```python
from odoo.tests.common import TransactionCase
from odoo.exceptions import ValidationError

class TestDTECertificate(TransactionCase):
    """
    Tests for DTE Certificate according to SII regulations.

    Odoo 19 Pattern: TransactionCase for unit tests.
    """

    def setUp(self):
        """Setup test data"""
        super().setUp()

        # Store model references
        self.Certificate = self.env['dte.certificate']
        self.Company = self.env['res.company']

        # Setup company
        self.company = self.Company.create({
            'name': 'Test Company',
            'vat': '76123456-K',
            'country_id': self.env.ref('base.cl').id,
        })

    def test_01_certificate_creation_basic(self):
        """Test basic certificate creation"""
        cert = self.Certificate.create({
            'name': 'Test Certificate',
            'company_id': self.company.id,
            'pfx_file': b'test_pfx_content',
            'pfx_password': 'test_password',
        })

        self.assertTrue(cert.id)
        self.assertEqual(cert.company_id, self.company)

    def test_02_certificate_unique_constraint(self):
        """Test: Only one certificate per company (Odoo 19 @api.constrains)"""
        # Create first certificate
        self.Certificate.create({
            'name': 'Certificate 1',
            'company_id': self.company.id,
            'pfx_file': b'cert1',
            'pfx_password': 'pass1',
        })

        # Try to create second (should fail)
        with self.assertRaises(ValidationError):
            self.Certificate.create({
                'name': 'Certificate 2',
                'company_id': self.company.id,
                'pfx_file': b'cert2',
                'pfx_password': 'pass2',
            })
```

**Naming Conventions:**
- Test file: `test_[feature].py`
- Test class: `Test[Feature](TransactionCase)`
- Test methods: `test_NN_[description]` (NN = sequential)
- Use Spanish for business logic comments
- Use English for technical comments

---

## 10. Performance Best Practices

### 1. Avoid N+1 Queries

```python
# ❌ BAD: N+1 queries
def process_invoices(self):
    for invoice in self.invoices:
        partner_name = invoice.partner_id.name  # Query per invoice!

# ✅ GOOD: Prefetch
def process_invoices(self):
    # Single query with prefetch
    invoices = self.invoices.with_context(prefetch_fields=True)
    for invoice in invoices:
        partner_name = invoice.partner_id.name  # Cached
```

### 2. Use read() for Large Datasets

```python
# ❌ SLOW: ORM overhead
invoices = self.env['account.move'].search([])
for invoice in invoices:
    data = {
        'number': invoice.name,
        'amount': invoice.amount_total,
    }

# ✅ FAST: Direct read
invoice_data = self.env['account.move'].search_read(
    [],
    ['name', 'amount_total']
)
for data in invoice_data:
    number = data['name']
    amount = data['amount_total']
```

### 3. Batch Database Operations

```python
# ❌ SLOW: Multiple writes
for value in values_list:
    record.write({'field': value})

# ✅ FAST: Single write
record.write({'field': values_list[-1]})

# Or batch update
records.write({'state': 'done'})
```

---

## Quick Checklist for Odoo 19 Compliance

Before writing any Odoo 19 code:

- [ ] libs/ contains PURE Python (no AbstractModel)
- [ ] Use @api.constrains (not _sql_constraints)
- [ ] Use @api.depends for computed fields
- [ ] Add store=True for frequently accessed computed fields
- [ ] Use @api.model_create_multi for batch operations
- [ ] Add company_id ONLY to transactional data
- [ ] Data loading order: security → data → wizards → views → menus
- [ ] Views use XPath inheritance (not replacement)
- [ ] Tests use TransactionCase
- [ ] Version starts with 19.0.

---

**Last Updated:** 2025-11-08
**Source:** Odoo 19 official documentation + EERGYGROUP project analysis
**Compliance:** Odoo 19 CE standards
