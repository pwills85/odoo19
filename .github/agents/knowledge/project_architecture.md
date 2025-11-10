# EERGYGROUP Project Architecture

**For:** All agents working on this project
**Purpose:** Understand project-specific architecture and decisions

---

## Project Overview

**Client:** EERGYGROUP
**Project:** Odoo 19 CE Chilean Localization (3 modules)
**Status:** Production v1.0.5 (Certified - Zero Warnings)
**Certification Date:** 2025-11-07

### Modules

```
l10n_cl_dte                    100% Backend Complete, Certified
├── Lines of Code: 18,388
├── Model Files: 40+
├── Test Coverage: 80%
└── Status: ✅ Production Ready

l10n_cl_hr_payroll             78% Complete (Sprint 4.1)
├── Model Files: 28
├── Coverage: P0/P1 gaps closed
└── Status: 🔄 Active Development

l10n_cl_financial_reports      67% Complete (Phase 3-4)
├── Model Files: 56
├── Architecture: Service Registry pattern
└── Status: 🔄 Active Development
```

---

## Architecture Evolution (CRITICAL)

### Phase 1: Microservices (2024-01 to 2024-10)

```
OLD ARCHITECTURE (Deprecated):
┌──────────────┐
│  Odoo 19 CE  │
│              │
│  l10n_cl_dte │
└──────┬───────┘
       │ HTTP
       ▼
┌──────────────┐     ┌──────────────┐
│ AI Service   │────▶│ Redis Queue  │
│ (FastAPI)    │     │ (optional)   │
└──────────────┘     └──────────────┘
```

**Why Changed:**
- HTTP overhead (~100-200ms per request)
- Network latency
- Deployment complexity
- Reliability concerns (network failures)

### Phase 2: Native Python libs/ (2024-10 onwards)

```
CURRENT ARCHITECTURE (v1.0.5):
┌──────────────────────────────────┐
│           Odoo 19 CE             │
│                                  │
│  ┌────────────────────────────┐  │
│  │   l10n_cl_dte              │  │
│  │                            │  │
│  │  models/  ←─── libs/       │  │
│  │  (ORM)        (Pure Python)│  │
│  └────────────────────────────┘  │
│                                  │
│  AI Service (FastAPI)            │
│  └─ NON-critical path only       │
└──────────────────────────────────┘
```

**Benefits:**
- ✅ No HTTP overhead (100-200ms faster)
- ✅ No network dependencies
- ✅ Simpler deployment (single container)
- ✅ More reliable (no network failures)
- ✅ Easier testing (no mocks needed)

**AI Service Role (Post-Migration):**
- ❌ NOT for critical path (DTE signature, validation)
- ✅ ONLY for non-critical features:
  - AI Chat (Previred questions)
  - Project matching (ML predictions)
  - Cost tracking/analytics

---

## libs/ Directory Pattern (CRITICAL)

### Structure

```
l10n_cl_dte/libs/
├── caf_signature_validator.py      # CAF validation (SII)
├── dte_structure_validator.py      # DTE structure validation
├── rut_validator.py                 # RUT modulo 11
├── safe_xml_parser.py               # XXE-safe XML parsing
├── sii_error_codes.py               # 59 SII error codes mapped
├── sii_soap_client.py               # SOAP client for SII
├── xml_canonicalizer.py             # C14N canonicalization
├── xml_generator.py                 # DTE XML generation
└── xml_signer.py                    # XMLDSig signature
```

### Design Principles

**1. Pure Python Classes**
```python
# ✅ CORRECT: Pure Python
class DTEStructureValidator:
    """No Odoo dependencies"""

    def __init__(self):
        pass

    def validate_dte_structure(self, dte_data):
        """Pure function: data in, result out"""
        # Business logic only
        return is_valid, errors

# ❌ WRONG: Don't do this in libs/
class DTEValidator(models.AbstractModel):
    _name = 'dte.validator'
    # ERROR: AbstractModel not allowed in libs/
```

**2. Dependency Injection When Needed**
```python
# For libs/ that need DB access
class XMLSigner:

    def __init__(self, env=None):
        """Inject env for DB access"""
        self.env = env

    def sign_xml(self, xml, cert_id):
        # Uses self.env to load certificate
        cert = self.env['dte.certificate'].browse(cert_id)
```

**3. Separation of Concerns**
```
libs/        → Business logic (pure Python)
models/      → ORM integration (data access)
services/    → Complex operations (orchestration)
wizards/     → User interactions (UI logic)
```

---

## Key Architectural Decisions

### 1. EXTEND, NOT DUPLICATE

**Pattern:**
```python
# ✅ CORRECT: Extend existing Odoo model
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'

    # Add ONLY DTE-specific fields
    dte_status = fields.Selection([...])
    dte_folio = fields.Char()
    # ... etc

# ❌ WRONG: Create new model duplicating core
class CustomInvoice(models.Model):
    _name = 'custom.invoice'

    # Duplicates all account.move fields
    partner_id = fields.Many2one('res.partner')
    amount_total = fields.Monetary()
    # ... BAD: Breaks Odoo workflows
```

**Why:**
- Reuses Odoo workflows (invoicing, payments, etc.)
- Maintains compatibility with other modules
- Easier upgrades
- Less code to maintain

### 2. Multi-Company vs Shared Data

**Transactional Data (has company_id):**
```python
class DTECertificate(models.Model):
    _name = 'dte.certificate'

    company_id = fields.Many2one(
        'res.company',
        required=True,
        default=lambda self: self.env.company,
    )
    # Each company has own certificate
```

**Master Data (NO company_id):**
```python
class L10nClComuna(models.Model):
    _name = 'l10n.cl.comuna'

    # NO company_id - shared across all companies
    code = fields.Char()
    name = fields.Char()
    # 347 Chilean communes same for everyone
```

**Decision Rule:**
```
Does data vary per company?
  YES → Add company_id + multi-company rule
  NO  → Shared (no company_id)
```

### 3. Security Layers

**Three-Level Security:**

```
Level 1: Groups
├── group_dte_user         → Read-only
└── group_dte_manager      → Full access

Level 2: Access Rights (ir.model.access.csv)
├── Users: Read on models
└── Managers: Full CRUD

Level 3: Record Rules
├── Multi-company: domain [('company_id', 'in', company_ids)]
└── Custom business rules
```

### 4. Testing Strategy

**Coverage Targets:**
- Critical paths: 100% (signature, SII communication)
- DTE module: 80% (achieved)
- Payroll: 70% (target)
- Financial Reports: 65% (target)

**Mock External Services:**
```python
@patch('l10n_cl_dte.libs.sii_soap_client.SIISoapClient.send_dte_to_sii')
def test_dte_submission(self, mock_sii):
    mock_sii.return_value = {'track_id': 'TEST', 'status': 'accepted'}
    # Test without actual SII call
```

---

## Module Dependencies

### Dependency Graph

```
l10n_cl_dte
├── base (Odoo core)
├── account (Accounting)
├── l10n_latam_base (LATAM foundation)
├── l10n_latam_invoice_document (Fiscal documents)
└── l10n_cl (Chilean chart of accounts)

l10n_cl_hr_payroll
├── base
├── hr (Human Resources)
├── hr_payroll (Payroll core)
└── l10n_cl (Chilean localization)

l10n_cl_financial_reports
├── base
├── account
├── account_reports (Odoo enterprise reports)
└── l10n_cl_dte (for DTE integration)
```

**IMPORTANT:**
- l10n_cl_dte is INDEPENDENT (can work alone)
- l10n_cl_hr_payroll is INDEPENDENT
- l10n_cl_financial_reports DEPENDS on l10n_cl_dte

---

## Data Flow Patterns

### DTE Emission Flow

```
1. User creates invoice (account.move)
   └─> account_move_dte.py (extends account.move)

2. User clicks "Generate DTE"
   └─> action_generate_dte()
       ├─> libs/xml_generator.py → Generate XML
       ├─> libs/xml_signer.py → Sign XML
       └─> Update dte_xml field

3. User clicks "Send to SII"
   └─> action_send_dte()
       ├─> libs/sii_soap_client.py → SOAP call
       └─> Update dte_status + dte_track_id

4. Cron job polls SII status
   └─> _cron_check_dte_status()
       ├─> Query SII with track_id
       └─> Update dte_status (accepted/rejected)
```

### CAF Management Flow

```
1. Admin uploads CAF from SII
   └─> dte.caf model
       ├─> Validate signature (libs/caf_signature_validator.py)
       ├─> Extract folio range
       └─> Encrypt private key (cryptography.fernet)

2. Invoice creation needs folio
   └─> Get next folio from active CAF
       ├─> Check remaining folios
       ├─> Assign to invoice
       └─> Increment current folio

3. CAF exhausted
   └─> Notify admin to upload new CAF
```

---

## Chilean-Specific Patterns

### RUT Handling (3 Formats)

```python
# Storage (database)
vat = '12345678-5'  # Clean + dash

# SII XML
<RUTEmisor>12345678-5</RUTEmisor>  # Dash, no dots

# Display (UI)
12.345.678-5  # Full format with dots
```

**Implementation:**
```python
# Storage
vat = fields.Char(help='Format: 12345678-5')

# For SII XML
def _format_rut_sii(self, rut):
    return re.sub(r'[.\s]', '', rut)  # Remove dots, keep dash

# For display
@tools.ormcache('vat')
def _format_rut_display(self, vat):
    # Add dots: 12.345.678-5
```

### Chilean Currency (CLP)

```xml
<!-- CLP has 0 decimal places -->
<field name="amount_total" widget="monetary"
       options="{'currency_field': 'currency_id', 'field_digits': [0, 0]}"/>
```

**IMPORTANT:** All amounts in CLP are integers (no cents).

### Chilean Date Format

```python
# SII requires ISO 8601
dte_date = fields.Date('DTE Date')

def _format_date_sii(self, date):
    """SII format: YYYY-MM-DD"""
    return date.strftime('%Y-%m-%d')
```

---

## Performance Optimizations

### 1. ORM Cache Usage

```python
# Frequently called formatting
@tools.ormcache('vat_number')
def _format_rut_cached(self, vat_number):
    # Cached by vat_number
    return formatted_rut
```

### 2. Computed Fields with Store

```python
# Store frequently accessed computed fields
folio_remaining = fields.Integer(
    compute='_compute_folio_remaining',
    store=True,  # Stored in DB for performance
)
```

### 3. Batch Operations

```python
@api.model_create_multi
def create(self, vals_list):
    # Process multiple records in single transaction
    return super().create(vals_list)
```

---

## Security Best Practices

### 1. Certificate Encryption

```python
# NEVER store private keys in plain text
rsask_encrypted = fields.Binary(
    help='RSA Private Key encrypted with Fernet (AES-128)'
)

# Decrypt only in memory
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)
decrypted = cipher.decrypt(encrypted_key)
```

### 2. XXE Protection

```python
# libs/safe_xml_parser.py
parser = etree.XMLParser(
    no_network=True,        # No network access
    dtd_validation=False,   # No DTD processing
    load_dtd=False,         # Don't load DTD
    resolve_entities=False, # No entity resolution
)
```

### 3. SQL Injection Prevention

```python
# ✅ ALWAYS use ORM
records = self.env['account.move'].search([('state', '=', 'draft')])

# ❌ NEVER use raw SQL with user input
self.env.cr.execute(f"SELECT * FROM account_move WHERE state = '{state}'")
```

---

## Quick Reference

### File Organization

```
addons/localization/l10n_cl_dte/
├── __init__.py
├── __manifest__.py
├── models/                # ORM integration
│   ├── __init__.py
│   ├── account_move_dte.py
│   └── dte_certificate.py
├── libs/                  # Pure Python business logic
│   ├── xml_generator.py
│   └── xml_signer.py
├── views/                 # UI (XML)
│   ├── account_move_views.xml
│   └── menus.xml
├── security/              # Access control
│   ├── security_groups.xml
│   ├── multi_company_rules.xml
│   └── ir.model.access.csv
├── data/                  # Master data
│   └── l10n_cl_comunas_data.xml
├── wizards/               # User interactions
│   └── dte_send_wizard.py
└── tests/                 # Unit tests
    └── test_dte_certificate.py
```

### Common Patterns

**Create a model:**
1. Add to `models/model_name.py`
2. Import in `models/__init__.py`
3. Add access rights in `security/ir.model.access.csv`
4. Add multi-company rule if needed
5. Create views in `views/model_name_views.xml`
6. Add menu in `views/menus.xml`
7. Write tests in `tests/test_model_name.py`

**Add a computed field:**
1. Define field with `compute='_compute_field'`
2. Add `@api.depends('dependency_fields')`
3. Implement `_compute_field(self)` method
4. Add `store=True` if frequently accessed
5. Test computation in unit tests

**Inherit a model:**
1. Use `_inherit = 'existing.model'`
2. Add ONLY new fields (don't duplicate)
3. Override methods with `super()` call
4. Test inheritance doesn't break core

---

**Last Updated:** 2025-11-08
**Version:** 1.0.5
**Source:** EERGYGROUP project analysis
**Architecture:** Native Python libs/ (post-microservices migration)
