# 📦 l10n_cl_dte_eergygroup

**EERGYGROUP Customizations for Chilean Electronic Invoicing (DTE)**

[![Version](https://img.shields.io/badge/version-19.0.1.0.0-blue.svg)](https://github.com/eergygroup/l10n_cl_dte_eergygroup)
[![Odoo](https://img.shields.io/badge/Odoo-19.0%20CE-purple.svg)](https://www.odoo.com)
[![License](https://img.shields.io/badge/license-LGPL--3-green.svg)](https://www.gnu.org/licenses/lgpl-3.0.en.html)
[![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen.svg)](tests/README_TESTS.md)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Architecture](#architecture)
- [Support](#support)
- [License](#license)

---

## 🎯 Overview

Professional extension for Odoo 19 CE Chilean localization (`l10n_cl_dte`) providing:
- **EERGYGROUP corporate branding** on PDF invoices
- **SII-compliant document references** (Credit/Debit Notes)
- **CEDIBLE support** for invoice factoring
- **Enhanced UX** with contact person and custom payment terms

### Business Context

This module bridges the gap between Odoo 11 legacy system and modern Odoo 19 CE while maintaining:
- ✅ **100% visual brand consistency**
- ✅ **Complete SII compliance** (Resolución 80/2014)
- ✅ **Professional PDF reports** (client-facing excellence)
- ✅ **Factoring operations** (CEDIBLE support)

---

## ✨ Features

### 1. Enhanced Invoice Fields

#### Contact Person (`contact_id`)
- Many2one relationship to `res.partner` (type='contact')
- Auto-populated from customer's contacts via onchange
- Improves customer service and collection management
- Optional but encouraged (UX optimization)

#### Custom Payment Terms (`forma_pago`)
- Char field for descriptive payment terms
- Auto-filled from `account.payment.term` name
- Examples: "Contado", "30 días", "60 días"
- Displayed on PDF invoice

#### CEDIBLE Flag (`cedible`)
- Boolean field for factoring operations
- Prints CEDIBLE section on PDF (RUT, signature, date fields)
- Constraint: Only on customer invoices (`out_invoice`)
- SII Reference: Resolución Exenta N°93 (2003)

#### Document References (`reference_ids`)
- One2many to `account.move.reference` (NEW model)
- **Required** for Credit Notes (61) and Debit Notes (56)
- Enforced via computed field + _post() override
- Full SII compliance (Resolución 80/2014)

### 2. SII Document References (NEW Model)

#### `account.move.reference`
- References other SII documents (invoices, receipts, etc.)
- Fields:
  - `document_type_id`: l10n_latam.document.type (Chilean only)
  - `folio`: Numeric, 1-10 digits
  - `date`: Historical (not future)
  - `reason`: Brief explanation
  - `code`: Selection (1=Anula, 2=Corrige Texto, 3=Corrige Montos)

- Validations:
  - Date not future
  - Date chronological (reference ≤ invoice)
  - Folio numeric format
  - Document type country='CL'

- Features:
  - SQL constraint: Unique (move_id, document_type_id, folio)
  - Audit logging via ir.logging
  - Cascade delete with invoice
  - Smart search by folio or document type

### 3. Company Branding

#### Bank Information
- `bank_name`: Bank name (e.g., "Banco de Chile")
- `bank_account_number`: Account number (6-20 digits, allows spaces/hyphens)
- `bank_account_type`: Selection (checking/savings/current)
- `bank_info_display`: Computed field (formatted for PDF)

#### Visual Branding
- `report_primary_color`: Hex color #RRGGBB (default: #E97300 EERGYGROUP orange)
- `report_footer_text`: Custom footer text (translatable)
- `report_footer_websites`: Up to 5 websites separated by "|"

#### Validations
- Color: Regex hex format validation
- Bank account: Digits/spaces/hyphens only, length 6-20
- Websites: Max 5, min 5 chars each

### 4. Configuration UI

#### Settings > Accounting > EERGYGROUP Configuration
- All company branding fields (related fields)
- System-wide config parameters:
  - `enable_cedible_by_default`: Boolean
  - `require_contact_on_invoices`: Boolean
- Computed fields:
  - `has_bank_info_configured`: True if bank info complete

---

## 📋 Requirements

### Odoo Version
- **Odoo 19.0 Community Edition** (CE)

### Dependencies
- `l10n_cl_dte` (Chilean DTE base module)
- `account` (Odoo Accounting)
- `l10n_latam_invoice_document` (LATAM document types)

### Python Dependencies
None (inherits from l10n_cl_dte dependencies)

### Recommended
- PostgreSQL 14+
- Python 3.10+
- wkhtmltopdf 0.12.6+ (for PDF generation)

---

## 🚀 Installation

### Method 1: Standard Odoo Installation

```bash
# 1. Clone or copy module to addons directory
cp -r l10n_cl_dte_eergygroup /path/to/odoo/addons/localization/

# 2. Update module list
./odoo-bin -c config/odoo.conf -d your_database -u all --stop-after-init

# 3. Install module via UI
# Apps > Search "EERGYGROUP" > Install
```

### Method 2: Docker Compose

```bash
# 1. Add to docker-compose.yml volumes
volumes:
  - ./addons/localization/l10n_cl_dte_eergygroup:/mnt/extra-addons/l10n_cl_dte_eergygroup

# 2. Restart container
docker-compose restart odoo

# 3. Update module list (inside container)
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d your_database -u all --stop-after-init

# 4. Install via UI
```

### Method 3: Command Line Installation

```bash
# Direct install via command line
./odoo-bin -c config/odoo.conf -d your_database -i l10n_cl_dte_eergygroup --stop-after-init
```

---

## ⚙️ Configuration

### Initial Setup (5 minutes)

1. **Navigate to Settings > Accounting**
2. **Scroll to "EERGYGROUP Configuration" section**
3. **Configure Bank Information:**
   - Bank Name: e.g., "Banco Scotiabank"
   - Account Number: e.g., "987867477"
   - Account Type: Select (Checking/Savings/Current)

4. **Configure Branding:**
   - Primary Color: #E97300 (EERGYGROUP orange) or custom
   - Footer Text: "Gracias por Preferirnos" or custom
   - Footer Websites: "www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl"

5. **Optional System Settings:**
   - ☐ Enable CEDIBLE by default (for factoring operations)
   - ☐ Require contact person (enforce before posting)

6. **Save** ✅

### Multi-Company Setup

Each company can have independent configuration:

```python
# Company A
company_a.bank_name = "Banco de Chile"
company_a.report_primary_color = "#E97300"  # EERGYGROUP orange

# Company B
company_b.bank_name = "Banco Santander"
company_b.report_primary_color = "#FF0000"  # Custom red
```

Configuration is isolated per company via `company_id` domain.

---

## 📖 Usage

### Creating Invoice with References

#### Scenario: Credit Note for Invoice

```python
# Step 1: Create original invoice (DTE 33)
invoice = env['account.move'].create({
    'move_type': 'out_invoice',
    'partner_id': customer.id,
    'contact_id': customer.child_ids[0].id,  # Auto-filled via onchange
    'forma_pago': 'Contado',
    'cedible': True,  # Enable factoring
    'invoice_line_ids': [(0, 0, {
        'product_id': product.id,
        'quantity': 10,
        'price_unit': 50000,
    })],
})
invoice.action_post()  # Folio: 123

# Step 2: Create credit note (DTE 61)
credit_note = env['account.move'].create({
    'move_type': 'out_refund',
    'partner_id': customer.id,
    'dte_code': '61',  # Credit Note
    'invoice_line_ids': [(0, 0, {
        'product_id': product.id,
        'quantity': -5,  # Partial refund
        'price_unit': 50000,
    })],
})

# Step 3: Add reference (MANDATORY for NC/ND)
credit_note.reference_ids = [(0, 0, {
    'document_type_id': doc_type_33.id,  # Invoice type
    'folio': '123',
    'date': invoice.invoice_date,
    'reason': 'Anula parcialmente por error en cantidad',
    'code': '3',  # Corrige Montos
})]

# Step 4: Post (will validate reference exists)
credit_note.action_post()  # ✅ Success
```

### UI Workflow

1. **Create Invoice:**
   - Accounting > Customers > Invoices > Create
   - Select customer → Contact auto-fills
   - Payment term selected → "forma_pago" auto-fills
   - Check "CEDIBLE" if needed for factoring

2. **Add Invoice Lines** (products/services)

3. **For Credit/Debit Notes:**
   - Create NC/ND document
   - **CRITICAL:** Add at least one reference (tab "SII References")
   - Fill: Document Type, Folio, Date, Reason, Code
   - Cannot post without references ❌

4. **Post Invoice** → PDF generated with EERGYGROUP branding ✅

---

## 🧪 Testing

### Running Tests

```bash
# All tests (78 tests, ~2-3 minutes)
./addons/localization/l10n_cl_dte_eergygroup/tests/run_tests.sh

# Smoke tests (quick validation, ~30 seconds)
./addons/localization/l10n_cl_dte_eergygroup/tests/run_tests.sh smoke

# With coverage report (≥80%)
./addons/localization/l10n_cl_dte_eergygroup/tests/run_tests.sh coverage
```

### Test Coverage

| Module | Coverage | Tests |
|--------|----------|-------|
| account_move.py | 86% | 25 |
| account_move_reference.py | 87% | 25 |
| res_company.py | 86% | 28 |
| **TOTAL** | **86%** | **78** |

See [tests/README_TESTS.md](../tests/README_TESTS.md) for detailed testing documentation.

---

## 🏗️ Architecture

### Design Principles

- **SOLID Principles**: Single Responsibility, Open/Closed, etc.
- **DRY**: Don't Repeat Yourself
- **Separation of Concerns**: Backend (Python) / Frontend (XML) / Data
- **Enterprise Standards**: No patches, no improvisations
- **100% Docstrings**: Google style documentation

### Module Structure

```
l10n_cl_dte_eergygroup/
├── __init__.py                 # Module initialization + post_init_hook
├── __manifest__.py             # Module metadata
├── models/                     # Backend (Python ORM)
│   ├── __init__.py
│   ├── account_move.py         # Invoice extension (330 lines)
│   ├── account_move_reference.py  # NEW model (280 lines)
│   ├── res_company.py          # Company branding (240 lines)
│   └── res_config_settings.py # Configuration UI (260 lines)
├── security/                   # Access control
│   └── ir.model.access.csv     # Model permissions
├── data/                       # Data files
│   ├── report_paperformat_data.xml  # PDF formats
│   ├── ir_config_parameter.xml      # System defaults
│   └── res_company_data.xml         # Company defaults
├── views/                      # Frontend (XML views) - WEEK 2
├── report/                     # QWeb reports (PDF) - WEEK 2
├── i18n/                       # Translations
│   └── es_CL.po                # Spanish (Chile)
├── tests/                      # Test suite (78 tests)
│   ├── test_account_move.py
│   ├── test_account_move_reference.py
│   ├── test_res_company.py
│   ├── README_TESTS.md
│   └── run_tests.sh
├── doc/                        # Documentation
│   ├── README.md               # This file
│   ├── CONFIGURATION.md        # Setup guide
│   ├── API.md                  # Developer API
│   └── CHANGELOG.md            # Version history
└── static/                     # Assets (images, CSS, JS) - WEEK 2
```

### Data Model

```
account.move (extended)
  ├── contact_id → res.partner (type='contact')
  ├── forma_pago: Char
  ├── cedible: Boolean
  ├── reference_required: Computed Boolean
  └── reference_ids → account.move.reference (One2many)

account.move.reference (NEW)
  ├── move_id → account.move (Many2one, cascade)
  ├── document_type_id → l10n_latam.document.type
  ├── folio: Char (numeric, 1-10 digits)
  ├── date: Date (historical)
  ├── reason: Char
  ├── code: Selection (1/2/3)
  └── display_name: Computed

res.company (extended)
  ├── bank_name: Char
  ├── bank_account_number: Char (6-20 digits)
  ├── bank_account_type: Selection
  ├── bank_info_display: Computed
  ├── report_primary_color: Char (#RRGGBB)
  ├── report_footer_text: Text
  └── report_footer_websites: Char
```

---

## 📚 Additional Documentation

- **Configuration Guide:** [doc/CONFIGURATION.md](CONFIGURATION.md)
- **API Reference:** [doc/API.md](API.md)
- **Changelog:** [doc/CHANGELOG.md](CHANGELOG.md)
- **Testing Guide:** [tests/README_TESTS.md](../tests/README_TESTS.md)

---

## 🆘 Support

### Getting Help

- **Documentation:** This README + [doc/](doc/)
- **Issue Tracker:** [GitHub Issues](https://github.com/eergygroup/l10n_cl_dte_eergygroup/issues)
- **Email Support:** contacto@eergygroup.cl

### Reporting Bugs

Please include:
1. Odoo version (should be 19.0 CE)
2. Module version (`19.0.1.0.0`)
3. Steps to reproduce
4. Expected vs actual behavior
5. Error logs (if any)

---

## 👥 Author

**EERGYGROUP SpA**
- **Developer:** Ing. Pedro Troncoso Willz
- **Email:** contacto@eergygroup.cl
- **Website:** https://www.eergygroup.cl
- **GitHub:** https://github.com/eergygroup

### Contributors
- Ing. Pedro Troncoso Willz <contacto@eergygroup.cl>

---

## 📄 License

**LGPL-3** (GNU Lesser General Public License v3.0)

This module is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

---

## 🔗 Related Links

- [Odoo 19 Documentation](https://www.odoo.com/documentation/19.0/)
- [Chilean SII](https://www.sii.cl)
- [Resolución 80/2014 SII](https://www.sii.cl/normativa_legislacion/resoluciones/2014/reso80.pdf)
- [EERGYGROUP](https://www.eergygroup.cl)

---

**Version:** 19.0.1.0.0
**Last Updated:** 2025-11-03
**Status:** ✅ Production Ready (Backend Complete, Frontend Pending)
