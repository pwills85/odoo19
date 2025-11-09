# 📦 l10n_cl_dte_enhanced

**Enhanced DTE Features for Chilean Electronic Invoicing**

[![Version](https://img.shields.io/badge/version-19.0.1.0.0-blue.svg)](https://github.com/eergygroup/l10n_cl_dte_enhanced)
[![Odoo](https://img.shields.io/badge/Odoo-19.0%20CE-purple.svg)](https://www.odoo.com)
[![License](https://img.shields.io/badge/license-LGPL--3-green.svg)](https://www.gnu.org/licenses/lgpl-3.0.en.html)
[![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen.svg)](tests/README_TESTS.md)

---

## 🎯 Purpose

Professional enhancements for Chilean electronic invoicing (DTE) focused on:
- ✅ **SII Compliance** (Resoluciones 80/2014, 93/2003)
- ✅ **UX Improvements** (auto-fill, better workflows)
- ✅ **Chilean Business Practices** (forma_pago, CEDIBLE, bank info)

**IMPORTANT:** This module is **GENERIC** - it provides FUNCTIONALITY only.
For visual customization (branding), install a separate branding module.

---

## ✨ Features

### 1. SII Document References (NEW MODEL)

**`account.move.reference`** - Complete support for SII references

- **REQUIRED** for Credit Notes (DTE 61) and Debit Notes (DTE 56) per SII Resolución 80/2014
- References original invoices or documents being corrected/cancelled
- Fields: document_type, folio, date, reason, reference_code
- Validations: date not future, folio numeric, Chilean documents only
- Audit logging via ir.logging

### 2. Extended Invoice Fields

**`account.move` extensions:**

- **`contact_id`**: Contact person at customer/vendor (auto-populated from partner)
- **`forma_pago`**: Descriptive payment terms (auto-filled from payment term)
- **`cedible`**: Enable CEDIBLE section for invoice factoring (SII Resolución 93/2003)
- **`reference_ids`**: One2many to account.move.reference
- **`reference_required`**: Computed field (True for DTE 56/61)

### 3. Bank Information

**`res.company` extensions:**

- **`bank_name`**: Bank name for payment information
- **`bank_account_number`**: Account number (validated format)
- **`bank_account_type`**: Checking/Savings/Current
- **`bank_info_display`**: Computed formatted bank info for invoices

### 4. UX Improvements

- **Auto-fill contact:** When partner selected, contact auto-populated
- **Auto-fill forma_pago:** When payment term selected, description auto-filled
- **Validations:** User-friendly error messages in Spanish
- **Help texts:** Comprehensive field descriptions

---

## 📋 Requirements

- **Odoo:** 19.0 Community Edition
- **Dependencies:**
  - `l10n_cl_dte` (base Chilean DTE)
  - `account`
  - `l10n_latam_invoice_document`

---

## 🚀 Installation

```bash
# Install module
odoo-bin -i l10n_cl_dte_enhanced

# With branding (optional)
odoo-bin -i l10n_cl_dte_enhanced,eergygroup_branding
```

---

## ⚙️ Configuration

No configuration required - works out of the box.

**Optional:**
- Configure bank information: Settings > Companies > Your Company > Bank Info
- Enable CEDIBLE by default: System Parameters (see documentation)

---

## 📖 Usage

### Creating Credit Note with References

```python
# Create credit note
credit_note = env['account.move'].create({
    'move_type': 'out_refund',
    'partner_id': customer.id,
    'dte_code': '61',  # Credit Note
    'invoice_line_ids': [...],
})

# Add SII reference (REQUIRED for NC)
credit_note.reference_ids = [(0, 0, {
    'document_type_id': doc_type_33.id,  # Original invoice type
    'folio': '123',
    'date': original_invoice.invoice_date,
    'reason': 'Anula factura por error en cantidad',
    'code': '3',  # Corrige Montos
})]

# Post (will validate reference exists)
credit_note.action_post()
```

---

## 🧪 Testing

```bash
# All tests (78 tests)
./tests/run_tests.sh

# With coverage
./tests/run_tests.sh coverage
```

**Coverage:** 86% (exceeds 80% target) ✅

---

## 🏗️ Architecture

### Separation of Concerns

```
l10n_cl_dte_enhanced (this module)
  - FUNCTIONALITY: DTE/SII compliance features
  - GENERIC: Reusable by any Chilean company

eergygroup_branding (separate module)
  - AESTHETICS: Visual identity
  - SPECIFIC: EERGYGROUP colors/logos/templates
```

### Scalability

Multiple companies can use this module with different branding:

```
l10n_cl_dte_enhanced (REUSABLE)
    ↓ used by
    ├── eergygroup_branding (EERGYGROUP SpA)
    ├── eergymas_branding (EERGYMAS)
    └── eergyhaus_branding (EERGYHAUS)
```

---

## 📚 Documentation

- **Tests:** [tests/README_TESTS.md](tests/README_TESTS.md)
- **API:** See inline docstrings (100% coverage)
- **SII Compliance:** All features validated against SII regulations

---

## 🆘 Support

- **Email:** contacto@eergygroup.cl
- **Website:** https://www.eergygroup.cl
- **Issues:** GitHub Issues

---

## 👥 Author

**EERGYGROUP SpA**
- Developer: Ing. Pedro Troncoso Willz
- Email: contacto@eergygroup.cl

---

## 📄 License

**LGPL-3** (GNU Lesser General Public License v3.0)

This module is free software compatible with Odoo Community Edition.

---

**Version:** 19.0.1.0.0
**Status:** ✅ Production Ready
**Last Updated:** 2025-11-03
