# ⚙️ Configuration Guide - l10n_cl_dte_eergygroup

**Complete setup guide for EERGYGROUP Chilean DTE customizations**

---

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Initial Configuration](#initial-configuration)
- [Bank Information Setup](#bank-information-setup)
- [Branding Configuration](#branding-configuration)
- [System Parameters](#system-parameters)
- [Multi-Company Setup](#multi-company-setup)
- [Testing Configuration](#testing-configuration)
- [Troubleshooting](#troubleshooting)

---

## 🎯 Prerequisites

Before configuring this module, ensure:

1. ✅ **Odoo 19.0 CE** is installed and running
2. ✅ **l10n_cl_dte** module is installed (Chilean DTE base)
3. ✅ **l10n_cl_dte_eergygroup** module is installed
4. ✅ You have **Settings / Administration** access rights
5. ✅ Company basic info is configured (Name, RUT, Address)

---

## 🚀 Initial Configuration

### Step 1: Access Configuration Menu

```
Settings → Accounting → Chilean Localization → EERGYGROUP Configuration
```

Or navigate to:
```
Settings → Technical → Parameters → System Parameters
```

### Step 2: Verify Module Installation

Check that the module is installed:
```
Apps → Search "EERGYGROUP" → Should show "Installed"
```

---

## 🏦 Bank Information Setup

### Overview

Bank information appears on PDF invoices to facilitate customer payments. This is **critical** for business operations.

### Configuration Steps

#### 1. Navigate to Company Settings

```
Settings → General Settings → Companies → Configure Company
```

Or:
```
Settings → Accounting → EERGYGROUP Configuration
```

#### 2. Fill Bank Information Fields

| Field | Description | Example | Required |
|-------|-------------|---------|----------|
| **Bank Name** | Name of your bank | "Banco Scotiabank" | ✅ Yes |
| **Account Number** | Your account number | "987867477" | ✅ Yes |
| **Account Type** | Type of account | "Checking Account" | ✅ Yes |

#### 3. Account Number Format

Accepted formats:
- ✅ Digits only: `987867477`
- ✅ With hyphens: `9878-6747-7`
- ✅ With spaces: `9878 6747 7`

**Validation Rules:**
- 6-20 digits (excluding spaces/hyphens)
- Only digits, spaces, or hyphens allowed
- No letters or special characters

**Examples:**

```python
# ✅ Valid
"987867477"
"9878-6747-7"
"9878 6747 7"

# ❌ Invalid
"9878.6747"      # Dots not allowed
"9878ABC"        # Letters not allowed
"12345"          # Too short (< 6 digits)
"123456789012345678901"  # Too long (> 20 digits)
```

#### 4. Account Type Options

| Value | Spanish | Common Use |
|-------|---------|------------|
| `checking` | Cuenta Corriente | Most common in Chile (businesses) |
| `savings` | Cuenta de Ahorro | Personal savings |
| `current` | Cuenta Vista | Instant access account |

**Recommendation:** Use "Checking Account" (Cuenta Corriente) for business operations.

#### 5. Verify Configuration

After saving, check the computed field **"Bank Information (Formatted)"**:

```
Expected Output:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Banco Scotiabank
Cuenta Corriente N° 987867477
Titular: EERGYGROUP SpA
RUT: 76.489.218-6
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

This formatted text will appear on PDF invoices.

---

## 🎨 Branding Configuration

### Overview

Customize PDF reports with EERGYGROUP corporate identity:
- Primary color (hex format)
- Footer text
- Company websites

### Primary Color Configuration

#### Access

```
Settings → Accounting → EERGYGROUP Configuration → Primary Color
```

#### Default Value

```
#E97300  (EERGYGROUP Orange)
```

#### Format Requirements

- **Format:** `#RRGGBB` (hex color code)
- **Length:** Exactly 7 characters (# + 6 hex digits)
- **Valid characters:** 0-9, A-F (case insensitive)

#### Examples

```python
# ✅ Valid
"#E97300"  # EERGYGROUP orange
"#FF0000"  # Red
"#00FF00"  # Green
"#0000FF"  # Blue
"#FFFFFF"  # White
"#000000"  # Black
"#AbCdEf"  # Mixed case (valid)

# ❌ Invalid
"E97300"    # Missing #
"#E97"      # Too short
"#E973001"  # Too long (7 hex digits)
"#GGGGGG"   # Invalid characters (G not hex)
"orange"    # Named colors not allowed
```

#### Color Picker Tool

Use online tool to find hex codes:
- [HTML Color Picker](https://www.w3schools.com/colors/colors_picker.asp)
- [Adobe Color](https://color.adobe.com/)

### Footer Text Configuration

#### Access

```
Settings → Accounting → EERGYGROUP Configuration → Report Footer Text
```

#### Default Value

```
Gracias por Preferirnos
```

#### Recommendations

Common Chilean business phrases:

| Spanish | English | Use Case |
|---------|---------|----------|
| Gracias por Preferirnos | Thank you for choosing us | General (default) |
| Gracias por su Compra | Thank you for your purchase | Retail |
| A su Servicio | At your service | Service industry |
| Gracias por su Confianza | Thank you for your trust | Professional services |

**Custom Examples:**
```
"Gracias por Preferirnos - EERGYGROUP SpA"
"A su Servicio desde 2010"
"Calidad y Compromiso - EERGYGROUP"
```

**Limitations:**
- Max 500 characters
- Translatable (supports multiple languages)
- Appears on all PDF reports

### Footer Websites Configuration

#### Access

```
Settings → Accounting → EERGYGROUP Configuration → Footer Websites
```

#### Default Value

```
www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl
```

#### Format Requirements

- Websites separated by ` | ` (space-pipe-space)
- Each website min 5 characters
- Maximum 5 websites

#### Examples

```python
# ✅ Valid
"www.eergygroup.cl"
"www.eergymas.cl | www.eergyhaus.cl"
"www.site1.cl | www.site2.cl | www.site3.cl"

# ❌ Invalid
"ab"  # Too short (< 5 chars)
"site1|site2"  # Missing spaces around |
"www.s1.cl | www.s2.cl | www.s3.cl | www.s4.cl | www.s5.cl | www.s6.cl"  # > 5 websites
```

#### Preview

Footer renders as:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Gracias por Preferirnos

www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 🔧 System Parameters

### Overview

System-wide configuration parameters stored in `ir.config_parameter`.

### Access

```
Settings → Technical → Parameters → System Parameters
```

Or via code:
```python
env['ir.config_parameter'].sudo().get_param('key_name')
```

### Available Parameters

#### 1. Enable CEDIBLE by Default

**Key:** `l10n_cl_dte_eergygroup.enable_cedible_by_default`

**Values:**
- `True`: New invoices have CEDIBLE checkbox pre-checked
- `False`: CEDIBLE checkbox unchecked (default)

**Business Context:**
CEDIBLE allows invoices to be used for factoring (invoice financing). Enable this if your company frequently uses factoring services.

**Configuration:**
```
Settings → Accounting → EERGYGROUP Configuration → Enable CEDIBLE by Default
```

**Impact:**
- ✅ Enabled: Users save 1 click per invoice
- ❌ Enabled: Users might accidentally enable CEDIBLE
- **Recommendation:** `False` (let users enable manually when needed)

#### 2. Require Contact Person

**Key:** `l10n_cl_dte_eergygroup.require_contact_on_invoices`

**Values:**
- `True`: Cannot post invoice without contact person
- `False`: Contact person optional (default)

**Business Context:**
Contact person improves customer service and collection management by providing direct communication channel.

**Configuration:**
```
Settings → Accounting → EERGYGROUP Configuration → Require Contact Person
```

**Impact:**
- ✅ Enabled: Ensures complete customer data
- ❌ Enabled: Slows down invoice creation workflow
- **Recommendation:** `False` (optional, but encourage via auto-fill)

#### 3. Default Payment Terms

**Key:** `l10n_cl_dte_eergygroup.default_payment_terms`

**Default:** `Contado`

**Common Values:**
- `Contado` (Cash/Immediate)
- `30 días` (30 days net)
- `60 días` (60 days net)
- `90 días` (90 days net)
- `Anticipado` (Advance payment)

**Configuration (via code only):**
```python
env['ir.config_parameter'].sudo().set_param(
    'l10n_cl_dte_eergygroup.default_payment_terms',
    '30 días'
)
```

#### 4. Default Primary Color

**Key:** `l10n_cl_dte_eergygroup.default_primary_color`

**Default:** `#E97300` (EERGYGROUP orange)

**Configuration (via code only):**
```python
env['ir.config_parameter'].sudo().set_param(
    'l10n_cl_dte_eergygroup.default_primary_color',
    '#FF0000'  # Red
)
```

#### 5. Audit Logging

**Key:** `l10n_cl_dte_eergygroup.enable_reference_audit_logging`

**Default:** `True`

**Values:**
- `True`: Log all reference CRUD to `ir.logging` (recommended)
- `False`: Disable audit logging (NOT recommended for compliance)

**SII Compliance:**
Audit trail required for SII compliance. **Always keep enabled.**

---

## 🏢 Multi-Company Setup

### Overview

Each company can have **independent configuration**:
- Different bank accounts
- Different branding (colors, footer)
- Isolated per company

### Configuration Steps

#### 1. Switch Company Context

```
Top-right corner → Select Company
```

#### 2. Configure Each Company Independently

```python
# Company A (EERGYGROUP SpA)
company_a = env['res.company'].browse(1)
company_a.write({
    'bank_name': 'Banco Scotiabank',
    'bank_account_number': '987867477',
    'report_primary_color': '#E97300',  # EERGYGROUP orange
    'report_footer_websites': 'www.eergymas.cl | www.eergyhaus.cl',
})

# Company B (Subsidiary)
company_b = env['res.company'].browse(2)
company_b.write({
    'bank_name': 'Banco de Chile',
    'bank_account_number': '123456789',
    'report_primary_color': '#0000FF',  # Blue
    'report_footer_websites': 'www.subsidiary.cl',
})
```

#### 3. Verify Isolation

Each company's invoices will have:
- Different bank information
- Different branding colors
- Different footer text/websites

**No configuration leakage between companies.** ✅

---

## 🧪 Testing Configuration

### Verify Bank Information

#### Method 1: Via UI

1. Create test invoice
2. Print PDF
3. Check footer for bank information

#### Method 2: Via Code

```python
company = env.company

# Check bank info display
print(company.bank_info_display)

# Expected output:
# Banco Scotiabank
# Cuenta Corriente N° 987867477
# Titular: EERGYGROUP SpA
# RUT: 76.489.218-6
```

### Verify Branding

```python
company = env.company

# Check primary color
assert company.report_primary_color == '#E97300', "Color should be EERGYGROUP orange"

# Check footer text
assert company.report_footer_text == 'Gracias por Preferirnos'

# Check websites
assert 'www.eergygroup.cl' in company.report_footer_websites
```

### Verify System Parameters

```python
ICP = env['ir.config_parameter'].sudo()

# Check CEDIBLE default
cedible_default = ICP.get_param('l10n_cl_dte_eergygroup.enable_cedible_by_default')
print(f"CEDIBLE default: {cedible_default}")

# Check contact required
require_contact = ICP.get_param('l10n_cl_dte_eergygroup.require_contact_on_invoices')
print(f"Require contact: {require_contact}")
```

---

## 🐛 Troubleshooting

### Issue 1: Bank Information Not Appearing on PDF

**Symptoms:**
- Bank info fields filled
- PDF footer shows no bank information

**Possible Causes:**
1. Missing bank name or account number
2. `bank_info_display` computed field not stored
3. PDF template not updated (Week 2 pending)

**Solution:**
```python
company = env.company

# Check all fields are filled
assert company.bank_name, "Bank name is required"
assert company.bank_account_number, "Account number is required"

# Recompute bank_info_display
company._compute_bank_info_display()

# Check result
print(company.bank_info_display)
```

### Issue 2: Primary Color Validation Error

**Symptoms:**
```
ValidationError: Primary color must be in hex format: #RRGGBB
```

**Causes:**
- Missing `#` prefix
- Wrong length (not 6 hex digits)
- Invalid characters (not 0-9, A-F)

**Solution:**
```python
# ❌ Wrong
company.report_primary_color = 'E97300'  # Missing #

# ✅ Correct
company.report_primary_color = '#E97300'
```

### Issue 3: Footer Websites Validation Error

**Symptoms:**
```
ValidationError: Footer websites must be separated by ' | '...
```

**Causes:**
- More than 5 websites
- Websites too short (< 5 chars)
- Wrong separator (not ` | `)

**Solution:**
```python
# ❌ Wrong
company.report_footer_websites = 'site1|site2'  # Missing spaces

# ✅ Correct
company.report_footer_websites = 'www.site1.cl | www.site2.cl'
```

### Issue 4: Configuration Not Saving

**Symptoms:**
- Changes made but not persisted
- Settings revert after page reload

**Possible Causes:**
1. No write permissions
2. `noupdate="1"` on data file
3. Cache issue

**Solution:**
```python
# Method 1: Direct write (requires Settings access)
env.company.write({'bank_name': 'New Bank'})

# Method 2: Via config settings
config = env['res.config.settings'].create({})
config.bank_name = 'New Bank'
config.execute()  # Important: Call execute() to save
```

### Issue 5: Multi-Company Configuration Mixing

**Symptoms:**
- Company A shows Company B's bank info

**Cause:**
- Missing `company_id` domain on fields

**Solution:**
This should NOT happen with proper module installation. If it does:

```python
# Verify each company has independent config
for company in env['res.company'].search([]):
    print(f"{company.name}: {company.bank_name} - {company.report_primary_color}")
```

---

## 📞 Support

### Configuration Help

If you encounter issues not covered here:

1. **Check logs:** `Settings → Technical → Logging`
2. **Verify installation:** All data files loaded correctly
3. **Test environment:** Create test company and configure
4. **Contact support:** contacto@eergygroup.cl

### Pre-Configuration Checklist

Before contacting support, verify:

- [ ] Odoo 19.0 CE installed
- [ ] l10n_cl_dte module installed
- [ ] l10n_cl_dte_eergygroup module installed
- [ ] Company basic info complete (Name, RUT)
- [ ] User has Settings / Administration access
- [ ] Database in normal operating mode (not --test-enable)

---

**Author:** EERGYGROUP - Ing. Pedro Troncoso Willz
**Email:** contacto@eergygroup.cl
**Version:** 19.0.1.0.0
**Last Updated:** 2025-11-03
