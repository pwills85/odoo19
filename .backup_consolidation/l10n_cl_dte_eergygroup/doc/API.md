# 🔧 API Reference - l10n_cl_dte_eergygroup

**Developer API documentation for EERGYGROUP Chilean DTE customizations**

---

## 📋 Table of Contents

- [account.move Extension](#accountmove-extension)
- [account.move.reference (NEW Model)](#accountmovereference-new-model)
- [res.company Extension](#rescompany-extension)
- [res.config.settings Extension](#resconfigsettings-extension)
- [Utility Methods](#utility-methods)
- [Usage Examples](#usage-examples)

---

## 📦 account.move Extension

### Model

```python
_inherit = 'account.move'
```

### New Fields

#### `contact_id`

**Type:** `Many2one('res.partner')`

**Description:** Contact person at customer/vendor company

**Domain:**
```python
[('type', '=', 'contact'), '|',
 ('parent_id', '=', partner_id),
 ('id', '=', partner_id)]
```

**Usage:**
```python
invoice = env['account.move'].create({
    'partner_id': customer.id,
    'contact_id': customer.child_ids[0].id,  # Contact from customer
})
```

**Business Logic:**
- Auto-populated via `_onchange_partner_id_contact()` when partner selected
- Filters only contacts (`type='contact'`)
- Shows contacts from selected partner or partner itself

#### `forma_pago`

**Type:** `Char`

**Description:** Custom payment terms text for PDF display

**Auto-fill:** From `invoice_payment_term_id.name` via onchange

**Usage:**
```python
invoice = env['account.move'].create({
    'invoice_payment_term_id': term_30_days.id,  # Auto-fills forma_pago
    # forma_pago will be "30 días" automatically
})

# Or set manually
invoice.forma_pago = "Contado contra entrega"
```

#### `cedible`

**Type:** `Boolean`

**Default:** `False`

**Description:** Enable CEDIBLE section on PDF for factoring

**Constraints:**
- Only allowed on customer invoices (`move_type='out_invoice'`)
- Raises `ValidationError` if enabled on other document types

**Usage:**
```python
# ✅ Valid
invoice = env['account.move'].create({
    'move_type': 'out_invoice',
    'cedible': True,  # OK for customer invoice
})

# ❌ Invalid
refund = env['account.move'].create({
    'move_type': 'out_refund',
    'cedible': True,  # ERROR: CEDIBLE only on out_invoice
})
```

#### `reference_ids`

**Type:** `One2many('account.move.reference', 'move_id')`

**Description:** SII document references (required for NC/ND)

**Usage:**
```python
credit_note = env['account.move'].create({
    'move_type': 'out_refund',
    'dte_code': '61',
    'reference_ids': [(0, 0, {
        'document_type_id': doc_type_33.id,
        'folio': '123',
        'date': fields.Date.today(),
        'reason': 'Anula factura por error',
        'code': '1',
    })],
})
```

#### `reference_required`

**Type:** `Boolean` (Computed, stored)

**Compute:** `_compute_reference_required()`

**Dependencies:** `dte_code`, `move_type`

**Logic:**
```python
@api.depends('dte_code', 'move_type')
def _compute_reference_required(self):
    for move in self:
        move.reference_required = move.dte_code in ('56', '61')
```

**Usage:**
```python
# Check if references required
if invoice.reference_required and not invoice.reference_ids:
    raise UserError("References required for this document type")
```

### Onchange Methods

#### `_onchange_partner_id_contact()`

**Trigger:** `partner_id` changes

**Behavior:** Auto-populates `contact_id` with first contact from partner

**Code:**
```python
@api.onchange('partner_id')
def _onchange_partner_id_contact(self):
    if self.partner_id:
        default_contact = self.partner_id.child_ids.filtered(
            lambda c: c.type == 'contact'
        )[:1]
        if default_contact:
            self.contact_id = default_contact
```

#### `_onchange_invoice_payment_term_id_forma_pago()`

**Trigger:** `invoice_payment_term_id` changes

**Behavior:** Auto-fills `forma_pago` from payment term name

**Code:**
```python
@api.onchange('invoice_payment_term_id')
def _onchange_invoice_payment_term_id_forma_pago(self):
    if self.invoice_payment_term_id:
        self.forma_pago = self.invoice_payment_term_id.name
```

### Constraint Methods

#### `_check_cedible_only_customer_invoices()`

**Validates:** CEDIBLE only on customer invoices

**Raises:** `ValidationError` if CEDIBLE on non-customer invoice

**Code:**
```python
@api.constrains('cedible', 'move_type')
def _check_cedible_only_customer_invoices(self):
    for move in self:
        if move.cedible and move.move_type != 'out_invoice':
            raise ValidationError(_(
                "CEDIBLE can only be enabled on customer invoices..."
            ))
```

#### `_check_references_required_on_nc_nd()`

**Validates:** References exist on Credit/Debit Notes before posting

**Note:** Enforced in `_post()` override, not as constraint

### Override Methods

#### `_post(soft=True)`

**Overrides:** `account.move._post()`

**Purpose:** Validate references before posting NC/ND

**Code:**
```python
def _post(self, soft=True):
    for move in self:
        if move.reference_required and not move.reference_ids:
            raise UserError(_(
                "Cannot post Credit Note (61) or Debit Note (56) without..."
            ))
    return super()._post(soft=soft)
```

**Usage:**
```python
# Automatic validation when posting
credit_note.action_post()  # Will check references exist
```

### Business Methods

#### `action_add_reference()`

**Purpose:** Open wizard to add SII document reference

**Returns:** `ir.actions.act_window` dict

**Code:**
```python
def action_add_reference(self):
    self.ensure_one()
    return {
        'type': 'ir.actions.act_window',
        'name': _('Add SII Reference'),
        'res_model': 'account.move.reference',
        'view_mode': 'form',
        'target': 'new',
        'context': {'default_move_id': self.id},
    }
```

**Usage:**
```python
# From button in UI
<button name="action_add_reference"
        string="Add Reference"
        type="object"/>
```

---

## 📄 account.move.reference (NEW Model)

### Model

```python
_name = 'account.move.reference'
_description = 'SII Document Reference'
_order = 'date desc, id desc'
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `move_id` | Many2one('account.move') | ✅ Yes | Parent invoice |
| `document_type_id` | Many2one('l10n_latam.document.type') | ✅ Yes | Referenced document type |
| `folio` | Char | ✅ Yes | Folio number (1-10 digits) |
| `date` | Date | ✅ Yes | Document date (not future) |
| `reason` | Char | ❌ No | Brief explanation |
| `code` | Selection | ❌ No | SII reference code (1/2/3) |
| `display_name` | Char (Computed) | - | Formatted display |

### Field Definitions

```python
move_id = fields.Many2one(
    comodel_name='account.move',
    string='Invoice',
    required=True,
    ondelete='cascade',  # Delete references when invoice deleted
    index=True,
)

document_type_id = fields.Many2one(
    comodel_name='l10n_latam.document.type',
    string='Document Type',
    required=True,
    domain="[('country_id.code', '=', 'CL')]",  # Chilean only
)

folio = fields.Char(
    string='Folio Number',
    required=True,
    help='The folio/invoice number (numeric, 1-10 digits).',
)

date = fields.Date(
    string='Document Date',
    required=True,
    default=fields.Date.context_today,
    help='The date of the referenced document (cannot be in the future).',
)

reason = fields.Char(
    string='Reference Reason',
    help='Brief explanation of why this document is being referenced.',
)

code = fields.Selection(
    selection=[
        ('1', '1 - Anula Documento de Referencia'),
        ('2', '2 - Corrige Texto Documento de Referencia'),
        ('3', '3 - Corrige Montos'),
    ],
    string='Reference Code',
    help='SII reference code indicating the type of correction.',
)
```

### Computed Fields

#### `display_name`

**Depends:** `document_type_id`, `folio`, `date`

**Format:** `"{doc_type} Folio {folio} ({date})"`

**Example:** `"Factura Electrónica (33) Folio 123 (2025-11-01)"`

**Code:**
```python
@api.depends('document_type_id', 'folio', 'date')
def _compute_display_name(self):
    for ref in self:
        if ref.document_type_id and ref.folio:
            ref.display_name = _(
                "{doc_type} Folio {folio} ({date})"
            ).format(
                doc_type=ref.document_type_id.name,
                folio=ref.folio,
                date=ref.date or '',
            )
```

### Constraint Methods

#### `_check_date_not_future()`

**Validates:** Reference date not in future

```python
@api.constrains('date')
def _check_date_not_future(self):
    for ref in self:
        if ref.date and ref.date > fields.Date.today():
            raise ValidationError(_(
                "Document date cannot be in the future..."
            ))
```

#### `_check_date_chronological()`

**Validates:** Reference date ≤ invoice date

```python
@api.constrains('date', 'move_id')
def _check_date_chronological(self):
    for ref in self:
        if ref.date and ref.move_id.invoice_date:
            if ref.date > ref.move_id.invoice_date:
                raise ValidationError(_(
                    "Reference date (%s) cannot be after invoice date (%s)..."
                ))
```

#### `_check_folio_format()`

**Validates:** Folio numeric and 1-10 digits

```python
@api.constrains('folio')
def _check_folio_format(self):
    for ref in self:
        if ref.folio:
            if not ref.folio.isdigit():
                raise ValidationError(_("Folio must be numeric..."))
            if len(ref.folio) < 1 or len(ref.folio) > 10:
                raise ValidationError(_("Folio must be 1-10 digits..."))
```

### SQL Constraints

```python
_sql_constraints = [
    ('unique_reference_per_move',
     'UNIQUE(move_id, document_type_id, folio)',
     'You cannot reference the same document twice in the same invoice!')
]
```

**Prevents:** Duplicate references in same invoice

### CRUD Hooks

#### `create()`

**Behavior:** Log creation to `ir.logging` (audit trail)

```python
@api.model_create_multi
def create(self, vals_list):
    records = super().create(vals_list)
    for record in records:
        _logger.info(
            'SII Reference created: %s → %s',
            record.move_id.name,
            record.display_name
        )
    return records
```

### Search Methods

#### `name_search()`

**Purpose:** Search by folio or document type name

**Usage:**
```python
# Search by folio
refs = env['account.move.reference'].name_search('123')

# Search by document type
refs = env['account.move.reference'].name_search('Factura')
```

---

## 🏢 res.company Extension

### Model

```python
_inherit = 'res.company'
```

### New Fields - Bank Information

```python
bank_name = fields.Char(string='Bank Name')

bank_account_number = fields.Char(
    string='Bank Account Number',
    help='Can include spaces or hyphens (e.g., 9878-6747-7)',
)

bank_account_type = fields.Selection([
    ('checking', 'Checking Account (Cuenta Corriente)'),
    ('savings', 'Savings Account (Cuenta de Ahorro)'),
    ('current', 'Current Account (Cuenta Vista)'),
], string='Account Type', default='checking')
```

### New Fields - Branding

```python
report_primary_color = fields.Char(
    string='Primary Color',
    default='#E97300',  # EERGYGROUP orange
    help='Must be in hex format: #RRGGBB',
)

report_footer_text = fields.Text(
    string='Report Footer Text',
    translate=True,
    default='Gracias por Preferirnos',
)

report_footer_websites = fields.Char(
    string='Footer Websites',
    help="Separated by ' | ', max 5 websites",
    default='www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl',
)
```

### Computed Fields

#### `bank_info_display`

**Type:** `Text` (Computed, stored)

**Depends:** `bank_name`, `bank_account_number`, `bank_account_type`, `name`, `vat`

**Format:**
```
{bank_name}
{account_type_label} N° {account_number}
Titular: {company_name}
RUT: {company_vat}
```

**Code:**
```python
@api.depends('bank_name', 'bank_account_number', 'bank_account_type', 'name', 'vat')
def _compute_bank_info_display(self):
    for company in self:
        if company.bank_name and company.bank_account_number:
            account_type_label = dict(
                company._fields['bank_account_type'].selection
            ).get(company.bank_account_type, '')

            company.bank_info_display = _(
                "{bank}\n{type} N° {account}\nTitular: {name}\nRUT: {vat}"
            ).format(...)
        else:
            company.bank_info_display = False
```

### Constraint Methods

```python
@api.constrains('bank_account_number')
def _check_bank_account_format(self):
    # Validates: only digits, spaces, hyphens; length 6-20

@api.constrains('report_primary_color')
def _check_color_format(self):
    # Validates: hex format #RRGGBB

@api.constrains('report_footer_websites')
def _check_footer_websites(self):
    # Validates: max 5 websites, min 5 chars each
```

### Business Methods

```python
def get_default_report_color(self):
    """Return EERGYGROUP orange #E97300"""
    return '#E97300'

def action_preview_bank_info(self):
    """Open preview dialog for bank information"""
    return {
        'type': 'ir.actions.act_window',
        'res_model': 'res.company',
        'res_id': self.id,
        'view_mode': 'form',
        'target': 'new',
    }
```

---

## ⚙️ res.config.settings Extension

### Model

```python
_inherit = 'res.config.settings'
```

### Related Fields (Company)

```python
bank_name = fields.Char(
    related='company_id.bank_name',
    readonly=False,
)

bank_account_number = fields.Char(
    related='company_id.bank_account_number',
    readonly=False,
)

# ... other company fields
```

### Config Parameters

```python
enable_cedible_by_default = fields.Boolean(
    string='Enable CEDIBLE by Default',
    config_parameter='l10n_cl_dte_eergygroup.enable_cedible_by_default',
)

require_contact_on_invoices = fields.Boolean(
    string='Require Contact Person',
    config_parameter='l10n_cl_dte_eergygroup.require_contact_on_invoices',
)
```

### Computed Fields

```python
has_bank_info_configured = fields.Boolean(
    compute='_compute_has_bank_info_configured',
    string='Bank Info Configured',
)

@api.depends('bank_name', 'bank_account_number')
def _compute_has_bank_info_configured(self):
    for config in self:
        config.has_bank_info_configured = bool(
            config.bank_name and config.bank_account_number
        )
```

---

## 🔧 Utility Methods

### Getting Config Parameters

```python
# Get parameter value
ICP = env['ir.config_parameter'].sudo()
value = ICP.get_param('l10n_cl_dte_eergygroup.enable_cedible_by_default')

# Set parameter value
ICP.set_param('l10n_cl_dte_eergygroup.enable_cedible_by_default', 'True')
```

### Checking Bank Info

```python
company = env.company

if company.bank_name and company.bank_account_number:
    print("Bank info configured:", company.bank_info_display)
else:
    print("Bank info missing - please configure")
```

---

## 📚 Usage Examples

### Example 1: Create Invoice with All EERGYGROUP Fields

```python
invoice = env['account.move'].create({
    'move_type': 'out_invoice',
    'partner_id': customer.id,
    'contact_id': customer.child_ids[0].id,
    'invoice_payment_term_id': term_30_days.id,  # Auto-fills forma_pago
    'cedible': True,
    'invoice_line_ids': [(0, 0, {
        'product_id': product.id,
        'quantity': 10,
        'price_unit': 50000,
    })],
})
invoice.action_post()
```

### Example 2: Create Credit Note with References

```python
credit_note = env['account.move'].create({
    'move_type': 'out_refund',
    'partner_id': customer.id,
    'dte_code': '61',
    'invoice_line_ids': [(0, 0, {
        'product_id': product.id,
        'quantity': -5,
        'price_unit': 50000,
    })],
    'reference_ids': [(0, 0, {
        'document_type_id': doc_type_33.id,
        'folio': '123',
        'date': original_invoice.invoice_date,
        'reason': 'Anula parcialmente por error en cantidad',
        'code': '3',
    })],
})
credit_note.action_post()
```

### Example 3: Configure Company Branding

```python
company = env.company
company.write({
    'bank_name': 'Banco Scotiabank',
    'bank_account_number': '987867477',
    'bank_account_type': 'checking',
    'report_primary_color': '#E97300',
    'report_footer_text': 'Gracias por Preferirnos - EERGYGROUP SpA',
    'report_footer_websites': 'www.eergymas.cl | www.eergyhaus.cl',
})
```

### Example 4: Search References

```python
# By folio
refs = env['account.move.reference'].search([('folio', '=', '123')])

# By document type
refs = env['account.move.reference'].search([
    ('document_type_id.code', '=', '33')
])

# By invoice
refs = env['account.move.reference'].search([
    ('move_id', '=', invoice.id)
])
```

---

**Author:** EERGYGROUP - Ing. Pedro Troncoso Willz
**Version:** 19.0.1.0.0
**Last Updated:** 2025-11-03
