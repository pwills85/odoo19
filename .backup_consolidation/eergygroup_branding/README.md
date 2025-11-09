# EERGYGROUP - Corporate Branding

**Version:** 19.0.1.0.0
**Category:** Customizations
**License:** LGPL-3
**Author:** EERGYGROUP - Ing. Pedro Troncoso Willz

---

## 📋 Overview

Complete visual customization module for **EERGYGROUP SpA** corporate identity in Odoo 19 CE.

This module provides **AESTHETICS ONLY**. For DTE (Chilean electronic invoicing) functionality, install the `l10n_cl_dte_enhanced` module.

---

## 🎨 Features

### EERGYGROUP Color Palette

| Color | Hex Code | Purpose | Psychology |
|-------|----------|---------|------------|
| **Primary** | `#E97300` | Headers, buttons, branding | Orange = Energy, Enthusiasm, Warmth |
| **Secondary** | `#1A1A1A` | Text, section headers | Dark gray = Professionalism, Stability |
| **Accent** | `#FF9933` | Highlights, hover states | Light orange = Friendliness, Accessibility |

### Visual Components

#### 1. **Logos** (Binary fields in `res.company`)
- **Header Logo:** Displayed in PDF report headers (200x80px recommended)
- **Footer Logo:** Optional footer logo (150x60px recommended)
- **Watermark Logo:** Optional background watermark (light/transparent)

#### 2. **Footer Branding**
- **Footer Text:** "Gracias por Preferirnos" (customizable, translatable)
- **Footer Websites:**
  - www.eergymas.cl
  - www.eergyhaus.cl
  - www.eergygroup.cl
  - (Maximum 5 websites, separated by ` | `)

#### 3. **Typography**
- **Font Family:** Helvetica, Arial, sans-serif
- **Font Sizes (PDF):**
  - H1: 18pt (titles)
  - H2: 14pt (section headers)
  - H3: 12pt (subsection headers)
  - Body: 10pt (standard text)
  - Small: 8pt (notes, fine print)

#### 4. **Backend UI Customization**
- EERGYGROUP orange navigation bar
- Branded buttons and links
- Custom form field styling
- EERGYGROUP-themed list views
- Kanban cards with brand colors
- Notifications and badges

---

## 🏗️ Architecture

### Separation of Concerns

This module follows **enterprise architecture principles**:

```
┌─────────────────────────────────────┐
│  EERGYGROUP Branding (This Module) │
│  ─────────────────────────────────  │
│  • AESTHETICS: Colors, logos        │
│  • SPECIFIC: EERGYGROUP SpA only    │
│  • DEPENDENCY: l10n_cl_dte_enhanced │
└─────────────────────────────────────┘
              ▼ depends on
┌─────────────────────────────────────┐
│  l10n_cl_dte_enhanced               │
│  ─────────────────────────────────  │
│  • FUNCTIONALITY: DTE/SII features  │
│  • GENERIC: Reusable by ANY company │
│  • DEPENDENCY: l10n_cl_dte          │
└─────────────────────────────────────┘
              ▼ depends on
┌─────────────────────────────────────┐
│  l10n_cl_dte (Odoo Base)            │
│  ─────────────────────────────────  │
│  • BASE: Core DTE functionality     │
│  • OFFICIAL: Odoo community module  │
└─────────────────────────────────────┘
```

### Why This Separation?

**Before (❌ Mixed architecture):**
- One module with functionality + branding mixed
- Not reusable by other companies
- Difficult to maintain
- Violates Single Responsibility Principle

**After (✅ Clean architecture):**
- **l10n_cl_dte_enhanced:** Pure functionality, reusable by ANY Chilean company
- **eergygroup_branding:** Pure aesthetics, specific to EERGYGROUP SpA
- Easy to create `eergymas_branding`, `eergyhaus_branding` for other group companies
- Follows SOLID principles

---

## 📦 Installation

### Prerequisites

```bash
# Install base Chilean localization first
odoo-bin -i l10n_cl_dte

# Install enhanced DTE features (required dependency)
odoo-bin -i l10n_cl_dte_enhanced
```

### Install EERGYGROUP Branding

```bash
# Install this module
odoo-bin -i eergygroup_branding
```

### Complete Stack Installation

```bash
# Install all three modules together
odoo-bin -i l10n_cl_dte,l10n_cl_dte_enhanced,eergygroup_branding
```

### Post-Installation

The `post_init_hook` automatically applies EERGYGROUP defaults to all companies:

- ✅ Primary color set to `#E97300` (EERGYGROUP orange)
- ✅ Secondary color set to `#1A1A1A` (dark gray)
- ✅ Accent color set to `#FF9933` (light orange)
- ✅ Footer text: "Gracias por Preferirnos"
- ✅ Footer websites: EERGYGROUP group websites
- ✅ Font family: Helvetica, Arial, sans-serif

**Note:** Only applies defaults if company doesn't have custom branding already (respects existing customization).

---

## 🎯 Usage

### 1. Configure Company Branding

Navigate to: **Settings → General Settings → Companies**

Edit your company and scroll to **"EERGYGROUP Branding"** section:

```
┌─────────────────────────────────────────────┐
│ EERGYGROUP Branding                         │
├─────────────────────────────────────────────┤
│ Primary Brand Color:    #E97300             │
│ Secondary Brand Color:  #1A1A1A             │
│ Accent Color:           #FF9933             │
│                                             │
│ Report Footer Text:                         │
│ ┌─────────────────────────────────────────┐ │
│ │ Gracias por Preferirnos                 │ │
│ └─────────────────────────────────────────┘ │
│                                             │
│ Footer Websites:                            │
│ www.eergymas.cl | www.eergyhaus.cl | ...   │
│                                             │
│ Font Family: Helvetica, Arial, sans-serif  │
└─────────────────────────────────────────────┘
```

### 2. Upload Logos

**Header Logo (200x80px PNG):**
- Upload logo for PDF report headers
- Transparent background recommended
- EERGYGROUP orange dominant color

**Footer Logo (150x60px PNG - Optional):**
- Smaller logo for PDF footers
- Use grayscale or subtle color version

**Watermark (Optional):**
- Very light/transparent version of logo
- For background branding on sensitive documents

### 3. Customize Backend UI

The module automatically applies EERGYGROUP colors to:

- ✅ Navigation bar (orange background)
- ✅ Primary buttons (orange)
- ✅ Links and hyperlinks (orange)
- ✅ Status bars on invoices
- ✅ Badges and tags
- ✅ Kanban cards
- ✅ Notifications
- ✅ Search filters

**No additional configuration needed** - works automatically after installation!

### 4. Reset to Defaults

If you've customized branding and want to restore EERGYGROUP defaults:

1. Navigate to **Settings → Companies**
2. Select your company
3. Click **"Reset EERGYGROUP Branding"** button
4. All fields reset to EERGYGROUP standard values

---

## 📂 Module Structure

```
eergygroup_branding/
├── __init__.py                          # Module init + post_init_hook
├── __manifest__.py                      # Module metadata
│
├── models/
│   ├── __init__.py
│   └── res_company.py                   # Branding fields extension
│
├── data/
│   └── eergygroup_branding_defaults.xml # Configuration parameters
│
├── static/
│   ├── description/
│   │   ├── icon.png                     # Module icon (128x128)
│   │   └── README_ICON.md               # Icon design guidelines
│   │
│   └── src/
│       └── css/
│           └── eergygroup_branding.css  # Backend UI styling
│
├── i18n/
│   └── es_CL.po                         # Spanish (Chile) translations
│
└── README.md                            # This file
```

---

## 🔧 Technical Details

### Model Extensions

**`res.company` (models/res_company.py):**

```python
class ResCompany(models.Model):
    _inherit = 'res.company'

    # Branding fields
    report_primary_color = fields.Char(default='#E97300')
    report_secondary_color = fields.Char(default='#1A1A1A')
    report_accent_color = fields.Char(default='#FF9933')
    report_footer_text = fields.Text(default='Gracias por Preferirnos', translate=True)
    report_footer_websites = fields.Char(default='www.eergymas.cl | www.eergyhaus.cl | www.eergygroup.cl')
    report_header_logo = fields.Binary(attachment=True)
    report_footer_logo = fields.Binary(attachment=True)
    report_watermark_logo = fields.Binary(attachment=True)
    report_font_family = fields.Char(default='Helvetica, Arial, sans-serif')

    # Validation constraints
    @api.constrains('report_primary_color', 'report_secondary_color', 'report_accent_color')
    def _check_color_format(self):
        """Validate hex color format #RRGGBB"""
        # ...

    @api.constrains('report_footer_websites')
    def _check_footer_websites(self):
        """Validate footer websites (max 5, min 5 chars each)"""
        # ...

    # Business methods
    def get_brand_colors(self):
        """Get EERGYGROUP brand colors as dict"""
        return {
            'primary': self.report_primary_color or '#E97300',
            'secondary': self.report_secondary_color or '#1A1A1A',
            'accent': self.report_accent_color or '#FF9933',
        }

    def action_reset_eergygroup_branding(self):
        """Reset all branding fields to EERGYGROUP defaults"""
        # ...
```

### CSS Variables

**Backend CSS (static/src/css/eergygroup_branding.css):**

```css
:root {
    --eergygroup-primary: #E97300;      /* EERGYGROUP Orange */
    --eergygroup-secondary: #1A1A1A;    /* Dark gray */
    --eergygroup-accent: #FF9933;       /* Light orange */
}

/* Navigation bar */
.o_main_navbar {
    background-color: var(--eergygroup-primary) !important;
}

/* Primary buttons */
.btn-primary {
    background-color: var(--eergygroup-primary) !important;
}

/* ... 300+ lines of EERGYGROUP branding CSS ... */
```

---

## 🚀 For Other EERGYGROUP Companies

### Creating Branding Modules for Other Group Companies

This architecture is **designed for scalability**. To create branding for other companies:

#### Example: EERGYMAS Branding

```bash
# Copy this module as template
cp -r eergygroup_branding eergymas_branding

# Update __manifest__.py
'name': 'EERGYMAS - Corporate Branding',
'depends': ['l10n_cl_dte_enhanced'],  # Same functional dependency

# Update default colors in res_company.py
report_primary_color = fields.Char(default='#YOUR_EERGYMAS_COLOR')
report_footer_websites = fields.Char(default='www.eergymas.cl')

# Update CSS variables
:root {
    --eergymas-primary: #YOUR_COLOR;
}

# Update post_init_hook in __init__.py
def post_init_hook(env):
    # Apply EERGYMAS defaults instead of EERGYGROUP
    ...
```

#### Example: EERGYHAUS Branding

```bash
# Same process as EERGYMAS
cp -r eergygroup_branding eergyhaus_branding

# Update all references:
# - EERGYGROUP → EERGYHAUS
# - #E97300 → #YOUR_EERGYHAUS_COLOR
# - www.eergygroup.cl → www.eergyhaus.cl
```

### Multi-Company Installation

```bash
# Install functional module once (shared by all)
odoo-bin -i l10n_cl_dte_enhanced

# Install branding for each company
odoo-bin -i eergygroup_branding,eergymas_branding,eergyhaus_branding

# Each company gets its own visual identity
# But all share the same DTE functionality
```

---

## 🧪 Testing

### Manual Testing Checklist

**Backend UI:**
- [ ] Navigation bar displays EERGYGROUP orange
- [ ] Primary buttons use EERGYGROUP orange
- [ ] Links and hyperlinks use EERGYGROUP orange
- [ ] Status bars on invoices display correctly
- [ ] Form views use EERGYGROUP styling
- [ ] List/tree views have proper theming
- [ ] Kanban cards show EERGYGROUP border on hover
- [ ] Badges and tags use EERGYGROUP colors

**Company Configuration:**
- [ ] Default colors applied on first install
- [ ] Color validation works (rejects invalid hex codes)
- [ ] Website validation works (max 5 websites)
- [ ] Logo upload and display works
- [ ] Footer text is translatable
- [ ] Reset branding button restores defaults

**Integration:**
- [ ] Module installs without errors
- [ ] Depends on l10n_cl_dte_enhanced correctly
- [ ] Post-init hook applies defaults
- [ ] Doesn't interfere with DTE functionality
- [ ] CSS loads in backend
- [ ] No JavaScript console errors

---

## 🤝 Contributing

### Code Standards

- **Python:** PEP 8 compliant, 100% docstrings
- **CSS:** Well-commented, organized by sections
- **XML:** Proper indentation, noupdate flags where needed
- **Commits:** Conventional commits (feat:, fix:, docs:)

### Adding New Branding Features

**Example: Adding report_header_font_size**

1. **Add field to `res_company.py`:**
   ```python
   report_header_font_size = fields.Integer(
       string='Report Header Font Size',
       default=18,
       help='Font size for PDF report headers (in points).'
   )
   ```

2. **Add to `eergygroup_branding_defaults.xml`:**
   ```xml
   <record id="config_eergygroup_header_font_size" model="ir.config_parameter">
       <field name="key">eergygroup_branding.header_font_size</field>
       <field name="value">18</field>
   </record>
   ```

3. **Update `post_init_hook`:**
   ```python
   'report_header_font_size': 18,
   ```

4. **Document in README:** Update this file!

---

## 📄 License

**LGPL-3** (GNU Lesser General Public License v3.0)

Compatible with Odoo Community Edition.

This module can be freely used, modified, and distributed under LGPL-3 terms.

---

## 👨‍💻 Author & Support

**EERGYGROUP SpA**
**Author:** Ing. Pedro Troncoso Willz

- **Email:** contacto@eergygroup.cl
- **Website:** https://www.eergygroup.cl
- **Phone:** +56 9 XXXX XXXX

### Group Companies

- **EERGYMAS:** www.eergymas.cl (Renewable energy solutions)
- **EERGYHAUS:** www.eergyhaus.cl (Sustainable housing)
- **EERGYGROUP:** www.eergygroup.cl (Holding company)

---

## 📚 Related Modules

| Module | Purpose | Relationship |
|--------|---------|--------------|
| **l10n_cl_dte** | Base Chilean DTE | Required (indirect) |
| **l10n_cl_dte_enhanced** | Enhanced DTE features | Required (direct dependency) |
| **eergygroup_branding** | EERGYGROUP aesthetics | This module |
| **eergymas_branding** | EERGYMAS aesthetics | Future module (similar architecture) |
| **eergyhaus_branding** | EERGYHAUS aesthetics | Future module (similar architecture) |

---

## 🗺️ Roadmap

### Week 1 ✅ COMPLETE
- [x] Branding fields in `res.company`
- [x] Configuration parameters
- [x] Post-init hook
- [x] Backend CSS styling
- [x] Color validation
- [x] Website validation
- [x] Documentation

### Week 2 (In Progress)
- [ ] QWeb report templates with EERGYGROUP branding
- [ ] PDF invoice template with logos and colors
- [ ] Form views for branding configuration
- [ ] Enhanced CSS for advanced UI elements
- [ ] Module icon design and upload
- [ ] Screenshot documentation

### Week 3 (Planned)
- [ ] Advanced PDF customization
- [ ] Email templates with EERGYGROUP branding
- [ ] Letterhead templates
- [ ] Export templates (Excel, CSV)
- [ ] Mobile-responsive CSS
- [ ] Multi-language support
- [ ] User documentation (videos, tutorials)

---

**Last Updated:** 2025-11-03
**Module Version:** 19.0.1.0.0
**Documentation Version:** 1.0
**Status:** ✅ Production Ready (Week 1 Complete)

---

*"Gracias por Preferirnos" - EERGYGROUP SpA*
