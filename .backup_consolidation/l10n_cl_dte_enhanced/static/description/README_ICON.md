# l10n_cl_dte_enhanced - Module Icon

## Required File

**Filename:** `icon.png`
**Location:** `/addons/localization/l10n_cl_dte_enhanced/static/description/icon.png`

## Specifications

### Technical Requirements
- **Format:** PNG (Portable Network Graphics)
- **Dimensions:** 128x128 pixels (Odoo standard)
- **Color mode:** RGB with transparency (RGBA)
- **File size:** < 50 KB recommended
- **Background:** Transparent or white

### Design Guidelines

#### Color Palette (Chilean Localization Theme)
- **Chilean Blue:** #0033A0 (from Chilean flag)
- **Chilean Red:** #D52B1E (from Chilean flag)
- **White:** #FFFFFF (neutral background)
- **Dark Gray:** #333333 (text/professional)

**Note:** This module is GENERIC for Chilean companies, so avoid company-specific colors (EERGYGROUP orange). Use neutral Chilean national colors instead.

#### Design Concept Options

**Option 1: Chilean Flag + DTE**
```
┌────────────────────┐
│  🇨🇱               │  ← Chilean flag colors (subtle)
│                    │
│   DTE              │  ← Bold text
│   Enhanced         │  ← Smaller text
│                    │
└────────────────────┘
```

**Option 2: Electronic Invoice Symbol**
```
┌────────────────────┐
│                    │
│   📄 ⚡ ✓         │  ← Document + Electronic + Validated
│                    │
│   SII CL           │  ← SII reference
│                    │
└────────────────────┘
```

**Option 3: Abstract Document Flow**
```
┌────────────────────┐
│                    │
│   ┌───┐            │
│   │   │ → SII      │  ← Document flowing to SII
│   └───┘            │
│                    │
└────────────────────┘
```

**Option 4: Professional Badge**
```
┌────────────────────┐
│                    │
│      ⭐            │  ← Star for "enhanced"
│    DTE CL          │  ← Chilean DTE
│   Enhanced         │
│                    │
└────────────────────┘
```

#### Typography
- **Font:** Helvetica, Arial, or similar professional sans-serif
- **Text color:** #333333 (dark gray) for readability
- **Hierarchy:** "DTE" larger, "Enhanced" smaller
- **Alignment:** Center or left-aligned

#### Visual Elements
- **Chilean identity:** Flag colors, stars, Chilean outline (optional)
- **Electronic concept:** Lightning bolt, digital waves, connectivity
- **Professional:** Clean, modern, enterprise-grade
- **SII reference:** Optional "SII" text or shield icon
- **Document theme:** Invoice/receipt icon, PDF symbol

### Design Tools

#### Recommended Software
1. **Adobe Illustrator** (professional, vector-based)
2. **Inkscape** (free, open-source, vector-based)
3. **GIMP** (free, raster-based)
4. **Canva** (online, template-based)

#### Export Settings
```
Format: PNG
Width: 128 pixels
Height: 128 pixels
DPI: 72 (web standard)
Color mode: RGB
Transparency: Yes (alpha channel)
Compression: Best quality
```

### Installation Instructions

1. **Create or obtain the icon:**
   - Design using specifications above
   - Use Chilean national colors (blue/red)
   - Avoid company-specific branding

2. **Save to correct location:**
   ```bash
   cp /path/to/your/icon.png \
      /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte_enhanced/static/description/icon.png
   ```

3. **Verify installation:**
   ```bash
   ls -lh /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte_enhanced/static/description/icon.png
   ```

4. **Restart Odoo:**
   ```bash
   docker-compose restart odoo19
   ```

5. **Update module list:**
   - Navigate to Apps
   - Click "Update Apps List"
   - Search for "Chilean DTE Enhanced"
   - Icon should appear

### Alternative: Temporary Placeholder

If you need a quick placeholder for testing:

```bash
# Create a simple Chilean flag-inspired icon using ImageMagick
convert -size 128x128 xc:"white" \
        -fill "#0033A0" -draw "rectangle 0,0 128,64" \
        -gravity center -pointsize 20 -fill white -annotate +0-10 "DTE" \
        -pointsize 14 -annotate +0+10 "Enhanced" \
        /Users/pedro/Documents/odoo19/addons/localization/l10n_cl_dte_enhanced/static/description/icon.png
```

### Distinguishing from Base Module

This module extends `l10n_cl_dte` (base Chilean localization). Make sure the icon is distinct:

| Module | Icon Theme | Colors |
|--------|------------|--------|
| **l10n_cl_dte** | Basic Chilean flag | Red, blue, white |
| **l10n_cl_dte_enhanced** | "Enhanced" badge or star | Blue, red + gold/star |
| **eergygroup_branding** | Company branding | Orange (#E97300) |

### Quality Checklist

- [ ] Icon displays correctly at 128x128px
- [ ] Icon is recognizable at 64x64px (thumbnail)
- [ ] Uses neutral Chilean colors (not company-specific)
- [ ] Transparent background (no white borders)
- [ ] Professional appearance
- [ ] File size < 50 KB
- [ ] Readable text (if any)
- [ ] Distinct from base l10n_cl_dte module
- [ ] Generic enough for any Chilean company

### Differentiation Strategy

**Base module (l10n_cl_dte):**
- Basic DTE functionality
- Simple icon (Chilean flag or basic document)

**Enhanced module (l10n_cl_dte_enhanced):**
- Advanced features (references, contact person, forma_pago)
- Enhanced icon (badge, star, "plus" symbol)
- Professional appearance

**Branding module (eergygroup_branding):**
- Company-specific visual identity
- Company colors and logo

### References

- **SII Logo:** [https://www.sii.cl](https://www.sii.cl) (for inspiration, not direct use)
- **Chilean Flag:** Official colors #0033A0 (blue), #D52B1E (red), #FFFFFF (white)
- **Odoo Apps:** [https://apps.odoo.com](https://apps.odoo.com) (see other localization modules)

---

**Created:** 2025-11-03
**Author:** EERGYGROUP - Ing. Pedro Troncoso Willz
**License:** LGPL-3
**Module:** l10n_cl_dte_enhanced v19.0.1.0.0
**Purpose:** Generic Chilean DTE enhancements (reusable by any Chilean company)
