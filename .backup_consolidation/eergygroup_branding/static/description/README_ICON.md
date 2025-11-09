# EERGYGROUP Branding - Module Icon

## Required File

**Filename:** `icon.png`
**Location:** `/addons/localization/eergygroup_branding/static/description/icon.png`

## Specifications

### Technical Requirements
- **Format:** PNG (Portable Network Graphics)
- **Dimensions:** 128x128 pixels (Odoo standard)
- **Color mode:** RGB with transparency (RGBA)
- **File size:** < 50 KB recommended
- **Background:** Transparent or white

### Design Guidelines

#### Primary Color Palette
- **EERGYGROUP Orange:** #E97300 (primary brand color)
- **Dark Gray:** #1A1A1A (secondary)
- **Light Orange:** #FF9933 (accent)
- **White:** #FFFFFF (background/contrast)

#### Design Concept Options

**Option 1: Abstract Energy Icon**
```
┌────────────────────┐
│                    │
│    ⚡ EERGY  ⚡    │  ← Lightning bolt with EERGYGROUP orange
│                    │
│   GROUP SpA        │  ← Dark gray text
│                    │
└────────────────────┘
```

**Option 2: Minimalist Logo**
```
┌────────────────────┐
│                    │
│       E G          │  ← Large initials in orange
│      ─────         │  ← Orange separator line
│    Branding        │  ← Small text in dark gray
│                    │
└────────────────────┘
```

**Option 3: Solar/Energy Theme**
```
┌────────────────────┐
│                    │
│       ☀️           │  ← Stylized sun in EERGYGROUP orange
│                    │
│   EERGYGROUP       │  ← Company name
│                    │
└────────────────────┘
```

#### Typography
- **Font:** Helvetica Bold, Arial Bold, or similar sans-serif
- **Text color:** #1A1A1A (dark gray) or #E97300 (orange)
- **Readability:** Ensure text is readable at 64x64px (half size)

#### Visual Elements
- **Energy themes:** Lightning bolts, sun rays, power symbols
- **Chilean elements:** Optional subtle references (stars, Andes mountains)
- **Professional:** Clean, modern, enterprise-grade appearance

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
   - Or hire a designer
   - Or use company logo adapted to 128x128

2. **Save to correct location:**
   ```bash
   cp /path/to/your/icon.png \
      /Users/pedro/Documents/odoo19/addons/localization/eergygroup_branding/static/description/icon.png
   ```

3. **Verify installation:**
   ```bash
   ls -lh /Users/pedro/Documents/odoo19/addons/localization/eergygroup_branding/static/description/icon.png
   ```

4. **Restart Odoo:**
   ```bash
   docker-compose restart odoo19
   ```

5. **Update module list:**
   - Navigate to Apps
   - Click "Update Apps List"
   - Search for "EERGYGROUP"
   - Icon should appear

### Alternative: Temporary Placeholder

If you need a quick placeholder for testing:

```bash
# Create a simple colored square using ImageMagick
convert -size 128x128 xc:"#E97300" \
        -gravity center -pointsize 24 -fill white -annotate +0+0 "EG" \
        /Users/pedro/Documents/odoo19/addons/localization/eergygroup_branding/static/description/icon.png
```

### Quality Checklist

- [ ] Icon displays correctly at 128x128px
- [ ] Icon is recognizable at 64x64px (thumbnail)
- [ ] Colors match EERGYGROUP brand palette
- [ ] Transparent background (no white borders)
- [ ] Professional appearance
- [ ] File size < 50 KB
- [ ] Readable text (if any)
- [ ] Consistent with EERGYGROUP visual identity

### Examples from Other Companies

Reference these for inspiration:
- **Odoo Community modules:** Simple, clean icons
- **Enterprise apps:** Professional, polished designs
- **Energy sector:** Solar, wind, power themes

---

**Created:** 2025-11-03
**Author:** EERGYGROUP - Ing. Pedro Troncoso Willz
**License:** LGPL-3
**Module:** eergygroup_branding v19.0.1.0.0
