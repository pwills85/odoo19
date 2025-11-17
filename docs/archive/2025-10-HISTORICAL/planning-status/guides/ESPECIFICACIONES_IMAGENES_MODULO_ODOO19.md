# 📸 Especificaciones Imágenes y Screenshots - Módulos Odoo 19 CE

**Fecha:** 2025-10-23
**Fuente:** Documentación Oficial Odoo + Vendor Guidelines + Best Practices
**Estándar:** Odoo 19 CE Apps Store Requirements

---

## 📋 Resumen Ejecutivo

Según la documentación oficial de Odoo 19 CE y las Vendor Guidelines del Odoo Apps Store, los módulos requieren **3 tipos de assets visuales** en la carpeta `static/description/`:

| Asset | Cantidad | Ubicación | Formato | Tamaño |
|-------|----------|-----------|---------|--------|
| **Icon** | 1 (obligatorio) | `static/description/icon.png` | PNG | 128x128 px |
| **Banner/Cover** | 1 (recomendado) | `static/description/banner.png` | PNG/JPG | 560x280 px |
| **Screenshots** | 3-6 (recomendado) | `static/description/screenshot_*.png` | PNG/JPG/GIF | 1024x768 px |

---

## 1️⃣ ICON (Obligatorio) ⭐

### Especificaciones

| Propiedad | Valor |
|-----------|-------|
| **Nombre archivo** | `icon.png` |
| **Ubicación** | `static/description/icon.png` |
| **Formato** | PNG (con transparencia) |
| **Tamaño** | **128x128 píxeles** |
| **Peso** | < 50 KB |
| **Colores** | RGB, transparencia alpha |

### Propósito

- Se muestra en la lista de módulos (Apps)
- Se muestra en el menú principal de Odoo
- Se usa como favicon del módulo
- **CRÍTICO:** Sin icon, el módulo pierde puntos en ranking Odoo Apps

### Ejemplo Referencia en __manifest__.py

```python
# NO necesita declararse explícitamente
# Odoo busca automáticamente: static/description/icon.png
```

### Uso en Menús

```xml
<menuitem
    id="menu_dte_root"
    name="DTE Chile"
    web_icon="l10n_cl_dte,static/description/icon.png"
    sequence="10"/>
```

### Mejores Prácticas

✅ **Usar diseño simple y reconocible**
✅ **Colores corporativos de la empresa**
✅ **Transparencia en fondo (alpha channel)**
✅ **Optimizar para retina displays (2x)**
✅ **Sin texto (solo iconografía)**

❌ **NO usar logos complejos con muchos detalles**
❌ **NO usar fondos blancos/negros sólidos**
❌ **NO usar imágenes pixeladas o borrosas**

---

## 2️⃣ BANNER/COVER (Recomendado)

### Especificaciones

| Propiedad | Valor |
|-----------|-------|
| **Nombre archivo** | `banner.png` o `banner.jpg` |
| **Ubicación** | `static/description/banner.png` |
| **Formato** | PNG o JPG |
| **Tamaño** | **560x280 píxeles** (2:1 ratio) |
| **Peso** | < 200 KB |
| **Uso** | Thumbnail en Odoo Apps Store |

### Propósito

- **Thumbnail principal** en Odoo Apps Store
- Primera impresión visual del módulo
- Se muestra en búsquedas y listados
- **IMPORTANTE:** Sin banner, el módulo pierde ranking

### Declaración en __manifest__.py

```python
'images': [
    'static/description/banner.png',
    # Primer imagen con '_screenshot' en el nombre se usa como banner
],
```

### Contenido Recomendado

✅ **Logo del módulo + Nombre**
✅ **Tagline descriptivo (1 línea)**
✅ **Imagen representativa de funcionalidad**
✅ **Colores corporativos**
✅ **Diseño profesional, limpio**

**Ejemplo:**
```
┌────────────────────────────────┐
│  [LOGO]  Chilean DTE System    │
│          Enterprise-Grade      │
│  [Screenshot preview pequeño]  │
└────────────────────────────────┘
```

---

## 3️⃣ SCREENSHOTS (Recomendado)

### Especificaciones

| Propiedad | Valor |
|-----------|-------|
| **Nombre archivos** | `screenshot_1.png`, `screenshot_2.png`, etc. |
| **Ubicación** | `static/description/screenshot_*.png` |
| **Formato** | PNG, JPG, GIF |
| **Tamaño mínimo** | **1024x768 píxeles** (4:3 ratio) |
| **Tamaño recomendado** | **1920x1080 píxeles** (16:9 ratio) |
| **Cantidad** | 3-6 screenshots |
| **Peso** | < 500 KB cada uno |

### Propósito

- Demostrar funcionalidad del módulo
- Mostrar UI/UX real del sistema
- Ayudar a usuarios a entender features
- Aumentar conversiones de descarga/compra

### Declaración en __manifest__.py

```python
'images': [
    'static/description/banner.png',
    'static/description/screenshot_1.png',
    'static/description/screenshot_2.png',
    'static/description/screenshot_3.png',
    'static/description/screenshot_4.png',
    'static/description/screenshot_5.png',
],
```

### Contenido de Screenshots (Sugerido)

Para módulo **l10n_cl_dte**, se recomienda:

1. **screenshot_1.png** - Dashboard principal con KPIs
   - DTEs enviados hoy
   - Tasa de aceptación SII
   - Folios disponibles
   - Estado sistema

2. **screenshot_2.png** - Formulario generación DTE
   - Vista de factura con campos DTE
   - Botones de acción (Generar, Enviar)
   - Status visual

3. **screenshot_3.png** - Configuración certificados
   - Upload certificado digital
   - Validación automática
   - Gestión CAFs

4. **screenshot_4.png** - Listado DTEs
   - Tree view con estados
   - Decoraciones visuales (colores)
   - Filtros y búsquedas

5. **screenshot_5.png** - Reportes SII
   - Libro Compra/Venta
   - Consumo de folios
   - Gráficos estadísticos

6. **screenshot_6.png** (opcional) - Integración SII
   - Polling automático
   - Webhooks
   - Logs comunicación

### Mejores Prácticas Screenshots

✅ **Usar datos demo realistas** (no vacío)
✅ **Resolución alta** (1920x1080 o superior)
✅ **Sin información sensible** (RUT, nombres reales)
✅ **UI/UX limpia y profesional**
✅ **Fondo Odoo blanco estándar**
✅ **Agregar anotaciones si es necesario** (flechas, highlights)

❌ **NO usar screenshots con errores**
❌ **NO incluir barra navegador/OS**
❌ **NO usar resoluciones bajas**
❌ **NO screenshots borrosos o pixelados**

---

## 4️⃣ ESTRUCTURA DE CARPETAS

### Layout Completo

```
l10n_cl_dte/
├── __manifest__.py
├── static/
│   └── description/
│       ├── icon.png                  ✅ 128x128 px (OBLIGATORIO)
│       ├── banner.png                ✅ 560x280 px (RECOMENDADO)
│       ├── screenshot_1.png          ✅ 1920x1080 px
│       ├── screenshot_2.png          ✅ 1920x1080 px
│       ├── screenshot_3.png          ✅ 1920x1080 px
│       ├── screenshot_4.png          ✅ 1920x1080 px
│       ├── screenshot_5.png          ✅ 1920x1080 px
│       ├── screenshot_6.png          ⚠️  Opcional
│       ├── index.html                ✅ Descripción HTML rica
│       ├── icon.svg                  ⚠️  Opcional (vector source)
│       └── README.rst                ⚠️  Opcional (texto plano)
```

---

## 5️⃣ FORMATO HTML DESCRIPTION (index.html)

### Especificaciones

| Propiedad | Valor |
|-----------|-------|
| **Nombre archivo** | `index.html` |
| **Ubicación** | `static/description/index.html` |
| **Formato** | HTML5 |
| **CSS** | Inline o en `<style>` tag |
| **JavaScript** | ❌ NO permitido (seguridad) |

### Estructura Recomendada

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Chilean Electronic Invoicing - DTE System</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; }
        .section { margin: 40px 0; }
        h1 { color: #71639e; font-size: 32px; }
        h2 { color: #4c4c4c; font-size: 24px; }
        .feature-list { list-style: none; }
        .feature-list li:before { content: "✅ "; }
        img { max-width: 100%; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <section class="section">
        <h1>Chilean Electronic Invoicing - DTE System</h1>
        <p>Sistema enterprise-grade de facturación electrónica para Chile...</p>
    </section>

    <section class="section">
        <h2>🎯 Características Principales</h2>
        <ul class="feature-list">
            <li>DTE 33: Factura Electrónica</li>
            <li>DTE 61: Nota de Crédito</li>
            <!-- ... -->
        </ul>
        <img src="screenshot_1.png" alt="Dashboard DTE">
    </section>

    <section class="section">
        <h2>🚀 Instalación</h2>
        <ol>
            <li>Instalar dependencias...</li>
            <li>Configurar certificado...</li>
            <!-- ... -->
        </ol>
    </section>

    <section class="section">
        <h2>📞 Soporte</h2>
        <p>
            <strong>Desarrollado por:</strong> Ing. Pedro Troncoso Willz<br>
            <strong>Empresa:</strong> EERGYGROUP<br>
            <strong>Email:</strong> <a href="mailto:contacto@eergygroup.cl">contacto@eergygroup.cl</a><br>
            <strong>Website:</strong> <a href="https://www.eergygroup.com">www.eergygroup.com</a>
        </p>
    </section>
</body>
</html>
```

### Contenido HTML Recomendado

1. **Header:** Logo + Título + Badges
2. **Descripción breve:** 2-3 párrafos
3. **Screenshots con captions**
4. **Features list** (bullet points)
5. **Requisitos técnicos**
6. **Guía de instalación**
7. **Configuración paso a paso**
8. **FAQ** (preguntas frecuentes)
9. **Información de soporte**
10. **Licencia y disclaimer**

---

## 6️⃣ EJEMPLO COMPLETO __manifest__.py

```python
{
    'name': 'Chilean Localization - Electronic Invoicing (DTE)',
    'version': '19.0.1.0.0',
    'category': 'Accounting/Localizations',
    'summary': 'Sistema DTE Enterprise-Grade para SII',

    # ✅ IMAGES (declarar TODAS las imágenes)
    'images': [
        'static/description/banner.png',           # Thumbnail principal
        'static/description/screenshot_1.png',     # Dashboard
        'static/description/screenshot_2.png',     # Formulario DTE
        'static/description/screenshot_3.png',     # Certificados
        'static/description/screenshot_4.png',     # Listado
        'static/description/screenshot_5.png',     # Reportes
        'static/description/screenshot_6.png',     # Integración SII
    ],

    # Icon NO se declara, Odoo lo busca automáticamente en:
    # static/description/icon.png

    'author': 'EERGYGROUP - Ing. Pedro Troncoso Willz',
    'maintainer': 'EERGYGROUP',
    'contributors': [
        'Ing. Pedro Troncoso Willz <contacto@eergygroup.cl>',
    ],
    'website': 'https://www.eergygroup.com',
    'support': 'contacto@eergygroup.cl',
    'license': 'LGPL-3',

    # ... resto del manifest
}
```

---

## 7️⃣ HERRAMIENTAS RECOMENDADAS

### Para Crear Icons

- **Figma** (https://figma.com) - Diseño vectorial
- **Inkscape** (gratuito) - Editor SVG
- **GIMP** (gratuito) - Editor raster
- **Canva** (plantillas pre-hechas)

### Para Optimizar Imágenes

- **TinyPNG** (https://tinypng.com) - Compresión PNG/JPG
- **ImageOptim** (Mac) - Optimización batch
- **RIOT** (Windows) - Optimización sin pérdida
- **Squoosh** (https://squoosh.app) - Google tool online

### Para Screenshots

- **Lightshot** (captura + anotaciones)
- **Snagit** (profesional)
- **macOS Screenshot Tool** (Cmd+Shift+4)
- **Windows Snipping Tool** (Win+Shift+S)

### Plantillas

- **Odoo Apps Template:** https://github.com/odoo/odoo/tree/19.0/addons/website/static/description
- **Bootstrap Grid:** Para layouts responsive
- **Material Design Icons:** Para iconografía consistente

---

## 8️⃣ CHECKLIST PUBLICACIÓN

### Antes de Subir a Odoo Apps Store

- [ ] ✅ Icon 128x128 px en `static/description/icon.png`
- [ ] ✅ Banner 560x280 px declarado en `images`
- [ ] ✅ Mínimo 3 screenshots 1920x1080 px
- [ ] ✅ Todas las imágenes declaradas en `__manifest__.py`
- [ ] ✅ Archivo `index.html` con descripción rica
- [ ] ✅ Screenshots sin datos sensibles
- [ ] ✅ Imágenes optimizadas (< 500 KB cada una)
- [ ] ✅ Formato PNG para icon, PNG/JPG para resto
- [ ] ✅ Probado visual en Apps list (Settings → Apps)
- [ ] ✅ Validado en ambiente local antes de publicar

### Scoring Odoo Apps (Impacto Visual)

| Criterio | Impacto en Ranking |
|----------|-------------------|
| Sin icon | 🔴 Negativo alto |
| Sin banner/cover | 🔴 Negativo medio |
| Sin screenshots | 🟡 Negativo bajo |
| Screenshots baja calidad | 🟡 Negativo bajo |
| HTML description completo | ✅ Positivo medio |
| Diseño profesional | ✅ Positivo alto |

---

## 9️⃣ EJEMPLOS REFERENCIAS

### Módulos Odoo Oficiales (Estándar)

- `account` - https://github.com/odoo/odoo/tree/19.0/addons/account/static/description
- `website` - https://github.com/odoo/odoo/tree/19.0/addons/website/static/description
- `crm` - https://github.com/odoo/odoo/tree/19.0/addons/crm/static/description

### Apps Store Top-Rated (Inspiración)

- https://apps.odoo.com/apps/modules/19.0/
- Filtrar por "Most Popular"
- Ver estructura de screenshots

---

## 🔟 FAQ

### ¿Es obligatorio el icon.png?

✅ **Sí.** Sin icon, el módulo:
- Se muestra con icono genérico
- Pierde puntos en ranking Apps Store
- Parece poco profesional

### ¿Cuántos screenshots como mínimo?

⚠️ **Recomendado:** 3-6 screenshots
- Menos de 3: Poca información visual
- Más de 8: Abrumador, usuarios no ven todos

### ¿Puedo usar SVG para el icon?

❌ **No directamente.** Odoo busca `icon.png` (raster)
✅ **Pero:** Puedes tener `icon.svg` como fuente y exportar PNG

### ¿Qué pasa si no declaro 'images' en manifest?

⚠️ **Las imágenes NO se mostrarán** en:
- Odoo Apps Store
- Module description page
- Thumbnails

Odoo SOLO muestra imágenes declaradas en `'images': [...]`

### ¿Puedo usar imágenes con marca de agua?

❌ **No recomendado.**
- Se ve poco profesional
- Distrae del contenido
- Mejor usar branding sutil (logo esquina)

---

## 📚 Referencias Oficiales

1. **Odoo 19 Developer Documentation:** https://www.odoo.com/documentation/19.0/developer/reference/backend/module.html
2. **Odoo Apps Vendor Guidelines:** https://apps.odoo.com/apps/vendor-guidelines
3. **Odoo Apps FAQ:** https://apps.odoo.com/apps/faq
4. **Odoo GitHub (source code):** https://github.com/odoo/odoo/tree/19.0/addons

---

**FIN DE ESPECIFICACIONES**

*Documento creado por: Claude Code (Anthropic)*
*Fecha: 2025-10-23*
*Para: Módulo l10n_cl_dte - EERGYGROUP*
