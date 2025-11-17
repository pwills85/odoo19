# Deep-Dive Técnico: web_enterprise v12 → Odoo 19 CE

**Fecha:** 2025-11-08
**Versión Analizada:** Odoo 12 Enterprise
**Objetivo:** Documentar arquitectura funcional para replicación en Odoo 19 CE
**Licencia Original:** OEEL-1 (análisis funcional permitido, NO copia de código)

---

## 1. RESUMEN EJECUTIVO

El módulo `web_enterprise` v12 proporciona el diseño Enterprise y responsividad para el cliente web de Odoo. Su arquitectura se basa en:

- **1,979 líneas** de código SCSS (20 archivos)
- **2,434 líneas** de código JavaScript (12 archivos)
- **2 templates** QWeb principales
- **0 modelos Python** (solo herencia `ir.http`)

**Componentes Core:**
1. Home Menu / App Drawer
2. Control Panel responsive
3. Form View enhancements
4. List/Kanban view spacing
5. Mobile menu system
6. Variables de tema (colores, tipografía, spacing)

---

## 2. INVENTARIO COMPLETO DE ASSETS

### 2.1 Archivos SCSS (Ordenados por Complejidad)

| Archivo | Líneas | Tipo | Propósito | Prioridad |
|---------|--------|------|-----------|-----------|
| `form_view.scss` | 592 | Layout | Diseño formularios, sheets, botones | **P0** |
| `home_menu.scss` | 169 | UI | Diseño del Home Menu/App Drawer | **P0** |
| `webclient.scss` | 172 | UI | Estilos generales del webclient | **P0** |
| `list_view.scss` | 172 | Layout | Padding y spacing de tablas | P1 |
| `bootstrap_overridden.scss` | 173 | Variables | Override variables Bootstrap 3 | **P0** |
| `menu_mobile.scss` | 124 | Mobile | Menú mobile responsive | P1 |
| `webclient_layout.scss` | 88 | Layout | Flexbox layout del webclient | **P0** |
| `home_menu_layout.scss` | 87 | Layout | Layout del Home Menu | **P0** |
| `control_panel_layout.scss` | 72 | Layout | Control panel responsive | P1 |
| `dropdown.scss` | 61 | UI | Estilos dropdowns | P2 |
| `menu_search.scss` | 51 | UI | Búsqueda en Home Menu | P1 |
| `fields.scss` | 45 | UI | Campos formulario | P2 |
| `search_view.scss` | 42 | UI | Search panel | P2 |
| `fonts.scss` | 38 | Variables | Font-face Roboto | **P0** |
| `primary_variables.scss` | 31 | Variables | Variables primarias de tema | **P0** |
| `secondary_variables.scss` | 21 | Variables | Variables secundarias | **P0** |
| `touch_device.scss` | 19 | Mobile | Touch device styles | P2 |
| `kanban_view.scss` | 14 | UI | Kanban quick create | P2 |
| `ui.scss` | 5 | UI | Background gradiente | P2 |
| `datepicker.scss` | 3 | UI | Datepicker styles | P2 |

**Total:** 1,979 líneas

### 2.2 Archivos JavaScript (Ordenados por Complejidad)

| Archivo | Líneas | Tipo | Propósito | Tecnología | Prioridad |
|---------|--------|------|-----------|------------|-----------|
| `home_menu.js` | 711 | Widget | Home Menu interactivo | jQuery/Widget | **P0** |
| `web_client.js` | 383 | Core | WebClient principal | jQuery/Widget | **P0** |
| `menu.js` | 251 | Widget | Navbar/Menu principal | jQuery/Widget | **P0** |
| `menu_mobile.js` | 160 | Widget | Mobile menu | jQuery/Widget | P1 |
| `views/form_renderer.js` | 53 | View | Form renderer mobile | jQuery | P1 |
| `widgets/user_menu.js` | 52 | Widget | User menu systray | jQuery/Widget | P1 |
| `widgets/debug_manager.js` | 35 | Widget | Debug manager | jQuery/Widget | P2 |
| `views/relational_fields.js` | 39 | Widget | Relational fields mobile | jQuery/Widget | P2 |
| `control_panel.js` | 30 | Widget | Control panel breadcrumb | jQuery/Widget | P1 |
| `apps.js` | ~80 | Widget | App icons management | jQuery/Widget | P1 |
| `views/form_view.js` | ~20 | View | Form view override | jQuery/Widget | P1 |
| `views/upgrade_fields.js` | ~40 | Widget | Upgrade fields | jQuery/Widget | P2 |

**Total:** ~2,434 líneas

### 2.3 Templates QWeb

| Archivo | Templates | Propósito | Prioridad |
|---------|-----------|-----------|-----------|
| `base.xml` | 3 | HomeMenu, HomeMenu.Content, WebClient.database_expiration_panel | **P0** |
| `base_mobile.xml` | ~5 | Templates mobile (no analizado en detalle) | P1 |

### 2.4 Archivos de Assets Bundle

| Archivo | Tipo | Propósito |
|---------|------|-----------|
| `views/webclient_templates.xml` | XML | Declaración bundles: assets_backend, assets_common, qweb |

---

## 3. COMPONENTES UI A REPLICAR

### 3.1 Home Menu / App Drawer

**Descripción:**
Pantalla de inicio con grid de apps + búsqueda + menú items filtrados.

**Elementos Clave:**

```
┌─────────────────────────────────────┐
│  🔍 Search...                       │ ← .o_menu_search
├─────────────────────────────────────┤
│  [APP] [APP] [APP] [APP] [APP]      │ ← .o_apps
│  [APP] [APP] [APP] [APP] [APP]      │
├─────────────────────────────────────┤
│  Ventas / Clientes                  │ ← .o_menuitems
│  Ventas / Productos                 │
│  Contabilidad / Facturas            │
├─────────────────────────────────────┤
│  [Odoo Logo]                        │ ← .o_home_menu_footer
└─────────────────────────────────────┘
```

**Selectores CSS Exactos:**

```scss
.o_home_menu {
  .o_menu_search {
    .o_menu_search_input { /* Input búsqueda */ }
    .o_menu_search_icon { /* Icono lupa */ }
  }

  .o_home_menu_scrollable {
    .o_apps {
      .o_app {
        .o_app_icon { /* Icono app con box-shadow */ }
        .o_caption { /* Nombre app */ }

        &:hover, &.o_focused {
          .o_app_icon {
            box-shadow: 0 8px 15px -10px black;
            transform: translateY(-1px);
          }
        }
      }
    }

    .o_menuitems {
      .o_menuitem {
        .o_menuitem_parents { /* Breadcrumb path */ }
      }
    }
  }

  .o_home_menu_footer { /* Odoo logo */ }
}

.o_home_menu_background {
  /* Gradiente de fondo */
  /* Transparencia del navbar */
}
```

**Interacciones JavaScript:**

- Búsqueda en tiempo real (filter apps + menu items)
- Navegación por teclado (arrow keys, enter, escape)
- Eventos: `app_clicked`, `menu_clicked`, `show_home_menu`, `hide_home_menu`
- Compositing input support (japonés, chino)

**Variables SCSS:**

```scss
$o-home-menu-container-size: 850px;
$o-home-menu-app-icon-max-width: 70px;
$o-home-studio-menu-shadow: 0 1px 0 rgba(black, 0.45);
```

**Estimación:** **L** (711 líneas JS + 169 líneas SCSS)

---

### 3.2 Webclient Layout (Flexbox)

**Descripción:**
Layout principal con navbar, control panel y content area.

**Estructura:**

```scss
html {
  height: 100%;

  .o_web_client {
    height: 100%;
    display: flex;
    flex-flow: column nowrap;

    .o_main_navbar {
      flex: 0 0 auto; // Fixed height
    }

    .o_control_panel {
      flex: 0 0 auto; // Fixed height
    }

    .o_content {
      flex: 1 1 auto; // Grows to fill space
      overflow: auto;
      position: relative;

      > .o_view_controller {
        position: absolute;
        top: 0; right: 0; bottom: 0; left: 0;
        height: 100%;
      }
    }
  }
}
```

**Responsive:**

```scss
@include media-breakpoint-down(sm) {
  .o_content {
    overflow: visible;
    height: auto;

    > .o_view_controller {
      position: static;
      height: auto;
    }
  }
}
```

**Estimación:** **S** (88 líneas SCSS)

---

### 3.3 Form View Enterprise

**Descripción:**
Formularios con sheet, button box, avatars, spacing mejorado.

**Elementos Clave:**

```
┌────────────────────────────────────────┐
│  [Stat] [Stat] [Stat]                  │ ← .oe_button_box
├────────────────────────────────────────┤
│  ┌──────────────────────────────────┐  │ ← .o_form_sheet
│  │  [Avatar]  ┌───────────────────┐ │  │
│  │            │ oe_title          │ │  │
│  │            │ ├─ name           │ │  │
│  │            └───────────────────┘ │  │
│  │                                  │  │
│  │  ┌────────────────────────────┐ │  │ ← .o_group
│  │  │  Field: Value              │ │  │
│  │  │  Field: Value              │ │  │
│  │  └────────────────────────────┘ │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

**Selectores CSS Exactos:**

```scss
.o_form_view {
  // Sheet con sombra y padding responsivo
  .o_form_sheet_bg {
    flex: 1 0 auto;
    background-color: $o-webclient-background-color;
    border-bottom: 1px solid gray('300');

    > .o_form_sheet {
      @include make-container();
      @include make-container-max-widths();

      background-color: $o-view-background-color;
      border: 1px solid gray('400');
      box-shadow: 0 5px 20px -15px black;
      margin: $o-sheet-vpadding*0.2 auto;
      padding: $o-sheet-vpadding;

      @include o-form-sheet-inner-right-padding;
      @include o-form-sheet-inner-left-padding;
    }
  }

  // Button Box
  .oe_button_box {
    position: relative;
    display: block;
    margin-bottom: $o-sheet-vpadding;
    margin-top: -$o-sheet-vpadding;
    @include o-form-sheet-negative-margin;
    box-shadow: inset 0 -1px 0 gray('400');

    &.o_full .oe_stat_button:not(.o_invisible_modifier) ~ .oe_stat_button {
      border-left: 1px solid gray('400');
    }
  }

  // Avatar
  .oe_avatar {
    float: right;
    margin-bottom: 10px;

    > img {
      max-width: $o-avatar-size;
      max-height: $o-avatar-size;
      border: 1px solid $o-main-color-muted;
    }

    + .oe_title {
      padding-right: $o-avatar-size + 10;
    }
  }
}
```

**Mixins Importantes:**

```scss
@mixin o-form-sheet-inner-left-padding {
  padding-left: $o-horizontal-padding;
  @include media-breakpoint-between(lg, xl) {
    padding-left: $o-horizontal-padding*2;
  }
}

@mixin o-form-sheet-inner-right-padding {
  padding-right: $o-horizontal-padding;
  @include media-breakpoint-between(lg, xl) {
    padding-right: $o-horizontal-padding*2;
  }
}

@mixin o-form-sheet-negative-margin {
  margin-left: -$o-horizontal-padding;
  margin-right: -$o-horizontal-padding;
  @include media-breakpoint-between(lg, xl) {
    margin-left: -$o-horizontal-padding*2;
    margin-right: -$o-horizontal-padding*2;
  }
}
```

**Estimación:** **XL** (592 líneas SCSS + 53 líneas JS)

---

### 3.4 Control Panel Responsive

**Descripción:**
Breadcrumbs colapsables, search view, botones de acción.

**Comportamiento Mobile:**

```scss
@include media-breakpoint-down(sm) {
  .o_control_panel {
    .breadcrumb {
      @include o-when-not-full; // width: 0; max-height: 44px;
      overflow: hidden;

      > li.o_back_button {
        &:before {
          font-family: FontAwesome;
          content: ""; // fa-arrow-left
        }
        > a { display: none; }
      }
    }

    .o_cp_searchview {
      width: 12%;
      text-align: right;
    }

    &.o_breadcrumb_full {
      .breadcrumb {
        @include o-when-full; // width: 88%; max-height: 1000px;
      }
    }
  }
}
```

**JavaScript:**

```javascript
// control_panel.js
ControlPanel.include({
  _render_breadcrumbs_li: function (bc, index, length) {
    var $bc = this._super.apply(this, arguments);
    var is_last = (index === length-1);
    var is_before_last = (index === length-2);

    $bc.toggleClass('d-none d-md-inline-block', !is_last && !is_before_last)
       .toggleClass('o_back_button', is_before_last)
       .toggleClass('btn btn-secondary', is_before_last && config.device.isMobile);

    return $bc;
  },
});
```

**Estimación:** **M** (72 líneas SCSS + 30 líneas JS)

---

### 3.5 List View Enhancements

**Descripción:**
Padding responsivo para tablas, sortable headers, full-width layouts.

**Mixins:**

```scss
@mixin o-list-view-sortable-caret-padding($base: $table-cell-padding, $ratio: 1) {
  > thead > tr > th.o_column_sortable:not(:empty) {
    padding-right: ceil((($base * $ratio) / 1rem) * $o-root-font-size) + 5px;
  }
}

@mixin o-list-view-full-width-padding($base: $table-cell-padding, $ratio: 1) {
  $body-padding: floor((($base * $ratio * 0.7) / 1rem) * $o-root-font-size);

  > thead > tr > :not(:empty) {
    padding: ceil((($base * $ratio) / 1rem) * $o-root-font-size + 4px) 4px;
  }
  > tbody > tr:not(.o_list_view_grouped) > td {
    padding: $body-padding 4px;
  }
  > tfoot > tr > :not(:empty) {
    padding: ceil((($base * $ratio) / 1rem) * $o-root-font-size + 2px) 4px;
  }

  // Full-width padding
  > thead, > tbody, > tfoot {
    > tr > * {
      &:first-child {
        padding-left: $o-horizontal-padding!important;
      }
      &:last-child {
        padding-right: $o-horizontal-padding!important;
      }
    }
  }
}
```

**Estimación:** **M** (172 líneas SCSS)

---

### 3.6 Mobile Menu System

**Descripción:**
Menú hamburgués, navegación mobile, breadcrumbs mobile.

**Elementos:**

```scss
.o_mobile_menu_toggle { /* Botón hamburgués */ }
.o_menu_sections { /* Secciones del menú */ }
.o_sub_menu { /* Submenús */ }
.o_menu_entry_lvl_* { /* Niveles de profundidad */ }
```

**JavaScript:**

```javascript
// menu_mobile.js (160 líneas)
- Manejo de eventos touch
- Navegación por niveles
- Breadcrumbs dinámicos
- Search dentro del menú
```

**Estimación:** **M** (124 líneas SCSS + 160 líneas JS)

---

### 3.7 Menu Principal (Navbar)

**Descripción:**
Navbar superior con brand, secciones, systray, toggle home menu.

**Template QWeb:**

```xml
<t t-name="Menu">
  <nav class="o_main_navbar">
    <button class="o_menu_toggle"/>  <!-- fa-th / fa-chevron-left -->
    <span class="o_menu_brand"/>     <!-- Nombre de app actual -->
    <ul class="o_menu_sections"/>    <!-- Menú secundario -->
    <div class="o_menu_systray"/>    <!-- User menu, etc. -->
  </nav>
</t>
```

**JavaScript (`menu.js`):**

```javascript
var Menu = Widget.extend({
  template: 'Menu',
  events: {
    'click .o_menu_toggle': '_onToggleHomeMenu',
    'mouseover .o_menu_sections > li:not(.show)': '_onMouseOverMenu',
    'click .o_menu_brand': '_onAppNameClicked',
  },

  toggle_mode: function (home_menu, overapp) {
    this.$menu_toggle.toggleClass('fa-chevron-left', home_menu)
                     .toggleClass('fa-th', !home_menu);
    this.$menu_brand_placeholder.toggleClass('d-none', home_menu);
    this.$section_placeholder.toggleClass('d-none', home_menu);
  },

  change_menu_section: function (primary_menu_id) {
    // Cambia secciones del menú según app actual
  },
});
```

**Estimación:** **L** (251 líneas JS)

---

### 3.8 WebClient Principal

**Descripción:**
Controlador principal del cliente web, maneja home menu, actions, hashchange.

**JavaScript (`web_client.js`):**

```javascript
var WebClient = AbstractWebClient.extend({
  custom_events: {
    app_clicked: 'on_app_clicked',
    menu_clicked: 'on_menu_clicked',
    show_home_menu: '_onShowHomeMenu',
    hide_home_menu: '_onHideHomeMenu',
  },

  load_menus: function () {
    return this._rpc({
      model: 'ir.ui.menu',
      method: 'load_menus',
      args: [config.debug],
    }).then(function(menu_data) {
      // Compute action_id if not defined on top menu item
      // ...
    });
  },

  show_application: function () {
    // Instancia home_menu, menu, action_manager
    // Maneja hashchange
    // Ejecuta home action o muestra home menu
  },

  on_hashchange: function (event) {
    // Alterna entre home menu y apps
  },
});
```

**Estimación:** **XL** (383 líneas JS)

---

## 4. VARIABLES DE TEMA

### 4.1 Variables Primarias (`primary_variables.scss`)

**Colores:**

```scss
$o-brand-odoo: $o-enterprise-color;              // Color Odoo Enterprise
$o-brand-primary: $o-enterprise-primary-color;   // Color primario
$o-brand-secondary: #8f8f8f;                     // Gris secundario
$o-brand-lightsecondary: $o-gray-100;            // Gris claro

$o-main-text-color: #666666;                     // Texto principal
$o-list-footer-bg-color: white;                  // Footer tablas
```

**Botones:**

```scss
$o-btn-secondary-bg: white;
$o-btn-secondary-hover-bg: darken($o-btn-secondary-bg, 10%);
$o-btn-secondary-active-bg: darken($o-btn-secondary-bg, 8%);
```

**Layout:**

```scss
$o-statbutton-height: 44px;
$o-statbutton-vpadding: 0px;
$o-statbutton-spacing: 6px;
```

**Home Menu:**

```scss
$o-home-menu-container-size: 850px;
$o-home-menu-app-icon-max-width: 70px;
$o-home-studio-menu-shadow: 0 1px 0 rgba(black, 0.45);
```

### 4.2 Variables Secundarias (`secondary_variables.scss`)

```scss
$o-form-lightsecondary: lighten($o-brand-secondary, 25%);
$o-list-footer-color: $o-main-text-color;
$o-control-panel-background-color: $o-view-background-color;

// Tooltip
$o-tooltip-background-color: $o-view-background-color;
$o-tooltip-color: $o-main-text-color;
$o-tooltip-arrow-color: $o-main-text-color;

// Sheet
$o-sheet-cancel-tpadding: $o-horizontal-padding;
$o-sheet-cancel-bpadding: $o-horizontal-padding + $o-sheet-vpadding;

// Chatter
$o-chatter-min-width: 530px;
$o-form-sheet-min-width: 990px;
```

### 4.3 Bootstrap Overrides (`bootstrap_overridden.scss`)

**Colores Bootstrap:**

```scss
$primary: $o-brand-primary;
$secondary: $gray-600;
$success: #00A04A;
$info: #87C0D1;
$warning: #F0AD4E;
$danger: #DC6965;
```

**Body:**

```scss
$body-bg: $o-brand-secondary;
$body-color: $o-main-text-color;
```

**Links:**

```scss
$link-color: darken($o-brand-primary, 5%);
$link-hover-decoration: none;
```

**Tipografía:**

```scss
$font-family-sans-serif: 'Roboto';
$font-size-base: $o-font-size-base;
$line-height-base: $o-line-height-base;

$h1-font-size: $o-font-size-base * 2.4;
$h2-font-size: $o-font-size-base * 1.5;
$h3-font-size: $o-font-size-base * 1.3;
$h4-font-size: $o-font-size-base * 1.2;
```

**Border Radius:**

```scss
$border-radius: 0;
$border-radius-lg: 0;
$border-radius-sm: 0;
```

**Grid:**

```scss
$grid-gutter-width: $o-horizontal-padding * 2;
```

---

## 5. TRADUCCIÓN v12 → v19

### 5.1 JavaScript: jQuery/Widget → OWL 2

| Componente v12 | Tecnología v12 | Migración v19 | Complejidad |
|----------------|----------------|---------------|-------------|
| `HomeMenu` (Widget) | jQuery + QWeb | OWL Component + useState | **XL** |
| `Menu` (Widget) | jQuery + QWeb | OWL Component | **L** |
| `WebClient` | jQuery + AbstractWebClient | OWL Component + useService | **XL** |
| `ControlPanel` | jQuery + Widget.include | OWL patch/inheritance | **M** |
| `MobileMenu` | jQuery + Widget | OWL Component + useEffect | **L** |
| `FormRenderer` | jQuery + Renderer.include | OWL override | **M** |
| Systray widgets | jQuery + Widget | OWL Component | **S-M** |

**Patrón de Migración:**

```javascript
// v12 (jQuery Widget)
var HomeMenu = Widget.extend({
  template: 'HomeMenu',
  events: {
    'click .o_menuitem': '_onMenuitemClick',
    'input .o_menu_search_input': '_onMenuSearchInput',
  },
  init: function (parent, menuData) {
    this._menuData = menuData;
    this._state = this._getInitialState();
  },
  _render: function () {
    this.$mainContent.html(QWeb.render('HomeMenu.Content', {widget: this}));
  },
});

// v19 (OWL Component)
import { Component, useState } from "@odoo/owl";

class HomeMenu extends Component {
  static template = "web_enterprise.HomeMenu";

  setup() {
    this.state = useState({
      apps: this.props.menuData.filter(m => m.is_app),
      menuItems: [],
      focus: null,
    });
  }

  onMenuitemClick(ev) {
    const menuId = ev.target.dataset.menu;
    this.env.services.menu.selectMenu(menuId);
  }

  onMenuSearchInput(ev) {
    const searchValue = ev.target.value.toLowerCase();
    this.state.apps = this._filterApps(searchValue);
    this.state.menuItems = this._filterMenuItems(searchValue);
  }
}
```

**Estimación Migración JS Total:** **80-120 horas**

---

### 5.2 CSS: Bootstrap 3 → Bootstrap 5

| Clase Bootstrap 3 | Bootstrap 5 | Notas |
|-------------------|-------------|-------|
| `.pull-right` | `.float-end` | Flotante derecha |
| `.pull-left` | `.float-start` | Flotante izquierda |
| `.hidden-xs` | `.d-none .d-sm-block` | Ocultar en mobile |
| `.visible-xs` | `.d-block .d-sm-none` | Mostrar solo mobile |
| `.btn-default` | `.btn-secondary` | Botón secundario |
| `.panel` | `.card` | Contenedor card |
| `.panel-heading` | `.card-header` | Header card |
| `.panel-body` | `.card-body` | Body card |
| `.label` | `.badge` | Badge |
| `.label-primary` | `.badge .bg-primary` | Badge primario |
| `@include media-breakpoint-*` | **Sin cambios** | BS5 mantiene mixins |

**Grid System:**

- Bootstrap 3: 4 breakpoints (xs, sm, md, lg)
- Bootstrap 5: 5 breakpoints (xs, sm, md, lg, xl, xxl)

**Utility Classes:**

```scss
// v12 Bootstrap 3
.d-none.d-md-inline-block { }

// v19 Bootstrap 5 (sin cambios)
.d-none.d-md-inline-block { }
```

**Estimación Migración CSS:** **20-30 horas**

---

### 5.3 Assets Bundling: v12 → v19

**v12 (webclient_templates.xml):**

```xml
<template id="assets_backend" inherit_id="web.assets_backend">
  <xpath expr="//link[@href='/web/static/src/scss/webclient_extra.scss']" position="replace">
    <link rel="stylesheet" type="text/scss" href="/web_enterprise/static/src/scss/webclient.scss"/>
  </xpath>

  <xpath expr="//script[@src='/web/static/src/js/chrome/web_client.js']" position="replace">
    <script type="text/javascript" src="/web_enterprise/static/src/js/web_client.js"/>
  </xpath>
</template>
```

**v19 (Modular Assets - Recomendado):**

```python
# __manifest__.py
{
  'assets': {
    'web.assets_backend': [
      # SCSS
      'web_enterprise/static/src/scss/variables.scss',
      'web_enterprise/static/src/scss/webclient.scss',
      'web_enterprise/static/src/scss/home_menu.scss',
      'web_enterprise/static/src/scss/form_view.scss',

      # JavaScript (OWL)
      'web_enterprise/static/src/components/**/*.js',
      'web_enterprise/static/src/components/**/*.xml',
    ],

    'web.assets_web': [
      # Common assets
      'web_enterprise/static/src/scss/fonts.scss',
    ],

    # Lazy loading para home menu
    'web_enterprise.assets_home_menu': [
      'web_enterprise/static/src/components/home_menu/**/*',
    ],
  },
}
```

**Ventajas v19:**

- Lazy loading de componentes
- Tree shaking automático
- Hot module replacement (HMR)
- Mejor cache management

**Estimación:** **8-12 horas**

---

### 5.4 QWeb Templates: v12 → v19

**v12 (QWeb XML):**

```xml
<div t-name="HomeMenu" class="o_home_menu">
  <div class="o_menu_search">
    <input type="text" class="o_menu_search_input"/>
  </div>
  <div class="o_home_menu_scrollable">
    <t t-call="HomeMenu.Content"/>
  </div>
</div>

<t t-name="HomeMenu.Content">
  <div t-if="widget._state.apps.length" class="o_apps">
    <t t-foreach="widget._state.apps" t-as="app">
      <a class="o_app" t-att-data-menu="app.id">
        <div class="o_app_icon" t-attf-style="background-image: url('#{app.web_icon_data}');"/>
        <div class="o_caption"><t t-esc="app.label"/></div>
      </a>
    </t>
  </div>
</t>
```

**v19 (OWL XML):**

```xml
<t t-name="web_enterprise.HomeMenu" owl="1">
  <div class="o_home_menu">
    <div class="o_menu_search">
      <input type="text"
             class="o_menu_search_input"
             t-on-input="onMenuSearchInput"/>
    </div>
    <div class="o_home_menu_scrollable">
      <div t-if="state.apps.length" class="o_apps">
        <t t-foreach="state.apps" t-as="app" t-key="app.id">
          <a class="o_app"
             t-att-data-menu="app.id"
             t-on-click="onAppClick">
            <div class="o_app_icon"
                 t-attf-style="background-image: url('{{app.web_icon_data}}');"/>
            <div class="o_caption" t-esc="app.label"/>
          </a>
        </t>
      </div>
    </div>
  </div>
</t>
```

**Cambios Clave:**

- `widget._state` → `state` (OWL reactive state)
- `t-att-data-*` → Sin cambios
- Event handlers: `'click .selector'` → `t-on-click="method"`
- Loops: `t-foreach` sin cambios, pero requiere `t-key`

**Estimación:** **12-16 horas**

---

## 6. PUNTOS DE EXTENSIÓN

### 6.1 Variables SCSS Expuestas

**Archivo:** `primary_variables.scss`

```scss
// Colores principales (público para extensión)
$o-brand-odoo: $o-enterprise-color !default;
$o-brand-primary: $o-enterprise-primary-color !default;
$o-brand-secondary: #8f8f8f !default;
$o-main-text-color: #666666 !default;

// Layout
$o-home-menu-container-size: 850px !default;
$o-statbutton-height: 44px !default;
```

**Uso en Módulo Extendido:**

```scss
// mi_tema/static/src/scss/variables.scss
$o-brand-primary: #FF5733;  // Override
$o-main-text-color: #333333;

@import 'web_enterprise/static/src/scss/primary_variables';
```

---

### 6.2 Templates QWeb Extensibles

**Herencia XPath:**

```xml
<!-- mi_modulo/views/templates.xml -->
<template id="home_menu_custom" inherit_id="web_enterprise.HomeMenu">
  <!-- Agregar logo custom arriba del search -->
  <xpath expr="//div[@class='o_menu_search']" position="before">
    <div class="my_custom_logo">
      <img src="/mi_modulo/static/src/img/logo.png"/>
    </div>
  </xpath>

  <!-- Reemplazar footer -->
  <xpath expr="//div[@class='o_home_menu_footer']" position="replace">
    <div class="o_home_menu_footer">
      <img src="/mi_modulo/static/src/img/custom_footer.png"/>
    </div>
  </xpath>
</template>
```

---

### 6.3 JavaScript Hooks (v19 OWL)

**Services:**

```javascript
// web_enterprise/static/src/services/home_menu_service.js
import { registry } from "@web/core/registry";

const homeMenuService = {
  start(env) {
    let isVisible = false;

    return {
      show() {
        isVisible = true;
        env.bus.trigger('HOME_MENU_SHOWN');
      },
      hide() {
        isVisible = false;
        env.bus.trigger('HOME_MENU_HIDDEN');
      },
      toggle() {
        isVisible ? this.hide() : this.show();
      },
      get isVisible() { return isVisible; },
    };
  },
};

registry.category("services").add("homeMenu", homeMenuService);
```

**Uso en Componentes:**

```javascript
import { useService } from "@web/core/utils/hooks";

class MiComponente extends Component {
  setup() {
    this.homeMenu = useService("homeMenu");
  }

  onShowHomeMenu() {
    this.homeMenu.show();
  }
}
```

---

### 6.4 Herencia de Componentes OWL

```javascript
import { HomeMenu } from "@web_enterprise/components/home_menu/home_menu";
import { patch } from "@web/core/utils/patch";

patch(HomeMenu.prototype, "mi_modulo.HomeMenuPatch", {
  setup() {
    this._super();
    console.log('HomeMenu extended!');
  },

  onAppClick(ev) {
    // Custom logic antes
    console.log('Custom app click logic');

    // Llamar original
    this._super(ev);
  },
});
```

---

## 7. ARQUITECTURA MODULAR CE-PRO

### 7.1 Propuesta de Estructura

```
addons/
├── web_responsive/                 # Base CE (MIT/LGPL)
│   ├── static/
│   │   ├── src/
│   │   │   ├── scss/
│   │   │   │   ├── variables.scss         # Variables base
│   │   │   │   ├── webclient_layout.scss  # Layout flexbox
│   │   │   │   └── responsive.scss        # Media queries
│   │   │   ├── components/
│   │   │   │   └── navbar/                # Navbar básico
│   │   │   └── services/
│   │   │       └── menu_service.js        # Servicio menú básico
│   │   └── __manifest__.py
│
├── web_enterprise_phoenix/         # Theme Enterprise-like (LGPL-3)
│   ├── static/
│   │   ├── src/
│   │   │   ├── scss/
│   │   │   │   ├── variables_enterprise.scss  # Colores Enterprise
│   │   │   │   ├── home_menu.scss             # Home Menu styles
│   │   │   │   ├── form_view_enterprise.scss  # Form enhancements
│   │   │   │   └── control_panel.scss         # Control panel
│   │   │   ├── components/
│   │   │   │   ├── home_menu/
│   │   │   │   │   ├── home_menu.js           # HomeMenu OWL
│   │   │   │   │   └── home_menu.xml          # Template
│   │   │   │   ├── menu/
│   │   │   │   │   ├── menu.js                # Menu OWL
│   │   │   │   │   └── menu.xml
│   │   │   │   └── web_client/
│   │   │   │       ├── web_client.js          # WebClient OWL
│   │   │   │       └── web_client.xml
│   │   │   └── services/
│   │   │       └── home_menu_service.js       # HomeMenu service
│   │   └── __manifest__.py
│   │       depends: ['web', 'web_responsive']
│
└── web_enterprise_mobile/          # Mobile enhancements (LGPL-3)
    ├── static/
    │   ├── src/
    │   │   ├── scss/
    │   │   │   ├── mobile_menu.scss
    │   │   │   └── touch_device.scss
    │   │   └── components/
    │   │       └── mobile_menu/
    │   └── __manifest__.py
        depends: ['web_enterprise_phoenix']
```

### 7.2 Diagrama de Dependencias

```
┌─────────────────┐
│   web (Odoo CE) │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ web_responsive  │  (Base layout responsive)
└────────┬────────┘
         │
         v
┌──────────────────────┐
│ web_enterprise_phoenix│  (Theme + Home Menu)
└────────┬─────────────┘
         │
         v
┌──────────────────────┐
│ web_enterprise_mobile│  (Mobile menu)
└──────────────────────┘
```

### 7.3 Decisiones de Arquitectura

**¿Por qué modular?**

1. **Mantenibilidad:** Separar base responsive de theme visual
2. **Testing:** Componentes testeables independientemente
3. **Licencia:** Claridad en origen del código (CE vs reimplementación)
4. **Performance:** Lazy loading de home menu
5. **Extensibilidad:** Otros temas pueden heredar `web_responsive`

**Licencias Sugeridas:**

- `web_responsive`: **LGPL-3** (compatible con Odoo CE)
- `web_enterprise_phoenix`: **LGPL-3** (reimplementación limpia)
- `web_enterprise_mobile`: **LGPL-3**

---

## 8. ESTIMACIÓN DE ESFUERZO

### 8.1 Desglose por Componente

| Componente | SCSS | JS (v12) | JS (v19 OWL) | Complejidad | Horas |
|------------|------|----------|--------------|-------------|-------|
| **1. Variables + Fonts** | 90 | 0 | 0 | S | 4h |
| **2. Webclient Layout** | 88 | 0 | 0 | S | 6h |
| **3. Bootstrap Overrides** | 173 | 0 | 0 | M | 8h |
| **4. Home Menu** | 256 | 711 | ~400 | **XL** | **40h** |
| **5. Menu Principal** | 0 | 251 | ~150 | L | 24h |
| **6. WebClient Core** | 0 | 383 | ~200 | **XL** | **32h** |
| **7. Form View** | 592 | 53 | ~30 | **XL** | **36h** |
| **8. List View** | 172 | 0 | 0 | M | 12h |
| **9. Control Panel** | 72 | 30 | ~20 | M | 16h |
| **10. Mobile Menu** | 124 | 160 | ~100 | L | 20h |
| **11. Search View** | 42 | 0 | 0 | S | 4h |
| **12. Fields** | 45 | 39 | ~25 | M | 8h |
| **13. Kanban View** | 14 | 0 | 0 | S | 2h |
| **14. Touch Device** | 19 | 0 | 0 | S | 2h |
| **15. Widgets (systray)** | 0 | 87 | ~50 | M | 12h |
| **16. Assets Bundle** | - | - | - | M | 8h |
| **17. Tests** | - | - | - | L | 24h |
| **18. Documentación** | - | - | - | M | 12h |
| **Total** | 1,687 | 1,714 | ~975 | - | **270h** |

### 8.2 Fases de Implementación

**Fase 1: Core Layout (40h)**

- Variables + Fonts (4h)
- Webclient Layout (6h)
- Bootstrap Overrides (8h)
- Form View SCSS (20h)
- Tests básicos (2h)

**Fase 2: Home Menu System (80h)**

- Home Menu OWL Component (40h)
  - State management
  - Search functionality
  - Keyboard navigation
  - Tests
- WebClient Core (32h)
  - Menu loading
  - Hashchange handling
  - Action manager integration
- Assets Bundle (8h)

**Fase 3: Menu & Navigation (48h)**

- Menu Principal OWL (24h)
- Control Panel Responsive (16h)
- Tests (8h)

**Fase 4: Views Enhancements (40h)**

- List View Padding (12h)
- Kanban View (2h)
- Search View (4h)
- Fields (8h)
- Touch Device (2h)
- Tests (12h)

**Fase 5: Mobile (32h)**

- Mobile Menu (20h)
- Responsive breakpoints (8h)
- Tests mobile (4h)

**Fase 6: Polish & Documentation (30h)**

- Widgets systray (12h)
- Documentación técnica (12h)
- User guide (6h)

**Total:** **270 horas** (~7 semanas con 1 dev full-time)

---

## 9. RIESGOS Y MITIGACIONES

### 9.1 Riesgos Técnicos

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| Cambios en APIs OWL v19 | Media | Alto | Validar con Odoo 19 CE actual, usar documentación oficial |
| Performance Home Menu | Media | Medio | Lazy loading, virtualización para +100 apps |
| Compatibilidad Bootstrap 5 | Baja | Medio | Tests exhaustivos en breakpoints |
| Mobile touch events | Media | Medio | Usar librerías estándar (Hammer.js?) |
| Assets bundle conflicts | Alta | Alto | Namespacing, testing con módulos comunes |

### 9.2 Riesgos de Licencia

| Riesgo | Mitigación |
|--------|------------|
| Similitud visual = copia código | **Reimplementación limpia desde cero**, sin copy-paste |
| Variables/clases idénticas | Usar nombres diferentes: `o_enterprise_*` → `o_phoenix_*` |
| Auditoría OEEL-1 | Documentar decisiones de diseño, justificar similaridades funcionales |

---

## 10. CHECKLIST DE IMPLEMENTACIÓN

### 10.1 Pre-Implementación

- [ ] Revisar arquitectura de módulos en Odoo 19 CE actual
- [ ] Validar APIs OWL 2 en documentación oficial
- [ ] Configurar entorno de desarrollo con hot reload
- [ ] Definir guía de estilo (ESLint, Prettier, SCSS lint)
- [ ] Crear repositorio Git con estructura modular

### 10.2 Durante Implementación

- [ ] Escribir tests ANTES de implementar componentes (TDD)
- [ ] Code review cada componente (peer review)
- [ ] Validar responsive en 3 breakpoints (mobile, tablet, desktop)
- [ ] Documentar decisiones de arquitectura (ADRs)
- [ ] Mantener coverage > 80%

### 10.3 Post-Implementación

- [ ] Auditoría de licencias (black-duck, fossology)
- [ ] Performance audit (Lighthouse, WebPageTest)
- [ ] Accessibility audit (WCAG 2.1 AA)
- [ ] User testing con 5+ usuarios reales
- [ ] Documentación usuario final

---

## 11. REFERENCIAS

### 11.1 Documentación Odoo

- [Odoo 19 JavaScript Framework](https://www.odoo.com/documentation/19.0/developer/reference/frontend/javascript_reference.html)
- [OWL Components](https://github.com/odoo/owl)
- [Assets Management v19](https://www.odoo.com/documentation/19.0/developer/reference/frontend/assets.html)

### 11.2 Bootstrap 5

- [Migration Guide BS3 → BS5](https://getbootstrap.com/docs/5.0/migration/)
- [Bootstrap 5 Utilities](https://getbootstrap.com/docs/5.0/utilities/api/)

### 11.3 Proyectos Similares (Inspiración)

- [OCA web_responsive](https://github.com/OCA/web/tree/16.0/web_responsive)
- [web_enterprise (Odoo 16-17 Community reverse engineering)](https://github.com/OCA/web/issues)

---

## 12. APÉNDICES

### 12.1 Tabla de Selectores CSS Críticos

| Selector | Componente | Prioridad |
|----------|------------|-----------|
| `.o_home_menu` | Home Menu container | P0 |
| `.o_home_menu_background` | Background gradiente | P0 |
| `.o_apps` | Grid de apps | P0 |
| `.o_app` | App individual | P0 |
| `.o_app_icon` | Icono app con sombra | P0 |
| `.o_menu_search_input` | Input búsqueda | P0 |
| `.o_form_sheet` | Form sheet con sombra | P0 |
| `.oe_button_box` | Button box forms | P0 |
| `.o_control_panel` | Control panel | P1 |
| `.breadcrumb` | Breadcrumbs | P1 |
| `.o_back_button` | Botón back mobile | P1 |
| `.o_mobile_menu_toggle` | Toggle mobile | P1 |
| `.o_list_view` | List view | P1 |
| `.o_column_sortable` | Columna ordenable | P1 |

### 12.2 Eventos JavaScript Críticos

| Evento | Origen | Destino | Propósito |
|--------|--------|---------|-----------|
| `app_clicked` | HomeMenu | WebClient | Abrir app |
| `menu_clicked` | HomeMenu | WebClient | Abrir menú |
| `show_home_menu` | Navbar | WebClient | Mostrar home |
| `hide_home_menu` | WebClient | Navbar | Ocultar home |
| `change_menu_section` | WebClient | Menu | Cambiar sección |
| `toggle_mode` | WebClient | Menu | Toggle home/app |
| `hashchange` | Browser | WebClient | Navegación URL |

### 12.3 Comandos de Testing

```bash
# Unit tests JavaScript
npm test -- --grep "HomeMenu"

# Unit tests Python
pytest addons/web_enterprise_phoenix/tests/

# Coverage
npm run coverage -- --min-coverage 80

# SCSS lint
stylelint "addons/web_enterprise_phoenix/static/src/scss/**/*.scss"

# JS lint
eslint addons/web_enterprise_phoenix/static/src/components/
```

---

## 13. CONCLUSIONES

### 13.1 Factibilidad

✅ **VIABLE:** La reimplementación de `web_enterprise` en Odoo 19 CE es técnicamente factible y legalmente segura si se sigue un proceso de **reimplementación limpia**.

### 13.2 Esfuerzo Total Estimado

- **Desarrollo:** 270 horas (~7 semanas)
- **Testing:** 50 horas adicionales (incluidas en fases)
- **Documentación:** 20 horas (incluidas)
- **Buffer (20%):** 54 horas

**Total:** **324 horas** (~8-9 semanas con 1 desarrollador senior full-time)

### 13.3 Componentes Críticos (80/20)

**20% del esfuerzo que da 80% del valor:**

1. **Home Menu** (40h) → UX principal
2. **Form View enhancements** (36h) → Profesionalismo visual
3. **WebClient Core** (32h) → Funcionalidad base
4. **Menu Principal** (24h) → Navegación fluida

**Total crítico:** 132 horas (49% del total)

### 13.4 Recomendaciones

1. **Empezar por Fase 1 (Core Layout):** Validar viabilidad rápidamente
2. **TDD estricto:** Evitar regresiones en migración v12→v19
3. **Modularizar desde día 1:** Facilitar mantenimiento a largo plazo
4. **Documentar decisiones:** Justificar similaridades ante auditorías
5. **Peer review obligatorio:** Código de alta calidad desde el inicio

---

**Documento Generado:** 2025-11-08
**Autor:** Odoo Developer Agent (Claude Code)
**Versión:** 1.0
**Próximo Paso:** Crear PoC del Home Menu (Fase 2.1 - 40h)
