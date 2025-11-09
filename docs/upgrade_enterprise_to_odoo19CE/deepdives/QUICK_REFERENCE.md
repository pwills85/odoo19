# Quick Reference: web_enterprise → Odoo 19 CE

**Cheat Sheet rápido para consulta durante implementación**

---

## COMANDOS RÁPIDOS

```bash
# Ver documentación completa
cat docs/upgrade_enterprise_to_odoo19CE/deepdives/web_enterprise_technical.md

# Ver resumen visual
cat docs/upgrade_enterprise_to_odoo19CE/deepdives/WEB_ENTERPRISE_VISUAL_SUMMARY.md

# Buscar componente específico
grep -A 20 "Home Menu" web_enterprise_technical.md
grep -A 20 "Form View" web_enterprise_technical.md
grep -A 20 "Control Panel" web_enterprise_technical.md

# Ver estimaciones de tiempo
grep -A 30 "Estimación de Esfuerzo" web_enterprise_technical.md

# Ver variables SCSS
grep -B 2 -A 10 "primary_variables" web_enterprise_technical.md
```

---

## TOP 5 COMPONENTES (80/20)

| # | Componente | Esfuerzo | Archivos v12 | Prioridad |
|---|------------|----------|--------------|-----------|
| 1 | Home Menu | 40h | home_menu.js (711), home_menu.scss (169) | P0 |
| 2 | Form View | 36h | form_view.scss (592), form_renderer.js (53) | P0 |
| 3 | WebClient Core | 32h | web_client.js (383), webclient_layout.scss (88) | P0 |
| 4 | Menu Principal | 24h | menu.js (251) | P0 |
| 5 | Control Panel | 16h | control_panel_layout.scss (72), control_panel.js (30) | P1 |

**Total Crítico:** 148h (55% del total)

---

## VARIABLES SCSS MÁS USADAS

```scss
// Copiar a tu módulo web_enterprise_phoenix/static/src/scss/variables.scss

// Colores
$o-brand-primary: #875A7B !default;
$o-brand-secondary: #8f8f8f !default;
$o-main-text-color: #666666 !default;

// Home Menu
$o-home-menu-container-size: 850px !default;
$o-home-menu-app-icon-max-width: 70px !default;

// Forms
$o-statbutton-height: 44px !default;
$o-avatar-size: 90px !default;
$o-form-sheet-min-width: 990px !default;

// Typography
$font-family-sans-serif: 'Roboto' !default;
$h1-font-size: $o-font-size-base * 2.4 !default;

// Bootstrap
$border-radius: 0 !default;
```

---

## SELECTORES CSS ESENCIALES

```scss
// Home Menu
.o_home_menu { /* Container */ }
.o_apps { /* Grid de apps */ }
.o_app_icon { /* Icono con hover effect */ }
.o_menu_search_input { /* Search bar */ }

// Forms
.o_form_sheet { /* Sheet con sombra */ }
.oe_button_box { /* Stat buttons */ }
.oe_avatar { /* Avatar flotante */ }

// Control Panel
.o_control_panel { /* Container */ }
.breadcrumb { /* Breadcrumbs */ }
.o_back_button { /* Back mobile */ }

// List
.o_list_view { /* Table */ }
.o_column_sortable { /* Sortable header */ }
```

---

## PATRÓN DE MIGRACIÓN JQUERY → OWL

### Antes (v12 jQuery Widget)

```javascript
odoo.define('web_enterprise.HomeMenu', function (require) {
  var Widget = require('web.Widget');

  var HomeMenu = Widget.extend({
    template: 'HomeMenu',
    events: {
      'click .o_app': '_onAppClick',
    },
    init: function (parent, menuData) {
      this._super.apply(this, arguments);
      this._state = {apps: menuData};
    },
    _onAppClick: function (ev) {
      var appId = $(ev.currentTarget).data('menu');
      this.trigger_up('app_clicked', {menu_id: appId});
    },
  });

  return HomeMenu;
});
```

### Después (v19 OWL Component)

```javascript
import { Component, useState } from "@odoo/owl";
import { useService } from "@web/core/utils/hooks";

export class HomeMenu extends Component {
  static template = "web_enterprise.HomeMenu";

  setup() {
    this.menu = useService("menu");
    this.state = useState({
      apps: this.props.menuData,
    });
  }

  onAppClick(ev) {
    const appId = ev.currentTarget.dataset.menu;
    this.menu.selectMenu(appId);
  }
}
```

---

## BOOTSTRAP 3 → 5 QUICK MAP

```scss
// Floating
.pull-right       → .float-end
.pull-left        → .float-start

// Visibility
.hidden-xs        → .d-none.d-sm-block
.visible-xs       → .d-block.d-sm-none

// Buttons
.btn-default      → .btn-secondary

// Cards
.panel            → .card
.panel-heading    → .card-header
.panel-body       → .card-body

// Badges
.label            → .badge
```

---

## MIXINS ÚTILES (SCSS)

```scss
// Padding responsivo en forms
@mixin o-form-sheet-inner-left-padding {
  padding-left: $o-horizontal-padding;
  @include media-breakpoint-between(lg, xl) {
    padding-left: $o-horizontal-padding*2;
  }
}

// List view padding
@mixin o-list-view-full-width-padding($base: $table-cell-padding) {
  > thead > tr > :not(:empty) {
    padding: ceil((($base) / 1rem) * $o-root-font-size + 4px) 4px;
  }
}

// Sortable caret
@mixin o-list-view-sortable-caret-padding($base: $table-cell-padding) {
  > thead > tr > th.o_column_sortable:not(:empty) {
    padding-right: ceil((($base) / 1rem) * $o-root-font-size) + 5px;
  }
}
```

---

## ESTRUCTURA DE ARCHIVOS RECOMENDADA

```
addons/web_enterprise_phoenix/
├── __manifest__.py
├── static/
│   └── src/
│       ├── scss/
│       │   ├── variables.scss              # Variables de tema
│       │   ├── bootstrap_overrides.scss    # Bootstrap overrides
│       │   ├── webclient_layout.scss       # Layout flexbox
│       │   ├── home_menu.scss              # Home Menu styles
│       │   ├── form_view.scss              # Form enhancements
│       │   ├── control_panel.scss          # Control panel
│       │   └── list_view.scss              # List view
│       │
│       ├── components/
│       │   ├── home_menu/
│       │   │   ├── home_menu.js            # HomeMenu OWL
│       │   │   └── home_menu.xml           # Template
│       │   │
│       │   ├── menu/
│       │   │   ├── menu.js                 # Menu OWL
│       │   │   └── menu.xml
│       │   │
│       │   └── web_client/
│       │       ├── web_client.js           # WebClient OWL
│       │       └── web_client.xml
│       │
│       └── services/
│           └── home_menu_service.js        # HomeMenu service
│
└── tests/
    ├── test_home_menu.js
    ├── test_menu.js
    └── test_web_client.js
```

---

## TEMPLATE MANIFEST.PY

```python
{
    'name': 'Web Enterprise Phoenix',
    'version': '1.0.0',
    'category': 'Hidden',
    'summary': 'Enterprise-like theme for Odoo 19 CE',
    'description': '''
        Reimplementation of Enterprise theme features for Community Edition.
        Includes Home Menu, enhanced forms, and responsive design.
    ''',
    'depends': ['web'],
    'data': [],
    'assets': {
        'web.assets_backend': [
            # SCSS Variables
            'web_enterprise_phoenix/static/src/scss/variables.scss',
            'web_enterprise_phoenix/static/src/scss/bootstrap_overrides.scss',

            # SCSS Components
            'web_enterprise_phoenix/static/src/scss/webclient_layout.scss',
            'web_enterprise_phoenix/static/src/scss/home_menu.scss',
            'web_enterprise_phoenix/static/src/scss/form_view.scss',
            'web_enterprise_phoenix/static/src/scss/control_panel.scss',
            'web_enterprise_phoenix/static/src/scss/list_view.scss',

            # JavaScript Services
            'web_enterprise_phoenix/static/src/services/*.js',

            # JavaScript Components
            'web_enterprise_phoenix/static/src/components/**/*.js',
            'web_enterprise_phoenix/static/src/components/**/*.xml',
        ],
    },
    'license': 'LGPL-3',
    'installable': True,
    'auto_install': False,
}
```

---

## TESTS TEMPLATE (OWL)

```javascript
import { describe, expect, test } from "@odoo/hoot";
import { mountWithCleanup } from "@web/../tests/web_test_helpers";
import { HomeMenu } from "@web_enterprise_phoenix/components/home_menu/home_menu";

describe("HomeMenu Component", () => {
  test("renders apps correctly", async () => {
    const menuData = [
      { id: 1, name: "Sales", is_app: true, web_icon_data: "..." },
      { id: 2, name: "CRM", is_app: true, web_icon_data: "..." },
    ];

    await mountWithCleanup(HomeMenu, { props: { menuData } });

    expect(".o_app").toHaveCount(2);
    expect(".o_app:first .o_caption").toHaveText("Sales");
  });

  test("search filters apps", async () => {
    // ... test search functionality
  });

  test("keyboard navigation works", async () => {
    // ... test arrow keys
  });
});
```

---

## DEBUGGING TIPS

```javascript
// Inspeccionar state de componente OWL en consola
owl.Component.env.qweb.templates  // Ver templates registrados
owl.Component.current              // Componente actual

// Hotkeys útiles
Ctrl+K → Home (toggle home menu)
Alt+H → Home (fallback)

// Inspeccionar eventos
core.bus.on('show_home_menu', () => console.log('Home menu shown'));
```

---

## BREAKPOINTS RESPONSIVE

```scss
// Bootstrap 5 breakpoints
$grid-breakpoints: (
  xs: 0,      // Mobile
  sm: 576px,  // Phablet
  md: 768px,  // Tablet
  lg: 992px,  // Desktop
  xl: 1200px, // Large Desktop
  xxl: 1400px // Extra Large Desktop
);

// Uso en media queries
@include media-breakpoint-down(sm) { /* Mobile */ }
@include media-breakpoint-up(md) { /* Tablet+ */ }
@include media-breakpoint-between(md, lg) { /* Tablet only */ }
```

---

## LICENCIA Y COMPLIANCE

```markdown
# Reimplementación Limpia (Clean Room)

1. NUNCA copiar código OEEL-1 directamente
2. Documentar decisiones de diseño independientes
3. Usar nombres de variables diferentes:
   - `o_enterprise_*` → `o_phoenix_*`
4. Implementar funcionalidad basada en specs públicas
5. Tests independientes (no copiar tests Enterprise)

# Licencia Propuesta: LGPL-3
- Compatible con Odoo CE (LGPL-3)
- Permite uso comercial
- Requiere compartir modificaciones
```

---

## RECURSOS ÚTILES

| Recurso | URL |
|---------|-----|
| Odoo 19 JS Framework | https://www.odoo.com/documentation/19.0/developer/reference/frontend/ |
| OWL Documentation | https://github.com/odoo/owl |
| Bootstrap 5 | https://getbootstrap.com/docs/5.0/ |
| Migration BS3→5 | https://getbootstrap.com/docs/5.0/migration/ |
| OCA web_responsive | https://github.com/OCA/web |

---

## ESTIMACIÓN RÁPIDA POR FASE

| Fase | Componentes | Horas | Semanas (1 dev) |
|------|-------------|-------|-----------------|
| 1 | Core Layout | 40h | 1.0 |
| 2 | Home Menu System | 80h | 2.0 |
| 3 | Menu & Navigation | 48h | 1.2 |
| 4 | Views Enhancements | 40h | 1.0 |
| 5 | Mobile | 32h | 0.8 |
| 6 | Polish & Docs | 30h | 0.75 |
| **Total** | **15 componentes** | **270h** | **6.75** |

---

## CONTACTO Y SOPORTE

- Documento completo: `web_enterprise_technical.md`
- Resumen visual: `WEB_ENTERPRISE_VISUAL_SUMMARY.md`
- Índice general: `README.md`

**Fecha:** 2025-11-08
**Autor:** Odoo Developer Agent (Claude Code)
