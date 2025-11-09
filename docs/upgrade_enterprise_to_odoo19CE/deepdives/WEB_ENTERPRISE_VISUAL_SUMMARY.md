# web_enterprise v12 → Odoo 19 CE: Resumen Visual

**Fecha:** 2025-11-08
**Documento Completo:** `web_enterprise_technical.md` (1,374 líneas)

---

## ARQUITECTURA DEL MÓDULO

```
web_enterprise v12 Enterprise
├── SCSS (1,979 líneas)
│   ├── Variables (90 líneas)
│   │   ├── primary_variables.scss      (31) - Colores, layout, home menu
│   │   ├── secondary_variables.scss    (21) - Forms, chatter, tooltips
│   │   ├── fonts.scss                  (38) - Roboto font-face
│   │   └── bootstrap_overridden.scss  (173) - Override BS3 variables
│   │
│   ├── Layout (332 líneas)
│   │   ├── webclient_layout.scss       (88) - Flexbox layout ★★★★★
│   │   ├── home_menu_layout.scss       (87) - Home Menu layout ★★★★★
│   │   ├── control_panel_layout.scss   (72) - Control panel responsive ★★★
│   │   └── form_view.scss             (592) - Forms, sheets, avatars ★★★★★
│   │
│   ├── UI Components (585 líneas)
│   │   ├── home_menu.scss             (169) - Home Menu styles ★★★★★
│   │   ├── webclient.scss             (172) - Webclient general ★★★★
│   │   ├── list_view.scss             (172) - List padding ★★★
│   │   ├── menu_mobile.scss           (124) - Mobile menu ★★★
│   │   ├── dropdown.scss               (61) - Dropdowns ★★
│   │   └── menu_search.scss            (51) - Search bar ★★★
│   │
│   └── Minor Components (145 líneas)
│       ├── fields.scss                 (45) - Form fields ★★
│       ├── search_view.scss            (42) - Search panel ★★
│       ├── touch_device.scss           (19) - Touch styles ★
│       ├── kanban_view.scss            (14) - Kanban quick create ★
│       ├── ui.scss                      (5) - Background gradient ★
│       └── datepicker.scss              (3) - Datepicker ★
│
├── JavaScript (2,434 líneas)
│   ├── Core (1,345 líneas)
│   │   ├── home_menu.js               (711) - Home Menu Widget ★★★★★
│   │   ├── web_client.js              (383) - WebClient core ★★★★★
│   │   └── menu.js                    (251) - Navbar/Menu ★★★★★
│   │
│   ├── Mobile (213 líneas)
│   │   ├── menu_mobile.js             (160) - Mobile menu ★★★
│   │   └── views/form_renderer.js      (53) - Form mobile ★★
│   │
│   ├── Views & Widgets (176 líneas)
│   │   ├── apps.js                     (80) - App icons ★★★
│   │   ├── widgets/user_menu.js        (52) - User menu ★★
│   │   ├── views/relational_fields.js  (39) - Relational fields ★★
│   │   ├── widgets/debug_manager.js    (35) - Debug manager ★
│   │   └── views/upgrade_fields.js     (40) - Upgrade fields ★
│   │
│   └── Utilities (60 líneas)
│       ├── control_panel.js            (30) - Breadcrumb patch ★★★
│       └── views/form_view.js          (20) - Form view patch ★★
│
├── QWeb Templates
│   ├── base.xml                        - HomeMenu, Content, Expiration panel
│   └── base_mobile.xml                 - Mobile templates
│
└── Assets Bundle
    └── webclient_templates.xml         - Bundle definitions, meta tags
```

---

## COMPONENTES UI (ORDENADOS POR IMPACTO)

### Top 5 Componentes Críticos (80% del Valor)

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. HOME MENU / APP DRAWER (711 JS + 169 SCSS = 880 líneas)     │
├─────────────────────────────────────────────────────────────────┤
│  Esfuerzo: 40h (XL)  │  Prioridad: P0  │  Impacto: ★★★★★      │
├─────────────────────────────────────────────────────────────────┤
│  Tecnología v12: jQuery Widget + QWeb                           │
│  Migración v19:  OWL Component + useState + useService          │
├─────────────────────────────────────────────────────────────────┤
│  Features:                                                       │
│  • Grid de apps con iconos (max 70px)                          │
│  • Búsqueda en tiempo real (apps + menu items)                 │
│  • Navegación por teclado (arrows, enter, escape)              │
│  • Animaciones hover (translateY -1px, box-shadow)             │
│  • Footer con logo Odoo                                         │
│  • Background gradiente (transparencia navbar)                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 2. FORM VIEW ENTERPRISE (592 SCSS + 53 JS = 645 líneas)        │
├─────────────────────────────────────────────────────────────────┤
│  Esfuerzo: 36h (XL)  │  Prioridad: P0  │  Impacto: ★★★★★      │
├─────────────────────────────────────────────────────────────────┤
│  Features:                                                       │
│  • Sheet con sombra (box-shadow: 0 5px 20px -15px black)       │
│  • Button Box con border inferior                               │
│  • Avatar flotante derecho (max 90x90)                         │
│  • Padding responsivo (1x en SM, 2x en LG-XL)                  │
│  • Stat buttons (44px height, 6px spacing)                     │
│  • Mixins reutilizables (inner-padding, negative-margin)       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 3. WEBCLIENT CORE (383 JS + 88 SCSS = 471 líneas)              │
├─────────────────────────────────────────────────────────────────┤
│  Esfuerzo: 32h (XL)  │  Prioridad: P0  │  Impacto: ★★★★★      │
├─────────────────────────────────────────────────────────────────┤
│  Tecnología v12: AbstractWebClient + jQuery                     │
│  Migración v19:  OWL Component + useService('action')           │
├─────────────────────────────────────────────────────────────────┤
│  Features:                                                       │
│  • Layout Flexbox (navbar + control_panel + content)           │
│  • Hashchange routing (#menu_id=X&action_id=Y)                 │
│  • Menu loading (ir.ui.menu.load_menus)                        │
│  • Toggle home menu / apps                                      │
│  • Anchor navigation (href="#section")                         │
│  • Responsive mobile (position: static en SM)                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 4. MENU PRINCIPAL (251 JS = 251 líneas)                        │
├─────────────────────────────────────────────────────────────────┤
│  Esfuerzo: 24h (L)   │  Prioridad: P0  │  Impacto: ★★★★★      │
├─────────────────────────────────────────────────────────────────┤
│  Features:                                                       │
│  • Navbar con brand + secciones + systray                      │
│  • Toggle button (fa-th ↔ fa-chevron-left)                    │
│  • Menu sections por app (change_menu_section)                 │
│  • Systray widgets (user menu, debug manager)                  │
│  • Auto more menu (colapsar en overflow)                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 5. CONTROL PANEL RESPONSIVE (72 SCSS + 30 JS = 102 líneas)     │
├─────────────────────────────────────────────────────────────────┤
│  Esfuerzo: 16h (M)   │  Prioridad: P1  │  Impacto: ★★★★       │
├─────────────────────────────────────────────────────────────────┤
│  Features:                                                       │
│  • Breadcrumbs colapsables (width: 0 → 88%)                    │
│  • Back button mobile (fa-arrow-left)                          │
│  • Search view responsive (12% width en mobile)                │
│  • Dropdown view switcher inline-flex                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## ESTIMACIÓN DE ESFUERZO (VISUAL)

```
Total: 270 horas (~7 semanas, 1 dev senior full-time)

█████████████████████████████████████████████ Home Menu (40h) ★★★★★
█████████████████████████████████████████ Form View (36h) ★★★★★
███████████████████████████████████ WebClient (32h) ★★★★★
███████████████████████████ Menu Principal (24h) ★★★★★
─────────────────────────────────────────────────────────────
                                             Crítico: 132h (49%)

█████████████████████ Mobile Menu (20h) ★★★
████████████████ Control Panel (16h) ★★★
████████████ List View (12h) ★★★
████████ Assets Bundle (8h) ★★
████████ Bootstrap Overrides (8h) ★★
████████ Fields (8h) ★★
██████ Webclient Layout (6h) ★
████ Variables+Fonts (4h) ★
████ Search View (4h) ★
██ Kanban (2h) ★
██ Touch (2h) ★

Tests:           █████████████████████████ 24h
Widgets Systray: ████████████ 12h
Documentación:   ████████████ 12h
```

---

## MIGRACIÓN v12 → v19 (VISUAL)

### JavaScript: jQuery Widget → OWL Component

```
┌─────────────────────────────────┐      ┌─────────────────────────────────┐
│  v12 Enterprise (jQuery)        │      │  v19 CE (OWL 2)                 │
├─────────────────────────────────┤      ├─────────────────────────────────┤
│                                 │      │                                 │
│ var HomeMenu = Widget.extend({  │  →   │ class HomeMenu extends Component│
│   template: 'HomeMenu',         │      │   static template = "HomeMenu"; │
│   events: {                     │      │                                 │
│     'click .o_app': '_onClick', │      │   setup() {                     │
│   },                            │      │     this.state = useState({     │
│   init: function() {            │      │       apps: [],                 │
│     this._state = {apps: []};   │      │     });                         │
│   },                            │      │   }                             │
│   _render: function() {         │      │                                 │
│     this.$el.html(               │      │   onAppClick(ev) {              │
│       QWeb.render('Template')   │      │     // OWL auto-renders        │
│     );                          │      │   }                             │
│   },                            │      │ }                               │
│ });                             │      │                                 │
└─────────────────────────────────┘      └─────────────────────────────────┘

Cambios Clave:
• Widget.extend()      → class extends Component
• events: {}           → t-on-click="method" (template)
• this.$el             → reactive state (OWL)
• this._state          → this.state = useState()
• QWeb.render()        → Automatic reactivity
• _super()             → super()
```

### CSS: Bootstrap 3 → Bootstrap 5

```
┌────────────────────────┐      ┌────────────────────────┐
│  Bootstrap 3           │      │  Bootstrap 5           │
├────────────────────────┤      ├────────────────────────┤
│ .pull-right            │  →   │ .float-end             │
│ .pull-left             │  →   │ .float-start           │
│ .hidden-xs             │  →   │ .d-none .d-sm-block    │
│ .visible-xs            │  →   │ .d-block .d-sm-none    │
│ .btn-default           │  →   │ .btn-secondary         │
│ .panel                 │  →   │ .card                  │
│ .panel-heading         │  →   │ .card-header           │
│ .label                 │  →   │ .badge                 │
└────────────────────────┘      └────────────────────────┘

Grid Breakpoints:
v12: xs (0)    sm (768px)  md (992px)  lg (1200px)
v19: xs (0)    sm (576px)  md (768px)  lg (992px)  xl (1200px)  xxl (1400px)
```

---

## ARQUITECTURA MODULAR PROPUESTA

```
┌─────────────────────────────────────────────────────────────────┐
│                      Odoo 19 CE (Base)                          │
│                    web/ (Core Framework)                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────────────┐
│                    web_responsive (LGPL-3)                      │
│                  Base Layout + Responsive                       │
├─────────────────────────────────────────────────────────────────┤
│ • Webclient flexbox layout                                      │
│ • Responsive breakpoints                                        │
│ • Media query utilities                                         │
│ • Base navbar component                                         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────────────┐
│              web_enterprise_phoenix (LGPL-3)                    │
│              Theme Enterprise-like + Home Menu                  │
├─────────────────────────────────────────────────────────────────┤
│ • Home Menu / App Drawer (OWL)                                  │
│ • WebClient Core (OWL)                                          │
│ • Menu Principal (OWL)                                          │
│ • Form View enhancements (SCSS)                                 │
│ • Control Panel responsive                                      │
│ • Enterprise variables (colors, spacing)                        │
│ • Bootstrap 5 overrides                                         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────────────┐
│              web_enterprise_mobile (LGPL-3)                     │
│                  Mobile Menu + Touch                            │
├─────────────────────────────────────────────────────────────────┤
│ • Mobile hamburger menu                                         │
│ • Touch device styles                                           │
│ • Mobile form renderer                                          │
└─────────────────────────────────────────────────────────────────┘

Beneficios:
✓ Modularidad: Separar layout base de theme visual
✓ Mantenibilidad: Componentes independientes
✓ Testing: Tests unitarios por módulo
✓ Performance: Lazy loading del Home Menu
✓ Extensibilidad: Otros temas pueden heredar web_responsive
```

---

## FASES DE IMPLEMENTACIÓN

```
Fase 1: Core Layout (40h)
├── Variables + Fonts (4h)
├── Webclient Layout (6h)
├── Bootstrap Overrides (8h)
└── Form View SCSS (20h + 2h tests)

Fase 2: Home Menu System (80h) ★ CRÍTICO
├── Home Menu OWL (40h)
│   ├── Component structure (8h)
│   ├── State management (8h)
│   ├── Search functionality (12h)
│   ├── Keyboard navigation (8h)
│   └── Tests (4h)
├── WebClient Core OWL (32h)
│   ├── Routing & hashchange (12h)
│   ├── Menu loading (8h)
│   ├── Action manager integration (8h)
│   └── Tests (4h)
└── Assets Bundle (8h)

Fase 3: Menu & Navigation (48h)
├── Menu Principal OWL (24h)
├── Control Panel Responsive (16h)
└── Tests (8h)

Fase 4: Views Enhancements (40h)
├── List View Padding (12h)
├── Kanban + Search + Fields + Touch (16h)
└── Tests (12h)

Fase 5: Mobile (32h)
├── Mobile Menu (20h)
├── Responsive breakpoints (8h)
└── Tests (4h)

Fase 6: Polish & Documentation (30h)
├── Systray Widgets (12h)
├── Documentación técnica (12h)
└── User guide (6h)

Total: 270 horas (~7 semanas)
Crítico (Fases 1+2): 120 horas (44%)
```

---

## VARIABLES SCSS CLAVE

```scss
// COLORES
$o-brand-primary: #875A7B;           // Purple Odoo
$o-brand-secondary: #8f8f8f;         // Gray
$o-main-text-color: #666666;         // Texto principal

// LAYOUT
$o-home-menu-container-size: 850px;  // Max-width Home Menu
$o-home-menu-app-icon-max-width: 70px; // Icono app
$o-statbutton-height: 44px;          // Stat button height
$o-statbutton-spacing: 6px;          // Espacio entre stat buttons

// FORMS
$o-form-sheet-min-width: 990px;      // Min-width sheet
$o-chatter-min-width: 530px;         // Min-width chatter
$o-avatar-size: 90px;                // Avatar max size

// TIPOGRAFÍA
$font-family-sans-serif: 'Roboto';
$h1-font-size: $o-font-size-base * 2.4;
$h2-font-size: $o-font-size-base * 1.5;
$h3-font-size: $o-font-size-base * 1.3;

// BOOTSTRAP OVERRIDES
$border-radius: 0;                   // Sin border-radius
$grid-gutter-width: $o-horizontal-padding * 2;
```

---

## SELECTORES CSS CRÍTICOS

```scss
// HOME MENU
.o_home_menu {}                      // Container principal
.o_home_menu_background {}           // Gradiente de fondo
.o_apps {}                           // Grid de apps
.o_app {}                            // App individual
.o_app_icon {}                       // Icono con sombra
.o_menu_search_input {}              // Input búsqueda
.o_menuitems {}                      // Lista menu items
.o_home_menu_footer {}               // Footer con logo

// FORM VIEW
.o_form_sheet {}                     // Sheet con sombra
.o_form_sheet_bg {}                  // Background del form
.oe_button_box {}                    // Button box superior
.oe_avatar {}                        // Avatar flotante
.oe_title {}                         // Título del form

// CONTROL PANEL
.o_control_panel {}                  // Container
.breadcrumb {}                       // Breadcrumbs
.o_back_button {}                    // Botón back mobile
.o_cp_searchview {}                  // Search view

// LIST VIEW
.o_list_view {}                      // Table container
.o_column_sortable {}                // Columna ordenable

// MOBILE
.o_mobile_menu_toggle {}             // Toggle hamburgués
.o_menu_sections {}                  // Secciones menú
```

---

## EVENTOS JAVASCRIPT

```javascript
// Custom Events (OWL v19: env.bus.trigger)
app_clicked        // HomeMenu → WebClient (abrir app)
menu_clicked       // HomeMenu → WebClient (abrir menú)
show_home_menu     // Navbar → WebClient (mostrar home)
hide_home_menu     // WebClient → Navbar (ocultar home)
change_menu_section // WebClient → Menu (cambiar sección)
toggle_mode        // WebClient → Menu (toggle home/app)

// Browser Events
hashchange         // Browser → WebClient (navegación URL)
keydown            // Browser → HomeMenu (navegación teclado)
scroll             // HomeMenu → Bus (scroll propagation)
```

---

## CHECKLIST RÁPIDO

### Pre-Implementación
- [ ] Validar APIs OWL 2 en Odoo 19 CE
- [ ] Configurar entorno dev con hot reload
- [ ] Definir guía de estilo (ESLint, SCSS lint)
- [ ] Crear repositorio Git modular

### Implementación
- [ ] TDD: Tests ANTES de implementar
- [ ] Code review cada componente
- [ ] Validar responsive (mobile, tablet, desktop)
- [ ] Documentar decisiones (ADRs)

### Post-Implementación
- [ ] Auditoría de licencias
- [ ] Performance audit (Lighthouse)
- [ ] Accessibility audit (WCAG 2.1 AA)
- [ ] User testing (5+ usuarios)
- [ ] Documentación usuario final

---

## MÉTRICAS CLAVE

| Métrica | Valor |
|---------|-------|
| **Líneas SCSS** | 1,979 |
| **Líneas JavaScript v12** | 2,434 |
| **Líneas JavaScript v19 (estimado)** | ~975 (60% reducción) |
| **Componentes UI** | 15 |
| **Componentes Críticos (P0)** | 5 |
| **Esfuerzo Total** | 270h (~7 semanas) |
| **Esfuerzo Crítico (80/20)** | 132h (~3.5 semanas) |
| **Fases** | 6 |
| **Licencia Propuesta** | LGPL-3 |

---

## PRÓXIMOS PASOS

1. **Validar Viabilidad (8h)**
   - PoC Home Menu en Odoo 19 CE
   - Validar APIs OWL disponibles
   - Verificar compatibilidad Bootstrap 5

2. **Kickoff Fase 1 (40h)**
   - Variables + Fonts
   - Webclient Layout
   - Bootstrap Overrides
   - Form View SCSS

3. **Implementar Crítico (132h)**
   - Home Menu (40h)
   - Form View (36h)
   - WebClient Core (32h)
   - Menu Principal (24h)

**Meta:** Tener 80% del valor en 4 semanas con Fase 1 + Crítico completo.

---

**Documento Completo:** `web_enterprise_technical.md` (1,374 líneas)
**Fecha:** 2025-11-08
**Autor:** Odoo Developer Agent (Claude Code)
