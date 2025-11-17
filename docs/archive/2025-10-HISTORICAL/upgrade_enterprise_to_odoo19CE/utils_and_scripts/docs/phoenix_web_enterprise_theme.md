# Phoenix: Tema y UI Backend estilo Enterprise (Odoo 19 CE)

## Objetivo
Proveer una estética y UX de backend moderna, cercana a Enterprise, respetando CE 19 (sin reutilizar código OEEL-1), basada en OWL/SCSS y bundles de assets.

## Principios

- Extender, no reemplazar: hooks/overrides mínimos, compatible con upgrades.
- CSS-first: priorizar variables y SCSS sobre JS para rendimiento.
- Modularidad: micro-módulos (tema base, componentes, dashboards, vistas avanzadas) habilitando adopción gradual.
- Accesibilidad: contraste suficiente, estados de foco, tamaños adaptables.

## Alcance

- Tema base (tipografía, colores, espaciados, sombras, bordes, densidad).
- Componentes: navbar, control panel, breadcrumbs, filtros, botones, badges, pills, dropdowns, tabs.
- Vistas: list, kanban, form (headers y sheets), search panel; dashboards básicos.
- Modos: light/dark opcional y switch persistente por usuario.

## No-objetivos

- No clonar 1:1 el CSS/JS Enterprise ni reutilizar su código.
- Studio/Website Studio no están en alcance (bajo ROI en CE-Pro).

## Arquitectura

- SCSS con `@use` y variables CSS para runtime theming.
- Bundles en manifest (web.assets_backend) con orden y aislamiento adecuados.
- OWL para componentes (control panel enhancements, tiles de dashboard) sin bloquear el core.
- Utilidades JS mínimas: comportamiento accesible y progresivo.

## Guía SCSS

- Variables: color-scheme (primary, surface, info, warning, danger), radii, elevation (sombra), spacing scale (4/8/12), typography scale.
- Mixins: focus-ring, gradient subtle, elevation levels, responsive helpers.
- BEM/ITCSS: nombres predecibles, capas (settings/tools/generic/components/utilities).

## Compatibilidad y riesgos

- Evitar `!important`; usar tokens/variables para alinearse con el core.
- Probar en vistas de alta densidad (list, pivot, kanban con imágenes).
- No romper layouts de módulos CE existentes (QA en 3-5 módulos representativos).

## Integración con vistas avanzadas

- Dashboard: tarjetas KPI, rejilla responsiva; charts via vistas existentes (graph/pivot) con skin consistente.
- Gantt/Grid/Cohort: se implementarán como micro-módulos aparte ("REPLICATE_CE_PRO" en el backlog) para no acoplar Phoenix.

## Roadmap (sprints)

- S1: Tema base (variables, tipografía, colores) + navbar/control panel + list view spacing.
- S2: Form headers, badges, tabs, search panel.
- S3: Dashboards básicos (tiles OWL, KPIs, cards) y dark mode.
- S4: Pulido (hover/focus), densidad compacta/comfortable y guía de estilos.

## Criterios de aceptación

- Sin regresiones visuales graves en vistas core.
- Rendimiento estable (TBT/JS minimal) y Lighthouse aceptable en backend.
- Consistencia visual en 5 vistas clave (list, form, kanban, pivot, graph).

## Notas de implementación

- Proveer variables de tema por compañía/usuario en `res.users` (opcional).
- Tests visuales básicos (screenshots) en flows críticos.
