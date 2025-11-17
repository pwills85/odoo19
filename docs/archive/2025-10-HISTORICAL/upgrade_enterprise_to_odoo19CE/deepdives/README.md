# Deep-Dives Técnicos - Odoo Enterprise → Odoo 19 CE

Este directorio contiene análisis técnicos profundos de módulos Enterprise para planificar reimplementaciones limpias en Odoo 19 CE.

---

## Documentos Disponibles

### 1. web_enterprise_technical.md

**Análisis Completo del Tema Enterprise Phoenix**

- **Tamaño:** 1,374 líneas, 38KB
- **Módulo Analizado:** `web_enterprise` v12 Enterprise
- **Objetivo:** Reimplementación del diseño Enterprise en Odoo 19 CE

**Contenido:**

1. **Inventario de Assets**
   - 20 archivos SCSS (1,979 líneas)
   - 12 archivos JavaScript (2,434 líneas)
   - Tablas detalladas por prioridad

2. **Componentes UI Documentados**
   - Home Menu / App Drawer
   - Webclient Layout (Flexbox)
   - Form View Enterprise (sheets, button box, avatars)
   - Control Panel Responsive
   - List View Enhancements
   - Mobile Menu System
   - Menu Principal (Navbar)
   - WebClient Core

3. **Guías de Migración**
   - jQuery/Widget → OWL 2 Components
   - Bootstrap 3 → Bootstrap 5
   - Assets bundling v12 → v19
   - QWeb Templates v12 → OWL XML

4. **Arquitectura Propuesta**
   - Estructura modular: `web_responsive` + `web_enterprise_phoenix` + `web_enterprise_mobile`
   - Diagrama de dependencias
   - Decisiones de arquitectura

5. **Estimación de Esfuerzo**
   - Desglose por componente (S/M/L/XL)
   - 6 fases de implementación
   - **Total:** 270 horas (~7 semanas con 1 dev senior)
   - **Crítico (80/20):** 132 horas

6. **Puntos de Extensión**
   - Variables SCSS expuestas
   - Templates QWeb extensibles
   - JavaScript Hooks (services, patches)

7. **Apéndices**
   - Tabla de selectores CSS críticos
   - Eventos JavaScript
   - Comandos de testing

**Uso:**

```bash
# Leer análisis completo
cat docs/upgrade_enterprise_to_odoo19CE/deepdives/web_enterprise_technical.md

# Buscar componente específico
grep -A 20 "Home Menu" web_enterprise_technical.md

# Ver estimaciones
grep -A 30 "Estimación de Esfuerzo" web_enterprise_technical.md
```

---

## Metodología de Análisis

### 1. Análisis Funcional (NO copia de código)

- Inventario de archivos y estructura
- Identificación de componentes UI
- Documentación de selectores CSS
- Mapeo de interacciones JavaScript

### 2. Traducción de Tecnologías

- Equivalencias v12 → v19
- Patrones de migración
- Best practices Odoo 19

### 3. Estimación de Esfuerzo

- Complejidad por componente (S/M/L/XL)
- Fases de implementación
- Riesgos y mitigaciones

### 4. Arquitectura Propuesta

- Modularización
- Puntos de extensión
- Decisiones de diseño

---

## Convenciones

### Prioridades

- **P0:** Crítico, core functionality
- **P1:** Alta, UX importante
- **P2:** Media, nice-to-have

### Complejidad

- **S:** Simple (< 50 líneas, < 8h)
- **M:** Medio (50-200 líneas, 8-16h)
- **L:** Grande (200-400 líneas, 16-32h)
- **XL:** Extra Grande (> 400 líneas, > 32h)

### Licencias

- **OEEL-1:** Odoo Enterprise License (código original analizado)
- **LGPL-3:** Licencia propuesta para reimplementaciones

---

## Roadmap de Deep-Dives

- [x] **web_enterprise** (Tema Phoenix) - 2025-11-08
- [ ] **account_reports** (Reportes dinámicos)
- [ ] **helpdesk** (Sistema de tickets)
- [ ] **studio** (Diseño visual)
- [ ] **approvals** (Flujos de aprobación)

---

## Contribuir

Para agregar un nuevo deep-dive:

1. Analizar módulo Enterprise (v12-v16)
2. Crear documento: `{modulo}_technical.md`
3. Seguir estructura de `web_enterprise_technical.md`
4. Actualizar este README

**Template:**

```markdown
# Deep-Dive Técnico: {modulo} v{version} → Odoo 19 CE

1. Resumen Ejecutivo
2. Inventario de Assets
3. Componentes Funcionales
4. Traducción v{X} → v19
5. Puntos de Extensión
6. Arquitectura Propuesta
7. Estimación de Esfuerzo
8. Riesgos y Mitigaciones
9. Checklist de Implementación
10. Referencias
11. Apéndices
12. Conclusiones
```

---

**Última Actualización:** 2025-11-08
**Documentos:** 1
**Total Páginas Analizadas:** ~40 páginas equivalentes
