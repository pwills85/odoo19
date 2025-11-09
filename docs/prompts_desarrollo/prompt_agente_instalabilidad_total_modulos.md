# Prompt Profesional — Instalabilidad Total y Estable de Módulos

Fecha: 2025-11-07
Ámbito: Repo `odoo19` — Odoo 19 CE (Docker Compose)

Objetivo central: Garantizar instalación TOTAL, ESTABLE y SIN WARNINGS ni ERRORES de todos los módulos del stack en desarrollo (localización chilena + extensiones), incluyendo validación de dependencias, orden de carga, data, seguridad, migraciones, rendimiento inicial y ausencia de side-effects.

---
## Alcance

Módulos foco (prioridad):

- Núcleo Localización: `l10n_cl_dte`, `l10n_cl_financial_reports`, `l10n_cl_hr_payroll`
- Branding y soporte: `eergygroup_branding`
- Terceros (si presentes en `addons/third_party`) — validar integridad y compatibilidad Odoo 19.

Excluidos (fase futura): módulos experimentales, prototipos AI no críticos.

---
 
## Metas de Calidad de Instalación

| Gate | Meta | Criterio de Aprobación |
|------|------|------------------------|
| Dependencias | Completas | Ningún módulo falla en `-i` por dependencia faltante |
| Seguridad Access CSV | 100% limpio | Sin warnings de `ir.model.access.csv` duplicados o mal formados |
| Data XML | 100% válido | Carga sin warnings de campos inexistentes / xpaths rotos |
| Migraciones | Idempotentes | Scripts ejecutan sin excepción y pueden re-ejecutarse sin efectos adversos |
| Performance init | p95 < 3s módulo pesado | Tiempo de instalación medido; heavy modules bajo umbral |
| Logs WARNING/ERROR | 0 nuevos | Instalación genera solo INFO y menores conocidos documentados |
| Integrity Models | OK | Sin traceback por campos inexistentes, inherits inválidos o mixins faltantes |
| Cron jobs | Registrados | `ir.cron` entradas creadas y activas sin error |
| External deps | Disponibles | `pip show <dep>` para cada dependencia declarada en manifest |
| Uninstall (crítico) | Limpio | Desinstalación sin residuos críticos (opcional fase 2) |

---
 
## Fases Operativas

1. Fase A — Inventario y Normalización

- A1. Listar todos los módulos en `addons/localization`, `addons/custom`, `addons/third_party`.
- A2. Clasificar: core, dependencia indirecta, opcional.
- A3. Verificar manifests: claves requeridas (`name`, `version`, `depends`, `data`, `license`, `installable`).
- A4. Detectar claves duplicadas / obsoletas (p.ej. `category` repetida, assets mal formados).
- A5. Generar matriz `INSTALABILIDAD_MODULOS_YYYY-MM-DD.csv` con columnas: módulo | tipo | depende_de | external_deps | cron | migraciones | estado preliminar.

1. Fase B — Validación Estática Pre-Instalación

- B1. Lint rápido manifests (formato JSON sintáctico si se usa pyproject, aquí son dict Python → buscar comas faltantes, duplicados).
- B2. Validar rutas de todos los ficheros en `data/` referenciados en `__manifest__.py`.
- B3. Revisar `security/ir.model.access.csv`: columnas correctas (id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink).
- B4. Verificar que ningún XML contenga modelos inexistentes (`model="non.existent"`).
- B5. Identificar migraciones: asegurar que scripts usan APIs soportadas Odoo 19 (sin imports legacy removidos).

1. Fase C — Instalación Controlada Incremental (Contenedor Limpio)

- C1. Iniciar stack Docker (db vacía `odoo_instalab`).
- C2. Instalar módulo base por lote lógico:
  - Lote 1: `l10n_cl_dte`
  - Lote 2: `l10n_cl_financial_reports`
  - Lote 3: `l10n_cl_hr_payroll`
  - Lote 4: módulos auxiliares / branding.
- C3. Capturar logs y tiempos (timestamp inicio/fin instalación cada lote).
- C4. Parsear logs buscando tokens: `WARNING`, `ERROR`, `Traceback`. Registrar en matriz.
- C5. Si falla un lote: identificar dependencia oculta, revertir DB (descartar contenedor) y aplicar fix antes de reintentar.

1. Fase D — Verificación Profunda Post-Instalación

- D1. Comprobar cron jobs creados (`l10n_cl_tax_forms_cron.xml`, KPI alerts, etc.).
- D2. Validar disponibilidad de modelos clave con `ir.model`: `l10n_cl.f29`, `l10n_cl.f22`, mixins DTE.
- D3. Abrir vistas críticas (simulación headless): cargar QWeb templates para asegurar no hay campos inexistentes.
- D4. Verificar migraciones aplicadas (si existen carpetas `migrations/`): estado idempotente.
- D5. Revisar integridad i18n: compilar `.po` si necesario (sin errores de sintaxis).

1. Fase E — Consolidación y Evidencias

- E1. Actualizar matriz con estado final PASA / FALLA por módulo.
- E2. Generar `evidencias/INSTALABILIDAD_YYYY-MM-DD/REPORTE_FINAL.md` con:
  - Resumen métricas
  - Tiempos instalación
  - Warnings/Errors clasificados
  - Próximas acciones
- E3. Guardar logs de instalación crudos como artefactos (para auditoría).
- E4. Registrar diff si hubo cambios en manifests o access CSV.

1. Fase F — Hardening (Opcional inmediato / Recomendado)

- F1. Implementar guardas en scripts de migración (evitar duplicados).
- F2. Añadir tests smoke de instalación (pytest marcador `smoke`):
  - `test_module_installed('<module_name>')` via `ir.module.module`
  - `test_models_exist()`
  - `test_cron_jobs_registered()`.
- F3. Integrar job “instalabilidad” en CI (workflow separado) que cree DB, instale lote y falle si hay WARNING/ERROR nuevos.

---
 
## Checklists

Instalación por módulo (ejemplo):

- [ ] Manifest válido (sin claves obsoletas ni duplicadas)
- [ ] Dependencias resolubles en imagen base
- [ ] Data XML carga sin warnings
- [ ] Migraciones (si existen) ejecutadas OK
- [ ] Cron jobs activos
- [ ] Acciones y vistas se abren (sin campos missing)
- [ ] Sin nuevos WARNING/ERROR en log

Matriz CSV columnas sugeridas:
`modulo,tipo,depends,external_deps,migraciones,cron_jobs,tiempo_seg,warnings,errors,estado_final,notas`

---

## Comandos (referencia ejecución contenedor)

```sh
# 1. Crear DB limpia
odoo -c /etc/odoo/odoo.conf -d odoo_instalab --stop-after-init --log-level=info

# 2. Instalar lote 1
odoo -c /etc/odoo/odoo.conf -d odoo_instalab -i l10n_cl_dte --stop-after-init --log-level=info

# 3. Instalar lote 2
odoo -c /etc/odoo/odoo.conf -d odoo_instalab -i l10n_cl_financial_reports --stop-after-init --log-level=info

# 4. Instalar lote 3
odoo -c /etc/odoo/odoo.conf -d odoo_instalab -i l10n_cl_hr_payroll --stop-after-init --log-level=info || true  # Documentar fallo si ocurre

# 5. Instalar lote auxiliares
odoo -c /etc/odoo/odoo.conf -d odoo_instalab -i eergygroup_branding --stop-after-init --log-level=info
```

(Adaptar lista de módulos auxiliares según inventario real.)

---
## Política de Cambios

- Cambios a manifests deben ser mínimos, justificados y acompañados de evidencia (diff + razón).
- Un commit por grupo lógico (fix manifest, fix access CSV, fix data XML, añadir smoke tests).
- No introducir nuevas dependencias externas sin validar disponibilidad en imagen base.

---
 
## Métricas a Capturar

- Tiempo instalación por módulo (segundos).
- Conteo de warnings/errors por lote.
- Número de migraciones aplicadas.
- Cron jobs registrados (n).
- Tasa de éxito por módulo = módulos instalados / totales.

---
 
## Criterios de Cierre Definitivo

Se considera INSTALABILIDAD TOTAL cuando:

1. Todos los módulos objetivo instalan sin errores (exit code 0) y sin warnings nuevos críticos.
2. No existen campos missing, xpaths fallidos ni trazas en logs.
3. Migraciones idempotentes (segunda instalación no crea duplicados ni lanza excepciones).
4. Cron jobs registrados y activos (`model=ir.cron`).
5. External dependencies presentes (pip show sin error).
6. Reporte final y matriz CSV actualizados y guardados en evidencias.

---
 
## Riesgos y Mitigación

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| Dependencia Enterprise faltante | Alta (PR-3) | Media | Documentar, diferir módulo o crear stub temporal |
| Warnings masivos legacy | Media | Baja | Clasificar y plan de refactor posterior |
| Migración rompe reinstalación | Baja | Media | Añadir guardas (exists) en scripts |
| External dep no instalada | Media | Media | Añadir al Dockerfile base o requirements-dev |

---
 
## Entregables Finales

- `matrices/INSTALABILIDAD_MODULOS_2025-11-07.csv`
- `evidencias/2025-11-07/INSTALABILIDAD/REPORTE_FINAL.md`
- Logs crudos instalación por lote
- Diff manifests y access CSV (si hubo cambios)
- Smoke tests (pytest) añadidos

---
 
## Ejecución del Agente

El agente debe:

1. Crear matriz preliminar (Fase A).
2. Ejecutar validación estática (Fase B) y registrar hallazgos.
3. Lanzar instalaciones por lote (Fase C), capturar tiempos y logs.
4. Ejecutar verificación profunda (Fase D).
5. Consolidar evidencias y matriz (Fase E).
6. (Opcional) Implementar hardening y smoke tests (Fase F) si el tiempo lo permite.

Cada fase debe producir salida verificable; si aparece un bloqueo (dependencia ausente), documentar y seguir con lo posible (no detener ejecución completa).

---
 
## Notas

- Priorizar correcciones que desbloqueen instalación limpia antes de refactors extensos.
- Mantener coherencia con objetivos QA globales (lint, seguridad, reproducibilidad).
- Abstenerse de introducir cambios de negocio fuera del scope (solo instalabilidad/infra).

---
**Fin del Prompt — Ejecutar desde aquí.**
