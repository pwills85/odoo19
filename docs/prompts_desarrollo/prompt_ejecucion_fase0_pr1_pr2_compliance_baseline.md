---
id: ejecucion-fase0-pr1-pr2
type: desarrollo-coordinado
module: DTE + Nómina + QA
phase: fase0_pr1_pr2
requires:
  - PLAN_FASE0_EJECUCION.md
  - MATRIZ_BRECHAS_GLOBAL_CONSOLIDADA_2025-11-07.csv
  - MAXIMAS_DESARROLLO.md
  - MAXIMAS_AUDITORIA.md
  - CONTEXTO_GLOBAL_MODULOS.md
related:
  - prompt_cierre_total_definitivo_brechas_global_sii_nomina_reportes.md
  - prompt_seleccion_accion_cierre_total_definitivo.md
deliverables:
  - PR-1: DTE-SOAP-TIMEOUT (timeout + retry + tests + docs)
  - PR-2: NOMINA-TOPE-AFP-FIX (cap con vigencias + regla + tests)
  - BASELINE_FASE0_2025-11-07.md (métricas iniciales)
  - scripts/compliance_check.py (stub funcional)
---

# Prompt: Ejecución Fase 0 (PR-1 + PR-2) con soporte QA

## Objetivo

Ejecutar en paralelo PR-1 (DTE-SOAP-TIMEOUT) y PR-2 (Nómina Tope AFP) y montar el soporte mínimo de calidad (baseline de métricas y compliance_check) para garantizar un merge seguro y medible.

## Contexto

- Quick wins confirmados CERRADOS: DTE-C001 y NOM-M002
- Críticos objetivo Fase 0: 10 → 0, iniciando por P0-A (DTE-C002 y NOM-C001)
- Duración objetivo primera ola: ≤ 1 día hábil para cerrar PR-1 + PR-2

## Alcance

Incluye:

- Implementar timeouts y retry robusto en cliente SOAP del SII + tests
- Normalizar tope AFP vía tabla de vigencias + corrección regla + tests
- Crear baseline de métricas (rendimiento y consultas)
- Crear stub de compliance_check para gate pre-merge

Excluye:

- Cambios de Reportes F29/F22 (cubiertos en PR-3)
- Finiquito/Previred (PR-4/PR-5)

## Contrato de éxito (DoD)

- General
  - Branches dedicadas y PRs separados por dominio
  - Tests verdes; cobertura mínima ≥ 85% en archivos tocados
  - Sin hardcodes regulatorios; usar modelos con `valid_from`/`valid_until`
  - i18n aplicado a nuevos strings (es_CL, en_US)
  - Evidencias en `evidencias/<fecha>/<pr-id>/`

- PR-1 (DTE-SOAP-TIMEOUT)
  - session timeout: connect=10s, read=30s
  - retry policy: 3 intentos con backoff exponencial (p.ej. 0.5s → 1s → 2s)
  - logging estructurado en errores (correlationId, timestamp, endpoint)
  - tests: timeout (>30s) y HTTP 500 con reintentos; cobertura ≥ 90% del módulo afectado

- PR-2 (Nómina Tope AFP)
  - registro `AFP_TOPE_IMPONIBLE` en tabla legal caps con vigencias (UF)
  - regla `TOPE_IMPONIBLE_UF` usa `get_cap('AFP_TOPE_IMPONIBLE', payslip.date_to)`
  - eliminar fallback hardcoded; lanzar UserError si faltan indicadores
  - tests: caso feliz 2025 (81.6 UF) y negativo (sin indicadores); cobertura ≥ 95% de la regla

- Soporte QA
  - `BASELINE_FASE0_2025-11-07.md` creado con métricas antes del cambio
  - `scripts/compliance_check.py` ejecuta lint + tests + cobertura y retorna exit code !=0 en fallo

## Pasos de ejecución (orden y detalle)

1. Crear baseline de métricas
   - Archivo: `docs/BASELINE_FASE0_2025-11-07.md`
   - Contenido mínimo:
     - Dashboard DTE: tiempo carga inicial (p50/p95 si disponible)
     - Cálculo F29 simple: tiempo y consultas (QueryCounter) si existe test
     - Payslip nominal simple: tiempo y consultas
     - Cobertura global estimada (si hay)
   - Objetivo: comparar post-PRs y registrar mejoras o regresiones

2. PR-1: DTE-SOAP-TIMEOUT
   - Branch: `fix/dte-soap-timeout`
   - Archivos objetivo:
     - `addons/localization/l10n_cl_dte/libs/sii_soap_client.py`
     - `addons/localization/l10n_cl_dte/tests/test_sii_soap_client.py` (nuevo)
   - Implementación:
     - Configurar session timeout `(10, 30)` y retry (3x) con backoff exponencial
     - Añadir logs estructurados en excepciones de timeout/retry
   - Tests sugeridos:
     - Mock endpoint lento (> 30s) → assert timeout
     - Mock endpoint 500 → assert 3 reintentos y backoff
     - Asegurar no hay bloqueos de worker (simulación controlada)
   - DoD PR-1: criterios cumplidos + evidencias en `evidencias/<fecha>/PR-1/`

3. PR-2: NOMINA-TOPE-AFP
   - Branch: `fix/nomina-tope-afp`
   - Archivos objetivo:
     - `addons/localization/l10n_cl_hr_payroll/data/l10n_cl_legal_caps_2025.xml`
     - `addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml`
     - `addons/localization/l10n_cl_hr_payroll/tests/test_payroll_calculation_p1.py`
   - Implementación:
     - Crear/actualizar registro `AFP_TOPE_IMPONIBLE` (UF) con vigencias 2025
     - Usar `get_cap()` en la regla `TOPE_IMPONIBLE_UF`; remover fallback hardcoded
     - Lanzar `UserError` si faltan indicadores
   - Tests sugeridos:
     - Payslip 2025: usa 81.6 UF (con indicador UF presente)
     - Caso sin indicadores: levanta `UserError`
   - DoD PR-2: criterios cumplidos + evidencias en `evidencias/<fecha>/PR-2/`

4. Soporte QA
   - Crear `scripts/compliance_check.py` (stub):
     - Ejecuta `ruff`/`flake8` o equivalente del repo
     - Ejecuta `pytest` con `--maxfail=1 -q` y cobertura mínima en archivos tocados
     - Verifica extracción i18n para nuevos strings (si aplica)
     - Retorna exit code no cero si falla cualquiera
   - Anexar su uso a la plantilla de PR (pre-merge manual o job CI si existe)

5. Actualización de matriz y documentación
   - Marcar DTE-C002 y NOM-C001 como EN PROGRESO al crear PRs; CERRADO al merge con evidencias
   - Actualizar `CHANGELOG.md` por cada PR con conventional commits
   - Adjuntar baseline y resultados en el PR correspondiente

## Guardrails y estándares

- Sin literales ni valores legales hardcodeados
- Strings traducibles y sin texto duro en vistas/JS
- Presupuesto de consultas: < 50 por acción en tests críticos
- Multi-compañía no afectada por los cambios
- Sin `eval()` inseguro; revisar permisos en nuevos modelos/datos

## Entregables

- PR-1 y PR-2 con:
  - Descripción clara, riesgos, pruebas, métricas y evidencias
  - Tests pasando y cobertura dentro de objetivo
  - Entradas de `CHANGELOG.md`
- `docs/BASELINE_FASE0_2025-11-07.md`
- `scripts/compliance_check.py`

## Reporte de avance (formato)

```text
[HH:MM] PR-1 creado -> link
[HH:MM] PR-2 creado -> link
[HH:MM] Baseline creada -> docs/BASELINE_FASE0_2025-11-07.md
[HH:MM] compliance_check.py listo -> scripts/compliance_check.py
[HH:MM] Matriz actualizada -> ids DTE-C002, NOM-C001
```

## Cronograma de la primera ola (≤ 1 día)

- 0h–1h: Baseline + branches + esqueleto tests
- 1h–4h: Implementación PR-1 con tests
- 1h–3h: Implementación PR-2 con tests (en paralelo)
- 4h–7h: Ajustes, evidencias, actualización matriz y CHANGELOG
