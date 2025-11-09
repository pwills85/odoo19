---
id: nom-dev-p0-p1-fix-2025-11-07
type: dev
module: l10n_cl_hr_payroll
phase: P0_P1_Cierre_Brechas
criticality: high
status: active
requires:
  - audit_report: AUDITORIA_NOMINA_VERIFICACION_P0_P1_2025-11-07.md
  - evidence_table: AUDITORIA_NOMINA_P0_P1_TABLA_EVIDENCIAS.md
  - branch: feat/p1_payroll_calculation_lre
deliverables:
  - code
  - tests
  - docs
updated: 2025-11-07
---

# PROMPT: Cierre de Brechas P0/P1 – Nómina Chilena (Odoo 19 CE)

## 1) Contexto

La auditoría P0/P1 de Nómina ha concluido con veredicto "CONDICIONADO PARA P2". El motor de cálculo y el wizard LRE están mayormente correctos (12/14 reglas OK, 14 tests, LRE completo), pero existe un hallazgo crítico (H-007) que bloquea el paso a P2, además de tres gaps menores (H-001, H-002, H-003).

## 2) Máximas de Desarrollo (aplíquense todas las de la carpeta de prompts)

- Odoo 19 CE nativo; sin APIs obsoletas.
- Sin hardcoding de parámetros legales; usar modelo de indicadores/legales con vigencias.
- Integración con módulos del stack y respeto de `ir.config_parameter` cuando corresponda.
- Calidad: `flake8`/`pylint`/`black`, tests ≥ 90%, commits atómicos (Conventional Commits).
- Docker: pruebas y validaciones pensadas para entorno dockerizado.

## 3) Brecha Crítica (Bloqueante)

### H-007: Regla TOPE_IMPONIBLE_UF usa campo inexistente `year`

- Problema: La regla busca en `l10n_cl.legal_caps` por un campo `year` que no existe; el modelo define vigencias con `valid_from`/`valid_until`.
- Acción Correctiva:
  1. Localizar la regla (en `data/hr_salary_rules_p1.xml` o código asociado) y el helper/método que consulta `l10n_cl.legal_caps`.
  2. Reemplazar filtro por rango de fechas: usar la fecha de la liquidación (`payslip.date_to`) para seleccionar el registro vigente: `valid_from <= date <= valid_until`.
  3. Si hay múltiples registros solapados, definir criterio determinista (más reciente por `valid_from` o `id`).
  4. Manejo de ausencia: si no hay registro, lanzar `UserError` con mensaje claro y guía para parametrizar.
- Tests requeridos (`tests/test_payroll_caps_dynamic.py`):
  - Caso A: Fecha dentro de un rango → devuelve valor correcto.
  - Caso B: Cambio de rango (dos vigencias en el año) → selecciona el vigente.
  - Caso C: Sin registro vigente → lanza `UserError`.
- Commit sugerido: `fix(payroll): use validity range for legal caps instead of non-existent year`

## 4) Gaps Menores (No Bloqueantes)

### H-001: Fallback hardcoded 81.6 UF

- Acción: Eliminar fallback fijo. Usar siempre el modelo de indicadores/legales. Si falta dato, registrar advertencia y bloquear cálculo con error claro (evitar resultados silenciosos incorrectos).
- Test: Simular ausencia de indicador y verificar que se alza `UserError` con mensaje instructivo.
- Commit: `refactor(payroll): remove hardcoded UF fallback and enforce configured caps`

### H-002: Falta permisos para Wizard LRE

- Acción: Revisar `ir.model.access.csv` y vista del wizard; crear grupo `hr_payroll_user`/`hr_manager` según política. Restringir acción del wizard a grupos HR.
- Test: Probar acceso con usuario sin grupo HR (debe fallar) y con HR (debe permitir).
- Commit: `feat(payroll): add access controls for LRE wizard`

### H-003: Sin traducciones i18n

- Acción: Crear `i18n/es_CL.po` y al menos `en_US.po` con traducciones para vistas/etiquetas principales del wizard y mensajes de error nuevos.
- Commit: `i18n(payroll): add es_CL and en_US translations for LRE and messages`

## 5) Criterios de Aceptación (DoD)

- H-007: Consulta a `l10n_cl.legal_caps` por vigencia implementada y probada; sin referencias a `year` en código.
- H-001: Sin literales de UF o valores legales hardcodeados en reglas/lógica.
- H-002: Wizard LRE con permisos adecuados y tests de acceso.
- H-003: Paquetes i18n presentes y cargan sin warnings.
- Tests totales mantienen ≥ 90% y suite pasa completa.

## 6) Plan de Validación (No ejecutar, documentar)

```zsh
# Ejecutar solo tests nuevos de caps y permisos
docker exec -it odoo bash -lc "pytest -q addons/localization/l10n_cl_hr_payroll/tests/test_payroll_caps_dynamic.py --disable-warnings"

docker exec -it odoo bash -lc "pytest -q addons/localization/l10n_cl_hr_payroll/tests/test_lre_access_rights.py --disable-warnings"

# Ejecutar suite completa con cobertura
docker exec -it odoo bash -lc "pytest -q addons/localization/l10n_cl_hr_payroll/tests --cov=addons/localization/l10n_cl_hr_payroll --cov-report=term-missing"
```

## 7) Notas Técnicas

- Si el modelo `l10n_cl.legal_caps` no existe exactamente así, adaptar a `l10n_cl.previsional.indicator` u otro equivalente existente (manteniendo el contrato de vigencias por fecha).
- Evitar duplicación de consultas: cachear el valor vigente por `company_id` y fecha dentro del ciclo de cálculo si es necesario.
- Documentar en README del módulo dónde configurar las vigencias (menú de Ajustes o datos de demo).
