---
id: desarrollo_nomina_fase_p1_cierre_total_brechas_preparacion_p2
type: desarrollo
module: l10n_cl_hr_payroll
phase: P1 -> P2 transition
requires:
  - docs/prompts_desarrollo/MAXIMAS_DESARROLLO.md
  - docs/prompts_desarrollo/MAXIMAS_AUDITORIA.md
  - docs/prompts_desarrollo/CONTEXTO_GLOBAL_MODULOS.md
  - docs/prompts_desarrollo/prompt_auditoria_regulatoria_sii_nomina_fase_dev_migracion_odo11_verificacion.md
  - ai-service/knowledge/nomina/
  - ai-service/knowledge/normativa/
deliverables:
  - PR: feat(payroll): finalize P1 robustness & prepare P2 (validations, constraints, perf, multi-company)
  - tests: addons/localization/l10n_cl_hr_payroll/tests/test_payroll_p1_hardening.py
  - docs: CIERRE_TOTAL_P1_PAYROLL.md + README actualización sección "Mantenimiento Legal"
  - i18n: verificación completa (es_CL, en_US)
  - matriz: matrices/NOMINA_P1_HARDENING_CHECKLIST.csv
---

# Cierre Total de Brechas – Nómina Chilena (Hardening P1 y Preparación P2)

Objetivo: transformar el estado "Listo para P2" en una base endurecida y verificable eliminando riesgos residuales (solapamientos de vigencias, multi-compañía, ausencia de stress test, mantenimiento legal, auditoría de cambios y pruebas negativas), garantizando trazabilidad completa y escalabilidad inicial.

## Alcance

- Modelos de parámetros legales (topes imponibles, UF/UTM, tasas SIS, seguro cesantía, impuesto único, retención honorarios).
- Reglas salariales asociadas a vigencias (`valid_from`/`valid_until`).
- Wizards críticos (LRE / exportaciones previsionales).
- Traducciones y ACL para componentes creados en P0/P1.

## Estado Inicial (Resumen Brechas Cerradas Previas)

Referencias: H-007, H-001, H-002, H-003 (todas cerradas). Pendientes de endurecer:

- Solapamiento y unicidad en rangos de vigencia.
- Multi-compañía y aislamiento paramétrico.
- Rendimiento base (dataset ≥ 500 liquidaciones / 300 contratos).
- Mantenimiento legal periódico (procedimiento y responsable).
- Auditoría de modificaciones de parámetros críticos.
- Pruebas negativas (ausencia de configuración, rango vacío, fecha fuera de cualquier vigencia).

## Backlog de Hardening (Orden Recomendado)

1. Constraints y Validaciones de Vigencias
   - Agregar constraint SQL/Python: no permitir solapamiento para mismo `cap_type` + `company_id`.
   - Verificar unicidad (cap_type, valid_from, valid_until, company_id).
   - Test: creación de rango que intersecta otro -> falla con mensaje claro.

2. Multi-Compañía
   - Crear segunda compañía de prueba y parámetros distintos.
   - Tests: cálculo usa parámetros de la compañía activa, nunca mezcla.
   - Revisar dominios en búsquedas (company_id obligatorio).

3. Pruebas Negativas y Bordes
   - Sin parámetros vigentes -> UserError con mensaje accionable (ya implementado, testear).
   - Fecha exacta = `valid_until` incluida (boundary) – verificar.
   - Historial sin rangos: retorna error, no fallback.
   - Rango futuro (valid_from > hoy) no se usa en cálculo actual.

4. Auditoría de Cambios Paramétricos
   - Añadir campos: `changed_by`, `changed_at` (in `write` override) o aprovechar chatter.
   - Registrar mensaje en log interno/`message_post`: "Parametro X actualizado de Y a Z (usuario, fecha)."
   - Test: modificación genera entrada en chatter.

5. Mantenimiento Legal y Procedimiento
   - Añadir doc `MANTENIMIENTO_LEGAL_NOMINA.md` con:
     - Fuente: Previred / SII / Superintendencia.
     - Frecuencia: mensual.
     - Script sugerido: `scripts/update_payroll_indicators.py` (TODO si no existe).
     - Checklist: descargar, validar, cargar, test automático, commit.

6. Rendimiento Base
   - Generar dataset sintético: 300 contratos, 500 liquidaciones, 2 rangos de tope.
   - Test performance (QueryCounter/tiempo): cálculo masivo < 3s y < 60 queries.
   - Documentar métricas en `CIERRE_TOTAL_P1_PAYROLL.md`.

7. Internacionalización Completa
   - Verificar 0 strings sin traducción en módulo updated.
   - Añadir test superficial: cargar traducciones y chequear algunas claves.

8. Limpieza Técnica
   - Revisar nombres de campos/rules para consistencia.
   - Eliminar posibles restos de referencias a `year` (si quedara en comentarios obsoletos).

## Campos / Cambios Técnicos (Ejemplo)

- En modelo de parámetros: constraint `_check_no_overlap`.
- `message_post` en `create`/`write` de parámetros críticos.
- Script `scripts/generate_payroll_perf_dataset.py` (opcional) para dataset sintético.

## Matriz de Verificación (CSV)

Columnas: `item`, `categoria`, `estado`, `evidencia`, `acción`, `responsable`, `fecha_objetivo`.
Ejemplos:

- overlap_validation | vigencias | OK | test solapamiento fallo | N/A | dev | hoy
- multi_company_isolation | multi_company | OK | test aislado | N/A | dev | hoy
- perf_mass_calculation | performance | OK | tiempo 2.4s / 48 queries | optimize si >3s | dev | hoy

## Tests Obligatorios (Archivo: test_payroll_p1_hardening.py)

- test_no_overlap_ranges_creation_fails
- test_unique_range_keys
- test_multi_company_parameter_isolation
- test_negative_no_parameters_available
- test_boundary_valid_until_included
- test_future_range_not_applied_yet
- test_audit_log_on_parameter_update
- test_massive_calculation_performance (marcar slow si necesario)
- test_translations_loaded (opcional)

## Métricas a Capturar

- Tiempo cálculo masivo (segundos).
- Queries en cálculo principal.
- Cantidad de parámetros por tipo.
- Cantidad de contratos y liquidaciones en dataset prueba.

## Definición de Hecho (DoD)

- Todos los tests verdes (incluyendo performance preliminar).
- Cobertura en archivo de parámetros ≥ 90%.
- Constraint de solapamiento verificada.
- Multi-compañía validado con test.
- Auditoría de cambios funcionando (chatter o log).
- Documentación de mantenimiento legal creada y referenciada en README.
- Matriz CSV completada y guardada.
- CHANGELOG actualizado con sección "Payroll P1 Hardening".

## Plan de Commits Sugerido

1. feat(payroll): add validity overlap constraints + tests
2. feat(payroll): add multi-company isolation tests
3. feat(payroll): add audit logging for legal parameter changes
4. feat(payroll): performance dataset + initial perf test
5. docs(payroll): add maintenance legal guide + update README
6. chore(payroll): i18n sync & cleanup obsolete references

## Riesgos y Contingencias

- Si performance >3s: registrar métrica, abrir issue de optimización (indexado, batch prefetch).
- Si queries >60: revisar `search` vs `read_group` y caching.
- Si falta fuente oficial en algún parámetro: marcar en doc como PENDIENTE y crear placeholder + test de ausencia.

## Última Línea Mandatoria

No cerrar la transición a P2 hasta entregar `CIERRE_TOTAL_P1_PAYROLL.md` con: tabla de métricas (antes/después), evidencia de constraints y multi-compañía, métricas performance, log de auditoría, matriz CSV completa y confirmación de procedimiento mensual documentado.
