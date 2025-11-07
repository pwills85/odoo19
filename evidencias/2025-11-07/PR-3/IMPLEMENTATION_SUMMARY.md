---
pr_id: PR-3
fecha_inicio: 2025-11-07
fase: Fase 1
scope: Reportes F29/F22 Core (REP-C001..REP-C006)
estado: EN_PROGRESO
branch_sugerido: feat/f1_pr3_reportes_f29_f22
owner: desarrollo_reportes
---

# IMPLEMENTATION_SUMMARY – PR-3 (Reportes F29/F22 Core)

## 1. Objetivo

Implementar base funcional y técnica para formularios fiscales F29 y F22:

- Modelos y servicios base de cálculo.
- Vistas y acciones de usuario corregidas.
- Cron para generación mensual F29.
- Eliminación de errores actuales (MissingError, TypeError, KeyError, XML embedding).

## 2. Issues Cubiertos

| ID | Descripción | Tipo | Estado Inicial | Meta |
|----|-------------|------|----------------|------|
| REP-C001 | Models no importa submódulos core/services | P0 | ERROR arquitectura | Estructura modular |
| REP-C002 | Vista F29 campos inexistentes | P0 | MissingError | Vista limpia |
| REP-C003 | F29 cálculo TypeError period_date | P0 | Excepción | Función estable |
| REP-C004 | F29 account.report XML incrusta records | P0 | XML malformado | Render limpio |
| REP-C005 | F22 KeyError integración SII | P0 | Excepción | Integración estable |
| REP-C006 | Cron create_monthly_f29() inexistente | P0 | Ausente | Cron activo |

## 3. Alcance Técnico

- Modelo base `l10n_cl.f29.report` y `l10n_cl.f22.report` (si no existen) con campos claves y estado.
- Servicio de cálculo desacoplado: `services/fiscal_forms.py`.
- Hook de actualización para poblar metadatos iniciales.
- Acción de menú + vista tree/form minimales.
- Cron mensual generando borrador F29.
- Uso de `account.report` donde corresponda para consistencia.

## 4. Exclusiones (No en PR-3)

- Optimización performance avanzada (se difiere a Fase 2 si aplica).
- Export XML definitivo SII (se incluye stub válido mínimamente).
- Validaciones legales profundas multi-periodo (parcial).

## 5. Diseño de Componentes

| Componente | Archivo | Propósito |
|------------|--------|-----------|
| Modelo F29 | models/f29_report.py | Persistir líneas y totales |
| Modelo F22 | models/f22_report.py | Persistir datos anuales |
| Servicio cálculo | services/fiscal_forms.py | Lógica centralizada |
| Vista F29 | views/f29_report_views.xml | UI usuario |
| Vista F22 | views/f22_report_views.xml | UI usuario |
| Cron | data/ir_cron_f29.xml | Generación mensual |
| Report Template | reports/f29_report_template.xml | Render (stub) |

## 6. Plan de Implementación (Pasos)

1. Crear branch `feat/f1_pr3_reportes_f29_f22`.
2. Identificar si existen modelos previos y evaluar refactor vs replace.
3. Añadir modelos y servicio cálculo inicial.
4. Crear vistas básicas sin campos inexistentes.
5. Implementar función cálculo F29 (mínima) sin excepciones actuales.
6. Implementar stub cálculo F22.
7. Crear cron y data de activación.
8. Añadir tests unitarios (estructura + cálculo simple + cron).
9. Ejecutar `compliance_check.py --baseline` para área tocada.
10. Ajustar según lint/cobertura.

## 7. Tests Planeados

| Test | Tipo | Objetivo |
|------|------|----------|
| test_f29_model_structure | unit | Verifica creación de campos clave |
| test_f29_basic_calculation | unit | Calcula total simple sin errores |
| test_f29_cron_generation | integration | Cron crea borrador mensual |
| test_f22_model_structure | unit | Campos anuales presentes |
| test_f22_basic_stub | unit | Stub retorna estructura válida |
| test_report_account_integration | integration | Ensambla account.report sin embedding |

## 8. Métricas Objetivo PR

| Métrica | Objetivo |
|---------|----------|
| Errores MissingError/TypeError/KeyError | 0 |
| Cobertura archivos nuevos | ≥90% |
| Lint nuevo | 0 issues |
| Tiempo cálculo F29 simple (10 líneas) | < 0.5s |
| Cron ejecución | < 1.0s |

## 9. Riesgos

| Riesgo | Mitigación |
|--------|------------|
| Falta de datos históricos F29/F22 | Generar fixtures mínimos y documentar supuestos |
| Cálculo incompleto line items | Diseñar servicio con puntos de extensión y marcar TODO reglamentarios |
| Cron saturando recursos | Limitar lote inicial y agregar logging básico |
| Desalineación con account.report | Revisar API y usar adaptadores simples |
| Cobertura < objetivo | Añadir tests parametrizados y medir temprano |

## 10. Verificación Rápida (Checklist)

- [ ] Modelos cargan sin errores.
- [ ] Vistas sin campos huérfanos.
- [ ] Cron genera borrador F29.
- [ ] Servicio cálculo retorna estructura estable.
- [ ] Reporte stub sin embedding de registros.
- [ ] Tests nuevos ≥90% cobertura.
- [ ] Lint sin issues.

## 11. Evidencia Post-Implementación

Se adjuntarán:

- Captura ejecución cron (log).
- Output pytest cobertura (xml/json).
- Reporte compliance baseline delta.
- Ejecución manual cálculo F29 (shell / UI) con tiempos.

## 12. Próximo Paso

Elevar cálculo detallado líneas F29 (sub‑PR) y comenzar enriquecimiento F22 anual; preparar PR‑6 infraestructura QA ampliada.

---
FIN IMPLEMENTATION_SUMMARY PR-3
