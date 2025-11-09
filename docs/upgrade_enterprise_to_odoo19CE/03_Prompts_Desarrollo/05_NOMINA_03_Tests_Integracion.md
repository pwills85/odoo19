---
id: NOMINA-03-TESTS
pilar: Nómina
fase: P0
owner: QA Engineer
fecha: 2025-11-08
version: 1.0
estado: Ready
relacionados:
  - ../04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md
  - ../04_Artefactos_Mejora/OBSERVABILIDAD_METRICAS_SPEC.md
  - ../04_Artefactos_Mejora/MASTER_PLAN_v2.md
---

# PROMPT: Pruebas de Integración y Casos de Borde para Nómina

**PROYECTO:** Nómina Chilena

**TÍTULO:** Suite de Tests Integración — Motor Cálculo + LRE — Fase P0-P1

---

## 1. Objetivo

Implementar una **suite exhaustiva de tests** que valide la precisión, robustez e integración del motor de cálculo de nómina (NOMINA-01) con la generación de LRE (NOMINA-02), cubriendo casos comunes, borde y errores, con mínimo 90% cobertura de código.

**Objetivos específicos:**

1. Crear tests unitarios para cálculo payslip (haberes, descuentos, impuestos, líquido)
2. Validar casos borde: bajo mínimo imponible, sobre tope imponible, cambios legislativos
3. Validar integración P0 (indicadores económicos) → payslip → LRE
4. Crear fixtures de datos sintéticos reutilizables (empleados, contratos, payslips)
5. Implementar tests de trazabilidad: cada línea payslip tiene origen verificable
6. Validar precisión decimal: errores < 0.01 CLP
7. Generar reportes cobertura + análisis brechas

---

## 2. Alcance

### Incluye

- Suite tests unitarios: reglas salariales, cálculos intermedios, sueldo líquido
- Tests integración: Fase P0 (indicadores) → payslip → LRE
- Tests de casos borde: bajo mínimo, sobre tope, sin descuentos, múltiples bonificaciones
- Tests de validación: datos obligatorios, rangos válidos, coherencia totales
- Fixtures datos sintéticos (empleados, contratos, configuración)
- Reportes cobertura código (>90% target)
- Tests de rendimiento: cálculo payslip <500ms para 1000 empleados
- Documentación: cómo ejecutar tests, interpretar resultados, agregar casos

### Fuera de Alcance

- Tests de UI/Interfaces Web (es P2)
- Tests de SII integration (subida, validación SII es P2)
- Tests de performance extrema (>10.000 payslips)
- Tests de data migration (es P2)
- Load testing (es P2)

---

## 3. Entradas y Dependencias

### Archivos de Referencia

- `addons/localization/l10n_cl_hr_payroll/tests/` (directorio tests)
- `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md`
- `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/OBSERVABILIDAD_METRICAS_SPEC.md`
- `ESPECIFICACION_MOTOR_CALCULO.md` (NOMINA-01)
- `ESPECIFICACION_LRE_LAYOUT.md` (NOMINA-02)

### Artefactos Relacionados

- `DATASET_SINTETICO_SPEC.md` → Especificación datos test (empleados, contratos, payslips)
- `OBSERVABILIDAD_METRICAS_SPEC.md` → Métricas monitoreo, logs, alertas
- `MASTER_PLAN_v2.md` → Hito Testing integración

### Entorno Necesario

- Odoo 19 funcional con `l10n_cl_hr_payroll` instalado
- Docker compose configurado para ejecutar tests
- Python 3.10+ con pytest, coverage instalados
- Fixtures datos sintéticos cargables
- SII compliance docs (para validación legales)

---

## 4. Tareas

### Fase 1: Diseño Suite Tests (QA Engineer)

1. Revisar `DATASET_SINTETICO_SPEC.md` y mapear casos test
2. Especificar fixtures: empleados, contratos, indicadores, payslips esperados
3. Diseñar matriz de casos: categorías (haberes, descuentos, impuesto), escenarios (bajo mín, tope, promedio)
4. Definir métricas: cobertura código, tiempo ejecución, precisión decimales
5. Documentar en `ESPECIFICACION_SUITE_TESTS.md`

### Fase 2: Fixtures y Data Sintética

6. Crear `fixtures_empleados.py`: generador empleados test (RUT, nombre, contrato)
7. Crear `fixtures_contratos.py`: generador contratos (sueldo base, vigencia, descuentos)
8. Crear `fixtures_indicadores.py`: cargar UF, IPC, topes del período
9. Crear `fixtures_payslip_esperados.py`: valores esperados para cada caso (JSON)
10. Implementar helpers: `_create_employee()`, `_create_payslip()`, `_assert_payslip_equals()`

### Fase 3: Tests Unitarios — Haberes

11. Test: empleado sueldo base 500.000 CLP → HABERES_IMPONIBLES = 500.000
12. Test: empleado sueldo base + gratificación → suma correcta
13. Test: empleado con asignación familiar → HABERES_NO_IMPONIBLES calculados
14. Test: empleado con bono por desempeño → suma haberes correcta
15. Test: empleado sin bonificaciones → payslip simple válido

### Fase 4: Tests Unitarios — Base Tributable y Topes

16. Test: Empleado bajo mínimo imponible (ej: 400.000 CLP, mínimo 436.000) → BASE_TRIBUTABLE = 0
17. Test: Empleado sobre tope imponible (ej: 4.000.000 CLP, tope 100.5 UF) → BASE_TRIBUTABLE capped
18. Test: Empleado entre mínimo y tope → BASE_TRIBUTABLE = TOTAL_IMPONIBLE
19. Test: Cambio UF entre mes anterior y actual → tope recalculado correctamente
20. Test: Validación tope no puede ser negativo

### Fase 5: Tests Unitarios — Descuentos Previsionales

21. Test: AFP 10% sobre base tributable 1.000.000 → AFP = 100.000
22. Test: Salud FONASA 7% sobre base → Salud = 70.000
23. Test: Seguro Cesantía 0.6% sobre base → Cesantía = 6.000
24. Test: Empleado sin ISAPRE (FONASA) → descuento correcto
25. Test: Empleado con ISAPRE (mayor a FONASA) → descuento ISAPRE validado
26. Test: Total descuentos no excede base tributable

### Fase 6: Tests Unitarios — Impuesto Único

27. Test: Empleado bajo mínimo imponible → IMPUESTO_UNICO = 0
28. Test: Empleado dentro tramo impositivo → IMPUESTO_UNICO según tabla
29. Test: Aplicar crédito por descuentos previsionales (si aplica)
30. Test: Validación impuesto no es negativo
31. Test: Tabla `hr.tax.bracket` correctamente utilizada

### Fase 7: Tests Unitarios — Sueldo Líquido

32. Test: Fórmula SUELDO_LIQUIDO = HABERES - DESCUENTOS - IMPUESTO
33. Test: Verificar trazabilidad: cada componente tiene origen en regla
34. Test: Validar sueldo líquido > 0 (o = 0 si bajo mínimo)
35. Test: Empleado con múltiples descuentos especiales (APV, préstamo, etc.)

### Fase 8: Tests de Casos Borde

36. Test: Empleado con 30 días de licencia → salario prorrateado
37. Test: Empleado con ausencias (3 días sin justificación) → descuento proporcional
38. Test: Cambio AFP durante mes → cálculo prorrateado
39. Test: Empleado nuevo (primeros 15 días) → salario proporcional
40. Test: Empleado que se va (últimos 10 días) → salario proporcional
41. Test: Payslip ajuste (negativo) → validación señales correctas

### Fase 9: Tests de Integración P0 → Payslip

42. Test: Cargar indicadores P0 (UF 10/2025, IPC, topes)
43. Test: Crear payslip con indicadores P0
44. Test: Verificar tope imponible usa UF correcta
45. Test: Verificar validación indicadores disponibles antes generar payslip
46. Test: Error handling si indicadores falta → mensaje claro

### Fase 10: Tests de Integración Payslip → LRE

47. Test: Generar LRE a partir de 1 payslip, validar estructura CSV
48. Test: Generar LRE a partir de 5 payslips, verificar totales
49. Test: CSV mapea payslip.line → columnas LRE correctamente
50. Test: Validar encoding UTF-8, separadores, encabezados

### Fase 11: Tests de Trazabilidad Completa

51. Test: Payslip completo P0 → P1 sin pérdida datos
52. Test: Cada `hr.payslip.line` referencia `hr.salary.rule` origen
53. Test: Auditoria: quién, cuándo, qué cambios en payslip
54. Test: Trazabilidad matemática: auditar cada cálculo intermedio

### Fase 12: Tests de Precisión Decimal

55. Test: Error máximo cálculos < 0.01 CLP
56. Test: Redondeo consistente (banker's rounding vs round-half-up)
57. Test: Validar que no hay errores acumulativos en múltiples payslips

### Fase 13: Tests de Validación Datos

58. Test: Intentar crear payslip sin empleado → error + mensaje
59. Test: Intentar crear payslip con contrato inactivo → error + mensaje
60. Test: Intentar crear payslip sin régimen previsional → error + mensaje
61. Test: Validar RUT formato correcto (si aplica)
62. Test: Validar fechas coherentes (date_from < date_to)

### Fase 14: Tests de Rendimiento

63. Test: Calcular 100 payslips en <10 segundos
64. Test: Generar LRE 100 empleados en <5 segundos
65. Test: Validar queries optimizadas (sin N+1 problems)

### Fase 15: Reportes y Validación

66. Ejecutar coverage report (target >90%)
67. Identificar brechas cobertura (qué reglas no están cubiertas)
68. Generar reporte validación vs MATRIZ_SII_CUMPLIMIENTO.md
69. Documentar results en `TEST_EXECUTION_REPORT.md`

---

## 5. Entregables

| Archivo | Ubicación | Contenido |
|---------|-----------|-----------|
| `fixtures_empleados.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Generador empleados test |
| `fixtures_contratos.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Generador contratos test |
| `fixtures_indicadores.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Cargar indicadores test |
| `test_haberes_p0.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests unitarios haberes |
| `test_descuentos_p0.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests unitarios descuentos |
| `test_impuesto_p0.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests unitarios impuesto |
| `test_casos_borde_p0.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests casos borde |
| `test_integracion_p0_p1.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests integración P0→LRE |
| `test_trazabilidad.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests trazabilidad completa |
| `test_precision_decimal.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests precisión decimales |
| `conftest.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Fixtures pytest comunes |
| `ESPECIFICACION_SUITE_TESTS.md` | `docs/l10n_cl_hr_payroll/` | Diseño suite, casos, matriz |
| `TEST_EXECUTION_REPORT.md` | `docs/l10n_cl_hr_payroll/` | Resultados ejecución, cobertura |
| `coverage_report.html` | `addons/localization/l10n_cl_hr_payroll/tests/coverage/` | Reporte cobertura código |

---

## 6. Criterios de Aceptación

| Criterio | Métrica | Umbral | Verificación |
|----------|---------|--------|--------------|
| **Cobertura Código** | % líneas código cubiertas | ≥90% | coverage report |
| **Tests Exitosos** | % tests pasan | 100% | pytest results |
| **Casos Borde** | # casos borde cubiertos | ≥15 | checklist casos |
| **Precisión Decimal** | Error máximo CLP | <0.01 | test assertions |
| **Integración P0→P1** | % flujo cubierto | ≥95% | test coverage |
| **Documentación** | Especificación + resultados | Completa | revisión manual |
| **Rendimiento** | Tiempo ejecución 65 tests | <30s | benchmark |

---

## 7. Pruebas

### 7.1 Ejecución Tests (Docker)

```bash
# Ejecutar suite completa
docker compose exec odoo odoo -c /etc/odoo/odoo.conf \
  --test-enable --stop-after-init -d odoo_db \
  -i l10n_cl_hr_payroll

# Ejecutar tests específicos
docker compose exec odoo python -m pytest \
  addons/localization/l10n_cl_hr_payroll/tests/ -v --cov

# Generar coverage report HTML
docker compose exec odoo python -m pytest \
  --cov=addons/localization/l10n_cl_hr_payroll \
  --cov-report=html
```

### 7.2 Validación Cobertura

**Objetivo:** >90% cobertura en:
- `models/hr_salary_rule.py`
- `models/hr_payslip.py`
- `models/hr_lre_wizard.py`
- `reports/*.py`

**Identificar brechas:** Qué funciones/métodos sin test
**Plan:** Crear tests para brechas identificadas

### 7.3 Validación Precisión

**Método:** Comparar payslip Odoo vs cálculo manual para cada caso
**Tolerancia:** ±0.01 CLP (redondeo)
**Reportar:** Cualquier discrepancia

---

## 8. Clean-Room (Protocolo Legal)

### Roles y Restricciones

| Rol | Persona | Restricciones | Evidencia |
|-----|---------|---------------|-----------|
| **QA Engineer** | QA Lead | ✅ Acceso specs NOMINA-01/02<br>✅ Acceso datos test<br>❌ NO acceso Enterprise | Tests + fixtures |
| **Auditor Calidad** | QA Manager | ✅ Revisa test coverage vs requisitos | Audit report |
| **Desarrollador CE** | Backend Dev | ❌ NO acceso Enterprise<br>✅ Solo ejecuta tests | Test results |

### Evidencias Requeridas

1. Suite tests completa (≥90% cobertura)
2. Fixtures datos sintéticos reproducibles
3. Reporte cobertura código
4. Test results exitosos (100% pass rate)

---

## 9. Riesgos y Mitigaciones

| ID | Riesgo | Probabilidad | Impacto | Severidad | Mitigación |
|----|--------|--------------|---------|-----------|------------|
| **R-TST-01** | Tests insuficientes descubren bugs post-deployment | Media (0.4) | Crítico (5) | 2.0 | >90% cobertura + manual review |
| **R-TST-02** | Datos test no reproducen escenarios reales | Media (0.3) | Alto (4) | 1.2 | Validar fixtures vs DATASET_SPEC |
| **R-TST-03** | Tests lentos (>60s) ralentizan feedback loop | Baja (0.2) | Medio (3) | 0.6 | Optimizar queries, paralelizar tests |
| **R-TST-04** | Cambios NOMINA-01/02 rompen tests | Media (0.5) | Medio (3) | 1.5 | Mantener tests sincronizados |

### Triggers de Decisión

- Si **R-TST-01** ocurre: PAUSE entrega hasta 90% cobertura
- Si **R-TST-03** ocurre: Refactorizar tests (fixture setup, SQL queries)

---

## 10. Trazabilidad

### Brecha que Cierra

| Brecha P0-P1 | Artefacto que la cierra | Métrica |
|--------------|------------------------|---------|
| Falta validación integral motor nómina | Suite tests + coverage report | 90% cobertura + 100% pass |
| Precisión decimales no verificada | test_precision_decimal.py | Error <0.01 CLP |
| Integración P0→P1 sin tests E2E | test_integracion_p0_p1.py | Flujo completo validado |

### Relación con Master Plan v2

- **Fase 1 (Mes 1-2):** Hito Testing — "Suite Integración Nómina"
- **P0:** Motor cálculo + Tests unitarios (NOMINA-01, NOMINA-03)
- **P1:** LRE + Tests integración (NOMINA-02, NOMINA-03)
- **P1/P2:** Auditoría SII (NOMINA-03 extensión futura)

---

## 11. Governance y QA Gates

### Gates Aplicables

| Gate | Criterio | Responsable |
|------|----------|-------------|
| **Gate-Calidad** | Tests ≥90% cobertura, 100% pass | QA Manager |
| **Gate-Precisión** | Validación precisión decimal <0.01 CLP | QA Engineer |
| **Gate-Integración** | Tests E2E P0→P1 exitosos | Tech Lead |

### Checklist Pre-Entrega

- [ ] Suite tests completa: ≥65 tests implementados
- [ ] Coverage report generado: ≥90% cobertura
- [ ] Todos tests pasan (0 failures, 0 skipped)
- [ ] Fixtures datos sintéticos reutilizables
- [ ] Documentación: especificación + ejecución
- [ ] Performance benchmark: 65 tests en <30s
- [ ] Validación precisión: error <0.01 CLP en todos casos

---

## 12. Próximos Pasos

1. **Ejecutar Prompt:** QA Engineer implementa tareas Fases 1-15
2. **Validación Cobertura:** Generar coverage report, identificar brechas
3. **Ejecución Tests:** Correr suite completa, documentar resultados
4. **Auditoría Calidad:** QA Manager revisa coverage vs requisitos
5. **Entrega:** Test results + reportes → NOMINA-01/02 pueden go-live

---

## 13. Notas Adicionales

### Supuestos

- Indicadores P0 están disponibles en test database
- Dataset sintético sigue `DATASET_SINTETICO_SPEC.md`
- Payslips NOMINA-01 y LRE NOMINA-02 están implementados antes tests
- Documentación SII/DT es estable (no cambios esperados Oct-Dec)

### Decisiones Técnicas

- **Framework:** pytest (NO unittest de Odoo nativo, para flexibilidad)
- **Fixtures:** Usar factories (factory_boy) para datos reproducibles
- **Mocking:** Mockear indicadores P0 en tests unitarios, usar reales en integración
- **Coverage:** Usar pytest-cov, target 90% en líneas ejecutables
- **Reportes:** HTML coverage + JSON para integración CI/CD futura

---

**Versión:** 1.0
**Estado:** Ready para ejecución
**Owner:** QA Engineer
**Aprobado por:** Tech Lead (2025-11-08)
