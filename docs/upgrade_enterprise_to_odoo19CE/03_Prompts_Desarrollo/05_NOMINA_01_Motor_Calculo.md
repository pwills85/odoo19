---
id: NOMINA-01-MOTOR-CALC
pilar: Nómina
fase: P0
owner: Payroll Lead
fecha: 2025-11-08
version: 1.0
estado: Ready
relacionados:
  - ../04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md
  - ../04_Artefactos_Mejora/DATASET_SINTETICO_SPEC.md
  - ../04_Artefactos_Mejora/MASTER_PLAN_v2.md
---

# PROMPT: Implementación del Motor de Cálculo de Liquidación de Sueldo

**PROYECTO:** Nómina Chilena

**TÍTULO:** Motor de Cálculo de Liquidación de Sueldo — Fase P0

---

## 1. Objetivo

Implementar un **motor de cálculo completo** para liquidaciones de sueldo chilenas utilizando el framework de reglas salariales de Odoo 19 (`hr.salary.rule`), que procese correctamente haberes, descuentos previsionales, impuestos y genere un `hr.payslip` con precisión regulatoria SII.

**Objetivos específicos:**

1. Construir cadena de cálculo salarial chilena desde haberes hasta sueldo líquido
2. Implementar categorías de reglas: HABERES_IMPONIBLES, HABERES_NO_IMPONIBLES, BASE_TRIBUTABLE, DESCUENTOS_PREVISIONALES, IMPUESTO_UNICO, SUELDO_LIQUIDO
3. Integrar consultas a indicadores económicos (`UF`, `IPC`, `topes imponibles`) desde `l10n_cl.legal_caps`
4. Validar precisión de cálculos contra legislación chilena vigente (2025)
5. Generar `hr.payslip` auditables con trazabilidad completa de cada línea de cálculo

---

## 2. Alcance

### Incluye

- Diseño y especificación de `hr.salary.rule` para nómina chilena
- Implementación de reglas de haberes imponibles y no imponibles
- Cálculo de base tributable con aplicación de topes UF
- Descuentos previsionales (AFP, Salud, Seguro de Cesantía)
- Cálculo de Impuesto Único con tabla `hr.tax.bracket`
- Tests unitarios e integración con Fase P0 (indicadores económicos)
- Documentación de flujo cálculo y reglas aplicadas
- Validación contra MATRIZ_SII_CUMPLIMIENTO.md

### Fuera de Alcance

- Integración con SII (eso es NOMINA-02-LRE)
- Procesos previsionales específicos (APV, Fondos, etc. son P1)
- Generación de PDF o reportes (es P1)
- Interfaces Web (es P1)

---

## 3. Entradas y Dependencias

### Archivos de Referencia

- `addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule.py`
- `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py`
- `addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p0.xml`
- `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md`

### Artefactos Relacionados

- `DATASET_SINTETICO_SPEC.md` → Casos de prueba (empleado mínimo, tope, promedio)
- `MATRIZ_SII_CUMPLIMIENTO.md` → Mapeo requisitos SII a reglas
- `MASTER_PLAN_v2.md` → Hito Nómina (Mes 1-2)

### Entorno Necesario

- Odoo 19 funcional con módulo `l10n_cl_hr_payroll` instalable
- Indicadores económicos Fase P0 cargados (`hr.economic.indicator`)
- Dataset sintético de empleados y contratos
- Docker compose para ejecución de tests

---

## 4. Tareas

### Fase 1: Diseño de Reglas Salariales (Payroll Lead)

1. Revisar `MATRIZ_SII_CUMPLIMIENTO.md` y mapear requisitos a `hr.salary.rule`
2. Especificar categorías de reglas: estructura, secuencia evaluación, inputs/outputs
3. Definir fórmulas de cálculo para cada categoría (sin código Python aún)
4. Documentar dependencias entre reglas (qué regla usa output de otra)

### Fase 2: Implementación de Reglas Base

5. Crear reglas para HABERES_IMPONIBLES (sueldo base, gratificación, bono)
6. Crear reglas para HABERES_NO_IMPONIBLES (asignación familiar, colación, etc.)
7. Implementar regla de TOTAL_IMPONIBLE (suma haberes imponibles)
8. Implementar consulta a `hr.economic.indicator` para obtener UF vigente

### Fase 3: Base Tributable y Descuentos

9. Implementar regla BASE_TRIBUTABLE (capping con TOPE_IMPONIBLE_UF)
10. Crear reglas para AFP, Salud (FONASA/ISAPRE), Seguro Cesantía sobre BASE_TRIBUTABLE
11. Implementar BASE_IMPUESTO_UNICO (cálculo específico para impuesto)
12. Validar descuentos no excedan limites legales

### Fase 4: Impuesto Único

13. Implementar regla IMPUESTO_UNICO usando `hr.tax.bracket` tabla de tramos
14. Aplicar exención para menores a sueldo mínimo
15. Implementar crédito por descuentos previsionales (si aplica)

### Fase 5: Sueldo Líquido y Tests

16. Implementar regla SUELDO_LIQUIDO (haberes - descuentos - impuestos)
17. Crear tests unitarios para casos: bajo mínimo, sobre tope, promedio
18. Crear test de integración con Fase P0 (carga indicadores, calcula payslip)
19. Validar cobertura tests ≥90%

### Fase 6: Documentación y Validación

20. Documentar flujo cálculo en archivo técnico
21. Validar contra MATRIZ_SII_CUMPLIMIENTO.md
22. Ejecutar smoke tests finales

---

## 5. Entregables

| Archivo | Ubicación | Contenido |
|---------|-----------|-----------|
| `hr_salary_rules_p0.xml` | `addons/localization/l10n_cl_hr_payroll/data/` | Definición de todas las reglas salariales |
| `hr_payslip.py` (actualizado) | `addons/localization/l10n_cl_hr_payroll/models/` | Métodos cálculo e integración con indicadores |
| `test_motor_calculo_p0.py` | `addons/localization/l10n_cl_hr_payroll/tests/` | Tests unitarios e integración |
| `ESPECIFICACION_MOTOR_CALCULO.md` | `docs/l10n_cl_hr_payroll/` | Documentación técnica de reglas y flujo |
| `MATRIZ_TRAZABILIDAD_REGLAS.csv` | `matrices/` | Mapeo reglas SII vs `hr.salary.rule` |

---

## 6. Criterios de Aceptación

| Criterio | Métrica | Umbral | Verificación |
|----------|---------|--------|--------------|
| **Completitud Reglas** | % reglas implementadas vs especificadas | ≥95% | Conteo en XML |
| **Precisión Cálculos** | Error máximo en líquido vs cálculo manual | <0.01 CLP | Tests unitarios |
| **Cobertura Tests** | % cobertura código nuevo | ≥90% | Reporte coverage |
| **Trazabilidad SII** | % requisitos matriz mapeados a reglas | 100% | CSV trazabilidad |
| **Integración P0** | Payslip calcula con indicadores P0 sin errores | Sí | Test integración |
| **Documentación** | Especificación incluye formulas, ejemplos, casos borde | Completa | Revisión manual |

---

## 7. Pruebas

### 7.1 Pruebas Unitarias

**Test 1: Haberes Imponibles**
- Empleado con sueldo base 500.000 CLP
- Esperado: HABERES_IMPONIBLES = 500.000 CLP

**Test 2: Empleado Bajo Mínimo Imponible**
- Sueldo 400.000 CLP (bajo mínimo ~436.000 CLP 2025)
- Esperado: BASE_TRIBUTABLE capped, IMPUESTO_UNICO = 0

**Test 3: Empleado Sobre Tope Imponible**
- Sueldo 4.000.000 CLP (sobre tope ~100.5 UF 2025)
- Esperado: BASE_TRIBUTABLE capped, descuentos sobre tope aplicados

**Test 4: Descuentos Previsionales**
- Base tributable 1.000.000 CLP
- AFP 10%, Salud 7%, Cesantía 0.6%
- Esperado: Total descuentos previsionales = 175.600 CLP

**Test 5: Impuesto Único Cálculo**
- BASE_IMPUESTO_UNICO = 2.000.000 CLP
- Aplicar tabla `hr.tax.bracket`
- Esperado: IMPUESTO_UNICO = X CLP (según tramo)

### 7.2 Pruebas de Integración

**Test 6: Con Indicadores P0**
- Cargar UF fecha payslip (ej: 10/2025)
- Calcular payslip con `hr.payslip.create()`
- Esperado: No errores, tope aplicado usando UF correcta

**Test 7: Trazabilidad Completa**
- Payslip generado
- Revisar cada línea (hr.payslip.line) tiene regla referencia
- Verificar amount calculado = formula resultado

### 7.3 Validación SII

**Test 8: Matriz Cumplimiento**
- Para cada fila en MATRIZ_SII_CUMPLIMIENTO.md
- Verificar requisito mapeado a regla existente
- Simular escenario y validar resultado

---

## 8. Clean-Room (Protocolo Legal)

### Roles y Restricciones

| Rol | Persona | Restricciones | Evidencia |
|-----|---------|---------------|-----------|
| **Payroll Lead (Equipo A)** | Nómina Specialist | ✅ Acceso docs Enterprise<br>❌ NO copiar código | `ESPECIFICACION_MOTOR_CALCULO.md` |
| **Auditor Legal** | Legal Counsel | ✅ Revisión specs vs legislación SII | `audits/nomina_01_legal_review.md` |
| **Desarrollador CE (Equipo B)** | Backend Dev | ❌ NO acceso Enterprise<br>✅ Solo specs | Commits en `l10n_cl_hr_payroll` |

### Evidencias Requeridas

1. Especificación abstracta sin código literal Enterprise
2. Fórmulas expresadas en pseudo-código/descripción textual
3. Referencias a legislación chilena oficial (SII, Dirección del Trabajo)
4. Aprobación auditor legal sobre cumplimiento regulatorio

---

## 9. Riesgos y Mitigaciones

| ID | Riesgo | Probabilidad | Impacto | Severidad | Mitigación |
|----|--------|--------------|---------|-----------|------------|
| **R-NOM-01** | Error cálculo generar pasivos fiscales | Alta (0.6) | Crítico (5) | 3.0 | Auditoría legal + tests contra SII |
| **R-NOM-02** | Indicadores P0 incompletos/obsoletos | Media (0.4) | Alto (4) | 1.6 | Validar dataset P0 antes implementar |
| **R-NOM-03** | Reglas complejas difíciles mantener | Media (0.3) | Medio (3) | 0.9 | Documentación exhaustiva + código comentado |
| **R-NOM-04** | Cambios legislativos (2025) invalidan specs | Baja (0.2) | Alto (4) | 0.8 | Monitorear SII + flexibilidad diseño |

### Triggers de Decisión

- Si **R-NOM-01** ocurre: STOP hasta auditoría legal apruebe
- Si **R-NOM-02** ocurre: Pausar desarrollo, completar P0 primero

---

## 10. Trazabilidad

### Brecha que Cierra

| Brecha P0 | Artefacto que la cierra | Métrica |
|-----------|------------------------|---------|
| Motor cálculo nómina chilena gap | `ESPECIFICACION_MOTOR_CALCULO.md` + `hr_salary_rules_p0.xml` | 95% reglas + tests ≥90% |
| Integración indicadores económicos | Test integración P0 exitoso | Payslip calcula sin errores |

### Relación con Master Plan v2

- **Fase 1 (Mes 1-2):** Hito Nómina — "Motor de Cálculo"
- **P0:** Motor operacional (haberes, descuentos, impuesto)
- **P1:** LRE y reportes (NOMINA-02, NOMINA-03)

---

## 11. Governance y QA Gates

### Gates Aplicables

| Gate | Criterio | Responsable |
|------|----------|-------------|
| **Gate-Legal** | Auditor Legal aprueba cumplimiento SII | Legal |
| **Gate-Calidad** | Tests ≥90% + specs completas | QA |
| **Gate-Técnico** | Code review + integración P0 OK | Tech Lead |

### Checklist Pre-Entrega

- [ ] Todas las reglas salariales implementadas en `hr_salary_rules_p0.xml`
- [ ] Tests unitarios ≥90% cobertura, todos pasan
- [ ] Test integración P0 ejecutado exitosamente
- [ ] Documentación técnica completa con ejemplos
- [ ] Auditor legal revisó y aprobó cumplimiento SII
- [ ] Matriz trazabilidad SII generada y validada
- [ ] Code review completado sin observaciones críticas

---

## 12. Próximos Pasos

1. **Ejecutar Prompt:** Payroll Lead implementa tareas Fases 1-6
2. **Revisión Legal:** Auditor Legal valida cumplimiento SII
3. **QA Validation:** Ejecutar todos los tests, validar cobertura
4. **Entrega:** Código merged a rama `main`, NOMINA-02 (LRE) puede comenzar

---

## 13. Notas Adicionales

### Supuestos

- Indicadores económicos P0 están cargados y disponibles
- Dataset sintético de empleados disponible (ver `DATASET_SINTETICO_SPEC.md`)
- Legislación chilena 2025 es base de cálculo (no cambios esperados Oct-Dec)
- Equipo tiene acceso a documentación SII oficial actualizada

### Decisiones Técnicas

- **Framework:** Usar `hr.salary.rule` de Odoo (NO cálculos Python ad-hoc)
- **APIs:** Consultar indicadores vía `l10n_cl.legal_caps` (NO hardcoded)
- **Tabla Impuesto:** Usar `hr.tax.bracket` con actualización anual
- **Trazabilidad:** Cada `hr.payslip.line` incluye referencia a regla origen

---

**Versión:** 1.0
**Estado:** Ready para ejecución
**Owner:** Payroll Lead
**Aprobado por:** Tech Lead (2025-11-08)
