---
id: nom-audit-verify-p0-p1-2025-11-07
type: audit
module: l10n_cl_hr_payroll
phase: P0_P1_verification
criticality: n/a
status: active
requires:
  - branch: feat/p1_payroll_calculation_lre
  - prior_phases: [P0_indicadores_apv, P1_motor_lre]
deliverables:
  - audit_report_markdown
  - evidence_table
updated: 2025-11-07
---

# Auditoría Focal de Verificación P0/P1 – Nómina Chilena (Odoo 19 CE)

## 1) Rol y Objetivo

- Rol: Auditor Senior de Nómina Chilena en Odoo 19 CE.
- Objetivo: Verificar y contrastar, con evidencias técnicas y funcionales, el estado real de los entregables P0 y P1 del módulo `l10n_cl_hr_payroll` declarados por el desarrollador. La auditoría debe concluir si el módulo está listo para iniciar la Fase P2 (evolución funcional) sin riesgos.

## 2) Alcance

- Código, datos y vistas del módulo en: `addons/localization/l10n_cl_hr_payroll/`.
- Rama: `feat/p1_payroll_calculation_lre`.
- Archivos declarados por el agente (XML reglas salariales, wizard LRE, vistas, tests, documentación).
- Parámetros/indicadores previsionales usados por el motor de cálculo (incluye APV).

## 3) Restricciones y Modo de Trabajo

- Modo lectura: No modifiques código ni configuración.
- Si es necesario ejecutar algo, redacta un plan y comandos sugeridos (no los ejecutes). Señala entradas, precondiciones y resultados esperados.
- Cita rutas y líneas exactas de los hallazgos siempre que sea posible.

## 4) Evidencias Declaradas a Verificar

El desarrollador reportó:

- 14 reglas salariales (XML) que implementan la cadena de cálculo completa.
- Wizard LRE con CSV de 29 columnas (normativa 2025) y validaciones.
- Integración con P0 (indicadores, APV) sin hardcoding (tope 81.6 UF indicado como aplicado correctamente).
- 14 tests (6 cálculo, 8 LRE) y cobertura > 92%.
- Commits: `9ccbc38` (feat LRE) y `a766132` (tests P1).
- Documentación: `FASE_P1_COMPLETADA.md` y `FASE_P1_RESUMEN.md`.

## 5) Lista de Verificación Técnica (paso a paso)

### A. Reglas Salariales (XML)

1. Ubica `data/hr_salary_rules_p1.xml` y valida:
   - Existen 14 reglas (`<record model="hr.salary.rule" ...>`). Cuenta exacta.
   - Los códigos de regla son claros y consistentes (ej.: `BAS`, `AFP`, `SALUD`, `AFC`, `IMP_UNICO`, `APV`, `TOPE_AFP`).
   - No hay valores legales hardcodeados (p. ej., no debe aparecer el literal `81.6` ni `UF` fijos). En su lugar, deben referenciar utilidades/métodos que buscan indicadores vigentes.
   - Las secuencias (`sequence`) implementan correctamente el orden: Haberes → Topes → Descuentos Previsionales → Impuesto → Líquido.
   - Las condiciones y cantidades evitan Python complejo embebido innecesario; prioriza funciones nativas y/o helpers del módulo.

2. Verifica que el tope imponible AFP se obtenga dinámicamente del modelo de indicadores (ej.: `l10n_cl.previsional.indicator` o equivalente) con consulta por fecha del payslip.

3. Confirma que APV está integrado y parametrizado; evita hardcoding de tasas o topes voluntarios.

### B. Wizard LRE (Libro de Remuneraciones Electrónico)

1. Ubica `wizards/hr_lre_wizard.py` y `wizards/hr_lre_wizard_views.xml`.

2. Verifica:
   - Generación de archivo LRE (CSV o TXT) con exactamente 29 columnas según la normativa 2025; documenta el mapeo campo→columna.
   - Validaciones incluidas: periodo válido, RUT, totales consistentes.
   - Gestión de separador/encoding y normalización de RUT (usa `stdnum` si disponible en el proyecto).
   - Comportamiento seguro: permisos/grupos adecuados para acceder al wizard.

3. Busca evidencia de pruebas con dataset mediano (p. ej., +100 payslips): si no existen, señala el riesgo de rendimiento y propone prueba en el anexo de comandos.

### C. Integración P0 (Indicadores + APV)

1. Confirma existencia del modelo de indicadores previsionales, campos clave (`code`, `date_from`, `date_to`, `value`) y consulta por rango vigente.
2. Verifica que todas las reglas que consumen indicadores hacen la consulta por fecha de la nómina y no por fecha actual.
3. Señala cualquier solapamiento potencial de periodos o ausencia de validación de solapes.

### D. Tests y Cobertura

1. Ubica `tests/test_payroll_calculation_p1.py` y `tests/test_lre_generation.py`.
2. Cuenta los tests (esperado: 14) y clasifícalos (cálculo vs LRE).
3. Revisa casos cubiertos: sueldo bajo, sueldo alto con tope, APV, validaciones de LRE; identifica casos de borde faltantes (multi-compañía, contrato sin AFP, isapre con plan fijo, etc.).
4. Si existe reporte de cobertura, consígnalo. Si no, propone comandos para generarlo y el umbral esperado (≥90%).

### E. Seguridad, Permisos e i18n

1. Revisa `ir.model.access.csv` y grupos relacionados: ¿quién puede ver/generar LRE y ver/editar indicadores?
2. Valida que el wizard esté restringido a perfiles HR adecuados.
3. Confirma existencia de carpeta `i18n/` y traducciones mínimas (es/en) para vistas/etiquetas principales.

### F. Multi-compañía y Analítica

1. Confirma que reglas y cálculos se realizan en el contexto de `company_id` y que cualquier parámetro/indicador sea filtrable por compañía si aplica.
2. Señala si hay integración con contabilidad analítica (etiquetas/centros de costo) o si debe abordarse en la siguiente fase.

### G. Commits y Documentación

1. Verifica existencia de los commits `9ccbc38` y `a766132`, su formato (Conventional Commits) y que tocan los archivos reportados.
2. Revisa `FASE_P1_COMPLETADA.md` y `FASE_P1_RESUMEN.md`:
   - Coherencia entre lo declarado y lo implementado (archivos, conteos, flujos).
   - Pasos de uso del wizard y ejemplos.

## 6) Matriz de Hallazgos (formato requerido)

Genera `AUDITORIA_NOMINA_VERIFICACION_P0_P1_2025-11-07.md` con:

- Resumen ejecutivo (veredicto: Listo/Condicionado/No Listo para P2).
- Tabla con columnas: ID | Archivo/Línea | Evidencia | Expectativa | Estado (OK/Gap) | Criticidad (Alta/Media/Baja) | Recomendación.
- Anexos con listado de reglas salariales y su propósito, y mapeo LRE (29 columnas).

## 7) Criterios de Aceptación para “Listo para P2”

- 14 reglas presentes, sin hardcoding legal, con tope AFP dinámico y APV integrado.
- Wizard LRE cumple 29 columnas y validaciones principales.
- Tests ≥14 y cobertura reportada ≥90% o plan de aumento con casos de borde claros.
- Permisos adecuados y sin riesgos de exposición.
- Commits y documentación verifican lo declarado.

## 8) Anexo: Plan de Comandos (Opcional, a ejecutar por el líder)

No ejecutar; redacta y valida los comandos. Ejemplos:

- Cobertura de tests (zsh):

```zsh
# dentro del contenedor de Odoo (ajustar nombre del servicio)
docker exec -it odoo bash -lc "pytest -q addons/localization/l10n_cl_hr_payroll/tests --maxfail=1 --disable-warnings --cov=addons/localization/l10n_cl_hr_payroll --cov-report=term-missing"
```

- Conteo de reglas y búsqueda de hardcoding:

```zsh
grep -R "<record model=\"hr.salary.rule\"" -n addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml | wc -l
grep -R "81.6\|UF" -n addons/localization/l10n_cl_hr_payroll
```

- Verificación de commits:

```zsh
git log --oneline --decorate --graph --max-count=20 feat/p1_payroll_calculation_lre | cat
git show --stat 9ccbc38
git show --stat a766132
```

- Smoke test LRE (si hay datos de demo):

```zsh
# Ejecutar wizard vía test o script si existe; de lo contrario, documentar cómo crearlo en UI
```

## 9) Salida Esperada de la Auditoría

- Veredicto claro (Listo/Condicionado/No Listo) y lista priorizada de acciones para P2.
- Si hay gaps, clasifícalos en: bloquear (P1), corto plazo (P2), mejora (P3).
- Recomendaciones de pruebas adicionales (stress LRE, multi-compañía, casos especiales: contrato sin AFP, isapre plan fijo, gratificaciones, horas extra).
