# Prompt P4-Deep: Auditoría Arquitectónica l10n_cl_hr_payroll

**Módulo:** Nóminas Chilenas (Payroll)  
**Versión:** 19.0.1.0.0  
**Nivel:** P4-Deep (1,200-1,500 palabras | ≥30 refs | ≥6 verificaciones)  
**Objetivo:** Auditoría arquitectónica cálculos payroll Chile con compliance Código del Trabajo

---

## 🔄 REGLAS DE PROGRESO (7 PASOS OBLIGATORIOS)

[Ver estructura progreso en template P4-Deep base]

**⭐ PASO 1-7**: Aplicar misma estructura de progreso que `p4_deep_l10n_cl_dte.md`

---

## 📊 CONTEXTO CUANTIFICADO DENSO - MÓDULO L10N_CL_HR_PAYROLL

### Métricas del Módulo

| Métrica | Valor | Contexto |
|---------|-------|----------|
| **Archivos Python** | 19 modelos | `addons/localization/l10n_cl_hr_payroll/models/` |
| **LOC Total** | ~4,200 líneas | Sin comentarios ni blanks |
| **Modelo Principal** | `hr_payslip.py` | 980 LOC (23% del módulo) |
| **Segundo Crítico** | `hr_salary_rule.py` | 450 LOC (reglas salariales) |
| **Tercero Crítico** | `hr_economic_indicators.py` | 320 LOC (UF/UTM/IPC sync) |
| **Tests** | 25+ tests | `tests/`, coverage ~65% |
| **Dependencias Python** | 2 críticas | requests (microservicio), python-dotenv (env vars) |
| **Dependencias Odoo** | 5 módulos | base, hr, hr_holidays, account, l10n_cl |
| **Reglas Salariales** | 35+ rules | AFP, ISAPRE, impuesto único, gratificación, APV |
| **Indicadores Económicos** | 3 tipos | UF, UTM, IPC (sync Banco Central Chile) |
| **Fondos AFP** | 10 instituciones | Capital, Cuprum, Habitat, Modelo, PlanVital, ProVida, Uno, UNO Apenta |
| **ISAPREs** | 7 instituciones | Banmédica, Consalud, Cruz Blanca, Masvida, Nueva Masvida, Colmena, Vida Tres |
| **Cron Jobs** | 2 schedulers | Indicadores económicos (diario), cálculos batch (mensual) |

### Optimizaciones Arquitectónicas Clave

1. **Cálculos matemáticos precisos**: Algoritmo impuesto único con 7 tramos progresivos
2. **Tope imponible UF 90.3**: Validación automática contra indicadores económicos
3. **Sync indicadores económicos**: API Banco Central Chile + fallback manual
4. **Previred export**: Formato 105 campos validado contra especificación oficial
5. **Reforma Pensional 2025 (Ley 21.735)**: Aporte empleador 0.5% progresivo hasta 3%

### Arquitectura Multi-Capa

```
Layer 1: UI/UX (Views + Wizards)
  ├── views/hr_payslip_views.xml
  ├── views/hr_economic_indicators_views.xml
  └── wizards/previred_validation_wizard_views.xml

Layer 2: Business Logic (Models ORM)
  ├── models/hr_payslip.py (980 LOC - core cálculos)
  ├── models/hr_salary_rule.py (450 LOC - reglas AFP/ISAPRE/impuesto)
  ├── models/hr_economic_indicators.py (320 LOC - UF/UTM/IPC)
  ├── models/hr_contract_cl.py (extensiones contrato chileno)
  └── models/hr_afp.py, hr_isapre.py (instituciones)

Layer 3: Integrations (External APIs)
  ├── Banco Central Chile API (indicadores económicos)
  ├── Payroll Microservice (cálculos complejos - opcional)
  └── AI Service (validación payroll - opcional)

Layer 4: Data Master (XML)
  ├── data/hr_salary_rules_p1.xml (reglas base)
  ├── data/hr_tax_bracket_2025.xml (tramos impuesto único)
  ├── data/l10n_cl_apv_institutions.xml (APV)
  └── data/hr_salary_rules_ley21735.xml (Reforma Pensiones 2025)
```

### Deuda Técnica Conocida

1. **hr_payslip.py acoplado a microservicio**: 980 LOC → Debería ser agnóstico (libs/ nativo)
2. **Tests cálculos matemáticos incompletos**: Coverage 65% → Target 85%+ (faltan tests edge cases topes UF)
3. **Indicadores económicos sync single-threaded**: Debería ser async (httpx + asyncio)
4. **Previred export manual**: Wizard requiere validación UI compleja (debería ser automático)
5. **Reforma Pensiones 2025 pendiente validación**: Ley 21.735 implementada pero sin tests completos

---

## 🔍 RUTAS CLAVE A ANALIZAR (≥30 FILES TARGET)

### Core Payroll (P0 - Críticos)

```
1.  addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py:1
2.  addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule.py:1
3.  addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py:1
4.  addons/localization/l10n_cl_hr_payroll/models/hr_contract_cl.py:1
5.  addons/localization/l10n_cl_hr_payroll/models/hr_afp.py:1
6.  addons/localization/l10n_cl_hr_payroll/models/hr_isapre.py:1
7.  addons/localization/l10n_cl_hr_payroll/models/hr_apv.py:1
8.  addons/localization/l10n_cl_hr_payroll/models/hr_payslip_input.py:1
9.  addons/localization/l10n_cl_hr_payroll/models/hr_payslip_line.py:1
10. addons/localization/l10n_cl_hr_payroll/models/hr_payslip_run.py:1
```

### Reglas Salariales (P0)

```
11. addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule_category.py:1
12. addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule_aportes_empleador.py:1
13. addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule_asignacion_familiar.py:1
14. addons/localization/l10n_cl_hr_payroll/models/hr_salary_rule_gratificacion.py:1
15. addons/localization/l10n_cl_hr_payroll/models/hr_tax_bracket.py:1
16. addons/localization/l10n_cl_hr_payroll/models/l10n_cl_apv_institution.py:1
```

### Datos Master (P1)

```
17. addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_p1.xml:1
18. addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_apv.xml:1
19. addons/localization/l10n_cl_hr_payroll/data/hr_salary_rules_ley21735.xml:1 (Reforma 2025)
20. addons/localization/l10n_cl_hr_payroll/data/hr_tax_bracket_2025.xml:1
21. addons/localization/l10n_cl_hr_payroll/data/l10n_cl_apv_institutions.xml:1
22. addons/localization/l10n_cl_hr_payroll/data/hr_salary_rule_category_base.xml:1
23. addons/localization/l10n_cl_hr_payroll/data/hr_salary_rule_category_sopa.xml:1
```

### Views y UX (P2)

```
24. addons/localization/l10n_cl_hr_payroll/views/hr_payslip_views.xml:1
25. addons/localization/l10n_cl_hr_payroll/views/hr_contract_views.xml:1
26. addons/localization/l10n_cl_hr_payroll/views/hr_economic_indicators_views.xml:1
27. addons/localization/l10n_cl_hr_payroll/views/hr_afp_views.xml:1
28. addons/localization/l10n_cl_hr_payroll/views/hr_isapre_views.xml:1
```

### Testing (P2)

```
29. addons/localization/l10n_cl_hr_payroll/tests/test_ai_driven_payroll.py:1
30. addons/localization/l10n_cl_hr_payroll/tests/test_payslip_calculations.py:1 (si existe)
```

---

## 📋 ÁREAS DE EVALUACIÓN (10 DIMENSIONES OBLIGATORIAS)

### A) ARQUITECTURA Y MODULARIDAD (≥5 sub-dimensiones)

**Analizar:**

- A.1) **Herencia de Modelos**: ¿`hr_payslip.py` usa `_inherit='hr.payslip'` correctamente? ¿Compatibilidad Odoo 19 CE vs Enterprise?
- A.2) **Cálculos matemáticos isolados**: ¿Fórmulas AFP/ISAPRE/impuesto están en métodos puros Python (testables sin ORM)?
- A.3) **Dependencia microservicio**: ¿`hr_payslip.py` está acoplado a microservicio payroll o funciona standalone?
- A.4) **Reglas salariales vs código**: ¿Lógica está en XML data (reglas) o hardcodeada en Python?
- A.5) **Monolitos detectados**: ¿`hr_payslip.py` 980 LOC tiene múltiples responsabilidades?

**Referencias clave:** `hr_payslip.py:1`, `hr_salary_rule.py:1`, `data/hr_salary_rules_p1.xml:1`

---

### B) PATRONES DE DISEÑO ODOO 19 CE (≥5 sub-dimensiones)

**Analizar:**

- B.1) **@api.depends en cálculos**: ¿Campos computed `total_imponible`, `total_tributable` tienen dependencias correctas?
- B.2) **@api.constrains validación**: ¿Tope UF 90.3 validado con constrains vs raise manual?
- B.3) **@api.onchange UX**: ¿Cambios en `afp_id` actualizan automáticamente tasa comisión?
- B.4) **Odoo 19 deprecations compliance**: ¿Hay uso de `hr_contract` module (Enterprise-only)?
- B.5) **Performance cálculos**: ¿Se usa `.mapped()` para sumar líneas o loops Python?

**Referencias clave:** `hr_payslip.py:50-200` (computed fields), `hr_contract_cl.py:1`

---

### C) INTEGRACIONES EXTERNAS (≥5 sub-dimensiones)

**Analizar:**

- C.1) **Banco Central Chile API**: ¿Sync indicadores económicos tiene timeout? ¿Retry logic?
- C.2) **Previred export**: ¿Formato 105 campos validado contra especificación oficial?
- C.3) **Payroll Microservice (opcional)**: ¿Circuit breaker si microservicio cae? ¿Fallback cálculo nativo?
- C.4) **AI Service validación**: ¿Pre-validación payroll usa AI Service o es manual?
- C.5) **Error handling externo**: ¿Manejo de API down, timeout, datos corruptos?

**Referencias clave:** `hr_economic_indicators.py:50-150` (sync), `models/hr_payslip.py:500-600` (Previred export)

---

### D) SEGURIDAD MULTICAPA (≥4 sub-dimensiones)

**Analizar:**

- D.1) **Datos sensibles nómina**: ¿Salarios están protegidos por RBAC? ¿Encriptación en DB?
- D.2) **SQL Injection**: ¿Cálculos usan ORM vs raw SQL con f-strings?
- D.3) **Multi-company isolation**: ¿Empleados segregados por compañía?
- D.4) **Audit trail**: ¿Trazabilidad 7 años (Art. 54 Código del Trabajo)?

**Referencias clave:** `security/security_groups.xml:1`, `security/multi_company_rules.xml:1`

---

### E) OBSERVABILIDAD (≥3 sub-dimensiones)

**Analizar:**

- E.1) **Logging cálculos**: ¿Se loggea total imponible, AFP, ISAPRE, impuesto único por empleado?
- E.2) **Error tracking cálculos**: ¿Errores matemáticos (división por cero, UF no disponible) se registran?
- E.3) **Métricas payroll**: ¿Se trackea p95 tiempo cálculo por empleado? ¿Success rate batch?

**Referencias clave:** `hr_payslip.py:300-400` (compute methods)

---

### F) TESTING Y COBERTURA (≥5 sub-dimensiones)

**Analizar:**

- F.1) **Coverage actual**: ¿65% es suficiente para cálculos matemáticos críticos? Target 85%+
- F.2) **Tests edge cases**: ¿Tope UF 90.3, salario cero, múltiples AFP mismo mes?
- F.3) **Tests reforma 2025**: ¿Ley 21.735 aporte empleador 0.5%-3% progresivo tiene tests?
- F.4) **Tests integración**: ¿Cálculo completo payslip → líneas AFP/ISAPRE/impuesto?
- F.5) **Tests performance**: ¿Cálculo batch 1000 empleados en <5 min?

**Referencias clave:** `tests/test_ai_driven_payroll.py:1`, `tests/test_payslip_calculations.py:1`

---

### G) PERFORMANCE Y ESCALABILIDAD (≥4 sub-dimensiones)

**Analizar:**

- G.1) **Cálculos batch**: ¿`hr_payslip_run` procesa 1000 empleados sin timeout?
- G.2) **N+1 queries**: ¿Cálculo por empleado itera sobre contratos sin prefetch?
- G.3) **Indicadores económicos cacheados**: ¿UF/UTM se consultan 1 vez por batch vs por empleado?
- G.4) **Índices DB**: ¿Tabla `hr_payslip` tiene índice en `employee_id, date_from, date_to`?

**Referencias clave:** `hr_payslip.py:400-500` (batch compute), `hr_payslip_run.py:1`

---

### H) DEPENDENCIAS Y DEUDA TÉCNICA (≥4 sub-dimensiones)

**Analizar:**

- H.1) **Dependencia hr_contract (Enterprise)**: ¿Módulo funciona en Odoo 19 CE sin hr_contract?
- H.2) **Dependencia microservicio payroll**: ¿Es crítica o opcional? ¿Fallback nativo?
- H.3) **Monolitos pendientes**: ¿`hr_payslip.py` 980 LOC se puede refactorizar?
- H.4) **TODOs en código**: ¿Hay `# TODO:` reforma 2025 sin implementar?

**Referencias clave:** `__manifest__.py:depends`, `hr_payslip.py:1-980`

---

### I) CONFIGURACIÓN Y DEPLOYMENT (≥3 sub-dimensiones)

**Analizar:**

- I.1) **Configuración indicadores**: ¿URLs Banco Central Chile configurables? ¿API keys en `.env`?
- I.2) **Post-install hooks**: ¿Inicializa indicadores económicos UF/UTM/IPC?
- I.3) **Cron jobs**: ¿Sync diario indicadores configurado? ¿Batch mensual payroll?

**Referencias clave:** `data/ir_cron_data.xml:1`, `__init__.py:1`

---

### J) ERRORES Y MEJORAS CRÍTICAS (≥5 sub-dimensiones)

**Analizar:**

- J.1) **Cálculos matemáticos incorrectos**: ¿Impuesto único con 7 tramos progresivos correcto?
- J.2) **Tope UF 90.3 no aplicado**: ¿Validación automática AFP/ISAPRE?
- J.3) **Reforma 2025 incompleta**: ¿Ley 21.735 aporte empleador 0.5%-3% progresivo implementado?
- J.4) **Indicadores económicos obsoletos**: ¿UF/UTM sincronizado vs manual?
- J.5) **Previred export errores**: ¿Formato 105 campos validado?

**Referencias clave:** `hr_tax_bracket.py:1`, `hr_salary_rule.py:100-200`, `data/hr_salary_rules_ley21735.xml:1`

---

## ✅ REQUISITOS DE SALIDA (OBLIGATORIO)

[Ver requisitos completos en template P4-Deep base]

### Verificaciones Obligatorias (≥6)

#### V1 (P0): Tope imponible UF 90.3 no validado

**Comando:**

```bash
docker compose exec odoo grep -r "90.3" addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py || echo "NOT FOUND"
```

**Hallazgo Esperado:**

```python
tope_imponible_uf = 90.3 * uf_value
```

**Si NO se encuentra:**

- **Problema:** Cálculo AFP/ISAPRE sin tope UF 90.3 (Art. 16 DL 3.500)
- **Corrección:** Agregar validación en `hr_payslip.py:compute_total_imponible()`

**Clasificación:** P0 (crítico - compliance legal)

---

#### V2 (P1): Coverage tests cálculos matemáticos < 85%

**Comando:**

```bash
docker compose exec odoo pytest addons/localization/l10n_cl_hr_payroll/tests/ --cov=l10n_cl_hr_payroll --cov-report=term-missing | grep "TOTAL"
```

**Hallazgo Esperado:**

```
TOTAL 4200 1500 65%
```

**Si coverage < 85%:**

- **Problema:** Tests insuficientes para cálculos críticos (AFP, impuesto único, gratificación)
- **Corrección:** Agregar tests edge cases (salario cero, tope UF, múltiples AFP)

**Clasificación:** P1 (alta - calidad)

---

[Agregar V3-V6 siguiendo mismo formato]

---

## 📖 ANEXOS Y REFERENCIAS

### Código del Trabajo Chile

- **DL 3.500/1980**: Ley AFP (tope imponible UF 90.3)
- **Ley 18.933/1990**: Ley ISAPRE (7% mínimo, sin tope)
- **DL 824/1974**: Ley Impuesto a la Renta (impuesto único, 7 tramos)
- **Ley 21.735/2025**: Reforma Pensional (aporte empleador 0.5%-3%)
- **Art. 54 CT**: Trazabilidad liquidaciones 7 años

### Previred

- **Circular 1/2018**: Formato archivo 105 campos
- **Manual Técnico 2025**: Especificación exportación Previred

### Banco Central Chile

- **API Indicadores**: https://si3.bcentral.cl/estadisticas/Principal1/enlaces/series/
- **UF, UTM, IPC**: Series históricas oficiales

---

**Última Actualización:** 2025-11-11  
**Versión Prompt:** 1.0.0  
**Autor:** EERGYGROUP  
**Basado en:** Template P4-Deep
