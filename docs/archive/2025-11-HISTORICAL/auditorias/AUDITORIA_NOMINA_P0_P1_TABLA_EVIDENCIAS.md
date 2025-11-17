# 📊 TABLA DE EVIDENCIAS - AUDITORÍA P0/P1 NÓMINA CHILENA

**Fecha:** 2025-11-07  
**Módulo:** `l10n_cl_hr_payroll`  
**Rama:** `feat/p1_payroll_calculation_lre`

---

## ✅ EVIDENCIAS POSITIVAS

| # | Componente | Archivo | Evidencia | Estado |
|---|------------|---------|-----------|--------|
| 1 | **Reglas Salariales** | `data/hr_salary_rules_p1.xml` | 14 reglas implementadas (297 líneas) | ✅ Completo |
| 2 | **Wizard LRE** | `wizards/hr_lre_wizard.py` | 368 líneas, 29 columnas CSV | ✅ Completo |
| 3 | **Vista Wizard** | `wizards/hr_lre_wizard_views.xml` | 91 líneas, formulario interactivo | ✅ Completo |
| 4 | **Tests Cálculo** | `tests/test_payroll_calculation_p1.py` | 6 tests, 354 líneas | ✅ Completo |
| 5 | **Tests LRE** | `tests/test_lre_generation.py` | 8 tests, 285 líneas | ✅ Completo |
| 6 | **Modelo Indicadores** | `models/hr_economic_indicators.py` | Modelo completo, método `get_indicator_for_payslip()` | ✅ Completo |
| 7 | **Modelo Topes Legales** | `models/l10n_cl_legal_caps.py` | Modelo con método `get_cap()`, 150 líneas | ✅ Completo |
| 8 | **Datos Topes 2025** | `data/l10n_cl_legal_caps_2025.xml` | 4 topes legales (APV, AFC, Gratificación) | ✅ Completo |
| 9 | **Seguridad Grupos** | `security/security_groups.xml` | 2 grupos (user, manager) | ✅ Completo |
| 10 | **Seguridad Accesos** | `security/ir.model.access.csv` | 32 entradas (16 modelos × 2 grupos) | ⚠️ Falta LRE wizard |
| 11 | **Commit LRE** | `9ccbc38` | +768 líneas (reglas + wizard + vistas) | ✅ Verificado |
| 12 | **Commit Tests** | `a766132` | +641 líneas (14 tests) | ✅ Verificado |
| 13 | **Documentación P1** | `FASE_P1_COMPLETADA.md` | 248 líneas, detalle completo | ✅ Coherente |
| 14 | **Resumen Ejecutivo** | `FASE_P1_RESUMEN.md` | 87 líneas, resumen conciso | ✅ Coherente |

---

## ⚠️ GAPS IDENTIFICADOS

| # | Severidad | Componente | Gap | Archivo/Línea | Impacto | Acción Requerida |
|---|-----------|------------|-----|---------------|---------|------------------|
| **H-007** | 🔴 **CRÍTICO** | Regla TOPE_IMPONIBLE_UF | Búsqueda por campo `year` inexistente en modelo | `data/hr_salary_rules_p1.xml:85` | **BLOQUEANTE** - Regla no funcionará | 1. Agregar dato tope AFP en `l10n_cl_legal_caps_2025.xml`<br>2. Corregir búsqueda para usar `get_cap()` |
| **H-001** | ⚠️ **MEDIA** | Regla TOPE_IMPONIBLE_UF | Fallback hardcoded `81.6 * 38000` | `data/hr_salary_rules_p1.xml:91-92` | Valor estático si falla búsqueda | Eliminar fallback, lanzar `UserError` |
| **H-002** | ⚠️ **MEDIA** | Permisos | Sin acceso definido para `hr.lre.wizard` | `security/ir.model.access.csv` | Wizard visible pero sin permisos explícitos | Agregar 2 líneas (user + manager) |
| **H-003** | ℹ️ **BAJA** | i18n | Carpeta `i18n/` no existe | Raíz módulo | Sin traducciones | Crear `es_CL.po` y `en_US.po` |
| **H-004** | ℹ️ **BAJA** | Validación RUT | No usa `stdnum.cl.rut` | `wizards/hr_lre_wizard.py:333-347` | Método propio vs biblioteca estándar | Evaluar migrar a `stdnum` |
| **H-005** | ℹ️ **BAJA** | Validación Tramos | Búsqueda de tramo sin error explícito | `data/hr_salary_rules_p1.xml:227` | Error silencioso si no hay tramo | Agregar `or raise UserError()` |
| **H-006** | ℹ️ **BAJA** | Tests | Casos de borde faltantes | `tests/` | Cobertura incompleta de escenarios especiales | Planificar tests P2 |

---

## 📋 DESGLOSE DE 14 REGLAS SALARIALES

| # | Código | Nombre | Secuencia | Estado | Observaciones |
|---|--------|--------|-----------|--------|---------------|
| 1 | BASIC | Sueldo Base | 10 | ✅ OK | Desde `contract.wage` |
| 2 | HABERES_IMPONIBLES | Total Haberes Imponibles | 100 | ✅ OK | Suma categorías imponibles |
| 3 | HABERES_NO_IMPONIBLES | Total Haberes No Imponibles | 101 | ✅ OK | Suma categorías no imponibles |
| 4 | TOTAL_IMPONIBLE | Total Imponible | 200 | ✅ OK | = HABERES_IMPONIBLES |
| 5 | TOPE_IMPONIBLE_UF | Tope Imponible (UF) | 201 | 🔴 GAP H-007 | Búsqueda incorrecta + fallback hardcoded |
| 6 | BASE_TRIBUTABLE | Base Tributable | 202 | ✅ OK | min(TOTAL_IMPONIBLE, TOPE_IMPONIBLE_UF) |
| 7 | AFP | AFP (Pensión) | 300 | ✅ OK | 10% + comisión variable |
| 8 | SALUD | Salud | 301 | ✅ OK | 7% FONASA / tasa ISAPRE |
| 9 | AFC | Seguro Cesantía | 302 | ✅ OK | 0.6% |
| 10 | BASE_IMPUESTO_UNICO | Base Impuesto Único | 400 | ✅ OK | Base - descuentos previsionales |
| 11 | IMPUESTO_UNICO | Impuesto 2da Cat. | 401 | ⚠️ H-005 | Búsqueda tramo sin validación robusta |
| 12 | TOTAL_HABERES | TOTAL HABERES | 900 | ✅ OK | Suma haberes |
| 13 | TOTAL_DESCUENTOS | TOTAL DESCUENTOS | 901 | ✅ OK | Suma descuentos (incluye APV) |
| 14 | NET | ALCANCE LÍQUIDO | 902 | ✅ OK | Haberes + Descuentos |

**Total:** 14/14 (100%)  
**Funcionando correctamente:** 12/14 (86%)  
**Con gaps:** 2/14 (14%)

---

## 📊 DESGLOSE DE 14 TESTS

### Tests de Cálculo (6)

| # | Test | Archivo | LOC | Cobertura |
|---|------|---------|-----|-----------|
| 1 | `test_01_empleado_sueldo_bajo` | `test_payroll_calculation_p1.py` | ~50 | Sueldo bajo, tramo exento |
| 2 | `test_02_empleado_sueldo_alto_con_tope` | `test_payroll_calculation_p1.py` | ~60 | Sueldo alto, tope AFP |
| 3 | `test_03_empleado_con_apv` | `test_payroll_calculation_p1.py` | ~55 | Integración P0 APV |
| 4 | `test_04_totales_consistencia` | `test_payroll_calculation_p1.py` | ~40 | Validación ecuación |
| 5 | `test_05_validacion_fechas` | `test_payroll_calculation_p1.py` | ~35 | Validación fechas |
| 6 | `test_06_numero_secuencial` | `test_payroll_calculation_p1.py` | ~30 | Unicidad números |

### Tests de LRE (8)

| # | Test | Archivo | LOC | Cobertura |
|---|------|---------|-----|-----------|
| 1 | `test_01_wizard_creation` | `test_lre_generation.py` | ~25 | Creación wizard |
| 2 | `test_02_generate_lre_success` | `test_lre_generation.py` | ~40 | Generación exitosa |
| 3 | `test_03_lre_content_structure` | `test_lre_generation.py` | ~45 | 29 columnas CSV |
| 4 | `test_04_lre_totals_match` | `test_lre_generation.py` | ~50 | Coincidencia totales |
| 5 | `test_05_no_payslips_error` | `test_lre_generation.py` | ~30 | Error sin payslips |
| 6 | `test_06_filename_format` | `test_lre_generation.py` | ~25 | Formato nombre |
| 7 | `test_07_rut_splitting` | `test_lre_generation.py` | ~35 | RUT-DV |
| 8 | `test_08_working_days_calculation` | `test_lre_generation.py` | ~35 | Días trabajados |

**Total:** 14 tests, 639 líneas  
**Cobertura declarada:** >92%  
**Estado:** ✅ Completo (verificación de ejecución pendiente)

---

## 🔄 VERIFICACIÓN DE INTEGRACIÓN P0

| Componente P0 | Estado Integración | Evidencia |
|---------------|-------------------|-----------|
| **Indicadores Económicos** | ✅ Integrado | Campo `payslip.indicadores_id`, método `get_indicator_for_payslip()` |
| **APV (Ahorro Previsional)** | ✅ Integrado | Regla TOTAL_DESCUENTOS incluye APV con `hasattr(categories, 'APV')` |
| **Topes Legales** | ⚠️ Gap H-007 | Modelo existe pero búsqueda incorrecta en regla |
| **Tramos Impuesto** | ✅ Integrado | Modelo `hr.tax.bracket`, búsqueda por año y rango |
| **AFP/ISAPRE** | ✅ Integrado | Modelos `hr.afp`, `hr.isapre` con tasas dinámicas |

**Evaluación:** Integración P0 completa con salvedad de H-007 (tope AFP).

---

## 📝 VALIDACIÓN DE DOCUMENTACIÓN

| Documento | Líneas | Contenido Verificado | Coherencia |
|-----------|--------|---------------------|------------|
| **FASE_P1_COMPLETADA.md** | 248 | ✅ 14 reglas listadas<br>✅ Cadena de cálculo<br>✅ 29 columnas LRE<br>✅ 14 tests<br>✅ Métricas código | ✅ Alta |
| **FASE_P1_RESUMEN.md** | 87 | ✅ Archivos creados<br>✅ Commits<br>✅ Próximos pasos | ✅ Alta |

**Evaluación:** Documentación completa y coherente con implementación.

---

## 🎯 MATRIZ DE DECISIÓN PARA P2

| Criterio | Cumple | Bloquea P2 | Observación |
|----------|--------|------------|-------------|
| **Reglas salariales completas** | Sí | No | 14/14 implementadas |
| **Reglas funcionan sin errores** | **No** | **Sí** | H-007 crítico |
| **Wizard LRE funcional** | Sí | No | 29 columnas OK |
| **Tests suficientes** | Sí | No | 14 tests, >92% cov. |
| **Integración P0** | Parcial | Sí | H-007 afecta tope AFP |
| **Seguridad básica** | Sí | No | Falta H-002 (no crítico) |
| **Documentación** | Sí | No | Completa |

### Veredicto

```
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║  ESTADO: CONDICIONADO PARA P2                         ║
║                                                       ║
║  Requiere corrección CRÍTICA H-007 antes de avanzar.  ║
║  Estimación: 2-3 horas de corrección + 1h testing     ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
```

---

## 📋 CHECKLIST DE CORRECCIONES

### 🔴 Críticas (Antes de continuar)

- [ ] **H-007**: Corregir búsqueda de tope AFP
  - [ ] Agregar dato `AFP_TOPE_IMPONIBLE` en `l10n_cl_legal_caps_2025.xml`
  - [ ] Actualizar regla TOPE_IMPONIBLE_UF para usar `get_cap('AFP_TOPE_IMPONIBLE', payslip.date_to)`
  - [ ] Ejecutar tests para verificar

### ⚠️ Importantes (P2 inmediato)

- [ ] **H-001**: Eliminar fallback hardcoded, lanzar `UserError`
- [ ] **H-002**: Agregar permisos wizard LRE en `ir.model.access.csv`

### ℹ️ Mejoras (P2+)

- [ ] **H-003**: Crear traducciones i18n (es_CL, en_US)
- [ ] **H-004**: Evaluar uso de `stdnum.cl.rut`
- [ ] **H-005**: Fortalecer validación tramos impositivos
- [ ] **H-006**: Planificar tests adicionales (multi-compañía, etc.)

---

**Tabla generada el:** 2025-11-07  
**Próxima revisión:** Post-corrección H-007  
**Documento principal:** `AUDITORIA_NOMINA_VERIFICACION_P0_P1_2025-11-07.md`
