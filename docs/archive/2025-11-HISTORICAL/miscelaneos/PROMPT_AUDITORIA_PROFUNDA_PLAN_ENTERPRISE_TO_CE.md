# 🔍 PROMPT: Auditoría Profunda Plan Enterprise→CE con Validación Empírica

## Metadata del Prompt

| Campo | Valor |
|-------|-------|
| **Fecha Creación** | 9 de noviembre de 2025 |
| **Autor** | Pedro Troncoso (Senior Engineering Lead) |
| **Versión** | 1.0.0 |
| **Agente Target** | Auditor Técnico Local (CLI/Codex) |
| **Clasificación** | 🔴 CONFIDENCIAL - Auditoría Interna |
| **Tiempo Estimado** | 4-6 horas (deep analysis) |
| **Output Esperado** | Documento markdown estructurado 50-100 páginas |

---

## 🎯 Objetivo de la Auditoría

Realizar una **auditoría técnica exhaustiva, empírica y objetiva** del plan de migración/upgrade de funcionalidades de **Odoo 12 Enterprise** → **Odoo 19 CE-Pro**, validando o refutando los hallazgos críticos identificados en la conversación entre el agente auditor previo y el ingeniero senior.

**Scope específico**: Evaluar la viabilidad técnica, riesgos, presupuestos y supuestos del plan documentado en `docs/upgrade_enterprise_to_odoo19CE/` confrontándolos con evidencia concreta del workspace actual.

---

## 📋 Contexto Crítico del Proyecto

### 1.1 Antecedentes

EERGYGROUP está evaluando un proyecto estratégico para:

1. **Migrar** de Odoo 12 Enterprise a Odoo 19 CE
2. **Implementar** funcionalidades Enterprise críticas como módulos custom CE
3. **Adaptar** features Enterprise (Phoenix UI, Quantum Reports) a stack Odoo 19 CE con **tecnologías actualizadas** (OWL 2, Python 3.12, PostgreSQL 16, etc.)

**Inversión estimada**: USD $126,600 (1,266h)

**Proyectos pilares**:

- **Phoenix** (UI/UX Enterprise-like)
- **Quantum** (Reporting drill-down 7 niveles + compliance SII Chile)

### 1.2 Documentación Base a Auditar

**Ubicación**: `/Users/pedro/Documents/odoo19/docs/upgrade_enterprise_to_odoo19CE/`

**Artefactos críticos** (ver `INDEX_PROFESIONAL.md`):
- `04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md` (Plan maestro v2, score 86/100)
- `04_Artefactos_Mejora/EXECUTIVE_SUMMARY_v2.md` (Resumen ejecutivo)
- `04_Artefactos_Mejora/ADDENDUM_FINANCIERO.md` (Reconciliación presupuestaria)
- `04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md` (180h compliance SII)
- `04_Artefactos_Mejora/MIGRACION_MULTI_VERSION_PLAN.md` (Plan multi-hop 12→19)
- `04_Artefactos_Mejora/CLEAN_ROOM_PROTOCOL_OPERATIVO.md` (Protocolo legal)
- `04_Artefactos_Mejora/POCS_PLAN.md` (4 PoCs con criterios pass/fail)
- `reports/financials_recalc.md` (Baseline USD $126,600)

### 1.3 Hallazgos Previos a Validar/Refutar

**Agente Auditor Previo** (conversación analizada) identificó:

✅ **Hallazgos Confirmados**:
1. GAP #1 (Data Migration): +86h (+$8,600)
2. GAP #2 (Testing Strategy): +84h neto (+$8,400)
3. GAP #5 (Rollback Strategy): +50h (+$5,000)

❌ **Hallazgos Refutados**:
4. GAP #3 (Odoo 19 Capabilities): 11K LOC duplicadas account.report NO bloqueante → $0
5. GAP #4 (Team Capabilities): Bus factor=1 es riesgo, NO aumenta horas → $0

**Ingeniero Senior** (crítica técnica) contra-argumentó:

⚠️ **Contradicciones Identificadas**:
1. **GAP #3**: 11K LOC duplicadas son **technical debt crítico**, impacta Odoo 20 upgrade (estimado +80h = $8K)
2. **GAP #4**: Bus factor=1 **SÍ aumenta overhead** 15% = +244h ≈ $24,400 (mitigable parcialmente)
3. **Testing coverage**: Statement 72% ≠ Branch coverage ~45-50% (falta +36h = $3,600)
4. **Rollback scripts**: NO validados (¿existen? ¿funcionan?), falta PITR setup (+30h = $3,000)
5. **Volumen datos**: "15-20K facturas" SIN evidencia concreta (riesgo subestimación)

**Presupuestos comparados**:
- Original Plan: USD $126,600
- Agente Validado: USD $162,800 (+28.6%)
- Senior Ajustado: USD $191,600 (+51.4%) 🔴

---

## 🔬 Metodología de Auditoría Requerida

### 2.1 Principios Metodológicos

1. **Empirismo Radical**: Toda afirmación debe respaldarse con **evidencia verificable** del workspace
2. **Objetividad**: No asumir posición a priori (ni optimista ni pesimista)
3. **Reproducibilidad**: Documentar comandos bash/queries ejecutados con output completo
4. **Trazabilidad**: Referenciar archivos como `file:line` en todas las citas
5. **Cuantificación**: Preferir métricas numéricas sobre juicios cualitativos
6. **Bidireccionalidad**: Buscar ajustes **tanto al alza como a la baja** del presupuesto

### 2.2 Fuentes de Evidencia Válidas

| Tipo | Ejemplos | Peso |
|------|----------|------|
| **Código Fuente** | `.py`, `.js`, `.xml`, `.scss` en workspace | 100% |
| **Tests Existentes** | `addons/*/tests/*.py`, LOC, cobertura | 100% |
| **Git History** | Commits, contributors, bus factor | 100% |
| **Documentación Técnica** | `docs/`, `*.md` con specs concretas | 80% |
| **Scripts Operacionales** | `*.sh`, `docker-compose.yml`, backups | 100% |
| **Bases de Datos** | Queries volumen datos (si accesible) | 100% |
| **Afirmaciones sin evidencia** | Claims en docs sin respaldo workspace | 20% |

### 2.3 Estructura de Output Mandatoria

**Nombre archivo**: `AUDITORIA_PROFUNDA_PLAN_ENTERPRISE_CE_2025-11-09.md`

**Secciones obligatorias**:

```markdown
# 🔍 AUDITORÍA PROFUNDA: PLAN ENTERPRISE→CE PROFESIONAL

## Executive Summary
- Veredicto final: GO/CONDITIONAL GO/HOLD/NO-GO
- Score ajustado: X/100 (vs 86/100 plan actual)
- Presupuesto recomendado: USD $X (vs $126.6K baseline, $162.8K agente, $191.6K senior)
- 3 hallazgos críticos (bullet points)
- 3 recomendaciones accionables inmediatas

## 1. Validación de Supuestos Técnicos
### 1.1 Arquitectura Odoo 19 CE vs Plan
### 1.2 Viabilidad Phoenix (UI/UX)
### 1.3 Viabilidad Quantum (Reporting)
### 1.4 Compatibilidad Tecnológica (OWL 2, Python 3.12, PG 16)

## 2. Validación de Volúmenes de Datos
### 2.1 Contactos (res.partner)
### 2.2 Facturas (account.move/invoice)
### 2.3 DTEs (l10n_cl_dte)
### 2.4 Payroll (hr.payslip)
### 2.5 Estimación Migración (horas)

## 3. Validación de Testing Strategy
### 3.1 Tests Existentes (inventario completo)
### 3.2 Cobertura Real (statement vs branch)
### 3.3 Gaps Testing (P0/P1/P2)
### 3.4 Horas Ajustadas

## 4. Validación de Technical Debt
### 4.1 Duplicación Código (account.report 11K LOC)
### 4.2 Impacto Odoo 20 Upgrade
### 4.3 Refactorización: Bloqueante vs Opcional
### 4.4 Costo Real Technical Debt

## 5. Validación de Team Capabilities
### 5.1 Bus Factor (git contributors)
### 5.2 Overhead Real Bus Factor=1
### 5.3 Mitigaciones (backup contractor, docs)
### 5.4 Horas Ajustadas

## 6. Validación de Rollback Strategy
### 6.1 Scripts Existentes (backup/restore)
### 6.2 PITR Setup (PostgreSQL)
### 6.3 Drill Testing (evidencia)
### 6.4 RTO/RPO Cuantificados

## 7. Validación de SII Compliance
### 7.1 Horas Matriz SII (180h desglose)
### 7.2 Comparativa Enterprise vs CE-Pro
### 7.3 Riesgo Regulatorio

## 8. Validación Financiera
### 8.1 ROI Recalculado (3 escenarios)
### 8.2 Sensibilidad Usuarios (30/60/100)
### 8.3 Break-even Point

## 9. Matriz de Riesgos Ajustada
### 9.1 Top 10 Riesgos P×I
### 9.2 Mitigaciones vs Plan
### 9.3 Contingencia Recomendada

## 10. Presupuesto Final Auditado
### 10.1 Tabla Comparativa (4 columnas: Original/Agente/Senior/Auditor)
### 10.2 Ajustes Justificados (al alza y a la baja)
### 10.3 Baseline Recomendado

## 11. Condiciones Mandatorias Ajustadas
### 11.1 Validaciones Pre-GO (comandos concretos)
### 11.2 POCs Obligatorios
### 11.3 Criterios Abort

## 12. Recomendaciones Estratégicas
### 12.1 Opción A (MVP Recomendado)
### 12.2 Opción B (Go Full)
### 12.3 Opción C (Abort)

## 13. Calificación del Plan Original
### 13.1 Score por Dimensión (tabla)
### 13.2 Fortalezas (top 5)
### 13.3 Debilidades (top 5)

## 14. Accionables Inmediatos
### 14.1 Para Ingeniero Senior (5 comandos)
### 14.2 Para Comité Ejecutivo (3 decisiones)
### 14.3 Para Equipo DevOps (2 setups)

## Anexos
### A. Comandos Ejecutados (reproducibles)
### B. Outputs Completos (evidencia)
### C. Referencias Workspace (file:line)
### D. Glosario Técnico
```

---

## 🔍 Instrucciones Detalladas por Sección

### 3.1 Executive Summary

**Objetivo**: Resumen <500 palabras con **veredicto final claro**.

**Elementos mandatorios**:
- Score ajustado X/100 con justificación delta vs 86/100 actual
- Presupuesto recomendado USD $X con rango confianza (ej: $140K-$160K, 80% confidence)
- Comparativa 4 columnas: Plan Baseline / Agente Validado / Senior Ajustado / **Tu Auditoría**
- Clasificación final: `GO` / `CONDITIONAL GO` / `HOLD` / `NO-GO`
- Si CONDITIONAL: listar 3-6 condiciones P0 **específicas y verificables**

**Criterios de decisión**:
```python
if score >= 90:
    veredicto = "GO"
elif score >= 80:
    veredicto = "CONDITIONAL GO" + condiciones_P0
elif score >= 70:
    veredicto = "HOLD" + re_work_requerido
else:
    veredicto = "NO-GO" + justificación
```

### 3.2 Sección 1: Validación de Supuestos Técnicos

**Comandos a ejecutar**:

```bash
# 1.1 Validar Odoo 19 CE instalado y versión
find addons -name "__manifest__.py" -exec grep -l "version.*19\." {} \; | head -20

# 1.2 Validar OWL 2 disponible
find addons/web -name "*.js" -exec grep -l "@odoo/owl" {} \; | head -10

# 1.3 Validar stack tecnológico
python --version
psql --version
redis-server --version 2>/dev/null || echo "Redis NO instalado"

# 1.4 Validar módulos localization Chile
ls -lh addons/localization/l10n_cl_*/
find addons/localization/l10n_cl_dte -name "*.py" | wc -l

# 1.5 Validar account.report duplicación (GAP #3)
find addons/localization/l10n_cl_financial_reports -name "*.py" -exec wc -l {} + | tail -1
grep -r "class.*AbstractModel.*account\.report" addons/localization/l10n_cl_financial_reports/models/
```

**Preguntas a responder**:
1. ¿Existe código Phoenix (UI components OWL) actualmente? ¿Dónde? ¿LOC?
2. ¿Existe código Quantum (financial reports drill-down)? ¿LOC? ¿Estado?
3. ¿Las 11K LOC `l10n_cl_financial_reports` duplican `account.report` nativo? ¿Evidencia concreta?
4. ¿Odoo 19 CE incluye `account.report` nativo? ¿Versión? ¿Capacidades?

**Output esperado**: Tabla con 15-20 componentes validados (✅/❌/⚠️) + evidencia `file:line`.

---

### 3.3 Sección 2: Validación de Volúmenes de Datos

**Comandos críticos**:

```bash
# 2.1 Contactos (verificar archivo migración o DB actual)
find docs/migrations -name "*.py" -exec grep -H "res.partner\|contact" {} \; | head -20
grep -r "3,929.*contact\|partner" docs/ --include="*.md"

# 2.2 Facturas (CRÍTICO: validar "15-20K facturas" claim agente)
grep -r "invoice.*total\|total.*facturas\|account\.move.*count" docs/migrations/ --include="*.md" --include="*.py"
find docs -name "*volume*.md" -o -name "*dataset*.md" -exec cat {} \;

# 2.3 Scripts migración existentes
ls -lh docs/migrations/odoo11-to-odoo19/*.py
head -50 docs/migrations/odoo11-to-odoo19/verify_full_migration.py

# 2.4 Si hay acceso a DB Odoo 11 producción (IDEAL):
# psql -h <host> -U odoo -d production -c "SELECT COUNT(*) FROM account_invoice WHERE date >= '2020-01-01';"
# Si NO hay acceso: documentar como "VOLUMEN NO VALIDADO - RIESGO ALTO"
```

**Preguntas críticas**:
1. ¿Cuál es el **volumen real de facturas** a migrar? (con evidencia)
2. ¿El claim "15-20K facturas" tiene respaldo? ¿Fuente?
3. ¿Volumen DTEs l10n_cl? ¿Payslips hr.payroll?
4. Si volumen es **50K+ facturas** (no 15-20K), ¿impacto en horas migración?

**Output esperado**: Tabla volúmenes con 3 columnas: `Claim Plan / Evidencia Encontrada / Delta Riesgo`

---

### 3.4 Sección 3: Validación de Testing Strategy

**Comandos exhaustivos**:

```bash
# 3.1 Inventario completo tests
find addons/localization -type d -name "tests" -exec echo "=== {} ===" \; -exec ls -lh {} \;

# 3.2 LOC y cantidad tests por módulo
echo "=== l10n_cl_dte ===" && find addons/localization/l10n_cl_dte/tests -name "*.py" -exec wc -l {} + | tail -1
echo "=== l10n_cl_financial_reports ===" && find addons/localization/l10n_cl_financial_reports/tests -name "*.py" 2>/dev/null -exec wc -l {} + | tail -1
echo "=== l10n_cl_hr_payroll ===" && find addons/localization/l10n_cl_hr_payroll/tests -name "*.py" 2>/dev/null -exec wc -l {} + | tail -1

# 3.3 Tipos de tests (unit/integration/e2e)
grep -r "@tagged\|TransactionCase\|HttpCase\|SingleTransactionCase" addons/localization/l10n_cl_dte/tests/ | wc -l

# 3.4 Cobertura statement (si existe pytest-cov)
find . -name ".coverage" -o -name "coverage.xml" -o -name "htmlcov/"

# 3.5 Tests SII específicos (críticos compliance)
grep -r "test.*sii\|test.*dte.*33\|test.*dte.*56" addons/localization/l10n_cl_dte/tests/ --include="*.py"
```

**Análisis requerido**:
1. **Claim agente**: "196 tests, 8,344 LOC, 72% cobertura" → Validar cada número
2. **Crítica senior**: "72% statement ≠ 45-50% branch" → ¿Evidencia de branch coverage?
3. **Gap identificado**: 0 tests integration E2E SII → ¿Cuántos faltan? (estimación)
4. **Ajuste horas**: Agente +84h vs Senior +120h → ¿Cuál es realista?

**Output esperado**: 
- Tabla con 10-15 archivos test más críticos (path, LOC, tipo, coverage estimado)
- Cálculo ajustado horas testing: `(Total tests requeridos - Tests existentes) × Factor complejidad`

---

### 3.5 Sección 4: Validación de Technical Debt

**Comandos específicos**:

```bash
# 4.1 Confirmar duplicación 11K LOC
find addons/localization/l10n_cl_financial_reports/models/services -name "*.py" -exec wc -l {} + | tail -1

# 4.2 Analizar dependencias account.report
grep -r "from odoo.addons.account_reports\|_inherit.*account\.report" addons/localization/l10n_cl_financial_reports/ --include="*.py"

# 4.3 Buscar comentarios "FIXME", "TODO", "HACK", "XXX" (indicadores technical debt)
grep -rn "FIXME\|TODO.*refactor\|HACK\|XXX" addons/localization/l10n_cl_financial_reports/ --include="*.py" | head -30

# 4.4 Validar si account.report existe en Odoo 19 CE (vs Enterprise)
find addons -name "*account*report*" -type d | grep -v localization
ls -lh addons/account/models/ | grep report
```

**Análisis crítico**:
1. **Agente claim**: "Refactorización NO bloqueante" → ¿Es cierto?
2. **Senior crítica**: "Upgrade Odoo 20 conflicto 75%" → ¿Qué cambia account.report en 20?
3. **Costo real**: ¿80h refactorización ($8K) es realista? ¿Muy bajo? ¿Muy alto?
4. **Decisión arquitectónica**: ¿Refactorizar ahora vs post-MVP? → Análisis riesgo

**Output esperado**: 
- Veredicto: `BLOQUEANTE P0` / `P1 EARLY SPRINT` / `P2 POST-MVP`
- Horas ajustadas: X-Y rango con confianza
- Justificación técnica (400-600 palabras)

---

### 3.6 Sección 5: Validación de Team Capabilities

**Comandos git**:

```bash
# 5.1 Contributors análisis
git log --all --format="%an" | sort | uniq -c | sort -rn | head -20

# 5.2 Commits último año
git log --all --since="2024-01-01" --oneline | wc -l

# 5.3 Bus factor (Gini coefficient aprox.)
git log --all --format="%an" | sort | uniq -c | awk '{print $1}' | sort -rn

# 5.4 Actividad por módulo crítico
git log --all --since="2024-06-01" -- addons/localization/l10n_cl_dte/ | wc -l
git log --all --since="2024-06-01" -- addons/localization/l10n_cl_financial_reports/ | wc -l

# 5.5 Tamaño medio commits (indicador calidad)
git log --all --oneline --shortstat | grep "file changed" | awk '{print $1}' | head -50
```

**Análisis requerido**:
1. **Claim agente**: "Bus factor=1 NO aumenta horas" → ¿Es defendible técnicamente?
2. **Crítica senior**: "Bus factor=1 → +15% overhead = +244h" → ¿Es realista?
3. **Mitigación backup contractor**: ¿$10K suficiente? ¿Onboarding viable?
4. **Documentación calidad**: ¿78 archivos .md son suficientes para mitigar bus factor?

**Fórmula propuesta**:
```
Overhead Bus Factor = Base Hours × Factor Experiencia × Factor Documentación

Factor Experiencia (contributors):
- 1 contributor: 1.20 (20% overhead)
- 2-3 contributors: 1.10 (10% overhead)
- 4+ contributors: 1.00 (sin overhead)

Factor Documentación (calidad docs):
- Excelente (>100 MD, tests 80%+): 0.75× (reduce overhead)
- Buena (50-100 MD, tests 60-80%): 0.90×
- Regular (<50 MD, tests <60%): 1.10× (aumenta overhead)
```

**Output esperado**: 
- Overhead calculado: X% (rango Y-Z)
- Horas ajustadas: +A h (+$B)
- Mitigaciones recomendadas con costo

---

### 3.7 Sección 6: Validación de Rollback Strategy

**Comandos críticos**:

```bash
# 6.1 Scripts backup existentes
find . -name "*backup*.sh" -o -name "*restore*.sh" -o -name "*rollback*.sh" -exec echo "=== {} ===" \; -exec cat {} \;

# 6.2 Docker compose backup strategy
grep -A 10 "backup\|PITR\|pg_dump\|pg_basebackup" docker-compose.yml docker-compose*.yml 2>/dev/null

# 6.3 Scripts migración rollback
find docs/migrations -name "*.py" -exec grep -l "rollback\|revert\|undo" {} \;

# 6.4 Documentación disaster recovery
find docs -name "*backup*" -o -name "*disaster*" -o -name "*recovery*" -o -name "*rollback*" | head -10

# 6.5 PostgreSQL PITR config (si accesible)
# psql -U odoo -d odoo19 -c "SHOW wal_level; SHOW archive_mode; SHOW archive_command;"
```

**Análisis requerido**:
1. **Claim plan**: "Rollback <60min por salto" → ¿Scripts existen y funcionan?
2. **Claim agente**: "+50h rollback" → ¿Incluye drill testing? ¿PITR setup?
3. **Crítica senior**: "Falta PITR, DNS cutover, drill testing" → +30h más = +$3,000
4. **RTO/RPO**: ¿Cuantificados? (Recovery Time/Point Objective)

**Checklist validación**:
- [ ] Scripts `backup.sh` existen y tienen <6 meses antigüedad
- [ ] Script `restore.sh` existe con validación checksums
- [ ] PostgreSQL `wal_level=replica` y `archive_mode=on` configurado
- [ ] Documentación drill testing con evidencia fecha última ejecución
- [ ] Plan DNS cutover (staging ↔ production)
- [ ] Certificados SII staging environment configurados

**Output esperado**:
- Checklist 15-20 items (✅/❌/⚠️)
- Horas ajustadas: +X h (+$Y)
- Plan rollback detallado recomendado (500-800 palabras)

---

### 3.8 Sección 7: Validación de SII Compliance

**Comandos específicos**:

```bash
# 7.1 Validar matriz 180h desglose
cat docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md

# 7.2 Código DTE existente (tipos DTEs)
grep -r "type.*33\|type.*34\|type.*52\|type.*56\|type.*61" addons/localization/l10n_cl_dte/models/ --include="*.py"

# 7.3 Tests compliance SII (críticos regulatorios)
find addons/localization/l10n_cl_dte/tests -name "*.py" -exec grep -l "test.*dte.*33\|test.*dte.*56\|test.*f29\|test.*f22" {} \;

# 7.4 Reportes F29/F22 existentes
find addons/localization -name "*f29*" -o -name "*f22*" -o -name "*sii*report*"
```

**Análisis requerido**:
1. **Matriz SII 180h**: ¿Desglose F29 (98h) + F22 (64h) es realista?
2. **Comparativa Enterprise**: ¿Odoo Enterprise tiene F29/F22 nativos? (evidencia)
3. **Riesgo regulatorio**: ¿Qué pasa si F29 falla certificación SII? (contingencia)
4. **Fase P1 vs P0**: ¿F29 debe ser P0 (bloqueante) vs P1 (post-MVP)?

**Output esperado**:
- Tabla comparativa: `Requisito SII / Odoo Enterprise / CE-Pro Plan / Estado Actual / Gap Real`
- Validación 180h: `Realista` / `Optimista` / `Pesimista` con ajuste
- Priorización ajustada: P0 vs P1 vs P2

---

### 3.9 Sección 8: Validación Financiera

**Análisis requerido**:

```bash
# 8.1 Leer baseline reconciliado
cat docs/upgrade_enterprise_to_odoo19CE/reports/financials_recalc.md

# 8.2 Validar addendum financiero
cat docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/ADDENDUM_FINANCIERO.md
```

**Recalcular ROI con presupuesto ajustado**:

```python
# Fórmula ROI 3 años
scenarios = {
    "Base (30 users)": {
        "enterprise_cost_3y": 67_286,
        "ce_pro_investment": PRESUPUESTO_AUDITADO,  # Tu cálculo
        "ce_pro_maintenance_3y": 28_500,
        "benefits_3y": 182_841,
    },
    "Growth (60 users)": {
        "enterprise_cost_3y": 134_000,
        "ce_pro_investment": PRESUPUESTO_AUDITADO,
        "ce_pro_maintenance_3y": 28_500,
        "benefits_3y": 182_841,
    },
    "Scale (100 users)": {
        "enterprise_cost_3y": 218_400,
        "ce_pro_investment": PRESUPUESTO_AUDITADO,
        "ce_pro_maintenance_3y": 28_500,
        "benefits_3y": 182_841,
    }
}

for scenario, data in scenarios.items():
    roi = ((data["benefits_3y"] - data["ce_pro_investment"] - data["ce_pro_maintenance_3y"]) / 
           data["ce_pro_investment"]) * 100
    print(f"{scenario}: ROI {roi:.1f}%")
```

**Output esperado**:
- Tabla ROI actualizada con **TU presupuesto auditado**
- Análisis sensibilidad: ¿Cuántos usuarios para break-even?
- Veredicto financiero: `Viable` / `Marginal` / `Inviable` por escenario

---

### 3.10 Sección 9: Matriz de Riesgos Ajustada

**Comandos**:

```bash
# 9.1 Leer matriz riesgos existente
find docs/upgrade_enterprise_to_odoo19CE -name "*RIESGO*" -o -name "*RISK*" -exec cat {} \;
```

**Análisis requerido**:
1. Identificar **top 10 riesgos P×I más altos**
2. Validar mitigaciones propuestas son **accionables**
3. Agregar riesgos NO contemplados por plan original

**Tabla esperada**:

| # | Riesgo | P (0-1) | I (1-5) | S=P×I | Mitigación Plan | Mitigación Adicional Requerida | Costo |
|---|--------|---------|---------|-------|-----------------|-------------------------------|-------|
| R01 | Corrupción datos migración | 0.4 | 5 | 2.0 | PITR backups | + Drill test quincenal | +$2K |
| R02 | Bus factor=1 (Pedro) | 0.3 | 4 | 1.2 | Documentación | + Backup contractor 3 meses | +$15K |
| R03 | F29 falla certificación SII | 0.25 | 5 | 1.25 | Tests compliance | + Contador externo validación | +$3K |
| ... | ... | ... | ... | ... | ... | ... | ... |

---

### 3.11 Sección 10: Presupuesto Final Auditado

**Tabla mandatoria** (5 columnas):

| Categoría | Plan Baseline | Agente Validado | Senior Ajustado | **AUDITOR (TU)** | Justificación Auditor |
|-----------|---------------|-----------------|-----------------|------------------|-----------------------|
| Desarrollo Core | $96,400 | $96,400 | $96,400 | **$X** | [Razón] |
| Data Migration | $20,300 | $28,900 | $29,000 | **$X** | [Razón] |
| Testing & QA | $10,100 | $18,500 | $22,100 | **$X** | [Razón] |
| Refactorización (GAP #3) | $0 | $0 | $8,000 | **$X** | [Razón] |
| Bus Factor Overhead (GAP #4) | $0 | $0 | $14,400 | **$X** | [Razón] |
| Rollback Strategy | $0 | $5,000 | $8,000 | **$X** | [Razón] |
| SII Compliance | $17,700 | $17,700 | $17,700 | **$X** | [Razón] |
| Risk Mitigation | $0 | $10,000 | $10,000 | **$X** | [Razón] |
| Contingencia 10% | $12,660 | $16,280 | $19,160 | **$X** | [Razón] |
| **TOTAL** | **$126,600** | **$162,800** | **$191,600** | **$X** | - |

**Criterios ajustes**:
- Ajustes **al alza**: Solo si evidencia concreta demuestra gap
- Ajustes **a la baja**: Si plan sobrestima (ej: código ya existe parcialmente)
- **Rango confianza**: Indicar (ej: $145K-$165K, 75% confidence)

---

### 3.12 Sección 11: Condiciones Mandatorias Ajustadas

**Formato**:

```markdown
## 11.1 Validaciones Pre-GO (Comandos Concretos)

### V1: Validar Volumen Real Facturas
```bash
# Ejecutar en BD Odoo 11 producción:
psql -h <host> -U odoo -d production -c "SELECT COUNT(*) FROM account_invoice WHERE date >= '2020-01-01';"
```
**Criterio**: Si volumen >50K facturas → Re-calcular horas migración (+40h)

### V2: Validar Scripts Backup Funcionan
```bash
./scripts/backup/backup_full.sh
./scripts/backup/restore_test.sh
diff <(pg_dump odoo19_backup) <(pg_dump odoo19_restored) | wc -l
```
**Criterio**: Diff <10 líneas → PASS / Diff >10 → Re-work rollback strategy

[... continuar 10-15 validaciones concretas]
```

---

### 3.13 Sección 12: Recomendaciones Estratégicas

**3 opciones mandatorias**:

#### Opción A: MVP Reducido (Recomendada si presupuesto >$150K)
```markdown
Presupuesto: USD $X
Timeline: Y semanas
Alcance: [Bullet points]
ROI 3 años: Z%
Probabilidad éxito: W%
```

#### Opción B: Go Full (Solo si presupuesto <$160K y score >85)
```markdown
[Misma estructura]
```

#### Opción C: Abort → Renovar Enterprise
```markdown
Costo 3 años Enterprise: $67,286 (30 users)
Trade-offs: [Lista]
Cuándo elegir: [Criterios]
```

---

### 3.14 Sección 13: Calificación del Plan Original

**Tabla scoring** (usar fórmula plan):

| Dimensión | Peso | Score Plan | Score Auditor | Delta | Justificación |
|-----------|------|------------|---------------|-------|---------------|
| Legal/Licencias | 15% | 85 | **X** | ±Y | [Razón] |
| Arquitectura Técnica | 20% | 90 | **X** | ±Y | [Razón] |
| Reporting/Export | 15% | 85 | **X** | ±Y | [Razón] |
| Compliance SII | 15% | 90 | **X** | ±Y | [Razón] |
| Performance | 10% | 80 | **X** | ±Y | [Razón] |
| Riesgos & Mitigación | 10% | 85 | **X** | ±Y | [Razón] |
| Observabilidad | 5% | 80 | **X** | ±Y | [Razón] |
| Migración Datos | 5% | 90 | **X** | ±Y | [Razón] |
| UI/UX Phoenix | 5% | 80 | **X** | ±Y | [Razón] |
| **TOTAL** | **100%** | **86.0** | **X** | **±Y** | - |

---

### 3.15 Sección 14: Accionables Inmediatos

**14.1 Para Ingeniero Senior (Pedro)**

```bash
# 1. Validar volumen facturas real
psql -U odoo -d odoo11_prod -c "SELECT COUNT(*), MIN(date), MAX(date) FROM account_invoice;"

# 2. Ejecutar tests cobertura branch
pytest addons/localization/l10n_cl_dte/tests/ --cov --cov-branch --cov-report=html

# 3. Revisar scripts backup
./scripts/backup/test_backup_restore.sh 2>&1 | tee /tmp/backup_validation.log

# 4. Estimar refactorización account.report
find addons/localization/l10n_cl_financial_reports -name "*.py" -exec grep -l "account\.report" {} \; | wc -l

# 5. Git log bus factor último año
git log --all --since="2024-01-01" --format="%an" | sort | uniq -c
```

**14.2 Para Comité Ejecutivo**

1. **Decisión Pre-GO**: Aprobar presupuesto $X (vs $126.6K baseline) condicionado a POCs
2. **Validación Usuarios**: Confirmar proyección crecimiento 60+ usuarios en 18-24 meses
3. **Audit Externa**: Contratar auditor legal protocolo clean-room ($5K, 2 semanas)

**14.3 Para Equipo DevOps**

1. **Setup PITR PostgreSQL**: Configurar `wal_level=replica` + `archive_mode=on` (4h trabajo)
2. **Staging SII**: Crear ambiente staging con certificados SII sandbox (8h trabajo)

---

## 🎯 Criterios de Éxito de la Auditoría

Tu auditoría será considerada **exitosa** si cumple:

1. **✅ Objetividad**: Ajustes tanto al alza (+) como a la baja (-) del presupuesto
2. **✅ Evidencia Empírica**: Cada claim respaldado con comando bash + output
3. **✅ Reproducibilidad**: Otro auditor puede ejecutar tus comandos y llegar a mismas conclusiones
4. **✅ Trazabilidad**: 50+ referencias `file:line` a código workspace
5. **✅ Cuantificación**: Presupuesto final con rango confianza (no número único)
6. **✅ Accionabilidad**: 10-15 accionables inmediatos concretos (no genéricos)
7. **✅ Profesionalismo**: Documento 50-100 páginas, tablas bien formateadas, sin typos

**Indicadores de calidad**:
- Comandos bash ejecutados: ≥30
- Tablas de evidencia: ≥15
- Archivos workspace referenciados: ≥40
- Hallazgos críticos nuevos (no en conversación previa): ≥3

---

## ⚖️ Postura Requerida del Auditor

**NO ERES**:
- Abogado defensor del plan (no justificar decisiones previas)
- Fiscal pesimista (no buscar solo problemas)
- Consultor de ventas (no inflar presupuesto artificialmente)

**ERES**:
- **Científico**: Método empírico, evidencia > opinión
- **Ingeniero Senior**: Juicio técnico informado, 10+ años experiencia
- **Auditor Independiente**: Verdad técnica > política/presupuesto
- **Pragmático**: Balance entre rigor y feasibility

**Tono del documento**:
- Profesional pero directo
- Técnico pero comprensible para C-level
- Crítico pero constructivo
- Cuantitativo > cualitativo

---

## 📚 Referencias y Contexto Adicional

### Archivos Críticos a Leer (Orden Recomendado)

1. `docs/upgrade_enterprise_to_odoo19CE/INDEX_PROFESIONAL.md` (mapa completo)
2. `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/MASTER_PLAN_ODOO19_CE_PRO_v2.md` (459 líneas)
3. `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/EXECUTIVE_SUMMARY_v2.md` (370 líneas)
4. `docs/upgrade_enterprise_to_odoo19CE/reports/financials_recalc.md` (277 líneas)
5. `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/MATRIZ_SII_CUMPLIMIENTO.md`
6. `docs/upgrade_enterprise_to_odoo19CE/04_Artefactos_Mejora/MIGRACION_MULTI_VERSION_PLAN.md`

### Glosario Técnico

| Término | Definición |
|---------|-----------|
| **Phoenix** | Framework UI/UX CE-Pro inspirado Enterprise (OWL 2 + SCSS) |
| **Quantum** | Motor reporting drill-down 7 niveles + compliance SII |
| **GAP #N** | Brecha identificada en plan original (5 gaps totales) |
| **Bus Factor** | Riesgo si contributor clave abandona proyecto |
| **PITR** | Point-In-Time Recovery (backup continuo PostgreSQL) |
| **RTO/RPO** | Recovery Time/Point Objective (SLA disaster recovery) |
| **F29/F22** | Formularios SII Chile (IVA mensual / Renta anual) |
| **DTE** | Documento Tributario Electrónico (factura electrónica Chile) |
| **OWL 2** | Odoo Web Library v2 (framework componentes JavaScript) |
| **OEEL-1** | Odoo Enterprise Edition License v1.0 (riesgo infracción) |

---

## 🚀 Entrega Final

### Archivo Output

**Nombre**: `AUDITORIA_PROFUNDA_PLAN_ENTERPRISE_CE_2025-11-09.md`  
**Ubicación**: `/Users/pedro/Documents/odoo19/`  
**Formato**: Markdown profesional (tablas, headers, código)  
**Tamaño**: 50-100 páginas (~25,000-50,000 palabras)

### Anexos Opcionales (Si Tiempo Disponible)

1. `ANEXO_A_COMANDOS_EJECUTADOS.md` - Lista completa bash commands
2. `ANEXO_B_OUTPUTS_COMPLETOS.txt` - Outputs sin truncar
3. `ANEXO_C_COMPARATIVE_TABLE.xlsx` - Tabla comparativa Excel (plan vs auditor)

### Metadata Final Documento

```yaml
---
title: "Auditoría Profunda Plan Odoo Enterprise→CE Professional"
date: 2025-11-09
auditor: "Senior Technical Auditor (Local Agent)"
project: "EERGYGROUP - Odoo 19 CE-Pro"
classification: "CONFIDENTIAL - Internal Use Only"
version: 1.0.0
workspace: /Users/pedro/Documents/odoo19
baseline_plan: USD $126,600 (1,266h)
audited_budget: USD $X (TBD)
score_plan: 86.0/100
score_auditor: X/100 (TBD)
veredicto: "GO / CONDITIONAL GO / HOLD / NO-GO" (TBD)
confidence: "75-85%" (TBD)
---
```

---

## ✅ Checklist Pre-Entrega

Antes de entregar documento, validar:

- [ ] Executive Summary <500 palabras con veredicto claro
- [ ] Todas las 14 secciones mandatorias completadas
- [ ] ≥30 comandos bash ejecutados con outputs documentados
- [ ] ≥15 tablas de evidencia bien formateadas
- [ ] ≥40 referencias `file:line` a workspace
- [ ] Presupuesto final con rango confianza (ej: $140K-$160K, 80%)
- [ ] 3 opciones estratégicas (MVP/Full/Abort) con ROI calculado
- [ ] 10-15 accionables inmediatos concretos
- [ ] Anexo A (comandos reproducibles) incluido
- [ ] Metadata YAML completo
- [ ] 0 typos (pasar spell checker)
- [ ] Markdown válido (lint con markdownlint)
- [ ] Tablas alineadas correctamente
- [ ] No usar lenguaje genérico ("considerar", "evaluar", "mejorar")
- [ ] Cada recomendación es SMART (Specific, Measurable, Achievable, Relevant, Time-bound)

---

## 🔐 Clasificación y Distribución

**Clasificación**: 🔴 **CONFIDENCIAL - SOLO COMITÉ EJECUTIVO**

**Distribución autorizada**:
1. Pedro Troncoso (Senior Engineering Lead)
2. CFO EERGYGROUP
3. CTO EERGYGROUP
4. CEO EERGYGROUP (Executive Summary solamente)
5. Auditor Legal Externo (si aplica)

**NO distribuir a**:
- Equipo desarrollo completo (riesgo filtración presupuesto)
- Stakeholders externos
- Odoo SA (riesgo legal clean-room)

---

## 📞 Soporte y Dudas

Si durante la auditoría encuentras:
- **Código inaccesible**: Documentar como "NO VALIDADO - RIESGO ALTO"
- **Comandos que fallan**: Documentar error + workaround intentado
- **Ambigüedad plan**: Listar 2-3 interpretaciones posibles + tu elección justificada
- **Datos contradictorios**: Crear tabla comparativa + análisis discrepancia

**Principio**: Mejor **documentar incertidumbre** que **asumir sin evidencia**.

---

## 🎯 Inicio de la Auditoría

**Comando inicial**:

```bash
cd /Users/pedro/Documents/odoo19
echo "=== INICIO AUDITORÍA $(date) ===" | tee AUDITORIA_LOG.txt
git log --oneline -10 >> AUDITORIA_LOG.txt
find docs/upgrade_enterprise_to_odoo19CE -name "*.md" | wc -l >> AUDITORIA_LOG.txt
```

**Tiempo estimado**: 4-6 horas (profundidad completa)

**Prioridad secciones** (si tiempo limitado):
1. ✅ Executive Summary (MANDATORIO)
2. ✅ Sección 2: Volumen Datos (CRÍTICO)
3. ✅ Sección 3: Testing Strategy (CRÍTICO)
4. ✅ Sección 10: Presupuesto Final (MANDATORIO)
5. ⚠️ Resto secciones (deseable)

---

**¡Comienza la auditoría! 🚀**

**Recuerda**: Tu objetivo NO es validar o invalidar el plan, sino **descubrir la verdad técnica** con evidencia empírica. Sé implacable con los datos, generoso con el contexto, y profesional en el tono.

---

_Fin del Prompt de Auditoría Profunda_
