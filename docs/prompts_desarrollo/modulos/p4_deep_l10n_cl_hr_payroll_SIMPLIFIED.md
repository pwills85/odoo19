# Auditoría Arquitectónica P4-Deep: Módulo l10n_cl_hr_payroll

**OBJETIVO:** Analizar arquitectura completa del módulo de Nóminas Chilenas (Payroll) en Odoo 19 CE.

**OUTPUT REQUERIDO:**
- 1,200-1,500 palabras (máximo 1,500)
- ≥30 referencias a código (`archivo.py:línea`)
- ≥6 verificaciones reproducibles (comandos shell)
- 10 dimensiones (A-J) analizadas
- Prioridades P0/P1/P2 clasificadas

---

## ESTRUCTURA OBLIGATORIA

### PASO 1: RESUMEN EJECUTIVO (100-150 palabras)

- Propósito del módulo l10n_cl_hr_payroll
- Arquitectura general (cálculos, indicadores económicos, Previred)
- 3 hallazgos críticos principales
- Score de salud: X/10

### PASO 2: ANÁLISIS POR DIMENSIONES (800-1,000 palabras)

#### A) Arquitectura y Patrones de Diseño
Referencias `archivo.py:línea` obligatorias

#### B) Integraciones y Dependencias
- Banco Central Chile API (UF/UTM/IPC)
- Previred export
- Odoo modules (hr, hr_holidays, account)

#### C) Seguridad y Compliance
- Código del Trabajo compliance
- Ley 21.735 (Reforma Pensional 2025)
- Protección datos personales

#### D) Testing y Calidad
Cobertura tests, gaps críticos

#### E) Performance y Escalabilidad
Cálculos batch 1000+ empleados

#### F) Observabilidad y Debugging
Logging cálculos, error handling

#### G) Deployment y DevOps
Strategy deployment, rollback

#### H) Documentación y Mantenibilidad
Docstrings, complejidad

#### I) CVEs y Dependencias Vulnerables
Versiones requests, python-dotenv

#### J) Roadmap y Deuda Técnica
Prioridades mejora

### PASO 3: VERIFICACIONES REPRODUCIBLES (≥6 comandos)

Formato:
```
### Verificación V1: [Título] (P0/P1/P2)

**Comando:**
```bash
[comando shell]
```

**Hallazgo esperado:** [...]
**Problema si falla:** [...]
**Cómo corregir:** [...]
```

Incluir:
- 2 P0 (compliance Código del Trabajo, cálculos correctos)
- 2 P1 (performance, testing)
- 2 P2 (calidad, documentación)

### PASO 4: RECOMENDACIONES PRIORIZADAS (300-400 palabras)

Tabla + detalles con código ANTES/DESPUÉS

---

## CONTEXTO DEL MÓDULO

**Ubicación:** `addons/localization/l10n_cl_hr_payroll/`

**Métricas:**
- 19 modelos Python (~4,200 LOC)
- Modelo principal: `hr_payslip.py` (980 LOC)
- Tests: 25+ (coverage ~65%)
- Reglas salariales: 35+ (AFP, ISAPRE, impuesto único)

**Arquitectura:**
```
l10n_cl_hr_payroll/
├── models/
│   ├── hr_payslip.py (980 LOC - core)
│   ├── hr_salary_rule.py (450 LOC - reglas)
│   ├── hr_economic_indicators.py (320 LOC - UF/UTM/IPC)
│   └── hr_payroll_afp.py, hr_payroll_isapre.py
├── wizards/
│   └── previred_export.py (formato 105 campos)
├── data/
│   ├── salary_rules/ (35+ XML)
│   └── afp_isapre_data.xml
└── tests/
```

**Cálculos críticos:**
1. **AFP:** 10% sobre imponible (max 90.3 UF)
2. **ISAPRE:** 7% mínimo sobre imponible (max 90.3 UF)
3. **Impuesto único:** 7 tramos progresivos (0%, 4%, 8%, 13.5%, 23%, 30.4%, 35%)
4. **Gratificación:** 25% sobresueldo anual (max 4.75 IMM)
5. **Reforma 2025:** Aporte empleador 0.5% → 3% progresivo

**Integraciones:**
- Banco Central Chile API (indicadores diarios)
- Previred TXT export (105 campos)
- Odoo hr_holidays (ausencias)

---

## REGLAS CRÍTICAS

1. File refs obligatorios: `archivo.py:línea`
2. Comandos verificables
3. Prioridades P0/P1/P2 justificadas
4. No inventes: `[NO VERIFICADO]` si no puedes confirmar
5. Cuantifica: LOC, coverage %, performance ms

---

## EJEMPLO HALLAZGO BIEN DOCUMENTADO

❌ **MAL:** "Hay problemas en el cálculo de AFP"

✅ **BIEN:**
"**Cálculo AFP sin validar tope 90.3 UF** (`hr_payslip.py:345`)

```python
# hr_payslip.py:345
afp_amount = self.total_imponible * 0.10  # ❌ No valida tope
```

**Verificación:**
```bash
grep -n "total_imponible \* 0.10" addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
```

**Impacto:** P0 - Cálculo incorrecto, multa SII
**Solución:**
```python
tope_uf = self.env['hr.economic.indicators'].get_latest('UF') * 90.3
imponible_afp = min(self.total_imponible, tope_uf)
afp_amount = imponible_afp * 0.10
```

**Referencia:** Art. 17 DL 3.500 (Ley AFP)"

---

**COMIENZA ANÁLISIS. MAX 1,500 PALABRAS.**
