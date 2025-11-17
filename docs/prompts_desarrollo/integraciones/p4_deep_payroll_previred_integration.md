# Auditoría P4-Deep: Integración Payroll ↔ Previred

**Nivel:** P4-Deep (Auditoría Integración)  
**Target:** 1,200-1,500 palabras  
**Objetivo:** Auditar integración entre nóminas chilenas y Previred

---

## 🎯 CONTEXTO INTEGRACIÓN

**Componentes:**
- **l10n_cl_hr_payroll:** Módulo nóminas Odoo (Python 3.11)
- **Previred API/File:** Archivo TXT 105 campos fijos
- **Indicadores económicos:** UF, UTM, IPC, salario mínimo

**Formato Previred:**
- Encoding: ISO-8859-1 (Latin-1)
- Campos: 105 posiciones fijas
- Validación: Checksum Modulo 10
- Frecuencia: Mensual (hasta día 10)

**Cálculos críticos:**
- AFP: 10% sobre imponible (tope 90.3 UF)
- ISAPRE: 7% mínimo sobre imponible
- Impuesto único: Tramos progresivos
- APV: Ahorros voluntarios con tope

---

## 📊 ESTRUCTURA ANÁLISIS

### PASO 1: RESUMEN EJECUTIVO (100-150 palabras)

- Propósito integración Payroll-Previred
- Arquitectura archivo TXT generación
- 3 hallazgos críticos compliance
- Score salud integración: X/10

### PASO 2: ANÁLISIS POR DIMENSIONES (800-1,000 palabras)

#### A) Arquitectura Generación TXT
- 105 campos posiciones fijas
- Encoding ISO-8859-1 handling
- Line endings CRLF

#### B) Validación Datos Previred
- Checksum Modulo 10
- RUT empleado formato correcto
- Montos máximos UF

#### C) Compliance Laboral Chile
- Código del Trabajo Art. 42
- Ley 21.133 (40 horas)
- Circular 1/2018 Previred

#### D) Cálculos Imponibles
- Tope imponible 90.3 UF
- Total imponible vs Total haberes
- Descuentos legales priority

#### E) Performance Generación
- Nóminas >1,000 empleados
- Generación <60s target
- Memory usage archivos grandes

#### F) Testing Archivo Previred
- Tests sintéticos empleados
- Validación checksum
- Formato campos numéricos

#### G) Deployment y Config
- Indicadores económicos auto-sync
- Environment Previred test/prod
- Certificación empresa

#### H) Documentación Compliance
- Logs generación archivo
- Trazabilidad nóminas enviadas
- Respaldos auditoría

#### I) Dependencies Vulnerables
- openpyxl (Excel export)
- pandas (si se usa)
- Bibliotecas cálculo

#### J) Roadmap Previred Future
- API REST Previred (futuro)
- Integración digital certificados
- Nuevos campos Ley 21.578

### PASO 3: VERIFICACIONES (≥6 comandos)

**V1: Wizard generación Previred presente (P0)**
```bash
find addons/localization/l10n_cl_hr_payroll/wizards -name "*previred*" | head -5
```

**V2: Cálculo tope imponible 90.3 UF (P0)**
```bash
grep -rn "90\.3\|tope_imponible\|max_imponible" addons/localization/l10n_cl_hr_payroll/models/ | head -10
```

**V3: Encoding ISO-8859-1 configurado (P1)**
```bash
grep -rn "iso-8859-1\|latin-1\|latin1" addons/localization/l10n_cl_hr_payroll/ | head -5
```

**V4: Checksum Modulo 10 implementado (P0)**
```bash
grep -rn "checksum\|modulo.*10\|mod.*10" addons/localization/l10n_cl_hr_payroll/ | head -10
```

**V5: Indicadores económicos sync (P1)**
```bash
find addons/localization/l10n_cl_hr_payroll/models -name "*indicator*" -o -name "*uf*" | head -5
```

**V6: Tests generación archivo TXT (P1)**
```bash
find addons/localization/l10n_cl_hr_payroll/tests -name "*previred*" -o -name "*txt*" | head -5
```

### PASO 4: RECOMENDACIONES (300-400 palabras)

Tabla + código ANTES/DESPUÉS

---

## 🔍 ARCHIVOS CLAVE

**Payroll module:**
- `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py` (nómina)
- `addons/localization/l10n_cl_hr_payroll/models/hr_economic_indicators.py` (UF/UTM)
- `addons/localization/l10n_cl_hr_payroll/wizards/previred_export.py` (generación TXT)
- `addons/localization/l10n_cl_hr_payroll/libs/previred_validator.py` (checksum)

**Config:**
- `config/odoo.conf` (APIs indicadores)
- `.env` (Previred credentials test)

---

## 📋 MÉTRICAS ESPERADAS

- Palabras: 1,200-1,500
- File refs: ≥30
- Verificaciones: ≥6 comandos
- Dimensiones: 10/10 (A-J)
- Prioridades: P0/P1/P2

---

**COMIENZA ANÁLISIS. MAX 1,500 PALABRAS.**
