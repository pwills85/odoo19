# DASHBOARD - GAPS NÓMINA CHILE 2025
## l10n_cl_hr_payroll - Estado de Cumplimiento

**Última Actualización:** 2025-11-08
**Próxima Revisión:** 2025-11-15

---

## 📊 MÉTRICAS GLOBALES

```
╔═══════════════════════════════════════════════════════════╗
║  ESTADO GENERAL MÓDULO: 75% COMPLETO                      ║
║  GAPS CRÍTICOS (P0): 3 gaps - 26 horas                    ║
║  RIESGO LEGAL: 🔴 ALTO                                     ║
║  DEADLINE CRÍTICO: 2025-01-15 (38 días)                   ║
╚═══════════════════════════════════════════════════════════╝
```

### Distribución Esfuerzo

```
Total: 41 horas (~2 semanas)

P0 (CRÍTICO) ████████████████████████░░░░░░  26h (63%)
P1 (ALTO)    ████████████░░░░░░░░░░░░░░░░░░  12h (29%)
P2 (BAJO)    ███░░░░░░░░░░░░░░░░░░░░░░░░░░░   3h  (8%)
```

### Compliance por Feature

```
Reforma 2025       [██░░░░░░░░] 20%  🔴 CRÍTICO
Previred Export    [░░░░░░░░░░]  0%  🔴 CRÍTICO
Tope AFP 87.8 UF   [██████░░░░] 60%  🟠 ALTO
LRE 105 Campos     [███░░░░░░░] 28%  🟠 ALTO
Indicadores Econ.  [█████████░] 90%  🟢 BAJO
```

---

## 🚨 ALERTAS CRÍTICAS

### ALERTA 1: REFORMA PREVISIONAL 2025
```
⚠️ URGENTE - VIGENCIA: 2025-01-01 (en 54 días)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Falta implementar: Cotización adicional 1% empleador
  • 0.1% → Cuenta Individual
  • 0.9% → SSP/FAPP

IMPACTO:
  ✗ Multas SII: 20 UTM/trabajador (~$1.200.000)
  ✗ Previred rechaza declaración
  ✗ Incumplimiento Ley 21.XXX

ACCIÓN: Iniciar desarrollo INMEDIATAMENTE
```

### ALERTA 2: PREVIRED EXPORT NO FUNCIONA
```
🔴 BLOQUEANTE - ERROR EN PRODUCCIÓN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Botón "Exportar Previred" arroja error:
  ValueError: Model 'previred.export.wizard' does not exist

IMPACTO:
  ✗ Imposible declarar mensualmente
  ✗ Multa 2 UTM/día atraso (~$120.000/día)
  ✗ Trabajadores sin cobertura previsional

ACCIÓN: Crear wizard URGENTE
```

### ALERTA 3: TOPE AFP INCONSISTENTE
```
🟠 ALTA - CÁLCULOS INCORRECTOS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Valor oficial 2025: 87.8 UF
Implementado:       83.1 UF (XML) vs 87.8 UF (hardcoded)

IMPACTO:
  ✗ Descuentos AFP erróneos
  ✗ Base imponible SIS/AFC incorrecta
  ✗ Previred rechaza por topes

ACCIÓN: Corregir y eliminar hardcoding
```

---

## 📋 DETALLES POR GAP

### GAP-001: REFORMA PREVISIONAL 2025

| Atributo | Valor |
|----------|-------|
| **Estado** | ⚠️ 20% implementado |
| **Gap** | 80% faltante |
| **Esfuerzo** | 10 horas |
| **Prioridad** | P0 - CRÍTICO |
| **Deadline** | 2025-01-15 |
| **Riesgo Multa** | $1.200.000+ |

**Marco Legal:**
- Ley 21.XXX (agosto 2024)
- Vigencia: enero 2025
- Superintendencia de Pensiones Circular N°2324/2024

**Implementado:**
```python
✅ Modelo aportes empleador existe
✅ Campos SIS, Cesantía, CCAF
✅ Métodos cálculo base
```

**Faltante:**
```python
❌ Campo aporte_reforma_2025_ci (0.1%)
❌ Campo aporte_reforma_2025_ssp (0.9%)
❌ Método _compute_aporte_reforma_2025()
❌ Método _get_tasa_reforma_2025(year)
❌ Reglas salariales XML
❌ Vista formulario liquidación
❌ Integración LRE/Previred
❌ Tests unitarios
```

**Archivos Afectados:**
- `models/hr_salary_rule_aportes_empleador.py`
- `data/hr_salary_rules_reforma_2025.xml`
- `wizards/hr_lre_wizard.py`
- `views/hr_payslip_views.xml`
- `tests/test_reforma_2025.py`

**Plan de Acción:**
1. Día 1: Campos + métodos Python (4h)
2. Día 2: Reglas salariales XML + vistas (3h)
3. Día 3: Integración LRE/Previred + tests (3h)

---

### GAP-002: WIZARD EXPORTACIÓN PREVIRED

| Atributo | Valor |
|----------|-------|
| **Estado** | ❌ 0% implementado |
| **Gap** | 100% faltante |
| **Esfuerzo** | 13 horas |
| **Prioridad** | P0 - CRÍTICO |
| **Deadline** | 2025-01-15 |
| **Riesgo Multa** | $120.000/día |

**Marco Legal:**
- Previred - Declaración mensual obligatoria
- Plazo: Día 13 de cada mes
- Formato: TXT 105 campos delimitado ";"

**Problema Actual:**
```python
# models/hr_payslip_run.py línea 358
def action_export_previred(self):
    return {
        'res_model': 'previred.export.wizard',  # ← NO EXISTE
    }

# Error:
# ValueError: Model 'previred.export.wizard' does not exist
```

**Faltante:**
```python
❌ Modelo previred.export.wizard
❌ Vista form wizard
❌ Método _generate_previred_txt()
❌ Método _get_previred_line()
❌ Validación RUT módulo 11
❌ Validación códigos AFP/ISAPRE
❌ Campos previred_code en maestros
❌ Tests integración
```

**Archivos a Crear:**
- `wizards/previred_export_wizard.py` (nuevo)
- `wizards/previred_export_wizard_views.xml` (nuevo)
- `tests/test_previred_export.py` (nuevo)

**Archivos a Modificar:**
- `models/hr_afp.py` (agregar previred_code)
- `models/hr_isapre.py` (agregar previred_code)
- `data/l10n_cl_afp_data.xml` (códigos Previred)
- `data/l10n_cl_isapre_data.xml` (códigos Previred)
- `__manifest__.py` (agregar dependencia stdnum)

**Plan de Acción:**
1. Día 1-2: Modelo wizard + vista (6h)
2. Día 3: Validaciones RUT/códigos (2h)
3. Día 4: Códigos maestros AFP/ISAPRE (2h)
4. Día 5: Tests integración (3h)

---

### GAP-003: TOPE AFP 87.8 UF

| Atributo | Valor |
|----------|-------|
| **Estado** | ⚠️ 60% implementado |
| **Gap** | 40% faltante |
| **Esfuerzo** | 3 horas |
| **Prioridad** | P0 - CRÍTICO |
| **Deadline** | 2025-01-15 |
| **Riesgo Multa** | $500.000+ |

**Marco Legal:**
- Ley 20.255 Art. 17
- Superintendencia de Pensiones 2025
- Valor oficial: **87.8 UF** mensuales

**Inconsistencias Detectadas:**

| Archivo | Línea | Valor Actual | Correcto | Estado |
|---------|-------|--------------|----------|--------|
| `data/l10n_cl_legal_caps_2025.xml` | 52 | 83.1 | 87.8 | ❌ |
| `models/hr_salary_rule_aportes_empleador.py` | 202 | 87.8 (hardcoded) | Dinámico | ⚠️ |
| `models/hr_economic_indicators.py` | 62 | 83.1 (default) | 87.8 | ❌ |
| `models/hr_payslip.py` | 647 | 87.8 (comentario) | Consistente | ⚠️ |

**Solución:**

1. **Actualizar XML:**
```xml
<!-- data/l10n_cl_legal_caps_2025.xml línea 52 -->
<field name="amount">87.8</field>  <!-- Era 83.1 -->
```

2. **Eliminar Hardcoding:**
```python
# models/hr_salary_rule_aportes_empleador.py línea 202
# ❌ ANTES
tope = 87.8 * uf_value

# ✅ DESPUÉS
legal_cap = env['l10n_cl.legal.caps'].get_cap('AFP_IMPONIBLE_CAP', date)
tope = legal_cap[0] * uf_value
```

3. **Tests:**
```python
def test_tope_afp_87_8_uf(self):
    cap = self.env['l10n_cl.legal.caps'].search([
        ('code', '=', 'AFP_IMPONIBLE_CAP'),
        ('valid_from', '<=', '2025-01-01'),
    ])
    self.assertEqual(cap.amount, 87.8)
```

**Plan de Acción:**
1. Actualizar XML (15 min)
2. Eliminar hardcoding (1h)
3. Tests validación (1h)
4. Actualizar comentarios (45 min)

---

### GAP-004: LRE 105 CAMPOS

| Atributo | Valor |
|----------|-------|
| **Estado** | ⚠️ 28% implementado |
| **Gap** | 72% faltante |
| **Esfuerzo** | 12 horas |
| **Prioridad** | P1 - ALTO |
| **Deadline** | 2025-02-28 |
| **Riesgo Multa** | $3.600.000 |

**Marco Legal:**
- Código del Trabajo Art. 62
- Dirección del Trabajo Circular 1/2020
- Obligatorio: empresas ≥5 trabajadores

**Estado Secciones:**

| Sección | Campos | Estado | Gap |
|---------|--------|--------|-----|
| A: Empresa | 10 | ✅ 100% | 0% |
| B: Trabajador | 19 | ✅ 100% | 0% |
| C: Remuneraciones | 15 | ❌ 0% | 100% |
| D: Descuentos Legales | 12 | ❌ 0% | 100% |
| E: Descuentos Voluntarios | 8 | ❌ 0% | 100% |
| F: Haberes No Imponibles | 10 | ❌ 0% | 100% |
| G: Otros Movimientos | 18 | ❌ 0% | 100% |
| H: Aportes Empleador | 13 | ❌ 0% | 100% |
| **TOTAL** | **105** | **28%** | **72%** |

**Implementación Actual:**
```python
# wizards/hr_lre_wizard.py
def _get_csv_header(self):
    # Solo retorna 29 columnas (A + B)
    # Faltan 76 columnas (C-H)
```

**Solución:**

1. **Crear Reglas Salariales (~30 reglas):**
```xml
<record id="rule_remuneracion_variable_1" model="hr.salary.rule">
    <field name="code">VARIABLE_1</field>
    ...
</record>
```

2. **Actualizar Wizard:**
```python
def _get_csv_line(self, payslip):
    data = [
        # A, B (ya implementado)
        # C: Agregar 15 campos
        # D: Agregar 12 campos
        # E: Agregar 8 campos
        # F: Agregar 10 campos
        # G: Agregar 18 campos
        # H: Agregar 13 campos
    ]
    return ';'.join(data)
```

3. **Validaciones DT:**
```python
def _validate_csv_format(self, csv_content):
    for line in csv_content.split('\n')[1:]:
        fields = line.split(';')
        if len(fields) != 105:
            raise ValidationError('Debe tener 105 campos')
```

**Plan de Acción:**
1. Día 1-2: Reglas salariales XML (4h)
2. Día 3-4: Wizard 105 campos (4h)
3. Día 5: Validaciones DT (2h)
4. Día 6-7: Tests + docs (2h)

---

### GAP-005: INDICADORES ECONÓMICOS

| Atributo | Valor |
|----------|-------|
| **Estado** | ✅ 90% implementado |
| **Gap** | 10% faltante |
| **Esfuerzo** | 3 horas |
| **Prioridad** | P2 - BAJO |
| **Deadline** | 2025-06-30 |
| **Riesgo Multa** | $50.000 |

**Implementado:**
- ✅ Modelo hr.economic.indicators
- ✅ Validación período
- ✅ Integración AI-Service
- ✅ Cron job mensual

**Faltante:**
- ⚠️ Default afp_limit = 83.1 (debe ser 87.8)
- ⚠️ Validaciones rangos import manual
- ⚠️ Dashboard gráfico evolución

**Solución Rápida:**
```python
# models/hr_economic_indicators.py línea 62
afp_limit = fields.Float(default=87.8)  # Era 83.1
```

**Plan de Acción:**
1. Corregir default (5 min)
2. Validaciones import (1h)
3. Dashboard gráfico (2h)

---

## 🎯 ROADMAP IMPLEMENTACIÓN

### SPRINT 1: P0 - COMPLIANCE CRÍTICO
**Duración:** 1.5 semanas (26 horas)
**Deadline:** 2025-01-15

```
Semana 1
├─ Lun-Mar: Reforma 2025 (10h)
│  ├─ Campos + métodos (4h)
│  ├─ Reglas XML (3h)
│  └─ Tests (3h)
├─ Mie-Jue: Previred wizard parte 1 (6h)
│  ├─ Modelo + vista (4h)
│  └─ Método export (2h)

Semana 2
├─ Vie-Sab: Previred wizard parte 2 (7h)
│  ├─ Validaciones (2h)
│  ├─ Códigos maestros (2h)
│  └─ Tests (3h)
└─ Dom: Tope AFP 87.8 UF (3h)
   ├─ XML + hardcoding (1.5h)
   └─ Tests (1.5h)
```

**Entregables:**
- ✅ Reforma 2025 calculando 1%
- ✅ Previred exportando archivo
- ✅ Tope AFP corregido a 87.8 UF
- ✅ Suite tests 100% pasando

### SPRINT 2: P1 - LRE COMPLETO
**Duración:** 1 semana (12 horas)
**Deadline:** 2025-02-28

```
Semana 3
├─ Lun-Mar: Reglas salariales (4h)
├─ Mie-Jue: Wizard 105 campos (4h)
└─ Vie-Dom: Validaciones + docs (4h)
```

**Entregables:**
- ✅ LRE 105 campos completo
- ✅ Validaciones DT
- ✅ Portal Mi DT acepta archivo

### SPRINT 3: P2 - MEJORAS UX
**Duración:** 2 días (3 horas)
**Deadline:** 2025-06-30

```
Día 1: Dashboard indicadores (2h)
Día 2: Validaciones import (1h)
```

---

## 📈 TRACKING PROGRESO

### Completado vs Pendiente

```
TOTAL 41 HORAS

Completado     ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0%  (0h)
Sprint 1 (P0)  ████████████████████████░░░░░░  63% (26h)
Sprint 2 (P1)  ████████████░░░░░░░░░░░░░░░░░░  29% (12h)
Sprint 3 (P2)  ███░░░░░░░░░░░░░░░░░░░░░░░░░░░   8%  (3h)
```

### Hitos

- [ ] **2025-11-10:** Kickoff Sprint 1
- [ ] **2025-11-18:** Reforma 2025 completa
- [ ] **2025-11-22:** Previred wizard completo
- [ ] **2025-11-25:** Tope AFP corregido
- [ ] **2025-01-15:** DEPLOY P0 A PRODUCCIÓN ⭐
- [ ] **2025-02-28:** DEPLOY P1 LRE
- [ ] **2025-06-30:** DEPLOY P2 Mejoras

---

## ⚠️ RIESGOS Y MITIGACIONES

### Riesgo 1: Deadline Ajustado (2025-01-15)
**Probabilidad:** 🟠 MEDIA
**Impacto:** 🔴 ALTO

**Mitigación:**
- ✅ Asignar desarrollador senior full-time
- ✅ Daily standups para tracking
- ✅ Buffer 3 días antes del deadline

### Riesgo 2: Tests Incompletos
**Probabilidad:** 🟡 BAJA
**Impacto:** 🟠 ALTO

**Mitigación:**
- ✅ TDD: escribir tests primero
- ✅ Coverage mínimo 90%
- ✅ Smoke tests en staging

### Riesgo 3: Cambios Normativos de Última Hora
**Probabilidad:** 🟡 BAJA
**Impacto:** 🟠 ALTO

**Mitigación:**
- ✅ Monitorear portales oficiales
- ✅ Suscripción alertas SP/SII
- ✅ Arquitectura flexible para cambios

---

## 📞 CONTACTOS

**Equipo Desarrollo:**
- Eergygroup Development Team
- https://www.eergygroup.com

**Stakeholders:**
- Product Owner: [Nombre]
- Tech Lead: [Nombre]
- QA Lead: [Nombre]

**Referencias Legales:**
- Superintendencia de Pensiones: https://www.spensiones.cl
- Dirección del Trabajo: https://www.dt.gob.cl
- Previred: https://www.previred.com

---

## 🔄 HISTORIAL ACTUALIZACIONES

| Fecha | Cambio | Responsable |
|-------|--------|-------------|
| 2025-11-08 | Análisis inicial gaps | Claude Code |
| 2025-11-08 | Creación dashboard | Claude Code |
| ... | ... | ... |

---

**Última Sincronización:** 2025-11-08 15:30 UTC
**Próxima Revisión:** 2025-11-15 10:00 UTC

---

## 📊 MÉTRICAS FINALES

```
╔═══════════════════════════════════════════════════════════╗
║  GAPS TOTALES: 5                                          ║
║  ESFUERZO TOTAL: 41 horas                                 ║
║  CRITICIDAD: 🔴 ALTA                                       ║
║  DEADLINE CRÍTICO: 2025-01-15                             ║
║  RIESGO MULTAS: >$5.000.000                               ║
║  ACCIÓN REQUERIDA: INMEDIATA                              ║
╚═══════════════════════════════════════════════════════════╝
```

**Estado:** 🔴 REQUIERE ACCIÓN INMEDIATA
**Recomendación:** INICIAR SPRINT 1 HOY
