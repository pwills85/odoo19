# CHECKLIST VERIFICACIÓN TÉCNICA - NÓMINA CHILENA

Uso: Marcar ✅ al completar cada ítem de verificación.

---

## FASE 1: FIXES CRÍTICOS (P0)

### 1.1 Impuesto Único - Cálculo Dinámico

- [ ] **Crear modelo `hr.tax.bracket`**
  - [ ] Campos: `year`, `bracket_number`, `min_uta`, `max_uta`, `rate`, `rebate_formula`
  - [ ] Constraint: año + tramo único
  - [ ] Método: `get_brackets_for_year(year)`

- [ ] **Migrar tabla hardcoded a registros BD**
  - [ ] Script migración: `data/hr_tax_bracket_data.xml`
  - [ ] Datos 2018-2025 (7 años × 7 tramos = 49 registros)
  - [ ] Validar contra tablas oficiales SII

- [ ] **Refactorizar `_calculate_progressive_tax()`**
  - [ ] Eliminar `TRAMOS` hardcoded
  - [ ] Llamar `hr.tax.bracket.get_brackets_for_year()`
  - [ ] Calcular límites basado en UTA vigente
  - [ ] Test: Verificar valores 2025 vs tabla actual

- [ ] **Tests edge cases**
  - [ ] Test valor exacto en límite tramo (ej. 13.5 UTA)
  - [ ] Test 1 peso sobre límite
  - [ ] Test cambio UTA entre años
  - [ ] Test trabajador zona extrema (rebaja 50%)

**Verificación:**
```bash
# Debe retornar registros, NO hardcoded
>>> self.env['hr.tax.bracket'].search([('year', '=', 2025)])
<hr.tax.bracket(7)>

# Cálculo debe usar UTA
>>> payslip._calculate_progressive_tax(1000000)
# Internamente debe: 1000000 / UTA → tramo → cálculo
```

---

### 1.2 Wizard Exportación Previred

- [ ] **Crear wizard `previred.export.wizard`**
  - [ ] Archivo: `wizards/previred_export_wizard.py`
  - [ ] Vista: `wizards/previred_export_wizard_views.xml`
  - [ ] Botón en `hr.payslip.run` form view

- [ ] **Implementar generación header (10 campos)**
  - [ ] RUT empleador
  - [ ] Nombre empresa
  - [ ] Período (MM/AAAA)
  - [ ] Total trabajadores
  - [ ] Total imponible
  - [ ] ...resto según Circular 1556

- [ ] **Implementar generación línea empleado (105 campos)**
  - [ ] Método: `_generate_employee_line(payslip)`
  - [ ] Campos 1-11: RUT trabajador (ljust 11)
  - [ ] Campos 12-61: Nombre completo (ljust 50)
  - [ ] Campos 62-63: Código AFP (ej. "03")
  - [ ] Campos 64-73: Remuneración imponible
  - [ ] Campos 74-83: Cotización AFP
  - [ ] Campos 84-89: Código ISAPRE/FONASA
  - [ ] Campos 90-99: Cotización salud
  - [ ] Campos 100-109: AFC trabajador
  - [ ] Campos 110-119: AFC empleador
  - [ ] ...resto según especificación

- [ ] **Implementar generación trailer (totales)**
  - [ ] Suma total AFP
  - [ ] Suma total Salud
  - [ ] Suma total AFC
  - [ ] Suma remuneraciones

- [ ] **Validación formato Previred**
  - [ ] Método: `_validate_previred_format(lines)`
  - [ ] Longitud línea exacta (105 campos separados por |)
  - [ ] Tipos de dato correctos (numérico donde corresponde)
  - [ ] RUT con dígito verificador válido
  - [ ] Totales cuadran con suma líneas

- [ ] **Generación archivo descargable**
  - [ ] Método: `action_export_txt()`
  - [ ] Nombre archivo: `PREVIRED_MMAAAA_RUTEMP.txt`
  - [ ] Encoding: ISO-8859-1 (Windows-1252)
  - [ ] Line endings: CRLF (\r\n)

- [ ] **Tests**
  - [ ] Test 1 trabajador (caso simple)
  - [ ] Test 100 trabajadores (caso batch)
  - [ ] Test trabajador con ISAPRE
  - [ ] Test trabajador con cargas familiares
  - [ ] Test validación formato incorrecto

**Verificación:**
```bash
# Wizard debe abrir correctamente
>>> payslip_run.action_export_previred()
# {'type': 'ir.actions.act_window', 'res_model': 'previred.export.wizard', ...}

# Archivo debe tener estructura correcta
# Header: 10 campos
# Líneas: 105 campos cada una
# Trailer: totales
```

**Referencia:** Circular N°1556 Previred - Manual Técnico Archivo TXT

---

### 1.3 Actualizar Topes AFP/Cesantía

- [ ] **Tope AFP: 83.1 UF → 87.8 UF**
  - [ ] Actualizar `models/hr_economic_indicators.py:73`
  - [ ] Cambiar `default=83.1` a `default=87.8`
  - [ ] Actualizar help text con fecha cambio

- [ ] **Tope Cesantía: 120.2 UF → 131.3 UF**
  - [ ] Actualizar `models/hr_salary_rule_aportes_empleador.py:124`
  - [ ] Cambiar `120.2` a `131.3`
  - [ ] Agregar comentario con referencia legal

- [ ] **Script migración datos existentes**
  ```python
  # migrations/19.0.1.1.0/post-migration.py
  def migrate(cr, version):
      # Actualizar indicadores con tope antiguo
      cr.execute("""
          UPDATE hr_economic_indicators
          SET afp_limit = 87.8
          WHERE afp_limit = 83.1
      """)
  ```

- [ ] **Tests regresión**
  - [ ] Test cálculo AFP con sueldo > 83.1 UF
  - [ ] Test cálculo AFP con sueldo > 87.8 UF (debe topar)
  - [ ] Test AFC con sueldo > 131.3 UF

**Verificación:**
```python
# Tope debe ser 87.8 UF
>>> indicators = self.env['hr.economic.indicators'].search([('period', '=', '2025-01-01')])
>>> indicators.afp_limit
87.8

# Cálculo debe aplicar tope correcto
>>> payslip.contract_id.wage = 5000000  # ~140 UF
>>> payslip._calculate_afp()
# Debe calcular sobre 87.8 UF × UF_valor, NO sobre 5.000.000
```

---

### 1.4 Desconfiguar Asignación Familiar

- [ ] **Agregar campos faltantes en `hr.economic.indicators`**
  - [ ] `asignacion_familiar_maternal_a` (Monetary)
  - [ ] `asignacion_familiar_maternal_b` (Monetary)
  - [ ] `asignacion_familiar_maternal_c` (Monetary)
  - [ ] `asignacion_familiar_invalid` (Monetary, valor fijo $45,795)

- [ ] **Refactorizar `_compute_family_allowance_lines()`**
  - [ ] Eliminar hardcoded: `monto_simple = 15268`
  - [ ] Usar: `indicators.asignacion_familiar_amount_a`
  - [ ] Eliminar hardcoded: `monto_maternal = 9606`
  - [ ] Usar: `indicators.asignacion_familiar_maternal_a`
  - [ ] Aplicar para tramos B y C también

- [ ] **Actualizar vista indicadores económicos**
  - [ ] Agregar campos en form view
  - [ ] Agrupar: "Asignación Familiar"
  - [ ] Help text con referencia DFL 150

- [ ] **Migrar valores actuales a indicadores**
  ```xml
  <!-- data/hr_economic_indicators_asig_fam.xml -->
  <record id="indicators_2025_01" model="hr.economic.indicators">
      <field name="asignacion_familiar_amount_a">15268</field>
      <field name="asignacion_familiar_maternal_a">9606</field>
      <field name="asignacion_familiar_invalid">45795</field>
      <!-- ... resto tramos -->
  </record>
  ```

- [ ] **Tests**
  - [ ] Test tramo A con cargas simples
  - [ ] Test tramo B con cargas maternales
  - [ ] Test tramo C con cargas inválidas
  - [ ] Test cambio de montos entre meses (ej. actualización anual)

**Verificación:**
```python
# NO debe haber valores hardcoded en código
>>> grep -r "15268\|9606\|45795" models/hr_salary_rule_asignacion_familiar.py
# (vacío)

# Valores deben venir de indicadores
>>> payslip.indicadores_id.asignacion_familiar_amount_a
15268.0
```

---

## FASE 2: ALTO RIESGO (P0-P1)

### 2.1 Modelo Finiquitos

- [ ] **Crear modelo `hr.payslip.settlement`**
  - [ ] Hereda: `mail.thread`, `mail.activity.mixin`
  - [ ] Campos: employee_id, contract_id, date_start, date_end
  - [ ] Campos: termination_reason (Selection Art. 159-162 CT)
  - [ ] Campos computados: years_worked, indemnizaciones, vacaciones

- [ ] **Implementar cálculo indemnización años servicio**
  ```python
  @api.depends('date_start', 'date_end', 'contract_id.wage')
  def _compute_indemnizacion_años(self):
      years = min((self.date_end - self.date_start).days / 365.25, 11.0)
      self.indemnizacion_años = self.contract_id.wage * years
  ```

- [ ] **Implementar cálculo indemnización aviso previo**
  - [ ] Si causal = Art. 161: 1 mes remuneración
  - [ ] Si causal = Art. 159-160: 0

- [ ] **Implementar cálculo vacaciones proporcionales**
  ```python
  # 15 días hábiles / año = 1.25 días/mes
  meses = self._get_meses_trabajados_año_actual()
  dias_vac = (15 / 12) * meses
  valor_dia = self.contract_id.wage / 30
  self.vacaciones_proporcionales = valor_dia * dias_vac
  ```

- [ ] **Implementar cálculo sueldo proporcional**
  ```python
  dias_trabajados = (self.date_end - self.date_end.replace(day=1)).days + 1
  self.sueldo_proporcional = (self.contract_id.wage / 30) * dias_trabajados
  ```

- [ ] **Wizard asistente finiquito**
  - [ ] Vista: selección empleado, fecha término, causal
  - [ ] Preview: mostrar cálculos antes de confirmar
  - [ ] Botón: "Generar Finiquito"
  - [ ] Genera liquidación especial tipo "settlement"

- [ ] **Integración con contabilidad**
  - [ ] Crear asiento contable finiquito
  - [ ] Provisión indemnizaciones
  - [ ] Cuenta gasto vacaciones

- [ ] **PDF Finiquito (Art. 177 CT)**
  - [ ] Template QWeb
  - [ ] Firmas: trabajador + empleador
  - [ ] Detalle: fecha, causal, montos, totales

- [ ] **Tests**
  - [ ] Test finiquito 1 año trabajado
  - [ ] Test finiquito 11 años (tope)
  - [ ] Test finiquito 15 años (debe topar en 11)
  - [ ] Test finiquito con vacaciones pendientes
  - [ ] Test finiquito Art. 161 (con aviso previo)
  - [ ] Test finiquito Art. 159 (sin aviso previo)

**Verificación:**
```python
# Debe calcular correctamente
>>> settlement = self.env['hr.payslip.settlement'].create({
...     'employee_id': employee.id,
...     'date_start': date(2015, 1, 1),
...     'date_end': date(2025, 11, 6),
...     'termination_reason': '161_1',
... })
>>> settlement.years_worked
10.85
>>> settlement.indemnizacion_años  # ~10.85 meses
# Debe ser wage × 10.85
```

---

### 2.2 Validaciones Adicionales

- [ ] **Gratificación: Validar proporcionalidad**
  ```python
  def _get_meses_trabajados_año(self, contract):
      # Contar meses desde inicio año o inicio contrato
      # Descontar ausencias sin goce
      # Retornar float (ej. 10.5 meses)
  ```

- [ ] **Cargas familiares: Modelo dependientes**
  - [ ] Crear `hr.family.dependent`
  - [ ] Validar edad hijo < 18 (o < 24 si estudiante)
  - [ ] Validar certificado matrícula (Binary field)
  - [ ] Validar certificado discapacidad (para inválidas)

- [ ] **Horas extras: Validar topes legales**
  ```python
  @api.constrains('input_line_ids')
  def _check_overtime_limits(self):
      hex_total = sum(line.amount for line in self.input_line_ids if line.code.startswith('HEX'))
      weeks = (self.date_to - self.date_from).days / 7
      if (hex_total / weeks) > 10:
          raise ValidationError("Excede tope 10 HEX/semana")
  ```

---

## FASE 3: MEJORAS (P2)

### 3.1 Tests Comprehensivos

- [ ] **Tests edge cases impuesto**
  - [ ] `test_tax_exact_bracket_limit.py`
  - [ ] `test_tax_one_peso_over.py`
  - [ ] `test_tax_zona_extrema.py`
  - [ ] `test_tax_uta_change_mid_year.py`

- [ ] **Tests multi-empresa**
  - [ ] `test_payslip_multi_company.py`
  - [ ] Verificar segregación indicadores
  - [ ] Verificar segregación liquidaciones

- [ ] **Tests integración contable**
  - [ ] `test_payslip_accounting_entries.py`
  - [ ] Verificar asientos AFP, Salud, Impuesto
  - [ ] Verificar aportes empleador
  - [ ] Verificar finiquitos

- [ ] **Target: Cobertura 80%+**
  ```bash
  pytest --cov=addons/localization/l10n_cl_hr_payroll --cov-report=html
  ```

---

### 3.2 Audit Trail Mejorado

- [ ] **Agregar campos tracking**
  ```python
  calculation_hash = fields.Char('Hash Cálculo', readonly=True)
  indicators_snapshot = fields.Text('Snapshot Indicadores', readonly=True)
  line_changes_log = fields.Text('Log Cambios', readonly=True)
  ```

- [ ] **Implementar hashing en compute**
  ```python
  import hashlib, json

  def action_compute_sheet(self):
      # ... cálculo ...

      # Snapshot indicadores
      self.indicators_snapshot = json.dumps({
          'uf': self.indicadores_id.uf,
          'utm': self.indicadores_id.utm,
          'uta': self.indicadores_id.uta,
      })

      # Hash
      hash_input = f"{self.total_imponible}|{self.net_wage}"
      self.calculation_hash = hashlib.sha256(hash_input.encode()).hexdigest()
  ```

---

### 3.3 Auto-Update Indicadores

- [ ] **Crear cron job mensual**
  ```xml
  <!-- data/ir_cron_indicators.xml -->
  <record id="cron_update_indicators" model="ir.cron">
      <field name="name">Actualizar Indicadores Económicos</field>
      <field name="model_id" ref="model_hr_economic_indicators"/>
      <field name="code">model.cron_fetch_current_month()</field>
      <field name="interval_number">1</field>
      <field name="interval_type">days</field>
  </record>
  ```

- [ ] **Implementar `cron_fetch_current_month()`**
  - [ ] Llamar AI-Service o scraper Previred
  - [ ] Crear/actualizar registro indicadores
  - [ ] Notificar por email si falla

---

## FASE 4: REFINAMIENTO (P3)

### 4.1 Optimizaciones

- [ ] **Cache tramos impuesto**
  ```python
  from functools import lru_cache

  @lru_cache(maxsize=128)
  def _get_tax_brackets_cached(self, year):
      return self.env['hr.tax.bracket'].search([('year', '=', year)])
  ```

- [ ] **Batch processing lotes**
  ```python
  from odoo.tools.misc import split_every

  for batch in split_every(50, draft_slips):
      batch.action_compute_sheet()
      self._update_progress()
  ```

---

### 4.2 UX Wizards

- [ ] **Wizard generación lote**
  - [ ] Filtros: departamento, tipo contrato
  - [ ] Checkboxes: selección empleados
  - [ ] Preview totales antes de generar

- [ ] **Wizard ajustes masivos**
  - [ ] Actualizar AFP múltiples contratos
  - [ ] Aplicar bono colectivo
  - [ ] Modificar gratificación lote

---

### 4.3 Documentación

- [ ] **Docstrings con fórmulas**
  ```python
  def _calculate_afp(self):
      """
      Calcular AFP (Administradora Fondos Pensiones)

      Normativa:
          DL 3500 Art. 17 - Cotización 10%
          Tope: 87.8 UF (DL 3500 Art. 16)

      Fórmula:
          afp = min(total_imponible, 87.8 × UF) × tasa_afp%

      Returns:
          float: Monto AFP en pesos chilenos
      """
  ```

- [ ] **README con ejemplos uso**
- [ ] **CHANGELOG actualizado**

---

## VALIDACIÓN FINAL

### Pre-Producción Checklist

- [ ] **Tests passing 100%**
  ```bash
  pytest addons/localization/l10n_cl_hr_payroll/tests/
  # Result: ALL PASSED
  ```

- [ ] **Cobertura tests ≥ 80%**
  ```bash
  pytest --cov --cov-report=term-missing
  # Coverage: 82%
  ```

- [ ] **No TODOs críticos**
  ```bash
  grep -r "TODO.*CRITICAL\|FIXME.*URGENT" models/
  # (vacío)
  ```

- [ ] **Lint OK**
  ```bash
  pylint addons/localization/l10n_cl_hr_payroll/models/
  # Score: 9.5/10
  ```

- [ ] **Security audit**
  ```bash
  bandit -r addons/localization/l10n_cl_hr_payroll/
  # No issues found
  ```

- [ ] **Migración datos test → producción**
  - [ ] Backup BD completo
  - [ ] Script migración probado en staging
  - [ ] Rollback plan documentado

- [ ] **Validación con abogado laboral**
  - [ ] Revisar cálculos finiquito
  - [ ] Verificar compliance Art. 162-163 CT
  - [ ] Aprobar templates documentos

- [ ] **Validación con contador**
  - [ ] Revisar asientos contables
  - [ ] Verificar archivo Previred vs declaración
  - [ ] Aprobar informes RRHH

---

## SIGN-OFF

### Fase 1 Completada

- [ ] Dev Lead: ________________________ Fecha: __________
- [ ] QA Lead: _________________________ Fecha: __________
- [ ] Tech Lead: _______________________ Fecha: __________

### Fase 2 Completada

- [ ] Dev Lead: ________________________ Fecha: __________
- [ ] QA Lead: _________________________ Fecha: __________
- [ ] Legal Review: ____________________ Fecha: __________
- [ ] Accounting Review: _______________ Fecha: __________

### Aprobación Producción

- [ ] CTO: _____________________________ Fecha: __________
- [ ] CFO: _____________________________ Fecha: __________
- [ ] Legal Counsel: ___________________ Fecha: __________

---

**Versión:** 1.0
**Última actualización:** 2025-11-06
**Responsable:** Equipo Desarrollo Odoo
