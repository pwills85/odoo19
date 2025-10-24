# 🔍 ANÁLISIS COMPLETO DE BRECHAS - FLUJO NÓMINAS

**Fecha:** 2025-10-23  
**Módulo:** l10n_cl_hr_payroll  
**Objetivo:** Análisis exhaustivo ficha trabajador → reportes legales

---

## 📊 ESTADO ACTUAL

### ✅ IMPLEMENTADO (68%)

1. **Ficha Trabajador** ✅ 90%
   - Datos básicos (hr.employee)
   - RUT validado ✅
   - AFP/ISAPRE configurados ✅
   
2. **Contrato** ✅ 95%
   - hr.contract heredado ✅
   - Campos chilenos (AFP, Salud, APV) ✅
   - Jornada semanal ✅
   - Validaciones ✅

3. **Input SOPA** ✅ 100%
   - hr.payslip.input ✅
   - Códigos (HEX, BONO, etc.) ✅
   - Procesamiento ✅

4. **Categorías Salariales** ✅ 100%
   - 15 categorías SOPA 2025 ✅
   - Base/Imponible/Tributable ✅
   - Descuentos ✅

5. **Totalizadores** ✅ 100%
   - total_imponible ✅
   - total_tributable ✅
   - total_gratificacion_base ✅
   - gross_wage/net_wage ✅

6. **Cálculos** ✅ 90%
   - AFP/Salud/AFC ✅
   - Impuesto Único ✅
   - Horas extras/Bonos ✅

### ❌ FALTANTE (32%)

7. **Estructura Salarial** ❌ 0%
   - hr.payroll.structure
   - No existe modelo

8. **Reglas Salariales** ❌ 0%
   - hr.salary.rule
   - No existen reglas

9. **Generación Batch** ❌ 0%
   - hr.payslip.run
   - No implementado

10. **Reportes PDF** ❌ 0%
    - Liquidación individual
    - Resumen nómina
    - Comprobante pago

11. **Reportes Previred** ❌ 0%
    - Archivo TXT 105 campos
    - Validaciones

12. **Libro Remuneraciones** ❌ 0%
    - Reporte legal mensual
    - Excel F30-1

---

## 🎯 PLAN DE CIERRE DE BRECHAS

### **FASE 1: ESTRUCTURA SALARIAL (4h)**

#### 1.1 Crear modelo hr.payroll.structure
```python
# models/hr_payroll_structure.py
class HrPayrollStructure(models.Model):
    _name = 'hr.payroll.structure'
    _description = 'Estructura Salarial'
    
    name = fields.Char(required=True)
    code = fields.Char(required=True)
    rule_ids = fields.One2many('hr.salary.rule', 'struct_id')
    parent_id = fields.Many2one('hr.payroll.structure')
```

#### 1.2 Crear datos base
```xml
<!-- data/hr_payroll_structure.xml -->
<record id="structure_base_cl" model="hr.payroll.structure">
    <field name="name">Estructura Base Chile</field>
    <field name="code">BASE_CL</field>
</record>
```

---

### **FASE 2: REGLAS SALARIALES (8h)**

#### 2.1 Crear modelo hr.salary.rule
```python
# models/hr_salary_rule.py
class HrSalaryRule(models.Model):
    _name = 'hr.salary.rule'
    _description = 'Regla Salarial'
    
    name = fields.Char(required=True)
    code = fields.Char(required=True)
    sequence = fields.Integer(default=10)
    category_id = fields.Many2one('hr.salary.rule.category')
    struct_id = fields.Many2one('hr.payroll.structure')
    condition = fields.Char(default='True')
    amount_python_compute = fields.Text()
```

#### 2.2 Crear reglas Chile
```xml
<!-- data/hr_salary_rules_cl.xml -->

<!-- HABERES -->
<record id="rule_basic" model="hr.salary.rule">
    <field name="name">Sueldo Base</field>
    <field name="code">BASIC</field>
    <field name="sequence">10</field>
    <field name="category_id" ref="category_base"/>
    <field name="amount_python_compute">result = contract.wage</field>
</record>

<record id="rule_hex50" model="hr.salary.rule">
    <field name="name">Horas Extras 50%</field>
    <field name="code">HEX50</field>
    <field name="sequence">20</field>
    <field name="category_id" ref="category_hex_sopa"/>
    <field name="condition">inputs.HEX50</field>
    <field name="amount_python_compute">
hourly_rate = (contract.wage * 12) / (52 * (contract.jornada_semanal or 45))
result = hourly_rate * 1.5 * inputs.HEX50.amount
    </field>
</record>

<!-- DESCUENTOS -->
<record id="rule_afp" model="hr.salary.rule">
    <field name="name">AFP</field>
    <field name="code">AFP</field>
    <field name="sequence">100</field>
    <field name="category_id" ref="category_desc_legal"/>
    <field name="amount_python_compute">
tope_uf = payslip.indicadores_id.uf * 87.8
base = min(payslip.total_imponible, tope_uf)
result = -(base * (contract.afp_rate / 100))
    </field>
</record>

<record id="rule_health" model="hr.salary.rule">
    <field name="name">Salud</field>
    <field name="code">HEALTH</field>
    <field name="sequence">110</field>
    <field name="category_id" ref="category_desc_legal"/>
    <field name="amount_python_compute">
if contract.health_system == 'fonasa':
    result = -(payslip.total_imponible * 0.07)
else:
    plan_clp = contract.isapre_plan_uf * payslip.indicadores_id.uf
    legal_7pct = payslip.total_imponible * 0.07
    result = -max(plan_clp, legal_7pct)
    </field>
</record>

<record id="rule_afc" model="hr.salary.rule">
    <field name="name">AFC</field>
    <field name="code">AFC</field>
    <field name="sequence">115</field>
    <field name="category_id" ref="category_desc_legal"/>
    <field name="amount_python_compute">
tope_uf = payslip.indicadores_id.uf * 120.2
base = min(payslip.total_imponible, tope_uf)
result = -(base * 0.006)
    </field>
</record>

<record id="rule_tax" model="hr.salary.rule">
    <field name="name">Impuesto Único</field>
    <field name="code">TAX</field>
    <field name="sequence">120</field>
    <field name="category_id" ref="category_desc_legal"/>
    <field name="amount_python_compute">
# Llamar método del payslip
result = -payslip._calculate_progressive_tax(payslip.total_tributable)
    </field>
</record>
```

---

### **FASE 3: GENERACIÓN BATCH (6h)**

#### 3.1 Crear hr.payslip.run
```python
# models/hr_payslip_run.py
class HrPayslipRun(models.Model):
    _name = 'hr.payslip.run'
    _description = 'Lote de Nóminas'
    
    name = fields.Char(required=True)
    date_start = fields.Date(required=True)
    date_end = fields.Date(required=True)
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('processing', 'Procesando'),
        ('done', 'Hecho'),
        ('cancel', 'Cancelado')
    ], default='draft')
    slip_ids = fields.One2many('hr.payslip', 'payslip_run_id')
    
    def action_generate_payslips(self):
        """Generar liquidaciones para todos los empleados activos"""
        employees = self.env['hr.employee'].search([
            ('active', '=', True)
        ])
        
        for employee in employees:
            contract = employee.contract_id
            if not contract or contract.state != 'open':
                continue
            
            # Crear liquidación
            self.env['hr.payslip'].create({
                'employee_id': employee.id,
                'contract_id': contract.id,
                'date_from': self.date_start,
                'date_to': self.date_end,
                'payslip_run_id': self.id,
                'name': f"{employee.name} - {self.name}",
            })
        
        self.state = 'processing'
    
    def action_compute_all(self):
        """Calcular todas las liquidaciones del lote"""
        for slip in self.slip_ids:
            slip.action_compute_sheet()
        
        self.state = 'done'
```

---

### **FASE 4: REPORTES PDF (8h)**

#### 4.1 Liquidación Individual
```xml
<!-- reports/report_payslip.xml -->
<template id="report_payslip_document">
    <t t-call="web.external_layout">
        <div class="page">
            <h2>Liquidación de Sueldo</h2>
            
            <!-- Header -->
            <div class="row">
                <div class="col-6">
                    <strong>Trabajador:</strong> <span t-field="o.employee_id.name"/><br/>
                    <strong>RUT:</strong> <span t-field="o.employee_id.identification_id"/><br/>
                </div>
                <div class="col-6">
                    <strong>Período:</strong> 
                    <span t-field="o.date_from"/> - <span t-field="o.date_to"/><br/>
                    <strong>Fecha Pago:</strong> <span t-field="o.date_to"/><br/>
                </div>
            </div>
            
            <!-- Haberes -->
            <h3>HABERES</h3>
            <table class="table table-sm">
                <tr t-foreach="o.line_ids.filtered(lambda l: l.total > 0)" t-as="line">
                    <td><span t-field="line.name"/></td>
                    <td class="text-right">
                        <span t-field="line.total" 
                              t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                    </td>
                </tr>
                <tr class="font-weight-bold">
                    <td>TOTAL HABERES</td>
                    <td class="text-right">
                        <span t-field="o.gross_wage"
                              t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                    </td>
                </tr>
            </table>
            
            <!-- Descuentos -->
            <h3>DESCUENTOS</h3>
            <table class="table table-sm">
                <tr t-foreach="o.line_ids.filtered(lambda l: l.total < 0)" t-as="line">
                    <td><span t-field="line.name"/></td>
                    <td class="text-right">
                        <span t-esc="abs(line.total)" 
                              t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                    </td>
                </tr>
            </table>
            
            <!-- Totales -->
            <div class="row mt-4">
                <div class="col-6 offset-6">
                    <table class="table">
                        <tr>
                            <td><strong>Total Imponible:</strong></td>
                            <td class="text-right">
                                <span t-field="o.total_imponible"
                                      t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                            </td>
                        </tr>
                        <tr>
                            <td><strong>Total Tributable:</strong></td>
                            <td class="text-right">
                                <span t-field="o.total_tributable"
                                      t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                            </td>
                        </tr>
                        <tr class="border-top">
                            <td><h4>LÍQUIDO A PAGAR:</h4></td>
                            <td class="text-right">
                                <h4>
                                    <span t-field="o.net_wage"
                                          t-options='{"widget": "monetary", "display_currency": o.company_id.currency_id}'/>
                                </h4>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
    </t>
</template>

<record id="action_report_payslip" model="ir.actions.report">
    <field name="name">Liquidación de Sueldo</field>
    <field name="model">hr.payslip</field>
    <field name="report_type">qweb-pdf</field>
    <field name="report_name">l10n_cl_hr_payroll.report_payslip_document</field>
    <field name="binding_model_id" ref="model_hr_payslip"/>
    <field name="binding_type">report</field>
</record>
```

---

### **FASE 5: PREVIRED (12h)**

#### 5.1 Wizard Exportación
```python
# wizards/previred_export_wizard.py
class PreviredExportWizard(models.TransientModel):
    _name = 'previred.export.wizard'
    _description = 'Exportar Previred'
    
    year = fields.Integer(required=True, default=lambda self: fields.Date.today().year)
    month = fields.Integer(required=True, default=lambda self: fields.Date.today().month)
    payslip_run_id = fields.Many2one('hr.payslip.run')
    file_data = fields.Binary('Archivo Previred', readonly=True)
    file_name = fields.Char(readonly=True)
    
    def action_generate_file(self):
        """Generar archivo TXT Previred 105 campos"""
        payslips = self._get_payslips()
        
        lines = []
        
        # Línea 1: Empleador
        lines.append(self._format_employer_line())
        
        # Líneas 2-N: Trabajadores
        for slip in payslips:
            lines.append(self._format_employee_line(slip))
        
        # Unir con salto de línea
        content = '\r\n'.join(lines)
        
        # Codificar
        file_data = base64.b64encode(content.encode('windows-1252'))
        
        # Guardar
        self.write({
            'file_data': file_data,
            'file_name': f'previred_{self.year}_{self.month:02d}.txt'
        })
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': self._name,
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }
    
    def _format_employee_line(self, slip):
        """
        Formatear línea trabajador (105 campos)
        
        Campos principales:
        1. RUT trabajador
        2. DV
        3. Apellido paterno
        4. Apellido materno
        5. Nombres
        ...
        95. Remuneración imponible AFP
        96. Remuneración imponible IPS
        97. Remuneración imponible Salud
        ...
        """
        emp = slip.employee_id
        contract = slip.contract_id
        
        # Parsear RUT
        rut_parts = emp.identification_id.split('-')
        rut_num = rut_parts[0].replace('.', '')
        rut_dv = rut_parts[1] if len(rut_parts) > 1 else ''
        
        # Nombres
        names = emp.name.split(' ')
        apellido_p = names[0] if len(names) > 0 else ''
        apellido_m = names[1] if len(names) > 1 else ''
        nombres = ' '.join(names[2:]) if len(names) > 2 else ''
        
        # Construir campos (105 total)
        fields = [
            rut_num.zfill(10),              # 1. RUT
            rut_dv.upper(),                  # 2. DV
            apellido_p[:30].ljust(30),      # 3. Apellido paterno
            apellido_m[:30].ljust(30),      # 4. Apellido materno
            nombres[:30].ljust(30),         # 5. Nombres
            # ... (continuar con 100 campos más)
            str(int(slip.total_imponible)).zfill(10),  # 95. Imponible AFP
            str(int(slip.total_imponible)).zfill(10),  # 96. Imponible IPS
            str(int(slip.total_imponible)).zfill(10),  # 97. Imponible Salud
            # ...
        ]
        
        return ''.join(fields)
```

---

### **FASE 6: LIBRO REMUNERACIONES (8h)**

#### 6.1 Reporte Excel
```python
# reports/libro_remuneraciones.py
class LibroRemuneraciones(models.AbstractModel):
    _name = 'report.l10n_cl_hr_payroll.libro_remuneraciones'
    _inherit = 'report.report_xlsx.abstract'
    
    def generate_xlsx_report(self, workbook, data, payslips):
        """Generar libro de remuneraciones en Excel"""
        sheet = workbook.add_worksheet('Libro Remuneraciones')
        
        # Formatos
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#D9E1F2',
            'border': 1
        })
        
        # Headers (columnas F30-1)
        headers = [
            'RUT', 'Nombre', 'Cargo',
            'Días Trabajados', 'Sueldo Base',
            'Horas Extras', 'Bonos',
            'Total Haberes', 'AFP', 'Salud',
            'AFC', 'Impuesto', 'Total Descuentos',
            'Líquido a Pagar'
        ]
        
        # Escribir headers
        for col, header in enumerate(headers):
            sheet.write(0, col, header, header_format)
        
        # Escribir datos
        row = 1
        for slip in payslips:
            sheet.write(row, 0, slip.employee_id.identification_id)
            sheet.write(row, 1, slip.employee_id.name)
            sheet.write(row, 2, slip.employee_id.job_id.name or '')
            sheet.write(row, 3, slip.worked_days_line_ids[0].number_of_days if slip.worked_days_line_ids else 30)
            sheet.write(row, 4, slip.contract_id.wage)
            # ... continuar con todos los campos
            sheet.write(row, 13, slip.net_wage)
            row += 1
        
        # Totales
        sheet.write(row, 3, 'TOTALES', header_format)
        for col in range(4, 14):
            formula = f'=SUM({chr(65+col)}2:{chr(65+col)}{row})'
            sheet.write(row, col, formula, header_format)
```

---

## 📋 CHECKLIST DE IMPLEMENTACIÓN

### ✅ FASE 1: Estructura Salarial (4h)
- [ ] Crear modelo hr.payroll.structure
- [ ] Crear vista form/tree
- [ ] Crear datos base Chile
- [ ] Tests unitarios

### ✅ FASE 2: Reglas Salariales (8h)
- [ ] Crear modelo hr.salary.rule
- [ ] Crear 15 reglas base Chile
- [ ] Integrar con hr.payslip
- [ ] Tests cálculo reglas

### ✅ FASE 3: Generación Batch (6h)
- [ ] Crear modelo hr.payslip.run
- [ ] Wizard generación masiva
- [ ] Vista kanban/list
- [ ] Tests batch

### ✅ FASE 4: Reportes PDF (8h)
- [ ] Template liquidación individual
- [ ] Template resumen nómina
- [ ] Comprobante pago
- [ ] Tests PDF

### ✅ FASE 5: Previred (12h)
- [ ] Wizard exportación
- [ ] Formateo 105 campos
- [ ] Validaciones SII
- [ ] Tests archivo TXT

### ✅ FASE 6: Libro Remuneraciones (8h)
- [ ] Reporte Excel
- [ ] Formato F30-1
- [ ] Totales y resúmenes
- [ ] Tests Excel

---

## ⏱️ TIEMPO TOTAL ESTIMADO

| Fase | Horas | Complejidad |
|------|-------|-------------|
| Fase 1 | 4h | Media |
| Fase 2 | 8h | Alta |
| Fase 3 | 6h | Media |
| Fase 4 | 8h | Media |
| Fase 5 | 12h | Alta |
| Fase 6 | 8h | Media |
| **TOTAL** | **46h** | **5-6 días** |

---

## 🎯 PRIORIZACIÓN

### 🔴 CRÍTICO (32h)
1. Reglas Salariales (8h)
2. Estructura Salarial (4h)
3. Generación Batch (6h)
4. Reportes PDF (8h)
5. Previred (12h) - **Obligatorio legal**

### 🟡 IMPORTANTE (8h)
6. Libro Remuneraciones (8h) - **Obligatorio legal**

### 🟢 OPCIONAL (6h)
7. Mejoras UI/UX
8. Reportes adicionales

---

## 📊 PROGRESO ESPERADO

| Hito | Progreso | Estado |
|------|----------|--------|
| Ahora | 68% | ✅ Sprint 3.2 |
| +Fase 1-2 | 78% | Estructura + Reglas |
| +Fase 3-4 | 88% | Batch + PDF |
| +Fase 5-6 | **100%** | Previred + Libro |

---

**Próximo paso:** Comenzar con Fase 1 (Estructura Salarial)
