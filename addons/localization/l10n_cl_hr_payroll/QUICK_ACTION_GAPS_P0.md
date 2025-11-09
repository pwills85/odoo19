# QUICK ACTION CARD - GAPS P0 CRÍTICOS
## l10n_cl_hr_payroll - Acción Inmediata

**URGENTE:** Cerrar gaps antes de 2025-01-15 (Vigencia Reforma 2025)

---

## 🎯 OBJETIVOS SPRINT P0

✅ Implementar Reforma Previsional 2025 (1% adicional)
✅ Crear Wizard Exportación Previred
✅ Corregir Tope AFP a 87.8 UF

**Esfuerzo Total:** 26 horas (~1.5 semanas)
**Deadline:** 2025-01-15

---

## 🚀 ACCIÓN 1: REFORMA PREVISIONAL 2025 (10h)

### Paso 1: Agregar Campos (2h)

**Archivo:** `models/hr_salary_rule_aportes_empleador.py`

**Agregar después de línea 65:**

```python
# ═══════════════════════════════════════════════════════════
# REFORMA PREVISIONAL 2025
# ═══════════════════════════════════════════════════════════

aporte_reforma_2025_ci = fields.Monetary(
    string='Reforma 2025 - Cuenta Individual (0.1%)',
    currency_field='company_currency_id',
    compute='_compute_aporte_reforma_2025',
    store=True,
    help='Reforma 2025: 0.1% a cuenta individual trabajador'
)

aporte_reforma_2025_ssp = fields.Monetary(
    string='Reforma 2025 - SSP/FAPP (0.9%)',
    currency_field='company_currency_id',
    compute='_compute_aporte_reforma_2025',
    store=True,
    help='Reforma 2025: 0.9% a Seguro Social Previsional / FAPP'
)

aporte_reforma_2025_total = fields.Monetary(
    string='Reforma 2025 - Total (1.0%)',
    currency_field='company_currency_id',
    compute='_compute_aporte_reforma_2025',
    store=True,
    help='Reforma Previsional 2025: suma 0.1% CI + 0.9% SSP/FAPP'
)

@api.depends('total_imponible', 'date_to')
def _compute_aporte_reforma_2025(self):
    """
    Calcular aporte Reforma Previsional 2025

    Ley 21.XXX (agosto 2024)
    2025: 1.0% (0.1% CI + 0.9% SSP)
    2026: 2.0% (0.2% CI + 1.8% SSP)
    ...
    2033: 8.5%
    """
    for payslip in self:
        if not payslip.total_imponible:
            payslip.aporte_reforma_2025_ci = 0.0
            payslip.aporte_reforma_2025_ssp = 0.0
            payslip.aporte_reforma_2025_total = 0.0
            continue

        # Obtener tasa según año
        year = payslip.date_to.year
        tasa_total = self._get_tasa_reforma_2025(year)

        # 10% va a Cuenta Individual, 90% a SSP/FAPP
        tasa_ci = tasa_total * 0.10
        tasa_ssp = tasa_total * 0.90

        # Aplicar tope AFP (87.8 UF)
        tope_afp_clp = payslip._get_tope_afp_clp()
        base_imponible = min(payslip.total_imponible, tope_afp_clp)

        # Calcular aportes
        payslip.aporte_reforma_2025_ci = base_imponible * tasa_ci
        payslip.aporte_reforma_2025_ssp = base_imponible * tasa_ssp
        payslip.aporte_reforma_2025_total = (
            payslip.aporte_reforma_2025_ci +
            payslip.aporte_reforma_2025_ssp
        )

        _logger.debug(
            f"Reforma 2025: CI=${payslip.aporte_reforma_2025_ci:,.0f} "
            f"SSP=${payslip.aporte_reforma_2025_ssp:,.0f} "
            f"(Tasa: {tasa_total*100}%, Base: ${base_imponible:,.0f})"
        )

def _get_tasa_reforma_2025(self, year):
    """
    Obtener tasa Reforma 2025 según año

    Returns:
        float: Tasa decimal (0.01 = 1%)
    """
    tasas = {
        2025: 0.010,  # 1.0%
        2026: 0.020,  # 2.0%
        2027: 0.030,  # 3.0%
        2028: 0.040,  # 4.0%
        2029: 0.050,  # 5.0%
        2030: 0.060,  # 6.0%
        2031: 0.070,  # 7.0%
        2032: 0.080,  # 8.0%
        2033: 0.085,  # 8.5%
    }

    if year < 2025:
        return 0.0  # No aplicable antes de 2025

    return tasas.get(year, 0.085)  # Post-2033 usa 8.5%
```

**Agregar en línea 167 (actualizar total empleador):**

```python
@api.depends('aporte_sis_amount', 'aporte_seguro_cesantia_amount',
             'aporte_ccaf_amount', 'aporte_reforma_2025_total')
def _compute_aporte_empleador_total(self):
    """Calcular total aportes empleador"""
    for payslip in self:
        payslip.aporte_empleador_total = (
            payslip.aporte_sis_amount +
            payslip.aporte_seguro_cesantia_amount +
            payslip.aporte_ccaf_amount +
            payslip.aporte_reforma_2025_total  # ← AGREGAR
        )
```

### Paso 2: Crear Reglas Salariales (2h)

**Crear archivo:** `data/hr_salary_rules_reforma_2025.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <data noupdate="1">

        <!-- ═══════════════════════════════════════════════════════════ -->
        <!-- REFORMA PREVISIONAL 2025 - LEY 21.XXX -->
        <!-- Vigencia: Enero 2025 -->
        <!-- ═══════════════════════════════════════════════════════════ -->

        <!-- Cotización Cuenta Individual 0.1% -->
        <record id="rule_aporte_ci_2025" model="hr.salary.rule">
            <field name="name">Reforma 2025 - Cuenta Individual (0.1%)</field>
            <field name="code">APORTE_CI_2025</field>
            <field name="category_id" ref="category_aporte_empleador"/>
            <field name="sequence">210</field>
            <field name="condition_select">none</field>
            <field name="amount_select">code</field>
            <field name="amount_python_compute">
# Reforma 2025: 0.1% a cuenta individual
result = payslip.aporte_reforma_2025_ci
            </field>
            <field name="active" eval="True"/>
        </record>

        <!-- Cotización SSP/FAPP 0.9% -->
        <record id="rule_aporte_ssp_2025" model="hr.salary.rule">
            <field name="name">Reforma 2025 - SSP/FAPP (0.9%)</field>
            <field name="code">APORTE_SSP_2025</field>
            <field name="category_id" ref="category_aporte_empleador"/>
            <field name="sequence">211</field>
            <field name="condition_select">none</field>
            <field name="amount_select">code</field>
            <field name="amount_python_compute">
# Reforma 2025: 0.9% a Seguro Social Previsional
result = payslip.aporte_reforma_2025_ssp
            </field>
            <field name="active" eval="True"/>
        </record>

        <!-- Total Reforma 2025 -->
        <record id="rule_aporte_reforma_total_2025" model="hr.salary.rule">
            <field name="name">Reforma 2025 - Total (1.0%)</field>
            <field name="code">APORTE_REFORMA_2025</field>
            <field name="category_id" ref="category_aporte_empleador"/>
            <field name="sequence">212</field>
            <field name="condition_select">none</field>
            <field name="amount_select">code</field>
            <field name="amount_python_compute">
# Total Reforma 2025
result = payslip.aporte_reforma_2025_total
            </field>
            <field name="active" eval="True"/>
        </record>

    </data>
</odoo>
```

### Paso 3: Actualizar Vista (1h)

**Archivo:** `views/hr_payslip_views.xml`

**Buscar sección aportes empleador y agregar:**

```xml
<group string="Aportes Empleador - Reforma 2025" col="4">
    <field name="aporte_reforma_2025_ci" widget="monetary"/>
    <field name="aporte_reforma_2025_ssp" widget="monetary"/>
    <field name="aporte_reforma_2025_total" widget="monetary"/>
</group>
```

### Paso 4: Actualizar Manifest (15 min)

**Archivo:** `__manifest__.py`

**Agregar en sección data:**

```python
'data': [
    # ...
    'data/hr_salary_rules_reforma_2025.xml',  # AGREGAR
],
```

### Paso 5: Tests (3h)

**Crear archivo:** `tests/test_reforma_2025.py`

```python
from odoo.tests import tagged
from odoo.tests.common import TransactionCase
from datetime import date

@tagged('post_install', '-at_install', 'payroll_reforma')
class TestReforma2025(TransactionCase):

    def setUp(self):
        super().setUp()

        # Indicadores enero 2025
        self.indicators = self.env['hr.economic.indicators'].create({
            'period': date(2025, 1, 1),
            'uf': 39509.50,
            'utm': 66040,
            'minimum_wage': 500000,
        })

        # Empleado
        self.employee = self.env['hr.employee'].create({
            'name': 'Test Reforma',
        })

        # Contrato
        self.contract = self.env['hr.contract'].create({
            'name': 'Contract Test',
            'employee_id': self.employee.id,
            'wage': 1500000,
            'date_start': date(2025, 1, 1),
        })

    def test_reforma_2025_1_percent(self):
        """Test: 2025 debe calcular 1.0%"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
        })

        payslip._compute_aporte_reforma_2025()

        # 1.0% de $1.500.000 = $15.000
        self.assertEqual(
            payslip.aporte_reforma_2025_total,
            15000,
            "Reforma 2025: debe calcular 1.0% en 2025"
        )

        # 0.1% CI = $1.500
        self.assertEqual(
            payslip.aporte_reforma_2025_ci,
            1500,
            "CI debe ser 0.1%"
        )

        # 0.9% SSP = $13.500
        self.assertEqual(
            payslip.aporte_reforma_2025_ssp,
            13500,
            "SSP debe ser 0.9%"
        )

    def test_reforma_2026_2_percent(self):
        """Test: 2026 debe calcular 2.0%"""
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2026, 1, 1),
            'date_to': date(2026, 1, 31),
        })

        payslip._compute_aporte_reforma_2025()

        # 2.0% de $1.500.000 = $30.000
        self.assertEqual(
            payslip.aporte_reforma_2025_total,
            30000,
            "Reforma 2025: debe calcular 2.0% en 2026"
        )

    def test_reforma_tope_afp(self):
        """Test: Aplicar tope 87.8 UF"""
        # Empleado sobre tope
        contract_high = self.env['hr.contract'].create({
            'name': 'Contract High',
            'employee_id': self.employee.id,
            'wage': 5000000,
            'date_start': date(2025, 1, 1),
        })

        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': contract_high.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
        })

        # Tope = 87.8 UF * $39.509,50 = $3.468.934
        tope_clp = 87.8 * 39509.50
        expected = tope_clp * 0.01  # 1.0%

        payslip._compute_aporte_reforma_2025()

        self.assertAlmostEqual(
            payslip.aporte_reforma_2025_total,
            expected,
            places=0,
            msg="Debe aplicar tope 87.8 UF"
        )
```

### Paso 6: Update Module (15 min)

```bash
docker-compose exec odoo odoo -d odoo19 -u l10n_cl_hr_payroll --stop-after-init
```

---

## 🚀 ACCIÓN 2: WIZARD PREVIRED (13h)

### Paso 1: Crear Modelo Wizard (4h)

**Crear archivo:** `wizards/previred_export_wizard.py`

```python
# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import base64
import logging

_logger = logging.getLogger(__name__)


class PreviredExportWizard(models.TransientModel):
    _name = 'previred.export.wizard'
    _description = 'Exportar Declaración Previred'

    company_id = fields.Many2one(
        'res.company',
        required=True,
        default=lambda self: self.env.company
    )

    payslip_run_id = fields.Many2one(
        'hr.payslip.run',
        string='Lote de Nóminas'
    )

    year = fields.Integer(required=True)
    month = fields.Selection([
        ('1', 'Enero'), ('2', 'Febrero'), ('3', 'Marzo'),
        ('4', 'Abril'), ('5', 'Mayo'), ('6', 'Junio'),
        ('7', 'Julio'), ('8', 'Agosto'), ('9', 'Septiembre'),
        ('10', 'Octubre'), ('11', 'Noviembre'), ('12', 'Diciembre'),
    ], required=True)

    previred_file = fields.Binary(readonly=True, attachment=True)
    previred_filename = fields.Char(readonly=True)

    state = fields.Selection([
        ('draft', 'Borrador'),
        ('done', 'Generado')
    ], default='draft')

    total_payslips = fields.Integer(readonly=True)
    total_employees = fields.Integer(readonly=True)

    def action_generate_previred(self):
        """Generar archivo Previred"""
        self.ensure_one()

        # 1. Obtener liquidaciones
        payslips = self._get_payslips()
        if not payslips:
            raise UserError(_('No hay liquidaciones para el período'))

        # 2. Generar TXT
        txt_content = self._generate_previred_txt(payslips)

        # 3. Validar formato
        self._validate_previred_format(txt_content)

        # 4. Guardar
        filename = 'PREVIRED_%s_%s%s.txt' % (
            self.company_id.vat or 'SINRUT',
            self.year,
            self.month.zfill(2)
        )

        self.write({
            'previred_file': base64.b64encode(
                txt_content.encode('ISO-8859-1')  # Encoding Previred
            ),
            'previred_filename': filename,
            'total_payslips': len(payslips),
            'total_employees': len(payslips.mapped('employee_id')),
            'state': 'done'
        })

        return {
            'type': 'ir.actions.act_window',
            'res_model': 'previred.export.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }

    def _get_payslips(self):
        """Obtener liquidaciones"""
        domain = [
            ('date_from', '>=', '%s-%s-01' % (self.year, self.month.zfill(2))),
            ('state', 'in', ['done', 'verify']),
            ('company_id', '=', self.company_id.id)
        ]

        if self.payslip_run_id:
            domain.append(('payslip_run_id', '=', self.payslip_run_id.id))

        return self.env['hr.payslip'].search(domain)

    def _generate_previred_txt(self, payslips):
        """Generar TXT formato Previred"""
        lines = []

        for payslip in payslips:
            line = self._get_previred_line(payslip)
            lines.append(line)

        return '\n'.join(lines)

    def _get_previred_line(self, payslip):
        """Generar línea Previred (105 campos)"""
        employee = payslip.employee_id
        contract = payslip.contract_id
        company = self.company_id

        # RUT sin formato
        rut_empresa = self._clean_rut(company.vat)
        rut_trabajador = self._clean_rut(employee.identification_id)

        # Período YYYYMM
        periodo = '%s%s' % (self.year, self.month.zfill(2))

        # Extraer valores
        values = {}
        for line in payslip.line_ids:
            values[line.code] = line.total

        def fmt(value):
            return str(int(round(value, 0)))

        # 105 campos (simplificado - completar todos)
        data = [
            rut_empresa,
            periodo,
            rut_trabajador,
            employee.lastname or '',
            employee.mothers_name or '',
            employee.firstname or employee.name or '',
            # ... completar 99 campos más
        ]

        return ';'.join(data)

    def _validate_previred_format(self, content):
        """Validar formato Previred"""
        lines = content.split('\n')

        for idx, line in enumerate(lines, 1):
            fields = line.split(';')

            if len(fields) != 105:
                raise ValidationError(_(
                    'Línea %d: Debe tener 105 campos (tiene %d)'
                ) % (idx, len(fields)))

            # Validar RUT
            rut = fields[2]
            if not self._validate_rut(rut):
                raise ValidationError(_(
                    'Línea %d: RUT inválido %s'
                ) % (idx, rut))

    def _validate_rut(self, rut):
        """Validar RUT chileno"""
        try:
            from stdnum.cl import rut as stdnum_rut
            return stdnum_rut.is_valid(rut)
        except ImportError:
            _logger.warning('stdnum not installed')
            return True

    def _clean_rut(self, rut):
        """Limpiar RUT"""
        if not rut:
            return ''
        return rut.replace('.', '').replace('-', '').upper()
```

### Paso 2: Crear Vista Wizard (1h)

**Crear archivo:** `wizards/previred_export_wizard_views.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>

    <record id="view_previred_export_wizard_form" model="ir.ui.view">
        <field name="name">previred.export.wizard.form</field>
        <field name="model">previred.export.wizard</field>
        <field name="arch" type="xml">
            <form>
                <header>
                    <button name="action_generate_previred"
                            string="Generar Archivo Previred"
                            type="object"
                            class="btn-primary"
                            states="draft"/>
                    <field name="state" widget="statusbar"/>
                </header>
                <sheet>
                    <group>
                        <group>
                            <field name="company_id" readonly="1"/>
                            <field name="payslip_run_id" readonly="1"/>
                        </group>
                        <group>
                            <field name="year"/>
                            <field name="month"/>
                        </group>
                    </group>

                    <group states="done" string="Resultado">
                        <field name="previred_filename" readonly="1"/>
                        <field name="total_payslips" readonly="1"/>
                        <field name="total_employees" readonly="1"/>
                    </group>

                    <div states="done" class="alert alert-success">
                        Archivo Previred generado exitosamente
                    </div>
                </sheet>
                <footer states="done">
                    <button name="action_download_file"
                            string="Descargar Archivo"
                            type="object"
                            class="btn-success"/>
                </footer>
            </form>
        </field>
    </record>

</odoo>
```

### Paso 3: Agregar Códigos Previred a Maestros (2h)

**Archivo:** `models/hr_afp.py`

```python
previred_code = fields.Char(
    string='Código Previred',
    size=2,
    help='Código numérico AFP para Previred (01-35)'
)
```

**Archivo:** `data/l10n_cl_afp_data.xml` (si existe, o crear)

```xml
<record id="afp_capital" model="hr.afp">
    <field name="previred_code">03</field>
</record>

<!-- Agregar códigos para las 10 AFP -->
```

### Paso 4: Actualizar Manifest (15 min)

```python
'data': [
    # ...
    'wizards/previred_export_wizard_views.xml',
],

'external_dependencies': {
    'python': [
        'requests',
        'stdnum',  # AGREGAR
    ],
},
```

### Paso 5: Tests (3h)

Similar a tests LRE, validar generación archivo.

---

## 🚀 ACCIÓN 3: TOPE AFP 87.8 UF (3h)

### Paso 1: Actualizar XML (15 min)

**Archivo:** `data/l10n_cl_legal_caps_2025.xml`

**Línea 52:**

```xml
<!-- CAMBIAR DE: -->
<field name="amount">83.1</field>

<!-- A: -->
<field name="amount">87.8</field>
```

### Paso 2: Eliminar Hardcoding (1h)

**Archivo:** `models/hr_salary_rule_aportes_empleador.py`

**Línea 202, cambiar:**

```python
# ❌ ANTES
tope = 87.8 * uf_value

# ✅ DESPUÉS
legal_cap = self.env['l10n_cl.legal.caps'].search([
    ('code', '=', 'AFP_IMPONIBLE_CAP'),
    ('valid_from', '<=', self.date_to),
    '|',
    ('valid_until', '=', False),
    ('valid_until', '>', self.date_to)
], limit=1)

if not legal_cap:
    raise UserError(_(
        'No se encontró tope AFP vigente para %s'
    ) % self.date_to)

tope = legal_cap.amount * uf_value
```

### Paso 3: Actualizar Default Indicadores (5 min)

**Archivo:** `models/hr_economic_indicators.py`

**Línea 62:**

```python
default=87.8,  # Era 83.1
```

### Paso 4: Tests (1h)

```python
def test_tope_afp_87_8_uf(self):
    cap = self.env['l10n_cl.legal.caps'].search([
        ('code', '=', 'AFP_IMPONIBLE_CAP'),
        ('valid_from', '<=', '2025-01-01'),
    ])
    self.assertEqual(cap.amount, 87.8)
```

---

## ✅ CHECKLIST FINAL

### Pre-Deploy

- [ ] Reforma 2025 campos creados
- [ ] Reforma 2025 reglas salariales XML
- [ ] Reforma 2025 vista actualizada
- [ ] Reforma 2025 tests pasando
- [ ] Wizard Previred modelo creado
- [ ] Wizard Previred vista creada
- [ ] Códigos Previred en maestros AFP/ISAPRE
- [ ] Tope AFP = 87.8 UF en XML
- [ ] Tope AFP sin hardcoding
- [ ] Suite completa tests pasa

### Post-Deploy

- [ ] Smoke test: crear liquidación enero 2025
- [ ] Verificar reforma 2025 calcula 1%
- [ ] Exportar Previred (no debe dar error)
- [ ] Validar archivo Previred 105 campos
- [ ] Verificar tope AFP usa 87.8 UF

---

## 📞 CONTACTO URGENTE

**Issues:** Reportar inmediatamente
**Blockers:** Escalar a Tech Lead

---

**INICIO:** HOY
**DEADLINE:** 2025-01-15
