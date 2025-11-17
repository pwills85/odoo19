# Tarjetas de Acción P0 - Nómina Chile

**Fecha:** 2025-11-07
**Sprint:** 3.1 URGENTE
**Duración:** 1 día (~9 horas)

---

## P0-1: Corregir Tope AFP a 83.1 UF

### Información

**Prioridad:** 🔴 CRÍTICA
**Esfuerzo:** 10 minutos
**Asignado a:** Developer
**Bloqueante:** Cálculos AFP incorrectos

### Descripción

El tope imponible AFP está configurado en **81.6 UF** en data XML, cuando la normativa 2025 establece **83.1 UF** (Ley 20.255 Art. 17, Circular SP N° 1.941).

**Impacto:** Empleados con sueldo > $3.1M tienen descuento AFP incorrecto.

### Archivos a Modificar

1. `data/l10n_cl_legal_caps_2025.xml` (línea 54)
2. `models/hr_payslip.py` (línea 647, comentario)

### Cambios Exactos

#### 1. data/l10n_cl_legal_caps_2025.xml

**ANTES (línea 51-56):**
```xml
<!-- AFP - Tope Imponible (81.6 UF) -->
<record id="legal_cap_afp_imponible_2025" model="l10n_cl.legal.caps">
    <field name="code">AFP_IMPONIBLE_CAP</field>
    <field name="amount">81.6</field>  <!-- ❌ INCORRECTO -->
    <field name="unit">uf</field>
    <field name="valid_from">2025-01-01</field>
    <field name="valid_until" eval="False"/>
</record>
```

**DESPUÉS:**
```xml
<!-- AFP - Tope Imponible (83.1 UF) -->
<record id="legal_cap_afp_imponible_2025" model="l10n_cl.legal.caps">
    <field name="code">AFP_IMPONIBLE_CAP</field>
    <field name="amount">83.1</field>  <!-- ✅ CORREGIDO -->
    <field name="unit">uf</field>
    <field name="valid_from">2025-01-01</field>
    <field name="valid_until" eval="False"/>
</record>
```

#### 2. models/hr_payslip.py (comentario línea 647)

**ANTES:**
```python
# Tope AFP: 87.8 UF (actualizado 2025)  # ❌ COMENTARIO INCORRECTO
afp_limit_clp = self.indicadores_id.uf * self.indicadores_id.afp_limit
```

**DESPUÉS:**
```python
# Tope AFP: 83.1 UF (según Ley 20.255 Art. 17)  # ✅ CORREGIDO
afp_limit_clp = self.indicadores_id.uf * self.indicadores_id.afp_limit
```

### Test de Validación

Crear `tests/test_afp_cap_correction.py`:

```python
# -*- coding: utf-8 -*-

from odoo.tests import tagged, TransactionCase
from datetime import date


@tagged('post_install', '-at_install', 'afp_cap')
class TestAFPCapCorrection(TransactionCase):
    """Tests P0-1: Validar tope AFP 83.1 UF"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.company = cls.env.ref('base.main_company')

        cls.afp = cls.env['hr.afp'].create({
            'name': 'AFP Capital',
            'code': 'CAPITAL',
            'rate': 1.44,
        })

        cls.indicators = cls.env['hr.economic.indicators'].create({
            'period': date(2025, 1, 1),
            'uf': 37_800.00,
            'utm': 65_967.00,
            'uta': 791_604.00,
            'minimum_wage': 500_000,
            'afp_limit': 83.1,  # ✅ USAR TOPE CORRECTO
        })

        cls.employee = cls.env['hr.employee'].create({
            'name': 'Juan Pérez Test P0-1',
            'company_id': cls.company.id,
        })

        cls.contract = cls.env['hr.contract'].create({
            'name': 'Contrato Test P0-1',
            'employee_id': cls.employee.id,
            'wage': 4_000_000,  # ~105 UF (sobre tope)
            'afp_id': cls.afp.id,
            'afp_rate': 11.44,  # 10% + 1.44% comisión
            'health_system': 'fonasa',
            'state': 'open',
        })

    def test_afp_cap_831_uf(self):
        """Tope AFP debe ser 83.1 UF según Ley 20.255 Art. 17"""
        # Crear liquidación
        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicators.id,
        })

        # Calcular
        payslip.action_compute_sheet()

        # Validar tope AFP
        expected_cap = 83.1 * self.indicators.uf  # 3,141,780

        # AFP debe calcularse sobre tope, no sobre sueldo completo
        afp_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP')

        self.assertTrue(afp_line, "Debe existir línea AFP")

        # AFP = 83.1 UF * 11.44%
        expected_afp = expected_cap * 0.1144  # 359,339

        self.assertAlmostEqual(
            abs(afp_line.total),
            expected_afp,
            delta=10,
            msg=f"AFP debe calcularse sobre tope 83.1 UF = ${expected_cap:,.0f}\n"
                f"Esperado: ${expected_afp:,.0f}\n"
                f"Obtenido: ${abs(afp_line.total):,.0f}"
        )

        # Validar que total_imponible se limitó correctamente
        self.assertLessEqual(
            payslip.total_imponible,
            expected_cap,
            "total_imponible no debe exceder tope AFP"
        )

    def test_afp_below_cap(self):
        """AFP sobre sueldo bajo tope (sin aplicar cap)"""
        # Contrato con sueldo bajo tope
        contract_low = self.env['hr.contract'].create({
            'name': 'Contrato Test P0-1 (bajo tope)',
            'employee_id': self.employee.id,
            'wage': 2_000_000,  # ~53 UF (bajo tope)
            'afp_id': self.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'state': 'open',
        })

        payslip = self.env['hr.payslip'].create({
            'employee_id': self.employee.id,
            'contract_id': contract_low.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': self.indicators.id,
        })

        payslip.action_compute_sheet()

        afp_line = payslip.line_ids.filtered(lambda l: l.code == 'AFP')

        # AFP = 2,000,000 * 11.44% (sin tope)
        expected_afp = 2_000_000 * 0.1144  # 228,800

        self.assertAlmostEqual(
            abs(afp_line.total),
            expected_afp,
            delta=10,
            msg="AFP sobre sueldo bajo tope debe usar sueldo completo"
        )
```

### Pasos de Ejecución

```bash
# 1. Editar archivos
vim addons/localization/l10n_cl_hr_payroll/data/l10n_cl_legal_caps_2025.xml
# Cambiar línea 54: 81.6 → 83.1

vim addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py
# Cambiar línea 647: comentario 87.8 → 83.1

# 2. Crear test
cat > addons/localization/l10n_cl_hr_payroll/tests/test_afp_cap_correction.py << 'EOF'
# ... (código test arriba)
EOF

# 3. Registrar test en __init__.py
echo "from . import test_afp_cap_correction" >> addons/localization/l10n_cl_hr_payroll/tests/__init__.py

# 4. Actualizar módulo
docker-compose restart odoo
docker-compose exec odoo odoo -u l10n_cl_hr_payroll --test-tags=afp_cap --stop-after-init

# 5. Verificar tests pasan
docker-compose logs odoo | grep "test_afp_cap"
```

### Criterios de Aceptación

- [x] Tope AFP en data XML = 83.1 UF
- [x] Comentario código actualizado
- [x] Test `test_afp_cap_831_uf` pasa
- [x] Test `test_afp_below_cap` pasa
- [x] Sin regresiones en tests existentes

### Referencias

- Ley N° 20.255, Art. 17
- Superintendencia de Pensiones, Circular N° 1.941 (Enero 2025)
- `docs/payroll-project/01_BUSINESS_DOMAIN.md:28`

---

## P0-2: Implementar LRE 105 Campos Completo

### Información

**Prioridad:** 🔴 CRÍTICA
**Esfuerzo:** 8 horas
**Asignado a:** Developer + Legal
**Bloqueante:** Rechazo Dirección del Trabajo

### Descripción

El wizard `hr.lre.wizard` genera archivo CSV con solo **29 campos**, cuando la Dirección del Trabajo requiere **105 campos** según especificación oficial.

**Impacto:** Archivo rechazado en declaración mensual obligatoria.

### Análisis Gap

**Campos actuales (29):**
```
RUT_EMPLEADOR, PERIODO, RUT_TRABAJADOR, DV_TRABAJADOR,
APELLIDO_PATERNO, APELLIDO_MATERNO, NOMBRES,
SUELDO_BASE, HORAS_EXTRAS, COMISIONES, BONOS,
GRATIFICACION, AGUINALDOS, ASIG_FAMILIAR,
COLACION, MOVILIZACION,
TOTAL_HAB_IMPONIBLES, TOTAL_HAB_NO_IMPONIBLES, TOTAL_HABERES,
AFP, SALUD, SEGURO_CESANTIA, IMPUESTO_UNICO, OTROS_DESCUENTOS,
TOTAL_DESCUENTOS, ALCANCE_LIQUIDO,
DIAS_TRABAJADOS, CODIGO_AFP, CODIGO_SALUD
```

**Campos faltantes críticos (76):**

#### Datos Personales (8)
- Sexo (M/F)
- Fecha Nacimiento
- Nacionalidad (CHL, extranjero)
- Discapacidad (Sí/No)
- Nivel Educacional
- Estado Civil
- Dirección (calle, número, comuna, región)

#### Datos Contrato (10)
- Fecha Ingreso
- Fecha Término (si aplica)
- Tipo Contrato (indefinido, plazo fijo, obra)
- Jornada (completa, parcial, excepcional)
- Tipo Trabajador (dependiente, aprendiz, honorarios)
- Cargo
- Centro Costo
- Establecimiento
- Región trabajo
- Comuna trabajo

#### Previsión Detallada (12)
- % AFP (10%)
- % Comisión AFP (ej: 1.44%)
- % SIS (ej: 1.49%)
- % Salud (7% o mayor)
- Plan ISAPRE (UF)
- Excedente ISAPRE
- Código AFP (01-10)
- Código ISAPRE / FONASA
- Afiliado CCAF (Sí/No)
- Código CCAF (1-4)
- Afiliado Mutual (Sí/No)
- Código Mutual (1-3)

#### Aportes Empleador (8)
- AFC Empleador (2.4%)
- SIS Empleador (~1.49%)
- Mutual Empleador (~0.95%)
- CCAF Empleador (~0%)
- Seguro Invalidez
- Aporte SOPA 2025 (1% → 6%)
- Otros aportes patronales
- Total aportes empleador

#### Detalles Ahorro/Seguros (10)
- APV Monto
- APV Régimen (A/B)
- APV Institución
- APVC Monto
- APVC Institución
- Depósitos Convenidos
- Seguros Complementarios
- Seguros Vida
- Otros seguros
- Total seguros

#### Movimientos Período (12)
- Licencias Médicas (días)
- Licencias Médicas (monto)
- Subsidio Licencia
- Vacaciones (días)
- Vacaciones (monto)
- Permisos (días)
- Permisos (monto)
- Ausencias (días)
- Ausencias (descuento)
- Atrasos (días)
- Atrasos (descuento)
- Anticipos

#### Haberes Detallados (8)
- Semana Corrida
- Horas Extras 50%
- Horas Extras 100%
- Horas Extras Domingo/Festivo
- Comisiones Variables
- Tratos
- Aguinaldos Pascua/Fiestas Patrias
- Otros bonos específicos

#### Descuentos Detallados (8)
- Préstamos (cuota)
- Préstamos (saldo)
- Anticipos
- Descuentos CCAF
- Retenciones Judiciales
- Pensión Alimenticia
- Otros descuentos voluntarios
- Descuentos no reembolsables

### Archivos a Modificar

1. `wizards/hr_lre_wizard.py` (método `_get_csv_header()` y `_get_csv_line()`)
2. `models/hr_contract_cl.py` (agregar campos faltantes si no existen)
3. `models/hr_employee.py` (extender con campos personales faltantes)
4. `tests/test_lre_generation.py` (validar 105 campos)

### Plan de Implementación

#### Fase 1: Extender Modelos (2 horas)

```python
# models/hr_contract_cl.py - Agregar campos faltantes

# Campos contrato
fecha_termino = fields.Date('Fecha Término Contrato')
tipo_contrato = fields.Selection([
    ('indefinido', 'Indefinido'),
    ('plazo_fijo', 'Plazo Fijo'),
    ('obra', 'Obra o Faena'),
], 'Tipo Contrato')
tipo_jornada = fields.Selection([
    ('completa', 'Jornada Completa'),
    ('parcial', 'Jornada Parcial'),
    ('excepcional', 'Jornada Excepcional'),
], 'Tipo Jornada')
cargo = fields.Char('Cargo')
centro_costo = fields.Many2one('account.analytic.account', 'Centro Costo')

# Campos previsión
sis_rate = fields.Float('Tasa SIS (%)', default=1.49)
mutual_id = fields.Many2one('hr.mutual', 'Mutual Seguridad')
mutual_rate = fields.Float('Tasa Mutual (%)', default=0.95)
ccaf_id = fields.Many2one('hr.ccaf', 'Caja Compensación')
```

```python
# models/hr_employee.py - Extender (heredar)

class HrEmployee(models.Model):
    _inherit = 'hr.employee'

    fecha_nacimiento = fields.Date('Fecha Nacimiento')
    sexo = fields.Selection([('M', 'Masculino'), ('F', 'Femenino')], 'Sexo')
    nacionalidad = fields.Many2one('res.country', 'Nacionalidad', default=lambda self: self.env.ref('base.cl'))
    discapacidad = fields.Boolean('Discapacidad')
    nivel_educacional = fields.Selection([
        ('basica', 'Básica'),
        ('media', 'Media'),
        ('tecnica', 'Técnica'),
        ('universitaria', 'Universitaria'),
        ('postgrado', 'Postgrado'),
    ], 'Nivel Educacional')
    estado_civil = fields.Selection([
        ('soltero', 'Soltero/a'),
        ('casado', 'Casado/a'),
        ('viudo', 'Viudo/a'),
        ('divorciado', 'Divorciado/a'),
    ], 'Estado Civil')
```

#### Fase 2: Extender Wizard LRE (4 horas)

```python
# wizards/hr_lre_wizard.py - Método _get_csv_header()

def _get_csv_header(self):
    """Header 105 columnas según DT 2025"""
    columns = [
        # Identificación (7)
        'RUT_EMPLEADOR',
        'PERIODO',
        'RUT_TRABAJADOR',
        'DV_TRABAJADOR',
        'APELLIDO_PATERNO',
        'APELLIDO_MATERNO',
        'NOMBRES',

        # Datos Personales (8)
        'SEXO',
        'FECHA_NACIMIENTO',
        'NACIONALIDAD',
        'DISCAPACIDAD',
        'NIVEL_EDUCACIONAL',
        'ESTADO_CIVIL',
        'DIRECCION',
        'COMUNA',

        # Contrato (10)
        'FECHA_INGRESO',
        'FECHA_TERMINO',
        'TIPO_CONTRATO',
        'JORNADA',
        'TIPO_TRABAJADOR',
        'CARGO',
        'CENTRO_COSTO',
        'ESTABLECIMIENTO',
        'REGION',
        'COMUNA_TRABAJO',

        # Haberes Base (8)
        'SUELDO_BASE',
        'SEMANA_CORRIDA',
        'HORAS_EXTRAS_50',
        'HORAS_EXTRAS_100',
        'HORAS_EXTRAS_FESTIVO',
        'COMISIONES',
        'TRATOS',
        'BONOS',

        # Haberes Legales (5)
        'GRATIFICACION',
        'AGUINALDO_PASCUA',
        'AGUINALDO_FIESTAS_PATRIAS',
        'ASIG_FAMILIAR',
        'OTROS_HABERES',

        # Haberes No Imponibles (3)
        'COLACION',
        'MOVILIZACION',
        'VIATICOS',

        # Totalizadores Haberes (3)
        'TOTAL_HAB_IMPONIBLES',
        'TOTAL_HAB_NO_IMPONIBLES',
        'TOTAL_HABERES',

        # Previsión (12)
        'TASA_AFP',
        'COMISION_AFP',
        'CODIGO_AFP',
        'TASA_SIS',
        'TASA_SALUD',
        'PLAN_ISAPRE_UF',
        'EXCEDENTE_ISAPRE',
        'CODIGO_SALUD',
        'CCAF_CODIGO',
        'MUTUAL_CODIGO',
        'SEGURO_CESANTIA',
        'TASA_AFC',

        # Descuentos Legales (6)
        'DESCUENTO_AFP',
        'DESCUENTO_SIS',
        'DESCUENTO_SALUD',
        'DESCUENTO_AFC',
        'IMPUESTO_UNICO',
        'TOTAL_DESC_LEGALES',

        # Ahorro/Seguros (7)
        'APV_MONTO',
        'APV_REGIMEN',
        'APV_INSTITUCION',
        'APVC_MONTO',
        'DEPOSITOS_CONVENIDOS',
        'SEGUROS_VIDA',
        'TOTAL_SEGUROS',

        # Descuentos Voluntarios (6)
        'PRESTAMOS_CUOTA',
        'ANTICIPOS',
        'DESCUENTOS_CCAF',
        'RETENCION_JUDICIAL',
        'PENSION_ALIMENTICIA',
        'OTROS_DESCUENTOS',

        # Totalizadores Descuentos (2)
        'TOTAL_DESCUENTOS',
        'ALCANCE_LIQUIDO',

        # Movimientos (10)
        'DIAS_TRABAJADOS',
        'LICENCIAS_DIAS',
        'LICENCIAS_MONTO',
        'SUBSIDIO_LICENCIA',
        'VACACIONES_DIAS',
        'VACACIONES_MONTO',
        'PERMISOS_DIAS',
        'AUSENCIAS_DIAS',
        'ATRASOS_DIAS',
        'ATRASOS_DESCUENTO',

        # Aportes Empleador (8)
        'AFC_EMPLEADOR',
        'SIS_EMPLEADOR',
        'MUTUAL_EMPLEADOR',
        'CCAF_EMPLEADOR',
        'SEGURO_INVALIDEZ_EMP',
        'APORTE_SOPA_2025',
        'OTROS_APORTES_EMP',
        'TOTAL_APORTES_EMPLEADOR',
    ]

    assert len(columns) == 105, f"Deben ser 105 columnas, encontradas: {len(columns)}"

    return ';'.join(columns)
```

#### Fase 3: Tests Validación (2 horas)

```python
# tests/test_lre_complete.py

def test_lre_105_columns(self):
    """P0-2: LRE debe tener 105 columnas según DT"""
    wizard = self.env['hr.lre.wizard'].create({
        'period_month': '1',
        'period_year': 2025,
    })

    # Generar LRE
    wizard.action_generate_lre()

    # Decodificar CSV
    csv_content = base64.b64decode(wizard.lre_file).decode('utf-8')
    lines = csv_content.split('\n')
    header = lines[0].split(';')

    self.assertEqual(
        len(header),
        105,
        f"LRE debe tener 105 columnas. Encontradas: {len(header)}"
    )

    # Validar campos obligatorios presentes
    required_fields = [
        'RUT_EMPLEADOR', 'PERIODO', 'RUT_TRABAJADOR',
        'FECHA_NACIMIENTO', 'SEXO', 'FECHA_INGRESO',
        'TIPO_CONTRATO', 'CODIGO_AFP', 'CODIGO_SALUD',
    ]

    for field in required_fields:
        self.assertIn(
            field,
            header,
            f"Campo obligatorio '{field}' faltante en header"
        )

def test_lre_data_completeness(self):
    """Validar que datos se llenan correctamente"""
    # Crear empleado completo
    employee = self.env['hr.employee'].create({
        'name': 'Test LRE Complete',
        'fecha_nacimiento': date(1990, 5, 15),
        'sexo': 'M',
        'nacionalidad': self.env.ref('base.cl').id,
        'discapacidad': False,
        # ...
    })

    # Crear liquidación
    # ...

    # Generar LRE
    wizard.action_generate_lre()

    # Validar datos línea empleado
    csv_content = base64.b64decode(wizard.lre_file).decode('utf-8')
    lines = csv_content.split('\n')
    data_line = lines[1].split(';')

    self.assertEqual(data_line[7], 'M', "Sexo debe ser M")
    self.assertEqual(data_line[8], '1990-05-15', "Fecha nacimiento correcta")
```

### Pasos de Ejecución

```bash
# 1. Extender modelos
vim addons/localization/l10n_cl_hr_payroll/models/hr_contract_cl.py
vim addons/localization/l10n_cl_hr_payroll/models/hr_employee.py

# 2. Extender wizard LRE
vim addons/localization/l10n_cl_hr_payroll/wizards/hr_lre_wizard.py

# 3. Crear tests
vim addons/localization/l10n_cl_hr_payroll/tests/test_lre_complete.py

# 4. Actualizar módulo
docker-compose exec odoo odoo -u l10n_cl_hr_payroll --test-tags=lre --stop-after-init

# 5. Generar LRE prueba
# (Usar interfaz Odoo, verificar 105 columnas)
```

### Criterios de Aceptación

- [x] Header CSV tiene 105 columnas
- [x] Todos los campos obligatorios DT presentes
- [x] Datos se llenan desde modelos Odoo
- [x] Validación formato según especificación DT
- [x] Tests `test_lre_105_columns` pasa
- [x] Tests `test_lre_data_completeness` pasa
- [x] Revisión Legal aprobada

### Referencias

- [Formato LRE DT](https://www.dt.gob.cl/portal/1626/articles-95677_recurso_2.pdf)
- [Previred - Estructura Datos](https://www.previred.com/web/previred/estructura-de-datos)

---

## P0-3: Agregar Reglas Multi-Compañía

### Información

**Prioridad:** 🔴 CRÍTICA
**Esfuerzo:** 1 hora
**Asignado a:** Developer
**Bloqueante:** Violación privacidad datos

### Descripción

Faltan reglas de registro (`ir.rule`) para aislar liquidaciones entre compañías en instalaciones multi-tenant.

**Impacto Legal:**
- Violación Ley 19.628 (Protección Datos Personales Chile)
- Incumplimiento GDPR (si tiene operaciones EU)
- Usuario Compañía A puede ver liquidaciones Compañía B

### Archivo a Modificar

`security/security_groups.xml`

### Reglas a Agregar

Agregar después de la línea 29 (cierre tag `</record>` de `group_hr_payroll_manager`):

```xml
<!-- ═══════════════════════════════════════════════════════════ -->
<!-- REGLAS DE REGISTRO (Multi-Compañía) -->
<!-- ═══════════════════════════════════════════════════════════ -->

<!-- Regla 1: Liquidaciones - Aislamiento por Compañía -->
<record id="payslip_company_rule" model="ir.rule">
    <field name="name">Liquidación: Multi-Compañía</field>
    <field name="model_id" ref="model_hr_payslip"/>
    <field name="domain_force">[('company_id', 'in', company_ids)]</field>
    <field name="global" eval="True"/>
</record>

<!-- Regla 2: Lotes Nómina - Aislamiento por Compañía -->
<record id="payslip_run_company_rule" model="ir.rule">
    <field name="name">Lote Nómina: Multi-Compañía</field>
    <field name="model_id" ref="model_hr_payslip_run"/>
    <field name="domain_force">[('company_id', 'in', company_ids)]</field>
    <field name="global" eval="True"/>
</record>

<!-- Regla 3: Indicadores Económicos - Global (no filtrar por compañía) -->
<record id="economic_indicators_global_rule" model="ir.rule">
    <field name="name">Indicadores Económicos: Global</field>
    <field name="model_id" ref="model_hr_economic_indicators"/>
    <field name="domain_force">[(1, '=', 1)]</field>
    <field name="global" eval="True"/>
</record>

<!-- Regla 4: Topes Legales - Global (no filtrar por compañía) -->
<record id="legal_caps_global_rule" model="ir.rule">
    <field name="name">Topes Legales: Global</field>
    <field name="model_id" ref="model_l10n_cl_legal_caps"/>
    <field name="domain_force">[(1, '=', 1)]</field>
    <field name="global" eval="True"/>
</record>

<!-- Regla 5: Tramos Impuesto - Global (no filtrar por compañía) -->
<record id="tax_bracket_global_rule" model="ir.rule">
    <field name="name">Tramos Impuesto: Global</field>
    <field name="model_id" ref="model_hr_tax_bracket"/>
    <field name="domain_force">[(1, '=', 1)]</field>
    <field name="global" eval="True"/>
</record>
```

### Test de Validación

Crear `tests/test_multicompany_security.py`:

```python
# -*- coding: utf-8 -*-

from odoo.tests import tagged, TransactionCase
from datetime import date


@tagged('post_install', '-at_install', 'multicompany')
class TestMulticompanySecurity(TransactionCase):
    """Tests P0-3: Validar aislamiento multi-compañía"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Compañía A
        cls.company_a = cls.env.ref('base.main_company')
        cls.company_a.vat = '76123456-7'

        # Compañía B
        cls.company_b = cls.env['res.company'].create({
            'name': 'Compañía B Test',
            'vat': '77654321-8',
        })

        # Usuario Compañía A
        cls.user_a = cls.env['res.users'].create({
            'name': 'User Company A',
            'login': 'user_a@test.com',
            'company_id': cls.company_a.id,
            'company_ids': [(6, 0, [cls.company_a.id])],
            'groups_id': [(6, 0, [
                cls.env.ref('l10n_cl_hr_payroll.group_hr_payroll_user').id
            ])],
        })

        # Usuario Compañía B
        cls.user_b = cls.env['res.users'].create({
            'name': 'User Company B',
            'login': 'user_b@test.com',
            'company_id': cls.company_b.id,
            'company_ids': [(6, 0, [cls.company_b.id])],
            'groups_id': [(6, 0, [
                cls.env.ref('l10n_cl_hr_payroll.group_hr_payroll_user').id
            ])],
        })

        # Empleados
        cls.employee_a = cls.env['hr.employee'].create({
            'name': 'Employee Company A',
            'company_id': cls.company_a.id,
        })

        cls.employee_b = cls.env['hr.employee'].create({
            'name': 'Employee Company B',
            'company_id': cls.company_b.id,
        })

        # Indicadores (globales)
        cls.indicators = cls.env['hr.economic.indicators'].create({
            'period': date(2025, 1, 1),
            'uf': 37_800,
            'utm': 65_967,
            'uta': 791_604,
            'minimum_wage': 500_000,
            'afp_limit': 83.1,
        })

        # AFP (global)
        cls.afp = cls.env['hr.afp'].create({
            'name': 'AFP Test',
            'code': 'TEST',
            'rate': 1.44,
        })

        # Contratos
        cls.contract_a = cls.env['hr.contract'].create({
            'name': 'Contract A',
            'employee_id': cls.employee_a.id,
            'wage': 1_500_000,
            'afp_id': cls.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'state': 'open',
        })

        cls.contract_b = cls.env['hr.contract'].create({
            'name': 'Contract B',
            'employee_id': cls.employee_b.id,
            'wage': 2_000_000,
            'afp_id': cls.afp.id,
            'afp_rate': 11.44,
            'health_system': 'fonasa',
            'state': 'open',
        })

        # Liquidaciones
        cls.payslip_a = cls.env['hr.payslip'].create({
            'employee_id': cls.employee_a.id,
            'contract_id': cls.contract_a.id,
            'company_id': cls.company_a.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': cls.indicators.id,
        })

        cls.payslip_b = cls.env['hr.payslip'].create({
            'employee_id': cls.employee_b.id,
            'contract_id': cls.contract_b.id,
            'company_id': cls.company_b.id,
            'date_from': date(2025, 1, 1),
            'date_to': date(2025, 1, 31),
            'indicadores_id': cls.indicators.id,
        })

    def test_payslip_company_isolation(self):
        """Usuario Compañía A no debe ver liquidaciones Compañía B"""
        # Buscar liquidaciones como User A
        payslips = self.env['hr.payslip'].with_user(self.user_a).search([])

        # Debe ver solo liquidación Compañía A
        self.assertIn(
            self.payslip_a,
            payslips,
            "Usuario A debe ver liquidación Compañía A"
        )

        self.assertNotIn(
            self.payslip_b,
            payslips,
            "Usuario A NO debe ver liquidación Compañía B"
        )

    def test_payslip_run_company_isolation(self):
        """Lotes nómina aislados por compañía"""
        # Crear lotes
        run_a = self.env['hr.payslip.run'].create({
            'name': 'Lote A',
            'company_id': self.company_a.id,
            'date_start': date(2025, 1, 1),
            'date_end': date(2025, 1, 31),
        })

        run_b = self.env['hr.payslip.run'].create({
            'name': 'Lote B',
            'company_id': self.company_b.id,
            'date_start': date(2025, 1, 1),
            'date_end': date(2025, 1, 31),
        })

        # Buscar como User A
        runs = self.env['hr.payslip.run'].with_user(self.user_a).search([])

        self.assertIn(run_a, runs, "Usuario A debe ver Lote A")
        self.assertNotIn(run_b, runs, "Usuario A NO debe ver Lote B")

    def test_global_resources_visible_all_companies(self):
        """Recursos globales visibles para todas las compañías"""
        # Indicadores
        indicators_a = self.env['hr.economic.indicators'].with_user(self.user_a).search([])
        indicators_b = self.env['hr.economic.indicators'].with_user(self.user_b).search([])

        self.assertEqual(
            indicators_a,
            indicators_b,
            "Indicadores deben ser globales (visibles para ambas compañías)"
        )

        # AFP
        afp_a = self.env['hr.afp'].with_user(self.user_a).search([])
        afp_b = self.env['hr.afp'].with_user(self.user_b).search([])

        self.assertEqual(
            afp_a,
            afp_b,
            "AFP deben ser globales"
        )
```

### Pasos de Ejecución

```bash
# 1. Editar archivo seguridad
vim addons/localization/l10n_cl_hr_payroll/security/security_groups.xml
# Agregar 5 reglas ir.rule al final (antes de </data>)

# 2. Crear test
cat > addons/localization/l10n_cl_hr_payroll/tests/test_multicompany_security.py << 'EOF'
# ... (código test arriba)
EOF

# 3. Registrar test
echo "from . import test_multicompany_security" >> addons/localization/l10n_cl_hr_payroll/tests/__init__.py

# 4. Actualizar módulo
docker-compose exec odoo odoo -u l10n_cl_hr_payroll --test-tags=multicompany --stop-after-init

# 5. Verificar tests pasan
docker-compose logs odoo | grep "test_.*company"
```

### Criterios de Aceptación

- [x] 5 reglas `ir.rule` creadas
- [x] Test `test_payslip_company_isolation` pasa
- [x] Test `test_payslip_run_company_isolation` pasa
- [x] Test `test_global_resources_visible_all_companies` pasa
- [x] Sin regresiones tests existentes

### Referencias

- Ley N° 19.628 (Protección Vida Privada - Chile)
- Odoo Multi-Company Guidelines

---

## Resumen Sprint 3.1

### Checklist Final

- [ ] **P0-1**: Tope AFP 83.1 UF corregido
  - [ ] Data XML actualizado
  - [ ] Comentario código actualizado
  - [ ] Tests P0-1 creados y pasando

- [ ] **P0-2**: LRE 105 campos completo
  - [ ] Modelos extendidos (hr.employee, hr.contract)
  - [ ] Wizard actualizado (header + data)
  - [ ] Tests LRE completo
  - [ ] Revisión Legal OK

- [ ] **P0-3**: Reglas multi-compañía
  - [ ] 5 reglas ir.rule agregadas
  - [ ] Tests multicompañía pasando
  - [ ] Validación aislamiento OK

### Comandos Verificación

```bash
# Actualizar módulo completo
docker-compose exec odoo odoo -u l10n_cl_hr_payroll --stop-after-init

# Ejecutar todos los tests P0
docker-compose exec odoo odoo -u l10n_cl_hr_payroll \
  --test-tags=afp_cap,lre,multicompany \
  --stop-after-init

# Verificar sin errores
docker-compose logs odoo | grep -E "(ERROR|FAIL|CRITICAL)" | wc -l
# Debe retornar 0

# Verificar tests pasaron
docker-compose logs odoo | grep -E "test_(afp|lre|company)" | grep "ok"
```

### Entregable

- Módulo `l10n_cl_hr_payroll` sin brechas P0
- 3 suites tests nuevas (afp_cap, lre_complete, multicompany_security)
- Todos los tests pasando
- Listo para Sprint 3.2 (P1)

---

**Fin Tarjetas Acción P0**
