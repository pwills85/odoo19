# 🎯 PLAN MAESTRO: CIERRE DE BRECHAS - Sistema Nóminas Chile

**Fecha:** 2025-10-23  
**Módulo:** l10n_cl_hr_payroll (Odoo 19 CE)  
**Estado Actual:** 73% (Sprint 3.2 completado)  
**Objetivo:** 100% (Sistema completo y operacional)  
**Tiempo Total:** 197 horas (5 semanas)

---

## 📊 EXECUTIVE SUMMARY

### Progreso Actual

```
MÓDULO ODOO (Core):           85% ████████████████▓▓▓
MICROSERVICIOS:                0% ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
─────────────────────────────────────────────────────
TOTAL PROYECTO:               73% ██████████████▓▓▓▓▓▓
```

### Brechas Identificadas

| Área | Estado | Horas | Prioridad |
|------|--------|-------|-----------|
| **Reglas Salariales Críticas** | 85% | 16h | 🔴 ALTA |
| **Reportes Legales** | 20% | 52h | 🔴 ALTA |
| **Finiquito** | 0% | 32h | 🔴 ALTA |
| **Payroll-Service** | 0% | 40h | 🔴 ALTA |
| **Completar Módulo Odoo** | 85% | 37h | 🟡 MEDIA |
| **AI-Service Extension** | 0% | 24h | 🟢 BAJA |
| **TOTAL** | **73%** | **197h** | |

---

## 🗓️ ROADMAP - 5 SEMANAS

### **Semana 1: Reglas Salariales Críticas** (40h)
**Objetivo:** Completar cálculos obligatorios por ley

- ✅ Día 1-2: Gratificación Legal (16h)
- ✅ Día 3: Asignación Familiar (8h)
- ✅ Día 4: Aportes Empleador Reforma 2025 (8h)
- ✅ Día 5: Testing + Validaciones (8h)

**Entregable:** Módulo Odoo al 95%

---

### **Semana 2: Reportes Legales Core** (40h)
**Objetivo:** Reportes obligatorios DT/Previred

- ✅ Día 1-2: Liquidación Individual PDF (12h)
- ✅ Día 3-4: Libro de Remuneraciones Excel (16h)
- ✅ Día 5: Resumen Contable (8h)
- ⚡ Buffer: Ajustes (4h)

**Entregable:** Reportes básicos funcionales

---

### **Semana 3: Previred + Finiquito** (40h)
**Objetivo:** Compliance Previred + Liquidaciones finales

- ✅ Día 1-3: Previred 105 campos (24h)
- ✅ Día 4-5: Finiquito base (16h)

**Entregable:** Exportación Previred + Finiquito básico

---

### **Semana 4: Payroll-Service** (40h)
**Objetivo:** Microservicio cálculos complejos

- ✅ Día 1: Setup FastAPI (8h)
- ✅ Día 2: Gratificación endpoint (8h)
- ✅ Día 3: Finiquito endpoint (8h)
- ✅ Día 4: Scraper Previred (8h)
- ✅ Día 5: Testing + CI/CD (8h)

**Entregable:** Payroll-Service operacional

---

### **Semana 5: Finiquito Completo + Polish** (37h)
**Objetivo:** Terminar finiquito + pulir detalles

- ✅ Día 1-2: Finiquito avanzado (16h)
- ✅ Día 3: Completar Lotes Nómina (8h)
- ✅ Día 4: Completar Ficha Trabajador (4h)
- ✅ Día 5: Testing integral + Docs (9h)

**Entregable:** Sistema al 100%

---

## 🔥 FASE 1: REGLAS SALARIALES CRÍTICAS (40h)

### **Sprint 4.1: Gratificación Legal** (16h)

#### **Contexto Legal**

Artículo 47-50 Código del Trabajo Chile:
- **Monto:** 25% de las utilidades líquidas de la empresa
- **Distribución:** Proporcional a lo devengado por cada trabajador
- **Tope:** 4.75 IMM (Ingreso Mínimo Mensual)
- **Mensualización:** Se puede pagar mensualmente (1/12)

#### **Implementación**

```python
# models/hr_payslip.py - AGREGAR

def _compute_gratification_lines(self):
    """
    Calcular gratificación legal mensual
    
    Técnica Odoo 19 CE:
    - Usa patrón Strategy
    - Totalizador total_gratificacion_base ya existe
    - Aplica tope 4.75 IMM
    """
    for payslip in self:
        if payslip.contract_id.gratification_type == 'legal':
            # Base: solo haberes que afectan gratificación
            base = payslip.total_gratificacion_base
            
            # Gratificación mensual: 25% / 12
            gratification_rate = 0.25 / 12
            gratification_amount = base * gratification_rate
            
            # Tope: 4.75 IMM
            imm = payslip.indicadores_id.ingreso_minimo
            tope = imm * 4.75
            
            if gratification_amount > tope:
                gratification_amount = tope
            
            # Crear línea
            payslip.env['hr.payslip.line'].create({
                'slip_id': payslip.id,
                'code': 'GRAT',
                'name': 'Gratificación Legal',
                'sequence': 25,
                'category_id': payslip.env.ref(
                    'l10n_cl_hr_payroll.category_haber_imponible'
                ).id,
                'amount': gratification_amount,
                'quantity': 1,
                'rate': gratification_rate * 100,
                'total': gratification_amount,
            })
            
            _logger.info(
                f"Gratificación calculada: {gratification_amount} "
                f"(base: {base}, tope: {tope})"
            )
        
        elif payslip.contract_id.gratification_type == 'monthly':
            # Gratificación mensual fija (1/12 del anual)
            # Generalmente acordada en contrato
            pass  # Implementar según necesidad

def _calculate_gratification_annual_distribution(self, company_profits):
    """
    Calcular distribución anual de gratificación
    
    Llamado desde contabilidad cuando se cierran utilidades.
    Distribuye 25% de utilidades entre trabajadores.
    """
    # Total devengado por todos en el año
    total_base = self.env['hr.payslip'].search([
        ('company_id', '=', self.env.company.id),
        ('date_from', '>=', f'{self.year}-01-01'),
        ('date_to', '<=', f'{self.year}-12-31'),
        ('state', '=', 'done'),
    ]).mapped('total_gratificacion_base')
    
    total_devengado = sum(total_base)
    
    # 25% utilidades
    gratification_pool = company_profits * 0.25
    
    # Proporcional por trabajador
    employee_share = (self.total_gratificacion_base / total_devengado) * gratification_pool
    
    # Tope 4.75 IMM anual
    tope_anual = self.indicadores_id.ingreso_minimo * 4.75 * 12
    
    if employee_share > tope_anual:
        employee_share = tope_anual
    
    return employee_share
```

#### **Data XML**

```xml
<!-- data/hr_salary_rule_gratificacion.xml - CREAR -->

<odoo>
    <data noupdate="1">
        
        <!-- Regla: Gratificación Legal -->
        <record id="rule_gratificacion_legal" model="hr.salary.rule">
            <field name="name">Gratificación Legal</field>
            <field name="code">GRAT</field>
            <field name="sequence">25</field>
            <field name="category_id" ref="category_haber_imponible"/>
            <field name="active">True</field>
            
            <!-- Condición: Solo si contrato tiene gratificación legal -->
            <field name="condition_select">python</field>
            <field name="condition_python">result = contract.gratification_type == 'legal'</field>
            
            <!-- Cálculo: Llama al método Python -->
            <field name="amount_select">code</field>
            <field name="amount_python_compute">
# Base: Solo haberes que afectan gratificación
base = payslip.total_gratificacion_base

# Gratificación mensual: 25% / 12
rate = 0.25 / 12
amount = base * rate

# Tope: 4.75 IMM
imm = payslip.indicadores_id.ingreso_minimo
tope = imm * 4.75

if amount > tope:
    amount = tope

result = amount
            </field>
            
            <!-- Flags -->
            <field name="appears_on_payslip">True</field>
            <field name="note">Gratificación legal según Art. 47-50 CT (25% utilidades, tope 4.75 IMM)</field>
        </record>
        
    </data>
</odoo>
```

#### **Tests**

```python
# tests/test_gratificacion.py - CREAR

from odoo.tests import TransactionCase, tagged

@tagged('post_install', '-at_install', 'payroll_gratification')
class TestGratificacion(TransactionCase):
    
    def setUp(self):
        super().setUp()
        
        # Indicadores
        self.indicadores = self.env['hr.economic.indicators'].create({
            'name': 'Enero 2025',
            'month': '01',
            'year': '2025',
            'uf': 37500.00,
            'utm': 65000.00,
            'ingreso_minimo': 500000.00,
        })
        
        # Empleado
        self.employee = self.env['hr.employee'].create({
            'name': 'Juan Pérez',
            'identification_id': '12.345.678-9',
        })
        
        # Contrato con gratificación legal
        self.contract = self.env['hr.contract'].create({
            'name': 'Contrato Juan',
            'employee_id': self.employee.id,
            'wage': 1000000,
            'gratification_type': 'legal',
            'date_start': '2025-01-01',
        })
    
    def test_gratification_basic(self):
        """Test cálculo básico gratificación"""
        payslip = self.env['hr.payslip'].create({
            'name': 'Liquidación Enero 2025',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': '2025-01-01',
            'date_to': '2025-01-31',
            'indicadores_id': self.indicadores.id,
        })
        
        payslip.compute_sheet()
        
        # Buscar línea gratificación
        grat_line = payslip.line_ids.filtered(lambda l: l.code == 'GRAT')
        
        self.assertTrue(grat_line, "Debe existir línea de gratificación")
        
        # Base: 1,000,000 (solo sueldo base)
        # Gratificación: 1,000,000 * (0.25 / 12) = 20,833.33
        expected = 1000000 * 0.25 / 12
        
        self.assertAlmostEqual(
            grat_line.total,
            expected,
            places=2,
            msg=f"Gratificación debe ser {expected}"
        )
    
    def test_gratification_with_tope(self):
        """Test gratificación con tope 4.75 IMM"""
        # Sueldo alto que excede tope
        self.contract.wage = 5000000
        
        payslip = self.env['hr.payslip'].create({
            'name': 'Liquidación Enero 2025',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': '2025-01-01',
            'date_to': '2025-01-31',
            'indicadores_id': self.indicadores.id,
        })
        
        payslip.compute_sheet()
        
        grat_line = payslip.line_ids.filtered(lambda l: l.code == 'GRAT')
        
        # Tope: 4.75 * 500,000 = 2,375,000 (anual) / 12 = 197,916.67
        tope_mensual = (4.75 * 500000) / 12
        
        self.assertAlmostEqual(
            grat_line.total,
            tope_mensual,
            places=2,
            msg=f"Gratificación debe estar topada en {tope_mensual}"
        )
    
    def test_no_gratification_if_type_none(self):
        """Test sin gratificación si tipo es 'none'"""
        self.contract.gratification_type = 'none'
        
        payslip = self.env['hr.payslip'].create({
            'name': 'Liquidación Enero 2025',
            'employee_id': self.employee.id,
            'contract_id': self.contract.id,
            'date_from': '2025-01-01',
            'date_to': '2025-01-31',
            'indicadores_id': self.indicadores.id,
        })
        
        payslip.compute_sheet()
        
        grat_line = payslip.line_ids.filtered(lambda l: l.code == 'GRAT')
        
        self.assertFalse(grat_line, "No debe haber gratificación si tipo es 'none'")
```

**Tiempo:** 16 horas

---

### **Sprint 4.2: Asignación Familiar** (8h)

#### **Contexto Legal**

Ley 18.020:
- **Beneficiarios:** Trabajadores con cargas familiares
- **Montos:** Variable según tramo de ingreso (A, B, C)
- **Carga simple:** Hijos menores 18 años, cónyuge
- **Carga maternal:** Madre viuda, madre soltera
- **Carga inválida:** Familiar con discapacidad
- **NO imponible, NO tributable**

#### **Implementación**

```python
# models/hr_payslip.py - AGREGAR

def _compute_family_allowance_lines(self):
    """
    Calcular asignación familiar
    
    Técnica Odoo 19 CE:
    - Lee cargas desde contrato
    - Determina tramo según ingreso
    - Aplica montos vigentes
    """
    for payslip in self:
        contract = payslip.contract_id
        
        # Total cargas
        total_simple = contract.family_allowance_simple
        total_maternal = contract.family_allowance_maternal
        total_invalid = contract.family_allowance_invalid
        
        if not (total_simple + total_maternal + total_invalid):
            continue  # Sin cargas, saltar
        
        # Determinar tramo según ingreso
        # Tramo A: < $439,484
        # Tramo B: $439,485 - $643,144
        # Tramo C: $643,145 - $1,000,827
        # Sin asignación: > $1,000,827
        
        base_income = contract.wage
        
        if base_income <= 439484:
            tramo = 'A'
            monto_simple = 15268
            monto_maternal = 9606
            monto_invalid = 45795
        elif base_income <= 643144:
            tramo = 'B'
            monto_simple = 10818
            monto_maternal = 6805
            monto_invalid = 45795
        elif base_income <= 1000827:
            tramo = 'C'
            monto_simple = 3048
            monto_maternal = 1918
            monto_invalid = 45795
        else:
            continue  # Sin asignación
        
        # Calcular monto total
        amount = (
            (total_simple * monto_simple) +
            (total_maternal * monto_maternal) +
            (total_invalid * monto_invalid)
        )
        
        # Crear línea
        payslip.env['hr.payslip.line'].create({
            'slip_id': payslip.id,
            'code': 'ASIGFAM',
            'name': f'Asignación Familiar (Tramo {tramo})',
            'sequence': 30,
            'category_id': payslip.env.ref(
                'l10n_cl_hr_payroll.category_legal_allowance_sopa'
            ).id,
            'amount': amount,
            'quantity': total_simple + total_maternal + total_invalid,
            'rate': 0,
            'total': amount,
        })
        
        _logger.info(
            f"Asignación familiar calculada: {amount} "
            f"(tramo {tramo}, {total_simple}S + {total_maternal}M + {total_invalid}I)"
        )
```

**Tiempo:** 8 horas

---

### **Sprint 4.3: Aportes Empleador Reforma 2025** (8h)

#### **Contexto Legal**

Reforma Previsional 2025:
- **Aporte gradual empleador a cuenta individual trabajador**
- **Calendario:**
  - 2024: 0.5%
  - 2025: 1.0%
  - 2026: 1.5%
  - ...
  - 2031+: 3.5%
- **Base:** Total imponible
- **Tope:** 87.8 UF

#### **Implementación**

```python
# models/hr_payslip.py - AGREGAR

def _compute_employer_contribution_lines(self):
    """
    Calcular aportes empleador (Reforma 2025)
    
    Técnica Odoo 19 CE:
    - Determina tasa según año
    - Calcula sobre total imponible
    - NO se descuenta al trabajador (informativo)
    """
    for payslip in self:
        # Determinar tasa según año
        year = payslip.date_from.year
        
        if year < 2024:
            rate = 0.0
        elif year == 2024:
            rate = 0.005
        elif year == 2025:
            rate = 0.010
        elif year == 2026:
            rate = 0.015
        elif year == 2027:
            rate = 0.020
        elif year == 2028:
            rate = 0.025
        elif year == 2029:
            rate = 0.030
        else:  # 2030+
            rate = 0.035
        
        if rate == 0:
            continue
        
        # Base: Total imponible con tope
        afp_limit_clp = payslip.indicadores_id.uf * 87.8
        base = min(payslip.total_imponible, afp_limit_clp)
        
        amount = base * rate
        
        # Crear línea (informativa, NO es descuento)
        payslip.env['hr.payslip.line'].create({
            'slip_id': payslip.id,
            'code': 'APORTE_EMP_AFP',
            'name': f'Aporte Empleador AFP ({rate*100:.1f}%)',
            'sequence': 200,
            'category_id': payslip.env.ref(
                'l10n_cl_hr_payroll.category_aportes'
            ).id,
            'amount': amount,
            'quantity': 1,
            'rate': rate * 100,
            'total': amount,
        })
        
        _logger.info(f"Aporte empleador AFP: {amount} ({rate*100}% sobre {base})")
        
        # AFC Empleador (2.4%)
        afc_tope = payslip.indicadores_id.uf * 120.2
        base_afc = min(payslip.total_imponible, afc_tope)
        afc_amount = base_afc * 0.024
        
        payslip.env['hr.payslip.line'].create({
            'slip_id': payslip.id,
            'code': 'AFC_EMP',
            'name': 'AFC Empleador (2.4%)',
            'sequence': 201,
            'category_id': payslip.env.ref(
                'l10n_cl_hr_payroll.category_aportes'
            ).id,
            'amount': afc_amount,
            'quantity': 1,
            'rate': 2.4,
            'total': afc_amount,
        })
```

**Tiempo:** 8 horas

---

### **Sprint 4.4: Testing + Validaciones** (8h)

- Tests automatizados (pytest)
- Validaciones edge cases
- Documentación

**Tiempo:** 8 horas

---

## 🔥 FASE 2: REPORTES LEGALES CORE (40h)

Ver análisis completo en documento `27_ANALISIS_STACK_COMPLETO_PAYROLL.md` sección 9.

### **Sprint 5.1: Liquidación Individual PDF** (12h)

Template QWeb completo con:
- Header empresa + trabajador
- Tabla haberes / descuentos
- Totalizadores
- Firmas
- Formato legal DT

**Tiempo:** 12 horas

---

### **Sprint 5.2: Libro de Remuneraciones Excel** (16h)

Wizard + generación Excel con:
- 40+ columnas requeridas
- Formato DT oficial
- Filtros por periodo
- Totales y subtotales

**Tiempo:** 16 horas

---

### **Sprint 5.3: Resumen Contable** (8h)

Integración contable:
- Asientos automáticos
- Cuentas parametrizables
- Resumen PDF/Excel

**Tiempo:** 8 horas

---

## 🔥 FASE 3: PREVIRED + FINIQUITO BASE (40h)

### **Sprint 6.1: Previred 105 Campos** (24h)

**Complejidad:** ALTA (105 campos posiciones fijas)

#### **Estructura Archivo**

```
Línea 710 caracteres (sin delimitadores):

Posiciones 1-10:    RUT empleador
Posición 11:        DV empleador
Posiciones 12-21:   RUT trabajador
Posición 22:        DV trabajador
Posiciones 23-52:   Apellido paterno (30 chars)
Posiciones 53-82:   Apellido materno (30 chars)
Posiciones 83-112:  Nombres (30 chars)
...
Posiciones 701-710: Campo control
```

#### **Wizard**

```python
# wizards/wizard_export_previred.py - CREAR

class WizardExportPrevired(models.TransientModel):
    _name = 'wizard.export.previred'
    _description = 'Exportar Previred'
    
    month = fields.Selection([...], required=True)
    year = fields.Char(required=True)
    company_id = fields.Many2one('res.company', required=True)
    
    # Campos opcionales
    movement_type = fields.Selection([
        ('0', 'Sin movimiento'),
        ('1', 'Cotización normal'),
        ('2', 'Licencia médica'),
        ('3', 'Subsidio'),
        # ... más tipos
    ])
    
    def action_generate(self):
        """Generar archivo Previred TXT"""
        
        # Buscar liquidaciones del periodo
        payslips = self._get_payslips()
        
        # Generar líneas
        lines = []
        for payslip in payslips:
            line = self._build_previred_line(payslip)
            lines.append(line)
        
        # Crear archivo
        content = '\r\n'.join(lines)  # CRLF requerido
        
        # Encoding ISO-8859-1 requerido
        attachment = self.env['ir.attachment'].create({
            'name': f'Previred_{self.year}{self.month}.txt',
            'datas': base64.b64encode(content.encode('iso-8859-1')),
            'mimetype': 'text/plain',
        })
        
        return self._download_attachment(attachment)
    
    def _build_previred_line(self, payslip):
        """
        Construir línea 710 caracteres
        
        Técnica: Clase helper PreviredLineBuilder
        """
        builder = PreviredLineBuilder(payslip)
        
        # Campos 1-105
        builder.add_rut_employer()
        builder.add_rut_employee()
        builder.add_employee_names()
        builder.add_dates()
        builder.add_amounts()
        # ... 100 campos más
        
        line = builder.build()
        
        # Validar largo
        if len(line) != 710:
            raise ValidationError(
                f"Línea Previred debe tener 710 caracteres, tiene {len(line)}"
            )
        
        return line


class PreviredLineBuilder:
    """Helper para construir línea Previred"""
    
    def __init__(self, payslip):
        self.payslip = payslip
        self.line = ""
    
    def add_rut_employer(self):
        """Campos 1-2: RUT empleador (10) + DV (1)"""
        rut_full = self.payslip.company_id.vat.replace('.', '').replace('-', '')
        rut = rut_full[:-1].rjust(10, '0')
        dv = rut_full[-1]
        self.line += rut + dv
    
    def add_rut_employee(self):
        """Campos 3-4: RUT trabajador (10) + DV (1)"""
        rut_full = self.payslip.employee_id.identification_id.replace('.', '').replace('-', '')
        rut = rut_full[:-1].rjust(10, '0')
        dv = rut_full[-1]
        self.line += rut + dv
    
    def add_employee_names(self):
        """Campos 5-7: Apellidos y nombres (30+30+30)"""
        # Split name
        names = self.payslip.employee_id.name.split()
        
        paterno = names[0] if len(names) > 0 else ""
        materno = names[1] if len(names) > 1 else ""
        nombres = " ".join(names[2:]) if len(names) > 2 else ""
        
        self.line += paterno.ljust(30)[:30]
        self.line += materno.ljust(30)[:30]
        self.line += nombres.ljust(30)[:30]
    
    # ... 100 métodos más
    
    def build(self):
        """Retornar línea completa"""
        return self.line
```

**Tiempo:** 24 horas

---

### **Sprint 6.2: Finiquito Base** (16h)

Modelo básico + cálculos esenciales:
- Sueldo proporcional
- Vacaciones proporcionales
- Indemnizaciones básicas
- Descuentos

**Tiempo:** 16 horas

---

## 🔥 FASE 4: PAYROLL-SERVICE (40h)

### **Arquitectura Microservicio**

```
payroll-service/
├── main.py                      # FastAPI app
├── routers/
│   ├── calculations.py          # Endpoints cálculos
│   ├── previred.py              # Scraping Previred
│   └── finiquito.py             # Cálculos finiquito
├── services/
│   ├── gratification_service.py # Lógica gratificación
│   ├── settlement_service.py    # Lógica finiquito
│   └── scraper_service.py       # Scraping Previred
├── models/
│   ├── payroll_models.py        # Pydantic models
│   └── previred_models.py
├── utils/
│   ├── calculations.py          # Helpers cálculo
│   └── validators.py
└── tests/
    ├── test_calculations.py
    └── test_scraper.py
```

### **Sprint 7.1: Setup FastAPI** (8h)

```python
# main.py

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer
import uvicorn

app = FastAPI(
    title="Payroll Service",
    description="Microservicio de cálculos de nómina Chile",
    version="1.0.0"
)

security = HTTPBearer()

@app.get("/")
def root():
    return {"service": "payroll", "status": "ok", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)
```

**docker-compose.yml update:**

```yaml
payroll-service:
  build: ./payroll-service
  container_name: payroll-service
  ports:
    - "8003:8003"
  environment:
    - REDIS_URL=redis://redis:6379
    - ODOO_URL=http://odoo:8069
  depends_on:
    - redis
  networks:
    - odoo_network
```

**Tiempo:** 8 horas

---

### **Sprint 7.2: Gratificación Endpoint** (8h)

```python
# routers/calculations.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

router = APIRouter(prefix="/api/v1/calculations", tags=["calculations"])

class GratificationRequest(BaseModel):
    employee_id: int
    base_amount: float
    company_profits: float
    total_employees_base: float
    year: int

class GratificationResponse(BaseModel):
    monthly_amount: float
    annual_amount: float
    is_capped: bool
    cap_amount: float

@router.post("/gratification", response_model=GratificationResponse)
async def calculate_gratification(req: GratificationRequest):
    """
    Calcular gratificación legal
    
    - 25% utilidades distribuido proporcionalmente
    - Tope 4.75 IMM
    """
    from services.gratification_service import GratificationService
    
    service = GratificationService()
    result = service.calculate(
        base_amount=req.base_amount,
        company_profits=req.company_profits,
        total_employees_base=req.total_employees_base,
        year=req.year
    )
    
    return result
```

**Tiempo:** 8 horas

---

### **Sprint 7.3-7.5: Resto endpoints** (24h)

- Finiquito endpoint (8h)
- Scraper Previred (8h)
- Testing + CI/CD (8h)

---

## 🔥 FASE 5: FINIQUITO COMPLETO + POLISH (37h)

### **Sprint 8.1: Finiquito Avanzado** (16h)

Completar:
- Todas las indemnizaciones
- Reporte PDF legal
- Workflow completo
- Firma digital

**Tiempo:** 16 horas

---

### **Sprint 8.2-8.5: Completar detalles** (21h)

- Lotes nómina (8h)
- Ficha trabajador (4h)
- Testing integral (9h)

---

## ✅ CHECKLIST DE CIERRE

### **Módulo Odoo (l10n_cl_hr_payroll)**

- [ ] Ficha trabajador (campos Previred)
- [ ] Contrato completo (5 campos adicionales)
- [ ] Inputs SOPA (8 inputs adicionales)
- [ ] **Gratificación Legal** 🔴
- [ ] **Asignación Familiar** 🔴
- [ ] **Aportes Empleador** 🔴
- [ ] **Liquidación PDF** 🔴
- [ ] **Libro Remuneraciones** 🔴
- [ ] **Previred 105 campos** 🔴
- [ ] **Finiquito completo** 🔴
- [ ] Lotes nómina (totalizadores)
- [ ] F30-1 (reporte anual)
- [ ] Resumen contable

### **Payroll-Service**

- [ ] Setup FastAPI 🔴
- [ ] Endpoint gratificación 🔴
- [ ] Endpoint finiquito 🔴
- [ ] Scraper Previred 🔴
- [ ] Tests (80% coverage) 🔴
- [ ] CI/CD pipeline 🔴
- [ ] Documentación API 🔴

### **AI-Service Extension** (Opcional)

- [ ] Validación contratos
- [ ] Chat laboral
- [ ] Analytics predictivo

### **Testing & QA**

- [ ] Tests unitarios (80% coverage)
- [ ] Tests integración
- [ ] Validación con datos reales
- [ ] Performance tests

### **Documentación**

- [ ] README actualizado
- [ ] Guía de usuario
- [ ] API documentation
- [ ] Troubleshooting guide

---

## 🎯 RESULTADO ESPERADO

### **Estado Final: 100%**

```
MÓDULO ODOO:              100% ████████████████████
PAYROLL-SERVICE:          100% ████████████████████
AI-SERVICE:               100% ████████████████████
─────────────────────────────────────────────────────
TOTAL PROYECTO:           100% ████████████████████

✅ Sistema completo y operacional
✅ Compliance 100% DT/SII/Previred
✅ Tests automatizados
✅ Documentación completa
✅ Listo para producción
```

### **Paridad con SOPA 2025**

| Feature | SOPA 2025 | Odoo 19 Final | Status |
|---------|-----------|---------------|--------|
| Categorías SOPA | ✅ | ✅ | ✅ |
| Cálculos base | ✅ | ✅ | ✅ |
| Gratificación | ✅ | ✅ | ✅ |
| Asignación familiar | ✅ | ✅ | ✅ |
| Previred | ✅ | ✅ | ✅ |
| Finiquito | ✅ | ✅ | ✅ |
| Reportes legales | ✅ | ✅ | ✅ |
| **TOTAL** | **100%** | **100%** | **✅** |

---

## 📊 INVERSIÓN

| Fase | Horas | Días | Costo ($100/h) |
|------|-------|------|----------------|
| Fase 1: Reglas Salariales | 40h | 5 | $4,000 |
| Fase 2: Reportes Core | 40h | 5 | $4,000 |
| Fase 3: Previred + Finiquito | 40h | 5 | $4,000 |
| Fase 4: Payroll-Service | 40h | 5 | $4,000 |
| Fase 5: Finiquito + Polish | 37h | 5 | $3,700 |
| **TOTAL** | **197h** | **25 días** | **$19,700** |

**Timeline:** 5 semanas (1 mes + 1 semana)

---

## 🚀 PRÓXIMOS PASOS

1. **Aprobar plan** ✅
2. **Asignar equipo** (1 dev Odoo + 1 dev Python)
3. **Iniciar Fase 1** (Reglas Salariales)
4. **Daily standups** (15 min)
5. **Demo semanal** (viernes)

---

**Plan generado:** 2025-10-23  
**Autor:** Claude AI + Pedro  
**Versión:** 1.0  
**Estado:** ✅ PLAN COMPLETO - LISTO PARA EJECUCIÓN
