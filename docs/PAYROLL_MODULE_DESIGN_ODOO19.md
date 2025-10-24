# 🏗️ DISEÑO MÓDULO: l10n_cl_hr_payroll (Odoo 19 CE)

**Fecha:** 2025-10-22  
**Patrón:** Microservicios + IA (igual que DTE)  
**Filosofía:** **EXTENDER, NO DUPLICAR**

---

## 🎯 OBJETIVO

Diseñar módulo nóminas Odoo 19 CE siguiendo **patrón exitoso DTE**:
- ✅ Arquitectura microservicios
- ✅ Integración IA (Claude)
- ✅ Aprovecha Odoo base (hr_payroll)
- ✅ Testing 80%
- ✅ Scoring: 90+ (World-Class)

---

## 📊 PATRÓN DTE (Referencia - 78/100)

```
ODOO (l10n_cl_dte)
  ├─ _inherit = 'account.move' ✅ EXTIENDE
  ├─ Campos DTE específicos
  └─ Orquesta microservicios
       ↓
DTE-SERVICE (FastAPI)     AI-SERVICE (Claude)
  ├─ Generación XML         ├─ Pre-validación
  ├─ Firma digital          ├─ Chat soporte
  └─ Envío SII              └─ Matching
```

**Éxitos:** Integración Odoo 97/100, Contingencia robusta, Testing 80%

---

## 🏗️ PATRÓN PAYROLL (Diseño)

```
ODOO (l10n_cl_hr_payroll)
  ├─ _inherit = 'hr.payslip' ✅ EXTIENDE
  ├─ _inherit = 'hr.contract' ✅ EXTIENDE
  ├─ Campos Chile específicos
  └─ Orquesta microservicios
       ↓
PAYROLL-SERVICE (FastAPI)  AI-SERVICE (Claude)
  ├─ Cálculos AFP/Salud      ├─ Validación contratos
  ├─ Impuesto único          ├─ Detección anomalías
  ├─ Previred                ├─ Optimización tributaria
  └─ Finiquito               └─ Chat laboral
```

---

## 📦 ESTRUCTURA MÓDULO

```
l10n_cl_hr_payroll/
├── __manifest__.py
├── models/
│   ├── hr_contract_cl.py (_inherit hr.contract)
│   ├── hr_payslip_cl.py (_inherit hr.payslip)
│   ├── hr_settlement.py (Finiquito)
│   ├── hr_afp.py (Maestro AFPs)
│   ├── hr_isapre.py (Maestro ISAPREs)
│   └── hr_economic_indicators.py (UF/UTM/UTA)
├── wizards/
│   ├── previred_export_wizard.py
│   └── settlement_wizard.py
├── tools/
│   ├── payroll_api_client.py (Cliente Payroll-Service)
│   └── ai_api_client.py (Cliente AI-Service)
├── views/
├── data/
├── security/
├── reports/
└── tests/ (80% coverage)
```

---

## 🔧 MODELOS CLAVE

### **1. hr_contract_cl.py**

```python
class HrContractCL(models.Model):
    _inherit = 'hr.contract'  # ✅ EXTIENDE
    
    # Solo campos Chile específicos
    afp_id = fields.Many2one('hr.afp')
    isapre_id = fields.Many2one('hr.isapre')
    isapre_plan_uf = fields.Float('Plan ISAPRE (UF)')
    colacion = fields.Monetary('Colación Art. 41 CT')
    movilizacion = fields.Monetary('Movilización Art. 41 CT')
    family_allowance_simple = fields.Integer('Cargas')
    gratification_type = fields.Selection([...])
    weekly_hours = fields.Integer(default=44)
    extreme_zone = fields.Boolean('Zona Extrema')
```

### **2. hr_payslip_cl.py**

```python
class HrPayslipCL(models.Model):
    _inherit = 'hr.payslip'  # ✅ EXTIENDE
    
    # Previred
    previred_sent = fields.Boolean()
    previred_file = fields.Binary()
    
    # Indicadores (snapshot)
    indicator_id = fields.Many2one('hr.economic.indicators')
    indicators_snapshot = fields.Text('JSON')
    
    # IA
    ai_validated = fields.Boolean()
    ai_warnings = fields.Text()
    
    def action_compute_sheet(self):
        # 1. Preparar datos
        data = self._prepare_payroll_data()
        
        # 2. Llamar Payroll-Service
        response = requests.post(
            f"{PAYROLL_SERVICE_URL}/api/payroll/calculate",
            json=data
        )
        
        # 3. Validar con IA
        ai_result = self._validate_with_ai(response.json())
        
        # 4. Aplicar resultados
        self._apply_calculation_results(response.json())
        
        # 5. Super() para workflow Odoo
        return super().action_compute_sheet()
```

---

## 🎯 COMPARATIVA DTE vs PAYROLL

| Aspecto | DTE | Payroll |
|---------|-----|---------|
| **Complejidad** | Media | Alta |
| **Evento** | Puntual | Mensual recurrente |
| **Cálculos** | XML simple | Matemáticos complejos |
| **Validación** | SII externo | Interna + Previred |
| **IA valor** | Medio | Alto |
| **Testing crítico** | Sí | Muy crítico |

**Conclusión:** Payroll es MÁS COMPLEJO → Microservicio es CRÍTICO

---

## 📋 __manifest__.py

```python
{
    'name': 'Chilean Localization - Payroll & HR',
    'version': '19.0.1.0.0',
    'category': 'Human Resources/Payroll',
    'depends': [
        'base',
        'hr',
        'hr_contract',
        'hr_payroll',          # ✅ Base Odoo
        'hr_payroll_account',
        'hr_work_entry',
        'hr_holidays',
        'l10n_cl',             # ✅ Localización Chile
        'account',
    ],
    'external_dependencies': {
        'python': ['requests', 'num2words'],
    },
    'data': [
        'security/ir.model.access.csv',
        'data/hr_afp_data.xml',
        'data/hr_isapre_data.xml',
        'views/hr_contract_views.xml',
        'views/hr_payslip_views.xml',
        'wizards/previred_export_wizard_views.xml',
    ],
    'installable': True,
    'application': True,
}
```

---

## 🚀 INTEGRACIÓN CON MICROSERVICIOS

### **Payroll-Service API**

```python
# Endpoint principal
POST /api/payroll/calculate
{
  "employee": {...},
  "contract": {
    "wage": 1500000,
    "afp_rate": 0.1144,
    "isapre_plan_uf": 2.5,
    "family_allowances": {"simple": 2}
  },
  "period": {"date_from": "2025-10-01"}
}

Response:
{
  "gross_salary": 1500000,
  "afp_amount": 171600,
  "health_amount": 95000,
  "tax_amount": 45000,
  "net_salary": 1188400,
  "employer_contribution": 7500  # Reforma 2025
}
```

### **AI-Service API**

```python
POST /api/payroll/validate
{
  "payslip_data": {...}
}

Response:
{
  "valid": true,
  "warnings": [
    "Sueldo 20% superior al promedio del cargo",
    "Considerar APV para optimizar impuesto"
  ],
  "suggestions": [...]
}
```

---

## ✅ VENTAJAS vs ODOO 11

| Aspecto | Odoo 11 | Odoo 19 (Diseño) |
|---------|---------|------------------|
| Arquitectura | Monolito | Microservicios ✅ |
| LOC | 50,000 | ~5,000 ✅ |
| Escalabilidad | Vertical | Horizontal ✅ |
| IA | ❌ | Claude ✅ |
| Testing | 0% | 80% ✅ |
| Mantenibilidad | Baja | Alta ✅ |
| Reforma 2025 | Parcial | Completa ✅ |

---

## 📊 ROADMAP IMPLEMENTACIÓN

### **FASE 1: Core (4 semanas)**
- Módulo Odoo (modelos, vistas)
- Payroll-Service (calculadoras)
- Liquidaciones básicas

### **FASE 2: Compliance (3 semanas)**
- Previred (archivo 105 campos)
- Finiquito
- Audit trail

### **FASE 3: IA (3 semanas)**
- Validación contratos
- Optimización tributaria
- Chat laboral

**Total:** 10 semanas | $24,000 USD

---

## 🎯 SCORING ESPERADO

- **Compliance Legal:** 95/100
- **Robustez Técnica:** 90/100
- **Escalabilidad:** 95/100
- **IA/Innovación:** 100/100
- **TOTAL:** **95/100** 🏆 **WORLD-CLASS**

vs DTE actual: 78/100 (+17 puntos)

---

## ✅ PRÓXIMOS PASOS

1. ✅ Aprobar diseño arquitectónico
2. ⏳ Crear estructura módulo
3. ⏳ Implementar modelos base
4. ⏳ Desarrollar Payroll-Service
5. ⏳ Integrar AI-Service
6. ⏳ Testing 80%

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ LISTO PARA IMPLEMENTACIÓN
