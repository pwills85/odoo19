# 🧪 ESTRATEGIA DE TESTING

**Proyecto:** l10n_cl_hr_payroll  
**Objetivo:** 80% coverage  
**Framework:** pytest + Odoo test framework

---

## 📊 PIRÁMIDE DE TESTING

```
        ┌─────────────┐
        │   E2E (5%)  │  8 tests
        │   Selenium  │
        └─────────────┘
       ┌───────────────┐
       │ Integración   │  32 tests
       │   (20%)       │
       └───────────────┘
      ┌─────────────────┐
      │   Unitarios     │  113 tests
      │     (75%)       │
      └─────────────────┘

TOTAL: 153 tests (80% coverage)
```

---

## 🎯 TESTS UNITARIOS (113 tests)

### **Payroll-Service (68 tests)**

#### AFPCalculator (10 tests)
```python
def test_afp_capital_rate():
    """Test tasa AFP Capital (11.44%)"""
    calc = AFPCalculator()
    result = calc.calculate(
        taxable_income=1500000,
        afp_name='capital',
        employee_age=35
    )
    assert result['rate'] == 0.1144
    assert result['amount'] == 171600

def test_afp_tope_imponible():
    """Test tope 83.1 UF"""
    calc = AFPCalculator()
    result = calc.calculate(
        taxable_income=5000000,  # Excede tope
        afp_name='capital',
        employee_age=35
    )
    assert result['tope_applied'] == True
    assert result['taxable_income'] == 3157800  # 83.1 * 38000

def test_afp_ajuste_edad_55():
    """Test ajuste por edad 55+"""
    # ... (8 tests más)
```

#### HealthCalculator (8 tests)
```python
def test_fonasa_7_percent():
    """Test FONASA 7% fijo"""
    
def test_isapre_plan_uf():
    """Test ISAPRE plan en UF"""
    
def test_isapre_excedente():
    """Test excedente ISAPRE como haber"""
    # ... (5 tests más)
```

#### TaxCalculator (15 tests)
```python
def test_tax_tramo_exento():
    """Test tramo exento (0-13.5 UTA)"""
    
def test_tax_tramo_2():
    """Test tramo 2 (13.5-30 UTA, 4%)"""
    
def test_tax_rebaja_cargas():
    """Test rebaja por cargas familiares"""
    
def test_tax_zona_extrema():
    """Test rebaja 50% zona extrema"""
    # ... (11 tests más)
```

#### GratificationCalculator (8 tests)
```python
def test_gratificacion_legal_25():
    """Test 25% utilidades"""
    
def test_gratificacion_tope_475_imm():
    """Test tope 4.75 IMM"""
    
def test_gratificacion_mensual():
    """Test gratificación mensual (1/12)"""
    # ... (5 tests más)
```

#### SettlementCalculator (10 tests)
```python
def test_finiquito_sueldo_proporcional():
    """Test sueldo proporcional"""
    
def test_finiquito_vacaciones_proporcionales():
    """Test vacaciones proporcionales (1.25 días/mes)"""
    
def test_finiquito_indemnizacion_años():
    """Test indemnización años servicio (tope 11)"""
    
def test_finiquito_aviso_previo():
    """Test indemnización aviso previo"""
    # ... (6 tests más)
```

#### PreviredGenerator (12 tests)
```python
def test_previred_105_campos():
    """Test archivo 105 campos"""
    
def test_previred_formato_fijo():
    """Test formato fijo"""
    
def test_previred_validacion():
    """Test validación formato"""
    # ... (9 tests más)
```

#### Validators (5 tests)
```python
def test_legal_validator():
    """Test validaciones legales"""
    
def test_mathematical_coherence():
    """Test coherencia matemática"""
    # ... (3 tests más)
```

---

### **Odoo Module (45 tests)**

#### Models (25 tests)
```python
class TestHrContractCL(TransactionCase):
    def test_contract_creation(self):
        """Test creación contrato Chile"""
        
    def test_contract_afp_validation(self):
        """Test validación AFP"""
        
    def test_contract_isapre_validation(self):
        """Test validación ISAPRE"""
        
    def test_contract_weekly_hours_constraint(self):
        """Test constraint jornada semanal"""
        # ... (21 tests más)

class TestHrPayslipCL(TransactionCase):
    def test_payslip_compute_sheet(self):
        """Test compute_sheet() completo"""
        
    def test_payslip_api_client_retry(self):
        """Test retry logic"""
        
    def test_payslip_circuit_breaker(self):
        """Test circuit breaker"""
        
    def test_payslip_indicators_snapshot(self):
        """Test snapshot indicadores (Odoo 11 pattern)"""
        # ... (más tests)
```

#### Wizards (10 tests)
```python
class TestPreviredExportWizard(TransactionCase):
    def test_wizard_generate_file(self):
        """Test generación archivo"""
        
    def test_wizard_validation(self):
        """Test validación"""
        # ... (8 tests más)
```

#### Tools (10 tests)
```python
class TestPayrollAPIClient(TransactionCase):
    def test_api_client_success(self):
        """Test llamada exitosa"""
        
    def test_api_client_timeout(self):
        """Test timeout"""
        
    def test_api_client_retry(self):
        """Test retry 3 intentos"""
        # ... (7 tests más)
```

---

## 🔗 TESTS DE INTEGRACIÓN (32 tests)

### **Odoo ↔ Payroll-Service (15 tests)**
```python
class TestPayrollIntegration(HttpCase):
    def test_full_payslip_calculation(self):
        """Test liquidación completa E2E"""
        # 1. Crear empleado + contrato
        # 2. Llamar compute_sheet()
        # 3. Verificar llamada a Payroll-Service
        # 4. Verificar resultados aplicados
        # 5. Verificar hr.payslip.line creadas
        
    def test_previred_generation(self):
        """Test generación Previred E2E"""
        
    def test_settlement_calculation(self):
        """Test finiquito E2E"""
        # ... (12 tests más)
```

### **Odoo ↔ AI-Service (10 tests)**
```python
class TestAIIntegration(HttpCase):
    def test_ai_validation(self):
        """Test validación IA"""
        
    def test_ai_anomaly_detection(self):
        """Test detección anomalías"""
        # ... (8 tests más)
```

### **Database (7 tests)**
```python
class TestDatabaseConstraints(TransactionCase):
    def test_payslip_unique_constraint(self):
        """Test constraint unicidad (Odoo 11 pattern)"""
        
    def test_audit_trail_retention(self):
        """Test retención 7 años"""
        # ... (5 tests más)
```

---

## 🌐 TESTS E2E (8 tests)

### **Selenium (8 tests)**
```python
class TestPayrollE2E(SeleniumTestCase):
    def test_create_contract_and_payslip(self):
        """Test flujo completo: contrato → liquidación"""
        # 1. Login
        # 2. Crear empleado
        # 3. Crear contrato
        # 4. Generar liquidación
        # 5. Validar resultados
        # 6. Exportar Previred
        
    def test_settlement_workflow(self):
        """Test flujo finiquito"""
        
    def test_ai_chat_interaction(self):
        """Test chat IA"""
        # ... (5 tests más)
```

---

## 📊 COVERAGE POR COMPONENTE

| Componente | Tests | Coverage |
|------------|-------|----------|
| **Payroll-Service** | 68 | 85% |
| - Calculators | 43 | 90% |
| - Generators | 22 | 80% |
| - Validators | 3 | 75% |
| **Odoo Module** | 45 | 80% |
| - Models | 25 | 85% |
| - Wizards | 10 | 75% |
| - Tools | 10 | 80% |
| **Integración** | 32 | 75% |
| **E2E** | 8 | N/A |
| **TOTAL** | **153** | **80%** |

---

## 🚀 EJECUCIÓN

### **Tests Unitarios**
```bash
# Payroll-Service
cd payroll-service
pytest tests/ -v --cov=. --cov-report=html

# Odoo Module
cd odoo19
./odoo-bin -c odoo.conf -d test_db -i l10n_cl_hr_payroll --test-enable --stop-after-init
```

### **Tests Integración**
```bash
pytest tests/integration/ -v --cov
```

### **Tests E2E**
```bash
pytest tests/e2e/ -v --headed  # Con UI
```

### **CI/CD (GitHub Actions)**
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: |
          pytest tests/ -v --cov --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

---

## ✅ CRITERIOS DE ACEPTACIÓN

### **Por Fase:**

**FASE 1 (Core):**
- [ ] 68 tests pasando
- [ ] Coverage > 80%
- [ ] Performance < 100ms p95 (calculadoras)

**FASE 2 (Compliance):**
- [ ] 40 tests adicionales
- [ ] Previred válido (validación externa)
- [ ] Finiquito correcto (casos legales)

**FASE 3 (IA):**
- [ ] 45 tests adicionales
- [ ] IA detecta anomalías (>90% accuracy)
- [ ] Chat responde correctamente (>85% accuracy)

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0
