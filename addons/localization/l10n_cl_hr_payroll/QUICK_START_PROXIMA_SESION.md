# 🚀 QUICK START - Próxima Sesión
# l10n_cl_hr_payroll - APV Integración + Indicadores Robustos

## ⚡ CONTEXTO RÁPIDO

**Completado en sesión anterior**:
- ✅ P0-1: Coherencia modelos/tests (100%)
- ✅ P0-3: Impuesto Único parametrizado (100%)
- ✅ P0-5: CI Gates iniciales (100%)

**Objetivo sesión actual**: Completar P0-2 (APV) + P0-4 (Indicadores) = P0 al 100%

---

## 📋 CHECKLIST PRE-START

```bash
# 1. Verificar estado actual
cd /Users/pedro/Documents/odoo19
git status
cat addons/localization/l10n_cl_hr_payroll/DASHBOARD_ESTADO.txt

# 2. Ejecutar CI Gates (debe pasar)
bash addons/localization/l10n_cl_hr_payroll/scripts/ci_gate_p0.sh

# 3. Leer documentos
cat addons/localization/l10n_cl_hr_payroll/RESUMEN_EJECUTIVO_P0.md
cat addons/localization/l10n_cl_hr_payroll/PROGRESO_CIERRE_BRECHAS.md
```

**Todos los checks deben estar ✅ antes de continuar.**

---

## 🎯 TAREA P0-2: APV INTEGRACIÓN (4 horas estimadas)

### Subtareas (orden de ejecución)

#### 1. Extender modelo hr_payslip.py (~60 min)
```python
# Ubicación: addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py

# Añadir método:
def _calculate_apv(self):
    """
    Calcular APV (Ahorro Previsional Voluntario)
    
    - Convertir UF → CLP usando indicadores
    - Régimen A (directo): rebaja directa base tributaria
    - Régimen B (indirecto): tratamiento diferenciado
    - Aplicar topes mensual/anual
    """
    if not self.contract_id.apv_id or self.contract_id.apv_amount_uf <= 0:
        return 0.0
    
    # Convertir UF a CLP
    uf_clp = self.indicadores_id.uf
    apv_clp = self.contract_id.apv_amount_uf * uf_clp
    
    # Aplicar tope mensual (TODO: obtener de parámetro)
    # Tope mensual = 600 UF anuales / 12 = 50 UF mensuales
    tope_mensual = 50 * uf_clp
    apv_clp = min(apv_clp, tope_mensual)
    
    return apv_clp

# Modificar método _get_total_previsional():
def _get_total_previsional(self):
    """Incluir APV en descuentos previsionales"""
    previsional_codes = ['AFP', 'HEALTH', 'APV']  # ← Añadir 'APV'
    
    previsional_lines = self.line_ids.filtered(
        lambda l: l.code in previsional_codes
    )
    
    total = sum(abs(line.total) for line in previsional_lines)
    return total
```

#### 2. Integrar en action_compute_sheet() (~30 min)
```python
# En action_compute_sheet(), después de calcular AFP/Salud:

# Calcular APV
if self.contract_id.apv_id:
    apv_amount = self._calculate_apv()
    
    if apv_amount > 0:
        # Crear línea APV
        apv_category = self.env.ref('l10n_cl_hr_payroll.category_desc_legal')
        
        self.env['hr.payslip.line'].create({
            'slip_id': self.id,
            'code': 'APV',
            'name': f'APV {self.contract_id.apv_id.name}',
            'sequence': 115,
            'category_id': apv_category.id,
            'amount': apv_amount,
            'quantity': 1.0,
            'rate': 0.0,
            'total': -apv_amount,  # Negativo = descuento
        })
        
        _logger.info(
            "APV calculado: $%s (régimen %s)",
            f"{apv_amount:,.0f}",
            self.contract_id.apv_type
        )
```

#### 3. Crear tests/test_apv.py (~90 min)
```python
# -*- coding: utf-8 -*-
from odoo.tests import tagged, TransactionCase
from datetime import date

@tagged('post_install', '-at_install', 'payroll_apv')
class TestAPV(TransactionCase):
    
    def setUp(self):
        super().setUp()
        # Setup empleado, contrato, indicadores, APV
        pass
    
    def test_apv_regimen_a_calculo(self):
        """Test APV régimen A: conversión UF → CLP"""
        pass
    
    def test_apv_regimen_b_calculo(self):
        """Test APV régimen B: tratamiento diferenciado"""
        pass
    
    def test_apv_tope_mensual(self):
        """Test tope mensual 50 UF aplicado"""
        pass
    
    def test_apv_sin_configurar(self):
        """Test liquidación sin APV funciona normal"""
        pass
    
    def test_apv_rebaja_base_tributaria(self):
        """Test APV reduce base para impuesto único"""
        pass
    
    def test_apv_en_total_previsional(self):
        """Test APV incluido en _get_total_previsional()"""
        pass
    
    def test_apv_monto_cero(self):
        """Test APV con monto 0 no crea línea"""
        pass
    
    def test_apv_multiple_periodos(self):
        """Test APV consistente en múltiples liquidaciones"""
        pass
```

#### 4. Actualizar __init__.py (~5 min)
```python
# tests/__init__.py
from . import test_apv
```

#### 5. Ejecutar tests (~15 min)
```bash
# Test solo APV
python3 odoo-bin -d test_payroll -i l10n_cl_hr_payroll --test-tags=payroll_apv --stop-after-init

# Test todos
python3 odoo-bin -d test_payroll -i l10n_cl_hr_payroll --test-enable --stop-after-init
```

---

## 🎯 TAREA P0-4: INDICADORES ROBUSTOS (3 horas estimadas)

### Subtareas

#### 1. Crear cron en data/ir_cron.xml (~30 min)
```xml
<?xml version="1.0" encoding="utf-8"?>
<odoo>
    <data noupdate="1">
        <record id="cron_fetch_economic_indicators" model="ir.cron">
            <field name="name">Fetch Economic Indicators Monthly</field>
            <field name="model_id" ref="model_hr_economic_indicators"/>
            <field name="state">code</field>
            <field name="code">model.cron_fetch_indicators()</field>
            <field name="interval_number">1</field>
            <field name="interval_type">months</field>
            <field name="numbercall">-1</field>
            <field name="doall" eval="False"/>
            <field name="active" eval="True"/>
            <field name="nextcall" eval="(DateTime.now() + relativedelta(months=1)).replace(day=1, hour=5, minute=0, second=0)"/>
        </record>
    </data>
</odoo>
```

#### 2. Implementar método cron_fetch_indicators() (~60 min)
```python
# models/hr_economic_indicators.py

@api.model
def cron_fetch_indicators(self):
    """
    Cron automático: obtener indicadores del mes siguiente
    
    Ejecuta día 1 de cada mes a las 05:00 AM
    Idempotente: si registro existe, no duplica
    """
    import logging
    _logger = logging.getLogger(__name__)
    
    today = date.today()
    next_month = (today.replace(day=1) + timedelta(days=32)).replace(day=1)
    
    # Verificar si ya existe
    existing = self.search([('period', '=', next_month)], limit=1)
    if existing:
        _logger.info("Indicadores %s ya existen (ID: %d), skip", 
                     next_month.strftime('%Y-%m'), existing.id)
        return existing
    
    # Intentar fetch desde AI-Service (con reintentos)
    year = next_month.year
    month = next_month.month
    
    for attempt in range(1, 4):  # 3 intentos
        try:
            indicator = self.fetch_from_ai_service(year, month)
            _logger.info("✅ Indicadores %s creados en intento %d", 
                         next_month.strftime('%Y-%m'), attempt)
            return indicator
            
        except Exception as e:
            _logger.warning("Intento %d/3 falló: %s", attempt, str(e))
            if attempt < 3:
                time.sleep(5 * attempt)  # Backoff exponencial
            else:
                _logger.error("❌ Todos los intentos fallaron. Usar wizard manual.")
                # Enviar notificación a admin
                self._notify_indicators_failure(year, month)
                raise

def _notify_indicators_failure(self, year, month):
    """Notificar a admin que debe cargar indicadores manualmente"""
    # TODO: Enviar email o crear activity
    pass
```

#### 3. Crear wizard manual fallback (~60 min)
```python
# wizards/hr_economic_indicators_wizard.py (nuevo archivo)

class HrEconomicIndicatorsWizard(models.TransientModel):
    _name = 'hr.economic.indicators.wizard'
    _description = 'Wizard Carga Manual Indicadores'
    
    period = fields.Date(string='Período', required=True)
    uf = fields.Float(string='UF', required=True)
    utm = fields.Float(string='UTM', required=True)
    uta = fields.Float(string='UTA', required=True)
    minimum_wage = fields.Float(string='Sueldo Mínimo', required=True)
    afp_limit = fields.Float(string='Tope AFP (UF)', default=87.8)
    
    def action_create_indicator(self):
        """Crear indicador manualmente"""
        self.env['hr.economic.indicators'].create({
            'period': self.period,
            'uf': self.uf,
            'utm': self.utm,
            'uta': self.uta,
            'minimum_wage': self.minimum_wage,
            'afp_limit': self.afp_limit,
        })
        
        return {'type': 'ir.actions.act_window_close'}
```

#### 4. Crear tests/test_indicators_robust.py (~45 min)
```python
def test_cron_creates_indicator(self):
    """Test cron crea indicador automáticamente"""
    pass

def test_cron_idempotent(self):
    """Test cron no duplica si existe"""
    pass

def test_fetch_retry_backoff(self):
    """Test reintentos con backoff exponencial"""
    pass

def test_wizard_manual_fallback(self):
    """Test wizard crea indicador correctamente"""
    pass

def test_indicator_consumed_by_payslip(self):
    """Test indicador creado es usado por liquidación"""
    pass
```

---

## ✅ CRITERIOS DE ACEPTACIÓN

### P0-2: APV
- [ ] Línea APV se crea en payslip con monto correcto
- [ ] Conversión UF → CLP usa indicadores del período
- [ ] Tope mensual 50 UF aplicado
- [ ] APV incluido en _get_total_previsional()
- [ ] APV rebaja base tributaria en impuesto único
- [ ] 8 tests pasan en verde
- [ ] Régimen A y B diferenciados

### P0-4: Indicadores
- [ ] Cron ejecuta automáticamente día 1 mes
- [ ] Cron es idempotente (no duplica)
- [ ] Reintentos (3) con backoff funcionan
- [ ] Wizard manual crea indicador válido
- [ ] Indicador creado es consumido por payslip
- [ ] 5 tests pasan en verde
- [ ] Logs estructurados informativos

---

## 🔍 VALIDACIÓN FINAL

```bash
# 1. CI Gates
bash addons/localization/l10n_cl_hr_payroll/scripts/ci_gate_p0.sh

# 2. Tests completos
python3 odoo-bin -d test_payroll -i l10n_cl_hr_payroll --test-enable --stop-after-init

# 3. Cobertura (meta: >=70% núcleo)
coverage run --source=addons/localization/l10n_cl_hr_payroll odoo-bin -d test_payroll -i l10n_cl_hr_payroll --test-enable --stop-after-init
coverage report -m

# 4. Actualizar dashboard
cat > addons/localization/l10n_cl_hr_payroll/DASHBOARD_ESTADO.txt << EOF
P0 (Critical): ████████████████████ 100% ✅
...
EOF
```

---

## 📞 CONTACTO SI BLOCKERS

- AI-Service no responde → Verificar docker-compose, logs
- Tests fallan → Revisar fixtures, datos mínimos
- Validaciones erróneas → Consultar normativa SII/Previred

---

**Tiempo estimado total**: 7 horas  
**Meta sesión**: P0 al 100% (APV + Indicadores funcionando)  
**Siguiente sesión**: Iniciar P1 (Finiquito + Previred)
