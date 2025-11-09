# 🔄 ACTUALIZACIÓN ARQUITECTURA: Simplificación con EERGY AI

**Fecha:** 2025-10-22  
**Decisión:** Reutilizar EERGY AI Microservice completo

---

## 📊 ARQUITECTURA ANTERIOR (Plan Original)

```
ODOO 19 CE
└─ l10n_cl_hr_payroll

PAYROLL-SERVICE (A desarrollar)
├─ Calculadoras
├─ Previred generator
└─ Finiquito

AI-SERVICE (A desarrollar)
├─ Validación
└─ Chat

EMPLOYEE-PORTAL (A desarrollar)
└─ Portal empleados
```

**Problema:** 3 microservicios a desarrollar desde cero (4-6 semanas)

---

## ✅ ARQUITECTURA ACTUALIZADA (Simplificada)

```
ODOO 19 CE
└─ l10n_cl_hr_payroll
   ├─ Modelos (hr.contract, hr.payslip, hr.economic.indicators)
   ├─ Vistas XML
   └─ Integración → EERGY AI

EERGY AI MICROSERVICE ✅ REUTILIZAR (Ya existe)
├─ Extracción Indicadores
│  ├─ Previred: 60 campos desde PDF
│  └─ SII: 32 campos tabla impuesto
├─ Portal Empleados
│  ├─ SQL Direct (8ms)
│  ├─ JWT Authentication
│  └─ 6 KPIs lifetime
├─ Validación IA
│  ├─ Claude API
│  └─ Contratos + Liquidaciones
├─ Chat Laboral
│  └─ Consultas con Claude
└─ Enterprise Features
   ├─ Audit Trail (Blockchain)
   ├─ Logging estructurado
   ├─ Métricas Prometheus
   └─ Alertas Slack
```

**Ventaja:** 1 microservicio ya existente (1 día adaptación)

---

## 🎯 DECISIÓN: INDICADORES ECONÓMICOS

### **Búsqueda, Análisis, Validación y Guardado**

**Implementación con EERGY AI:**

```python
# models/hr_economic_indicators.py

class HrEconomicIndicators(models.Model):
    _name = 'hr.economic.indicators'
    
    # Campos (60 desde Previred)
    uf = fields.Float('UF', digits=(10, 2))
    utm = fields.Float('UTM', digits=(10, 2))
    uta = fields.Float('UTA', digits=(10, 2))
    minimum_wage = fields.Float('Sueldo Mínimo')
    afp_limit = fields.Float('Tope AFP (UF)', default=87.8)
    # ... 55 campos más
    
    @api.model
    def fetch_from_ai_service(self, year, month):
        """
        BÚSQUEDA: Llamar EERGY AI para obtener indicadores
        ANÁLISIS: Claude API parsea PDF oficial
        VALIDACIÓN: Coherencia automática
        GUARDADO: Crear registro en BBDD
        """
        import requests
        import os
        
        ai_service_url = os.getenv('AI_SERVICE_URL', 'http://eergy-ai:8002')
        
        # 1. BÚSQUEDA - Llamar microservicio
        response = requests.post(
            f"{ai_service_url}/api/v1/scraping/previred",
            json={
                "context": {"periodo": f"{year}-{month:02d}"},
                "fields_count": 60
            },
            timeout=60
        )
        
        response.raise_for_status()
        result = response.json()
        
        if not result.get('success'):
            raise UserError(_("Error obteniendo indicadores: %s") % result.get('detail'))
        
        # 2. ANÁLISIS - Datos ya parseados por Claude
        data = result['data']
        metadata = result['metadata']
        
        _logger.info(
            "✅ Indicadores obtenidos desde %s (modelo: %s, costo: $%.4f)",
            metadata['source'],
            metadata['model_used'],
            metadata['cost_usd']
        )
        
        # 3. VALIDACIÓN - Verificar campos críticos
        required_fields = ['uf', 'utm', 'uta', 'sueldo_minimo']
        for field in required_fields:
            if not data.get(field) or data[field] <= 0:
                raise ValidationError(
                    _("Campo '%s' inválido: %s") % (field, data.get(field))
                )
        
        # Validación coherencia
        if data['utm'] < data['uf']:
            raise ValidationError(
                _("Incoherencia: UTM (%.2f) < UF (%.2f)") % (data['utm'], data['uf'])
            )
        
        # 4. GUARDADO - Crear registro en BBDD
        period = date(year, month, 1)
        
        indicator = self.create({
            'period': period,
            'uf': data['uf'],
            'utm': data['utm'],
            'uta': data['uta'],
            'minimum_wage': data['sueldo_minimo'],
            'afp_limit': data.get('afp_tope_uf', 87.8),
            'family_allowance_t1': data.get('asig_fam_tramo_1', 0),
            'family_allowance_t2': data.get('asig_fam_tramo_2', 0),
            'family_allowance_t3': data.get('asig_fam_tramo_3', 0),
            # ... 52 campos más
        })
        
        _logger.info(
            "✅ Indicadores %s guardados en BBDD (ID: %d)",
            period.strftime('%Y-%m'),
            indicator.id
        )
        
        return indicator
    
    @api.model
    def get_indicator_for_payslip(self, payslip_date):
        """
        Obtener indicador para cálculo de nómina
        
        Uso en hr.payslip:
        >>> indicator = self.env['hr.economic.indicators'].get_indicator_for_payslip(
        >>>     self.date_from
        >>> )
        >>> uf_value = indicator.uf
        >>> afp_limit_clp = indicator.uf * indicator.afp_limit
        """
        period = date(payslip_date.year, payslip_date.month, 1)
        
        indicator = self.search([('period', '=', period)], limit=1)
        
        if not indicator:
            raise UserError(_(
                "No se encontraron indicadores para %s.\n\n"
                "Acciones:\n"
                "• Ir a Nóminas > Configuración > Indicadores Económicos\n"
                "• Clic en 'Obtener desde Previred'\n"
                "• Seleccionar período %s-%02d"
            ) % (period.strftime('%B %Y'), payslip_date.year, payslip_date.month))
        
        return indicator
```

---

## 🔄 FLUJO COMPLETO

### **1. Carga Indicadores (Mensual)**

```
Usuario en Odoo
    │
    ├─> Clic "Obtener desde Previred"
    │
    ▼
Odoo: fetch_from_ai_service(2025, 10)
    │
    ├─> POST http://eergy-ai:8002/api/v1/scraping/previred
    │   Body: {"context": {"periodo": "2025-10"}}
    │
    ▼
EERGY AI Microservice
    │
    ├─> 1. Descarga PDF desde Previred.com
    │      https://www.previred.com/.../Indicadores-Octubre-2025.pdf
    │
    ├─> 2. Parsea PDF con Claude API
    │      Extrae 60 campos
    │
    ├─> 3. Valida coherencia
    │      UF > 30k, UTM > UF, etc.
    │
    └─> 4. Retorna JSON
        {
          "success": true,
          "data": {
            "uf": 39383.07,
            "utm": 68647,
            // ... 58 campos más
          },
          "metadata": {
            "source": "previred_pdf",
            "cost_usd": 0.025
          }
        }
    │
    ▼
Odoo: Guarda en hr_economic_indicators
    │
    └─> INSERT INTO hr_economic_indicators (
          period, uf, utm, uta, ...
        ) VALUES (
          '2025-10-01', 39383.07, 68647, 823764, ...
        )
```

---

### **2. Uso en Cálculo Nómina**

```python
# models/hr_payslip.py

def action_compute_sheet(self):
    """Calcular liquidación"""
    
    # 1. Obtener indicadores del mes
    indicator = self.env['hr.economic.indicators'].get_indicator_for_payslip(
        self.date_from
    )
    
    # 2. Calcular con indicadores
    uf_value = indicator.uf
    afp_limit_clp = uf_value * indicator.afp_limit  # 87.8 UF
    
    # 3. Calcular AFP
    imponible = self.contract_id.wage
    if imponible > afp_limit_clp:
        imponible = afp_limit_clp
    
    afp_amount = imponible * (self.contract_id.afp_rate / 100)
    
    # 4. Crear línea
    self.env['hr.payslip.line'].create({
        'slip_id': self.id,
        'code': 'AFP',
        'name': f'AFP {self.contract_id.afp_id.name}',
        'amount': -afp_amount,
    })
```

---

## ✅ VENTAJAS DE ESTA ARQUITECTURA

### **1. Simplicidad**
- ✅ 1 microservicio vs 3
- ✅ Ya existe y funciona
- ✅ 1 día adaptación vs 4-6 semanas

### **2. Completitud**
- ✅ 92 variables automáticas (60 Previred + 32 SII)
- ✅ Portal empleados incluido
- ✅ Validación IA incluida
- ✅ Chat laboral incluido

### **3. Enterprise-Grade**
- ✅ Score 15.5/16
- ✅ Audit trail blockchain
- ✅ Logging estructurado
- ✅ Métricas Prometheus

### **4. Costo**
- ✅ $0.30 USD/año
- ✅ vs $2,400/año manual
- ✅ Ahorro 99.99%

### **5. Mantenimiento**
- ✅ Código ya probado
- ✅ Documentación completa
- ✅ Tests automatizados

---

## 📋 CAMBIOS EN DOCUMENTACIÓN

### **Archivos Actualizados:**
- ✅ `00_MASTER_PLAN.md` - Dimensiones actualizadas
- ✅ `01_BUSINESS_DOMAIN.md` - Extracción indicadores con EERGY AI
- ✅ `02_ARCHITECTURE.md` - Arquitectura simplificada
- ✅ `10_SEPARACION_RESPONSABILIDADES.md` - EERGY AI en lugar de 3 servicios

### **Archivos Nuevos:**
- ✅ `14_ANALISIS_SCRAPER_PREVIRED.md` - Análisis scraper
- ✅ `15_MICROSERVICIO_EERGY_AI.md` - Análisis completo microservicio
- ✅ `16_ACTUALIZACION_ARQUITECTURA.md` - Este documento

---

## 🎯 PRÓXIMOS PASOS

1. ✅ Documentación actualizada
2. Continuar implementación modelos Odoo
3. Agregar método `fetch_from_ai_service()`
4. Crear wizard carga indicadores
5. Testing integración

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ ARQUITECTURA ACTUALIZADA
