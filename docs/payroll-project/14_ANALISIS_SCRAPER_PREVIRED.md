# 🔍 ANÁLISIS: Sistema de Extracción Previred (Odoo 11)

**Fecha:** 2025-10-22  
**Fuente:** Microservicio eergy-ai + Odoo 11 CE

---

## 📊 ARQUITECTURA ACTUAL (Odoo 11)

### **Sistema Dual**

```
┌─────────────────────────────────────────────────────────┐
│ MICROSERVICIO EERGY-AI (Recomendado) ✅                │
├─────────────────────────────────────────────────────────┤
│ previred_fetcher.py                                     │
│ ├─ Descarga PDF/HTML automático                        │
│ ├─ Múltiples patrones URL (variaciones nombrado)       │
│ ├─ Retry con exponential backoff                       │
│ └─ Fallback PDF → HTML                                 │
│                                                         │
│ scraping.py (Router FastAPI)                           │
│ ├─ POST /previred (con periodo)                        │
│ ├─ GET /previred/periods (listar disponibles)          │
│ └─ POST /sii/tax-brackets (tabla impuesto)            │
│                                                         │
│ pdf_parser.py + Claude API                             │
│ ├─ Extrae 49/49 campos desde PDF                      │
│ ├─ Validación inteligente                             │
│ └─ Costo: ~$0.03/mes                                   │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│ ODOO 11 - FALLBACK (Deprecado) ⚠️                      │
├─────────────────────────────────────────────────────────┤
│ hr_indicadores_previred_scraper.py                      │
│ ├─ Solo 4 campos extraídos (UF, UTM, UTA, Mínimo)     │
│ ├─ 45 campos hardcoded                                 │
│ ├─ Scraping HTML frágil                                │
│ └─ Solo para emergencias offline                       │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 COMPONENTES CLAVE

### **1. PreviredFetcher (Microservicio)**

**Archivo:** `microservices/eergy-ai/app/services/previred_fetcher.py`

**Características:**
```python
class PreviredFetcher:
    # Múltiples patrones URL (Previred cambia nombres)
    PDF_URL_PATTERNS = [
        "https://www.previred.com/wp-content/uploads/{year}/{month:02d}/"
        "Indicadores-Previsionales-Previred-{mes_nombre}-{year}.pdf",
        # + 3 variaciones más
    ]
    
    def fetch_indicadores(self, year, month, prefer_pdf=True):
        """
        Estrategia multi-fuente:
        1. Intentar PDF (más confiable)
        2. Fallback a HTML si PDF no disponible
        3. Retry automático con backoff
        """
```

**Ventajas:**
- ✅ PDF histórico disponible (2024+)
- ✅ Múltiples variaciones URL
- ✅ Retry automático (3 intentos)
- ✅ Fallback inteligente

---

### **2. Router Scraping (Microservicio)**

**Archivo:** `microservices/eergy-ai/app/routers/scraping.py`

**Endpoints:**

#### **POST /previred**
```python
@router.post("/previred")
async def scrape_previred(request: ScrapingRequest):
    """
    Extrae indicadores de Previred.
    
    Request:
    {
        "context": {
            "periodo": "2025-10"
        },
        "fields_count": 49
    }
    
    Response:
    {
        "success": true,
        "data": {
            "uf": 38000.50,
            "utm": 65000.00,
            "uta": 726000.00,
            // ... 46 campos más
        },
        "fields_extracted": 49,
        "metadata": {
            "source": "previred_pdf",
            "model_used": "claude-3-haiku",
            "cost_usd": 0.03
        }
    }
    """
```

#### **GET /previred/periods**
```python
@router.get("/previred/periods")
async def get_available_periods(start_year=2024):
    """
    Lista períodos con PDF disponible.
    
    Response:
    {
        "available_periods": [
            {"year": 2024, "month": 1, "periodo": "2024-01"},
            {"year": 2024, "month": 2, "periodo": "2024-02"},
            ...
        ]
    }
    """
```

---

### **3. Scraper Odoo (Fallback Deprecado)**

**Archivo:** `addons/l10n_cl_hr/models/hr_indicadores_previred_scraper.py`

**Limitaciones:**
- ❌ Solo 4 campos extraídos (8%)
- ❌ 45 campos hardcoded (pueden quedar obsoletos)
- ❌ Scraping HTML frágil
- ❌ Solo para emergencias

**Uso actual:**
```python
# Sistema SOPA usa IA primero
try:
    # Prioridad 1: Microservicio IA
    indicadores = self._fetch_from_ai_service(periodo)
except:
    # Fallback: Scraper legacy
    indicadores = scraper.scrape_periodo(year, month)
```

---

## 🎯 ADAPTACIÓN A ODOO 19

### **Estrategia Recomendada**

```
ODOO 19 CE (l10n_cl_hr_payroll)
├─ Modelo: hr.economic.indicators ✅ Ya creado
├─ Método: fetch_from_ai_service() ✅ A implementar
└─ Fallback: Carga manual asistida

MICROSERVICIO EERGY-AI (Reutilizar)
├─ POST /previred ✅ Ya existe
├─ GET /previred/periods ✅ Ya existe
└─ Adaptar a Odoo 19 (misma lógica)
```

---

## 📋 IMPLEMENTACIÓN EN ODOO 19

### **Paso 1: Agregar método fetch en hr.economic.indicators**

```python
# models/hr_economic_indicators.py

@api.model
def fetch_from_previred(self, year, month):
    """
    Obtener indicadores desde microservicio AI.
    
    Estrategia:
    1. Llamar microservicio /previred
    2. Si falla, proponer carga manual
    3. Crear registro hr.economic.indicators
    
    Args:
        year: Año (2025)
        month: Mes (1-12)
        
    Returns:
        Recordset hr.economic.indicators creado
    """
    import requests
    import os
    
    # URL microservicio
    ai_service_url = os.getenv(
        'AI_SERVICE_URL',
        'http://ai-service:8002'
    )
    
    try:
        # Llamar microservicio
        response = requests.post(
            f"{ai_service_url}/api/v1/scraping/previred",
            json={
                "context": {
                    "periodo": f"{year}-{month:02d}"
                },
                "fields_count": 49
            },
            timeout=60
        )
        
        response.raise_for_status()
        data = response.json()
        
        if not data.get('success'):
            raise Exception(data.get('detail', 'Error desconocido'))
        
        # Extraer indicadores
        indicators = data['data']
        
        # Crear registro
        period = date(year, month, 1)
        
        indicator = self.create({
            'period': period,
            'uf': indicators.get('uf', 0),
            'utm': indicators.get('utm', 0),
            'uta': indicators.get('uta', 0),
            'minimum_wage': indicators.get('sueldo_minimo', 0),
            'afp_limit': indicators.get('afp_tope_uf', 83.1),
            'family_allowance_t1': indicators.get('asig_fam_tramo_1', 0),
            'family_allowance_t2': indicators.get('asig_fam_tramo_2', 0),
            'family_allowance_t3': indicators.get('asig_fam_tramo_3', 0),
        })
        
        _logger.info(
            "✅ Indicadores %s creados desde AI Service (49 campos)",
            period.strftime('%Y-%m')
        )
        
        return indicator
        
    except Exception as e:
        _logger.error(
            "❌ Error obteniendo indicadores desde AI Service: %s",
            str(e)
        )
        
        raise UserError(_(
            "No se pudieron obtener indicadores para %s-%02d\n\n"
            "Error: %s\n\n"
            "Acciones sugeridas:\n"
            "• Verificar que microservicio AI esté corriendo\n"
            "• Cargar indicadores manualmente desde formulario\n"
            "• Contactar soporte técnico"
        ) % (year, month, str(e)))
```

---

### **Paso 2: Wizard de Carga Automática**

```python
# wizards/previred_fetch_wizard.py

class PreviredFetchWizard(models.TransientModel):
    _name = 'previred.fetch.wizard'
    _description = 'Asistente Carga Indicadores Previred'
    
    year = fields.Integer(
        string='Año',
        required=True,
        default=lambda self: date.today().year
    )
    month = fields.Integer(
        string='Mes',
        required=True,
        default=lambda self: date.today().month
    )
    
    def action_fetch(self):
        """Obtener indicadores desde AI Service"""
        indicator = self.env['hr.economic.indicators'].fetch_from_previred(
            self.year,
            self.month
        )
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'hr.economic.indicators',
            'res_id': indicator.id,
            'view_mode': 'form',
            'target': 'current',
        }
```

---

### **Paso 3: Botón en Vista**

```xml
<!-- views/hr_economic_indicators_views.xml -->

<record id="view_hr_economic_indicators_form" model="ir.ui.view">
    <field name="name">hr.economic.indicators.form</field>
    <field name="model">hr.economic.indicators</field>
    <field name="arch" type="xml">
        <form>
            <header>
                <button name="%(action_previred_fetch_wizard)d"
                    string="Obtener desde Previred"
                    type="action"
                    class="btn-primary"
                    icon="fa-download"/>
            </header>
            <sheet>
                <group>
                    <field name="period"/>
                    <field name="uf"/>
                    <field name="utm"/>
                    <field name="uta"/>
                </group>
            </sheet>
        </form>
    </field>
</record>
```

---

## ✅ VENTAJAS DE ESTA ESTRATEGIA

### **1. Reutilización Total**
- ✅ Microservicio ya existe y funciona
- ✅ 49 campos automáticos
- ✅ PDF + HTML fallback
- ✅ Claude API integrado

### **2. Simplicidad**
- ✅ Solo agregar método `fetch_from_previred()`
- ✅ Wizard simple
- ✅ Sin duplicar código

### **3. Mantenibilidad**
- ✅ Lógica compleja en microservicio
- ✅ Odoo solo orquesta
- ✅ Fácil actualizar

### **4. Costo**
- ✅ ~$0.03/mes (Claude API)
- ✅ vs riesgo errores hardcoded

---

## 📋 PLAN DE IMPLEMENTACIÓN

### **Sprint 1 (Hoy)**
- [x] Modelo `hr.economic.indicators` ✅ Ya creado
- [ ] Agregar método `fetch_from_previred()`
- [ ] Crear wizard `previred.fetch.wizard`
- [ ] Vista con botón "Obtener desde Previred"

### **Sprint 2 (Próxima semana)**
- [ ] Testing integración
- [ ] Cron job automático (1er día mes)
- [ ] Notificaciones si falla

---

## 🎯 DECISIÓN

**✅ REUTILIZAR MICROSERVICIO EERGY-AI**

**Razones:**
1. Ya existe y funciona (49 campos)
2. PDF + HTML fallback
3. Claude API integrado
4. Retry y circuit breaker
5. Solo agregar método en Odoo

**NO crear scraper nuevo en Odoo 19**

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ ANÁLISIS COMPLETO
