# 🔄 EXTENSIÓN AI-SERVICE: Agregar Funcionalidades Nóminas

**Fecha:** 2025-10-22  
**Decisión:** Extender AI-Service existente en lugar de crear EERGY AI nuevo

---

## 🎯 SITUACIÓN ACTUAL

### **AI-Service Existente (DTE)**

**Ubicación:** `/Users/pedro/Documents/odoo19/ai-service/`

**Funcionalidades Actuales:**
```python
# ai-service/main.py

✅ POST /api/ai/validate          # Validación DTEs con Claude
✅ POST /api/ai/reconcile         # Reconciliación facturas (deprecated)
✅ POST /api/ai/sii/monitor       # Monitoreo SII
✅ POST /api/ai/chat              # Chat DTE con Claude
✅ GET  /health                   # Health check
```

**Stack Actual:**
- FastAPI
- Claude API (Anthropic) - Primary
- OpenAI API - Fallback
- Redis (context manager)
- Structured logging (structlog)

**Características:**
- ✅ Ligero (485 MB vs 8.2 GB antes)
- ✅ Rápido (< 5s startup)
- ✅ Memoria eficiente (384 MB idle)
- ✅ Professional code quality

---

## ✅ ESTRATEGIA: EXTENDER AI-SERVICE

### **Agregar Módulo Payroll**

```
ai-service/
├── clients/
│   ├── anthropic_client.py ✅ Existente
│   └── openai_client.py ✅ Existente
├── chat/
│   ├── engine.py ✅ Existente (DTE)
│   ├── context_manager.py ✅ Existente
│   └── knowledge_base.py ✅ Existente (DTE)
├── sii_monitor/ ✅ Existente
├── payroll/ ✅ NUEVO - Agregar
│   ├── __init__.py
│   ├── previred_scraper.py      # Extracción Previred
│   ├── payroll_calculator.py    # Cálculos nómina
│   ├── payroll_validator.py     # Validación con IA
│   └── knowledge_base_payroll.py # KB nóminas
├── main.py ✅ Extender
└── config.py ✅ Extender
```

---

## 📋 FUNCIONALIDADES A AGREGAR

### **1. Extracción Indicadores Previred** ✅

**Endpoint:**
```python
# main.py - AGREGAR

@app.post("/api/ai/payroll/previred/extract")
async def extract_previred_indicators(
    period: str,  # "2025-10"
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """
    Extraer indicadores Previred usando Claude API
    
    Request:
    POST /api/ai/payroll/previred/extract
    {
        "period": "2025-10"
    }
    
    Response:
    {
        "success": true,
        "indicators": {
            "uf": 39383.07,
            "utm": 68647,
            "uta": 823764,
            // ... 57 campos más
        },
        "metadata": {
            "source": "previred_pdf",
            "model": "claude-sonnet-4",
            "cost_usd": 0.025
        }
    }
    """
    from payroll.previred_scraper import PreviredScraper
    
    scraper = PreviredScraper(
        anthropic_client=get_anthropic_client()
    )
    
    result = await scraper.extract_indicators(period)
    
    return result
```

**Implementación:**
```python
# payroll/previred_scraper.py - NUEVO

import requests
from typing import Dict
import structlog

logger = structlog.get_logger()

class PreviredScraper:
    """
    Extractor de indicadores Previred usando Claude API
    
    Estrategia:
    1. Descargar PDF desde Previred.com
    2. Parsear con Claude API
    3. Validar coherencia
    4. Retornar 60 campos
    """
    
    PDF_URL_PATTERNS = [
        "https://www.previred.com/wp-content/uploads/{year}/{month:02d}/"
        "Indicadores-Previsionales-Previred-{mes_nombre}-{year}.pdf",
        # ... más variaciones
    ]
    
    MESES_ES = [
        "Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio",
        "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"
    ]
    
    def __init__(self, anthropic_client):
        self.claude = anthropic_client
        self.session = requests.Session()
    
    async def extract_indicators(self, period: str) -> Dict:
        """
        Extraer indicadores para período
        
        Args:
            period: "YYYY-MM" (ej: "2025-10")
        
        Returns:
            Dict con 60 campos + metadata
        """
        year, month = period.split("-")
        year = int(year)
        month = int(month)
        
        logger.info("previred_extraction_started", period=period)
        
        # 1. Descargar PDF
        pdf_bytes = self._download_pdf(year, month)
        
        # 2. Parsear con Claude
        indicators = await self._parse_with_claude(pdf_bytes, period)
        
        # 3. Validar
        self._validate_indicators(indicators)
        
        logger.info("previred_extraction_completed", 
                   period=period,
                   fields_extracted=len(indicators))
        
        return {
            "success": True,
            "indicators": indicators,
            "metadata": {
                "source": "previred_pdf",
                "period": period,
                "fields_count": len(indicators)
            }
        }
    
    def _download_pdf(self, year: int, month: int) -> bytes:
        """Descargar PDF de Previred"""
        mes_nombre = self.MESES_ES[month - 1]
        
        for pattern in self.PDF_URL_PATTERNS:
            url = pattern.format(
                year=year,
                month=month,
                mes_nombre=mes_nombre.lower()
            )
            
            try:
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    logger.info("pdf_downloaded", url=url, size_kb=len(response.content)/1024)
                    return response.content
            except Exception as e:
                logger.debug("pdf_download_failed", url=url, error=str(e))
                continue
        
        raise Exception(f"PDF no disponible para {year}-{month:02d}")
    
    async def _parse_with_claude(self, pdf_bytes: bytes, period: str) -> Dict:
        """
        Parsear PDF con Claude API
        
        Usa Claude para extraer los 60 campos desde el PDF
        """
        # Convertir PDF a texto o imágenes (Claude puede leer PDFs)
        # Por ahora, simplificado - en producción usar PDF parsing
        
        prompt = f"""
        Extrae los indicadores previsionales de Chile para el período {period}.
        
        Debes extraer EXACTAMENTE 60 campos:
        
        1. Indicadores económicos (4):
           - uf, utm, uta, sueldo_minimo
        
        2. Topes imponibles (3):
           - afp_tope_uf, salud_tope_uf, afc_tope_uf
        
        3. Tasas AFP (35):
           - 7 instituciones × 5 fondos (A, B, C, D, E)
        
        4. Tasas cotización (8):
           - exvida_pct, aporteafpe_pct, afc_trabajador, etc.
        
        5. Asignación familiar (9):
           - 3 tramos × 3 valores
        
        Retorna JSON con TODOS los campos.
        Números sin formato (39383.07 no "39.383,07").
        """
        
        # Llamar Claude API
        response = await self.claude.send_message(
            messages=[{"role": "user", "content": prompt}],
            system="Eres un experto en indicadores previsionales chilenos."
        )
        
        # Parsear JSON response
        import json
        indicators = json.loads(response.content)
        
        return indicators
    
    def _validate_indicators(self, indicators: Dict):
        """Validar coherencia de indicadores"""
        required = ['uf', 'utm', 'uta', 'sueldo_minimo']
        
        for field in required:
            if field not in indicators or indicators[field] <= 0:
                raise ValueError(f"Campo '{field}' inválido")
        
        # Validar coherencia
        if indicators['utm'] < indicators['uf']:
            raise ValueError("Incoherencia: UTM < UF")
```

---

### **2. Validación Liquidaciones con IA** ✅

**Endpoint:**
```python
# main.py - AGREGAR

@app.post("/api/ai/payroll/validate")
async def validate_payslip(
    payslip_data: Dict,
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """
    Validar liquidación con Claude API
    
    Detecta:
    - Errores de cálculo
    - Incoherencias
    - Violaciones legales
    - Anomalías vs histórico
    """
    from payroll.payroll_validator import PayrollValidator
    
    validator = PayrollValidator(
        anthropic_client=get_anthropic_client()
    )
    
    result = await validator.validate_payslip(payslip_data)
    
    return result
```

**Implementación:**
```python
# payroll/payroll_validator.py - NUEVO

class PayrollValidator:
    """
    Validador inteligente de liquidaciones usando Claude API
    
    Similar a validación DTEs pero para nóminas
    """
    
    def __init__(self, anthropic_client):
        self.claude = anthropic_client
    
    async def validate_payslip(self, payslip_data: Dict) -> Dict:
        """
        Validar liquidación con IA
        
        Args:
            payslip_data: {
                "employee_id": 123,
                "period": "2025-10",
                "wage": 1500000,
                "lines": [
                    {"code": "AFP", "amount": -157350},
                    {"code": "SALUD", "amount": -105000},
                    ...
                ]
            }
        
        Returns:
            {
                "confidence": 95.0,
                "errors": [],
                "warnings": ["AFP tasa parece alta"],
                "recommendation": "approve" | "review"
            }
        """
        prompt = f"""
        Valida esta liquidación de sueldo chilena:
        
        Empleado: {payslip_data['employee_id']}
        Período: {payslip_data['period']}
        Sueldo Base: ${payslip_data['wage']:,.0f}
        
        Líneas:
        {self._format_lines(payslip_data['lines'])}
        
        Verifica:
        1. Cálculo AFP correcto (10.49%-11.54%, tope 87.8 UF)
        2. Cálculo Salud correcto (FONASA 7% o ISAPRE variable)
        3. Impuesto Único correcto (7 tramos progresivos)
        4. Coherencia matemática (suma correcta)
        5. Cumplimiento legal (Código del Trabajo)
        
        Retorna JSON:
        {{
            "confidence": 0-100,
            "errors": ["error1", ...],
            "warnings": ["warning1", ...],
            "recommendation": "approve" | "review"
        }}
        """
        
        response = await self.claude.send_message(
            messages=[{"role": "user", "content": prompt}],
            system="Eres un experto en nóminas chilenas y Código del Trabajo."
        )
        
        import json
        result = json.loads(response.content)
        
        return result
```

---

### **3. Chat Laboral** ✅

**Endpoint:**
```python
# main.py - EXTENDER chat existente

@app.post("/api/ai/chat")
async def chat(
    message: str,
    session_id: str,
    context: str = "dte",  # ✅ AGREGAR: "dte" | "payroll"
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """
    Chat con IA - Ahora soporta DTE y Nóminas
    """
    from chat.engine import ChatEngine
    from payroll.knowledge_base_payroll import get_payroll_knowledge_base
    
    # Seleccionar knowledge base según contexto
    if context == "payroll":
        kb = get_payroll_knowledge_base()
    else:
        kb = get_dte_knowledge_base()  # Existente
    
    engine = ChatEngine(
        anthropic_client=get_anthropic_client(),
        knowledge_base=kb
    )
    
    response = await engine.send_message(message, session_id)
    
    return response
```

**Knowledge Base Nóminas:**
```python
# payroll/knowledge_base_payroll.py - NUEVO

PAYROLL_KNOWLEDGE_BASE = [
    {
        "id": "payroll_001",
        "title": "Cálculo AFP",
        "content": """
        AFP (Administradora de Fondos de Pensiones):
        - Tasa: 10.49% - 11.54% según AFP
        - Tope: 87.8 UF (Reforma 2025)
        - Base: Sueldo imponible
        - Fórmula: min(sueldo, 87.8 UF) × tasa_afp
        """,
        "tags": ["afp", "calculo", "prevision"],
        "module": "payroll"
    },
    {
        "id": "payroll_002",
        "title": "FONASA vs ISAPRE",
        "content": """
        FONASA:
        - Tasa fija: 7%
        - Sin tope
        
        ISAPRE:
        - Plan variable en UF
        - Si plan > 7%, trabajador paga diferencia
        - Si plan < 7%, excedente como haber
        """,
        "tags": ["salud", "fonasa", "isapre"],
        "module": "payroll"
    },
    # ... más artículos
]

def get_payroll_knowledge_base():
    """Retornar KB de nóminas"""
    return PAYROLL_KNOWLEDGE_BASE
```

---

## 📊 COMPARATIVA: EERGY AI vs Extender AI-Service

| Aspecto | EERGY AI Completo | Extender AI-Service |
|---------|-------------------|---------------------|
| **Código nuevo** | 0 líneas (ya existe) | ~1,500 líneas |
| **Mantenimiento** | 2 microservicios | 1 microservicio |
| **Complejidad** | Baja (copiar) | Media (desarrollar) |
| **Integración** | Requiere adaptación | Nativa |
| **Consistencia** | Diferente stack | Mismo stack |
| **Portal Empleados** | ✅ Incluido | ❌ Requiere desarrollo |
| **Tiempo** | 1 día (adaptación) | 3-4 días (desarrollo) |
| **Enterprise Features** | ✅ 15.5/16 | ✅ Ya tiene |

---

## ✅ RECOMENDACIÓN FINAL

### **OPCIÓN HÍBRIDA** (Mejor de ambos mundos)

**Estrategia:**

1. **Extender AI-Service** para funcionalidades core:
   - ✅ Extracción Previred (reutilizar lógica EERGY AI)
   - ✅ Validación liquidaciones
   - ✅ Chat laboral

2. **Portal Empleados**: Reutilizar de EERGY AI
   - ✅ Ya existe (920 líneas)
   - ✅ SQL Direct (performance)
   - ✅ Solo adaptar conexión DB

**Arquitectura Final:**
```
ODOO 19 CE
└─ l10n_cl_hr_payroll

AI-SERVICE (Extendido) ✅
├─ DTE (existente)
│  ├─ Validación
│  ├─ Monitoreo SII
│  └─ Chat DTE
└─ PAYROLL (nuevo) ✅
   ├─ Extracción Previred
   ├─ Validación liquidaciones
   └─ Chat laboral

EMPLOYEE-PORTAL (Reutilizar EERGY AI) ✅
└─ Portal empleados (SQL Direct)
```

**Ventajas:**
- ✅ Un solo AI-Service (consistencia)
- ✅ Portal empleados sin desarrollo (reutilizar)
- ✅ Tiempo: 2-3 días vs 4-6 semanas
- ✅ Mantenimiento simplificado

---

## 📋 PLAN DE IMPLEMENTACIÓN

### **Sprint 1: Extender AI-Service (2 días)**

**Día 1:**
- [ ] Crear módulo `payroll/`
- [ ] Implementar `previred_scraper.py`
- [ ] Agregar endpoint `/api/ai/payroll/previred/extract`
- [ ] Testing extracción

**Día 2:**
- [ ] Implementar `payroll_validator.py`
- [ ] Agregar endpoint `/api/ai/payroll/validate`
- [ ] Crear `knowledge_base_payroll.py`
- [ ] Extender chat para soportar contexto payroll
- [ ] Testing completo

### **Sprint 2: Portal Empleados (1 día)**

**Día 3:**
- [ ] Copiar employee-portal de EERGY AI
- [ ] Actualizar conexión DB (Odoo 11 → Odoo 19)
- [ ] Testing portal
- [ ] Deploy

---

## 🎯 CÓDIGO DE EJEMPLO

### **Integración desde Odoo**

```python
# models/hr_economic_indicators.py en Odoo

@api.model
def fetch_from_ai_service(self, year, month):
    """
    Obtener indicadores desde AI-Service extendido
    """
    import requests
    import os
    
    ai_service_url = os.getenv('AI_SERVICE_URL', 'http://ai-service:8000')
    api_key = os.getenv('AI_SERVICE_API_KEY')
    
    response = requests.post(
        f"{ai_service_url}/api/ai/payroll/previred/extract",
        json={"period": f"{year}-{month:02d}"},
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=60
    )
    
    response.raise_for_status()
    result = response.json()
    
    # Crear registro
    indicator = self.create({
        'period': date(year, month, 1),
        'uf': result['indicators']['uf'],
        'utm': result['indicators']['utm'],
        # ... 58 campos más
    })
    
    return indicator
```

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ ESTRATEGIA DEFINIDA
