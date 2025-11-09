# 🏗️ Matriz de Arquitectura y Responsabilidades

**Documento:** Architecture Responsibility Matrix  
**Versión:** 1.0  
**Fecha:** 2025-10-21  
**Para:** l10n_cl_dte + DTE Service + AI Service

---

## 🎯 PRINCIPIOS ARQUITECTÓNICOS

### 1. Maximizar Integración con Odoo Base ✅
- EXTENDER modelos existentes, NO crear desde cero
- REUTILIZAR validaciones de Odoo
- HEREDAR workflows de Odoo
- APROVECHAR UI/UX de Odoo

### 2. Separación de Responsabilidades ✅
- **Odoo:** Lógica de negocio, UI, datos
- **DTE Service:** Operaciones CPU/I/O intensivas
- **AI Service:** Inteligencia y automatización

### 3. Arquitectura de 3 Capas ✅
```
CAPA 1: Odoo Module (Python/PostgreSQL)
  └─ Responsabilidad: Datos, validaciones, UI, workflow

CAPA 2: DTE Microservice (FastAPI/Redis/RabbitMQ)
  └─ Responsabilidad: XML, firma, SOAP, queue

CAPA 3: AI Microservice (FastAPI/Ollama/Anthropic)
  └─ Responsabilidad: Validación, reconciliación, análisis
```

---

## 📊 MATRIZ COMPLETA DE RESPONSABILIDADES

### CREACIÓN DE DTE

| Funcionalidad | Odoo | DTE Service | AI Service | Tecnología | Razón |
|--------------|------|-------------|------------|-----------|-------|
| **Capturar datos factura** | ✅ | ❌ | ❌ | Odoo Form View | UI/UX nativa |
| **Validar RUT** | ✅ | ❌ | ❌ | Python (local) | Lógica de negocio |
| **Validar montos** | ✅ | ❌ | ❌ | Odoo computed | Reutilizar Odoo |
| **Pre-validación IA** | ⚠️ | ❌ | ✅ | LLM + embeddings | Detectar errores antes |
| **Generar XML DTE** | ❌ | ✅ | ❌ | lxml | CPU intensivo |
| **Validar XML vs XSD** | ❌ | ✅ | ❌ | lxml + XSD | I/O intensivo |
| **Firmar digitalmente** | ❌ | ✅ | ❌ | pyOpenSSL | Criptografía pesada |
| **Enviar a SII (SOAP)** | ❌ | ✅ | ❌ | zeep | I/O bloqueante |
| **Guardar respuesta** | ✅ | ⚠️ | ❌ | PostgreSQL | Persistencia en Odoo |
| **Actualizar estado** | ✅ | ❌ | ❌ | Odoo ORM | Workflow Odoo |

**Flujo:**
```
Usuario crea factura en Odoo
  ↓
Odoo valida datos (RUT, montos)
  ↓
Odoo llama AI Service (pre-validación opcional)
  ↓
Odoo llama DTE Service (generar XML)
  ↓
DTE Service genera + firma + envía SII
  ↓
DTE Service retorna resultado a Odoo
  ↓
Odoo guarda en BD y actualiza estado
```

---

### RECEPCIÓN DE COMPRAS

| Funcionalidad | Odoo | DTE Service | AI Service | Tecnología | Razón |
|--------------|------|-------------|------------|-----------|-------|
| **Polling DTEs SII** | ❌ | ✅ | ❌ | zeep + cron | SOAP bloqueante |
| **Descargar XML** | ❌ | ✅ | ❌ | zeep | I/O intensivo |
| **Parsear XML** | ❌ | ✅ | ❌ | lxml | CPU intensivo |
| **Matching con PO** | ⚠️ | ❌ | ✅ | Embeddings | IA similarity |
| **Crear account.move** | ✅ | ❌ | ❌ | Odoo ORM | Persistencia |
| **Notificar usuario** | ✅ | ❌ | ❌ | Odoo mail | Workflow Odoo |

**Flujo:**
```
DTE Service polling SII cada 30 min
  ↓
Descarga nuevos DTEs recibidos
  ↓
Parsea XML y extrae datos
  ↓
Envía a AI Service para matching con POs
  ↓
AI retorna PO con 92% confidence
  ↓
DTE Service notifica a Odoo (callback)
  ↓
Odoo crea factura de compra automático
  ↓
Odoo notifica a usuario (mail)
```

---

### REPORTES SII

| Funcionalidad | Odoo | DTE Service | AI Service | Tecnología | Razón |
|--------------|------|-------------|------------|-----------|-------|
| **Consumo de folios** | ✅ | ⚠️ | ❌ | PostgreSQL query | Datos en Odoo |
| **Generar XML consumo** | ❌ | ✅ | ❌ | lxml | XML generation |
| **Libro compra/venta** | ✅ | ⚠️ | ❌ | PostgreSQL query | Datos en Odoo |
| **Generar XML libro** | ❌ | ✅ | ❌ | lxml | XML generation |
| **Enviar a SII** | ❌ | ✅ | ❌ | zeep | SOAP |
| **Análisis tendencias** | ❌ | ❌ | ✅ | ML analytics | Insights IA |

**Flujo:**
```
Usuario solicita "Libro Venta Octubre" en Odoo
  ↓
Odoo consulta account.move (facturas del mes)
  ↓
Odoo envía datos a DTE Service
  ↓
DTE Service genera XML libro
  ↓
DTE Service envía a SII
  ↓
DTE Service retorna resultado
  ↓
Odoo guarda constancia
  ↓
Opcionalmente: AI Service genera análisis
```

---

### CERTIFICADOS DIGITALES

| Funcionalidad | Odoo | DTE Service | AI Service | Tecnología | Razón |
|--------------|------|-------------|------------|-----------|-------|
| **Upload certificado** | ✅ | ❌ | ❌ | Odoo Binary field | UI Odoo |
| **Almacenar encriptado** | ✅ | ❌ | ❌ | Encrypted field | Odoo security |
| **Cargar para firma** | ⚠️ | ✅ | ❌ | pyOpenSSL | Odoo envía a DTE |
| **Validar vigencia** | ✅ | ⚠️ | ❌ | Python | Ambos |
| **Alertar vencimiento** | ✅ | ❌ | ❌ | Odoo cron | Workflow Odoo |

**Flujo:**
```
Usuario sube certificado .pfx en Odoo
  ↓
Odoo almacena encriptado en BD
  ↓
Cuando se genera DTE:
  ↓
Odoo extrae certificado de BD
  ↓
Odoo envía a DTE Service (HTTPS)
  ↓
DTE Service usa para firmar
  ↓
DTE Service retorna XML firmado
  ↓
Odoo almacena resultado
```

---

### AUDITORÍA Y LOGGING

| Funcionalidad | Odoo | DTE Service | AI Service | Tecnología | Razón |
|--------------|------|-------------|------------|-----------|-------|
| **Log de operaciones** | ✅ | ✅ | ✅ | structlog | Los 3 registran |
| **Trazabilidad usuario** | ✅ | ❌ | ❌ | mail.thread | Odoo chatter |
| **Métricas performance** | ❌ | ✅ | ✅ | Prometheus | Servicios |
| **Alertas errores** | ✅ | ✅ | ✅ | Grafana | Todos |
| **Detección anomalías** | ❌ | ❌ | ✅ | ML detection | IA |

---

## 🔄 FLUJOS DE INTEGRACIÓN

### FLUJO 1: Emisión DTE 33 (Factura)

```
┌─────────────────────────────────────────────────────────────────┐
│ PASO 1: Usuario crea factura en Odoo                           │
└─────────────────────────────────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  Odoo valida:   │
                  │  - RUT cliente  │
                  │  - Montos       │
                  │  - Impuestos    │
                  └────────┬────────┘
                           │
┌─────────────────────────▼─────────────────────────────────────┐
│ PASO 2: Odoo llama AI Service (pre-validación opcional)       │
│         POST /api/ai/validate                                  │
│         Retorna: confidence 95%, warnings: []                  │
└─────────────────────────┬─────────────────────────────────────┘
                           │
┌─────────────────────────▼─────────────────────────────────────┐
│ PASO 3: Odoo llama DTE Service                                │
│         POST /api/dte/generate-and-send                        │
│         Body: {type: 33, invoice_data: {...}}                  │
└─────────────────────────┬─────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  DTE Service:   │
                  │  1. Genera XML  │
                  │  2. Firma XML   │
                  │  3. Envía SII   │
                  │  4. Recibe resp │
                  └────────┬────────┘
                           │
┌─────────────────────────▼─────────────────────────────────────┐
│ PASO 4: DTE Service retorna a Odoo                            │
│         Response: {status: 'accepted', folio: 123, ...}        │
└─────────────────────────┬─────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  Odoo guarda:   │
                  │  - dte_folio    │
                  │  - dte_status   │
                  │  - dte_xml      │
                  │  - timestamp    │
                  └─────────────────┘
```

---

### FLUJO 2: Recepción Compras

```
┌─────────────────────────────────────────────────────────────────┐
│ Cron DTE Service cada 30 min: Polling SII                      │
└─────────────────────────┬───────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  DTE Service:   │
                  │  - Descarga DTEs│
                  │  - Parsea XML   │
                  │  - Extrae datos │
                  └────────┬────────┘
                           │
┌─────────────────────────▼─────────────────────────────────────┐
│ DTE Service llama AI Service                                   │
│ POST /api/ai/reconcile                                         │
│ Body: {dte_xml: ..., pending_pos: [...]}                       │
└─────────────────────────┬─────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  AI Service:    │
                  │  - Embeddings   │
                  │  - Similarity   │
                  │  - Match 92%    │
                  └────────┬────────┘
                           │
┌─────────────────────────▼─────────────────────────────────────┐
│ DTE Service callback a Odoo                                    │
│ POST http://odoo:8069/api/dte/received                         │
│ Body: {dte_data: ..., matched_po_id: 123, confidence: 92}      │
└─────────────────────────┬─────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  Odoo:          │
                  │  - Crea factura │
                  │  - Link con PO  │
                  │  - Notifica user│
                  └─────────────────┘
```

---

### FLUJO 3: Liquidación Honorarios (DTE 34)

```
┌─────────────────────────────────────────────────────────────────┐
│ Usuario crea Liquidación Honorarios en Odoo                    │
│ (purchase.order con es_honorarios=True)                        │
└─────────────────────────┬───────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  Odoo calcula:  │
                  │  - Monto bruto  │
                  │  - Retención 10%│
                  │  - Neto a pagar │
                  └────────┬────────┘
                           │
┌─────────────────────────▼─────────────────────────────────────┐
│ Odoo llama DTE Service                                         │
│ POST /api/dte/generate-honorarios                              │
│ Body: {type: 34, purchase_data: {...}, retencion: 10%}         │
└─────────────────────────┬─────────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  DTE Service:   │
                  │  - XML DTE 34   │
                  │  - Con retención│
                  │  - Firma        │
                  │  - Envía SII    │
                  └────────┬────────┘
                           │
┌─────────────────────────▼─────────────────────────────────────┐
│ Odoo recibe resultado y:                                       │
│ 1. Guarda DTE 34                                               │
│ 2. Crea asiento contable (retención)                           │
│ 3. Actualiza retencion.iue (agregación mensual)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧩 DETALLE POR COMPONENTE

### ODOO MODULE (l10n_cl_dte)

**Responsabilidades:**
1. ✅ **Gestión de Datos**
   - Modelos: account.move, purchase.order, dte.certificate
   - Persistencia: PostgreSQL
   - Relaciones: Many2one, One2many

2. ✅ **UI/UX**
   - Vistas: Form, Tree, Search
   - Wizards: Envío masivo, carga certificado
   - Acciones: Botones, menús

3. ✅ **Validaciones de Negocio**
   - RUT válido (local)
   - Montos consistentes
   - Fechas válidas
   - Estados válidos

4. ✅ **Workflow**
   - Estados: draft → to_send → sent → accepted
   - Transiciones: validar → enviar → confirmar
   - Notificaciones: mail.thread

5. ✅ **Reportes Odoo**
   - Consumo de folios (query PostgreSQL)
   - Libro compra/venta (query PostgreSQL)
   - Reportes contables

6. ✅ **Integración con Microservicios**
   - Cliente HTTP para DTE Service
   - Cliente HTTP para AI Service
   - Manejo de respuestas async

**Tecnologías:**
- Python 3.11
- Odoo ORM
- PostgreSQL 15
- XML views
- QWeb reports

**Archivos principales:**
```
l10n_cl_dte/
├── models/
│   ├── account_move_dte.py
│   ├── purchase_order_dte.py
│   ├── dte_certificate.py
│   └── dte_communication.py
├── tools/
│   ├── rut_validator.py
│   └── dte_api_client.py
└── views/
    └── account_move_dte_views.xml
```

---

### DTE MICROSERVICE (FastAPI)

**Responsabilidades:**
1. ✅ **Generación XML**
   - Templates XML por tipo DTE (33, 34, 52, 56, 61)
   - Validación contra XSD
   - Formato según norma SII

2. ✅ **Firma Digital**
   - Carga de certificados .pfx
   - Firma PKCS#1 RSA
   - Firma XMLDsig

3. ✅ **Comunicación SOAP**
   - Cliente SOAP (zeep)
   - Autenticación con SII
   - Envío de DTEs
   - Recepción de respuestas
   - Manejo de errores SII

4. ✅ **Cola Asíncrona**
   - Queue de DTEs pendientes (RabbitMQ)
   - Workers Celery
   - Retry logic
   - Dead letter queue

5. ✅ **Polling de Compras**
   - Cron cada 30 min
   - Descarga DTEs recibidos
   - Parseo XML
   - Callback a Odoo

**Tecnologías:**
- Python 3.11
- FastAPI
- lxml (XML)
- pyOpenSSL (firma)
- zeep (SOAP)
- RabbitMQ (queue)
- Celery (workers)
- Redis (cache)

**Archivos principales:**
```
dte-service/
├── main.py
├── generators/
│   ├── dte_generator_33.py
│   ├── dte_generator_34.py
│   └── dte_generator_52.py
├── signers/
│   └── dte_signer.py
├── clients/
│   └── sii_soap_client.py
├── queue/
│   └── celery_tasks.py
└── config.py
```

**Endpoints:**
```python
POST /api/dte/generate          # Generar XML
POST /api/dte/sign              # Firmar XML
POST /api/dte/send              # Enviar SII
POST /api/dte/generate-and-send # Todo en uno
GET  /api/dte/status/{track_id} # Consultar estado
POST /api/dte/poll-received     # Polling compras (cron)
```

---

### AI MICROSERVICE (FastAPI + LLM)

**Responsabilidades:**
1. ✅ **Pre-validación Inteligente**
   - Detectar errores antes de envío
   - Comparar con historial de rechazos
   - Confidence score 0-100%

2. ✅ **Reconciliación Automática**
   - Matching factura proveedor ↔ PO
   - Embeddings de líneas
   - Cosine similarity > 85%

3. ✅ **Clasificación de Documentos**
   - Categorizar DTEs recibidos
   - Auto-asignar cuentas contables
   - Sugerir proyectos/centros de costo

4. ✅ **Detección de Anomalías**
   - Montos fuera de rango
   - Frecuencias inusuales
   - Proveedores nuevos sin validación

5. ✅ **Análisis y Reportes**
   - Tendencias de facturación
   - Proyecciones próximo mes
   - Recomendaciones optimización

**Tecnologías:**
- Python 3.11
- FastAPI
- Ollama (LLM local)
- Anthropic Claude (LLM cloud)
- sentence-transformers (embeddings)
- ChromaDB (vector DB)
- pandas (análisis)

**Archivos principales:**
```
ai-service/
├── main.py
├── validators/
│   └── intelligent_validator.py
├── reconciliation/
│   └── invoice_matcher.py
├── classification/
│   └── document_classifier.py
├── anomaly/
│   └── anomaly_detector.py
├── analysis/
│   └── trend_analyzer.py
└── config.py
```

**Endpoints:**
```python
POST /api/ai/validate           # Pre-validación
POST /api/ai/reconcile          # Matching facturas
POST /api/ai/classify           # Clasificación
POST /api/ai/detect-anomalies   # Anomalías
POST /api/ai/analyze-trends     # Análisis tendencias
```

---

## 📊 MATRIZ DE DECISIONES: ¿DÓNDE VA CADA FUNCIÓN?

### Criterios de Decisión

| Criterio | Odoo | DTE Service | AI Service |
|----------|------|-------------|-----------|
| **Acceso a datos Odoo** | ✅ Directo | ⚠️ API | ⚠️ API |
| **CPU intensivo** | ❌ | ✅ | ✅ |
| **I/O bloqueante** | ❌ | ✅ | ⚠️ |
| **UI requerida** | ✅ | ❌ | ❌ |
| **Lógica de negocio** | ✅ | ⚠️ | ❌ |
| **Criptografía** | ❌ | ✅ | ❌ |
| **ML/IA** | ❌ | ❌ | ✅ |
| **Escalabilidad** | ⚠️ | ✅ | ✅ |

### Reglas de Decisión

**Implementar en ODOO si:**
- ✅ Requiere acceso directo a BD Odoo
- ✅ Requiere UI/formularios
- ✅ Es lógica de negocio core
- ✅ Requiere workflow de estados
- ✅ Es validación simple/rápida

**Implementar en DTE SERVICE si:**
- ✅ Es generación/procesamiento XML
- ✅ Es firma digital/criptografía
- ✅ Es comunicación SOAP con SII
- ✅ Es I/O bloqueante
- ✅ Requiere cola asíncrona

**Implementar en AI SERVICE si:**
- ✅ Requiere ML/IA
- ✅ Es análisis de patrones
- ✅ Es matching/similarity
- ✅ Es clasificación automática
- ✅ Genera insights

---

## 🎯 EJEMPLO CONCRETO: EMISIÓN FACTURA

### Código en Odoo

```python
# models/account_move_dte.py
class AccountMoveDTE(models.Model):
    _inherit = 'account.move'
    
    dte_status = fields.Selection([...])
    dte_folio = fields.Char()
    
    def action_send_to_sii(self):
        """Enviar factura a SII"""
        self.ensure_one()
        
        # 1. Validaciones locales (Odoo)
        self._validate_dte_data()
        
        # 2. Pre-validación IA (opcional)
        if self.company_id.use_ai_validation:
            ai_result = self.env['dte.api.client'].ai_validate(self)
            if ai_result['confidence'] < 80:
                raise UserError(f"Confianza baja: {ai_result['warnings']}")
        
        # 3. Llamar DTE service
        dte_client = self.env['dte.api.client']
        result = dte_client.generate_and_send_dte(self)
        
        # 4. Guardar resultado
        self.write({
            'dte_status': 'sent' if result['success'] else 'error',
            'dte_folio': result.get('folio'),
            'dte_xml': result.get('xml'),
            'dte_timestamp': fields.Datetime.now(),
            'dte_response_sii': result.get('response')
        })
        
        # 5. Crear log de comunicación
        self.env['dte.communication'].create({
            'move_id': self.id,
            'action': 'send_to_sii',
            'status': 'success' if result['success'] else 'error',
            'response': result.get('response')
        })
        
        return result
    
    def _validate_dte_data(self):
        """Validaciones en Odoo"""
        # Validar RUT (local)
        from odoo.addons.l10n_cl_dte.tools.rut_validator import validate_rut
        if not validate_rut(self.partner_id.vat):
            raise ValidationError('RUT cliente inválido')
        
        # Validar montos (reutilizar Odoo)
        if self.amount_total <= 0:
            raise ValidationError('Monto debe ser mayor a 0')
```

### Código en DTE Service

```python
# dte-service/main.py
@app.post("/api/dte/generate-and-send")
async def generate_and_send_dte(data: DTEData):
    """Genera XML, firma y envía a SII"""
    
    # 1. Generar XML
    generator = get_generator(data.dte_type)  # 33, 34, 52, etc
    xml = generator.generate(data.invoice_data)
    
    # 2. Validar XML contra XSD
    validator = DTEValidator()
    if not validator.validate_xsd(xml):
        return {'success': False, 'error': 'XML inválido'}
    
    # 3. Firmar
    signer = DTESigner()
    signed_xml = signer.sign(xml, data.certificate, data.password)
    
    # 4. Enviar a SII (async con Celery)
    task = send_to_sii_task.delay(signed_xml, data.environment)
    
    # 5. Retornar resultado
    return {
        'success': True,
        'xml': signed_xml,
        'task_id': task.id
    }

# dte-service/queue/celery_tasks.py
@celery.task(bind=True, max_retries=3)
def send_to_sii_task(self, signed_xml: str, environment: str):
    """Enviar DTE a SII (async)"""
    try:
        sii_client = SIISoapClient(environment)
        result = sii_client.send_dte(signed_xml)
        
        # Callback a Odoo
        notify_odoo(result)
        
        return result
    except Exception as exc:
        # Retry con backoff
        self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)
```

### Código en AI Service

```python
# ai-service/validators/intelligent_validator.py
@app.post("/api/ai/validate")
async def validate_dte(data: DTEValidationRequest):
    """Pre-validación inteligente"""
    
    # 1. Cargar historial de rechazos
    rechazos = load_rejection_history(data.company_id)
    
    # 2. Embeddings del DTE actual
    dte_embedding = create_embedding(data.dte_data)
    
    # 3. Similarity con rechazos históricos
    similarities = compare_with_rejections(dte_embedding, rechazos)
    
    # 4. Si >80% similar a rechazo, alertar
    warnings = []
    for sim in similarities:
        if sim['score'] > 0.8:
            warnings.append(f"Similar a rechazo previo: {sim['reason']}")
    
    # 5. Calcular confidence
    confidence = 100 - (len(warnings) * 10)
    
    return {
        'confidence': confidence,
        'warnings': warnings,
        'errors': [],
        'recommendation': 'send' if confidence > 80 else 'review'
    }
```

---

## 🔧 INTEGRACIÓN ENTRE COMPONENTES

### Odoo → DTE Service

**Cliente HTTP en Odoo:**
```python
# tools/dte_api_client.py
import requests

class DTEApiClient(models.AbstractModel):
    _name = 'dte.api.client'
    
    DTE_SERVICE_URL = 'http://dte-service:8001'
    
    def generate_and_send_dte(self, move_id):
        """Llamar DTE service para generar y enviar"""
        
        # Preparar datos
        data = {
            'dte_type': move_id.dte_type,
            'invoice_data': self._prepare_invoice_data(move_id),
            'certificate': self._get_certificate(move_id.journal_id),
            'environment': 'sandbox'  # o 'production'
        }
        
        # Llamar servicio
        response = requests.post(
            f'{self.DTE_SERVICE_URL}/api/dte/generate-and-send',
            json=data,
            timeout=30
        )
        
        return response.json()
```

### Odoo → AI Service

**Cliente HTTP para IA:**
```python
# tools/ai_api_client.py
class AIApiClient(models.AbstractModel):
    _name = 'ai.api.client'
    
    AI_SERVICE_URL = 'http://ai-service:8002'
    
    def ai_validate(self, move_id):
        """Pre-validación con IA"""
        
        data = {
            'dte_data': self._prepare_invoice_data(move_id),
            'company_id': move_id.company_id.id,
            'history': self._get_rejection_history()
        }
        
        response = requests.post(
            f'{self.AI_SERVICE_URL}/api/ai/validate',
            json=data,
            timeout=5
        )
        
        return response.json()
```

### DTE Service → Odoo (Callback)

**Webhook en Odoo:**
```python
# controllers/dte_webhook.py
from odoo import http

class DTEWebhook(http.Controller):
    
    @http.route('/api/dte/callback', type='json', auth='api_key', methods=['POST'])
    def dte_callback(self, **kw):
        """Recibir resultado de DTE service"""
        
        move_id = request.jsonrequest.get('move_id')
        result = request.jsonrequest.get('result')
        
        move = request.env['account.move'].sudo().browse(move_id)
        move.write({
            'dte_status': result['status'],
            'dte_folio': result.get('folio'),
            'dte_response_sii': result.get('response')
        })
        
        return {'success': True}
```

---

## 📋 PLAN DE FASES DETALLADO

### FASE 0: Setup (Semanas 1-2)
- Stack Docker
- Configuración servicios
- Health checks

### FASE 1: MVP Ventas (Semanas 3-18)
- Semana 3-4: Modelos Odoo
- Semana 5-6: Validadores
- Semana 7-10: DTE Service (XML + Firma)
- Semana 11-14: DTE Service (SOAP)
- Semana 15-16: Integración Odoo ↔ DTE
- Semana 17-18: UI + Testing

### FASE 2: Reportes (Semanas 19-25)
- Semana 19-20: Consumo folios
- Semana 21-22: Libro compra/venta
- Semana 23-24: Guías DTE 52
- Semana 25: Cola async

### FASE 3: Honorarios (Semanas 26-30)
- Semana 26-27: Modelos + Generator DTE 34
- Semana 28-29: Retenciones + Reportes
- Semana 30: Testing

### FASE 4: Testing + IA (Semanas 31-37)
- Semana 31-32: AI - Pre-validación
- Semana 33-34: AI - Reconciliación
- Semana 35-36: Load testing
- Semana 37: Security + Compliance

### FASE 5: Deployment (Semanas 38-41.5)
- Semana 38-39: Documentación
- Semana 40: Training
- Semana 41-41.5: Go-live

---

## ✅ CHECKLIST DE VALIDACIÓN

### Por cada componente creado:

**Odoo Module:**
- [ ] Extiende modelos sin duplicar
- [ ] Reutiliza validaciones de Odoo
- [ ] UI integrada con estilo Odoo
- [ ] Tests unitarios > 85% coverage
- [ ] Documentación en código

**DTE Service:**
- [ ] XML válido contra XSD SII
- [ ] Firma digital verificable
- [ ] SOAP comunicando con SII sandbox
- [ ] Queue procesando async
- [ ] Monitoring con Prometheus

**AI Service:**
- [ ] Accuracy > 90% en validación
- [ ] Precision > 85% en reconciliación
- [ ] Response time < 2s
- [ ] Fallback si LLM falla
- [ ] Monitoring de costos API

---

**Status:** ✅ Plan maestro completo y detallado  
**Próximo Paso:** Iniciar Fase 0 (Setup)

---

**Fecha:** 2025-10-21  
**Versión:** 2.0 DEFINITIVA

