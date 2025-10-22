# 🤖 ESTRATEGIA DE INTEGRACIÓN: AGENTE IA ESPECIALIZADO EN ODOO 19 CE

**Versión:** 1.0  
**Fecha:** 2025-10-21  
**Alcance:** Análisis profundo + Plan de integración  
**Objetivo:** Agente IA con procesamiento local + API Anthropic maximizando módulos Odoo base

---

## 📋 ÍNDICE EJECUTIVO

**Contexto:** Instancia Odoo 19 CE con módulo `l10n_cl_dte` (facturación electrónica chilena)

**Oportunidad:** Agregar capacidades de IA para:
- ✅ Procesamiento de documentos financieros
- ✅ Análisis de DTEs y comprobantes
- ✅ Generación automática de reportes
- ✅ Clasificación y validación de datos
- ✅ Consultas inteligentes sobre datos

**Propuesta:** Microservicio IA como complemento a DTE Service

---

## 🎯 PARTE 1: ANÁLISIS DE MÓDULOS ODOO 19 CE A REUTILIZAR

### 1.1 Módulos Base Disponibles (Odoo 19 CE)

```
core/
├── account/                    Contabilidad + Facturas (CRÍTICO)
│   ├─ account.move             Documentos contables
│   ├─ account.journal          Diarios
│   ├─ account.tax              Impuestos
│   ├─ account.payment          Pagos
│   └─ account.analytic         Análisis analítica
│
├── purchase/                   Compras (CRÍTICO para recepción DTEs)
│   ├─ purchase.order           Órdenes compra
│   ├─ purchase.agreement       Acuerdos
│   └─ purchase.bill            Facturas compra (recepción)
│
├── sale/                       Ventas (CRÍTICO para DTEs emitidos)
│   ├─ sale.order               Órdenes venta
│   ├─ sale.order.line          Líneas
│   └─ sale.order.template      Plantillas
│
├── partner/                    Contactos
│   ├─ res.partner              Empresas/personas
│   ├─ res.partner.address      Direcciones
│   └─ res.partner.bank         Datos bancarios
│
├── company/                    Datos empresa
│   ├─ res.company              Empresa principal
│   └─ res.company.sibling      Sucursales
│
├── document/                   Gestión documentos
│   ├─ ir.attachment            Archivos adjuntos
│   ├─ ir.ui.view               Vistas
│   └─ ir.model                 Modelos
│
├── mail/                       Correo + Notificaciones
│   ├─ mail.message             Mensajes
│   ├─ mail.template            Plantillas email
│   └─ mail.channel             Canales comunicación
│
├── report/                     Reportes
│   ├─ ir.report                Definiciones reportes
│   ├─ ir.actions.report        Acciones reportes
│   └─ ir.qweb                  Templates QWeb
│
├── base/                       Sistema base
│   ├─ ir.cron                  Crons/schedules
│   ├─ ir.logging               Logging
│   ├─ res.users                Usuarios
│   ├─ res.groups               Grupos/Roles
│   ├─ ir.model.access          Control acceso
│   └─ ir.rule                  Reglas seguridad
│
└── web/                        Web + UI
    ├─ web.assets               Assets (JS/CSS)
    └─ web.client               Cliente web
```

### 1.2 Matriz de Reutilización para Agente IA

| Módulo Base | Entidad | Reutilización en Agente IA | Justificación |
|---|---|---|---|
| **account** | account.move | ⭐⭐⭐ MÁXIMA | Procesar facturas, DTEs, comprobantes |
| **account** | account.journal | ⭐⭐ MEDIA | Contexto de diario (venta/compra) |
| **account** | account.tax | ⭐⭐ MEDIA | Análisis de impuestos en DTEs |
| **purchase** | purchase.order | ⭐⭐⭐ MÁXIMA | Reconciliar DTEs recibidos con POs |
| **purchase** | purchase.bill | ⭐⭐⭐ MÁXIMA | Validar facturas compra recibidas |
| **sale** | sale.order | ⭐⭐⭐ MÁXIMA | Vincular DTEs emitidos con SOVs |
| **partner** | res.partner | ⭐⭐ MEDIA | Validación RUT, identificación clientes |
| **company** | res.company | ⭐⭐ MEDIA | Contexto tributario de empresa |
| **document** | ir.attachment | ⭐⭐⭐ MÁXIMA | Almacenar PDFs, XMLs, documentos DTE |
| **mail** | mail.message | ⭐⭐ MEDIA | Notificaciones de análisis IA |
| **report** | ir.report | ⭐⭐⭐ MÁXIMA | Generar reportes con insights IA |
| **base** | ir.cron | ⭐⭐⭐ MÁXIMA | Procesar documentos en batch |
| **base** | ir.logging | ⭐⭐ MEDIA | Auditoría de decisiones IA |
| **base** | res.users | ⭐⭐ MEDIA | Control de acceso a análisis |
| **base** | ir.model.access | ⭐⭐ MEDIA | Permisos granulares |
| **web** | web.assets | ⭐ BAJA | UI para resultados IA |

---

## 🏗️ PARTE 2: ARQUITECTURA DEL AGENTE IA

### 2.1 Componentes del Servicio IA

```
┌─────────────────────────────────────────────────────────────┐
│              AGENTE IA MICROSERVICIO (Python)              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 1. DOCUMENT PROCESSOR                               │  │
│  │ ├─ PDF Parser (pypdf, pdfplumber)                   │  │
│  │ ├─ XML Parser (lxml)                                │  │
│  │ ├─ CSV/Excel Parser (pandas)                        │  │
│  │ └─ OCR for images (pytesseract + tesseract)         │  │
│  └──────────────────────────────────────────────────────┘  │
│           ↓                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 2. LOCAL EMBEDDING & VECTORIZATION                  │  │
│  │ ├─ Ollama (local LLM inference)                      │  │
│  │ ├─ Sentence-Transformers (embeddings)               │  │
│  │ ├─ ChromaDB or Milvus (vector DB)                   │  │
│  │ └─ RAG Pipeline (Retrieval-Augmented Generation)    │  │
│  └──────────────────────────────────────────────────────┘  │
│           ↓                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 3. CONTEXT BUILDER (Odoo Integration)               │  │
│  │ ├─ Fetch account.move data                          │  │
│  │ ├─ Fetch purchase.order context                     │  │
│  │ ├─ Fetch partner info                               │  │
│  │ ├─ Fetch ir.attachment (PDFs/XMLs)                 │  │
│  │ └─ Build structured context JSON                    │  │
│  └──────────────────────────────────────────────────────┘  │
│           ↓                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 4. PROMPT ENGINEERING ENGINE                        │  │
│  │ ├─ Domain-specific prompts (DTE, accounting)        │  │
│  │ ├─ Few-shot learning templates                      │  │
│  │ ├─ Chain-of-thought reasoning                       │  │
│  │ └─ Output validation schemas                        │  │
│  └──────────────────────────────────────────────────────┘  │
│           ↓                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 5. API INTEGRATION (Anthropic Claude)               │  │
│  │ ├─ API client (anthropic library)                   │  │
│  │ ├─ Batch processing support                         │  │
│  │ ├─ Error handling & retries                         │  │
│  │ ├─ Cost tracking                                    │  │
│  │ └─ Token counting                                   │  │
│  └──────────────────────────────────────────────────────┘  │
│           ↓                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 6. RESULT PARSER & VALIDATOR                        │  │
│  │ ├─ JSON/Structured output parsing                   │  │
│  │ ├─ Confidence scoring                               │  │
│  │ ├─ Validation against schemas                       │  │
│  │ └─ Error classification                             │  │
│  └──────────────────────────────────────────────────────┘  │
│           ↓                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 7. ODOO WRITER & PERSISTENCE                        │  │
│  │ ├─ ORM integration (models create/write)            │  │
│  │ ├─ Transaction management                           │  │
│  │ ├─ Audit logging (ir.logging)                       │  │
│  │ ├─ Store results in ir.attachment                   │  │
│  │ └─ Notification via mail.message                    │  │
│  └──────────────────────────────────────────────────────┘  │
│           ↓                                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 8. REST API LAYER (FastAPI/Flask)                   │  │
│  │ ├─ POST /analyze/document (PDF/XML upload)          │  │
│  │ ├─ POST /analyze/dte (analyze DTE)                  │  │
│  │ ├─ POST /reconcile/purchase (match compras)         │  │
│  │ ├─ POST /classify/invoice (auto-classify)           │  │
│  │ ├─ GET /results/{job_id} (retrieve results)         │  │
│  │ └─ GET /health (service health)                     │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
           ↑              ↑              ↑
           │              │              │
        Odoo         Local Files    Anthropic
      ORM API       (PDF/XML)       Claude API
```

### 2.2 Flujo de Ejecución Completo

```
USUARIO EN ODOO
    │
    ├─→ Crea DTE (account.move + ir.attachment con PDF/XML)
    │
    └─→ Click "Analizar con IA" (botón custom en vista)
            │
            ├─→ Odoo REST POST a Agente IA
            │       {
            │         "move_id": 123,
            │         "document_type": "dte_invoice",
            │         "file_content_base64": "...",
            │         "context": {
            │           "company_vat": "76.123.456-5",
            │           "partner_vat": "76.654.321-2",
            │           "amount_total": 150000
            │         }
            │       }
            │
            ├─→ AGENTE IA PROCESA:
            │   1. Descarga documento
            │   2. Extrae texto/datos
            │   3. Construye contexto Odoo
            │   4. Genera embeddings (local)
            │   5. Prepara prompt
            │   6. Llama Claude API (Anthropic)
            │   7. Valida respuesta
            │   8. Escribe resultado en Odoo
            │
            ├─→ Agente IA retorna resultado:
            │       {
            │         "success": true,
            │         "analysis": {
            │           "is_valid": true,
            │           "confidence": 0.98,
            │           "classification": "factura_compra",
            │           "extracted_fields": {
            │             "folio": "12345",
            │             "amount": 150000,
            │             "date": "2025-10-21"
            │           },
            │           "anomalies": [],
            │           "recommendations": ["Verificar RUT proveedor"]
            │         }
            │       }
            │
            └─→ Odoo:
                ├─ Crea ir.attachment (resultado JSON)
                ├─ Escribe mail.message (notificación)
                ├─ Actualiza custom fields en account.move
                └─ Muestra resultado en UI (dashboard)

USUARIO VE:
    ✅ "DTE analizado correctamente"
    ✅ "Validación: PASÓ"
    ✅ "Confianza: 98%"
    ✅ "Anomalías: Ninguna"
    ✅ "Botón: Ver Detalles Análisis"
```

---

## 💡 PARTE 3: CASOS DE USO ESPECÍFICOS PARA FACTURACIÓN CHILENA

### 3.1 Caso 1: Validación Automática de DTEs Emitidos

**Problema:** Generar DTE pero validar antes de enviar a SII

**Solución IA:**
```
INPUT:
  └─ account.move (factura draft)
     ├─ lines (10 líneas)
     ├─ taxes (3 impuestos)
     └─ partner (cliente)

AGENTE IA EJECUTA:
  1. Extrae datos de account.move
  2. Construye contexto: "Validar factura chilena tipo 33"
  3. Llama Claude con:
     ├─ Datos factura
     ├─ Reglas SII conocidas
     ├─ RUT validation
     └─ Tax calculation verification
  4. Claude retorna:
     {
       "is_valid_for_sii": true,
       "issues": [
         {
           "field": "tax_code_1",
           "issue": "Impuesto adicional 14 sin código",
           "severity": "warning",
           "fix": "Agregar codigo_impuesto = 14"
         }
       ],
       "confidence": 0.99
     }
  5. Agente crea ir.attachment con resultado
  6. Notifica usuario: "DTE listo para enviar (1 advertencia)"

REUTILIZACIÓN ODOO:
  ├─ account.move (extender con field "ia_validation_result")
  ├─ account.tax (usar códigos existentes)
  ├─ ir.attachment (guardar análisis)
  ├─ mail.message (notificación)
  └─ ir.logging (auditoría)
```

### 3.2 Caso 2: Reconciliación Inteligente de Compras Recibidas

**Problema:** DTEs compras recibidos vs POs en Odoo = a veces hay discrepancias

**Solución IA:**
```
INPUT:
  └─ DTE recibido (XML descargado de SII)
     ├─ Proveedor RUT
     ├─ Monto
     ├─ Líneas
     └─ Fecha

AGENTE IA EJECUTA:
  1. Parsea XML del DTE
  2. Busca purchase.order relacionadas
     ├─ Mismo proveedor
     ├─ Fecha cercana (±15 días)
     └─ Monto aproximado (±5%)
  3. Para cada PO candidata:
     ├─ Compara líneas (descripción, cantidad)
     ├─ Compara montos (total, taxes)
     └─ Calcula similitud (cosine similarity embeddings)
  4. Claude analiza:
     {
       "matched_po_id": 567,
       "confidence": 0.95,
       "line_mapping": [
         {
           "dte_line": "10x Laptop Dell",
           "po_line": "10 DELL XPS 13",
           "match_confidence": 0.92
         }
       ],
       "anomalies": [
         {
           "type": "amount_mismatch",
           "expected": 2000000,
           "received": 2050000,
           "difference_pct": 2.5,
           "severity": "low"
         }
       ],
       "recommendation": "APPROVE_WITH_EXCEPTION"
     }
  5. Crea purchase.bill automáticamente
  6. Si anomalías = requiere aprobación manual

REUTILIZACIÓN ODOO:
  ├─ purchase.order (buscar/relacionar)
  ├─ purchase.bill (crear automáti)
  ├─ res.partner (validar proveedor)
  ├─ ir.attachment (guardar DTE XML)
  ├─ mail.message (notificación aprobador)
  └─ ir.logging (auditoría matching)
```

### 3.3 Caso 3: Clasificación Automática de Documentos Escaneados

**Problema:** Cliente envía factura escaneada = OCR + clasificación manual

**Solución IA:**
```
INPUT:
  └─ Usuario sube PDF escaneado vía adjunto en Odoo

AGENTE IA EJECUTA:
  1. Descarga PDF de ir.attachment
  2. OCR local (pytesseract en container)
  3. Construye texto extraído
  4. Claude analiza:
     {
       "document_type": "factura_compra",
       "confidence": 0.98,
       "extracted_fields": {
         "folio": "FC-2025-12345",
         "date": "2025-10-21",
         "vendor_name": "Proveedor XYZ Ltda",
         "vendor_rut": "76.654.321-2",
         "amount_total": 1500000,
         "amount_tax": 285000,
         "currency": "CLP"
       },
       "quality_assessment": {
         "legibility": "good",
         "completeness": "high",
         "data_extraction_confidence": 0.94
       }
     }
  5. Crea purchase.bill automáticamente:
     ├─ partner_id = búsqueda por RUT
     ├─ invoice_date = fecha extraída
     ├─ amount_total = monto extraído
     └─ attachment = PDF escaneado
  6. Notifica: "Factura importada automáticamente"

REUTILIZACIÓN ODOO:
  ├─ ir.attachment (documento original)
  ├─ purchase.bill (crear propuesta)
  ├─ res.partner (lookup por RUT)
  ├─ mail.message (notificación usuario)
  └─ ir.logging (auditoría OCR)
```

### 3.4 Caso 4: Análisis de Tendencias y Anomalías

**Problema:** "¿Hay compras sospechosas?" / "¿Patrones raros?"

**Solución IA:**
```
INPUT:
  └─ Últimas 100 purchase.bill (últimos 3 meses)

AGENTE IA EJECUTA:
  1. Extrae histórico:
     ├─ Montos por proveedor
     ├─ Fechas de compra
     ├─ Categorías de producto
     └─ Términos de pago
  2. Llama Claude con análisis estadístico:
     {
       "anomalies_detected": [
         {
           "type": "unusual_vendor",
           "vendor": "Empresa Rara Ltda",
           "issue": "Primera compra, monto alto (5M CLP)",
           "risk": "medium",
           "action": "Verificar RUT en SII"
         },
         {
           "type": "duplicate_invoice",
           "vendor": "Proveedor ABC",
           "duplicate_with": "Factura 2025-10-15",
           "risk": "high",
           "action": "REJECT - Posible duplicado"
         }
       ],
       "trends": [
         {
           "category": "Servicios TI",
           "trend": "spending_up_25%",
           "period": "last_3_months",
           "recommendation": "Revisar con área TI"
         }
       ]
     }
  3. Crea reporte ir.report automático
  4. Notifica gerencia: "3 anomalías detectadas"

REUTILIZACIÓN ODOO:
  ├─ purchase.bill (historial)
  ├─ ir.report (crear reporte)
  ├─ res.users (filtrar gerentes)
  ├─ mail.message (notificación)
  └─ ir.logging (análisis audit)
```

### 3.5 Caso 5: Generación de Reportes Analíticos Inteligentes

**Problema:** "Damé reporte de facturación por categoría" = manual

**Solución IA:**
```
INPUT:
  └─ Filtro: Ventas últimos 3 meses, por categoría

AGENTE IA EJECUTA:
  1. Consulta account.move + sale.order
  2. Claude analiza:
     {
       "report": {
         "period": "2025-08-21 a 2025-10-21",
         "categories": [
           {
             "category": "Productos Electrónicos",
             "count": 45,
             "total_amount": 150000000,
             "average": 3333333,
             "growth_vs_prev": "+12%",
             "top_customers": [
               "Empresa A",
               "Empresa B"
             ]
           }
         ],
         "insights": [
           "Categoría 'Electrónicos' creció 12% vs período anterior",
           "Cliente XYZ representó 25% de ventas",
           "Promedio de facturas = $3.3M"
         ],
         "recommendations": [
           "Enfocarse en segmento Electrónicos (mejor margen)"
         ]
       }
     }
  3. Genera PDF con gráficos (reportlab)
  4. Guarda en ir.attachment
  5. Notifica: "Reporte listo"

REUTILIZACIÓN ODOO:
  ├─ account.move (datos ventas)
  ├─ sale.order (contexto)
  ├─ ir.report (definición reporte)
  ├─ ir.attachment (guardar PDF)
  └─ mail.message (notificación)
```

---

## 🛠️ PARTE 4: STACK TÉCNICO COMPLETO

### 4.1 Componentes del Agente IA

| Componente | Librería | Versión | Función | Ubicación |
|---|---|---|---|---|
| **Document Processing** | pypdf | >=3.0 | PDF parsing | AI Service |
| | pdfplumber | >=0.9 | PDF text extraction | AI Service |
| | pandas | >=2.0 | CSV/Excel handling | AI Service |
| | python-pptx | >=0.6 | PowerPoint parsing | AI Service |
| | pytesseract | >=0.3 | OCR wrapper | AI Service |
| **Embeddings & Vectors** | sentence-transformers | >=2.2 | Local embeddings | AI Service |
| | chromadb | >=0.3 | Vector DB | AI Service |
| | numpy | >=1.24 | Numerical computing | AI Service |
| **Local LLM** | ollama | CLI | Local inference | AI Service (Docker) |
| | transformers | >=4.30 | Hugging Face models | AI Service |
| **API Integration** | anthropic | >=0.7 | Claude API | AI Service |
| | openai | >=1.0 | Fallback (optional) | AI Service |
| **Odoo Integration** | xmlrpc | stdlib | Odoo RPC | AI Service |
| | requests | >=2.31 | HTTP requests | AI Service |
| **Web Framework** | fastapi | >=0.100 | REST API | AI Service |
| | uvicorn | >=0.23 | ASGI server | AI Service |
| | pydantic | >=2.0 | Data validation | AI Service |
| **Utils** | python-dotenv | >=1.0 | Config management | AI Service |
| | loguru | >=0.7 | Logging | AI Service |
| | tenacity | >=8.2 | Retry logic | AI Service |

### 4.2 Docker Compose para AI Service

```yaml
version: '3.8'

services:
  # Servicio Odoo existente
  odoo:
    # ... configuración existente ...
    environment:
      - AI_SERVICE_URL=http://ai-service:8000
    depends_on:
      - ai-service

  # ========== NUEVO: AI Microservice ==========
  ai-service:
    build:
      context: ./ai-service
      dockerfile: Dockerfile
    image: eergygroup/ai-service:v1
    container_name: ai-service
    ports:
      - "8001:8000"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OLLAMA_API_URL=http://ollama:11434
      - ODOO_URL=http://odoo:8069
      - ODOO_DB=odoo
      - ODOO_USER=admin
      - ODOO_PASSWORD=${ODOO_PASSWORD}
      - LOG_LEVEL=info
    volumes:
      - ./ai-service/app:/app
      - ./data/ai-cache:/app/cache          # Cache para embeddings
      - ./data/ai-uploads:/app/uploads      # Documentos subidos
      - ./data/ai-logs:/app/logs            # Logs
    depends_on:
      - ollama
    networks:
      - odoo_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ========== Ollama para Local LLM ==========
  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    ports:
      - "11434:11434"
    volumes:
      - ./data/ollama-models:/root/.ollama  # Modelos descargados
    environment:
      - OLLAMA_HOST=0.0.0.0:11434
    networks:
      - odoo_network
    command: serve

volumes:
  postgres_data:

networks:
  odoo_network:
    driver: bridge
```

### 4.3 Dockerfile para AI Service

```dockerfile
FROM python:3.11-slim-bullseye

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    poppler-utils \
    libsm6 \
    libxext6 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 🔐 PARTE 5: INTEGRACIÓN SEGURA CON ANTHROPIC

### 5.1 Configuración y Credenciales

```python
# ai-service/config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Anthropic
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL = "claude-3-5-sonnet-20241022"
    ANTHROPIC_MAX_TOKENS = 4096
    
    # Ollama (local)
    OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434")
    OLLAMA_MODEL = "mistral"  # o "llama2"
    
    # Odoo
    ODOO_URL = os.getenv("ODOO_URL")
    ODOO_DB = os.getenv("ODOO_DB")
    ODOO_USER = os.getenv("ODOO_USER")
    ODOO_PASSWORD = os.getenv("ODOO_PASSWORD")
    
    # Security
    API_KEY = os.getenv("AI_SERVICE_API_KEY")  # Para autenticar llamadas Odoo → AI
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "info")
```

### 5.2 Cliente Seguro para Anthropic

```python
# ai-service/clients/anthropic_client.py
from anthropic import Anthropic, APIError
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

logger = logging.getLogger(__name__)

class AnthropicClient:
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        self.client = Anthropic(api_key=api_key)
        self.model = model
        self.conversation_history = []
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def analyze_document(
        self,
        document_text: str,
        context: dict,
        system_prompt: str
    ) -> dict:
        """
        Analizar documento con Claude
        
        Args:
            document_text: Texto extraído del documento
            context: Contexto Odoo (factura, cliente, etc)
            system_prompt: Instrucciones específicas del dominio
        
        Returns:
            Resultado análisis
        """
        try:
            # Construir prompt
            user_message = f"""
CONTEXTO ODOO:
{self._format_context(context)}

DOCUMENTO A ANALIZAR:
{document_text}

Por favor, analiza el documento según las instrucciones previas.
Retorna respuesta en JSON válido.
"""
            
            # Llamar Claude
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_message}
                ]
            )
            
            # Extraer y validar respuesta
            result_text = response.content[0].text
            result_json = self._parse_json_response(result_text)
            
            logger.info(f"Claude analysis successful. Cost estimate: {self._estimate_cost(response)}")
            
            return {
                "success": True,
                "analysis": result_json,
                "usage": {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens
                }
            }
        
        except APIError as e:
            logger.error(f"Anthropic API error: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "error_type": "api_error"
            }
    
    def _format_context(self, context: dict) -> str:
        """Formatear contexto Odoo para prompt"""
        return f"""
Company: {context.get('company_name')}
Company VAT: {context.get('company_vat')}
Partner: {context.get('partner_name')}
Partner VAT: {context.get('partner_vat')}
Document Type: {context.get('document_type')}
Amount: {context.get('amount_total')}
Currency: {context.get('currency')}
Date: {context.get('date')}
"""
    
    def _parse_json_response(self, text: str) -> dict:
        """Extraer JSON de respuesta Claude"""
        import json
        import re
        
        # Buscar JSON en la respuesta
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        
        # Fallback: retornar texto como respuesta
        return {"raw_response": text}
    
    def _estimate_cost(self, response) -> dict:
        """Estimar costo de la llamada API"""
        # Valores aproximados (octubre 2025)
        input_cost_per_1k = 0.003  # $3 per 1M input tokens
        output_cost_per_1k = 0.015  # $15 per 1M output tokens
        
        cost = (
            response.usage.input_tokens * input_cost_per_1k / 1000 +
            response.usage.output_tokens * output_cost_per_1k / 1000
        )
        
        return {"usd": cost}
```

### 5.3 Integración Segura con Odoo (desde AI Service)

```python
# ai-service/clients/odoo_client.py
import xmlrpc.client
from typing import List, Dict
import logging

logger = logging.getLogger(__name__)

class OdooClient:
    def __init__(self, url: str, db: str, username: str, password: str):
        self.url = url
        self.db = db
        self.username = username
        self.password = password
        self.common = xmlrpc.client.ServerProxy(f'{url}/jsonrpc')
        self.models = xmlrpc.client.ServerProxy(f'{url}/jsonrpc')
    
    def authenticate(self) -> int:
        """Autenticar con Odoo"""
        try:
            uid = self.common.execute(
                self.db,
                2,
                self.password,
                'res.users',
                'authenticate',
                self.username,
                self.password,
                {}
            )
            logger.info(f"Authenticated to Odoo as {self.username}")
            return uid
        except Exception as e:
            logger.error(f"Odoo authentication failed: {str(e)}")
            raise
    
    def get_account_move(self, move_id: int) -> dict:
        """Obtener factura desde account.move"""
        try:
            uid = self.authenticate()
            move = self.models.execute_kw(
                self.db, uid, self.password,
                'account.move', 'read', [move_id],
                {'fields': ['id', 'name', 'amount_total', 'partner_id', 'invoice_date', 'attachment_ids']}
            )
            return move[0] if move else None
        except Exception as e:
            logger.error(f"Failed to read account.move: {str(e)}")
            return None
    
    def create_attachment(self, move_id: int, filename: str, data: bytes, mimetype: str) -> int:
        """Crear ir.attachment con resultado análisis"""
        try:
            uid = self.authenticate()
            attachment_id = self.models.execute_kw(
                self.db, uid, self.password,
                'ir.attachment', 'create',
                [{
                    'name': filename,
                    'res_model': 'account.move',
                    'res_id': move_id,
                    'datas': data.hex(),
                    'type': 'binary',
                    'mimetype': mimetype
                }]
            )
            logger.info(f"Created attachment {attachment_id} for move {move_id}")
            return attachment_id
        except Exception as e:
            logger.error(f"Failed to create attachment: {str(e)}")
            raise
    
    def write_ai_analysis_field(self, move_id: int, analysis_result: dict):
        """Escribir resultado análisis en account.move (custom field)"""
        try:
            uid = self.authenticate()
            import json
            self.models.execute_kw(
                self.db, uid, self.password,
                'account.move', 'write',
                [move_id],
                {
                    'x_ai_analysis_result': json.dumps(analysis_result),
                    'x_ai_analysis_timestamp': datetime.now().isoformat()
                }
            )
            logger.info(f"Updated AI analysis for move {move_id}")
        except Exception as e:
            logger.error(f"Failed to write AI analysis: {str(e)}")
            raise
    
    def send_notification(self, user_ids: List[int], subject: str, message: str):
        """Enviar notificación via mail.message"""
        try:
            uid = self.authenticate()
            for user_id in user_ids:
                self.models.execute_kw(
                    self.db, uid, self.password,
                    'mail.message', 'create',
                    [{
                        'subject': subject,
                        'body': message,
                        'message_type': 'notification',
                        'res_model': 'res.users',
                        'res_id': user_id
                    }]
                )
            logger.info(f"Notification sent to {len(user_ids)} users")
        except Exception as e:
            logger.error(f"Failed to send notification: {str(e)}")
            raise
```

---

## 📋 PARTE 6: PLAN DE IMPLEMENTACIÓN

### 6.1 Fases de Desarrollo

| Fase | Duración | Objetivo | Componentes |
|---|---|---|---|
| **Fase 1** | 2 sem | Setup infraestructura | Docker, FastAPI, config Anthropic |
| **Fase 2** | 2 sem | Document processing | PDF/XML parsing, OCR local |
| **Fase 3** | 2 sem | Embedding & RAG | Sentence-transformers, ChromaDB |
| **Fase 4** | 2 sem | Integración Odoo | ORM client, custom fields, attachment storage |
| **Fase 5** | 3 sem | Prompts específicos | DTE analysis, reconciliation, classification |
| **Fase 6** | 2 sem | API REST layer | FastAPI endpoints, error handling |
| **Fase 7** | 2 sem | UI en Odoo | Botones, vistas, dashboards |
| **Fase 8** | 2 sem | Testing & Optimization | Unit tests, load testing, cost optimization |
| | **17 sem** | **MVP COMPLETO** | **Agente IA totalmente funcional** |

### 6.2 Hitos Clave

```
Semana 1-2:   ✅ Infraestructura base (Docker compose actualizado)
Semana 3-4:   ✅ Document processing (PDF/XML parsing)
Semana 5-6:   ✅ Local embeddings (RAG pipeline)
Semana 7-8:   ✅ Integración Odoo RPC
Semana 9-11:  ✅ Prompts dominio (DTE-específicos)
Semana 12-13: ✅ API REST endpoints
Semana 14-15: ✅ UI Odoo (botones, vistas)
Semana 16-17: ✅ Testing & optimización

MVP DELIVERY: Semana 17 (4 meses)
```

---

## 🎯 PARTE 7: CASOS DE USO ORDENADOS POR IMPACTO

### Matriz de Priorización

| Caso | Complejidad | Impacto | Reutilización Odoo | Prioridad |
|---|---|---|---|---|
| 1. Validación DTE | Media | Alto | account.move, ir.attachment | ⭐⭐⭐ CRÍTICA |
| 2. Reconciliación Compras | Alta | Alto | purchase.order, purchase.bill | ⭐⭐⭐ CRÍTICA |
| 3. Clasificación Documentos | Media | Medio | ir.attachment, purchase.bill | ⭐⭐ IMPORTANTE |
| 4. Anomalía Detection | Alta | Medio | purchase.bill, account.move | ⭐⭐ IMPORTANTE |
| 5. Reportes Analíticos | Media | Medio | account.move, ir.report | ⭐ DESEABLE |

**Recomendación:** Empezar con Casos 1 y 2 (semanas 9-13)

---

## 📊 PARTE 8: COST ANALYSIS

### 8.1 Costo API Anthropic

```
ESTIMACIÓN (por mes):

Caso: 500 documentos procesados/mes

Promedio tokens por documento:
  Input: ~3,000 tokens
  Output: ~1,500 tokens
  Total: 4,500 tokens por doc

Consumo mensual:
  500 docs × 4,500 tokens = 2.25M tokens input
  500 docs × 750 tokens output = 375k tokens output

Costo Anthropic (Claude 3.5 Sonnet - Oct 2025):
  Input: 2.25M × ($3/1M) = $6.75
  Output: 375k × ($15/1M) = $5.62
  
  TOTAL MENSUAL: ~$12.37 USD

Costo anual: ~$148 USD (MUY BAJO)

+ Infraestructura (Docker, GPU para Ollama): ~$100-200/mes
= TOTAL: ~$112-212/mes = $1,344-2,544/año
```

### 8.2 ROI

```
BENEFICIOS (anuales):
  - Validación DTE automática: 100 horas ahorradas = $3,000 USD
  - Reconciliación compras: 150 horas = $4,500 USD
  - Clasificación documentos: 80 horas = $2,400 USD
  - Análisis anomalías: 50 horas = $1,500 USD
  
  TOTAL AHORRO: $11,400 USD/año

COSTO TOTAL: $2,544 USD/año

ROI: 11,400 / 2,544 = 4.48x (450% return)

Payback period: ~27 días
```

---

## ✅ CONCLUSIÓN: RECOMENDACIÓN FINAL

### Implementar Agente IA CON:

1. **Arquitectura Híbrida:**
   - ✅ Local processing (OCR, embeddings via Ollama)
   - ✅ Cloud processing (análisis complejo via Claude)
   - ✅ Zero-latency para validaciones simples

2. **Máxima Reutilización Odoo:**
   - ✅ account.move (facturas)
   - ✅ purchase.order/bill (compras)
   - ✅ ir.attachment (documentos)
   - ✅ ir.logging (auditoría)
   - ✅ mail.message (notificaciones)
   - ✅ ir.report (reportes)

3. **Casos de Uso Priorizados:**
   - 🔴 P1: Validación DTE + Reconciliación compras
   - 🟡 P2: Clasificación documentos + Anomalía detection
   - 🟢 P3: Reportes analíticos

4. **Timeline:**
   - 🚀 MVP: 17 semanas (4 meses)
   - 💰 ROI: 4.48x en primer año
   - 📦 Costo: ~$2,500 USD/año

5. **Siguiente Paso:**
   - ✅ Crear documento "AI-SERVICE-ARCHITECTURE.md" con especificaciones técnicas detalladas
   - ✅ Preparar estructura de carpetas `/ai-service/`
   - ✅ Documentar prompts específicos para cada caso de uso
