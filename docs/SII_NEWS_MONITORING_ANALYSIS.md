# 🔍 ANÁLISIS PROFUNDO: Implementación de Monitoreo de Noticias SII

**Fecha:** 2025-10-22  
**Versión:** 1.0  
**Propósito:** Análisis arquitectónico para integrar monitoreo permanente de circulares, resoluciones y normativa SII  
**Estado:** ANÁLISIS (No implementación)

---

## 📋 ÍNDICE

1. [Contexto del Proyecto](#contexto)
2. [Análisis de Arquitectura Actual](#arquitectura-actual)
3. [Propuesta: AI Service como Orquestador](#propuesta)
4. [Diseño Detallado](#diseño-detallado)
5. [Integración con Componentes Existentes](#integración)
6. [Flujos de Datos](#flujos)
7. [Consideraciones Técnicas](#consideraciones)
8. [Roadmap de Implementación](#roadmap)

---

<a name="contexto"></a>
## 1. 🎯 CONTEXTO DEL PROYECTO

### 1.1 Situación Actual

**Proyecto:** Odoo 19 CE con localización chilena DTE (99.5% completo)

**Arquitectura:**
```
┌─────────────────────────────────────────────────────────────┐
│                    ODOO 19 CE                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  l10n_cl_dte Module                                   │  │
│  │  - account.move extensions (DTEs 33,56,61)           │  │
│  │  - purchase.order extensions (DTE 34)                │  │
│  │  - stock.picking extensions (DTE 52)                 │  │
│  │  - Wizards, Views, Security                          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐      ┌─────▼────┐     ┌─────▼─────┐
    │   DTE   │      │    AI    │     │ RabbitMQ  │
    │ Service │      │ Service  │     │   Queue   │
    │ (8001)  │      │ (8002)   │     │           │
    └─────────┘      └──────────┘     └───────────┘
         │                 │                 │
    XML/Firma      Claude API +        Async Jobs
    SII SOAP       Embeddings          (batch)
```

**Servicios Actuales:**
- **Odoo Module:** UI/UX, modelos, workflows
- **DTE Service:** Generación XML, firma digital, SOAP SII
- **AI Service:** Validación pre-envío (Claude), reconciliación (embeddings)
- **RabbitMQ:** Procesamiento asíncrono batch
- **Redis:** Cache (certificados, CAF ranges)
- **PostgreSQL:** Persistencia

### 1.2 Problema a Resolver

**Desafío:**
El SII publica constantemente:
- ✅ Circulares con interpretaciones normativas
- ✅ Resoluciones con cambios técnicos
- ✅ Actualizaciones de esquemas XSD
- ✅ Cambios en tipos de documentos
- ✅ Nuevos códigos de impuestos
- ✅ Modificaciones en SOAP endpoints

**Impacto:**
- ❌ Sin monitoreo → Implementación obsoleta
- ❌ Cambios detectados tarde → Rechazos SII
- ❌ Revisión manual → Ineficiente y propensa a errores
- ❌ Sin trazabilidad → Compliance en riesgo

**Objetivo:**
Sistema automatizado que:
1. Monitoree URLs SII permanentemente
2. Detecte cambios en normativa
3. Extraiga información relevante
4. Clasifique impacto en componentes
5. Notifique al equipo
6. Actualice documentación
7. Genere tareas de implementación

---

<a name="arquitectura-actual"></a>
## 2. 🏗️ ANÁLISIS DE ARQUITECTURA ACTUAL

### 2.1 AI Service - Estado Actual

**Ubicación:** `/ai-service/`

**Estructura:**
```
ai-service/
├── main.py                          # FastAPI app
├── config.py                        # Settings (Pydantic)
├── clients/
│   └── anthropic_client.py          # Claude API
├── reconciliation/
│   └── invoice_matcher.py           # Embeddings (sentence-transformers)
├── receivers/
│   └── xml_parser.py                # Parse XML DTEs
├── validators/                      # (Pendiente)
├── models/                          # (Pendiente)
└── utils/                           # (Pendiente)
```

**Endpoints Actuales:**
```python
POST /api/ai/validate
- Pre-validación DTE con Claude
- Input: dte_data, company_id, history
- Output: confidence, warnings, errors, recommendation

POST /api/ai/reconcile
- Reconciliación factura recibida con POs
- Input: dte_xml, pending_pos
- Output: po_id, confidence, line_matches
```

**Capacidades Existentes:**
✅ Claude API integrado (Anthropic)
✅ Embeddings (sentence-transformers)
✅ FastAPI + async
✅ Singleton pattern (modelos ML)
✅ Error handling con fallback
✅ Logging estructurado (structlog)
✅ Security (Bearer token)

**Gaps Identificados:**
❌ No tiene web scraping
❌ No tiene scheduling (cron)
❌ No tiene almacenamiento de noticias
❌ No tiene análisis de texto
❌ No tiene clasificación de impacto
❌ No tiene notificaciones

### 2.2 Capacidades de Claude API

**Claude 3.5 Sonnet (actual):**
- ✅ 200K tokens de contexto
- ✅ Comprensión de documentos largos
- ✅ Análisis semántico avanzado
- ✅ Clasificación de texto
- ✅ Extracción de entidades
- ✅ Resumen de documentos
- ✅ Detección de cambios
- ✅ Análisis de impacto

**Uso Ideal para Noticias SII:**
```python
# Prompt ejemplo
"""
Eres un experto en facturación electrónica chilena (SII).

TAREA: Analiza la siguiente circular/resolución del SII:

{documento_sii}

CONTEXTO DE NUESTRO SISTEMA:
- Soportamos DTEs: 33, 34, 52, 56, 61
- Generadores XML con XSD validation
- Firma digital PKCS#1 (RSA-SHA256)
- SOAP Client (Maullin/Palena)
- Odoo 19 CE con módulo l10n_cl_dte

RESPONDE EN JSON:
{
  "tipo_documento": "circular|resolucion|xsd|otro",
  "fecha": "YYYY-MM-DD",
  "numero": "XX",
  "titulo": "...",
  "resumen": "...",
  "cambios_tecnicos": ["..."],
  "fecha_vigencia": "YYYY-MM-DD",
  "impacto": {
    "nivel": "alto|medio|bajo",
    "componentes_afectados": ["generador_33", "signer", ...],
    "requiere_certificacion": true|false,
    "breaking_change": true|false
  },
  "acciones_requeridas": ["..."],
  "prioridad": 1-5
}
"""
```

### 2.3 Odoo Module - Capacidades de Integración

**Modelos Existentes:**
```python
# l10n_cl_dte/models/
- account_move_dte.py           # DTEs 33,56,61
- purchase_order_dte.py         # DTE 34
- stock_picking_dte.py          # DTE 52
- dte_certificate.py            # Certificados digitales
- dte_caf.py                    # Folios (CAF)
- dte_communication.py          # Logs SOAP SII
- dte_consumo_folios.py         # Consumo folios
- dte_libro.py                  # Libros contables
- res_config_settings.py        # Configuración
```

**Puntos de Extensión:**
1. **Nuevo Modelo:** `dte.sii.news` (noticias SII)
2. **Nuevo Modelo:** `dte.sii.monitoring` (configuración monitoreo)
3. **Nuevo Wizard:** `wizard/sii_news_review.py` (revisión manual)
4. **Nueva Vista:** Vista tree/form para noticias
5. **Nuevo Cron:** `ir.cron` para scheduling
6. **Nuevo Dashboard:** Widget con noticias recientes

---

<a name="propuesta"></a>
## 3. 💡 PROPUESTA: AI SERVICE COMO ORQUESTADOR

### 3.1 Por Qué AI Service (No DTE Service)

**Justificación:**

| Criterio | AI Service | DTE Service | Ganador |
|----------|-----------|-------------|---------|
| **Capacidad Claude API** | ✅ Ya integrado | ❌ No tiene | 🏆 AI |
| **NLP/Análisis Texto** | ✅ Embeddings, ML | ❌ Solo XML | 🏆 AI |
| **Web Scraping** | ✅ Fácil agregar | ⚠️ Fuera scope | 🏆 AI |
| **Clasificación** | ✅ ML models | ❌ No | 🏆 AI |
| **Contexto** | ✅ Enfoque inteligencia | ❌ Enfoque DTEs | 🏆 AI |
| **Carga trabajo** | ⚠️ Bajo (2 endpoints) | ✅ Alta (crítico) | 🏆 AI |
| **Escalabilidad** | ✅ Fácil agregar features | ❌ Ya complejo | 🏆 AI |

**Decisión:** ✅ **AI Service como orquestador de monitoreo**

**Razones:**
1. Ya tiene Claude API configurado
2. Capacidad de análisis semántico
3. Bajo acoplamiento con DTE generation
4. Scope alineado (inteligencia/análisis)
5. No impacta flujo crítico de DTEs

### 3.2 Arquitectura Propuesta

```
┌─────────────────────────────────────────────────────────────────┐
│                         ODOO 19 CE                              │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  l10n_cl_dte Module                                         │ │
│  │                                                             │ │
│  │  [NUEVO] Models:                                            │ │
│  │  - dte.sii.news (noticias almacenadas)                     │ │
│  │  - dte.sii.monitoring (config URLs, frecuencia)            │ │
│  │                                                             │ │
│  │  [NUEVO] Wizards:                                           │ │
│  │  - wizard/sii_news_review.py (revisión manual)             │ │
│  │                                                             │ │
│  │  [NUEVO] Views:                                             │ │
│  │  - views/dte_sii_news_views.xml                            │ │
│  │  - Dashboard con noticias críticas                         │ │
│  │                                                             │ │
│  │  [NUEVO] Cron:                                              │ │
│  │  - ir.cron → Trigger AI Service cada 6h                    │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ API Call (cada 6h)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AI SERVICE (8002)                          │
│                                                                  │
│  [NUEVO] Módulo: sii_monitor/                                   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  scraper.py                                                 │ │
│  │  - Scrapea URLs SII (BeautifulSoup/Scrapy)                │ │
│  │  - Detecta cambios (hash comparison)                       │ │
│  │  - Descarga PDFs/HTML                                      │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  extractor.py                                               │ │
│  │  - Extrae texto de PDFs (pdfplumber)                       │ │
│  │  - Limpia HTML                                             │ │
│  │  - Normaliza formato                                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  analyzer.py (CLAUDE API)                                   │ │
│  │  - Analiza documento con Claude 3.5                        │ │
│  │  - Extrae metadatos                                        │ │
│  │  - Clasifica tipo (circular/resolución)                    │ │
│  │  - Detecta cambios técnicos                                │ │
│  │  - Evalúa impacto en componentes                           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  classifier.py                                              │ │
│  │  - Asigna prioridad (1-5)                                  │ │
│  │  - Mapea a componentes afectados                           │ │
│  │  - Determina acción (certificar/actualizar/ignorar)        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  storage.py                                                 │ │
│  │  - Almacena en Redis (cache 7 días)                        │ │
│  │  - Envía a Odoo vía API                                    │ │
│  │  - Guarda PDF en MinIO/S3 (opcional)                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  notifier.py                                                │ │
│  │  - Notifica Slack/Email/Telegram                           │ │
│  │  - Crea issue en GitHub (opcional)                         │ │
│  │  - Log estructurado                                        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  [NUEVO] Endpoints:                                             │
│  POST /api/ai/sii/monitor          (trigger manual)             │
│  GET  /api/ai/sii/news              (listar noticias)           │
│  GET  /api/ai/sii/news/{id}         (detalle noticia)           │
│  POST /api/ai/sii/news/{id}/analyze (re-analizar)               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ Notificaciones
                            ▼
                  ┌──────────────────┐
                  │  Slack/Email     │
                  │  GitHub Issues   │
                  │  Odoo Messages   │
                  └──────────────────┘
```

---

<a name="diseño-detallado"></a>
## 4. 🔧 DISEÑO DETALLADO

### 4.1 Nuevos Componentes AI Service

#### 4.1.1 Scraper Module (`sii_monitor/scraper.py`)

**Responsabilidad:** Scraping de URLs SII

**Tecnologías:**
- `requests` + `BeautifulSoup4` (básico)
- `Scrapy` (avanzado, opcional)
- `selenium` (si JavaScript, opcional)

**Funciones:**
```python
class SIIScraper:
    def __init__(self, urls: List[str]):
        self.urls = urls
        self.session = requests.Session()
        
    async def scrape_all(self) -> List[Document]:
        """Scrapea todas las URLs configuradas"""
        
    async def scrape_url(self, url: str) -> Document:
        """Scrapea una URL específica"""
        
    def detect_changes(self, new_hash: str, old_hash: str) -> bool:
        """Detecta cambios comparando hashes"""
        
    def download_pdf(self, url: str) -> bytes:
        """Descarga PDF si existe"""
```

**URLs a Monitorear:**
```python
SII_URLS = {
    'normativa_fe': 'https://www.sii.cl/factura_electronica/normativa.htm',
    'circulares': 'https://www.sii.cl/normativa_legislacion/circulares/',
    'resoluciones': 'https://www.sii.cl/normativa_legislacion/resoluciones/',
    'faq': 'https://www.sii.cl/preguntas_frecuentes/factura_electronica/',
    'maullin': 'https://maullin.sii.cl/cvc/dte/certificacion_dte.html',
}
```

**Estrategia de Detección:**
```python
# Opción 1: Hash del contenido
import hashlib

def get_content_hash(html: str) -> str:
    return hashlib.sha256(html.encode()).hexdigest()

# Opción 2: RSS feed (si existe)
# Opción 3: Metadata (last-modified header)
```

#### 4.1.2 Extractor Module (`sii_monitor/extractor.py`)

**Responsabilidad:** Extracción de texto limpio

**Funciones:**
```python
class DocumentExtractor:
    def extract_text_from_pdf(self, pdf_bytes: bytes) -> str:
        """Extrae texto de PDF (pdfplumber)"""
        
    def extract_text_from_html(self, html: str) -> str:
        """Extrae texto de HTML (BeautifulSoup)"""
        
    def clean_text(self, text: str) -> str:
        """Limpia y normaliza texto"""
        
    def extract_metadata(self, document) -> Dict:
        """Extrae fecha, número, tipo"""
```

**Ejemplo:**
```python
# Input: PDF circular SII
# Output:
{
    'text': 'CIRCULAR N° 35...',
    'metadata': {
        'tipo': 'circular',
        'numero': '35',
        'fecha': '2025-01-15',
        'titulo': 'Ley N° 21.713...'
    }
}
```

#### 4.1.3 Analyzer Module (`sii_monitor/analyzer.py`)

**Responsabilidad:** Análisis con Claude API

**Funciones:**
```python
class SIIDocumentAnalyzer:
    def __init__(self, anthropic_client: AnthropicClient):
        self.client = anthropic_client
        
    async def analyze_document(self, document: Document) -> Analysis:
        """Analiza documento con Claude"""
        prompt = self._build_analysis_prompt(document)
        response = await self.client.analyze(prompt)
        return self._parse_response(response)
        
    def _build_analysis_prompt(self, document: Document) -> str:
        """Construye prompt optimizado para Claude"""
        return f"""
        Eres un experto en facturación electrónica chilena.
        
        DOCUMENTO SII:
        {document.text}
        
        NUESTRO SISTEMA:
        - DTEs: 33, 34, 52, 56, 61
        - Componentes: {COMPONENTS_MAP}
        
        ANALIZA Y RESPONDE JSON:
        {{
          "tipo": "circular|resolucion|xsd",
          "numero": "XX",
          "fecha": "YYYY-MM-DD",
          "vigencia": "YYYY-MM-DD",
          "resumen": "...",
          "cambios_tecnicos": ["..."],
          "impacto": {{
            "nivel": "alto|medio|bajo",
            "componentes": ["generador_33", ...],
            "requiere_certificacion": true|false,
            "breaking_change": true|false
          }},
          "acciones": ["..."],
          "prioridad": 1-5
        }}
        """
```

**Mapeo de Componentes:**
```python
COMPONENTS_MAP = {
    'generador_33': 'Generador DTE 33 (Factura)',
    'generador_34': 'Generador DTE 34 (Honorarios)',
    'generador_52': 'Generador DTE 52 (Guía)',
    'generador_56': 'Generador DTE 56 (Nota Débito)',
    'generador_61': 'Generador DTE 61 (Nota Crédito)',
    'signer': 'Firmador Digital (PKI)',
    'soap_client': 'Cliente SOAP SII',
    'xsd_validator': 'Validador XSD',
    'ted_generator': 'Generador TED (QR)',
    'rut_validator': 'Validador RUT',
    'ui_module': 'Interfaz Odoo',
}
```

#### 4.1.4 Classifier Module (`sii_monitor/classifier.py`)

**Responsabilidad:** Clasificación y priorización

**Funciones:**
```python
class ImpactClassifier:
    def classify_impact(self, analysis: Analysis) -> Impact:
        """Clasifica impacto en sistema"""
        
    def map_to_components(self, keywords: List[str]) -> List[str]:
        """Mapea keywords a componentes"""
        
    def calculate_priority(self, impact: Impact) -> int:
        """Calcula prioridad 1-5"""
        
    def determine_actions(self, impact: Impact) -> List[Action]:
        """Determina acciones requeridas"""
```

**Lógica de Prioridad:**
```python
def calculate_priority(impact: Impact) -> int:
    score = 0
    
    # Breaking change = crítico
    if impact.breaking_change:
        score += 5
        
    # Requiere certificación = alto
    if impact.requiere_certificacion:
        score += 3
        
    # Nivel de impacto
    score += {
        'alto': 3,
        'medio': 2,
        'bajo': 1
    }[impact.nivel]
    
    # Fecha vigencia cercana
    days_until = (impact.vigencia - today).days
    if days_until < 30:
        score += 2
    elif days_until < 90:
        score += 1
        
    # Normalizar a 1-5
    return min(5, max(1, score // 2))
```

#### 4.1.5 Storage Module (`sii_monitor/storage.py`)

**Responsabilidad:** Persistencia multi-capa

**Funciones:**
```python
class NewsStorage:
    def __init__(self, redis_client, odoo_client):
        self.redis = redis_client
        self.odoo = odoo_client
        
    async def save_news(self, news: News) -> int:
        """Guarda en Redis + Odoo"""
        # 1. Cache en Redis (7 días)
        await self.redis.setex(
            f'sii_news:{news.id}',
            7 * 86400,
            news.json()
        )
        
        # 2. Persistencia en Odoo
        odoo_id = await self.odoo.create_news(news)
        
        # 3. Archivo PDF (opcional)
        if news.pdf_url:
            await self.save_pdf_to_minio(news.pdf_url)
            
        return odoo_id
        
    async def get_news_by_date(self, since: datetime) -> List[News]:
        """Recupera noticias desde fecha"""
```

#### 4.1.6 Notifier Module (`sii_monitor/notifier.py`)

**Responsabilidad:** Notificaciones multi-canal

**Funciones:**
```python
class NewsNotifier:
    def __init__(self, config: NotifierConfig):
        self.slack = SlackClient(config.slack_webhook)
        self.email = EmailClient(config.smtp_config)
        self.telegram = TelegramClient(config.telegram_token)
        
    async def notify_new_news(self, news: News):
        """Notifica nueva noticia"""
        if news.priority >= 4:
            await self.notify_all(news)
        elif news.priority >= 3:
            await self.notify_slack(news)
        else:
            await self.notify_log_only(news)
            
    async def create_github_issue(self, news: News):
        """Crea issue en GitHub (opcional)"""
```

**Ejemplo Notificación Slack:**
```python
{
    "text": "🚨 Nueva Circular SII - Prioridad ALTA",
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Circular N° 35 del 15/01/2025"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Resumen:* Ley N° 21.713 - Cambios en validación DTEs\n*Vigencia:* 01/05/2025\n*Impacto:* Alto"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Componentes afectados:*\n- Generador DTE 33\n- XSD Validator\n- Signer"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Acciones requeridas:*\n1. Actualizar XSD schemas\n2. Modificar validador\n3. Certificar en Maullin"
            }
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Ver en Odoo"
                    },
                    "url": "http://odoo:8069/web#id=123&model=dte.sii.news"
                }
            ]
        }
    ]
}
```

### 4.2 Nuevos Endpoints AI Service

```python
@app.post("/api/ai/sii/monitor")
async def trigger_sii_monitoring(
    force: bool = False,
    dependencies=[Depends(verify_api_key)]
):
    """
    Trigger manual de monitoreo SII.
    
    Args:
        force: Si True, ignora cache y fuerza scraping
        
    Returns:
        {
            "status": "success",
            "news_found": 3,
            "news_ids": [1, 2, 3],
            "execution_time": "00:02:15"
        }
    """

@app.get("/api/ai/sii/news")
async def list_sii_news(
    since: Optional[datetime] = None,
    priority: Optional[int] = None,
    tipo: Optional[str] = None,
    limit: int = 50,
    dependencies=[Depends(verify_api_key)]
):
    """
    Lista noticias SII almacenadas.
    
    Query Params:
        since: Desde fecha (ISO 8601)
        priority: Filtrar por prioridad (1-5)
        tipo: circular|resolucion|xsd
        limit: Máx resultados
        
    Returns:
        {
            "total": 10,
            "news": [...]
        }
    """

@app.get("/api/ai/sii/news/{news_id}")
async def get_sii_news_detail(
    news_id: int,
    dependencies=[Depends(verify_api_key)]
):
    """
    Detalle de noticia específica.
    
    Returns:
        {
            "id": 123,
            "tipo": "circular",
            "numero": "35",
            "fecha": "2025-01-15",
            "titulo": "...",
            "resumen": "...",
            "analisis_completo": {...},
            "pdf_url": "...",
            "acciones": [...]
        }
    """

@app.post("/api/ai/sii/news/{news_id}/analyze")
async def reanalyze_news(
    news_id: int,
    dependencies=[Depends(verify_api_key)]
):
    """
    Re-analiza noticia con Claude (por si cambió contexto).
    
    Returns:
        {
            "status": "success",
            "analysis": {...}
        }
    """
```

### 4.3 Nuevos Modelos Odoo

#### 4.3.1 Modelo: `dte.sii.news`

**Ubicación:** `l10n_cl_dte/models/dte_sii_news.py`

```python
class DTESIINews(models.Model):
    _name = 'dte.sii.news'
    _description = 'Noticias y actualizaciones del SII'
    _order = 'fecha desc, priority desc'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    
    # Metadatos documento
    tipo = fields.Selection([
        ('circular', 'Circular'),
        ('resolucion', 'Resolución Exenta'),
        ('xsd', 'Actualización XSD'),
        ('faq', 'Actualización FAQ'),
        ('otro', 'Otro')
    ], string='Tipo', required=True, tracking=True)
    
    numero = fields.Char('Número', tracking=True)
    fecha = fields.Date('Fecha Publicación', required=True, tracking=True)
    vigencia = fields.Date('Fecha Vigencia', tracking=True)
    titulo = fields.Char('Título', required=True, size=512, tracking=True)
    url_origen = fields.Char('URL Origen', size=1024)
    
    # Contenido
    resumen = fields.Text('Resumen')
    contenido_completo = fields.Html('Contenido Completo')
    cambios_tecnicos = fields.Text('Cambios Técnicos')
    
    # Análisis IA
    analisis_ia = fields.Text('Análisis IA (JSON)', help='Análisis de Claude en JSON')
    componentes_afectados = fields.Char('Componentes Afectados', size=512)
    
    # Impacto
    nivel_impacto = fields.Selection([
        ('alto', 'Alto'),
        ('medio', 'Medio'),
        ('bajo', 'Bajo')
    ], string='Nivel Impacto', tracking=True)
    
    priority = fields.Integer('Prioridad', default=3, help='1-5 (5=crítico)')
    
    requiere_certificacion = fields.Boolean(
        'Requiere Re-certificación',
        tracking=True
    )
    
    breaking_change = fields.Boolean(
        'Breaking Change',
        tracking=True,
        help='Cambio que rompe compatibilidad'
    )
    
    # Acciones
    acciones_requeridas = fields.Text('Acciones Requeridas')
    
    # Estado
    state = fields.Selection([
        ('new', 'Nueva'),
        ('reviewed', 'Revisada'),
        ('in_progress', 'En Implementación'),
        ('done', 'Completada'),
        ('dismissed', 'Descartada')
    ], string='Estado', default='new', required=True, tracking=True)
    
    # Archivos adjuntos
    pdf_attachment_id = fields.Many2one(
        'ir.attachment',
        string='PDF Adjunto',
        ondelete='restrict'
    )
    
    # Auditoría
    reviewed_by = fields.Many2one('res.users', 'Revisado Por')
    reviewed_date = fields.Datetime('Fecha Revisión')
    notes = fields.Text('Notas Internas')
    
    # Relaciones
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        default=lambda self: self.env.company
    )
    
    # Métodos
    def action_mark_reviewed(self):
        """Marca como revisada"""
        self.write({
            'state': 'reviewed',
            'reviewed_by': self.env.user.id,
            'reviewed_date': fields.Datetime.now()
        })
        
    def action_start_implementation(self):
        """Inicia implementación"""
        self.write({'state': 'in_progress'})
        # Crear tarea/proyecto (opcional)
        
    def action_mark_done(self):
        """Marca como completada"""
        self.write({'state': 'done'})
        
    def action_dismiss(self):
        """Descarta noticia (no aplicable)"""
        self.write({'state': 'dismissed'})
        
    def action_reanalyze(self):
        """Trigger re-análisis con IA"""
        # Llamar a AI Service
        
    @api.model
    def create_from_ai_service(self, data: dict) -> int:
        """Crea registro desde AI Service"""
        return self.create(data).id
```

#### 4.3.2 Modelo: `dte.sii.monitoring`

**Ubicación:** `l10n_cl_dte/models/dte_sii_monitoring.py`

```python
class DTESIIMonitoring(models.Model):
    _name = 'dte.sii.monitoring'
    _description = 'Configuración de monitoreo SII'
    
    name = fields.Char('Nombre', required=True)
    active = fields.Boolean('Activo', default=True)
    
    # Configuración URLs
    url = fields.Char('URL a Monitorear', required=True, size=1024)
    tipo_contenido = fields.Selection([
        ('html', 'HTML'),
        ('rss', 'RSS Feed'),
        ('api', 'API JSON')
    ], string='Tipo Contenido', default='html')
    
    # Scheduling
    frequency = fields.Selection([
        ('hourly', 'Cada Hora'),
        ('6h', 'Cada 6 Horas'),
        ('daily', 'Diario'),
        ('weekly', 'Semanal')
    ], string='Frecuencia', default='6h', required=True)
    
    last_check = fields.Datetime('Última Verificación', readonly=True)
    last_hash = fields.Char('Último Hash', readonly=True, size=64)
    
    # Notificaciones
    notify_slack = fields.Boolean('Notificar Slack', default=True)
    notify_email = fields.Boolean('Notificar Email', default=False)
    email_recipients = fields.Char('Destinatarios Email')
    
    # Auditoría
    news_count = fields.Integer(
        'Noticias Detectadas',
        compute='_compute_news_count'
    )
    
    @api.depends('url')
    def _compute_news_count(self):
        for rec in self:
            rec.news_count = self.env['dte.sii.news'].search_count([
                ('url_origen', '=like', f'%{rec.url}%')
            ])
            
    def action_check_now(self):
        """Trigger verificación manual"""
        # Llamar a AI Service
```

#### 4.3.3 Wizard: `wizard/sii_news_review.py`

```python
class SIINewsReviewWizard(models.TransientModel):
    _name = 'sii.news.review.wizard'
    _description = 'Wizard para revisar noticias SII'
    
    news_id = fields.Many2one('dte.sii.news', 'Noticia', required=True)
    
    decision = fields.Selection([
        ('implement', 'Implementar'),
        ('monitor', 'Monitorear'),
        ('dismiss', 'Descartar')
    ], string='Decisión', required=True)
    
    notes = fields.Text('Notas')
    
    assigned_to = fields.Many2one('res.users', 'Asignar A')
    due_date = fields.Date('Fecha Límite')
    
    def action_confirm(self):
        """Confirma revisión"""
        self.news_id.write({
            'state': 'reviewed',
            'reviewed_by': self.env.user.id,
            'reviewed_date': fields.Datetime.now(),
            'notes': self.notes
        })
        
        if self.decision == 'implement':
            self.news_id.action_start_implementation()
            # Opcional: crear proyecto/tarea
            
        elif self.decision == 'dismiss':
            self.news_id.action_dismiss()
```

### 4.4 Vista Dashboard

**Ubicación:** `views/dte_sii_news_dashboard.xml`

```xml
<odoo>
    <!-- Dashboard de noticias SII -->
    <record id="view_dte_sii_news_dashboard" model="ir.ui.view">
        <field name="name">dte.sii.news.dashboard</field>
        <field name="model">dte.sii.news</field>
        <field name="arch" type="xml">
            <dashboard>
                <view type="kanban"/>
                
                <!-- KPIs -->
                <group col="4">
                    <group>
                        <field name="news_count_new" widget="statinfo" 
                               string="Nuevas"/>
                    </group>
                    <group>
                        <field name="news_count_critical" widget="statinfo" 
                               string="Críticas"/>
                    </group>
                    <group>
                        <field name="news_count_in_progress" widget="statinfo" 
                               string="En Progreso"/>
                    </group>
                    <group>
                        <field name="news_count_done" widget="statinfo" 
                               string="Completadas"/>
                    </group>
                </group>
                
                <!-- Gráficos -->
                <group>
                    <field name="news_by_type" widget="pie_chart"/>
                    <field name="news_by_priority" widget="bar_chart"/>
                </group>
                
                <!-- Últimas noticias críticas -->
                <group>
                    <field name="latest_critical_news" widget="one2many_list"/>
                </group>
            </dashboard>
        </field>
    </record>
</odoo>
```

---

<a name="integración"></a>
## 5. 🔗 INTEGRACIÓN CON COMPONENTES EXISTENTES

### 5.1 Integración con DTE Service

**Escenario:** Noticia afecta generador DTE 33

**Flujo:**
```
1. AI Service detecta cambio en XSD para factura
2. Analiza con Claude → Impacto: generador_33
3. Notifica a equipo
4. Equipo actualiza dte-service/generators/dte_generator_33.py
5. Testing en Maullin
6. Deploy
7. Marca noticia como 'done' en Odoo
```

**No hay integración automática** entre AI Service y DTE Service (diseño intencional para seguridad).

### 5.2 Integración con Odoo Module

**Comunicación:**
```python
# Odoo → AI Service (trigger monitoreo)
import requests

response = requests.post(
    'http://ai-service:8002/api/ai/sii/monitor',
    headers={'Authorization': f'Bearer {ai_api_key}'},
    timeout=300  # 5 min (puede demorar)
)

# AI Service → Odoo (crear noticia)
import requests

response = requests.post(
    'http://odoo:8069/api/dte/sii_news/create',
    json=news_data,
    headers={'Authorization': f'Bearer {odoo_api_key}'}
)
```

**Cron Job en Odoo:**
```xml
<record id="ir_cron_sii_monitoring" model="ir.cron">
    <field name="name">SII News Monitoring</field>
    <field name="model_id" ref="model_dte_sii_monitoring"/>
    <field name="state">code</field>
    <field name="code">model.cron_check_sii_news()</field>
    <field name="interval_number">6</field>
    <field name="interval_type">hours</field>
    <field name="numbercall">-1</field>
    <field name="active" eval="True"/>
</record>
```

### 5.3 Integración con Redis

**Cache Strategy:**
```python
# Key pattern
sii_news:{news_id}              # Noticia completa (7 días)
sii_url_hash:{url}              # Hash de URL (30 días)
sii_last_check:{url}            # Timestamp última verificación (1 día)

# Ejemplo
redis.setex('sii_news:123', 7*86400, json.dumps(news))
redis.setex('sii_url_hash:normativa_fe', 30*86400, content_hash)
```

---

<a name="flujos"></a>
## 6. 🔄 FLUJOS DE DATOS

### 6.1 Flujo Completo de Monitoreo

```
┌─────────────────────────────────────────────────────────────┐
│ 1. TRIGGER (Cron Odoo cada 6h)                             │
│    → Llama a AI Service /api/ai/sii/monitor                │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. SCRAPING (AI Service)                                    │
│    → Scrapea 7 URLs SII                                     │
│    → Calcula hash de cada página                            │
│    → Compara con Redis (último hash)                        │
│    → Detecta cambios: 2/7 URLs cambiaron                    │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. EXTRACCIÓN                                               │
│    → Extrae texto de HTML/PDF                               │
│    → Limpia y normaliza                                     │
│    → Extrae metadatos (fecha, número, tipo)                 │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. ANÁLISIS IA (Claude)                                     │
│    → Envía documento a Claude API                           │
│    → Recibe análisis estructurado (JSON)                    │
│    → Extrae: tipo, resumen, cambios, impacto                │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. CLASIFICACIÓN                                            │
│    → Mapea a componentes afectados                          │
│    → Calcula prioridad (1-5)                                │
│    → Determina acciones requeridas                          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. ALMACENAMIENTO                                           │
│    → Guarda en Redis (cache 7 días)                         │
│    → Crea registro en Odoo (dte.sii.news)                   │
│    → Guarda PDF en attachments                              │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. NOTIFICACIÓN                                             │
│    → Slack (si prioridad ≥ 3)                               │
│    → Email (si prioridad = 5)                               │
│    → Odoo message (siempre)                                 │
│    → GitHub issue (opcional, si prioridad ≥ 4)              │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. REVISIÓN HUMANA (Odoo)                                   │
│    → Usuario abre dashboard                                 │
│    → Ve 2 noticias nuevas                                   │
│    → Revisa detalle con análisis IA                         │
│    → Decide: implementar / monitorear / descartar           │
│    → Asigna a desarrollador (si implementar)                │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Flujo de Re-análisis

```
Usuario en Odoo → Botón "Re-analizar" → API AI Service
                                              │
                                              ▼
                                    Recupera documento de BD
                                              │
                                              ▼
                                    Llama Claude API (nuevo análisis)
                                              │
                                              ▼
                                    Actualiza registro en Odoo
                                              │
                                              ▼
                                    Notifica cambios (si hay)
```

---

<a name="consideraciones"></a>
## 7. 🔧 CONSIDERACIONES TÉCNICAS

### 7.1 Performance

**Scraping:**
- ⏱️ 7 URLs × 2-5 seg = **14-35 seg total**
- 💡 Paralelizar con `asyncio` / `aiohttp`

**Análisis Claude:**
- ⏱️ 1 documento × 5-15 seg = **5-15 seg**
- 💡 Solo analizar documentos nuevos (hash cambió)

**Total por ejecución:**
- Sin cambios: ~20 seg (solo scraping)
- Con 2 cambios: ~50 seg (scraping + 2 análisis)

**Frecuencia:** Cada 6h = 4 ejecuciones/día
**Costo tiempo:** ~5 min/día

### 7.2 Costos API

**Claude API (Anthropic):**
- Modelo: `claude-3-5-sonnet-20241022`
- Input: $3 / 1M tokens
- Output: $15 / 1M tokens

**Estimación:**
```
Circular promedio: 5,000 tokens input
Análisis: 1,500 tokens output

Costo por análisis:
- Input: 5,000 × $3/1M = $0.015
- Output: 1,500 × $15/1M = $0.0225
- Total: $0.0375 (~$0.04)

Escenario pesado:
- 10 circulares/mes nuevas
- Costo mensual: $0.40
- Costo anual: ~$5

COSTO DESPRECIABLE ✅
```

### 7.3 Seguridad

**Web Scraping:**
- ✅ Respetar `robots.txt` del SII
- ✅ Rate limiting (max 1 req/seg)
- ✅ User-Agent identificable
- ✅ Timeout 30 seg por request

**Almacenamiento:**
- ✅ Redis password-protected
- ✅ Odoo access control (grupos)
- ✅ PDFs encriptados en BD
- ✅ API keys en environment vars

**API Calls:**
- ✅ Bearer token authentication
- ✅ HTTPS only (producción)
- ✅ Internal network (no exponer internet)

### 7.4 Escalabilidad

**Horizontal:**
- AI Service puede escalar (stateless)
- Scraping distribuido (queue)

**Vertical:**
- Monitoreo ligero (no intensivo)
- Redis suficiente para cache

**Limitaciones:**
- Claude API: 50 req/min (más que suficiente)
- SII: Sin rate limit documentado (usar 1 req/seg por cortesía)

### 7.5 Mantenimiento

**Riesgos:**
1. **SII cambia HTML:** Scraper se rompe
   - Mitigation: Tests automáticos, alertas

2. **Claude API falla:** No se analiza
   - Mitigation: Guardar documento crudo, re-analizar después

3. **Falsos positivos:** Cambios menores detectados
   - Mitigation: Threshold de cambio mínimo (ej: >10% diferencia)

**Monitoring:**
- Logs estructurados (structlog)
- Alertas si scraping falla 3 veces seguidas
- Dashboard con métricas (opcional)

---

<a name="roadmap"></a>
## 8. 🗺️ ROADMAP DE IMPLEMENTACIÓN

### Fase 1: Base (2-3 días)

**Objetivos:**
- ✅ Scraper básico funcional
- ✅ Extractor de texto
- ✅ Integración Claude API
- ✅ Storage Redis + logs

**Tareas:**
```
1. ai-service/sii_monitor/scraper.py
   - Scraping de 1 URL (normativa FE)
   - Hash comparison
   - Tests básicos

2. ai-service/sii_monitor/extractor.py
   - Extracción HTML → texto
   - Limpieza básica
   - Tests

3. ai-service/sii_monitor/analyzer.py
   - Integración Claude (prompt v1)
   - Parse JSON response
   - Tests con documento real

4. Nuevo endpoint: POST /api/ai/sii/monitor
   - Orquestación scraper → extractor → analyzer
   - Return JSON resultado

5. Tests integración
   - Flujo completo con mock SII
```

### Fase 2: Odoo Integration (2-3 días)

**Objetivos:**
- ✅ Modelo `dte.sii.news` funcional
- ✅ Vistas básicas (tree, form)
- ✅ Integración AI Service → Odoo

**Tareas:**
```
1. l10n_cl_dte/models/dte_sii_news.py
   - Modelo completo
   - Métodos básicos
   - Access rights

2. l10n_cl_dte/views/dte_sii_news_views.xml
   - Vista tree
   - Vista form
   - Filtros y búsquedas

3. AI Service → Odoo API client
   - Cliente HTTP para Odoo
   - Crear noticias desde AI Service
   - Tests

4. Tests integración
   - Crear noticia desde AI Service
   - Verificar en BD Odoo
```

### Fase 3: Notificaciones (1-2 días)

**Objetivos:**
- ✅ Notificaciones Slack
- ✅ Notificaciones Odoo (mail.message)

**Tareas:**
```
1. ai-service/sii_monitor/notifier.py
   - Cliente Slack
   - Template notificación
   - Lógica prioridad

2. Odoo mail integration
   - mail.message al crear noticia
   - Seguimiento (followers)

3. Tests
   - Mock Slack webhook
   - Verificar notificaciones enviadas
```

### Fase 4: Scheduling (1 día)

**Objetivos:**
- ✅ Cron job en Odoo
- ✅ Modelo `dte.sii.monitoring`

**Tareas:**
```
1. l10n_cl_dte/models/dte_sii_monitoring.py
   - Modelo configuración
   - Métodos trigger

2. l10n_cl_dte/data/ir_cron.xml
   - Cron cada 6h
   - Llamada a AI Service

3. Tests
   - Trigger manual
   - Verificar ejecución cron
```

### Fase 5: Dashboard & UX (2 días)

**Objetivos:**
- ✅ Dashboard con KPIs
- ✅ Wizard revisión
- ✅ Workflow estados

**Tareas:**
```
1. l10n_cl_dte/wizard/sii_news_review.py
   - Wizard revisión
   - Lógica asignación

2. Dashboard
   - KPIs (nuevas, críticas, etc)
   - Gráficos (opcional)

3. UX improvements
   - Botones acción rápida
   - Smart buttons
   - Filtros inteligentes
```

### Fase 6: Producción (1 día)

**Objetivos:**
- ✅ Configuración producción
- ✅ Monitoring
- ✅ Documentación

**Tareas:**
```
1. Configuración
   - Environment vars
   - Secrets management
   - Rate limiting

2. Monitoring
   - Logs centralizados
   - Alertas errores

3. Documentación
   - README actualizado
   - User manual
   - Runbook operaciones
```

---

## 9. 📊 RESUMEN EJECUTIVO

### Por Qué AI Service

✅ **Claude API ya integrado** → No duplicar infraestructura  
✅ **Análisis semántico nativo** → Capacidad de NLP/ML  
✅ **Bajo acoplamiento** → No impacta DTEs críticos  
✅ **Scope alineado** → Inteligencia/análisis  
✅ **Escalable** → Fácil agregar features IA  

### Componentes Nuevos

**AI Service:**
- `sii_monitor/scraper.py` (scraping URLs)
- `sii_monitor/extractor.py` (extracción texto)
- `sii_monitor/analyzer.py` (Claude API)
- `sii_monitor/classifier.py` (clasificación)
- `sii_monitor/storage.py` (Redis + Odoo)
- `sii_monitor/notifier.py` (Slack, Email)

**Odoo Module:**
- `models/dte_sii_news.py` (almacenamiento)
- `models/dte_sii_monitoring.py` (configuración)
- `wizard/sii_news_review.py` (workflow)
- `views/dte_sii_news_views.xml` (UI)
- `data/ir_cron.xml` (scheduling)

### Beneficios

✅ **Automatización** → Fin de revisión manual  
✅ **Detección temprana** → Cambios detectados en horas  
✅ **Análisis inteligente** → Claude clasifica impacto  
✅ **Trazabilidad** → Todo almacenado y auditable  
✅ **Notificaciones** → Equipo informado instantáneamente  
✅ **Compliance** → Siempre actualizado con SII  

### Costos

💰 **Claude API:** ~$5/año (despreciable)  
⏱️ **Desarrollo:** 10-12 días (2 semanas)  
🔧 **Mantenimiento:** Bajo (scraper puede requerir ajustes)  

### Riesgos

⚠️ **Scraper frágil** → SII cambia HTML  
Mitigation: Tests + alertas + fallback

⚠️ **Falsos positivos** → Cambios menores  
Mitigation: Threshold + revisión humana

⚠️ **Claude API costo** → Si escala mucho  
Mitigation: Monitoreo uso + cache

### Decisión

🎯 **RECOMENDADO:** Implementar en AI Service  
📅 **Timeline:** 2 semanas  
🚀 **Prioridad:** Media-Alta (después de certificación DTE)

---

**Documento creado:** 2025-10-22  
**Autor:** Análisis arquitectónico profundo  
**Estado:** PROPUESTA (No implementación)  
**Próximo paso:** Validar con equipo y aprobar roadmap
