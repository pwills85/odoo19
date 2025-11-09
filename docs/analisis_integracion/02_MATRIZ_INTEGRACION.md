# 📊 MATRIZ DE INTEGRACIÓN - FUNCIONES BASE vs EXTENSIONES

**Fecha:** 2025-10-22  
**Versión:** 1.0  
**Documento:** 2 de 6

---

## 📋 OBJETIVO

Mapear con precisión quirúrgica:
- Funciones **BASE** de Odoo 19 CE (NO tocar)
- Funciones **EXTENDIDAS** por nuestro módulo (herencia controlada)
- Funciones **NUEVAS** (microservicios + IA)
- Puntos de **INTEGRACIÓN** y dependencias cruzadas

---

## 🎯 MATRIZ FUNCIONAL COMPLETA

### **CATEGORÍA 1: GESTIÓN DE PARTNERS (Clientes/Proveedores)**

| Función | Odoo Base | l10n_cl | l10n_cl_dte | Microservicios | IA | Integración |
|---------|-----------|---------|-------------|----------------|----|-----------| 
| **Gestión RUT** | ✅ res.partner.vat | ✅ Validación módulo 11 | - | - | - | Campo `vat` |
| **Tipo Identificación** | ✅ l10n_latam.identification.type | ✅ RUT chileno | - | - | - | `l10n_latam_identification_type_id` |
| **Tipo Contribuyente** | - | ✅ l10n_cl_sii_taxpayer_type | - | - | - | Campo directo |
| **Giro/Actividad** | - | ✅ l10n_cl_activity_description | - | - | - | Campo directo |
| **Email DTE** | - | - | ✅ dte_email | - | - | Campo nuevo |
| **Recepción DTE** | - | - | ✅ dte_reception_enabled | ✅ DTE Receiver | - | Webhook |
| **Validación RUT Online** | - | - | - | ✅ API SII | - | HTTP API |

**Puntos de Integración:**
```python
# Odoo → Módulo l10n_cl_dte
partner.vat  # Reutilizar
partner.l10n_cl_sii_taxpayer_type  # Reutilizar
partner.dte_email  # Nuevo campo

# Módulo → Microservicio
POST /api/dte/validate-rut
{
    "rut": partner.vat,
    "tipo_contribuyente": partner.l10n_cl_sii_taxpayer_type
}
```

---

### **CATEGORÍA 2: TIPOS DE DOCUMENTOS TRIBUTARIOS**

| Función | Odoo Base | l10n_cl | l10n_cl_dte | Microservicios | IA | Integración |
|---------|-----------|---------|-------------|----------------|----|-----------| 
| **Modelo Tipos DTE** | ✅ l10n_latam.document.type | ✅ Códigos CL | - | - | - | `l10n_latam_document_type_id` |
| **Códigos SII** | ✅ code (33,52,56,61) | ✅ Datos CL | - | - | - | Campo `code` |
| **Secuencias** | ✅ _get_starting_sequence() | ✅ Formato CL | - | - | - | Método heredado |
| **Gestión CAF** | - | - | ✅ dte.caf | - | - | Modelo nuevo |
| **Consumo Folios** | - | - | ✅ folio_actual | - | - | Campo nuevo |
| **Alerta Folios Bajos** | - | - | ✅ Cron | - | - | ir.cron |

**Puntos de Integración:**
```python
# Odoo → Módulo l10n_cl_dte
move.l10n_latam_document_type_id  # Reutilizar (base)
move.dte_code = move.l10n_latam_document_type_id.code  # Related

# Módulo → CAF
caf = env['dte.caf'].search([
    ('dte_type_id', '=', move.l10n_latam_document_type_id.id),
    ('folio_actual', '<=', 'folio_hasta')
], limit=1)
folio = caf.get_next_folio()
```

---

### **CATEGORÍA 3: FACTURAS Y DOCUMENTOS (account.move)**

| Función | Odoo Base | l10n_cl | l10n_cl_dte | Microservicios | IA | Integración |
|---------|-----------|---------|-------------|----------------|----|-----------| 
| **Modelo Factura** | ✅ account.move | ✅ Extensión CL | ✅ Extensión DTE | - | - | `_inherit` |
| **Tipo Documento** | ✅ l10n_latam_document_type_id | - | - | - | - | Many2one |
| **Validaciones SII** | - | ✅ _check_document_types_post() | ✅ Extender | - | - | `super()` |
| **Estado DTE** | - | - | ✅ dte_status | - | - | Selection |
| **Folio DTE** | - | - | ✅ dte_folio | - | - | Integer |
| **XML DTE** | - | - | ✅ dte_xml | ✅ Generador | - | Text |
| **Track ID SII** | - | - | ✅ dte_track_id | ✅ SOAP Client | - | Char |
| **Generación XML** | - | - | - | ✅ DTE Generator | - | HTTP POST |
| **Firma Digital** | - | - | - | ✅ DTE Signer | - | XMLDsig |
| **Envío SII** | - | - | - | ✅ SOAP Client | - | SOAP |
| **Validación XSD** | - | - | - | ✅ XSD Validator | - | lxml |
| **TED (QR)** | - | - | - | ✅ TED Generator | - | Base64 |
| **Validación IA** | - | - | - | - | ✅ Claude API | HTTP POST |

**Puntos de Integración:**
```python
# 1. Odoo → Módulo (Herencia)
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    def action_post(self):
        result = super().action_post()  # ← Llamar base
        # Agregar lógica DTE
        return result

# 2. Módulo → Microservicio DTE
def action_send_dte_async(self):
    response = requests.post(
        'http://dte-service:8001/api/dte/generate-and-send',
        json={
            'dte_type': self.dte_code,
            'folio': self.dte_folio,
            'emisor': {...},
            'receptor': {...},
            'totales': {...}
        }
    )

# 3. Microservicio → IA (Validación)
async def validate_dte_with_ai(dte_data):
    response = await httpx.post(
        'http://ai-service:8002/api/ai/validate-dte',
        json=dte_data
    )
```

---

### **CATEGORÍA 4: CERTIFICADOS DIGITALES**

| Función | Odoo Base | l10n_cl | l10n_cl_dte | Microservicios | IA | Integración |
|---------|-----------|---------|-------------|----------------|----|-----------| 
| **Modelo Certificado** | - | - | ✅ dte.certificate | - | - | Modelo nuevo |
| **Almacenamiento .pfx** | - | - | ✅ Binary | - | - | Encriptado |
| **Validación Vigencia** | - | - | ✅ Compute | - | - | @api.depends |
| **Firma XML** | - | - | - | ✅ XMLDsig | - | Signxml |
| **Verificación Firma** | - | - | - | ✅ Verify | - | xmlsec |

**Puntos de Integración:**
```python
# Módulo → Microservicio
certificate = env['dte.certificate'].get_active()
response = requests.post(
    'http://dte-service:8001/api/dte/sign',
    files={'certificate': certificate.certificate_file},
    data={'password': certificate.password, 'xml': dte_xml}
)
```

---

### **CATEGORÍA 5: MENSAJERÍA ASÍNCRONA (RabbitMQ)**

| Función | Odoo Base | l10n_cl | l10n_cl_dte | Microservicios | IA | Integración |
|---------|-----------|---------|-------------|----------------|----|-----------| 
| **Queue Management** | - | - | - | ✅ RabbitMQ | - | AMQP |
| **Publisher** | - | - | ✅ action_send_dte_async() | - | - | HTTP → Queue |
| **Consumer Generate** | - | - | - | ✅ generate_consumer | - | aio-pika |
| **Consumer Validate** | - | - | - | ✅ validate_consumer | - | aio-pika |
| **Consumer Send** | - | - | - | ✅ send_consumer | - | aio-pika |
| **Webhook Callback** | - | - | ✅ /dte/webhook | ✅ HTTP POST | - | FastAPI → Odoo |
| **Dead Letter Queue** | - | - | - | ✅ DLQ | - | RabbitMQ |
| **Retry Logic** | - | - | - | ✅ Exponential backoff | - | Python |

**Flujo de Integración:**
```
Odoo (l10n_cl_dte)
    │
    ├─→ HTTP POST → DTE Service
    │                   │
    │                   ├─→ RabbitMQ Queue: dte.generate
    │                   │       │
    │                   │       ├─→ Consumer: generate_dte()
    │                   │       │       │
    │                   │       │       ├─→ Generate XML
    │                   │       │       └─→ Queue: dte.validate
    │                   │       │
    │                   │       ├─→ Consumer: validate_dte()
    │                   │       │       │
    │                   │       │       ├─→ XSD Validation
    │                   │       │       └─→ Queue: dte.send
    │                   │       │
    │                   │       └─→ Consumer: send_dte()
    │                   │               │
    │                   │               ├─→ SOAP SII
    │                   │               └─→ Webhook → Odoo
    │                   │
    │                   └─→ Response: track_id
    │
    └─→ Update: dte_status, dte_track_id
```

---

### **CATEGORÍA 6: INTELIGENCIA ARTIFICIAL**

| Función | Odoo Base | l10n_cl | l10n_cl_dte | Microservicios | IA | Integración |
|---------|-----------|---------|-------------|----------------|----|-----------| 
| **Validación Semántica** | - | - | - | - | ✅ Claude API | HTTP POST |
| **Reconciliación** | - | - | - | - | ✅ Embeddings | Ollama |
| **Monitoreo SII** | - | - | - | - | ✅ Scraper + Claude | Cron |
| **Clasificación Impacto** | - | - | - | - | ✅ Claude | Redis |
| **Chat Conversacional** | - | - | - | - | ✅ Claude | WebSocket |
| **Notificaciones Slack** | - | - | - | - | ✅ Webhook | HTTP POST |

**Puntos de Integración:**
```python
# DTE Service → AI Service (Validación)
async def validate_dte_with_ai(dte_data):
    response = await httpx.post(
        'http://ai-service:8002/api/ai/validate-dte',
        json={
            'dte_type': dte_data['tipo'],
            'emisor': dte_data['emisor'],
            'receptor': dte_data['receptor'],
            'totales': dte_data['totales']
        }
    )
    return response.json()

# Odoo → AI Service (Monitoreo SII)
def action_check_sii_news(self):
    response = requests.post(
        'http://ai-service:8002/api/ai/sii/monitor',
        json={'force_refresh': True}
    )
    news = response.json()['news']
    # Crear registros en dte.sii.news
```

---

## 🔄 DIAGRAMA DE FLUJO COMPLETO

```
┌─────────────────────────────────────────────────────────────┐
│                      ODOO 19 CE                             │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ res.partner  │  │ account.move │  │ account.tax  │     │
│  │              │  │              │  │              │     │
│  │ - vat        │  │ - l10n_latam │  │ - amount     │     │
│  │ - country_id │  │   _document  │  │ - type       │     │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘     │
│         │                 │                                │
└─────────┼─────────────────┼────────────────────────────────┘
          │                 │
┌─────────▼─────────────────▼────────────────────────────────┐
│                  MÓDULO l10n_cl_dte                        │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ res.partner  │  │ account.move │  │ dte.caf      │     │
│  │  (extend)    │  │  (extend)    │  │  (new)       │     │
│  │              │  │              │  │              │     │
│  │ + dte_email  │  │ + dte_status │  │ - folio_desde│     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                 │              │
│         └─────────┬───────┴─────────────────┘              │
│                   │                                        │
│         ┌─────────▼─────────┐                              │
│         │ action_send_dte() │                              │
│         └─────────┬─────────┘                              │
└───────────────────┼────────────────────────────────────────┘
                    │
                    │ HTTP POST
                    │
┌───────────────────▼────────────────────────────────────────┐
│              MICROSERVICIO DTE                             │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ DTE Generator│  │ DTE Signer   │  │ SOAP Client  │     │
│  │              │  │              │  │              │     │
│  │ - XML        │  │ - XMLDsig    │  │ - SII        │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                 │              │
│         └─────────┬───────┴─────────────────┘              │
│                   │                                        │
│         ┌─────────▼─────────┐                              │
│         │   RabbitMQ Client │                              │
│         └─────────┬─────────┘                              │
└───────────────────┼────────────────────────────────────────┘
                    │
                    │ AMQP
                    │
┌───────────────────▼────────────────────────────────────────┐
│                   RABBITMQ                                 │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ dte.generate │→ │ dte.validate │→ │ dte.send     │     │
│  └──────────────┘  └──────────────┘  └──────┬───────┘     │
│                                              │              │
│                                    ┌─────────▼─────────┐   │
│                                    │ dte.dlq (errors)  │   │
│                                    └───────────────────┘   │
└────────────────────────────────────────────────────────────┘
                    │
                    │ Consumer
                    │
┌───────────────────▼────────────────────────────────────────┐
│              MICROSERVICIO AI                              │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Claude API   │  │ Ollama       │  │ SII Monitor  │     │
│  │              │  │              │  │              │     │
│  │ - Validate   │  │ - Embeddings │  │ - Scraper    │     │
│  │ - Chat       │  │ - Reconcile  │  │ - Classify   │     │
│  └──────────────┘  └──────────────┘  └──────┬───────┘     │
│                                              │              │
│                                    ┌─────────▼─────────┐   │
│                                    │ Redis (cache)     │   │
│                                    └───────────────────┘   │
└────────────────────────────────────────────────────────────┘
```

---

## 📋 TABLA DE DEPENDENCIAS CRUZADAS

| Componente | Depende De | Expone A | Protocolo |
|------------|------------|----------|-----------|
| **Odoo (l10n_cl_dte)** | l10n_cl, l10n_latam_base | DTE Service, AI Service | HTTP REST |
| **DTE Service** | RabbitMQ, PostgreSQL | Odoo (webhook) | HTTP + AMQP |
| **AI Service** | Redis, Anthropic API | Odoo, DTE Service | HTTP REST |
| **RabbitMQ** | - | DTE Service | AMQP |
| **PostgreSQL** | - | Odoo, DTE Service | TCP/5432 |
| **Redis** | - | AI Service | TCP/6379 |

---

## ✅ CONCLUSIONES MATRIZ

### **Principios de No Duplicación:**

1. ✅ **RUT:** Usar `res.partner.vat` (Odoo base)
2. ✅ **Tipo Contribuyente:** Usar `l10n_cl_sii_taxpayer_type` (l10n_cl)
3. ✅ **Tipos DTE:** Usar `l10n_latam.document.type` (l10n_latam_invoice_document)
4. ✅ **Validaciones:** Extender con `super()`, no reemplazar

### **Nuevas Funcionalidades (Sin Duplicación):**

1. ✅ **CAF:** Modelo nuevo `dte.caf` (no existe en Odoo)
2. ✅ **Certificados:** Modelo nuevo `dte.certificate` (no existe en Odoo)
3. ✅ **Generación XML:** Microservicio (no existe en Odoo)
4. ✅ **Firma Digital:** Microservicio (no existe en Odoo)
5. ✅ **IA:** Microservicio (no existe en Odoo)

---

**Próximo Documento:** `03_LIMITES_RESPONSABILIDAD.md`
