# 🎯 DELEGACIÓN DE RESPONSABILIDADES - FEATURES FALTANTES

**Fecha:** 2025-10-22  
**Análisis:** Dónde implementar cada feature de Odoo 18

---

## 📋 METODOLOGÍA DE DECISIÓN

### **Criterios para asignar responsabilidad:**

| Criterio | Módulo Odoo | Microservicio DTE | Microservicio IA |
|----------|-------------|-------------------|------------------|
| **Persistencia datos** | ✅ | ❌ | ❌ |
| **UI/UX** | ✅ | ❌ | ❌ |
| **Lógica negocio** | ✅ | ❌ | ❌ |
| **Procesamiento XML** | ❌ | ✅ | ❌ |
| **Integración SII** | ❌ | ✅ | ❌ |
| **Procesamiento pesado** | ❌ | ✅ | ❌ |
| **IA/ML** | ❌ | ❌ | ✅ |
| **Análisis semántico** | ❌ | ❌ | ✅ |

---

## 🔴 FEATURE 1: RECEPCIÓN DTE (CRÍTICO)

### **Componentes:**

#### **1.1 Descarga Email IMAP**
**Responsable:** 🏢 **MÓDULO ODOO**

**Justificación:**
- Requiere configuración UI (servidor IMAP, credenciales)
- Cron job Odoo (cada 15 min)
- Persistencia en base de datos Odoo

**Implementación:**
```python
# addons/localization/l10n_cl_dte/models/dte_inbox.py
class DTEInbox(models.Model):
    _name = 'dte.inbox'
    
    email_server = fields.Char('Servidor IMAP')
    email_user = fields.Char('Usuario')
    email_password = fields.Char('Password')
    
    @api.model
    def _cron_download_dtes(self):
        """Cron cada 15 min"""
        inboxes = self.search([('active', '=', True)])
        for inbox in inboxes:
            inbox._download_from_imap()
```

**Ubicación:** `addons/localization/l10n_cl_dte/models/dte_inbox.py`

---

#### **1.2 Parseo y Validación XML**
**Responsable:** 🚀 **MICROSERVICIO DTE**

**Justificación:**
- Procesamiento XML pesado
- Validación XSD (ya tenemos XSD)
- Extracción de datos técnicos

**Implementación:**
```python
# dte-service/parsers/dte_parser.py
class DTEParser:
    def parse_received_dte(self, xml_content: str) -> dict:
        """Parsea DTE recibido y extrae datos"""
        # Validar contra XSD
        # Extraer: RUT emisor, monto, items, TED
        # Retornar dict estructurado
```

**Ubicación:** `dte-service/parsers/dte_parser.py` (nuevo)

---

#### **1.3 Creación Factura Proveedor**
**Responsable:** 🏢 **MÓDULO ODOO**

**Justificación:**
- Crea `account.move` (modelo Odoo)
- Lógica de negocio (matching proveedor, productos)
- Persistencia en base de datos

**Implementación:**
```python
# addons/localization/l10n_cl_dte/models/dte_inbox.py
def _create_supplier_invoice(self, dte_data):
    """Crea factura de proveedor desde DTE"""
    partner = self._find_or_create_partner(dte_data['rut'])
    invoice = self.env['account.move'].create({
        'move_type': 'in_invoice',
        'partner_id': partner.id,
        'invoice_date': dte_data['fecha'],
        # ... más campos
    })
```

---

#### **1.4 Respuesta Comercial SII**
**Responsable:** 🚀 **MICROSERVICIO DTE**

**Justificación:**
- Genera XML respuesta
- Firma digital
- Envío SOAP a SII

**Implementación:**
```python
# dte-service/generators/commercial_response.py
class CommercialResponseGenerator:
    def generate_acceptance(self, dte_data: dict) -> str:
        """Genera XML de aceptación comercial"""
        # Generar XML según formato SII
        # Firmar con certificado
        # Retornar XML firmado
```

**Ubicación:** `dte-service/generators/commercial_response.py` (nuevo)

---

### **RESUMEN RECEPCIÓN DTE:**

| Componente | Responsable | Ubicación | Esfuerzo |
|------------|-------------|-----------|----------|
| Descarga IMAP | 🏢 Módulo Odoo | `models/dte_inbox.py` | 1 día |
| Parseo XML | 🚀 DTE Service | `parsers/dte_parser.py` | 1 día |
| Crear Factura | 🏢 Módulo Odoo | `models/dte_inbox.py` | 0.5 día |
| Respuesta SII | 🚀 DTE Service | `generators/commercial_response.py` | 0.5 día |

**Total:** 3 días

---

## 🔴 FEATURE 2: DISASTER RECOVERY (CRÍTICO)

### **Componentes:**

#### **2.1 Detección de Fallos**
**Responsable:** 🚀 **MICROSERVICIO DTE**

**Justificación:**
- Detecta timeout/error SII
- Lógica de retry
- Manejo de excepciones

**Implementación:**
```python
# dte-service/resilience/failure_detector.py
class FailureDetector:
    def detect_sii_failure(self, exception: Exception) -> bool:
        """Detecta si es fallo SII o error nuestro"""
        if isinstance(exception, (TimeoutError, ConnectionError)):
            return True  # Fallo SII
        return False  # Error nuestro
```

---

#### **2.2 Almacenamiento Local DTEs Fallidos**
**Responsable:** 🏢 **MÓDULO ODOO**

**Justificación:**
- Persistencia en base de datos
- UI para ver DTEs fallidos
- Gestión de reintentos

**Implementación:**
```python
# addons/localization/l10n_cl_dte/models/dte_failed.py
class DTEFailed(models.Model):
    _name = 'dte.failed'
    
    invoice_id = fields.Many2one('account.move')
    xml_content = fields.Text('XML DTE')
    failure_reason = fields.Text('Razón Fallo')
    retry_count = fields.Integer('Intentos')
    state = fields.Selection([
        ('pending', 'Pendiente'),
        ('retrying', 'Reintentando'),
        ('manual', 'Requiere Manual'),
    ])
```

---

#### **2.3 Generación Manual Fallback**
**Responsable:** 🚀 **MICROSERVICIO DTE**

**Justificación:**
- Genera XML localmente
- Firma con certificado
- No requiere SII online

**Implementación:**
```python
# dte-service/generators/manual_fallback.py
class ManualFallbackGenerator:
    def generate_offline(self, invoice_data: dict) -> str:
        """Genera DTE sin conexión SII"""
        # Generar XML completo
        # Firmar localmente
        # Guardar para envío posterior
```

---

#### **2.4 PDF de Respaldo**
**Responsable:** 🏢 **MÓDULO ODOO**

**Justificación:**
- Genera PDF con QR/TED
- Usa motor reportes Odoo
- Almacena en adjuntos

**Implementación:**
```python
# addons/localization/l10n_cl_dte/reports/dte_backup_pdf.py
def generate_backup_pdf(self):
    """Genera PDF de respaldo con TED"""
    # Usar QWeb template
    # Incluir QR code
    # Adjuntar a factura
```

---

### **RESUMEN DISASTER RECOVERY:**

| Componente | Responsable | Ubicación | Esfuerzo |
|------------|-------------|-----------|----------|
| Detección Fallos | 🚀 DTE Service | `resilience/failure_detector.py` | 0.5 día |
| Almacenamiento | 🏢 Módulo Odoo | `models/dte_failed.py` | 0.5 día |
| Generación Manual | 🚀 DTE Service | `generators/manual_fallback.py` | 0.5 día |
| PDF Respaldo | 🏢 Módulo Odoo | `reports/dte_backup_pdf.py` | 0.5 día |

**Total:** 2 días

---

## 🟡 FEATURE 3: CIRCUIT BREAKER (IMPORTANTE)

**Responsable:** 🚀 **MICROSERVICIO DTE**

**Justificación:**
- Patrón de resiliencia técnico
- No requiere UI
- Manejo de estados (CLOSED/OPEN/HALF_OPEN)

**Implementación:**
```python
# dte-service/resilience/circuit_breaker.py
class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.state = 'CLOSED'
        self.failure_count = 0
    
    async def call(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            raise CircuitOpenException("SII unavailable")
        
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise
```

**Ubicación:** `dte-service/resilience/circuit_breaker.py` (nuevo)

**Esfuerzo:** 1 día

---

## 🟡 FEATURE 4: FOLIO FORECASTING (IMPORTANTE)

### **Componentes:**

#### **4.1 Análisis Histórico**
**Responsable:** 🤖 **MICROSERVICIO IA**

**Justificación:**
- Análisis de datos históricos
- Predicción con ML
- Cálculos estadísticos

**Implementación:**
```python
# ai-service/forecasting/folio_predictor.py
class FolioPredictor:
    def predict_depletion(self, caf_data: dict) -> dict:
        """Predice agotamiento de folios"""
        # Analizar uso últimos 30 días
        # Calcular tendencia
        # Predecir fecha agotamiento
        return {
            'days_remaining': 45,
            'depletion_date': '2025-12-15',
            'confidence': 0.85
        }
```

---

#### **4.2 Alertas y UI**
**Responsable:** 🏢 **MÓDULO ODOO**

**Justificación:**
- Muestra predicciones en UI
- Genera alertas
- Permite solicitar CAF

**Implementación:**
```python
# addons/localization/l10n_cl_dte/models/dte_caf.py
def _check_folio_forecast(self):
    """Consulta predicción IA y alerta"""
    ai_client = AIServiceClient(self.env)
    forecast = ai_client.predict_folio_depletion(self.id)
    
    if forecast['days_remaining'] < 15:
        self._send_alert(forecast)
```

---

### **RESUMEN FOLIO FORECASTING:**

| Componente | Responsable | Ubicación | Esfuerzo |
|------------|-------------|-----------|----------|
| Predicción ML | 🤖 AI Service | `forecasting/folio_predictor.py` | 0.5 día |
| Alertas UI | 🏢 Módulo Odoo | `models/dte_caf.py` | 0.5 día |

**Total:** 1 día

---

## 🟡 FEATURE 5: POLLING ESTADO SII (IMPORTANTE)

**Responsable:** 🚀 **MICROSERVICIO DTE** + 🏢 **MÓDULO ODOO**

### **Componentes:**

#### **5.1 Consulta GetEstadoDTE**
**Responsable:** 🚀 **MICROSERVICIO DTE**

**Implementación:**
```python
# dte-service/clients/sii_status_client.py
class SIIStatusClient:
    async def get_dte_status(self, track_id: str) -> dict:
        """Consulta estado DTE en SII"""
        # SOAP GetEstadoDTE
        # Parsear respuesta
        return {'status': 'accepted', 'date': '2025-10-22'}
```

---

#### **5.2 Cron Polling**
**Responsable:** 🏢 **MÓDULO ODOO**

**Implementación:**
```python
# addons/localization/l10n_cl_dte/models/account_move_dte.py
@api.model
def _cron_poll_dte_status(self):
    """Cron cada 15 min - consulta estados pendientes"""
    pending = self.search([('dte_status', '=', 'sent')])
    for move in pending:
        move._update_sii_status()
```

---

### **RESUMEN POLLING:**

| Componente | Responsable | Ubicación | Esfuerzo |
|------------|-------------|-----------|----------|
| GetEstadoDTE | 🚀 DTE Service | `clients/sii_status_client.py` | 0.5 día |
| Cron Polling | 🏢 Módulo Odoo | `models/account_move_dte.py` | 0.5 día |

**Total:** 1 día

---

## 📊 RESUMEN GENERAL DE DELEGACIÓN

### **Por Componente:**

| Componente | Features Asignados | Esfuerzo Total |
|------------|-------------------|----------------|
| 🏢 **Módulo Odoo** | 8 tareas | 4 días |
| 🚀 **DTE Service** | 7 tareas | 3.5 días |
| 🤖 **AI Service** | 1 tarea | 0.5 día |

**Total:** 8 días

---

### **Por Feature:**

| Feature | Módulo Odoo | DTE Service | AI Service | Total |
|---------|-------------|-------------|------------|-------|
| **Recepción DTE** | 1.5 días | 1.5 días | - | 3 días |
| **Disaster Recovery** | 1 día | 1 día | - | 2 días |
| **Circuit Breaker** | - | 1 día | - | 1 día |
| **Folio Forecasting** | 0.5 día | - | 0.5 día | 1 día |
| **Polling Estado** | 0.5 día | 0.5 día | - | 1 día |

---

## ✅ CONCLUSIONES Y RECOMENDACIONES

### **Distribución Óptima:**

```
🏢 MÓDULO ODOO (50% del trabajo):
✅ UI y configuración
✅ Persistencia datos
✅ Lógica de negocio
✅ Cron jobs
✅ Reportes PDF

🚀 DTE SERVICE (44% del trabajo):
✅ Procesamiento XML
✅ Integración SII
✅ Resiliencia (circuit breaker)
✅ Generación manual
✅ Parseo DTEs recibidos

🤖 AI SERVICE (6% del trabajo):
✅ Predicción ML (folio forecasting)
✅ Análisis histórico
```

### **Principios Aplicados:**

1. ✅ **Separación de Concerns:** Cada componente hace lo que mejor sabe
2. ✅ **Escalabilidad:** Microservicios manejan procesamiento pesado
3. ✅ **Mantenibilidad:** Lógica negocio en Odoo, técnico en servicios
4. ✅ **Testabilidad:** Cada componente testeable independientemente

---

## 🎯 PRÓXIMOS PASOS

1. ✅ Aprobar esta delegación de responsabilidades
2. ✅ Actualizar Plan Maestro con estas asignaciones
3. ✅ Iniciar implementación por prioridad (Recepción DTE primero)

**¿Procedemos con esta distribución?** 🚀
