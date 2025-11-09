# 🎯 PLAN DE CIERRE DE BRECHAS POR CAPA

**Fecha:** 2025-10-22  
**Objetivo:** Cerrar 12 puntos para alcanzar World-Class (90+)  
**Enfoque:** Responsabilidades claras por capa arquitectónica

---

## 🏗️ ARQUITECTURA DE 3 CAPAS

```
┌─────────────────────────────────────────────────────────┐
│                    ODOO 19 CE                           │
│  Responsabilidad: UI, Business Logic, Persistencia      │
│  - Gestión de facturas (account.move)                   │
│  - Reportes contables                                    │
│  - Workflow de aprobación                               │
│  - Orquestación de microservicios                       │
└────────────────────┬────────────────────────────────────┘
                     │ HTTP/REST + RabbitMQ
        ┌────────────┴────────────┐
        │                         │
┌───────▼──────────┐    ┌────────▼─────────┐
│  DTE-SERVICE     │    │   AI-SERVICE     │
│  FastAPI/Python  │    │   FastAPI/Python │
├──────────────────┤    ├──────────────────┤
│ Responsabilidad: │    │ Responsabilidad: │
│ - Generación XML │    │ - Pre-validación │
│ - Firma digital  │    │ - Chat IA        │
│ - Envío a SII    │    │ - Matching POs   │
│ - CAF handling   │    │ - Knowledge Base │
│ - Contingencia   │    │ - Claude/OpenAI  │
└──────────────────┘    └──────────────────┘
```

---

## 📊 MATRIZ DE RESPONSABILIDADES

### **GAP 1: Reportes SII Formato Específico** (3 pts)

**Responsable:** 🟦 **ODOO** (80%) + 🟨 **DTE-SERVICE** (20%)

**Justificación:**
- Odoo tiene los datos (facturas, compras)
- Odoo genera reportes nativamente
- DTE-Service solo provee formato XML SII

**División de trabajo:**

| Tarea | Responsable | Esfuerzo |
|-------|-------------|----------|
| Libro Compras/Ventas (modelo) | ODOO | 8h |
| Libro Compras/Ventas (vista/reporte) | ODOO | 6h |
| RCV (Registro Compras/Ventas) | ODOO | 4h |
| Consumo de Folios | ODOO | 3h |
| Formato XML SII | DTE-SERVICE | 3h |

**Total:** 24h (ODOO: 21h, DTE-SERVICE: 3h)

---

### **GAP 2: Recepción Automática DTEs** (2 pts)

**Responsable:** 🟨 **DTE-SERVICE** (70%) + 🟦 **ODOO** (30%)

**Justificación:**
- DTE-Service es especialista en SII
- Debe descargar, parsear, validar XML
- Odoo solo crea factura borrador

**División de trabajo:**

| Tarea | Responsable | Esfuerzo |
|-------|-------------|----------|
| Recepción vía email (IMAP) | DTE-SERVICE | 6h |
| Descarga desde API SII | DTE-SERVICE | 4h |
| Parsing y validación XML | DTE-SERVICE | 2h |
| Endpoint POST /api/dte/received | DTE-SERVICE | 2h |
| Crear factura borrador en Odoo | ODOO | 2h |

**Total:** 16h (DTE-SERVICE: 14h, ODOO: 2h)

---

### **GAP 3: Retry + Circuit Breaker** (1 pt)

**Responsable:** 🟨 **DTE-SERVICE** (100%)

**Justificación:**
- DTE-Service comunica con SII
- Debe manejar fallos de red
- Patrón de resiliencia en microservicio

**División de trabajo:**

| Tarea | Responsable | Esfuerzo |
|-------|-------------|----------|
| Implementar retry con exponential backoff | DTE-SERVICE | 3h |
| Implementar circuit breaker (pybreaker) | DTE-SERVICE | 3h |
| Tests de resiliencia | DTE-SERVICE | 2h |

**Total:** 8h (DTE-SERVICE: 8h)

---

### **GAP 4: Monitoreo 24/7** (2 pts)

**Responsable:** 🟧 **INFRAESTRUCTURA** (100%)

**Justificación:**
- Monitoreo es responsabilidad de infraestructura
- Prometheus/Grafana son componentes externos
- Todos los servicios exponen métricas

**División de trabajo:**

| Tarea | Responsable | Esfuerzo |
|-------|-------------|----------|
| Deploy Prometheus | INFRA | 2h |
| Deploy Grafana | INFRA | 2h |
| Configurar dashboards | INFRA | 4h |
| Configurar alertas (Slack/Email) | INFRA | 2h |
| Exponer métricas en servicios | DEV (todos) | 2h |

**Total:** 12h (INFRA: 10h, DEV: 2h)

---

### **GAP 5: Backup Offsite** (2 pts)

**Responsable:** 🟧 **INFRAESTRUCTURA** (100%)

**Justificación:**
- Backup es responsabilidad de infraestructura
- Requiere acceso a servidores
- Scripts de sistema operativo

**División de trabajo:**

| Tarea | Responsable | Esfuerzo |
|-------|-------------|----------|
| Script backup PostgreSQL | INFRA | 2h |
| Script backup filestore | INFRA | 1h |
| Configurar S3/backup offsite | INFRA | 2h |
| Cron jobs automáticos | INFRA | 1h |
| Test de recovery | INFRA | 2h |

**Total:** 8h (INFRA: 8h)

---

### **GAP 6: DTEs Exportación (110-112)** (1 pt)

**Responsable:** 🟨 **DTE-SERVICE** (80%) + 🟦 **ODOO** (20%)

**Justificación:**
- DTE-Service genera XMLs
- Odoo solo agrega tipos en UI

**División de trabajo:**

| Tarea | Responsable | Esfuerzo |
|-------|-------------|----------|
| Agregar tipos 110, 111, 112 a validator | DTE-SERVICE | 1h |
| Templates XML exportación | DTE-SERVICE | 2h |
| Agregar tipos en Odoo (data XML) | ODOO | 1h |

**Total:** 4h (DTE-SERVICE: 3h, ODOO: 1h)

---

### **GAP 7: Load Testing** (1 pt)

**Responsable:** 🟧 **INFRAESTRUCTURA** (60%) + 🟩 **QA** (40%)

**Justificación:**
- Testing es responsabilidad de QA/Infra
- Requiere herramientas especializadas
- No modifica código de aplicación

**División de trabajo:**

| Tarea | Responsable | Esfuerzo |
|-------|-------------|----------|
| Setup Locust/k6 | INFRA | 2h |
| Escribir escenarios de carga | QA | 3h |
| Ejecutar tests | QA | 2h |
| Analizar resultados | QA | 1h |

**Total:** 8h (INFRA: 2h, QA: 6h)

---

## 📊 RESUMEN POR CAPA

| Capa | Esfuerzo | % Total | Gaps |
|------|----------|---------|------|
| 🟦 **ODOO** | 24h | 30% | Reportes SII, UI DTEs exportación |
| 🟨 **DTE-SERVICE** | 28h | 35% | Recepción, Retry/CB, DTEs exportación |
| 🟩 **AI-SERVICE** | 0h | 0% | - |
| 🟧 **INFRAESTRUCTURA** | 20h | 25% | Monitoreo, Backups |
| 🟪 **QA** | 8h | 10% | Load testing |
| **TOTAL** | **80h** | **100%** | **7 gaps** |

---

## 🎯 PLAN DE EJECUCIÓN POR SPRINT

### **SPRINT 1: Compliance SII** (Semana 1)

**Objetivo:** Cerrar gaps críticos de compliance

**Equipo:** 1 Dev Odoo + 1 Dev Python

| Día | Odoo | DTE-Service |
|-----|------|-------------|
| L | Libro Compras modelo (8h) | Recepción email IMAP (6h) |
| M | Libro Compras vista (6h) | Descarga API SII (4h) |
| X | RCV modelo (4h) | Parsing XML (2h) |
| J | Consumo Folios (3h) | Endpoint /received (2h) |
| V | Tests + integración (3h) | Retry + CB (6h) |

**Entregable:** +5 pts (78 → 83)

---

### **SPRINT 2: Robustez** (Semana 2)

**Objetivo:** Monitoreo y backups

**Equipo:** 1 DevOps + 1 Dev Python

| Día | Infraestructura | DTE-Service |
|-----|-----------------|-------------|
| L | Deploy Prometheus (2h) | DTEs exportación (3h) |
| M | Deploy Grafana (2h) | Exponer métricas (2h) |
| X | Dashboards (4h) | Tests (2h) |
| J | Alertas (2h) | - |
| V | Backup scripts (4h) | - |

**Entregable:** +4 pts (83 → 87)

---

### **SPRINT 3: Testing & Optimización** (Semana 3)

**Objetivo:** Load testing y ajustes finales

**Equipo:** 1 QA + 1 Dev

| Día | QA | Dev |
|-----|-----|-----|
| L | Setup Locust (2h) | Agregar DTEs en Odoo (1h) |
| M | Escenarios carga (3h) | Formato XML SII (3h) |
| X | Ejecutar tests (2h) | Crear factura borrador (2h) |
| J | Analizar resultados (1h) | Backup offsite config (2h) |
| V | Test recovery (2h) | Tests integración (2h) |

**Entregable:** +3 pts (87 → 90+) 🏆

---

## 📋 CONTRATOS DE API (Interfaces entre capas)

### **1. ODOO → DTE-SERVICE**

**Endpoint nuevo:** `POST /api/dte/generate`

```python
# Request (sin cambios)
{
  "dte_type": "33",
  "invoice_data": {...},
  "company_id": 1
}

# Response (mejorado con retry info)
{
  "success": true,
  "folio": "12345",
  "track_id": "ABC123",
  "xml_b64": "...",
  "retry_count": 0,  # NUEVO
  "circuit_breaker_state": "CLOSED"  # NUEVO
}
```

**Endpoint nuevo:** `POST /api/dte/received`

```python
# Request
{
  "xml_content": "...",  # XML del DTE recibido
  "source": "email",     # email | api_sii | manual
  "company_id": 1
}

# Response
{
  "success": true,
  "dte_data": {
    "dte_type": "33",
    "folio": "98765",
    "emisor_rut": "12345678-9",
    "monto_total": 100000,
    "fecha_emision": "2025-10-22"
  },
  "validation": {
    "is_valid": true,
    "errors": [],
    "warnings": []
  }
}
```

---

### **2. ODOO → AI-SERVICE**

**Sin cambios** - Ya está bien definido

---

### **3. DTE-SERVICE → SII**

**Mejorado con retry:**

```python
# Antes
response = sii_client.send_dte(xml)

# Después (con retry)
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def send_dte_with_retry(xml):
    return sii_client.send_dte(xml)
```

---

## 🔧 IMPLEMENTACIÓN DETALLADA

### **TAREA 1: Libro Compras/Ventas (ODOO)**

**Archivo:** `/addons/localization/l10n_cl_dte/models/dte_libro.py`

```python
class DTELibro(models.Model):
    """Libro de Compras y Ventas formato SII"""
    _name = 'dte.libro'
    _description = 'Libro Electrónico SII'
    
    name = fields.Char('Nombre', required=True)
    tipo = fields.Selection([
        ('compra', 'Libro de Compras'),
        ('venta', 'Libro de Ventas'),
    ], required=True)
    
    periodo_desde = fields.Date('Desde', required=True)
    periodo_hasta = fields.Date('Hasta', required=True)
    
    company_id = fields.Many2one('res.company', required=True)
    
    # Líneas del libro
    line_ids = fields.One2many('dte.libro.line', 'libro_id')
    
    # XML generado
    xml_content = fields.Binary('XML Libro', attachment=True)
    
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('generated', 'Generado'),
        ('sent', 'Enviado a SII'),
    ], default='draft')
    
    def action_generate(self):
        """Genera XML del libro según formato SII"""
        self.ensure_one()
        
        # 1. Obtener facturas del período
        domain = [
            ('company_id', '=', self.company_id.id),
            ('invoice_date', '>=', self.periodo_desde),
            ('invoice_date', '<=', self.periodo_hasta),
            ('state', '=', 'posted'),
        ]
        
        if self.tipo == 'venta':
            domain.append(('move_type', 'in', ['out_invoice', 'out_refund']))
        else:
            domain.append(('move_type', 'in', ['in_invoice', 'in_refund']))
        
        invoices = self.env['account.move'].search(domain)
        
        # 2. Crear líneas
        lines = []
        for inv in invoices:
            lines.append({
                'libro_id': self.id,
                'invoice_id': inv.id,
                'dte_type': inv.dte_code,
                'folio': inv.dte_folio,
                'fecha': inv.invoice_date,
                'rut': inv.partner_id.vat,
                'razon_social': inv.partner_id.name,
                'monto_neto': inv.amount_untaxed,
                'monto_iva': inv.amount_tax,
                'monto_total': inv.amount_total,
            })
        
        self.line_ids = [(0, 0, line) for line in lines]
        
        # 3. Generar XML formato SII
        xml_content = self._generate_xml_sii()
        
        self.write({
            'xml_content': xml_content,
            'state': 'generated'
        })
```

---

### **TAREA 2: Recepción Email (DTE-SERVICE)**

**Archivo:** `/dte-service/receivers/email_receiver.py`

```python
import imaplib
import email
from email.header import decode_header
import logging

logger = logging.getLogger(__name__)

class EmailDTEReceiver:
    """Recibe DTEs vía email (IMAP)"""
    
    def __init__(self, imap_server, email_user, email_pass):
        self.imap_server = imap_server
        self.email_user = email_user
        self.email_pass = email_pass
    
    def fetch_new_dtes(self):
        """Descarga DTEs nuevos desde email"""
        
        # Conectar a IMAP
        mail = imaplib.IMAP4_SSL(self.imap_server)
        mail.login(self.email_user, self.email_pass)
        mail.select('INBOX')
        
        # Buscar emails con DTEs (subject contiene "DTE")
        status, messages = mail.search(None, 'UNSEEN SUBJECT "DTE"')
        
        dtes = []
        
        for num in messages[0].split():
            # Fetch email
            status, data = mail.fetch(num, '(RFC822)')
            
            # Parse email
            msg = email.message_from_bytes(data[0][1])
            
            # Extraer attachments XML
            for part in msg.walk():
                if part.get_content_type() == 'application/xml':
                    xml_content = part.get_payload(decode=True).decode()
                    
                    dtes.append({
                        'xml_content': xml_content,
                        'source': 'email',
                        'email_from': msg['From'],
                        'email_subject': msg['Subject'],
                    })
            
            # Marcar como leído
            mail.store(num, '+FLAGS', '\\Seen')
        
        mail.close()
        mail.logout()
        
        logger.info(f"Fetched {len(dtes)} DTEs from email")
        
        return dtes
```

---

### **TAREA 3: Retry + Circuit Breaker (DTE-SERVICE)**

**Archivo:** `/dte-service/clients/sii_soap_client.py`

```python
from tenacity import retry, stop_after_attempt, wait_exponential
from pybreaker import CircuitBreaker
import logging

logger = logging.getLogger(__name__)

# Circuit breaker global
sii_circuit_breaker = CircuitBreaker(
    fail_max=5,           # Abre después de 5 fallos
    timeout_duration=60,  # Permanece abierto 60 segundos
    name='sii_circuit_breaker'
)

class SIISoapClient:
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True
    )
    @sii_circuit_breaker
    def send_dte(self, xml_content, rut_emisor):
        """
        Envía DTE al SII con retry y circuit breaker
        
        Retry: 3 intentos con exponential backoff
        Circuit breaker: Abre después de 5 fallos consecutivos
        """
        try:
            logger.info("Sending DTE to SII", rut_emisor=rut_emisor)
            
            # Envío SOAP
            response = self.soap_client.service.EnviarDTE(
                RutEmisor=rut_emisor,
                DvEmisor=self._get_dv(rut_emisor),
                DTE=xml_content
            )
            
            return {
                'success': True,
                'track_id': response.TrackID,
                'estado': response.Estado
            }
            
        except Exception as e:
            logger.error("SII send failed", error=str(e))
            raise  # Re-raise para que retry lo intente de nuevo
```

---

## ✅ CRITERIOS DE ACEPTACIÓN

### **Por Gap:**

**GAP 1: Reportes SII**
- [ ] Modelo `dte.libro` creado
- [ ] Vista de generación de libro
- [ ] XML formato SII correcto
- [ ] Test con facturas reales
- [ ] Exportación a archivo

**GAP 2: Recepción DTEs**
- [ ] Email receiver funcionando
- [ ] API SII download funcionando
- [ ] Parsing XML correcto
- [ ] Validación completa
- [ ] Factura borrador creada en Odoo

**GAP 3: Retry + CB**
- [ ] Retry con exponential backoff
- [ ] Circuit breaker configurado
- [ ] Logs de retry
- [ ] Tests de resiliencia
- [ ] Métricas expuestas

**GAP 4: Monitoreo**
- [ ] Prometheus desplegado
- [ ] Grafana desplegado
- [ ] 3+ dashboards creados
- [ ] Alertas configuradas
- [ ] Métricas en todos los servicios

**GAP 5: Backups**
- [ ] Script backup PostgreSQL
- [ ] Script backup filestore
- [ ] Backup offsite (S3/similar)
- [ ] Cron jobs configurados
- [ ] Test de recovery exitoso

**GAP 6: DTEs Exportación**
- [ ] Tipos 110, 111, 112 en validator
- [ ] Templates XML creados
- [ ] Tests de generación
- [ ] Tipos en Odoo UI

**GAP 7: Load Testing**
- [ ] Locust/k6 configurado
- [ ] 3+ escenarios de carga
- [ ] Tests ejecutados
- [ ] Reporte de resultados
- [ ] Optimizaciones aplicadas

---

## 📊 MÉTRICAS DE ÉXITO

| Métrica | Antes | Después | Target |
|---------|-------|---------|--------|
| **Scoring Total** | 78/100 | 90+/100 | ✅ |
| **Compliance SII** | 17/20 | 20/20 | ✅ |
| **Robustez** | 18/25 | 22/25 | ✅ |
| **Uptime** | ? | 99.5%+ | ✅ |
| **Response time** | ? | <2s p95 | ✅ |
| **Backup recovery** | ? | <1h RTO | ✅ |

---

## 🎯 CONCLUSIÓN

**Plan robusto con:**
- ✅ Responsabilidades claras por capa
- ✅ Contratos de API definidos
- ✅ 3 sprints de 1 semana cada uno
- ✅ 80 horas totales (2.5 semanas con 1 equipo)
- ✅ Criterios de aceptación claros
- ✅ Métricas de éxito definidas

**Equipo requerido:**
- 1 Dev Odoo (24h)
- 1 Dev Python (28h)
- 1 DevOps (20h)
- 1 QA (8h)

**Resultado esperado:** 90+ pts (World-Class) 🏆

---

**Documento generado:** 2025-10-22  
**Versión:** 1.0  
**Estado:** ✅ LISTO PARA EJECUTAR
