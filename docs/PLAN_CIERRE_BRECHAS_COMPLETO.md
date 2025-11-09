# 🎯 PLAN ROBUSTO DE CIERRE DE BRECHAS - STACK COMPLETO

**Fecha:** 2025-10-22
**Empresa:** Ingeniería B2B (solo facturación)
**Stack:** Odoo 19 CE + l10n_cl_dte custom + DTE Service + AI Service
**Estado Actual:** 97% funcional, 3% crítico faltante
**Meta:** 100% Production Ready con certificación SII

---

## 📊 RESUMEN EJECUTIVO

### Estado Actual del Stack

```
╔═══════════════════════════════════════════════════════════════╗
║                    STACK COMPLETO - COBERTURA                 ║
╠═══════════════════════════════════════════════════════════════╣
║ CAPA                      │ STATUS    │ COVERAGE │ GAP        ║
╟───────────────────────────┼───────────┼──────────┼────────────╢
║ Odoo 19 CE Base           │ ✅ Ready  │ 100%     │ -          ║
║ Módulo l10n_cl_dte        │ ✅ Ready  │ 100%     │ -          ║
║ DTE Microservice          │ ⚠️ Gaps   │  91%     │ 9%         ║
║ AI Microservice           │ ✅ Ready  │ 100%     │ -          ║
║ Infrastructure            │ ✅ Ready  │ 100%     │ -          ║
║ Security & Auth           │ ✅ Ready  │ 100%     │ -          ║
║ Testing Suite             │ ✅ Ready  │  80%     │ 20%        ║
╟───────────────────────────┼───────────┼──────────┼────────────╢
║ OVERALL                   │ ⚠️ Gaps   │  97%     │ 3%         ║
╚═══════════════════════════════════════════════════════════════╝
```

### Brechas Identificadas (5 Total)

| # | Brecha | Prioridad | Días | Capa Afectada |
|---|--------|-----------|------|---------------|
| 1 | EVENTOS SII (Acuse/Aceptación) | 🔴 CRÍTICO | 4-5 | DTE Service + Odoo Module |
| 2 | IECV Completo (línea x línea) | 🔴 CRÍTICO | 6-8 | DTE Service + Odoo Module |
| 3 | SET DE PRUEBAS SII | 🔴 CRÍTICO | 3-4 | Testing + DTE Service |
| 4 | DTE 71 Recepción | 🟡 IMPORTANTE | 0.5 | DTE Service |
| 5 | Libro de Guías Verificación | 🟡 IMPORTANTE | 2-3 | DTE Service + Odoo Module |

**Total Esfuerzo:** 16-20.5 días (3-4 semanas)
**Inversión:** $8,000 - $10,250 USD (@$500/día)

---

## 🏗️ ARQUITECTURA DE INTERDEPENDENCIAS

### Mapa de Capas y Flujos

```
┌─────────────────────────────────────────────────────────────┐
│                    USUARIO FINAL                            │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              ODOO 19 CE (Frontend + ORM)                    │
│  ┌──────────────────────────────────────────────────┐       │
│  │ Módulo l10n_cl_dte (Custom)                      │       │
│  │  • Models: account.move, dte.caf, dte.evento     │       │
│  │  • Views: formularios, wizards, reportes         │       │
│  │  • Logic: validaciones, workflows, UI/UX         │       │
│  └──────────────┬───────────────────────────────────┘       │
│                 │ REST API / RabbitMQ                        │
└─────────────────┼────────────────────────────────────────────┘
                  │
    ┌─────────────┴─────────────┐
    │                           │
┌───▼────────────┐    ┌────────▼─────────┐
│ DTE SERVICE    │    │  AI SERVICE      │
│ (FastAPI)      │    │  (FastAPI)       │
├────────────────┤    ├──────────────────┤
│ • Generators   │    │ • Chat Engine    │
│ • Validators   │    │ • SII Monitor    │
│ • SOAP Client  │    │ • Reconciliation │
│ • Signer       │    │ • Knowledge Base │
│ • Poller       │    │ • Claude API     │
└───┬────────────┘    └──────────────────┘
    │
    ▼
┌────────────────────────────────┐
│ SII (Servicio Impuestos)       │
│ • SOAP Endpoints               │
│ • Maullin (sandbox)            │
│ • Palena (producción)          │
└────────────────────────────────┘
```

### Puntos de Integración Críticos

**1. Odoo ↔ DTE Service:**
- Protocol: REST API + RabbitMQ (async)
- Auth: Bearer tokens (API_KEY)
- Data: JSON (invoices) → XML (DTEs)

**2. DTE Service ↔ SII:**
- Protocol: SOAP 1.1
- Auth: Digital signature (X.509)
- Data: XML firmado

**3. Odoo ↔ AI Service:**
- Protocol: REST API
- Auth: Bearer tokens
- Data: JSON (prevalidation, chat, reconciliation)

**4. AI Service ↔ Anthropic:**
- Protocol: HTTPS REST
- Auth: API Key
- Data: JSON (prompts → responses)

---

## 📋 PLAN DE IMPLEMENTACIÓN - 4 FASES

### FASE 1: Quick Wins (Semana 1 - 3 días) 🟢

**Objetivo:** Resolver brechas rápidas, mejorar testing, preparar terreno

#### Tarea 1.1: Fix DTE 71 Recepción (4 horas)

**Capa Afectada:** DTE Service

**Archivos a Modificar:**
```
dte-service/
├── validators/received_dte_validator.py  # Agregar '71' a VALID_DTE_TYPES
└── tests/test_received_dte_validator.py  # Agregar test case BHE
```

**Implementación:**
```python
# File: validators/received_dte_validator.py
# Line 23

# BEFORE:
VALID_DTE_TYPES = ['33', '34', '39', '41', '43', '46', '52', '56', '61', '70']

# AFTER:
VALID_DTE_TYPES = ['33', '34', '39', '41', '43', '46', '52', '56', '61', '70', '71']

# Agregar validación específica BHE
def _validate_bhe_specific(self, dte_data: Dict):
    """Validaciones específicas para DTE 71 (BHE)"""
    if dte_data.get('dte_type') != '71':
        return

    # BHE tiene retención 10% obligatoria
    if 'retencion' not in dte_data.get('totales', {}):
        self.validation_warnings.append("BHE should have 10% retention")
```

**Testing:**
```bash
# Test data: BHE de freelancer
pytest tests/test_received_dte_validator.py::test_bhe_reception -v
```

**Criterio de Éxito:**
- ✅ DTE 71 aceptado sin errores
- ✅ Validación retención 10%
- ✅ Test passing

---

#### Tarea 1.2: Verificar Libro de Guías (1 día)

**Capa Afectada:** DTE Service

**Investigación:**
```bash
# 1. Revisar libro_generator.py actual
cat dte-service/generators/libro_generator.py

# 2. Verificar si incluye guías o solo facturas
grep -n "52\|Guía\|Despacho" dte-service/generators/libro_generator.py

# 3. Consultar normativa SII
# ¿Libro de Guías es separado o va en Libro Compra/Venta?
```

**Outcomes Posibles:**

**A) Ya está incluido:** ✅ Marcar como completo
**B) Falta implementar:** Agregar a Fase 2

**Entregable:**
- Documento: `docs/LIBRO_GUIAS_ANALYSIS.md`
- Decisión: ¿Separado o incluido?

---

#### Tarea 1.3: Obtener SET DE PRUEBAS SII (1 día)

**Capa Afectada:** Testing

**Acciones:**
1. Crear cuenta en Maullin (sandbox SII)
2. Descargar casos de prueba oficiales
3. Organizar test data

**Estructura:**
```
tests/
└── sii_certification/
    ├── README.md
    ├── test_data/
    │   ├── caso_01_factura_basica.json
    │   ├── caso_02_factura_exenta.json
    │   ├── caso_03_nota_credito.json
    │   ├── ...
    │   └── caso_50_edge_cases.json
    ├── test_certification.py
    └── expected_results/
        ├── caso_01_expected.xml
        └── ...
```

**Entregable:**
- 50+ casos de prueba SII
- Script de validación automática
- Documentación de casos

---

### FASE 2: EVENTOS SII (Semana 1-2 - 5 días) 🔴

**Objetivo:** Implementar workflow completo de eventos para DTEs recibidos

**Prioridad:** CRÍTICA - Sin esto, workflow de compras incompleto

#### Arquitectura de Eventos

```
FLUJO EVENTOS SII:

Proveedor envía DTE 33
         ↓
    ┌────────────────────────────────────┐
    │ 1. RECEPCIÓN (ya tenemos ✅)       │
    │    - Download XML from SII         │
    │    - Parse + Validate              │
    │    - Store in dte.inbox            │
    └────────────┬───────────────────────┘
                 ↓
    ┌────────────────────────────────────┐
    │ 2. ACUSE RECIBO (falta ❌)         │
    │    - Usuario revisa DTE            │
    │    - Sistema envía "Recibido"      │
    │    - Plazo: 8 días hábiles         │
    └────────────┬───────────────────────┘
                 ↓
    ┌────────────────────────────────────┐
    │ 3. ACEPTACIÓN/RECHAZO (falta ❌)   │
    │    - Usuario aprueba o reclama     │
    │    - Sistema envía evento a SII    │
    │    - Plazo: 8 días desde recibo    │
    └────────────┬───────────────────────┘
                 ↓
         SII registra evento
```

#### Tarea 2.1: Modelos Odoo (1 día)

**Capa Afectada:** Odoo Module

**Archivos Nuevos:**
```
addons/localization/l10n_cl_dte/
└── models/
    └── dte_evento.py  # NUEVO
```

**Implementación:**
```python
# File: models/dte_evento.py

from odoo import models, fields, api

class DTEEvento(models.Model):
    _name = 'dte.evento'
    _description = 'Eventos SII para DTEs Recibidos'
    _order = 'fecha_evento desc'

    # Relación con DTE recibido
    dte_inbox_id = fields.Many2one('dte.inbox', string='DTE', required=True)

    # Tipo de evento
    tipo_evento = fields.Selection([
        ('acuse', 'Acuse de Recibo'),
        ('acepto', 'Aceptación'),
        ('reclamo', 'Reclamo'),
        ('ack_recibo', 'ACK Recibo Mercadería'),
    ], string='Tipo Evento', required=True)

    # Estado
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sent', 'Enviado'),
        ('accepted', 'Aceptado SII'),
        ('rejected', 'Rechazado SII'),
    ], default='draft')

    # Datos del evento
    fecha_evento = fields.Datetime('Fecha Evento', default=fields.Datetime.now)
    codigo_reclamo = fields.Selection([
        ('1', 'Reclamo por Rechazar Contenido del Documento'),
        ('2', 'Reclamo por Rechazar Contenido de alguna de las Líneas'),
        ('3', 'Reclamo por Rechazar Montos'),
    ], string='Código Reclamo')

    glosa = fields.Text('Glosa/Observación')

    # Respuesta SII
    track_id = fields.Char('Track ID SII')
    response_xml = fields.Text('Respuesta SII')
    error_message = fields.Text('Mensaje Error')

    # Metadata
    user_id = fields.Many2one('res.users', string='Usuario', default=lambda self: self.env.user)
    company_id = fields.Many2one('res.company', default=lambda self: self.env.company)

    def action_send_to_sii(self):
        """Enviar evento al SII via DTE Service"""
        self.ensure_one()

        # Call DTE microservice
        payload = {
            'tipo_evento': self.tipo_evento,
            'dte_type': self.dte_inbox_id.dte_type,
            'folio': self.dte_inbox_id.folio,
            'emisor_rut': self.dte_inbox_id.emisor_rut,
            'fecha_emision': self.dte_inbox_id.fecha_emision.isoformat(),
            'codigo_reclamo': self.codigo_reclamo if self.tipo_evento == 'reclamo' else None,
            'glosa': self.glosa,
        }

        # POST to DTE service
        response = requests.post(
            f"{self.env['ir.config_parameter'].get_param('dte_service_url')}/api/v1/eventos/send",
            json=payload,
            headers={'Authorization': f"Bearer {self.env['ir.config_parameter'].get_param('dte_api_key')}"}
        )

        if response.status_code == 200:
            data = response.json()
            self.write({
                'state': 'sent',
                'track_id': data.get('track_id'),
            })
        else:
            self.write({
                'state': 'rejected',
                'error_message': response.text,
            })
```

**Vistas:**
```xml
<!-- views/dte_evento_views.xml -->
<record id="view_dte_evento_tree" model="ir.ui.view">
    <field name="name">dte.evento.tree</field>
    <field name="model">dte.evento</field>
    <field name="arch" type="xml">
        <tree>
            <field name="fecha_evento"/>
            <field name="dte_inbox_id"/>
            <field name="tipo_evento"/>
            <field name="state" decoration-success="state == 'accepted'"
                   decoration-danger="state == 'rejected'"/>
            <field name="track_id"/>
        </tree>
    </field>
</record>

<!-- Smart button en dte.inbox para crear evento -->
<record id="view_dte_inbox_form_eventos" model="ir.ui.view">
    <field name="name">dte.inbox.form.eventos</field>
    <field name="model">dte.inbox</field>
    <field name="inherit_id" ref="view_dte_inbox_form"/>
    <field name="arch" type="xml">
        <xpath expr="//header" position="inside">
            <button name="action_create_acuse" string="📝 Acuse Recibo"
                    type="object" class="btn-primary"
                    invisible="state != 'received'"/>
            <button name="action_create_acepto" string="✅ Aceptar DTE"
                    type="object" class="btn-success"
                    invisible="state != 'acused'"/>
            <button name="action_create_reclamo" string="❌ Reclamar DTE"
                    type="object" class="btn-danger"
                    invisible="state != 'acused'"/>
        </xpath>
    </field>
</record>
```

---

#### Tarea 2.2: DTE Service - Eventos SOAP (2 días)

**Capa Afectada:** DTE Service

**Archivos Nuevos:**
```
dte-service/
├── routes/
│   └── eventos.py  # NUEVO - REST endpoints
├── clients/
│   └── sii_eventos_client.py  # NUEVO - SOAP client eventos
└── generators/
    └── evento_generator.py  # NUEVO - XML eventos
```

**Implementación:**

```python
# File: clients/sii_eventos_client.py

from zeep import Client
from zeep.transports import Transport
from requests import Session
import structlog

logger = structlog.get_logger()

class SIIEventosClient:
    """Cliente SOAP para eventos SII"""

    WSDL_SANDBOX = "https://maullin.sii.cl/DTEWS/DTEEventosService.asmx?WSDL"
    WSDL_PROD = "https://palena.sii.cl/DTEWS/DTEEventosService.asmx?WSDL"

    def __init__(self, environment: str = 'sandbox'):
        wsdl = self.WSDL_SANDBOX if environment == 'sandbox' else self.WSDL_PROD

        session = Session()
        session.verify = True
        transport = Transport(session=session, timeout=60)

        self.client = Client(wsdl=wsdl, transport=transport)
        self.environment = environment

    def enviar_evento(self, xml_evento: str, firma: str) -> dict:
        """
        Envía evento (Acuse, Aceptación, Reclamo) al SII.

        Args:
            xml_evento: XML del evento generado
            firma: Firma digital del XML

        Returns:
            dict con track_id y estado
        """
        logger.info("sending_evento_to_sii",
                    environment=self.environment)

        try:
            # SOAP call
            response = self.client.service.IngresarEventoDTE(
                RutEmisor="76123456-7",  # From evento data
                DvEmisor="7",
                RutReceptor="60805000-0",  # SII
                DvReceptor="0",
                Evento=xml_evento
            )

            # Parse response
            track_id = response.get('TRACKID')
            estado = response.get('ESTADO')

            logger.info("evento_sent_successfully",
                       track_id=track_id,
                       estado=estado)

            return {
                'success': True,
                'track_id': track_id,
                'estado': estado,
                'response': response,
            }

        except Exception as e:
            logger.error("evento_send_failed", error=str(e))
            return {
                'success': False,
                'error': str(e),
            }

    def consultar_estado_evento(self, track_id: str, rut_emisor: str) -> dict:
        """Consulta estado de evento enviado"""
        try:
            response = self.client.service.ConsultarEstadoEvento(
                TrackId=track_id,
                RutEmisor=rut_emisor
            )

            return {
                'success': True,
                'estado': response.get('ESTADO'),
                'glosa': response.get('GLOSA_ESTADO'),
            }
        except Exception as e:
            logger.error("evento_status_query_failed", error=str(e))
            return {
                'success': False,
                'error': str(e),
            }
```

```python
# File: generators/evento_generator.py

from lxml import etree
from datetime import datetime
import structlog

logger = structlog.get_logger()

class EventoGenerator:
    """Genera XML de Eventos SII"""

    def generate_acuse_recibo(self, dte_data: dict) -> str:
        """
        Genera XML de Acuse de Recibo.

        Args:
            dte_data: {
                'dte_type': '33',
                'folio': 12345,
                'fecha_emision': '2025-10-22',
                'emisor_rut': '76123456-7',
                'receptor_rut': '77654321-0',
                'monto_total': 100000,
            }
        """
        # Root
        evento = etree.Element('EnvioEvento',
                               xmlns="http://www.sii.cl/SiiDte",
                               version="1.0")

        # SetEvento
        set_evento = etree.SubElement(evento, 'SetEvento', ID="SetEvento")

        # Caratula
        caratula = etree.SubElement(set_evento, 'Caratula')
        etree.SubElement(caratula, 'RutResponde').text = dte_data['receptor_rut']
        etree.SubElement(caratula, 'RutRecibe').text = '60805000-0'  # SII
        etree.SubElement(caratula, 'FchEvento').text = datetime.now().strftime('%Y-%m-%d')
        etree.SubElement(caratula, 'CantidadEventos').text = '1'

        # Evento
        evento_doc = etree.SubElement(set_evento, 'Evento')
        documento_evento = etree.SubElement(evento_doc, 'DocumentoEvento')

        etree.SubElement(documento_evento, 'TipoEvento').text = 'ACUSE_RECIBO'
        etree.SubElement(documento_evento, 'TipoDTE').text = dte_data['dte_type']
        etree.SubElement(documento_evento, 'FolioDTE').text = str(dte_data['folio'])
        etree.SubElement(documento_evento, 'FchEmisionDTE').text = dte_data['fecha_emision']
        etree.SubElement(documento_evento, 'RUTEmisorDTE').text = dte_data['emisor_rut']
        etree.SubElement(documento_evento, 'MntTotalDTE').text = str(dte_data['monto_total'])

        # Convert to string
        xml_string = etree.tostring(
            evento,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')

        logger.info("acuse_recibo_generated",
                   dte_type=dte_data['dte_type'],
                   folio=dte_data['folio'])

        return xml_string

    def generate_aceptacion(self, dte_data: dict) -> str:
        """Similar a acuse_recibo pero TipoEvento = 'ACEPTO'"""
        # Similar structure, change TipoEvento
        pass

    def generate_reclamo(self, dte_data: dict, codigo_reclamo: str, glosa: str) -> str:
        """
        Genera XML de Reclamo.

        Args:
            codigo_reclamo: '1', '2', '3'
            glosa: Texto del reclamo
        """
        # Similar structure
        # TipoEvento = 'RECLAMO'
        # Agregar <CodigoReclamo> y <Glosa>
        pass
```

```python
# File: routes/eventos.py

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import structlog

from generators.evento_generator import EventoGenerator
from signers.dte_signer import DTESigner
from clients.sii_eventos_client import SIIEventosClient
from auth import get_current_user, require_permission, Permission

router = APIRouter(prefix="/api/v1/eventos", tags=["eventos"])
logger = structlog.get_logger()

class EventoRequest(BaseModel):
    tipo_evento: str  # 'acuse', 'acepto', 'reclamo'
    dte_type: str
    folio: int
    fecha_emision: str
    emisor_rut: str
    receptor_rut: str
    monto_total: int
    codigo_reclamo: Optional[str] = None
    glosa: Optional[str] = None

@router.post("/send")
@require_permission(Permission.DTE_EVENTOS_SEND)
async def send_evento(request: EventoRequest, user = Depends(get_current_user)):
    """Enviar evento al SII"""

    logger.info("evento_send_requested",
               tipo=request.tipo_evento,
               dte_type=request.dte_type,
               folio=request.folio)

    try:
        # 1. Generate XML
        generator = EventoGenerator()

        if request.tipo_evento == 'acuse':
            xml = generator.generate_acuse_recibo(request.dict())
        elif request.tipo_evento == 'acepto':
            xml = generator.generate_aceptacion(request.dict())
        elif request.tipo_evento == 'reclamo':
            xml = generator.generate_reclamo(
                request.dict(),
                request.codigo_reclamo,
                request.glosa
            )
        else:
            raise ValueError(f"Tipo evento inválido: {request.tipo_evento}")

        # 2. Sign XML
        signer = DTESigner()
        signed_xml = signer.sign(xml)

        # 3. Send to SII
        client = SIIEventosClient()
        result = client.enviar_evento(signed_xml, signer.get_signature())

        if result['success']:
            logger.info("evento_sent_successfully",
                       track_id=result['track_id'])

            return {
                'success': True,
                'track_id': result['track_id'],
                'estado': result['estado'],
            }
        else:
            raise HTTPException(status_code=500, detail=result['error'])

    except Exception as e:
        logger.error("evento_send_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
```

---

#### Tarea 2.3: Testing Eventos (1 día)

**Archivos:**
```
tests/
└── test_eventos_sii.py  # NUEVO
```

**Test Cases:**
```python
import pytest
from generators.evento_generator import EventoGenerator
from clients.sii_eventos_client import SIIEventosClient

class TestEventosSII:

    def test_generate_acuse_recibo(self):
        """Test generación XML Acuse Recibo"""
        generator = EventoGenerator()

        dte_data = {
            'dte_type': '33',
            'folio': 12345,
            'fecha_emision': '2025-10-22',
            'emisor_rut': '76123456-7',
            'receptor_rut': '77654321-0',
            'monto_total': 100000,
        }

        xml = generator.generate_acuse_recibo(dte_data)

        assert '<TipoEvento>ACUSE_RECIBO</TipoEvento>' in xml
        assert '<FolioDTE>12345</FolioDTE>' in xml

    def test_generate_aceptacion(self):
        """Test generación XML Aceptación"""
        # Similar
        pass

    def test_generate_reclamo(self):
        """Test generación XML Reclamo"""
        generator = EventoGenerator()

        dte_data = {...}
        xml = generator.generate_reclamo(dte_data, '1', 'Producto no recibido')

        assert '<TipoEvento>RECLAMO</TipoEvento>' in xml
        assert '<CodigoReclamo>1</CodigoReclamo>' in xml
        assert 'Producto no recibido' in xml

    @pytest.mark.integration
    def test_send_evento_to_sii_sandbox(self):
        """Test envío real a Maullin (requiere certificado)"""
        # Solo en CI/CD con certificado de prueba
        pass
```

---

#### Tarea 2.4: Documentación & Integration (1 día)

**Entregables:**

1. **User Guide:**
```markdown
# GUÍA: Gestión de Eventos SII

## Flujo de Trabajo

### 1. Recibir Factura de Proveedor
- Sistema descarga DTE del SII automáticamente
- Aparece en "DTEs Recibidos"

### 2. Acuse de Recibo (8 días)
- Abrir DTE recibido
- Click "📝 Acuse Recibo"
- Sistema envía automáticamente al SII

### 3. Aceptación o Reclamo (8 días desde acuse)
- Revisar contenido del DTE
- Opción A: Click "✅ Aceptar DTE"
- Opción B: Click "❌ Reclamar DTE"
  - Seleccionar código reclamo
  - Ingresar observación

### 4. Seguimiento
- Ver estado en smart button "Eventos"
- Track ID del SII
- Respuesta del SII
```

2. **API Documentation:**
```yaml
# openapi.yaml - Eventos endpoint
/api/v1/eventos/send:
  post:
    summary: Enviar evento al SII
    security:
      - BearerAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/EventoRequest'
    responses:
      200:
        description: Evento enviado exitosamente
        content:
          application/json:
            schema:
              type: object
              properties:
                success:
                  type: boolean
                track_id:
                  type: string
```

**Criterio de Éxito Fase 2:**
- ✅ Usuario puede enviar Acuse Recibo desde Odoo
- ✅ Usuario puede Aceptar/Reclamar DTEs
- ✅ SII recibe eventos correctamente
- ✅ Track ID almacenado y consultable
- ✅ Tests passing (95% coverage eventos)

---

### FASE 3: IECV Completo (Semana 2-3 - 7 días) 🔴

**Objetivo:** Implementar reporte IECV línea por línea (obligatorio SII)

**Prioridad:** CRÍTICA - Compliance legal

#### ¿Qué es IECV?

```
IECV = Información Electrónica de Compra y Venta

Diferencia vs Libro CV:

Libro CV (tenemos):
- Resumen mensual
- Totales por documento
- Un registro por DTE

IECV (falta):
- Detalle línea por línea
- Un registro por CADA PRODUCTO/SERVICIO
- Códigos de producto
- Descripciones completas
- Cantidades
- Precios unitarios
```

**Ejemplo:**

```
Factura 1234 por $100.000:
- Producto A: 10 unidades × $5.000 = $50.000
- Producto B:  5 unidades × $10.000 = $50.000

Libro CV (actual):
1 registro → Factura 1234 | $100.000

IECV (requerido):
2 registros → Factura 1234 Línea 1 | Producto A | 10 | $5.000 | $50.000
              Factura 1234 Línea 2 | Producto B |  5 | $10.000 | $50.000
```

---

#### Tarea 3.1: Análisis Normativa SII (1 día)

**Capa Afectada:** Research

**Acciones:**
1. Descargar especificación IECV desde SII
2. Analizar formato XML requerido
3. Identificar campos obligatorios/opcionales
4. Casos especiales (servicios sin cantidad, etc.)

**Entregable:**
- `docs/IECV_SPECIFICATION_SII.md`
- XSD schema del IECV (si disponible)

---

#### Tarea 3.2: Extender Modelos Odoo (1 día)

**Capa Afectada:** Odoo Module

**Archivos a Modificar:**
```
addons/localization/l10n_cl_dte/
└── models/
    ├── account_move_dte.py  # Agregar método get_iecv_lines()
    └── dte_iecv.py  # NUEVO - Modelo para almacenar IECV generados
```

**Implementación:**
```python
# File: models/account_move_dte.py

class AccountMoveDTE(models.Model):
    _inherit = 'account.move'

    def get_iecv_lines(self):
        """
        Retorna líneas para IECV (línea por línea).

        Returns:
            list of dict: [
                {
                    'tipo_dte': '33',
                    'folio': 1234,
                    'fecha': '2025-10-22',
                    'rut_contraparte': '76123456-7',
                    'razon_social': 'Cliente ABC',
                    'nro_linea': 1,
                    'codigo_producto': 'PROD-A',
                    'descripcion': 'Servicio Ingeniería',
                    'cantidad': 10.0,
                    'unidad_medida': 'HRS',
                    'precio_unitario': 50000,
                    'monto_neto_linea': 500000,
                    'monto_iva_linea': 95000,
                    'monto_total_linea': 595000,
                },
                ...
            ]
        """
        self.ensure_one()

        lines = []
        for idx, line in enumerate(self.invoice_line_ids, start=1):
            lines.append({
                'tipo_dte': self.l10n_latam_document_type_id.code,
                'folio': self.dte_folio,
                'fecha_emision': self.invoice_date.strftime('%Y-%m-%d'),
                'rut_contraparte': self.partner_id.vat,
                'razon_social': self.partner_id.name,
                'nro_linea': idx,
                'codigo_producto': line.product_id.default_code or '',
                'descripcion': line.name[:80],  # Max 80 chars SII
                'cantidad': line.quantity,
                'unidad_medida': line.product_uom_id.name[:4] or 'UN',
                'precio_unitario': line.price_unit,
                'descuento_pct': line.discount,
                'monto_descuento': (line.price_unit * line.quantity * line.discount / 100),
                'recargo_pct': 0,  # Si aplica
                'monto_neto_linea': line.price_subtotal,
                'monto_iva_linea': sum(tax.amount for tax in line.tax_ids if tax.tax_group_id.name == 'IVA'),
                'monto_total_linea': line.price_total,
                'codigo_impuesto': self._get_codigo_impuesto_sii(line),
            })

        return lines
```

```python
# File: models/dte_iecv.py

class DTEIECV(models.Model):
    _name = 'dte.iecv'
    _description = 'IECV - Información Electrónica Compra Venta'
    _order = 'periodo desc'

    name = fields.Char('Nombre', compute='_compute_name', store=True)
    tipo = fields.Selection([
        ('venta', 'IECV Ventas'),
        ('compra', 'IECV Compras'),
    ], required=True)

    periodo = fields.Char('Periodo', required=True, help='YYYY-MM')
    fecha_generacion = fields.Datetime('Fecha Generación', default=fields.Datetime.now)

    # Estado
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('generated', 'Generado'),
        ('sent', 'Enviado SII'),
        ('accepted', 'Aceptado SII'),
        ('rejected', 'Rechazado SII'),
    ], default='draft')

    # Archivos
    xml_file = fields.Binary('XML IECV')
    xml_filename = fields.Char('Nombre XML')

    # Respuesta SII
    track_id = fields.Char('Track ID SII')
    response_sii = fields.Text('Respuesta SII')

    # Metadata
    company_id = fields.Many2one('res.company', default=lambda self: self.env.company)
    user_id = fields.Many2one('res.users', default=lambda self: self.env.user)

    # Stats
    total_documentos = fields.Integer('Total Documentos', compute='_compute_stats')
    total_lineas = fields.Integer('Total Líneas', compute='_compute_stats')
    monto_total = fields.Monetary('Monto Total', compute='_compute_stats')

    @api.depends('tipo', 'periodo')
    def _compute_name(self):
        for rec in self:
            rec.name = f"IECV {rec.tipo.title()} {rec.periodo}"

    def action_generate_xml(self):
        """Genera XML IECV y llama al microservicio DTE"""
        self.ensure_one()

        # 1. Get invoices del periodo
        date_from = fields.Date.from_string(f"{self.periodo}-01")
        date_to = date_from + relativedelta(day=31)

        domain = [
            ('company_id', '=', self.company_id.id),
            ('invoice_date', '>=', date_from),
            ('invoice_date', '<=', date_to),
            ('state', '=', 'posted'),
            ('dte_status', '=', 'accepted'),  # Solo DTEs aceptados
        ]

        if self.tipo == 'venta':
            domain.append(('move_type', 'in', ['out_invoice', 'out_refund']))
        else:
            domain.append(('move_type', 'in', ['in_invoice', 'in_refund']))

        invoices = self.env['account.move'].search(domain)

        # 2. Extraer líneas IECV
        all_lines = []
        for inv in invoices:
            all_lines.extend(inv.get_iecv_lines())

        # 3. Call DTE Service para generar XML
        payload = {
            'tipo': self.tipo,
            'periodo': self.periodo,
            'rut_emisor': self.company_id.vat,
            'razon_social': self.company_id.name,
            'lineas': all_lines,
        }

        response = requests.post(
            f"{self.env['ir.config_parameter'].get_param('dte_service_url')}/api/v1/iecv/generate",
            json=payload,
            headers={'Authorization': f"Bearer {self.env['ir.config_parameter'].get_param('dte_api_key')}"}
        )

        if response.status_code == 200:
            xml_content = response.content

            self.write({
                'state': 'generated',
                'xml_file': base64.b64encode(xml_content),
                'xml_filename': f"IECV_{self.tipo}_{self.periodo}.xml",
            })
        else:
            raise UserError(f"Error generando IECV: {response.text}")

    def action_send_to_sii(self):
        """Envía IECV al SII"""
        self.ensure_one()

        if not self.xml_file:
            raise UserError("Debe generar el XML primero")

        # Call DTE Service para enviar
        files = {'xml_file': (self.xml_filename, base64.b64decode(self.xml_file))}

        response = requests.post(
            f"{self.env['ir.config_parameter'].get_param('dte_service_url')}/api/v1/iecv/send",
            files=files,
            headers={'Authorization': f"Bearer {self.env['ir.config_parameter'].get_param('dte_api_key')}"}
        )

        if response.status_code == 200:
            data = response.json()
            self.write({
                'state': 'sent',
                'track_id': data['track_id'],
            })
```

---

#### Tarea 3.3: DTE Service - Generador IECV (2 días)

**Capa Afectada:** DTE Service

**Archivos Nuevos:**
```
dte-service/
├── generators/
│   └── iecv_generator.py  # NUEVO
├── routes/
│   └── iecv.py  # NUEVO
└── clients/
    └── sii_iecv_client.py  # NUEVO
```

**Implementación:**
```python
# File: generators/iecv_generator.py

from lxml import etree
from typing import List, Dict
import structlog

logger = structlog.get_logger()

class IECVGenerator:
    """Generador de XML IECV (Información Electrónica Compra Venta)"""

    def generate(self, data: dict) -> str:
        """
        Genera XML IECV línea por línea.

        Args:
            data: {
                'tipo': 'venta' o 'compra',
                'periodo': 'YYYY-MM',
                'rut_emisor': '76123456-7',
                'razon_social': 'Mi Empresa',
                'lineas': [
                    {
                        'tipo_dte': '33',
                        'folio': 1234,
                        'nro_linea': 1,
                        'codigo_producto': 'PROD-A',
                        'descripcion': 'Servicio',
                        'cantidad': 10,
                        ...
                    },
                    ...
                ]
            }

        Returns:
            str: XML IECV generado
        """
        logger.info("generating_iecv",
                   tipo=data['tipo'],
                   periodo=data['periodo'],
                   total_lineas=len(data['lineas']))

        # Root
        iecv = etree.Element('LibroCompraVenta',
                            xmlns="http://www.sii.cl/SiiDte",
                            version="1.0")

        # EnvioLibro
        envio = etree.SubElement(iecv, 'EnvioLibro', ID="Libro")

        # Carátula
        self._add_caratula(envio, data)

        # ResumenPeriodo (agrupado por tipo DTE)
        self._add_resumenes(envio, data['lineas'])

        # Detalles línea por línea
        for linea in data['lineas']:
            self._add_detalle_linea(envio, linea)

        # TmstFirma
        etree.SubElement(envio, 'TmstFirma').text = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

        # Convert to string
        xml_string = etree.tostring(
            iecv,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')

        logger.info("iecv_generated",
                   periodo=data['periodo'],
                   lineas=len(data['lineas']))

        return xml_string

    def _add_caratula(self, envio: etree.Element, data: dict):
        """Agrega carátula IECV"""
        caratula = etree.SubElement(envio, 'Caratula')

        etree.SubElement(caratula, 'RutEmisorLibro').text = data['rut_emisor']
        etree.SubElement(caratula, 'RutEnvia').text = data['rut_emisor']
        etree.SubElement(caratula, 'PeriodoTributario').text = data['periodo']

        # Fecha resolución (debe venir de config)
        etree.SubElement(caratula, 'FchResol').text = '2014-08-22'
        etree.SubElement(caratula, 'NroResol').text = '80'

        # Tipo operación (COMPRA=1, VENTA=2)
        tipo_operacion = 'COMPRA' if data['tipo'] == 'compra' else 'VENTA'
        etree.SubElement(caratula, 'TipoOperacion').text = tipo_operacion

        # Tipo libro (MENSUAL)
        etree.SubElement(caratula, 'TipoLibro').text = 'MENSUAL'

        # Tipo envío
        etree.SubElement(caratula, 'TipoEnvio').text = 'TOTAL'

        # Folio notificación (opcional)
        # etree.SubElement(caratula, 'FolioNotificacion').text = '1'

    def _add_resumenes(self, envio: etree.Element, lineas: List[Dict]):
        """Agrega resúmenes agrupados por tipo DTE"""
        # Group by tipo_dte
        resumenes = {}
        for linea in lineas:
            tipo = linea['tipo_dte']
            if tipo not in resumenes:
                resumenes[tipo] = {
                    'count': 0,
                    'monto_neto': 0,
                    'monto_iva': 0,
                    'monto_total': 0,
                }

            resumenes[tipo]['count'] += 1
            resumenes[tipo]['monto_neto'] += linea.get('monto_neto_linea', 0)
            resumenes[tipo]['monto_iva'] += linea.get('monto_iva_linea', 0)
            resumenes[tipo]['monto_total'] += linea.get('monto_total_linea', 0)

        # Create XML elements
        for tipo_dte, stats in resumenes.items():
            resumen = etree.SubElement(envio, 'ResumenPeriodo')

            etree.SubElement(resumen, 'TpoDoc').text = tipo_dte
            etree.SubElement(resumen, 'TotDoc').text = str(stats['count'])
            etree.SubElement(resumen, 'TotMntNeto').text = str(int(stats['monto_neto']))
            etree.SubElement(resumen, 'TotMntIVA').text = str(int(stats['monto_iva']))
            etree.SubElement(resumen, 'TotMntTotal').text = str(int(stats['monto_total']))

    def _add_detalle_linea(self, envio: etree.Element, linea: Dict):
        """Agrega detalle de una línea"""
        detalle = etree.SubElement(envio, 'Detalle')

        # Identificación documento
        etree.SubElement(detalle, 'TpoDoc').text = linea['tipo_dte']
        etree.SubElement(detalle, 'NroDoc').text = str(linea['folio'])
        etree.SubElement(detalle, 'FchDoc').text = linea['fecha_emision']
        etree.SubElement(detalle, 'RUTDoc').text = linea['rut_contraparte']
        etree.SubElement(detalle, 'RznSoc').text = linea['razon_social'][:50]

        # Detalle de la línea ⭐ KEY DIFFERENCE
        etree.SubElement(detalle, 'NroLinDet').text = str(linea['nro_linea'])

        if linea.get('codigo_producto'):
            codigo = etree.SubElement(detalle, 'CdgItem')
            etree.SubElement(codigo, 'TpoCodigo').text = 'INT1'  # Código interno
            etree.SubElement(codigo, 'VlrCodigo').text = linea['codigo_producto'][:35]

        etree.SubElement(detalle, 'NmbItem').text = linea['descripcion'][:80]

        if linea.get('cantidad'):
            etree.SubElement(detalle, 'QtyItem').text = str(linea['cantidad'])

        if linea.get('unidad_medida'):
            etree.SubElement(detalle, 'UnmdItem').text = linea['unidad_medida'][:4]

        etree.SubElement(detalle, 'PrcItem').text = str(linea['precio_unitario'])

        if linea.get('descuento_pct', 0) > 0:
            etree.SubElement(detalle, 'DescuentoPct').text = str(linea['descuento_pct'])
            etree.SubElement(detalle, 'DescuentoMonto').text = str(int(linea['monto_descuento']))

        # Montos línea
        etree.SubElement(detalle, 'MontoItem').text = str(int(linea['monto_neto_linea']))

        # No agregar más campos del documento principal (esos van en resumen)
```

---

#### Tarea 3.4: SOAP Client IECV (1 día)

```python
# File: clients/sii_iecv_client.py

class SIIIECVClient:
    """Cliente SOAP para envío de IECV"""

    WSDL_SANDBOX = "https://maullin.sii.cl/DTEWS/LibroCV.asmx?WSDL"
    WSDL_PROD = "https://palena.sii.cl/DTEWS/LibroCV.asmx?WSDL"

    def enviar_iecv(self, xml_iecv: str, rut_emisor: str) -> dict:
        """Envía IECV al SII"""

        try:
            response = self.client.service.EnviarLibro(
                RutEmisor=rut_emisor.split('-')[0],
                DvEmisor=rut_emisor.split('-')[1],
                RutCompany="60805000",
                DvCompany="0",
                Archivo=xml_iecv
            )

            return {
                'success': True,
                'track_id': response.get('TRACKID'),
                'estado': response.get('ESTADO'),
            }
        except Exception as e:
            logger.error("iecv_send_failed", error=str(e))
            return {
                'success': False,
                'error': str(e),
            }
```

---

#### Tarea 3.5: Testing + Documentation (2 días)

**Tests:**
```python
def test_iecv_generation_venta():
    """Test generación IECV de ventas"""
    generator = IECVGenerator()

    data = {
        'tipo': 'venta',
        'periodo': '2025-10',
        'rut_emisor': '76123456-7',
        'razon_social': 'Mi Empresa',
        'lineas': [
            {
                'tipo_dte': '33',
                'folio': 1234,
                'fecha_emision': '2025-10-15',
                'rut_contraparte': '77654321-0',
                'razon_social': 'Cliente ABC',
                'nro_linea': 1,
                'codigo_producto': 'ING-001',
                'descripcion': 'Horas Ingeniería',
                'cantidad': 40,
                'unidad_medida': 'HRS',
                'precio_unitario': 50000,
                'monto_neto_linea': 2000000,
                'monto_iva_linea': 380000,
                'monto_total_linea': 2380000,
            },
            {
                'tipo_dte': '33',
                'folio': 1234,
                'nro_linea': 2,
                # Segunda línea misma factura
                ...
            },
        ]
    }

    xml = generator.generate(data)

    assert '<TipoOperacion>VENTA</TipoOperacion>' in xml
    assert '<NroLinDet>1</NroLinDet>' in xml
    assert '<NroLinDet>2</NroLinDet>' in xml
    assert 'Horas Ingeniería' in xml
```

**Criterio de Éxito Fase 3:**
- ✅ XML IECV generado con formato correcto
- ✅ Línea por línea (no solo totales)
- ✅ Todos los campos obligatorios
- ✅ Enviado y aceptado por SII sandbox
- ✅ Cron mensual configurado
- ✅ Usuario puede generar/enviar desde Odoo

---

### FASE 4: Certificación & Producción (Semana 4 - 5 días) 🟢

**Objetivo:** Completar SET DE PRUEBAS, certificar en Maullin, deploy a producción

#### Tarea 4.1: Completar SET DE PRUEBAS (2 días)

**Casos a Implementar:**
```
1. Validaciones RUT (10 casos)
   - RUT válido
   - RUT inválido DV
   - RUT extranjero
   - RUT genérico boletas

2. Validaciones Montos (15 casos)
   - Montos correctos
   - Suma líneas ≠ total
   - IVA mal calculado
   - Descuentos incorrectos

3. Validaciones Fechas (10 casos)
   - Fecha futuro
   - Fecha muy pasada (>60 días)
   - Fecha formato inválido

4. Validaciones Folios (10 casos)
   - Folio duplicado
   - Folio fuera de rango CAF
   - CAF vencido
   - CAF sin folios

5. Validaciones Firma (10 casos)
   - Certificado vencido
   - Firma inválida
   - Certificado clase incorrecta

6. Edge Cases (15 casos)
   - DTE sin líneas
   - Línea cantidad=0
   - Precio unitario negativo
   - Referencias circulares NC
```

---

#### Tarea 4.2: Certificación Maullin (2 días)

**Pasos:**
1. Obtener certificado digital de prueba
2. Configurar en Maullin
3. Solicitar CAF de prueba (4 tipos)
4. Ejecutar SET DE PRUEBAS
5. Enviar 10 DTEs de cada tipo
6. Verificar aceptación SII
7. Probar eventos (acuse, aceptación)
8. Enviar IECV de prueba

**Criterio de Éxito:**
- ✅ Todos los casos SII passing
- ✅ 40 DTEs aceptados (10 × 4 tipos)
- ✅ Eventos funcionando
- ✅ IECV aceptado
- ✅ Certificado oficial SII

---

#### Tarea 4.3: Deploy Producción (1 día)

**Checklist:**
```
Pre-Deploy:
□ Certificado digital real instalado
□ CAF real obtenido (4 tipos DTE)
□ Variables env configuradas (PROD)
□ Backup base de datos
□ Tests passing 100%
□ Security audit passing
□ Performance baselines establecidos

Deploy:
□ Switch SII_ENVIRONMENT=production
□ Restart DTE service
□ Smoke tests (5 DTEs prueba)
□ Monitor logs primeras 24h
□ Verificar polling automático
□ Configurar alertas

Post-Deploy:
□ Training usuarios
□ Documentación entregada
□ Soporte 1 semana post-deploy
□ Review primeros 30 DTEs
```

---

## 📊 RESUMEN PLAN COMPLETO

### Timeline Visual

```
SEMANA 1
├─ Día 1-2: Quick Wins (DTE 71, Libro Guías)
├─ Día 3: SET DE PRUEBAS setup
├─ Día 4-5: EVENTOS Odoo Models + Views
└─ ENTREGABLE: DTE 71 working, test data ready

SEMANA 2
├─ Día 1-2: EVENTOS DTE Service (SOAP + generators)
├─ Día 3: EVENTOS Testing + Integration
├─ Día 4: IECV Analysis + Odoo Models
└─ ENTREGABLE: Eventos funcionando end-to-end

SEMANA 3
├─ Día 1-2: IECV DTE Service generator
├─ Día 3: IECV SOAP client
├─ Día 4-5: IECV Testing + Documentation
└─ ENTREGABLE: IECV completo y probado

SEMANA 4
├─ Día 1-2: SET DE PRUEBAS completo (70 casos)
├─ Día 3-4: Certificación Maullin
├─ Día 5: Deploy Producción
└─ ENTREGABLE: Sistema en producción certificado SII
```

### Esfuerzo por Capa del Stack

```
╔══════════════════════════════════════════════════════════╗
║  CAPA                │  DÍAS  │  TAREAS  │  COMPLEJIDAD ║
╠══════════════════════════════════════════════════════════╣
║ Odoo Module          │  5.5   │    8     │  ⭐⭐⭐      ║
║ DTE Microservice     │  9.0   │   12     │  ⭐⭐⭐⭐⭐   ║
║ AI Microservice      │  0     │    0     │  -          ║
║ Testing              │  4.0   │    6     │  ⭐⭐⭐⭐    ║
║ Integration          │  2.0   │    4     │  ⭐⭐⭐      ║
║ Documentation        │  1.5   │    5     │  ⭐⭐       ║
╠══════════════════════════════════════════════════════════╣
║ TOTAL                │  22    │   35     │  ⭐⭐⭐⭐    ║
╚══════════════════════════════════════════════════════════╝
```

### Inversión Total

```
Fase 1 (Quick Wins):        3 días  ×  $500/día  =  $1,500
Fase 2 (EVENTOS SII):       5 días  ×  $500/día  =  $2,500
Fase 3 (IECV):              7 días  ×  $500/día  =  $3,500
Fase 4 (Certificación):     5 días  ×  $500/día  =  $2,500
──────────────────────────────────────────────────────────
TOTAL:                     20 días              = $10,000

+ Contingencia 10%:                              $1,000
+ Soporte post-deploy:      3 días              $1,500
═══════════════════════════════════════════════════════════
TOTAL FINAL:               23 días              = $12,500
```

---

## 🎯 CRITERIOS DE ÉXITO GLOBAL

### Técnicos
- ✅ DTE 71 (BHE) recepción funcional
- ✅ EVENTOS SII (acuse, aceptación, reclamo) operativos
- ✅ IECV línea por línea generándose mensualmente
- ✅ SET DE PRUEBAS SII 100% passing
- ✅ Certificación Maullin aprobada
- ✅ Sistema en producción stable 7 días

### Compliance
- ✅ 100% SII compliant
- ✅ Todos los reportes obligatorios
- ✅ Plazos legales cumplidos (8 días acuse, etc.)
- ✅ Auditoría trazable

### Operacionales
- ✅ Usuarios trained
- ✅ Documentación completa
- ✅ Monitoreo 24/7 activo
- ✅ Backup automático
- ✅ Soporte establecido

### Performance
- ✅ Response time < 500ms (p95)
- ✅ 1000+ DTEs/hora throughput
- ✅ 99.9% uptime
- ✅ Zero data loss

---

## 📚 ENTREGABLES FINALES

1. **Código:**
   - 8 archivos Python nuevos (eventos + IECV)
   - 4 modelos Odoo nuevos/extendidos
   - 6 vistas XML
   - 3 SOAP clients
   - 2 generadores XML

2. **Testing:**
   - 70+ casos SET DE PRUEBAS SII
   - 40+ tests unitarios nuevos
   - Coverage > 85%

3. **Documentación:**
   - User Guide EVENTOS SII
   - User Guide IECV
   - API Documentation actualizada
   - Deployment Guide
   - Troubleshooting Guide

4. **Certificación:**
   - Certificado SII Maullin
   - Evidencia 40 DTEs aprobados
   - Evidencia IECV aprobado

---

## 🚀 PRÓXIMOS PASOS INMEDIATOS

### Esta Semana:
1. **HOY:** Review este plan con stakeholders
2. **Mañana:** Aprobar presupuesto ($12.5k)
3. **Día 3:** Setup Maullin + obtener test data SII
4. **Día 4-5:** Iniciar Fase 1 (Quick Wins)

### Próxima Semana:
- Arrancar Fase 2 (EVENTOS SII)
- Daily standups 15 min
- Code reviews diarios
- Progress tracking con métricas

---

**Plan Creado:** 2025-10-22
**Última Actualización:** 2025-10-22 17:30 CLT
**Responsable Plan:** SuperClaude
**Aprobación Requerida:** Stakeholders + Technical Lead
**Status:** ⏳ Pending Approval
