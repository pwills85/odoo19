# 🔌 PATRONES DE INTEGRACIÓN Y EJEMPLOS DE APIs
## Odoo 19 - Arquitectura de 3 Capas

**Fecha:** 2025-10-22
**Versión:** 1.0

---

## 📋 TABLA DE CONTENIDOS

1. [Patrón 1: Odoo → DTE Service](#patrón-1-odoo--dte-service)
2. [Patrón 2: Odoo → AI Service](#patrón-2-odoo--ai-service)
3. [Patrón 3: DTE Service → Odoo (Webhooks)](#patrón-3-dte-service--odoo-webhooks)
4. [Patrón 4: AI Service → Odoo (Webhooks)](#patrón-4-ai-service--odoo-webhooks)
5. [Patrón 5: Async Processing (RabbitMQ)](#patrón-5-async-processing-rabbitmq)
6. [Patrón 6: Caching (Redis)](#patrón-6-caching-redis)
7. [Patrón 7: Error Handling & Retry](#patrón-7-error-handling--retry)
8. [Patrón 8: Authentication & Authorization](#patrón-8-authentication--authorization)

---

## PATRÓN 1: Odoo → DTE Service

### Use Cases
- Generar DTE (XML + firma)
- Enviar DTE a SII
- Consultar estado DTE
- Descargar DTEs recibidos
- Responder comercialmente

---

### 1.1 Generar y Enviar DTE

**Archivo Odoo:** `addons/localization/l10n_cl_dte/models/account_move_dte.py`

```python
from odoo import models, fields, api
import requests
import logging

_logger = logging.getLogger(__name__)

class AccountMoveDTE(models.Model):
    _inherit = 'account.move'

    # DTE-specific fields
    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('34', 'Factura Exenta'),
        ('39', 'Boleta Electrónica'),
        ('41', 'Boleta Exenta'),
        ('52', 'Guía de Despacho'),
        ('56', 'Nota de Débito'),
        ('61', 'Nota de Crédito'),
        ('70', 'Boleta Honorarios Electrónica'),
    ], string='Tipo DTE')

    dte_folio = fields.Integer(string='Folio', readonly=True)
    dte_xml = fields.Text(string='XML DTE', readonly=True)
    dte_status = fields.Selection([
        ('draft', 'Borrador'),
        ('pending', 'Pendiente'),
        ('sent', 'Enviado'),
        ('accepted', 'Aceptado'),
        ('rejected', 'Rechazado'),
        ('error', 'Error'),
    ], default='draft', string='Estado DTE')
    dte_sii_track_id = fields.Char(string='Track ID SII', readonly=True)
    dte_error_message = fields.Text(string='Mensaje de Error', readonly=True)

    @api.model
    def _get_dte_service_url(self):
        """Get DTE Service base URL from system parameters"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_url',
            'http://dte-service:8001'
        )

    @api.model
    def _get_dte_service_api_key(self):
        """Get DTE Service API key"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_api_key'
        )

    def action_generate_and_send_dte(self):
        """Main action: Generate XML, sign, and send to SII"""
        self.ensure_one()

        # 1. Validate invoice data
        self._validate_invoice_for_dte()

        # 2. Get next folio from CAF
        folio = self._get_next_folio()

        # 3. Prepare data for DTE Service
        dte_data = self._prepare_dte_data(folio)

        # 4. Call DTE Service
        try:
            result = self._call_dte_service_generate(dte_data)

            # 5. Update invoice with results
            self.write({
                'dte_folio': folio,
                'dte_xml': result.get('xml_signed'),
                'dte_sii_track_id': result.get('sii_track_id'),
                'dte_status': 'sent' if result.get('sii_accepted') else 'pending',
            })

            # 6. Attach PDF if generated
            if result.get('pdf_content'):
                self._attach_dte_pdf(result['pdf_content'])

            _logger.info(f"DTE {self.dte_type}-{folio} generated successfully")

        except Exception as e:
            _logger.error(f"Error generating DTE: {str(e)}")
            self.write({
                'dte_status': 'error',
                'dte_error_message': str(e),
            })
            raise

    def _prepare_dte_data(self, folio):
        """Prepare data dictionary for DTE Service"""
        return {
            'dte_type': self.dte_type,
            'folio': folio,
            'fecha_emision': self.invoice_date.isoformat(),
            'emisor': {
                'rut': self.company_id.vat,
                'razon_social': self.company_id.name,
                'giro': self.company_id.l10n_cl_activity_description,
                'direccion': self._format_address(self.company_id),
                'comuna': self.company_id.city,
                'ciudad': self.company_id.state_id.name,
            },
            'receptor': {
                'rut': self.partner_id.vat,
                'razon_social': self.partner_id.name,
                'giro': self.partner_id.l10n_cl_activity_description,
                'direccion': self._format_address(self.partner_id),
                'comuna': self.partner_id.city,
                'ciudad': self.partner_id.state_id.name,
            },
            'totales': {
                'monto_neto': self.amount_untaxed,
                'iva': self.amount_tax,
                'monto_total': self.amount_total,
            },
            'items': self._prepare_invoice_lines(),
            'referencias': self._prepare_referencias(),
        }

    def _call_dte_service_generate(self, dte_data):
        """Call DTE Service to generate and send DTE"""
        url = f"{self._get_dte_service_url()}/api/v1/dte/generate"
        headers = {
            'Authorization': f'Bearer {self._get_dte_service_api_key()}',
            'Content-Type': 'application/json',
        }

        response = requests.post(
            url,
            json=dte_data,
            headers=headers,
            timeout=60  # 60 seconds timeout
        )

        if response.status_code != 200:
            raise Exception(f"DTE Service error: {response.text}")

        return response.json()
```

**Archivo DTE Service:** `dte-service/main.py`

```python
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Optional
import logging

app = FastAPI(title="DTE Service", version="1.0.0")
logger = logging.getLogger(__name__)

class DTEItem(BaseModel):
    numero_linea: int
    nombre: str
    cantidad: float
    precio_unitario: float
    monto_total: float

class DTEReceptor(BaseModel):
    rut: str
    razon_social: str
    giro: str
    direccion: str
    comuna: str
    ciudad: str

class DTEEmisor(BaseModel):
    rut: str
    razon_social: str
    giro: str
    direccion: str
    comuna: str
    ciudad: str

class DTETotales(BaseModel):
    monto_neto: float
    iva: float
    monto_total: float

class DTEGenerateRequest(BaseModel):
    dte_type: str
    folio: int
    fecha_emision: str
    emisor: DTEEmisor
    receptor: DTEReceptor
    totales: DTETotales
    items: List[DTEItem]
    referencias: Optional[List[Dict]] = []

class DTEGenerateResponse(BaseModel):
    success: bool
    folio: int
    xml_signed: str
    xml_unsigned: str
    ted: str  # Timbre Electrónico (QR)
    sii_track_id: Optional[str]
    sii_accepted: bool
    pdf_content: Optional[str]  # Base64 encoded
    errors: List[str] = []

@app.post("/api/v1/dte/generate", response_model=DTEGenerateResponse)
async def generate_dte(
    request: DTEGenerateRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Generate DTE: XML generation → Digital signature → SII submission
    """
    try:
        logger.info(f"Generating DTE {request.dte_type}-{request.folio}")

        # 1. Get appropriate generator
        generator = _get_generator(request.dte_type)

        # 2. Generate XML (unsigned)
        xml_unsigned = generator.generate_xml(request)

        # 3. Validate against XSD
        validator = XSDValidator()
        if not validator.validate(xml_unsigned):
            raise HTTPException(400, f"XSD validation failed: {validator.errors}")

        # 4. Sign XML
        signer = XMLDsigSigner()
        xml_signed = signer.sign(xml_unsigned, certificate_id=request.emisor.rut)

        # 5. Generate TED (Timbre Electrónico)
        ted_generator = TEDGenerator()
        ted = ted_generator.generate(request, xml_signed)

        # 6. Send to SII
        sii_client = SIISoapClient()
        sii_result = sii_client.send_dte(xml_signed, request.dte_type)

        # 7. Generate PDF (optional)
        pdf_generator = DTEPDFGenerator()
        pdf_content = pdf_generator.generate(request, xml_signed, ted)

        return DTEGenerateResponse(
            success=True,
            folio=request.folio,
            xml_signed=xml_signed,
            xml_unsigned=xml_unsigned,
            ted=ted,
            sii_track_id=sii_result.get('track_id'),
            sii_accepted=sii_result.get('accepted', False),
            pdf_content=pdf_content,
        )

    except Exception as e:
        logger.error(f"Error generating DTE: {str(e)}")
        raise HTTPException(500, str(e))

def _get_generator(dte_type: str):
    """Factory pattern: get appropriate generator"""
    generators = {
        '33': DTEGenerator33,
        '34': DTEGenerator34,
        '39': DTEGenerator39,
        '41': DTEGenerator41,
        '52': DTEGenerator52,
        '56': DTEGenerator56,
        '61': DTEGenerator61,
        '70': DTEGenerator70,  # BHE (uses AI Service)
    }
    if dte_type not in generators:
        raise ValueError(f"Unsupported DTE type: {dte_type}")
    return generators[dte_type]()
```

---

### 1.2 Consultar Estado DTE

**Archivo Odoo:** `addons/localization/l10n_cl_dte/models/account_move_dte.py`

```python
def action_check_dte_status(self):
    """Check DTE status with SII"""
    self.ensure_one()

    if not self.dte_sii_track_id:
        raise UserError("No hay Track ID del SII para consultar")

    url = f"{self._get_dte_service_url()}/api/v1/dte/status"
    headers = {'Authorization': f'Bearer {self._get_dte_service_api_key()}'}

    response = requests.get(
        url,
        params={
            'track_id': self.dte_sii_track_id,
            'rut_emisor': self.company_id.vat,
            'dte_type': self.dte_type,
            'folio': self.dte_folio,
        },
        headers=headers,
        timeout=30
    )

    if response.status_code == 200:
        result = response.json()
        self.write({
            'dte_status': result['status'],
            'dte_error_message': result.get('error_message'),
        })
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'Estado DTE Actualizado',
                'message': f"Estado: {result['status_display']}",
                'type': 'success',
            }
        }
```

**Archivo DTE Service:** `dte-service/main.py`

```python
@app.get("/api/v1/dte/status")
async def get_dte_status(
    track_id: str,
    rut_emisor: str,
    dte_type: str,
    folio: int,
    current_user: dict = Depends(get_current_user)
):
    """Query DTE status from SII"""
    try:
        sii_client = SIISoapClient()
        result = sii_client.get_estado_dte(
            rut_emisor=rut_emisor,
            tipo_dte=dte_type,
            folio=folio,
            track_id=track_id
        )

        return {
            'status': result['estado'],
            'status_display': result['glosa_estado'],
            'error_message': result.get('error'),
            'fecha_revision': result.get('fecha_revision'),
        }
    except Exception as e:
        logger.error(f"Error checking DTE status: {str(e)}")
        raise HTTPException(500, str(e))
```

---

## PATRÓN 2: Odoo → AI Service

### Use Cases
- Pre-validación de DTE con Claude
- Reconciliación de facturas
- Monitoreo SII
- Chat conversacional
- Forecasting de folios

---

### 2.1 Pre-validación con Claude

**Archivo Odoo:** `addons/localization/l10n_cl_dte/models/account_move_dte.py`

```python
def action_ai_prevalidate(self):
    """Pre-validate invoice with AI before generating DTE"""
    self.ensure_one()

    url = f"{self._get_ai_service_url()}/api/v1/ai/prevalidate"
    headers = {'Authorization': f'Bearer {self._get_ai_service_api_key()}'}

    # Prepare data
    dte_data = self._prepare_dte_data(folio=0)  # Dummy folio for validation

    response = requests.post(
        url,
        json={
            'dte_data': dte_data,
            'company_context': {
                'industry': self.company_id.l10n_cl_activity_description,
                'historical_errors': self._get_recent_errors(),
            }
        },
        headers=headers,
        timeout=30
    )

    if response.status_code == 200:
        result = response.json()

        if result['issues']:
            # Show issues in wizard
            return {
                'type': 'ir.actions.act_window',
                'name': 'Problemas Detectados por IA',
                'res_model': 'dte.ai.validation.wizard',
                'view_mode': 'form',
                'target': 'new',
                'context': {
                    'default_invoice_id': self.id,
                    'default_issues': result['issues'],
                    'default_recommendations': result['recommendations'],
                }
            }
        else:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': '✅ Validación Exitosa',
                    'message': 'La IA no detectó problemas',
                    'type': 'success',
                }
            }

@api.model
def _get_ai_service_url(self):
    return self.env['ir.config_parameter'].sudo().get_param(
        'l10n_cl_dte.ai_service_url',
        'http://ai-service:8002'
    )

@api.model
def _get_ai_service_api_key(self):
    return self.env['ir.config_parameter'].sudo().get_param(
        'l10n_cl_dte.ai_service_api_key'
    )
```

**Archivo AI Service:** `ai-service/main.py`

```python
from anthropic import Anthropic
import os

@app.post("/api/v1/ai/prevalidate")
async def prevalidate_dte(request: PrevalidateRequest):
    """Pre-validate DTE data with Claude AI"""
    try:
        client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

        # Prepare prompt
        prompt = f"""Eres un experto en facturación electrónica chilena (DTE).
Analiza los siguientes datos de DTE y detecta posibles errores o inconsistencias:

Tipo DTE: {request.dte_data['dte_type']}
Emisor: {request.dte_data['emisor']['razon_social']} (RUT: {request.dte_data['emisor']['rut']})
Receptor: {request.dte_data['receptor']['razon_social']} (RUT: {request.dte_data['receptor']['rut']})
Monto Total: ${request.dte_data['totales']['monto_total']:,.0f}

Items:
{_format_items(request.dte_data['items'])}

Contexto de la empresa:
- Industria: {request.company_context['industry']}
- Errores recientes: {request.company_context.get('historical_errors', 'Ninguno')}

Analiza:
1. ¿El RUT del receptor es válido?
2. ¿Los montos son consistentes? (neto + IVA = total)
3. ¿Los items tienen sentido para esta industria?
4. ¿Hay algo inusual o sospechoso?

Responde en formato JSON:
{{
  "is_valid": true/false,
  "issues": ["lista de problemas detectados"],
  "recommendations": ["lista de recomendaciones"],
  "confidence": 0-100
}}
"""

        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        # Parse Claude response
        result = json.loads(response.content[0].text)

        return {
            'is_valid': result['is_valid'],
            'issues': result['issues'],
            'recommendations': result['recommendations'],
            'confidence': result['confidence'],
        }

    except Exception as e:
        logger.error(f"Error in AI prevalidation: {str(e)}")
        raise HTTPException(500, str(e))
```

---

### 2.2 Folio Forecasting

**Archivo Odoo:** `addons/localization/l10n_cl_dte/models/dte_folio_dashboard.py`

```python
class DTEFolioDashboard(models.Model):
    _name = 'dte.folio.dashboard'
    _description = 'Dashboard de Folios con Forecasting'

    @api.model
    def get_folio_forecast(self, dte_type, horizon_days=30):
        """Get folio consumption forecast from AI Service"""
        url = f"{self._get_ai_service_url()}/api/ai/forecast/folios"
        headers = {'Authorization': f'Bearer {self._get_ai_service_api_key()}'}

        # Get historical data
        historical = self._get_historical_folio_usage(dte_type, days=90)

        response = requests.post(
            url,
            json={
                'dte_type': dte_type,
                'historical_data': historical,
                'horizon_days': horizon_days,
                'company_id': self.env.company.id,
            },
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            forecast = response.json()

            # Calculate alert level
            current_folios = self._get_current_folios_remaining(dte_type)
            predicted_usage = forecast['predicted_usage']

            if current_folios < predicted_usage:
                self._create_folio_alert(dte_type, current_folios, predicted_usage)

            return forecast

    def _get_historical_folio_usage(self, dte_type, days=90):
        """Get historical folio consumption"""
        date_from = fields.Date.today() - timedelta(days=days)

        invoices = self.env['account.move'].search([
            ('dte_type', '=', dte_type),
            ('invoice_date', '>=', date_from),
            ('dte_status', '!=', 'draft'),
        ], order='invoice_date asc')

        # Group by date
        data = {}
        for invoice in invoices:
            date_key = invoice.invoice_date.isoformat()
            data[date_key] = data.get(date_key, 0) + 1

        return data
```

**Archivo AI Service:** `ai-service/forecasting/folio_forecaster.py`

```python
from sklearn.linear_model import LinearRegression
from sklearn.ensemble import RandomForestRegressor
import numpy as np
import pandas as pd

class FolioForecaster:
    """ML-based folio consumption forecaster"""

    def __init__(self):
        self.model = RandomForestRegressor(n_estimators=100, random_state=42)

    def forecast(self, historical_data: dict, horizon_days: int = 30):
        """Predict folio consumption for next N days"""

        # Convert to DataFrame
        df = pd.DataFrame([
            {'date': k, 'count': v}
            for k, v in historical_data.items()
        ])
        df['date'] = pd.to_datetime(df['date'])
        df = df.sort_values('date')

        # Feature engineering
        df['day_of_week'] = df['date'].dt.dayofweek
        df['day_of_month'] = df['date'].dt.day
        df['month'] = df['date'].dt.month
        df['is_month_end'] = df['day_of_month'] > 25

        # Train model
        X = df[['day_of_week', 'day_of_month', 'month', 'is_month_end']]
        y = df['count']
        self.model.fit(X, y)

        # Predict future
        future_dates = pd.date_range(
            start=df['date'].max() + pd.Timedelta(days=1),
            periods=horizon_days
        )

        future_df = pd.DataFrame({
            'date': future_dates,
            'day_of_week': future_dates.dayofweek,
            'day_of_month': future_dates.day,
            'month': future_dates.month,
            'is_month_end': future_dates.day > 25,
        })

        predictions = self.model.predict(
            future_df[['day_of_week', 'day_of_month', 'month', 'is_month_end']]
        )

        # Calculate confidence intervals (simple approach)
        std = np.std(predictions)

        return {
            'predicted_usage': int(np.sum(predictions)),
            'daily_predictions': [
                {
                    'date': date.isoformat(),
                    'predicted_count': int(pred),
                    'confidence_low': max(0, int(pred - std)),
                    'confidence_high': int(pred + std),
                }
                for date, pred in zip(future_dates, predictions)
            ],
            'avg_daily': float(np.mean(predictions)),
            'peak_day': future_dates[np.argmax(predictions)].isoformat(),
            'model_accuracy': float(self.model.score(X, y)),
        }

@app.post("/api/ai/forecast/folios")
async def forecast_folios(request: FolioForecastRequest):
    """Forecast folio consumption"""
    try:
        forecaster = FolioForecaster()
        forecast = forecaster.forecast(
            request.historical_data,
            request.horizon_days
        )
        return forecast
    except Exception as e:
        logger.error(f"Forecasting error: {str(e)}")
        raise HTTPException(500, str(e))
```

---

## PATRÓN 3: DTE Service → Odoo (Webhooks)

### Use Cases
- Notificar cambio de estado DTE
- Notificar DTE recibido
- Notificar error crítico

---

### 3.1 Webhook de Cambio de Estado

**Archivo DTE Service:** `dte-service/scheduler/dte_status_poller.py`

```python
class DTEStatusPoller:
    """Polls SII for DTE status changes and notifies Odoo via webhook"""

    def __init__(self):
        self.sii_client = SIISoapClient()
        self.redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)
        self.odoo_webhook_url = os.getenv('ODOO_WEBHOOK_URL', 'http://odoo:8069/dte/webhook/status_update')

    async def poll_pending_dtes(self):
        """Poll SII for all pending DTEs"""
        # Get pending DTEs from Redis
        pending_keys = self.redis_client.keys('dte:pending:*')

        for key in pending_keys:
            dte_info = json.loads(self.redis_client.get(key))

            try:
                # Query SII
                status = self.sii_client.get_estado_dte(
                    rut_emisor=dte_info['rut_emisor'],
                    tipo_dte=dte_info['dte_type'],
                    folio=dte_info['folio'],
                    track_id=dte_info['track_id']
                )

                # If status changed, notify Odoo
                if status['estado'] != dte_info.get('last_status'):
                    await self._notify_odoo_status_change(dte_info, status)

                    # Update Redis
                    dte_info['last_status'] = status['estado']
                    self.redis_client.set(key, json.dumps(dte_info))

                    # If accepted/rejected, remove from pending
                    if status['estado'] in ['accepted', 'rejected']:
                        self.redis_client.delete(key)

            except Exception as e:
                logger.error(f"Error polling DTE {key}: {str(e)}")

    async def _notify_odoo_status_change(self, dte_info, status):
        """Send webhook to Odoo"""
        payload = {
            'event': 'dte_status_changed',
            'dte_type': dte_info['dte_type'],
            'folio': dte_info['folio'],
            'track_id': dte_info['track_id'],
            'old_status': dte_info.get('last_status'),
            'new_status': status['estado'],
            'status_display': status['glosa_estado'],
            'timestamp': datetime.utcnow().isoformat(),
        }

        try:
            response = requests.post(
                self.odoo_webhook_url,
                json=payload,
                headers={'X-DTE-Service-Token': os.getenv('DTE_SERVICE_TOKEN')},
                timeout=10
            )

            if response.status_code != 200:
                logger.warning(f"Webhook failed: {response.text}")
        except Exception as e:
            logger.error(f"Webhook error: {str(e)}")
```

**Archivo Odoo:** `addons/localization/l10n_cl_dte/controllers/webhook_controller.py`

```python
from odoo import http
from odoo.http import request
import logging
import hmac
import hashlib

_logger = logging.getLogger(__name__)

class DTEWebhookController(http.Controller):

    @http.route('/dte/webhook/status_update', type='json', auth='none', methods=['POST'], csrf=False)
    def webhook_status_update(self, **kwargs):
        """Receive DTE status updates from DTE Service"""

        # 1. Validate token
        token = request.httprequest.headers.get('X-DTE-Service-Token')
        expected_token = request.env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.dte_service_token')

        if not hmac.compare_digest(token or '', expected_token or ''):
            _logger.warning("Invalid webhook token")
            return {'error': 'Unauthorized'}, 401

        # 2. Parse payload
        payload = request.jsonrequest

        _logger.info(f"Webhook received: {payload['event']} for DTE {payload['dte_type']}-{payload['folio']}")

        # 3. Find invoice
        invoice = request.env['account.move'].sudo().search([
            ('dte_type', '=', payload['dte_type']),
            ('dte_folio', '=', payload['folio']),
            ('dte_sii_track_id', '=', payload['track_id']),
        ], limit=1)

        if not invoice:
            _logger.warning(f"Invoice not found for DTE {payload['dte_type']}-{payload['folio']}")
            return {'error': 'Invoice not found'}, 404

        # 4. Update status
        invoice.write({
            'dte_status': payload['new_status'],
        })

        # 5. Trigger post-actions
        if payload['new_status'] == 'accepted':
            invoice._on_dte_accepted()
        elif payload['new_status'] == 'rejected':
            invoice._on_dte_rejected()

        return {'success': True}
```

---

## PATRÓN 4: AI Service → Odoo (Webhooks)

### 4.1 Notificación de Cambios SII

**Archivo AI Service:** `ai-service/sii_monitor/notifier.py`

```python
class SIIChangeNotifier:
    """Notify Odoo of SII regulatory changes"""

    def __init__(self):
        self.odoo_webhook_url = os.getenv('ODOO_WEBHOOK_URL', 'http://odoo:8069/dte/webhook/sii_change')

    async def notify_change(self, change: dict):
        """Send change notification to Odoo"""
        payload = {
            'event': 'sii_regulatory_change',
            'tipo': change['tipo'],
            'numero': change['numero'],
            'fecha': change['fecha'],
            'vigencia': change['vigencia'],
            'titulo': change['titulo'],
            'resumen': change['resumen'],
            'impacto': change['impacto'],
            'prioridad': change['prioridad'],
            'url': change['url'],
            'timestamp': datetime.utcnow().isoformat(),
        }

        try:
            response = requests.post(
                self.odoo_webhook_url,
                json=payload,
                headers={'X-AI-Service-Token': os.getenv('AI_SERVICE_TOKEN')},
                timeout=10
            )

            if response.status_code != 200:
                logger.warning(f"Odoo webhook failed: {response.text}")
        except Exception as e:
            logger.error(f"Webhook error: {str(e)}")
```

**Archivo Odoo:** `addons/localization/l10n_cl_dte/controllers/webhook_controller.py`

```python
@http.route('/dte/webhook/sii_change', type='json', auth='none', methods=['POST'], csrf=False)
def webhook_sii_change(self, **kwargs):
    """Receive SII regulatory change notifications"""

    # Validate token
    token = request.httprequest.headers.get('X-AI-Service-Token')
    expected_token = request.env['ir.config_parameter'].sudo().get_param('l10n_cl_dte.ai_service_token')

    if not hmac.compare_digest(token or '', expected_token or ''):
        return {'error': 'Unauthorized'}, 401

    payload = request.jsonrequest

    # Create SII news record
    news = request.env['dte.sii.news'].sudo().create({
        'tipo': payload['tipo'],
        'numero': payload['numero'],
        'fecha': payload['fecha'],
        'vigencia': payload['vigencia'],
        'titulo': payload['titulo'],
        'resumen': payload['resumen'],
        'impacto': payload['impacto'],
        'prioridad': payload['prioridad'],
        'url': payload['url'],
        'state': 'new',
    })

    # Send notification to admins
    if payload['prioridad'] >= 8:
        admins = request.env.ref('l10n_cl_dte.group_dte_admin').users
        news.message_post(
            body=f"⚠️ Cambio SII de alta prioridad: {payload['titulo']}",
            subject='Alerta SII',
            partner_ids=admins.mapped('partner_id').ids,
            subtype_xmlid='mail.mt_comment',
        )

    return {'success': True, 'news_id': news.id}
```

---

## PATRÓN 5: Async Processing (RabbitMQ)

### Use Cases
- Procesamiento masivo de DTEs
- Jobs de larga duración
- Desacoplar procesamiento

---

### 5.1 Queue de DTEs Masivos

**Archivo Odoo:** `addons/localization/l10n_cl_dte/wizards/dte_batch_wizard.py`

```python
class DTEBatchWizard(models.TransientModel):
    _name = 'dte.batch.wizard'
    _description = 'Wizard para Envío Masivo de DTEs'

    invoice_ids = fields.Many2many('account.move', string='Facturas')

    def action_send_batch(self):
        """Send batch of DTEs to queue"""
        # Publish to RabbitMQ
        channel = self._get_rabbitmq_channel()

        for invoice in self.invoice_ids:
            message = {
                'invoice_id': invoice.id,
                'dte_type': invoice.dte_type,
                'company_id': invoice.company_id.id,
            }

            channel.basic_publish(
                exchange='dte_exchange',
                routing_key='dte.generate',
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Persistent
                    content_type='application/json',
                )
            )

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'DTEs en Cola',
                'message': f'{len(self.invoice_ids)} DTEs agregados a la cola de procesamiento',
                'type': 'success',
            }
        }

    def _get_rabbitmq_channel(self):
        """Get RabbitMQ connection and channel"""
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=os.getenv('RABBITMQ_HOST', 'rabbitmq'),
                port=int(os.getenv('RABBITMQ_PORT', 5672)),
                credentials=pika.PlainCredentials('guest', 'guest')
            )
        )
        channel = connection.channel()
        channel.queue_declare(queue='dte_generate_queue', durable=True)
        return channel
```

**Archivo DTE Service:** `dte-service/queue/dte_consumer.py`

```python
import pika
import json

class DTEQueueConsumer:
    """Consume DTEs from RabbitMQ queue"""

    def __init__(self):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='rabbitmq', port=5672)
        )
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue='dte_generate_queue', durable=True)
        self.channel.basic_qos(prefetch_count=1)  # Process one at a time

    def start_consuming(self):
        """Start consuming messages"""
        self.channel.basic_consume(
            queue='dte_generate_queue',
            on_message_callback=self.process_dte,
            auto_ack=False
        )

        print("Started consuming DTE queue...")
        self.channel.start_consuming()

    def process_dte(self, ch, method, properties, body):
        """Process a single DTE from queue"""
        try:
            message = json.loads(body)
            print(f"Processing DTE for invoice {message['invoice_id']}")

            # Generate DTE
            # (Logic similar to /api/v1/dte/generate endpoint)

            # Acknowledge message
            ch.basic_ack(delivery_tag=method.delivery_tag)

        except Exception as e:
            print(f"Error processing DTE: {str(e)}")
            # Reject and requeue
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

# Run consumer
if __name__ == '__main__':
    consumer = DTEQueueConsumer()
    consumer.start_consuming()
```

---

## PATRÓN 6: Caching (Redis)

### 6.1 Cache de Validaciones

**Archivo DTE Service:** `dte-service/cache/validation_cache.py`

```python
import redis
import hashlib
import json

class ValidationCache:
    """Cache validation results in Redis"""

    def __init__(self):
        self.redis = redis.Redis(
            host='redis',
            port=6379,
            decode_responses=True
        )
        self.ttl = 3600  # 1 hour

    def get_rut_validation(self, rut: str):
        """Get cached RUT validation"""
        key = f"rut:validation:{rut}"
        cached = self.redis.get(key)
        if cached:
            return json.loads(cached)
        return None

    def set_rut_validation(self, rut: str, is_valid: bool):
        """Cache RUT validation result"""
        key = f"rut:validation:{rut}"
        value = {'is_valid': is_valid, 'timestamp': datetime.utcnow().isoformat()}
        self.redis.setex(key, self.ttl, json.dumps(value))

    def get_xsd_validation(self, xml_hash: str):
        """Get cached XSD validation"""
        key = f"xsd:validation:{xml_hash}"
        cached = self.redis.get(key)
        if cached:
            return json.loads(cached)
        return None

    def set_xsd_validation(self, xml_content: str, is_valid: bool, errors: list = None):
        """Cache XSD validation result"""
        xml_hash = hashlib.sha256(xml_content.encode()).hexdigest()
        key = f"xsd:validation:{xml_hash}"
        value = {
            'is_valid': is_valid,
            'errors': errors or [],
            'timestamp': datetime.utcnow().isoformat()
        }
        self.redis.setex(key, self.ttl, json.dumps(value))

# Usage in validator
class RUTValidator:
    def __init__(self):
        self.cache = ValidationCache()

    def validate(self, rut: str) -> bool:
        # Check cache first
        cached = self.cache.get_rut_validation(rut)
        if cached:
            return cached['is_valid']

        # Validate
        is_valid = self._validate_rut_algorithm(rut)

        # Cache result
        self.cache.set_rut_validation(rut, is_valid)

        return is_valid
```

---

## PATRÓN 7: Error Handling & Retry

### 7.1 Exponential Backoff Retry

**Archivo DTE Service:** `dte-service/clients/sii_soap_client.py`

```python
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

class SIISoapClient:
    """SII SOAP client with retry logic"""

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=60),
        retry=retry_if_exception_type((Timeout, ConnectionError)),
        reraise=True
    )
    def send_dte(self, xml_signed: str, dte_type: str):
        """Send DTE to SII with automatic retry"""
        try:
            response = self.client.service.RecepcionDTE(
                rutEmisor=self.extract_rut(xml_signed),
                dvEmisor=self.extract_dv(xml_signed),
                rutEnvia=self.rut_envia,
                xmlDTE=xml_signed
            )

            return self._parse_response(response)

        except Timeout as e:
            logger.warning(f"SII timeout, will retry: {str(e)}")
            raise
        except ConnectionError as e:
            logger.warning(f"SII connection error, will retry: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"SII error (won't retry): {str(e)}")
            raise
```

---

## PATRÓN 8: Authentication & Authorization

### 8.1 OAuth2 + RBAC

**Archivo DTE Service:** `dte-service/auth/dependencies.py`

```python
from fastapi import Depends, HTTPException, Header
from auth import verify_token, check_permission, Permission

async def get_current_user(authorization: str = Header(...)):
    """Extract and verify JWT token"""
    try:
        if not authorization.startswith('Bearer '):
            raise HTTPException(401, "Invalid authorization header")

        token = authorization.split(' ')[1]
        user = verify_token(token)

        if not user:
            raise HTTPException(401, "Invalid token")

        return user
    except Exception as e:
        raise HTTPException(401, str(e))

def require_permission(permission: Permission):
    """Dependency to check user has permission"""
    async def check(user: dict = Depends(get_current_user)):
        if not check_permission(user, permission):
            raise HTTPException(
                403,
                f"Permission denied: {permission.value}"
            )
        return user
    return check

# Usage in endpoints
@app.post("/api/v1/dte/generate")
async def generate_dte(
    request: DTEGenerateRequest,
    user: dict = Depends(require_permission(Permission.DTE_GENERATE))
):
    # User has DTE_GENERATE permission
    ...
```

---

## 📚 RESUMEN DE ENDPOINTS

### DTE Service (Port 8001)

```
POST   /api/v1/dte/generate              Generate and send DTE
GET    /api/v1/dte/status                Check DTE status
POST   /api/v1/dte/check_inbox           Check received DTEs
POST   /api/v1/dte/send_response         Send commercial response
POST   /api/v1/dte/recovery/resend       Resend failed DTE
GET    /api/v1/dte/caf/status            Check CAF status
POST   /api/v1/dte/certificate/upload    Upload certificate
GET    /health                           Health check
```

### AI Service (Port 8002)

```
POST   /api/v1/ai/prevalidate            Pre-validate DTE
POST   /api/v1/ai/reconcile              Reconcile invoices
POST   /api/ai/sii/monitor               Trigger SII monitoring
GET    /api/ai/sii/status                Get monitoring status
POST   /api/ai/forecast/folios           Forecast folio usage
POST   /api/ai/sii/chat                  Chat with Claude
GET    /health                           Health check
```

### Odoo Webhooks

```
POST   /dte/webhook/status_update        Receive DTE status updates
POST   /dte/webhook/sii_change           Receive SII change notifications
POST   /dte/webhook/error_alert          Receive error alerts
```

---

**Documento creado:** 2025-10-22
**Versión:** 1.0
**Estado:** ✅ Completo

Este documento contiene todos los patrones de integración y ejemplos de código necesarios para implementar la arquitectura de 3 capas.
