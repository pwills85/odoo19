# 🔗 AI Microservice - Integraciones con Odoo 19

**Documento:** 05 de 06  
**Fecha:** 2025-10-25  
**Audiencia:** Desarrolladores Odoo, Integradores

---

## 🎯 Visión General de Integraciones

El AI Microservice se integra con Odoo 19 a través de **HTTP/JSON APIs** desde múltiples módulos. La arquitectura es **loosely coupled** para permitir evolución independiente.

### Principios de Integración

1. **Asíncrono cuando posible** - No bloquear UI de Odoo
2. **Graceful degradation** - Odoo funciona sin AI service
3. **Timeout cortos** - Max 30s por request
4. **Retry logic** - 3 intentos con exponential backoff
5. **Error handling** - Logs detallados, no crashes

---

## 📦 Módulo 1: l10n_cl_dte (Facturación Electrónica)

### Integración: Pre-validación DTE

**Archivo Odoo:** `addons/localization/l10n_cl_dte/models/account_move.py`

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    def action_post(self):
        """Override para agregar validación IA antes de enviar al SII"""
        
        # 1. Validación tradicional (Odoo nativo)
        super().action_post()
        
        # 2. Si es DTE, validar con IA (opcional pero recomendado)
        if self.l10n_latam_document_type_id.code in ['33', '34', '52', '56', '61']:
            ai_result = self._validate_with_ai()
            
            if ai_result['recommendation'] == 'reject':
                # Bloquear envío
                raise UserError(
                    f"IA detectó errores críticos:\n" +
                    "\n".join(ai_result['errors'])
                )
            elif ai_result['recommendation'] == 'review':
                # Mostrar warning (usuario decide)
                return {
                    'type': 'ir.actions.client',
                    'tag': 'display_notification',
                    'params': {
                        'title': 'Advertencia IA',
                        'message': '\n'.join(ai_result['warnings']),
                        'type': 'warning',
                        'sticky': True
                    }
                }
        
        # 3. Continuar con envío al SII
        return self._send_to_sii()
    
    def _validate_with_ai(self):
        """Llamar AI service para validación"""
        import requests
        from odoo import http
        
        # Preparar datos
        dte_data = {
            'tipo_dte': self.l10n_latam_document_type_id.code,
            'folio': self.l10n_cl_sii_folio,
            'rut_emisor': self.company_id.vat,
            'rut_receptor': self.partner_id.vat,
            'fecha_emision': self.invoice_date.isoformat(),
            'monto_total': self.amount_total,
            'monto_neto': self.amount_untaxed,
            'monto_iva': self.amount_tax,
            'lineas': [
                {
                    'nombre': line.name,
                    'cantidad': line.quantity,
                    'precio_unitario': line.price_unit,
                    'monto': line.price_subtotal
                }
                for line in self.invoice_line_ids
            ]
        }
        
        # Obtener historial de rechazos (últimos 5)
        history = self._get_rejection_history()
        
        try:
            # Llamar AI service
            response = requests.post(
                'http://ai-service:8002/api/ai/validate',
                json={
                    'dte_data': dte_data,
                    'company_id': self.company_id.id,
                    'history': history
                },
                headers={
                    'Authorization': f'Bearer {self.env["ir.config_parameter"].sudo().get_param("ai_service.api_key")}',
                    'Content-Type': 'application/json'
                },
                timeout=10  # 10s timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                _logger.warning(f"AI validation failed: {response.status_code}")
                return self._default_validation_result()
                
        except requests.exceptions.Timeout:
            _logger.warning("AI service timeout")
            return self._default_validation_result()
        except Exception as e:
            _logger.error(f"AI validation error: {e}")
            return self._default_validation_result()
    
    def _default_validation_result(self):
        """Resultado por defecto si AI service no disponible"""
        return {
            'confidence': 50.0,
            'warnings': ['AI service no disponible'],
            'errors': [],
            'recommendation': 'send'  # No bloquear flujo
        }
    
    def _get_rejection_history(self):
        """Obtener últimos rechazos SII de esta compañía"""
        rejections = self.search([
            ('company_id', '=', self.company_id.id),
            ('l10n_cl_sii_status', '=', 'rejected'),
            ('invoice_date', '>=', fields.Date.today() - timedelta(days=90))
        ], limit=5, order='invoice_date desc')
        
        return [
            {
                'error_code': r.l10n_cl_sii_error_code,
                'message': r.l10n_cl_sii_error_message,
                'date': r.invoice_date.isoformat()
            }
            for r in rejections
        ]
```

### Configuración en Odoo

```python
# Settings > Technical > System Parameters
ir.config_parameter:
    - key: ai_service.api_key
      value: <API_KEY_FROM_ENV>
    
    - key: ai_service.url
      value: http://ai-service:8002
    
    - key: ai_service.enabled
      value: True
```

### UI: Botón de Validación Manual

```xml
<!-- views/account_move_views.xml -->
<record id="view_move_form_inherit_ai" model="ir.ui.view">
    <field name="name">account.move.form.inherit.ai</field>
    <field name="model">account.move</field>
    <field name="inherit_id" ref="l10n_cl_dte.view_move_form"/>
    <field name="arch" type="xml">
        <button name="action_post" position="before">
            <button name="action_validate_with_ai"
                    string="🤖 Validar con IA"
                    type="object"
                    class="btn-secondary"
                    attrs="{'invisible': [('state', '!=', 'draft')]}"/>
        </button>
    </field>
</record>
```

---

## 💰 Módulo 2: l10n_cl_hr_payroll (Nóminas)

### Integración: Validación de Liquidaciones

**Archivo Odoo:** `addons/localization/l10n_cl_hr_payroll/models/hr_payslip.py`

```python
class HrPayslip(models.Model):
    _inherit = 'hr.payslip'
    
    ai_validation_result = fields.Text('Resultado Validación IA', readonly=True)
    ai_confidence = fields.Float('Confianza IA (%)', readonly=True)
    ai_recommendation = fields.Selection([
        ('approve', 'Aprobar'),
        ('review', 'Revisar'),
        ('reject', 'Rechazar')
    ], string='Recomendación IA', readonly=True)
    
    def action_validate_with_ai(self):
        """Validar liquidación con IA"""
        self.ensure_one()
        
        # Preparar datos
        payslip_data = {
            'employee_id': self.employee_id.id,
            'period': f"{self.date_from.year}-{self.date_from.month:02d}",
            'wage': self.contract_id.wage,
            'lines': [
                {
                    'code': line.code,
                    'name': line.name,
                    'amount': line.total
                }
                for line in self.line_ids
            ]
        }
        
        try:
            response = requests.post(
                f"{self._get_ai_service_url()}/api/payroll/validate",
                json=payslip_data,
                headers=self._get_ai_headers(),
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Guardar resultado
                self.write({
                    'ai_validation_result': json.dumps(result, indent=2),
                    'ai_confidence': result['confidence'],
                    'ai_recommendation': result['recommendation']
                })
                
                # Mostrar notificación
                if result['errors']:
                    return self._show_validation_errors(result)
                elif result['warnings']:
                    return self._show_validation_warnings(result)
                else:
                    return self._show_validation_success(result)
            
        except Exception as e:
            _logger.error(f"AI payroll validation error: {e}")
            raise UserError(f"Error validando con IA: {str(e)}")
    
    def _show_validation_errors(self, result):
        """Mostrar errores críticos"""
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': '❌ Errores Detectados',
                'message': '<br/>'.join([
                    '<strong>Errores:</strong>',
                    *[f"• {e}" for e in result['errors']],
                    '',
                    f"<em>Confianza: {result['confidence']:.1f}%</em>"
                ]),
                'type': 'danger',
                'sticky': True
            }
        }
```

### Cron: Actualización Indicadores Previred

```python
# models/hr_previred_indicators.py
class HrPreviredIndicators(models.Model):
    _name = 'hr.previred.indicators'
    _description = 'Indicadores Previred'
    
    period = fields.Char('Período', required=True)  # YYYY-MM
    uf_value = fields.Float('Valor UF')
    utm_value = fields.Float('Valor UTM')
    minimum_wage = fields.Float('Sueldo Mínimo')
    # ... 60 campos más
    
    @api.model
    def _cron_update_indicators(self):
        """Cron que ejecuta mensualmente (día 1)"""
        import requests
        from datetime import date
        
        period = date.today().strftime('%Y-%m')
        
        try:
            response = requests.get(
                f"{self._get_ai_service_url()}/api/payroll/indicators/{period}",
                headers=self._get_ai_headers(),
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                indicators = data['indicators']
                
                # Crear o actualizar registro
                existing = self.search([('period', '=', period)])
                if existing:
                    existing.write(indicators)
                else:
                    self.create({
                        'period': period,
                        **indicators
                    })
                
                _logger.info(f"Previred indicators updated for {period}")
            
        except Exception as e:
            _logger.error(f"Failed to update Previred indicators: {e}")
```

```xml
<!-- data/ir_cron.xml -->
<record id="cron_update_previred_indicators" model="ir.cron">
    <field name="name">Update Previred Indicators</field>
    <field name="model_id" ref="model_hr_previred_indicators"/>
    <field name="state">code</field>
    <field name="code">model._cron_update_indicators()</field>
    <field name="interval_number">1</field>
    <field name="interval_type">months</field>
    <field name="numbercall">-1</field>
    <field name="doall" eval="False"/>
    <field name="nextcall" eval="(DateTime.now() + timedelta(days=1)).replace(day=1, hour=2, minute=0)"/>
</record>
```

---

## 💬 Módulo 3: Chat Widget (Transversal)

### Integración: Widget JavaScript

**Archivo:** `addons/custom/ai_chat/static/src/js/chat_widget.js`

```javascript
odoo.define('ai_chat.Widget', function (require) {
    'use strict';
    
    const AbstractAction = require('web.AbstractAction');
    const core = require('web.core');
    
    const AIChatWidget = AbstractAction.extend({
        template: 'AIChatWidget',
        
        events: {
            'click .send-message': '_onSendMessage',
            'keypress .message-input': '_onKeyPress'
        },
        
        init: function (parent, action) {
            this._super.apply(this, arguments);
            this.sessionId = this._generateSessionId();
            this.messages = [];
        },
        
        _onSendMessage: async function () {
            const input = this.$('.message-input');
            const message = input.val().trim();
            
            if (!message) return;
            
            // Agregar mensaje del usuario al chat
            this._addMessage('user', message);
            input.val('');
            
            // Llamar AI service (streaming)
            await this._streamAIResponse(message);
        },
        
        _streamAIResponse: async function (message) {
            // Crear bubble para respuesta IA
            const aiMessageId = this._addMessage('assistant', '');
            const aiMessageEl = this.$(`#message-${aiMessageId} .message-content`);
            
            try {
                // Server-Sent Events (SSE)
                const eventSource = new EventSource(
                    `/ai_chat/stream?` +
                    `session_id=${this.sessionId}&` +
                    `message=${encodeURIComponent(message)}`
                );
                
                eventSource.onmessage = (event) => {
                    const chunk = JSON.parse(event.data);
                    
                    if (chunk.type === 'text') {
                        // Append text en tiempo real
                        aiMessageEl.text(aiMessageEl.text() + chunk.content);
                        this._scrollToBottom();
                    } else if (chunk.type === 'done') {
                        // Mostrar metadata
                        this._showMetadata(aiMessageId, chunk.metadata);
                        eventSource.close();
                    } else if (chunk.type === 'error') {
                        aiMessageEl.text('Error: ' + chunk.content);
                        eventSource.close();
                    }
                };
                
                eventSource.onerror = () => {
                    aiMessageEl.text('Error de conexión con AI service');
                    eventSource.close();
                };
                
            } catch (error) {
                console.error('AI chat error:', error);
                aiMessageEl.text('Error: ' + error.message);
            }
        },
        
        _addMessage: function (role, content) {
            const messageId = `msg-${Date.now()}`;
            this.messages.push({id: messageId, role, content});
            
            const $message = $(QWeb.render('AIChatMessage', {
                id: messageId,
                role: role,
                content: content
            }));
            
            this.$('.messages-container').append($message);
            this._scrollToBottom();
            
            return messageId;
        },
        
        _generateSessionId: function () {
            return 'session-' + Math.random().toString(36).substr(2, 9);
        }
    });
    
    core.action_registry.add('ai_chat_widget', AIChatWidget);
    
    return AIChatWidget;
});
```

### Controller Odoo (Proxy)

```python
# controllers/main.py
from odoo import http
from odoo.http import request
import requests

class AIChatController(http.Controller):
    
    @http.route('/ai_chat/stream', type='http', auth='user')
    def stream_chat(self, session_id, message):
        """Proxy streaming desde AI service"""
        
        # Obtener contexto del usuario
        user_context = {
            'company_name': request.env.company.name,
            'company_rut': request.env.company.vat,
            'user_role': request.env.user.name,
            'environment': 'production' if request.env['ir.config_parameter'].sudo().get_param('sii.environment') == 'production' else 'sandbox'
        }
        
        # Llamar AI service (streaming)
        ai_url = request.env['ir.config_parameter'].sudo().get_param('ai_service.url')
        ai_key = request.env['ir.config_parameter'].sudo().get_param('ai_service.api_key')
        
        response = requests.post(
            f"{ai_url}/api/chat/message/stream",
            json={
                'session_id': session_id,
                'message': message,
                'user_context': user_context
            },
            headers={
                'Authorization': f'Bearer {ai_key}',
                'Content-Type': 'application/json'
            },
            stream=True  # ✅ Streaming
        )
        
        # Proxy streaming response
        def generate():
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    yield chunk
        
        return request.make_response(
            generate(),
            headers=[
                ('Content-Type', 'text/event-stream'),
                ('Cache-Control', 'no-cache'),
                ('X-Accel-Buffering', 'no')
            ]
        )
```

---

## 📊 Módulo 4: Analytics (Project Matching)

### Integración: Asignación Automática de Gastos

**Archivo:** `addons/custom/project_analytics/models/account_move.py`

```python
class AccountMove(models.Model):
    _inherit = 'account.move'
    
    suggested_project_id = fields.Many2one('project.project', 'Proyecto Sugerido (IA)')
    ai_match_confidence = fields.Float('Confianza Match (%)')
    ai_match_reasoning = fields.Text('Razonamiento IA')
    
    @api.onchange('ref', 'narration')
    def _onchange_suggest_project(self):
        """Auto-sugerir proyecto basado en descripción"""
        if not (self.ref or self.narration):
            return
        
        description = f"{self.ref or ''} {self.narration or ''}".strip()
        
        # Obtener proyectos activos
        projects = self.env['project.project'].search([
            ('active', '=', True),
            ('company_id', '=', self.company_id.id)
        ])
        
        if not projects:
            return
        
        # Llamar AI service
        try:
            result = self._match_project_with_ai(description, projects)
            
            if result['matched_project_id'] and result['confidence'] >= 70.0:
                self.suggested_project_id = result['matched_project_id']
                self.ai_match_confidence = result['confidence']
                self.ai_match_reasoning = result['reasoning']
                
                # Mostrar notificación
                return {
                    'warning': {
                        'title': '🤖 Proyecto Sugerido',
                        'message': f"IA sugiere: {self.suggested_project_id.name}\n"
                                 f"Confianza: {result['confidence']:.1f}%\n"
                                 f"Razón: {result['reasoning']}"
                    }
                }
        except Exception as e:
            _logger.warning(f"AI project matching failed: {e}")
    
    def _match_project_with_ai(self, description, projects):
        """Llamar AI service para matching"""
        projects_data = [
            {
                'id': p.id,
                'name': p.name,
                'description': p.description or '',
                'partner_name': p.partner_id.name if p.partner_id else ''
            }
            for p in projects
        ]
        
        response = requests.post(
            f"{self._get_ai_service_url()}/api/v1/analytics/match",
            json={
                'invoice_description': description,
                'projects': projects_data
            },
            headers=self._get_ai_headers(),
            timeout=5
        )
        
        return response.json()
```

---

## 🔔 Módulo 5: SII Monitoring (Notificaciones)

### Integración: Cron de Monitoreo

```python
# models/sii_monitoring.py
class SIIMonitoring(models.Model):
    _name = 'sii.monitoring'
    _description = 'SII Monitoring'
    
    @api.model
    def _cron_monitor_sii(self):
        """Ejecuta cada 6 horas"""
        try:
            response = requests.post(
                f"{self._get_ai_service_url()}/api/ai/sii/monitor",
                json={'force': False},
                headers=self._get_ai_headers(),
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                _logger.info(
                    f"SII monitoring completed: "
                    f"{result['news_created']} news, "
                    f"{result['notifications_sent']} notifications"
                )
            
        except Exception as e:
            _logger.error(f"SII monitoring failed: {e}")
```

---

## 🔧 Utilidades Comunes

### Helper Mixin

```python
# models/ai_service_mixin.py
class AIServiceMixin(models.AbstractModel):
    _name = 'ai.service.mixin'
    _description = 'AI Service Integration Mixin'
    
    def _get_ai_service_url(self):
        """Get AI service URL from config"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'ai_service.url',
            'http://ai-service:8002'
        )
    
    def _get_ai_headers(self):
        """Get AI service auth headers"""
        api_key = self.env['ir.config_parameter'].sudo().get_param('ai_service.api_key')
        return {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def _is_ai_service_enabled(self):
        """Check if AI service is enabled"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'ai_service.enabled',
            'False'
        ) == 'True'
```

### Uso del Mixin

```python
class AccountMove(models.Model):
    _name = 'account.move'
    _inherit = ['account.move', 'ai.service.mixin']
    
    def _validate_with_ai(self):
        if not self._is_ai_service_enabled():
            return self._default_validation_result()
        
        response = requests.post(
            f"{self._get_ai_service_url()}/api/ai/validate",
            headers=self._get_ai_headers(),
            # ...
        )
```

---

## 📊 Resumen de Integraciones

| Módulo Odoo | Endpoint AI Service | Frecuencia | Timeout |
|-------------|---------------------|------------|---------|
| l10n_cl_dte | POST /api/ai/validate | Por DTE | 10s |
| l10n_cl_hr_payroll | POST /api/payroll/validate | Por liquidación | 15s |
| l10n_cl_hr_payroll | GET /api/payroll/indicators/{period} | Mensual (cron) | 30s |
| ai_chat | POST /api/chat/message/stream | Por mensaje | 30s |
| project_analytics | POST /api/v1/analytics/match | Por factura | 5s |
| sii_monitoring | POST /api/ai/sii/monitor | Cada 6h (cron) | 60s |

---

## 🔗 Próximo Documento

**06_GUIA_OPERACIONAL.md** - Deployment, troubleshooting y mantenimiento

---

**Última Actualización:** 2025-10-25  
**Mantenido por:** EERGYGROUP Development Team
