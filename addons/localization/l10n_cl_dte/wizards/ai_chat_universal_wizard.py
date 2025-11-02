# -*- coding: utf-8 -*-
"""
Universal AI Chat Wizard - Multi-Module Support
================================================

Single chat interface that works across all Odoo modules.

Features:
- RBAC-aware (respects user permissions)
- Context-aware (auto-detects module from active_model)
- Streaming responses (Server-Sent Events)
- Session persistence (Redis)
- Quick actions (buttons for common tasks)

Competitive Advantage:
SAP/Oracle/NetSuite have separate chat per module (fragmented UX).
We have ONE unified chat that knows all modules (superior UX).

Author: EERGYGROUP - Phase 2 Enhancement 2025-10-24
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import requests
import json
import logging

_logger = logging.getLogger(__name__)


class AIChatUniversalWizard(models.TransientModel):
    """
    Universal AI Chat Wizard.

    Can be launched from:
    - Any model's action menu
    - Dashboard
    - Smart button
    - Standalone menu

    Automatically detects context and selects appropriate AI plugin.
    """
    _name = 'ai.chat.universal.wizard'
    _description = 'Universal AI Chat (Multi-Module)'

    # ═══════════════════════════════════════════════════════════════════
    # FIELDS
    # ═══════════════════════════════════════════════════════════════════

    user_message = fields.Text(
        string='Tu Mensaje',
        required=True,
        help='Escribe tu pregunta o solicitud'
    )

    conversation_history = fields.Html(
        string='Conversación',
        readonly=True,
        help='Historial de la conversación'
    )

    session_id = fields.Char(
        string='Session ID',
        readonly=True,
        help='ID de sesión (Redis)'
    )

    active_module = fields.Char(
        string='Módulo Activo',
        compute='_compute_active_module',
        store=False,
        help='Módulo Odoo desde donde se lanzó el chat'
    )

    selected_plugin = fields.Char(
        string='Plugin AI Seleccionado',
        compute='_compute_selected_plugin',
        store=False,
        help='Plugin de AI Service que se está usando'
    )

    allowed_plugins = fields.Char(
        string='Plugins Permitidos',
        compute='_compute_allowed_plugins',
        store=False,
        help='Plugins a los que el usuario tiene acceso'
    )

    is_streaming_enabled = fields.Boolean(
        string='Streaming Habilitado',
        default=True,
        help='Usar respuestas en tiempo real (streaming)'
    )

    # Context fields (from active_*)
    context_active_model = fields.Char(
        string='Active Model',
        compute='_compute_context',
        store=False
    )

    context_active_id = fields.Integer(
        string='Active ID',
        compute='_compute_context',
        store=False
    )

    context_active_record_name = fields.Char(
        string='Active Record',
        compute='_compute_context',
        store=False
    )

    # AI Service config
    ai_service_url = fields.Char(
        string='AI Service URL',
        compute='_compute_ai_service_config',
        store=False
    )

    ai_service_available = fields.Boolean(
        string='AI Service Available',
        compute='_compute_ai_service_config',
        store=False
    )

    # ═══════════════════════════════════════════════════════════════════
    # COMPUTE METHODS
    # ═══════════════════════════════════════════════════════════════════

    @api.depends_context('active_model')
    def _compute_context(self):
        """Extract context from active_* variables"""
        for wizard in self:
            wizard.context_active_model = self.env.context.get('active_model', '')
            wizard.context_active_id = self.env.context.get('active_id', 0)

            # Get active record name
            if wizard.context_active_model and wizard.context_active_id:
                try:
                    record = self.env[wizard.context_active_model].browse(wizard.context_active_id)
                    wizard.context_active_record_name = record.display_name
                except (KeyError, AttributeError, ValueError) as e:
                    # Failed to get display_name - use ID fallback
                    _logger.debug(
                        f"[AI Chat Wizard] Failed to get display_name for {wizard.context_active_model}:{wizard.context_active_id}: {e}",
                        extra={'error_type': type(e).__name__}
                    )
                    wizard.context_active_record_name = f"ID {wizard.context_active_id}"
            else:
                wizard.context_active_record_name = ''

    @api.depends_context('active_model')
    def _compute_active_module(self):
        """Detect active Odoo module from context"""
        for wizard in self:
            active_model = self.env.context.get('active_model', '')

            # Map model to module
            if 'account' in active_model:
                wizard.active_module = 'account'
            elif 'purchase' in active_model:
                wizard.active_module = 'purchase'
            elif 'stock' in active_model:
                wizard.active_module = 'stock'
            elif 'sale' in active_model:
                wizard.active_module = 'sale'
            elif 'hr' in active_model or 'payroll' in active_model:
                wizard.active_module = 'hr_payroll'
            elif 'project' in active_model:
                wizard.active_module = 'project'
            elif 'dte' in active_model:
                wizard.active_module = 'l10n_cl_dte'
            else:
                wizard.active_module = 'general'

    @api.depends()  # No field dependencies - queries external service
    def _compute_allowed_plugins(self):
        """
        Get plugins user can access.

        US-1.4: Added @api.depends() for external service query.
        No field dependencies (queries ai.agent.selector service).
        """
        for wizard in self:
            selector = self.env['ai.agent.selector']
            allowed = selector.get_allowed_plugins()
            wizard.allowed_plugins = ', '.join(allowed)

    @api.depends('user_message', 'context_active_model', 'context_active_id')
    def _compute_selected_plugin(self):
        """
        Determine which plugin will be used.

        US-1.4: Added @api.depends() to cache plugin selection.
        Recomputes when message or context changes.
        """
        for wizard in self:
            try:
                selector = self.env['ai.agent.selector']

                plugin = selector.select_plugin(
                    query=wizard.user_message or '',
                    context={
                        'active_model': wizard.context_active_model,
                        'active_id': wizard.context_active_id
                    }
                )

                wizard.selected_plugin = plugin
            except Exception as e:
                _logger.error("Error selecting plugin: %s", e)
                wizard.selected_plugin = 'unknown'

    @api.depends()  # No field dependencies - queries ir.config_parameter
    def _compute_ai_service_config(self):
        """
        Get AI Service configuration.

        US-1.4: Added @api.depends() for system config query.
        No field dependencies (queries ir.config_parameter + health check).
        """
        for wizard in self:
            try:
                config = self.env['ir.config_parameter'].sudo()

                wizard.ai_service_url = config.get_param(
                    'l10n_cl_dte.ai_service_url',
                    'http://ai-service:8002'
                )

                # Check availability (ping)
                try:
                    response = requests.get(
                        f"{wizard.ai_service_url}/health",
                        timeout=2
                    )
                    wizard.ai_service_available = (response.status_code == 200)
                except (requests.RequestException, requests.Timeout, ConnectionError) as e:
                    _logger.debug(
                        f"[AI Chat Wizard] AI service health check failed: {e}",
                        extra={
                            'ai_service_url': wizard.ai_service_url,
                            'error_type': type(e).__name__
                        }
                    )
                    wizard.ai_service_available = False

            except Exception as e:
                _logger.error("Error getting AI Service config: %s", e)
                wizard.ai_service_url = ''
                wizard.ai_service_available = False

    # ═══════════════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════════════

    def action_send_message(self):
        """
        Send message to AI Service and get response.

        Process:
        1. Validate message
        2. Select plugin (RBAC + context)
        3. Call AI Service /api/chat
        4. Display response
        5. Update conversation history
        """
        self.ensure_one()

        if not self.user_message:
            raise ValidationError(_('Debes escribir un mensaje.'))

        if not self.ai_service_available:
            raise UserError(_(
                'El servicio de IA no está disponible.\n'
                'Verifica que el AI Service esté ejecutándose.'
            ))

        # Select plugin
        selector = self.env['ai.agent.selector']

        try:
            plugin = selector.select_plugin(
                query=self.user_message,
                context={
                    'active_model': self.context_active_model,
                    'active_id': self.context_active_id
                }
            )

            # Validate access
            selector.validate_plugin_access(plugin)

            _logger.info(
                "💬 Chat: user=%s, plugin=%s, query='%s'",
                self.env.user.login,
                plugin,
                self.user_message[:100]
            )

        except Exception as e:
            raise UserError(str(e))

        # Prepare context for AI
        context_data = self._prepare_ai_context()

        # Call AI Service
        try:
            response = self._call_ai_service(
                plugin=plugin,
                user_message=self.user_message,
                context=context_data
            )

            # Update conversation history
            self._update_conversation_history(
                user_message=self.user_message,
                ai_response=response['message'],
                plugin=plugin
            )

            # Show response
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Respuesta IA'),
                    'message': response['message'][:200] + '...',
                    'type': 'success',
                    'sticky': False
                }
            }

        except requests.exceptions.RequestException as e:
            _logger.error("AI Service request failed: %s", e)
            raise UserError(_(
                'Error comunicándose con AI Service: %s'
            ) % str(e))

        except Exception as e:
            _logger.error("Error processing AI response: %s", e, exc_info=True)
            raise UserError(_(
                'Error procesando respuesta de IA: %s'
            ) % str(e))

    def action_clear_history(self):
        """Clear conversation history"""
        self.ensure_one()
        self.conversation_history = ''
        self.session_id = False

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Historial Borrado'),
                'message': _('La conversación se ha reiniciado.'),
                'type': 'info'
            }
        }

    # ═══════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════

    def _prepare_ai_context(self):
        """
        Prepare context data to send to AI Service.

        Returns:
            dict: Context with user info, active record data, etc.
        """
        self.ensure_one()

        context = {
            'user': {
                'id': self.env.user.id,
                'name': self.env.user.name,
                'login': self.env.user.login,
                'company_id': self.env.company.id,
                'company_name': self.env.company.name,
                'language': self.env.user.lang or 'es_CL'
            },
            'odoo': {
                'active_model': self.context_active_model,
                'active_id': self.context_active_id,
                'active_record_name': self.context_active_record_name
            },
            'session_id': self.session_id or self._generate_session_id()
        }

        # Add active record data (if exists)
        if self.context_active_model and self.context_active_id:
            try:
                record = self.env[self.context_active_model].browse(self.context_active_id)

                # Extract relevant fields (limit to avoid huge payload)
                record_data = {}

                for field_name, field in record._fields.items():
                    # Skip binary, html, computed fields
                    if field.type in ('binary', 'html') or field.compute:
                        continue

                    try:
                        value = record[field_name]

                        # Convert Many2one to dict
                        if field.type == 'many2one' and value:
                            record_data[field_name] = {
                                'id': value.id,
                                'name': value.display_name
                            }
                        # Convert dates to string
                        elif field.type in ('date', 'datetime'):
                            record_data[field_name] = str(value) if value else None
                        # Simple types
                        elif field.type in ('char', 'text', 'integer', 'float', 'monetary', 'selection'):
                            record_data[field_name] = value
                    except (KeyError, AttributeError, ValueError) as e:
                        # Failed to extract field data - skip this field
                        _logger.debug(
                            f"[AI Chat Wizard] Failed to extract field data: {e}",
                            extra={
                                'field_name': field_name,
                                'error_type': type(e).__name__
                            }
                        )
                        pass

                context['active_record_data'] = record_data

            except Exception as e:
                _logger.warning("Could not extract active record data: %s", e)

        return context

    def _call_ai_service(self, plugin, user_message, context):
        """
        Call AI Service /api/chat endpoint.

        Args:
            plugin (str): Plugin name (e.g., 'account')
            user_message (str): User's message
            context (dict): Context data

        Returns:
            dict: AI response {message, sources, confidence, etc.}
        """
        url = f"{self.ai_service_url}/api/chat"

        # Get API key
        api_key = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.ai_service_api_key',
            'default_ai_api_key'
        )

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        payload = {
            'message': user_message,
            'session_id': context.get('session_id'),
            'context': {
                **context,
                'module': plugin  # Hint for plugin selection
            },
            'stream': self.is_streaming_enabled
        }

        _logger.debug("Calling AI Service: %s with plugin=%s", url, plugin)

        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=30  # 30 seconds
        )

        response.raise_for_status()

        return response.json()

    def _update_conversation_history(self, user_message, ai_response, plugin):
        """
        Update conversation history HTML.

        Args:
            user_message (str): User's message
            ai_response (str): AI's response
            plugin (str): Plugin used
        """
        self.ensure_one()

        # Format messages
        timestamp = fields.Datetime.now().strftime('%H:%M')

        user_html = f'''
        <div class="o_mail_message o_mail_message_user" style="margin-bottom: 10px;">
            <div class="o_mail_message_body" style="padding: 10px; background: #f0f0f0; border-radius: 5px;">
                <strong>Tú ({timestamp}):</strong><br/>
                {user_message}
            </div>
        </div>
        '''

        ai_html = f'''
        <div class="o_mail_message o_mail_message_ai" style="margin-bottom: 10px;">
            <div class="o_mail_message_body" style="padding: 10px; background: #e3f2fd; border-radius: 5px;">
                <strong>IA ({plugin}) ({timestamp}):</strong><br/>
                {ai_response}
            </div>
        </div>
        '''

        # Append to history
        current_history = self.conversation_history or ''
        self.conversation_history = current_history + user_html + ai_html

    def _generate_session_id(self):
        """Generate unique session ID"""
        import uuid
        session_id = f"chat_{self.env.user.id}_{uuid.uuid4().hex[:8]}"
        self.session_id = session_id
        return session_id

    # ═══════════════════════════════════════════════════════════════════
    # DEFAULT GET
    # ═══════════════════════════════════════════════════════════════════

    @api.model
    def default_get(self, fields_list):
        """Set default values when opening wizard"""
        res = super().default_get(fields_list)

        # Generate session ID
        if 'session_id' in fields_list:
            res['session_id'] = self._generate_session_id()

        # Add welcome message
        if 'conversation_history' in fields_list:
            active_module = self.env.context.get('active_model', 'general')
            allowed_plugins = self.env['ai.agent.selector'].get_allowed_plugins()

            welcome = f'''
            <div style="padding: 15px; background: #fff3cd; border-radius: 5px; margin-bottom: 10px;">
                <h4>👋 Bienvenido al Asistente IA Universal</h4>
                <p>
                    <strong>Módulo activo:</strong> {active_module}<br/>
                    <strong>Plugins disponibles:</strong> {', '.join(allowed_plugins)}
                </p>
                <p style="font-size: 12px; color: #666;">
                    Pregúntame lo que necesites sobre Odoo. Puedo ayudarte con:
                    contabilidad, compras, inventario, ventas, nóminas, proyectos y más.
                </p>
            </div>
            '''

            res['conversation_history'] = welcome

        return res
