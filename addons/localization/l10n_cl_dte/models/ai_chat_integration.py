# -*- coding: utf-8 -*-
"""
AI Chat Service Integration
============================

Professional integration layer between Odoo and AI Chat Microservice.
Provides conversational AI support for DTE operations with context awareness.

Architecture principles:
- Single responsibility: Only AI Service API communication
- Context awareness: Passes company, user, and DTE context
- Session management: Multi-turn conversations
- Error resilience: Graceful handling of service unavailability
- User feedback: Clear error messages
- Logging: Comprehensive audit trail
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import requests
import logging
import json

_logger = logging.getLogger(__name__)


class AIChatIntegration(models.AbstractModel):
    """
    Abstract model for AI Chat Service integration.
    Mixin pattern for reusability across DTE models.
    """
    _name = 'ai.chat.integration'
    _description = 'AI Chat Service Integration Layer'

    # ═══════════════════════════════════════════════════════════
    # CONFIGURATION
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _get_ai_service_url(self):
        """Get AI Service URL from system parameters."""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.ai_service_url',
            'http://ai-service:8002'
        )

    @api.model
    def _get_ai_service_api_key(self):
        """Get AI Service API key from system parameters."""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.ai_service_api_key',
            ''
        )

    @api.model
    def _get_ai_service_timeout(self):
        """Get request timeout in seconds."""
        return int(self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.ai_service_timeout',
            '30'
        ))

    @api.model
    def _get_request_headers(self):
        """Build request headers with API key."""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Odoo-19-l10n_cl_dte/1.0',
        }

        api_key = self._get_ai_service_api_key()
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'

        return headers

    # ═══════════════════════════════════════════════════════════
    # HEALTH CHECK
    # ═══════════════════════════════════════════════════════════

    @api.model
    def check_ai_service_health(self):
        """
        Check AI Service health and availability.

        Returns:
            dict: Health status with details
        """
        try:
            base_url = self._get_ai_service_url()
            timeout = self._get_ai_service_timeout()

            # H9 FIX: Add Authorization header for health check
            api_key = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.ai_service_api_key', False
            )
            headers = {'Authorization': f'Bearer {api_key}'} if api_key else {}
            
            response = requests.get(
                f"{base_url}/health",
                headers=headers,
                timeout=min(timeout, 10)  # Max 10s for health check
            )

            if response.status_code == 200:
                health_data = response.json()

                _logger.info(
                    "AI Service health check successful: status=%s",
                    health_data.get('status', 'unknown')
                )

                return {
                    'success': True,
                    'status': health_data.get('status', 'healthy'),
                    'details': health_data,
                }

            _logger.warning(
                "AI Service health check failed: status_code=%s",
                response.status_code
            )

            return {
                'success': False,
                'status': 'unhealthy',
                'error': f'HTTP {response.status_code}',
            }

        except requests.exceptions.Timeout:
            _logger.error("AI Service health check timeout")
            return {
                'success': False,
                'status': 'timeout',
                'error': 'Service timeout',
            }

        except requests.exceptions.ConnectionError as e:
            _logger.error("AI Service connection error: %s", str(e))
            return {
                'success': False,
                'status': 'unavailable',
                'error': 'Service unavailable',
            }

        except Exception as e:
            _logger.error("AI Service health check error: %s", str(e), exc_info=True)
            return {
                'success': False,
                'status': 'error',
                'error': str(e),
            }

    # ═══════════════════════════════════════════════════════════
    # CONTEXT BUILDING
    # ═══════════════════════════════════════════════════════════

    def _build_user_context(self):
        """
        Build user context for AI chat.

        Returns:
            dict: User context including company, role, environment
        """
        user = self.env.user
        company = self.env.company

        # Get SII environment (sandbox vs production)
        sii_environment = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.sii_environment',
            'sandbox'
        )

        context = {
            'company_name': company.name,
            'company_rut': company.partner_id.vat or 'N/A',
            'user_name': user.name,
            'user_email': user.email or 'N/A',
            'user_role': 'Administrador' if user.has_group('base.group_system') else 'Usuario',
            'environment': 'Producción' if sii_environment == 'production' else 'Sandbox (Maullin)',
            'language': user.lang or 'es_CL',
        }

        # Add DTE-specific context if available (for account.move)
        if hasattr(self, 'dte_type_id'):
            context.update({
                'dte_type': self.dte_type_id.code if self.dte_type_id else None,
                'dte_status': self.dte_status if hasattr(self, 'dte_status') else None,
            })

        return context

    # ═══════════════════════════════════════════════════════════
    # CHAT SESSION MANAGEMENT
    # ═══════════════════════════════════════════════════════════

    @api.model
    def create_chat_session(self, user_context=None):
        """
        Create new chat session.

        Args:
            user_context (dict, optional): Additional user context

        Returns:
            dict: Session info with session_id and welcome_message

        Raises:
            UserError: If service unavailable or error occurs
        """
        try:
            base_url = self._get_ai_service_url()
            headers = self._get_request_headers()
            timeout = self._get_ai_service_timeout()

            # Build user context
            context = self._build_user_context() if hasattr(self, '_build_user_context') else {}
            if user_context:
                context.update(user_context)

            payload = {
                'user_context': context
            }

            _logger.info("Creating AI chat session with context: %s", json.dumps(context, indent=2))

            response = requests.post(
                f"{base_url}/api/chat/session/new",
                json=payload,
                headers=headers,
                timeout=timeout
            )

            if response.status_code == 200:
                session_data = response.json()

                _logger.info(
                    "AI chat session created successfully: session_id=%s",
                    session_data.get('session_id')
                )

                return {
                    'success': True,
                    'session_id': session_data.get('session_id'),
                    'welcome_message': session_data.get('welcome_message'),
                }

            # Handle HTTP errors
            error_msg = self._parse_error_response(response)
            _logger.error(
                "Failed to create AI chat session: status=%s, error=%s",
                response.status_code,
                error_msg
            )

            raise UserError(_(
                "No se pudo crear la sesión de chat con el asistente IA.\n"
                "Error: %s"
            ) % error_msg)

        except requests.exceptions.Timeout:
            _logger.error("AI Service timeout creating chat session")
            raise UserError(_(
                "Timeout al conectar con el asistente IA.\n"
                "Por favor, intente nuevamente."
            ))

        except requests.exceptions.ConnectionError:
            _logger.error("AI Service connection error creating chat session")
            raise UserError(_(
                "No se pudo conectar con el asistente IA.\n"
                "Verifique que el servicio esté en ejecución."
            ))

        except UserError:
            raise

        except Exception as e:
            _logger.error("Unexpected error creating chat session: %s", str(e), exc_info=True)
            raise UserError(_(
                "Error inesperado al crear sesión de chat.\n"
                "Error técnico: %s"
            ) % str(e))

    def send_chat_message(self, session_id, message, user_context=None):
        """
        Send message to AI chat and get response.

        Args:
            session_id (str): Session identifier
            message (str): User message
            user_context (dict, optional): Additional user context

        Returns:
            dict: Response with AI message, sources, confidence, etc.

        Raises:
            UserError: If service unavailable or error occurs
        """
        try:
            base_url = self._get_ai_service_url()
            headers = self._get_request_headers()
            timeout = self._get_ai_service_timeout()

            # Build user context
            context = self._build_user_context() if hasattr(self, '_build_user_context') else {}
            if user_context:
                context.update(user_context)

            payload = {
                'session_id': session_id,
                'message': message,
                'user_context': context
            }

            _logger.info(
                "Sending AI chat message: session_id=%s, message_length=%d",
                session_id,
                len(message)
            )

            response = requests.post(
                f"{base_url}/api/chat/message",
                json=payload,
                headers=headers,
                timeout=timeout
            )

            if response.status_code == 200:
                response_data = response.json()

                _logger.info(
                    "AI chat response received: session_id=%s, llm_used=%s, sources=%d",
                    response_data.get('session_id'),
                    response_data.get('llm_used'),
                    len(response_data.get('sources', []))
                )

                return {
                    'success': True,
                    'message': response_data.get('message'),
                    'sources': response_data.get('sources', []),
                    'confidence': response_data.get('confidence', 0.0),
                    'session_id': response_data.get('session_id'),
                    'llm_used': response_data.get('llm_used'),
                    'tokens_used': response_data.get('tokens_used'),
                }

            # Handle HTTP errors
            error_msg = self._parse_error_response(response)
            _logger.error(
                "Failed to send AI chat message: status=%s, error=%s",
                response.status_code,
                error_msg
            )

            raise UserError(_(
                "No se pudo enviar el mensaje al asistente IA.\n"
                "Error: %s"
            ) % error_msg)

        except requests.exceptions.Timeout:
            _logger.error("AI Service timeout sending chat message")
            raise UserError(_(
                "Timeout esperando respuesta del asistente IA.\n"
                "Por favor, intente nuevamente."
            ))

        except requests.exceptions.ConnectionError:
            _logger.error("AI Service connection error sending chat message")
            raise UserError(_(
                "No se pudo conectar con el asistente IA.\n"
                "Verifique que el servicio esté en ejecución."
            ))

        except UserError:
            raise

        except Exception as e:
            _logger.error("Unexpected error sending chat message: %s", str(e), exc_info=True)
            raise UserError(_(
                "Error inesperado enviando mensaje.\n"
                "Error técnico: %s"
            ) % str(e))

    @api.model
    def get_conversation_history(self, session_id):
        """
        Get conversation history for session.

        Args:
            session_id (str): Session identifier

        Returns:
            dict: Conversation history with messages and stats

        Raises:
            UserError: If service unavailable or error occurs
        """
        try:
            base_url = self._get_ai_service_url()
            headers = self._get_request_headers()
            timeout = self._get_ai_service_timeout()

            _logger.info("Getting AI chat history: session_id=%s", session_id)

            response = requests.get(
                f"{base_url}/api/chat/session/{session_id}",
                headers=headers,
                timeout=timeout
            )

            if response.status_code == 200:
                history_data = response.json()

                _logger.info(
                    "AI chat history retrieved: session_id=%s, message_count=%d",
                    session_id,
                    len(history_data.get('messages', []))
                )

                return {
                    'success': True,
                    'session_id': history_data.get('session_id'),
                    'messages': history_data.get('messages', []),
                    'stats': history_data.get('stats', {}),
                }

            # Handle HTTP errors
            error_msg = self._parse_error_response(response)
            _logger.error(
                "Failed to get AI chat history: status=%s, error=%s",
                response.status_code,
                error_msg
            )

            return {
                'success': False,
                'error': error_msg,
            }

        except Exception as e:
            _logger.error("Error getting chat history: %s", str(e), exc_info=True)
            return {
                'success': False,
                'error': str(e),
            }

    @api.model
    def clear_chat_session(self, session_id):
        """
        Clear chat session (delete history and context).

        Args:
            session_id (str): Session identifier

        Returns:
            dict: Success status

        Raises:
            UserError: If service unavailable or error occurs
        """
        try:
            base_url = self._get_ai_service_url()
            headers = self._get_request_headers()
            timeout = self._get_ai_service_timeout()

            _logger.info("Clearing AI chat session: session_id=%s", session_id)

            response = requests.delete(
                f"{base_url}/api/chat/session/{session_id}",
                headers=headers,
                timeout=timeout
            )

            if response.status_code == 200:
                _logger.info("AI chat session cleared: session_id=%s", session_id)
                return {'success': True}

            error_msg = self._parse_error_response(response)
            _logger.error(
                "Failed to clear AI chat session: status=%s, error=%s",
                response.status_code,
                error_msg
            )

            return {
                'success': False,
                'error': error_msg,
            }

        except Exception as e:
            _logger.error("Error clearing chat session: %s", str(e), exc_info=True)
            return {
                'success': False,
                'error': str(e),
            }

    # ═══════════════════════════════════════════════════════════
    # KNOWLEDGE BASE SEARCH
    # ═══════════════════════════════════════════════════════════

    @api.model
    def search_knowledge_base(self, query, top_k=3):
        """
        Search AI knowledge base directly (without chat session).

        Args:
            query (str): Search query
            top_k (int): Number of results to return

        Returns:
            dict: Search results

        Raises:
            UserError: If service unavailable or error occurs
        """
        try:
            base_url = self._get_ai_service_url()
            headers = self._get_request_headers()
            timeout = self._get_ai_service_timeout()

            _logger.info("Searching AI knowledge base: query='%s', top_k=%d", query, top_k)

            response = requests.get(
                f"{base_url}/api/chat/knowledge/search",
                params={'query': query, 'top_k': top_k},
                headers=headers,
                timeout=timeout
            )

            if response.status_code == 200:
                search_data = response.json()

                _logger.info(
                    "AI knowledge base search completed: results=%d",
                    len(search_data.get('results', []))
                )

                return {
                    'success': True,
                    'query': search_data.get('query'),
                    'results': search_data.get('results', []),
                }

            error_msg = self._parse_error_response(response)
            _logger.error(
                "Failed to search AI knowledge base: status=%s, error=%s",
                response.status_code,
                error_msg
            )

            return {
                'success': False,
                'error': error_msg,
            }

        except Exception as e:
            _logger.error("Error searching knowledge base: %s", str(e), exc_info=True)
            return {
                'success': False,
                'error': str(e),
            }

    # ═══════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _parse_error_response(self, response):
        """
        Parse error response from AI Service.

        Args:
            response: requests.Response object

        Returns:
            str: Human-readable error message
        """
        try:
            error_data = response.json()
            return error_data.get('detail', f'HTTP {response.status_code}')
        except (ValueError, KeyError, TypeError) as e:
            # JSON parsing failed or invalid structure
            _logger.warning(
                f"[AI Service] Failed to parse error response: {e}",
                extra={
                    'status_code': response.status_code,
                    'error_type': type(e).__name__,
                    'response_preview': response.text[:200]
                }
            )
            return f'HTTP {response.status_code}: {response.text[:100]}'


class AIChatSession(models.TransientModel):
    """
    Transient model for AI chat sessions.
    Stores active chat sessions for current user.
    """
    _name = 'ai.chat.session'
    _description = 'AI Chat Session'
    _inherit = ['ai.chat.integration']

    session_id = fields.Char(
        string='Session ID',
        required=True,
        readonly=True
    )

    user_id = fields.Many2one(
        comodel_name='res.users',
        string='User',
        required=True,
        readonly=True,
        default=lambda self: self.env.user
    )

    company_id = fields.Many2one(
        comodel_name='res.company',
        string='Company',
        required=True,
        readonly=True,
        default=lambda self: self.env.company
    )

    create_date = fields.Datetime(
        string='Created',
        readonly=True
    )

    message_count = fields.Integer(
        string='Messages',
        default=0
    )

    last_message = fields.Text(
        string='Last Message',
        readonly=True
    )

    last_response = fields.Text(
        string='Last Response',
        readonly=True
    )

    # ═══════════════════════════════════════════════════════════
    # CRUD OPERATIONS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def start_new_session(self, user_context=None):
        """
        Start new chat session.

        Args:
            user_context (dict, optional): Additional user context

        Returns:
            ai.chat.session: New session record
        """
        # Create session via AI Service
        result = self.create_chat_session(user_context=user_context)

        if not result.get('success'):
            raise UserError(_("No se pudo crear sesión de chat"))

        # Store session in database
        session = self.create({
            'session_id': result['session_id'],
            'user_id': self.env.user.id,
            'company_id': self.env.company.id,
        })

        _logger.info(
            "New AI chat session started: id=%d, session_id=%s",
            session.id,
            session.session_id
        )

        return session

    def send_message(self, message):
        """
        Send message in this session.

        Args:
            message (str): User message

        Returns:
            dict: AI response
        """
        self.ensure_one()

        result = self.send_chat_message(
            session_id=self.session_id,
            message=message
        )

        if result.get('success'):
            # Update session
            self.write({
                'message_count': self.message_count + 1,
                'last_message': message,
                'last_response': result.get('message'),
            })

        return result

    def get_history(self):
        """
        Get conversation history for this session.

        Returns:
            dict: Conversation history
        """
        self.ensure_one()
        return self.get_conversation_history(self.session_id)

    def clear_session(self):
        """
        Clear this session.

        Returns:
            dict: Success status
        """
        self.ensure_one()
        result = self.clear_chat_session(self.session_id)

        if result.get('success'):
            self.unlink()

        return result
