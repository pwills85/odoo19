# -*- coding: utf-8 -*-
"""
AI Chat Wizard
==============

Wizard for interactive chat with AI assistant specialized in DTE operations.
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError
import logging

_logger = logging.getLogger(__name__)


class AIChatWizard(models.TransientModel):
    """
    Wizard for AI chat interaction.
    Provides real-time conversational interface for DTE support.
    """
    _name = 'ai.chat.wizard'
    _description = 'AI Chat Wizard'
    _inherit = ['ai.chat.integration']

    # ═══════════════════════════════════════════════════════════
    # FIELDS
    # ═══════════════════════════════════════════════════════════

    session_id = fields.Char(
        string='Session ID',
        readonly=True,
        help='Internal session identifier'
    )

    welcome_message = fields.Text(
        string='Mensaje de Bienvenida',
        readonly=True,
        help='Initial welcome message from AI assistant'
    )

    conversation_html = fields.Html(
        string='Conversación',
        readonly=True,
        sanitize=False,
        help='Conversation history (formatted)'
    )

    user_message = fields.Text(
        string='Tu Mensaje',
        required=True,
        help='Type your question or message here'
    )

    ai_response = fields.Text(
        string='Respuesta IA',
        readonly=True,
        help='AI assistant response'
    )

    sources = fields.Text(
        string='Fuentes Consultadas',
        readonly=True,
        help='Knowledge base sources used in response'
    )

    message_count = fields.Integer(
        string='Mensajes',
        readonly=True,
        default=0,
        help='Number of messages in conversation'
    )

    llm_used = fields.Char(
        string='LLM Usado',
        readonly=True,
        help='Which LLM was used (anthropic/openai)'
    )

    # Context fields (for DTE-aware conversations)
    context_model = fields.Char(
        string='Modelo',
        help='Context model (e.g., account.move)'
    )

    context_res_id = fields.Integer(
        string='Record ID',
        help='Context record ID'
    )

    # ═══════════════════════════════════════════════════════════
    # DEFAULTS
    # ═══════════════════════════════════════════════════════════

    @api.model
    def default_get(self, fields_list):
        """Initialize wizard with new chat session."""
        res = super().default_get(fields_list)

        # Check service health
        health = self.check_ai_service_health()
        if not health.get('success'):
            raise UserError(_(
                "El Asistente IA no está disponible en este momento.\n"
                "Estado: %s\n\n"
                "Por favor, contacte al administrador del sistema."
            ) % health.get('error', 'Unknown'))

        # Create new session
        try:
            # Build context from active record (if available)
            user_context = {}

            if self.env.context.get('active_model') and self.env.context.get('active_id'):
                active_model = self.env.context.get('active_model')
                active_id = self.env.context.get('active_id')

                res['context_model'] = active_model
                res['context_res_id'] = active_id

                # Add DTE-specific context for account.move
                if active_model == 'account.move':
                    record = self.env[active_model].browse(active_id)
                    if record.exists():
                        user_context.update({
                            'document_type': record.move_type,
                            'partner_name': record.partner_id.name if record.partner_id else None,
                            'amount_total': record.amount_total,
                            'currency': record.currency_id.name if record.currency_id else None,
                        })

                        # Add DTE info if available
                        if hasattr(record, 'dte_type_id') and record.dte_type_id:
                            user_context.update({
                                'dte_type': record.dte_type_id.code,
                                'dte_type_name': record.dte_type_id.name,
                                'dte_status': record.dte_status if hasattr(record, 'dte_status') else None,
                            })

            session_result = self.create_chat_session(user_context=user_context)

            if session_result.get('success'):
                res.update({
                    'session_id': session_result['session_id'],
                    'welcome_message': session_result['welcome_message'],
                    'conversation_html': self._format_welcome_html(session_result['welcome_message']),
                })

                _logger.info(
                    "AI Chat wizard initialized: session_id=%s",
                    session_result['session_id']
                )
            else:
                raise UserError(_("No se pudo iniciar sesión de chat"))

        except UserError:
            raise

        except Exception as e:
            _logger.error("Error initializing AI Chat wizard: %s", str(e), exc_info=True)
            raise UserError(_(
                "Error al iniciar el Asistente IA.\n"
                "Error técnico: %s"
            ) % str(e))

        return res

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_send_message(self):
        """
        Send user message and get AI response.

        Returns:
            dict: Action to reload wizard with response
        """
        self.ensure_one()

        if not self.user_message or not self.user_message.strip():
            raise UserError(_("Por favor, escriba un mensaje"))

        try:
            # Send message to AI Service
            result = self.send_chat_message(
                session_id=self.session_id,
                message=self.user_message.strip()
            )

            if result.get('success'):
                # Update conversation
                self.message_count += 1

                # Build conversation HTML
                conversation_html = self._build_conversation_html(
                    user_message=self.user_message,
                    ai_response=result['message'],
                    sources=result.get('sources', [])
                )

                # Update wizard
                self.write({
                    'ai_response': result['message'],
                    'sources': self._format_sources(result.get('sources', [])),
                    'llm_used': result.get('llm_used', 'unknown'),
                    'conversation_html': conversation_html,
                    'user_message': '',  # Clear input
                })

                _logger.info(
                    "AI Chat message sent: session_id=%s, message_count=%d",
                    self.session_id,
                    self.message_count
                )

            else:
                raise UserError(_("No se pudo enviar el mensaje"))

        except UserError:
            raise

        except Exception as e:
            _logger.error("Error sending message: %s", str(e), exc_info=True)
            raise UserError(_(
                "Error al enviar mensaje.\n"
                "Error técnico: %s"
            ) % str(e))

        # Return action to reload wizard
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'ai.chat.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }

    def action_clear_session(self):
        """
        Clear chat session and start new one.

        Returns:
            dict: Action to reload wizard
        """
        self.ensure_one()

        try:
            # Clear current session
            if self.session_id:
                self.clear_chat_session(self.session_id)

            # Create new session
            session_result = self.create_chat_session()

            if session_result.get('success'):
                self.write({
                    'session_id': session_result['session_id'],
                    'welcome_message': session_result['welcome_message'],
                    'conversation_html': self._format_welcome_html(session_result['welcome_message']),
                    'user_message': '',
                    'ai_response': False,
                    'sources': False,
                    'message_count': 0,
                    'llm_used': False,
                })

                _logger.info(
                    "AI Chat session cleared and restarted: new_session_id=%s",
                    session_result['session_id']
                )

        except Exception as e:
            _logger.error("Error clearing session: %s", str(e), exc_info=True)
            raise UserError(_(
                "Error al limpiar sesión.\n"
                "Error técnico: %s"
            ) % str(e))

        return {
            'type': 'ir.actions.act_window',
            'res_model': 'ai.chat.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }

    def action_close(self):
        """Close wizard."""
        return {'type': 'ir.actions.act_window_close'}

    # ═══════════════════════════════════════════════════════════
    # FORMATTING HELPERS
    # ═══════════════════════════════════════════════════════════

    def _format_welcome_html(self, welcome_message):
        """Format welcome message as HTML."""
        return f"""
        <div style="font-family: Arial, sans-serif; padding: 10px;">
            <div style="background-color: #e8f5e9; padding: 15px; border-radius: 8px; margin-bottom: 10px;">
                <strong style="color: #2e7d32;">🤖 Asistente IA DTE:</strong>
                <p style="margin-top: 5px; color: #333;">{welcome_message}</p>
            </div>
        </div>
        """

    def _build_conversation_html(self, user_message, ai_response, sources):
        """Build conversation HTML with all messages."""
        # Get previous conversation
        prev_html = self.conversation_html or ''

        # Add new exchange
        new_html = f"""
        <div style="background-color: #e3f2fd; padding: 12px; border-radius: 8px; margin-bottom: 8px;">
            <strong style="color: #1565c0;">👤 Tú:</strong>
            <p style="margin-top: 5px; color: #333;">{user_message}</p>
        </div>
        <div style="background-color: #e8f5e9; padding: 12px; border-radius: 8px; margin-bottom: 10px;">
            <strong style="color: #2e7d32;">🤖 Asistente IA:</strong>
            <p style="margin-top: 5px; color: #333; white-space: pre-wrap;">{ai_response}</p>
        """

        if sources:
            sources_html = ', '.join([f'<em>{s}</em>' for s in sources])
            new_html += f"""
            <p style="margin-top: 10px; font-size: 0.85em; color: #666;">
                📚 Fuentes: {sources_html}
            </p>
            """

        new_html += "</div>"

        # Combine with previous conversation
        return f"""
        <div style="font-family: Arial, sans-serif; padding: 10px; max-height: 500px; overflow-y: auto;">
            {prev_html}
            {new_html}
        </div>
        """

    def _format_sources(self, sources):
        """Format sources as text."""
        if not sources:
            return False

        return "📚 Documentación consultada:\n" + "\n".join([f"• {s}" for s in sources])
