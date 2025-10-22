# -*- coding: utf-8 -*-
"""
Account Move DTE - Integración RabbitMQ
Extiende account.move para envío asíncrono de DTEs
"""

from odoo import api, fields, models, _
from odoo.exceptions import UserError
import logging

_logger = logging.getLogger(__name__)


class AccountMove(models.Model):
    _inherit = 'account.move'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS RABBITMQ - INTEGRACIÓN ASÍNCRONA
    # ═══════════════════════════════════════════════════════════
    
    dte_async_status = fields.Selection([
        ('draft', 'Borrador'),
        ('queued', 'En Cola RabbitMQ'),
        ('processing', 'Procesando'),
        ('sent', 'Enviado al SII'),
        ('accepted', 'Aceptado por SII'),
        ('rejected', 'Rechazado por SII'),
        ('error', 'Error')
    ], string='Estado DTE Asíncrono', default='draft', tracking=True,
       help='Estado del procesamiento asíncrono del DTE')
    
    dte_queue_date = fields.Datetime(
        string='Fecha Cola',
        help='Fecha en que se publicó a RabbitMQ',
        readonly=True
    )
    
    dte_processing_date = fields.Datetime(
        string='Fecha Procesamiento',
        help='Fecha en que DTE Service comenzó a procesar',
        readonly=True
    )
    
    dte_sent_date = fields.Datetime(
        string='Fecha Envío SII',
        help='Fecha en que se envió al SII',
        readonly=True
    )
    
    dte_track_id = fields.Char(
        string='Track ID SII',
        help='ID de seguimiento del SII',
        readonly=True
    )
    
    dte_xml = fields.Text(
        string='XML DTE',
        help='XML del DTE firmado (base64)',
        readonly=True
    )
    
    dte_error_message = fields.Text(
        string='Mensaje de Error',
        help='Detalles del error si falla el procesamiento',
        readonly=True
    )
    
    dte_retry_count = fields.Integer(
        string='Reintentos',
        default=0,
        help='Número de reintentos realizados',
        readonly=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS RABBITMQ
    # ═══════════════════════════════════════════════════════════
    
    def action_send_dte_async(self):
        """
        Envía DTE de forma asíncrona vía RabbitMQ
        
        Botón visible en facturas validadas con tipo DTE
        """
        for move in self:
            # Validaciones
            if move.state != 'posted':
                raise UserError(_('Solo se pueden enviar facturas validadas'))
            
            if not move.l10n_latam_document_type_id:
                raise UserError(_('La factura no tiene tipo DTE asignado'))
            
            if move.dte_async_status in ['queued', 'processing']:
                raise UserError(_(
                    'DTE ya está en proceso. Estado: %s'
                ) % dict(move._fields['dte_async_status'].selection).get(move.dte_async_status))
            
            # Determinar prioridad
            # Empresas tienen prioridad 8, particulares 5
            priority = 8 if move.partner_id.is_company else 5
            
            # Publicar a RabbitMQ
            move._publish_dte_to_rabbitmq(action='generate', priority=priority)
        
        # Notificación al usuario
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('DTE en Cola'),
                'message': _('%s DTE(s) publicado(s) a cola de procesamiento') % len(self),
                'type': 'success',
                'sticky': False,
                'next': {'type': 'ir.actions.act_window_close'},
            }
        }
    
    def _publish_dte_to_rabbitmq(self, action='generate', priority=5):
        """
        Publica DTE a RabbitMQ para procesamiento asíncrono
        
        Args:
            action (str): Acción a realizar ('generate', 'validate', 'send')
            priority (int): Prioridad 0-10 (10 = más alta)
        """
        self.ensure_one()
        
        _logger.info(
            "Publicando DTE a RabbitMQ: move_id=%s, dte_type=%s, action=%s, priority=%s",
            self.id,
            self.l10n_latam_document_type_id.code if self.l10n_latam_document_type_id else 'N/A',
            action,
            priority
        )
        
        # Preparar mensaje
        message = {
            'dte_id': f'DTE-{self.id}',
            'dte_type': self.l10n_latam_document_type_id.code,
            'action': action,
            'payload': self._prepare_dte_payload_for_service(),
            'priority': priority,
            'retry_count': self.dte_retry_count,
            'company_id': self.company_id.id,
            'user_id': self.env.user.id,
            'created_at': fields.Datetime.now().isoformat()
        }
        
        # Publicar a RabbitMQ
        rabbitmq = self.env['rabbitmq.helper']
        success = rabbitmq.publish_message(
            exchange='dte.direct',
            routing_key=action,
            message=message,
            priority=priority
        )
        
        if success:
            # Actualizar estado
            self.write({
                'dte_async_status': 'queued',
                'dte_queue_date': fields.Datetime.now(),
                'dte_error_message': False
            })
            
            # Registrar en chatter
            self.message_post(
                body=_('DTE publicado a cola RabbitMQ (acción: %s, prioridad: %s)') % (action, priority),
                subject=_('DTE en Cola')
            )
            
            _logger.info(
                "DTE publicado exitosamente: move_id=%s, dte_id=%s",
                self.id,
                message['dte_id']
            )
        else:
            raise UserError(_('Error al publicar DTE a RabbitMQ. Ver logs del sistema.'))
    
    def _prepare_dte_payload_for_service(self):
        """
        Prepara payload completo para DTE Service
        
        Returns:
            dict: Datos completos del DTE para procesamiento
        """
        self.ensure_one()
        
        # TODO: Implementar preparación completa de payload
        # Por ahora, estructura básica
        
        payload = {
            'invoice_id': self.id,
            'invoice_name': self.name,
            'invoice_date': self.invoice_date.isoformat() if self.invoice_date else None,
            'partner_id': self.partner_id.id,
            'partner_name': self.partner_id.name,
            'partner_vat': self.partner_id.vat,
            'amount_total': float(self.amount_total),
            'amount_untaxed': float(self.amount_untaxed),
            'amount_tax': float(self.amount_tax),
            'currency': self.currency_id.name,
            'company_id': self.company_id.id,
            'company_vat': self.company_id.vat,
        }
        
        _logger.debug(
            "Payload preparado para DTE Service: move_id=%s, payload_keys=%s",
            self.id,
            list(payload.keys())
        )
        
        return payload
    
    # ═══════════════════════════════════════════════════════════
    # WEBHOOK CALLBACK (llamado desde DTE Service)
    # ═══════════════════════════════════════════════════════════
    
    def dte_update_status_from_webhook(self, status, **kwargs):
        """
        Actualiza estado del DTE desde webhook del DTE Service
        
        Args:
            status (str): Nuevo estado ('sent', 'accepted', 'rejected', 'error')
            **kwargs: Datos adicionales (track_id, xml_b64, message, etc.)
        """
        self.ensure_one()
        
        _logger.info(
            "Actualizando estado DTE desde webhook: move_id=%s, status=%s",
            self.id,
            status
        )
        
        values = {
            'dte_async_status': status,
            'dte_processing_date': fields.Datetime.now()
        }
        
        # Actualizar según estado
        if status == 'sent':
            values.update({
                'dte_track_id': kwargs.get('track_id'),
                'dte_xml': kwargs.get('xml_b64'),
                'dte_sent_date': fields.Datetime.now()
            })
            message = _('DTE enviado al SII exitosamente. Track ID: %s') % kwargs.get('track_id')
            
        elif status == 'accepted':
            message = _('DTE aceptado por el SII')
            
        elif status == 'rejected':
            values['dte_error_message'] = kwargs.get('message')
            message = _('DTE rechazado por el SII: %s') % kwargs.get('message')
            
        elif status == 'error':
            values['dte_error_message'] = kwargs.get('message')
            values['dte_retry_count'] = self.dte_retry_count + 1
            message = _('Error al procesar DTE: %s') % kwargs.get('message')
        
        else:
            _logger.warning(
                "Estado desconocido desde webhook: move_id=%s, status=%s",
                self.id,
                status
            )
            return False
        
        # Actualizar factura
        self.write(values)
        
        # Registrar en chatter
        self.message_post(
            body=message,
            subject=_('Actualización DTE Service')
        )
        
        _logger.info(
            "Estado DTE actualizado: move_id=%s, status=%s",
            self.id,
            status
        )
        
        return True
