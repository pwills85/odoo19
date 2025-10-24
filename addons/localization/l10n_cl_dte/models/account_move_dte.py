# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import requests
import logging
import json

_logger = logging.getLogger(__name__)


class AccountMoveDTE(models.Model):
    """
    Extensión de account.move para Documentos Tributarios Electrónicos (DTE)
    
    ESTRATEGIA: EXTENDER, NO DUPLICAR
    - Reutilizamos todos los campos de account.move
    - Solo agregamos campos específicos DTE
    - Heredamos workflow de Odoo
    """
    _inherit = 'account.move'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS DTE ESPECÍFICOS
    # ═══════════════════════════════════════════════════════════
    
    dte_status = fields.Selection([
        ('draft', 'Borrador'),
        ('to_send', 'Por Enviar'),
        ('sending', 'Enviando...'),
        ('sent', 'Enviado a SII'),
        ('accepted', 'Aceptado por SII'),
        ('rejected', 'Rechazado por SII'),
        ('voided', 'Anulado'),
    ], string='Estado DTE', default='draft', tracking=True, copy=False)
    
    # Campo relacionado con l10n_latam_document_type para integración Odoo base
    dte_code = fields.Char(
        string='Código DTE',
        related='l10n_latam_document_type_id.code',
        store=True,
        readonly=True,
        help='Código del tipo de documento DTE (33, 34, 52, 56, 61). '
             'Integrado con l10n_latam_document_type para máxima compatibilidad Odoo 19 CE.'
    )
    
    dte_folio = fields.Char(
        string='Folio DTE',
        readonly=True,
        copy=False,
        tracking=True,
        index=True,  # Índice para búsquedas rápidas
        help='Folio asignado por el SII'
    )
    
    dte_timestamp = fields.Datetime(
        string='Timestamp DTE',
        readonly=True,
        copy=False,
        help='Fecha y hora de envío al SII'
    )
    
    dte_track_id = fields.Char(
        string='Track ID SII',
        readonly=True,
        copy=False,
        help='ID de seguimiento del SII'
    )
    
    dte_xml = fields.Binary(
        string='XML DTE',
        readonly=True,
        copy=False,
        attachment=True,
        help='XML del DTE generado y firmado'
    )
    
    dte_xml_filename = fields.Char(
        string='Nombre Archivo XML',
        compute='_compute_dte_xml_filename'
    )
    
    dte_response_xml = fields.Text(
        string='Respuesta XML SII',
        readonly=True,
        copy=False,
        help='XML de respuesta del SII'
    )
    
    dte_error_message = fields.Text(
        string='Mensaje de Error',
        readonly=True,
        copy=False,
        help='Mensaje de error del SII o del sistema'
    )

    # ⭐ CAMPOS ADICIONALES PARA TRACKING Y RELACIONES
    dte_accepted_date = fields.Datetime(
        string='Fecha Aceptación SII',
        readonly=True,
        copy=False,
        help='Fecha y hora en que el SII aceptó el DTE'
    )

    dte_certificate_id = fields.Many2one(
        'dte.certificate',
        string='Certificado Digital',
        readonly=True,
        copy=False,
        help='Certificado digital usado para firmar este DTE'
    )

    dte_caf_id = fields.Many2one(
        'dte.caf',
        string='CAF Utilizado',
        readonly=True,
        copy=False,
        help='Código de Autorización de Folios (CAF) usado para este DTE'
    )

    dte_environment = fields.Selection([
        ('sandbox', 'Sandbox (Maullin)'),
        ('production', 'Producción (Palena)')
    ], string='Ambiente SII', default='sandbox',
       help='Ambiente del SII donde se envió el DTE')

    is_contingency = fields.Boolean(
        string='Es Contingencia',
        default=False,
        copy=False,
        help='Indica si este DTE fue emitido en modo contingencia'
    )

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
       help='Estado del procesamiento asíncrono del DTE vía RabbitMQ')
    
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
    
    dte_retry_count = fields.Integer(
        string='Reintentos',
        default=0,
        help='Número de reintentos realizados',
        readonly=True
    )
    
    dte_qr_image = fields.Binary(
        string='QR Code TED',
        readonly=True,
        copy=False,
        attachment=True,
        help='Código QR del Timbre Electrónico para verificación'
    )
    
    # ═══════════════════════════════════════════════════════════
    # RELACIONES DTE
    # ═══════════════════════════════════════════════════════════
    
    dte_communication_ids = fields.One2many(
        'dte.communication',
        'move_id',
        string='Comunicaciones SII',
        help='Historial de comunicaciones con el SII'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('dte_folio', 'dte_code')
    def _compute_dte_xml_filename(self):
        """Genera nombre para archivo XML"""
        for move in self:
            if move.dte_folio and move.dte_code:
                move.dte_xml_filename = f'DTE_{move.dte_code}_{move.dte_folio}.xml'
            else:
                move.dte_xml_filename = False
    
    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS Y VALIDACIONES
    # ═══════════════════════════════════════════════════════════
    
    @api.constrains('partner_id')
    def _check_partner_rut(self):
        """
        Valida que el cliente tenga RUT para DTEs.
        
        NOTA: l10n_cl ya valida formato RUT automáticamente en partner._run_check_identification().
        Solo verificamos presencia del RUT aquí.
        """
        for move in self:
            if move.move_type in ['out_invoice', 'out_refund'] and move.dte_code:
                if not move.partner_id.vat:
                    raise ValidationError(_('El cliente debe tener RUT configurado para emitir DTE.'))
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS - DTE
    # ═══════════════════════════════════════════════════════════
    
    def action_send_to_sii(self):
        """
        Envía el DTE al SII a través del microservicio DTE.
        
        Flujo:
        1. Validar datos localmente
        2. Llamar DTE Service para generar XML
        3. DTE Service firma digitalmente
        4. DTE Service envía a SII (SOAP)
        5. Guardar resultado
        """
        self.ensure_one()
        
        # Validar que esté en estado correcto
        if self.state != 'posted':
            raise UserError(_('Solo se pueden enviar facturas confirmadas.'))
        
        if self.dte_status not in ['draft', 'to_send', 'rejected']:
            raise UserError(_('El DTE ya ha sido enviado. Estado actual: %s') % 
                          dict(self._fields['dte_status'].selection)[self.dte_status])
        
        # Validar datos requeridos
        self._validate_dte_data()
        
        # Cambiar estado a enviando (sin commit manual - mala práctica en Odoo)
        self.with_context(tracking_disable=True).write({'dte_status': 'sending'})
        
        try:
            # Llamar DTE Service
            result = self._call_dte_service()
            
            # Procesar resultado
            self._process_dte_result(result)
            
            # Crear log de comunicación
            self.env['dte.communication'].log_communication(
                action_type='send_dte',
                status='success',
                move_id=self.id,
                dte_type=self.dte_code,
                dte_folio=self.dte_folio,
                track_id=self.dte_track_id,
                response_xml=self.dte_response_xml
            )
            
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Éxito'),
                    'message': _('DTE enviado exitosamente al SII. Folio: %s') % self.dte_folio,
                    'type': 'success',
                    'sticky': False,
                }
            }
            
        except Exception as e:
            _logger.error(f'Error al enviar DTE: {str(e)}')
            
            # Actualizar estado a error
            self.write({
                'dte_status': 'draft',
                'dte_error_message': str(e)
            })
            
            # Crear log de error
            self.env['dte.communication'].log_communication(
                action_type='send_dte',
                status='error',
                move_id=self.id,
                dte_type=self.dte_code,
                error_message=str(e)
            )
            
            raise UserError(_('Error al enviar DTE: %s') % str(e))
    
    def _validate_dte_data(self):
        """Validaciones locales antes de enviar al DTE Service"""
        self.ensure_one()

        # Validar RUT cliente
        # Nota: Validación RUT delegada a Odoo nativo (l10n_cl → base_vat → python-stdnum)
        # Odoo valida automáticamente al asignar partner.vat con country_code='CL'
        if not self.partner_id.vat:
            raise ValidationError(_('El cliente debe tener RUT configurado.'))

        # Validar RUT empresa
        if not self.company_id.vat:
            raise ValidationError(_('La compañía debe tener RUT configurado.'))
        
        # Validar que tenga líneas
        if not self.invoice_line_ids:
            raise ValidationError(_('La factura debe tener al menos una línea.'))
        
        # Validar montos
        if self.amount_total <= 0:
            raise ValidationError(_('El monto total debe ser mayor a cero.'))
        
        # Validar que el diario tenga certificado
        if not self.journal_id.dte_certificate_id:
            raise ValidationError(_('El diario no tiene certificado digital configurado.'))
        
        # Validar que el certificado esté válido
        if self.journal_id.dte_certificate_id.state not in ['valid', 'expiring_soon']:
            raise ValidationError(
                _('El certificado digital no está válido. Estado: %s') % 
                dict(self.journal_id.dte_certificate_id._fields['state'].selection)[self.journal_id.dte_certificate_id.state]
            )
    
    def _call_dte_service(self):
        """
        Llama al DTE Microservice para generar, firmar y enviar el DTE.
        
        Returns:
            Dict con resultado de la operación
        """
        self.ensure_one()
        
        # URL del DTE Service
        dte_service_url = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_service_url',
            'http://odoo-eergy-services:8001'
        )
        
        # Preparar datos
        data = self._prepare_dte_data()
        
        # Headers con autenticación
        headers = {
            'Authorization': f'Bearer {self._get_dte_api_key()}',
            'Content-Type': 'application/json'
        }
        
        # Llamar al servicio
        try:
            response = requests.post(
                f'{dte_service_url}/api/dte/generate-and-send',
                json=data,
                headers=headers,
                timeout=60  # 60 segundos timeout
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            _logger.error(f'Error al llamar DTE Service: {str(e)}')
            raise UserError(_('Error de comunicación con DTE Service: %s') % str(e))
    
    def _prepare_dte_data(self):
        """
        Prepara los datos de la factura para enviar al DTE Service.
        
        Returns:
            Dict con datos de la factura
        """
        self.ensure_one()
        
        # Obtener certificado
        certificate = self.journal_id.dte_certificate_id
        cert_data = certificate.get_certificate_data()
        
        return {
            'dte_type': self.dte_code,
            'invoice_data': {
                'folio': self.journal_id._get_next_folio(),
                'fecha_emision': fields.Date.to_string(self.invoice_date or fields.Date.today()),
                # Emisor (nuestra empresa)
                'emisor': {
                    'rut': self.company_id.vat,
                    'razon_social': self.company_id.name,
                    'giro': self.company_id.l10n_cl_activity_description or 'Servicios',
                    'acteco': self.company_id.l10n_cl_activity_code,  # OBLIGATORIO: código 6 dígitos
                    'direccion': self._format_address(self.company_id),
                    'ciudad': self.company_id.city or '',
                    'comuna': self.company_id.partner_id.l10n_cl_comuna or (self.company_id.state_id.name if self.company_id.state_id else ''),
                },
                # Receptor (cliente)
                'receptor': {
                    'rut': self.partner_id.vat,
                    'razon_social': self.partner_id.name,
                    'giro': self.partner_id.industry_id.name if self.partner_id.industry_id else 'N/A',
                    'direccion': self._format_address(self.partner_id),
                    'ciudad': self.partner_id.city or '',
                    'comuna': self.partner_id.l10n_cl_comuna or (self.partner_id.state_id.name if self.partner_id.state_id else ''),
                },
                # Totales
                'totales': {
                    'monto_neto': self.amount_untaxed,
                    'monto_iva': self.amount_tax,
                    'monto_total': self.amount_total,
                },
                # Líneas
                'lineas': self._prepare_invoice_lines(),
            },
            'certificate': {
                'cert_file': cert_data['cert_file'].hex(),  # Convertir a hex para JSON
                'password': cert_data['password']
            },
            'environment': self._get_sii_environment(),
        }
    
    def _prepare_invoice_lines(self):
        """Prepara las líneas de la factura para el DTE"""
        self.ensure_one()
        
        lines = []
        for i, line in enumerate(self.invoice_line_ids.filtered(lambda l: not l.display_type), 1):
            lines.append({
                'numero_linea': i,
                'nombre': line.name or line.product_id.name,
                'descripcion': line.name,
                'cantidad': line.quantity,
                'unidad': line.product_uom_id.name if line.product_uom_id else 'UN',
                'precio_unitario': line.price_unit,
                'descuento_pct': line.discount,
                'subtotal': line.price_subtotal,
            })
        
        return lines
    
    def _format_address(self, partner):
        """Formatea dirección para DTE"""
        parts = []
        if partner.street:
            parts.append(partner.street)
        if partner.street2:
            parts.append(partner.street2)
        return ', '.join(parts) if parts else 'N/A'
    
    def _get_sii_environment(self):
        """Determina si usar sandbox o producción del SII"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.sii_environment',
            'sandbox'
        )
    
    def _get_dte_api_key(self):
        """Obtiene API key para DTE Service"""
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_api_key',
            'default_api_key'
        )
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS RABBITMQ - PROCESAMIENTO ASÍNCRONO
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
            'payload': self._prepare_dte_payload_for_rabbitmq(),
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
    
    def _prepare_dte_payload_for_rabbitmq(self):
        """
        Prepara payload para RabbitMQ (versión simplificada)
        Reutiliza _prepare_dte_data() del método síncrono
        
        Returns:
            dict: Datos del DTE para procesamiento asíncrono
        """
        self.ensure_one()
        
        # Reutilizar preparación de datos existente
        return self._prepare_dte_data()
    
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
                'dte_timestamp': fields.Datetime.now(),
                'dte_status': 'sent'  # Sincronizar con estado principal
            })
            message = _('DTE enviado al SII exitosamente. Track ID: %s') % kwargs.get('track_id')
            
        elif status == 'accepted':
            values['dte_status'] = 'accepted'
            message = _('DTE aceptado por el SII')
            
        elif status == 'rejected':
            values.update({
                'dte_error_message': kwargs.get('message'),
                'dte_status': 'rejected'
            })
            message = _('DTE rechazado por el SII: %s') % kwargs.get('message')
            
        elif status == 'error':
            values.update({
                'dte_error_message': kwargs.get('message'),
                'dte_retry_count': self.dte_retry_count + 1
            })
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
    
    def _process_dte_result(self, result):
        """
        Procesa el resultado del DTE Service.
        
        Args:
            result: Dict con respuesta del DTE Service
        """
        self.ensure_one()
        
        if result.get('success'):
            self.write({
                'dte_status': 'accepted',
                'dte_folio': result.get('folio'),
                'dte_track_id': result.get('track_id'),
                'dte_xml': result.get('xml_b64'),
                'dte_qr_image': result.get('qr_image_b64'),  # ⭐ NUEVO: QR code
                'dte_response_xml': result.get('response_xml'),
                'dte_timestamp': fields.Datetime.now(),
            })
        else:
            self.write({
                'dte_status': 'rejected',
                'dte_error_message': result.get('error_message', 'Error desconocido'),
                'dte_response_xml': result.get('response_xml'),
            })
            
            raise UserError(_('DTE rechazado por SII: %s') % result.get('error_message'))
    
    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════
    
    def action_download_dte_xml(self):
        """Descarga el XML del DTE"""
        self.ensure_one()
        
        if not self.dte_xml:
            raise UserError(_('No hay XML DTE disponible para descargar.'))
        
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/account.move/{self.id}/dte_xml/{self.dte_xml_filename}?download=true',
            'target': 'self',
        }
    
    def action_view_communications(self):
        """Ver historial de comunicaciones con SII"""
        self.ensure_one()
        
        return {
            'name': _('Comunicaciones SII'),
            'type': 'ir.actions.act_window',
            'res_model': 'dte.communication',
            'view_mode': 'tree,form',
            'domain': [('move_id', '=', self.id)],
            'context': {'default_move_id': self.id}
        }
    
    # ═══════════════════════════════════════════════════════════
    # OVERRIDE METHODS
    # ═══════════════════════════════════════════════════════════
    
    def button_draft(self):
        """Override para resetear estado DTE al volver a borrador"""
        result = super().button_draft()
        
        for move in self:
            if move.dte_status in ['sent', 'accepted']:
                raise UserError(_('No se puede volver a borrador un DTE que ya fue enviado al SII.'))
            
            move.write({'dte_status': 'draft'})
        
        return result
    
    def action_post(self):
        """Override para marcar DTE como 'por enviar' al confirmar"""
        result = super().action_post()
        
        for move in self:
            if move.dte_code and move.move_type in ['out_invoice', 'out_refund']:
                move.write({'dte_status': 'to_send'})
        
        return result

