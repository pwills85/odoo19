# -*- coding: utf-8 -*-
"""
Account Move DTE - Chilean Electronic Invoicing
================================================

Extends account.move with DTE (Chilean electronic invoicing) functionality.

Migration Note (2025-10-24):
- Migrated from microservice architecture to native Odoo libs/
- Eliminates HTTP overhead (~100ms faster)
- Uses Python libraries directly (lxml, xmlsec, zeep)
- Better integration with Odoo ORM and workflows
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
import logging
import base64
from datetime import datetime

_logger = logging.getLogger(__name__)


class AccountMoveDTE(models.Model):
    """
    Extensión de account.move para Documentos Tributarios Electrónicos (DTE)

    ESTRATEGIA: EXTENDER, NO DUPLICAR
    - Reutilizamos todos los campos de account.move
    - Solo agregamos campos específicos DTE
    - Heredamos workflow de Odoo

    DTE Generation: Uses native Python libs/ (no HTTP microservice)
    """
    _name = 'account.move'
    _inherit = [
        'account.move',
        'dte.xml.generator',      # libs/xml_generator.py
        'xml.signer',             # libs/xml_signer.py
        'sii.soap.client',        # libs/sii_soap_client.py
        'ted.generator',          # libs/ted_generator.py
        'xsd.validator',          # libs/xsd_validator.py
    ]
    
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
        ('contingency', 'Modo Contingencia'),  # SPRINT 3: Contingency mode
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

    dte_async_status = fields.Selection(
        [
            ('draft', 'Borrador'),
            ('queued', 'En Cola'),
            ('processing', 'Procesando'),
            ('sent', 'Enviado'),
            ('accepted', 'Aceptado'),
            ('rejected', 'Rechazado'),
            ('error', 'Error'),
        ],
        string='Estado Async DTE',
        default='draft',
        readonly=True,
        copy=False,
        tracking=True,
        index=True,
        help='Estado del procesamiento asíncrono del DTE'
    )

    dte_queue_date = fields.Datetime(
        string='Fecha Cola DTE',
        readonly=True,
        copy=False,
        help='Fecha y hora en que el DTE fue agregado a la cola de procesamiento'
    )

    dte_processing_date = fields.Datetime(
        string='Fecha Procesamiento DTE',
        readonly=True,
        copy=False,
        help='Fecha y hora en que se inició el procesamiento del DTE'
    )

    dte_retry_count = fields.Integer(
        string='Intentos de Reenvío',
        default=0,
        readonly=True,
        copy=False,
        help='Número de veces que se ha intentado reenviar el DTE'
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
    # CAMPOS RABBITMQ - ELIMINADOS (2025-10-24)
    # ═══════════════════════════════════════════════════════════
    # Migration Note: RabbitMQ async processing replaced with Odoo ir.cron
    # Native Odoo scheduled actions are simpler and more integrated
    # If you need these fields for migration, they can be deprecated instead of deleted
    
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
        Envía el DTE al SII usando bibliotecas Python nativas (libs/).

        Flujo (Native - NO microservice):
        1. Validar datos localmente
        2. Generar XML usando libs/xml_generator.py
        3. Firmar digitalmente usando libs/xml_signer.py
        4. Enviar a SII usando libs/sii_soap_client.py (SOAP)
        5. Guardar resultado en Odoo DB

        Performance: ~100ms más rápido (sin HTTP overhead)
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

        # Cambiar estado a enviando
        self.with_context(tracking_disable=True).write({'dte_status': 'sending'})

        try:
            # NUEVO: Generar, firmar y enviar DTE directamente (sin HTTP)
            result = self._generate_sign_and_send_dte()
            
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
    
    def _generate_sign_and_send_dte(self):
        """
        Genera, firma y envía DTE al SII usando bibliotecas Python nativas.

        Reemplaza HTTP call a microservicio con código Python directo.
        Performance: ~100ms más rápido (sin HTTP overhead).

        Returns:
            Dict con resultado de la operación
        """
        self.ensure_one()

        _logger.info(f"Generating DTE for move {self.id}, type {self.dte_code}")

        # 1. Preparar datos DTE
        dte_data = self._prepare_dte_data_native()

        # 2. Generar XML sin firmar (usa libs/xml_generator.py)
        unsigned_xml = self.generate_dte_xml(self.dte_code, dte_data)

        _logger.info(f"XML generated, size: {len(unsigned_xml)} bytes")

        # 3. Validar XML contra XSD (opcional, usa libs/xsd_validator.py)
        is_valid, error_msg = self.validate_xml_against_xsd(unsigned_xml, self.dte_code)

        if not is_valid:
            raise ValidationError(
                _('XML validation failed:\n\n%s') % error_msg
            )

        # 4. Firmar XML digitalmente (usa libs/xml_signer.py)
        signed_xml = self.sign_xml_dte(
            unsigned_xml,
            certificate_id=self.journal_id.dte_certificate_id.id
        )

        _logger.info("XML signed successfully")

        # ═══════════════════════════════════════════════════════════════════════
        # 4.5. CONTINGENCY MODE CHECK (SPRINT 3 - 2025-10-24)
        # ═══════════════════════════════════════════════════════════════════════
        # OBLIGATORIO por normativa SII: Si SII no disponible, almacenar DTE localmente

        contingency = self.env['dte.contingency'].search([
            ('company_id', '=', self.company_id.id)
        ], limit=1)

        if contingency and contingency.enabled:
            # 🔴 CONTINGENCY MODE ACTIVE: Store DTE locally instead of sending
            _logger.warning(
                f"🔴 CONTINGENCY MODE ACTIVE: Storing DTE {self.dte_code} {dte_data['folio']} locally "
                f"(reason: {contingency.reason})"
            )

            # Store pending DTE
            pending = self.env['dte.contingency.pending'].store_pending_dte(
                dte_type=self.dte_code,
                folio=dte_data['folio'],
                xml_content=signed_xml,
                move_id=self.id
            )

            # Save XML in attachments (for user reference)
            self._save_dte_xml(signed_xml)

            # Update move status
            self.write({
                'dte_status': 'contingency',  # New status for contingency mode
                'dte_folio': dte_data['folio']
            })

            return {
                'success': True,  # Success in contingency mode
                'contingency_mode': True,
                'folio': dte_data['folio'],
                'track_id': None,  # No track_id in contingency
                'xml_b64': base64.b64encode(signed_xml.encode('ISO-8859-1')).decode('ascii'),
                'message': _('DTE stored in contingency mode. Will be uploaded when SII is available.'),
                'pending_id': pending.id
            }

        # ✅ Normal operation: Send to SII
        # ═══════════════════════════════════════════════════════════════════════

        # 5. Enviar a SII vía SOAP (usa libs/sii_soap_client.py)
        try:
            sii_result = self.send_dte_to_sii(
                signed_xml,
                self.company_id.vat
            )

            if sii_result.get('success'):
                # ✅ ÉXITO - DISASTER RECOVERY: Backup automático
                _logger.info(f"✅ DTE sent successfully, track_id: {sii_result.get('track_id')}")

                self.env['dte.backup'].backup_dte(
                    dte_type=self.dte_code,
                    folio=dte_data['folio'],
                    xml_content=signed_xml,
                    track_id=sii_result.get('track_id'),
                    move_id=self.id,
                    rut_emisor=self.company_id.vat
                )

                # Guardar XML en Odoo attachments (método existente)
                self._save_dte_xml(signed_xml)

                return {
                    'success': True,
                    'folio': dte_data['folio'],
                    'track_id': sii_result.get('track_id'),
                    'xml_b64': base64.b64encode(signed_xml.encode('ISO-8859-1')).decode('ascii'),
                    'response_xml': sii_result.get('response_xml'),
                    'duration_ms': sii_result.get('duration_ms', 0)
                }

            else:
                # ❌ FALLO - DISASTER RECOVERY: Agregar a failed queue
                error_msg = sii_result.get('error_message', 'Unknown SII error')
                _logger.warning(f"❌ DTE send failed: {error_msg}")

                # Clasificar tipo de error
                error_type = 'unknown'
                if 'timeout' in error_msg.lower():
                    error_type = 'timeout'
                elif 'connection' in error_msg.lower() or 'connect' in error_msg.lower():
                    error_type = 'connection'
                elif 'unavailable' in error_msg.lower() or 'disponible' in error_msg.lower():
                    error_type = 'unavailable'
                elif 'validacion' in error_msg.lower() or 'validation' in error_msg.lower():
                    error_type = 'validation'

                # Agregar a cola de reintentos
                self.env['dte.failed.queue'].add_failed_dte(
                    dte_type=self.dte_code,
                    folio=dte_data['folio'],
                    xml_content=signed_xml,
                    error_type=error_type,
                    error_message=error_msg,
                    move_id=self.id,
                    rut_emisor=self.company_id.vat
                )

                _logger.info(f"DTE {self.dte_code} {dte_data['folio']} added to failed queue for retry")

                return {
                    'success': False,
                    'folio': dte_data['folio'],
                    'track_id': None,
                    'xml_b64': base64.b64encode(signed_xml.encode('ISO-8859-1')).decode('ascii'),
                    'error_message': error_msg
                }

        except Exception as e:
            # ❌ EXCEPCIÓN - DISASTER RECOVERY: Agregar a failed queue
            _logger.error(f"Exception sending DTE: {e}", exc_info=True)

            self.env['dte.failed.queue'].add_failed_dte(
                dte_type=self.dte_code,
                folio=dte_data['folio'],
                xml_content=signed_xml,
                error_type='unknown',
                error_message=str(e),
                move_id=self.id,
                rut_emisor=self.company_id.vat
            )

            raise ValidationError(
                _('Error sending DTE to SII:\n\n%s\n\nDTE added to retry queue.') % str(e)
            )
    
    def _prepare_dte_data_native(self):
        """
        Prepara los datos de la factura para generación DTE nativa (sin microservicio).

        Returns:
            Dict con datos estructurados para libs/xml_generator.py
        """
        self.ensure_one()

        # Obtener folio
        folio = self.journal_id._get_next_folio()

        return {
            'folio': folio,
            'fecha_emision': fields.Date.to_string(self.invoice_date or fields.Date.today()),
            # Emisor (nuestra empresa)
            'emisor': {
                'rut': self.company_id.vat,
                'razon_social': self.company_id.name,
                'giro': self.company_id.l10n_cl_activity_description or 'Servicios',
                'acteco': self.company_id.l10n_cl_activity_code or '620200',  # Default: Servicios
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
                'iva': self.amount_tax,
                'monto_total': self.amount_total,
            },
            # Líneas
            'lineas': self._prepare_invoice_lines(),
        }

    def _save_dte_xml(self, signed_xml):
        """
        Guarda el XML firmado como attachment en Odoo.

        Args:
            signed_xml (str): XML firmado digitalmente
        """
        self.ensure_one()

        # Convert XML to binary
        xml_binary = signed_xml.encode('ISO-8859-1')

        # Save as attachment using Odoo attachment manager
        attachment = self.env['ir.attachment'].create({
            'name': f'DTE_{self.dte_code}_{self.dte_folio}.xml',
            'type': 'binary',
            'datas': base64.b64encode(xml_binary),
            'res_model': self._name,
            'res_id': self.id,
            'mimetype': 'application/xml',
            'description': f'DTE {self.dte_code} firmado y enviado al SII'
        })

        _logger.info(f"DTE XML saved as attachment {attachment.id}")

        # Update dte_xml field
        self.write({
            'dte_xml': base64.b64encode(xml_binary),
            'dte_xml_filename': f'DTE_{self.dte_code}_{self.dte_folio}.xml'
        })
    
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

    # ═══════════════════════════════════════════════════════════
    # BACKGROUND SCHEDULERS - SPRINT 2 (2025-10-24)
    # ═══════════════════════════════════════════════════════════

    @api.model
    def _cron_poll_dte_status(self):
        """
        Scheduled action (ir.cron): Poll DTE status from SII every 15 minutes.

        Migration from: odoo-eergy-services/scheduler/dte_status_poller.py

        Workflow:
        1. Search all DTEs with status 'sent' and track_id
        2. For each DTE: query status from SII via SOAP
        3. Update Odoo DTE status according to SII response
        4. Log results

        Status mapping:
        - SII 'ACEPTADO' → Odoo 'accepted'
        - SII 'RECHAZADO' → Odoo 'rejected'
        - SII 'REPARADO' → Odoo 'repaired'

        Benefits vs microservice:
        - Direct ORM access (no HTTP)
        - Transactional updates
        - Unified logging
        """
        _logger.info("=" * 70)
        _logger.info("🔄 DTE STATUS POLLER - Starting...")
        _logger.info("=" * 70)

        # Search DTEs with status 'sent' that need status update
        moves = self.search([
            ('dte_status', '=', 'sent'),
            ('dte_track_id', '!=', False)
        ])

        total_count = len(moves)
        _logger.info(f"Found {total_count} DTEs to poll")

        if total_count == 0:
            _logger.info("No DTEs to poll. Exiting.")
            return

        success_count = 0
        updated_count = 0
        error_count = 0

        for move in moves:
            try:
                _logger.info(f"Polling DTE {move.dte_code} {move.dte_folio} (track_id: {move.dte_track_id})")

                # Query status from SII
                result = move.query_dte_status(move.dte_track_id, move.company_id.vat)

                if result.get('success'):
                    sii_status = result.get('status', '').upper()

                    # Map SII status to Odoo status
                    if sii_status == 'ACEPTADO':
                        move.write({'dte_status': 'accepted'})
                        updated_count += 1
                        _logger.info(f"✅ DTE {move.dte_code} {move.dte_folio} ACCEPTED by SII")

                    elif sii_status == 'RECHAZADO':
                        move.write({
                            'dte_status': 'rejected',
                            'dte_error_message': result.get('error_message', 'Rechazado por SII')
                        })
                        updated_count += 1
                        _logger.warning(f"❌ DTE {move.dte_code} {move.dte_folio} REJECTED by SII")

                    elif sii_status == 'REPARADO':
                        move.write({'dte_status': 'repaired'})
                        updated_count += 1
                        _logger.info(f"🔧 DTE {move.dte_code} {move.dte_folio} REPAIRED by SII")

                    else:
                        # Status not recognized or still processing
                        _logger.info(f"⏳ DTE {move.dte_code} {move.dte_folio} still processing (status: {sii_status})")

                    success_count += 1

                else:
                    # Query failed
                    error_msg = result.get('error_message', 'Unknown error')
                    _logger.error(f"Error querying DTE {move.dte_code} {move.dte_folio}: {error_msg}")
                    error_count += 1

            except Exception as e:
                _logger.error(f"Exception polling DTE {move.id}: {e}", exc_info=True)
                error_count += 1
                continue

        _logger.info("=" * 70)
        _logger.info(f"✅ DTE Status Poller completed:")
        _logger.info(f"   Total: {total_count}")
        _logger.info(f"   Success queries: {success_count}")
        _logger.info(f"   Updated: {updated_count}")
        _logger.info(f"   Errors: {error_count}")
        _logger.info("=" * 70)

    def query_dte_status(self, track_id, rut_emisor):
        """
        Query DTE status from SII using SOAP client.

        Args:
            track_id (str): Track ID returned by SII when DTE was sent
            rut_emisor (str): RUT of the issuer

        Returns:
            dict: {
                'success': bool,
                'status': str ('ACEPTADO', 'RECHAZADO', 'REPARADO', etc.),
                'error_message': str (if any)
            }

        Uses: libs/sii_soap_client.py - query_status_sii()
        """
        self.ensure_one()

        _logger.info(f"Querying DTE status from SII - track_id: {track_id}")

        try:
            # Use SOAP client from libs/sii_soap_client.py
            result = self.query_status_sii(track_id, rut_emisor)

            return result

        except Exception as e:
            _logger.error(f"Error querying DTE status: {e}", exc_info=True)

            return {
                'success': False,
                'status': None,
                'error_message': str(e)
            }

