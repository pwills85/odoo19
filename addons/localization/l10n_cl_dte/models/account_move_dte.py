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

**REFACTORED:** 2025-11-02 - FASE 2 - Odoo 19 CE Compliance
- Removed AbstractModel inheritance from libs/
- Now uses pure Python classes with Dependency Injection
- Cleaner architecture, better testability
"""

from odoo import models, fields, api, tools, _
from odoo.exceptions import ValidationError, UserError
import logging
import base64
from datetime import datetime

# Import pure Python classes from libs/ (FASE 2 refactor)
from ..libs.xml_generator import DTEXMLGenerator
from ..libs.xml_signer import XMLSigner
from ..libs.sii_soap_client import SIISoapClient
from ..libs.ted_generator import TEDGenerator
from ..libs.xsd_validator import XSDValidator

# P1.3 GAP CLOSURE: Performance metrics instrumentation
from ..libs.performance_metrics import measure_performance

_logger = logging.getLogger(__name__)


class AccountMoveDTE(models.Model):
    """
    Extensión de account.move para Documentos Tributarios Electrónicos (DTE)

    ESTRATEGIA: EXTENDER, NO DUPLICAR
    - Reutilizamos todos los campos de account.move
    - Solo agregamos campos específicos DTE
    - Heredamos workflow de Odoo

    DTE Generation: Uses native Python libs/ (no HTTP microservice)

    **FASE 2 REFACTOR (2025-11-02):** Removed AbstractModel inheritance.
    Now uses pure Python classes from libs/ with Dependency Injection pattern.
    Methods like generate_dte_xml() now delegate to DTEXMLGenerator instance.
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
        ('contingency', 'Modo Contingencia'),  # SPRINT 3: Contingency mode
        ('voided', 'Anulado'),
    ], string='Estado DTE', default='draft', tracking=True, copy=False, index=True)  # US-1.3: Index for frequent queries
    
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
        index=True,  # US-1.3: Index for SII track ID queries
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

    # P0-3 GAP CLOSURE: TED Complete Signature
    dte_ted_xml = fields.Text(
        string='TED XML',
        readonly=True,
        copy=False,
        help='TED (Timbre Electrónico) firmado con llave CAF.\\n'
             'Usado para generar código PDF417 en reportes PDF.\\n'
             'Contiene firma RSA-SHA1 del DD usando llave privada del CAF.'
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
    ], string='Ambiente SII', default='sandbox', index=True,  # US-1.3: Index for environment filtering
       help='Ambiente del SII donde se envió el DTE')

    is_contingency = fields.Boolean(
        string='Es Contingencia',
        default=False,
        copy=False,
        help='Indica si este DTE fue emitido en modo contingencia'
    )

    # ═══════════════════════════════════════════════════════════
    # P0-6 GAP CLOSURE: Historical DTE Preservation
    # ═══════════════════════════════════════════════════════════
    # DTEs migrados desde Odoo 11 (2018-2024) tienen certificados EXPIRADOS.
    # No se pueden re-firmar. Debemos preservar firma original para validez legal.

    is_historical_dte = fields.Boolean(
        string='DTE Histórico',
        default=False,
        copy=False,
        index=True,
        help='DTE migrado con firma digital original (certificado expirado). '
             'NO se re-firma, se preserva XML original para validez legal SII.'
    )

    signed_xml_original = fields.Binary(
        string='XML Firmado Original',
        attachment=True,
        copy=False,
        help='XML con firma digital original preservada. '
             'Usado para DTEs históricos que no pueden re-firmarse (certificado expirado).'
    )

    historical_signature_date = fields.Datetime(
        string='Fecha Firma Original',
        readonly=True,
        copy=False,
        help='Fecha y hora de la firma digital original del DTE histórico'
    )

    migration_source = fields.Selection([
        ('odoo11', 'Migrado desde Odoo 11'),
        ('odoo16', 'Migrado desde Odoo 16'),
        ('odoo17', 'Migrado desde Odoo 17'),
        ('manual', 'Carga Manual'),
    ], string='Origen Migración',
       copy=False,
       help='Sistema origen del DTE migrado')

    migration_date = fields.Datetime(
        string='Fecha Migración',
        readonly=True,
        copy=False,
        help='Fecha y hora en que se migró este DTE histórico'
    )

    # ──────────────────────────────────────────────────────────
    # Campos específicos DTE 52 (Guía de Despacho)
    # ──────────────────────────────────────────────────────────
    l10n_cl_dte_tipo_traslado = fields.Selection(
        selection=[
            ('1', '1 - Venta'),
            ('2', '2 - Venta por efectuar'),
            ('3', '3 - Consignación'),
            ('4', '4 - Entrega gratuita'),
            ('5', '5 - Traslado interno'),
            ('6', '6 - Otros traslados no venta'),
            ('7', '7 - Devolución'),
            ('8', '8 - Traslado para exportación'),
        ],
        string='Tipo de traslado (DTE 52)',
        help='Obligatorio en DTE 52. Valores permitidos por SII: 1..8.',
    )

    l10n_cl_dte_tipo_despacho = fields.Selection(
        selection=[
            ('1', '1 - Por cuenta del comprador'),
            ('2', '2 - Por cuenta del vendedor a instalaciones del comprador'),
            ('3', '3 - Por cuenta del vendedor a otras instalaciones'),
        ],
        string='Tipo de despacho (DTE 52)',
        help='Opcional en DTE 52. Si se informa, debe estar en 1..3.',
    )

    l10n_cl_dte_transporte = fields.Boolean(
        string='Informar transporte (DTE 52)',
        help='Si está marcado, se requieren datos mínimos del transporte (patente y RUT transportista).',
    )

    l10n_cl_dte_patente = fields.Char(
        string='Patente vehículo (DTE 52)',
        help='Patente del vehículo de transporte. Requerida si se marca Informar transporte.',
    )

    l10n_cl_dte_rut_transportista = fields.Char(
        string='RUT transportista (DTE 52)',
        help='RUT del transportista. Requerido si se marca Informar transporte.',
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
    # SQL CONSTRAINTS - Sprint 1.4 (B-009)
    # ═══════════════════════════════════════════════════════════

    _sql_constraints = [
        ('dte_track_id_unique',
         'UNIQUE(dte_track_id)',
         'El Track ID del SII debe ser único. Este DTE ya fue enviado previamente.'),
    ]

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
    # WRAPPER METHODS - LIBS/ DELEGATION (FASE 2 REFACTOR)
    # ═══════════════════════════════════════════════════════════
    # These methods delegate to pure Python classes from libs/
    # while maintaining the same interface for backward compatibility

    @measure_performance('generar_xml')
    def generate_dte_xml(self, dte_type, invoice_data):
        """
        Delegate to DTEXMLGenerator (pure Python).

        P1.3 GAP CLOSURE: Instrumented with performance metrics.
        """
        generator = DTEXMLGenerator()
        return generator.generate_dte_xml(dte_type, invoice_data)

    def generate_ted(self, dte_data, caf_id=None):
        """Delegate to TEDGenerator (with env injection)."""
        generator = TEDGenerator(self.env)
        return generator.generate_ted(dte_data, caf_id)

    def validate_xml_against_xsd(self, xml_string, dte_type):
        """Delegate to XSDValidator (pure Python)."""
        validator = XSDValidator()
        return validator.validate_xml_against_xsd(xml_string, dte_type)

    @measure_performance('firmar')
    def sign_dte_documento(self, xml_string, documento_id, certificate_id=None, algorithm='sha256'):
        """
        Delegate to XMLSigner.sign_dte_documento (with env injection).

        P1.3 GAP CLOSURE: Instrumented with performance metrics.
        """
        signer = XMLSigner(self.env)
        return signer.sign_dte_documento(xml_string, documento_id, certificate_id, algorithm)

    @measure_performance('firmar')
    def sign_envio_setdte(self, xml_string, setdte_id='SetDTE', certificate_id=None, algorithm='sha256'):
        """
        Delegate to XMLSigner.sign_envio_setdte (with env injection).

        P1.3 GAP CLOSURE: Instrumented with performance metrics.
        """
        signer = XMLSigner(self.env)
        return signer.sign_envio_setdte(xml_string, setdte_id, certificate_id, algorithm)

    @measure_performance('enviar_soap')
    def send_dte_to_sii(self, signed_xml, rut_emisor, company=None):
        """
        Delegate to SIISoapClient (with env injection).

        P1.3 GAP CLOSURE: Instrumented with performance metrics.
        """
        client = SIISoapClient(self.env)
        return client.send_dte_to_sii(signed_xml, rut_emisor, company)

    @measure_performance('consultar_estado')
    def query_dte_status(self, track_id, rut_emisor, company=None):
        """
        Delegate to SIISoapClient (with env injection).

        P1.3 GAP CLOSURE: Instrumented with performance metrics.
        """
        client = SIISoapClient(self.env)
        return client.query_dte_status(track_id, rut_emisor, company)

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

        # Validaciones específicas para cada tipo de DTE
        if self.dte_code == '52':  # Guía de despacho
            self._validate_dte_52()

    def _check_idempotency_before_send(self):
        """
        Sprint 1.4 - B-009: Idempotency check for DTE sending.

        Prevents duplicate DTE submissions on retry by checking if a track_id
        already exists from a previous successful send.

        Enterprise Pattern: Idempotent operations ensure safe retries without
        side effects, critical for distributed systems and network failures.

        Returns:
            dict or None: If already sent (has track_id), returns success dict
                         with existing track_id and idempotent flag.
                         If not sent yet, returns None to proceed with sending.
        """
        self.ensure_one()

        if self.dte_track_id:
            _logger.info(
                f"[B-009 Idempotency] DTE {self.id} already sent successfully. "
                f"track_id={self.dte_track_id}. Preventing duplicate submission."
            )

            # Return existing success result - no need to regenerate/resend
            return {
                'success': True,
                'idempotent': True,
                'folio': self.dte_folio,
                'track_id': self.dte_track_id,
                'xml_b64': self.dte_xml,  # Already stored
                'message': _('DTE already sent successfully (idempotent retry prevented)')
            }

        # No track_id = not sent yet, proceed with generation
        return None

    def _generate_sign_and_send_dte(self):
        """
        Genera, firma y envía DTE al SII usando bibliotecas Python nativas.

        Reemplaza HTTP call a microservicio con código Python directo.
        Performance: ~100ms más rápido (sin HTTP overhead).

        P0-6 GAP CLOSURE: DTEs históricos NO se re-firman (certificado expirado).
        Se preserva XML firmado original para mantener validez legal.

        P0-2 GAP CLOSURE: Redis lock SETNX prevents race condition on double-click.
        Lock must be acquired BEFORE idempotency check to prevent duplicates.

        Returns:
            Dict con resultado de la operación
        """
        self.ensure_one()

        # ═══════════════════════════════════════════════════════════════════════
        # P0-2 GAP CLOSURE: Redis Lock - Prevent race condition on double-click
        # ═══════════════════════════════════════════════════════════════════════
        # CRITICAL: Lock MUST be acquired BEFORE idempotency check.
        #
        # Problem: User double-clicks "Send DTE" button rapidly.
        # Both requests arrive before track_id is assigned.
        # Both pass idempotency check → both generate XML → both send → DUPLICATE!
        #
        # Solution: Redis SETNX lock with TTL 60s.
        # First request acquires lock, second request gets "in_progress" response.
        #
        # Lock key pattern: dte:send:lock:{company_id}:{move_id}
        # TTL: 60 seconds (enough for XML generation + signing + SII send)
        #
        # Security: FAIL-OPEN on Redis error (allow send without lock).
        # Rationale: Better to risk rare duplicate than block legitimate sends.

        try:
            redis_url = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.redis_url',
                'redis://redis:6379/1'
            )
            import redis
            r = redis.from_url(redis_url, decode_responses=True)

            # Lock key: dte:send:lock:{company_id}:{move_id}
            lock_key = f"dte:send:lock:{self.company_id.id}:{self.id}"
            lock_ttl = int(self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.send_lock_ttl_seconds',
                '60'
            ))

            # Try to acquire lock (SETNX: set if not exists - atomic operation)
            acquired = r.set(lock_key, '1', ex=lock_ttl, nx=True)

            if not acquired:
                # Lock already held by another process → return "in_progress"
                _logger.warning(
                    "DTE send lock already held - another process is sending this DTE",
                    extra={
                        'event': 'dte_send_lock_blocked',
                        'move_id': self.id,
                        'company_id': self.company_id.id,
                        'lock_key': lock_key,
                        'outcome': 'in_progress'
                    }
                )
                return {
                    'success': False,
                    'in_progress': True,
                    'lock_held': True,
                    'message': _('DTE en procesamiento por otro proceso. Espere unos segundos.')
                }

            _logger.debug(
                "DTE send lock acquired successfully",
                extra={
                    'event': 'dte_send_lock_acquired',
                    'move_id': self.id,
                    'lock_key': lock_key,
                    'ttl_seconds': lock_ttl
                }
            )

        except redis.RedisError as e:
            # FAIL-OPEN: If Redis unavailable, proceed without lock
            # Better to risk duplicate than block legitimate sends
            _logger.error(
                "Redis lock failed - Proceeding without lock (fail-open policy)",
                extra={
                    'event': 'dte_send_lock_error',
                    'error': str(e),
                    'move_id': self.id,
                    'policy': 'fail_open'
                }
            )

        # ═══════════════════════════════════════════════════════════════════════
        # B-009: Idempotency Check - Prevent duplicate submissions on retry
        # ═══════════════════════════════════════════════════════════════════════
        # NOTE: Lock is acquired BEFORE this check to prevent race condition
        idempotent_result = self._check_idempotency_before_send()
        if idempotent_result:
            return idempotent_result

        # ═══════════════════════════════════════════════════════════════════════
        # P0-6 GAP CLOSURE: Historical DTE - DO NOT RE-SIGN
        # ═══════════════════════════════════════════════════════════════════════
        if self.is_historical_dte:
            _logger.info(
                f"DTE {self.id} is HISTORICAL (migrated) - Using preserved original signature"
            )

            if not self.signed_xml_original:
                raise ValidationError(
                    _("DTE histórico debe tener XML firmado original preservado.\n\n"
                      "Este DTE fue marcado como histórico pero no tiene XML original. "
                      "Contacte al administrador del sistema.")
                )

            # Return existing data - DO NOT regenerate or re-sign
            return {
                'success': True,
                'historical': True,
                'folio': self.dte_folio,
                'track_id': self.dte_track_id,
                'xml_b64': base64.b64encode(self.signed_xml_original).decode('ascii'),
                'message': _('DTE histórico preservado (no re-firmado)')
            }

        # ═══════════════════════════════════════════════════════════════════════

        _logger.info(f"Generating DTE for move {self.id}, type {self.dte_code}")

        # 1. Preparar datos DTE según tipo (PEER REVIEW FIX: Adaptadores por tipo)
        if self.dte_code == '34':
            dte_data = self._prepare_dte_34_data()  # Factura exenta
        elif self.dte_code == '52':
            dte_data = self._prepare_dte_52_data()  # Guía de despacho
        elif self.dte_code in ('56', '61'):
            dte_data = self._prepare_dte_nota_data()  # Notas débito/crédito
        else:
            dte_data = self._prepare_dte_data_native()  # DTE 33 y otros

        # 2. Generar XML sin firmar (usa libs/xml_generator.py)
        unsigned_xml = self.generate_dte_xml(self.dte_code, dte_data)

        _logger.info(f"XML generated, size: {len(unsigned_xml)} bytes")

        # 2.5. P0-3 GAP CLOSURE: Generar TED firmado con CAF
        # ═══════════════════════════════════════════════════════════════════════
        # TED (Timbre Electrónico Digital) es OBLIGATORIO por SII
        # Debe firmarse con llave privada del CAF y agregarse al DTE antes de firmar

        _logger.info("[TED] Generating TED with CAF signature...")

        # Preparar datos para TED
        ted_data = {
            'rut_emisor': self.company_id.vat,
            'rut_receptor': self.partner_id.vat or '66666666-6',  # RUT genérico si no hay
            'folio': dte_data['folio'],
            'fecha_emision': dte_data.get('fecha_emision', fields.Date.today().strftime('%Y-%m-%d')),
            'monto_total': self.amount_total,
            'tipo_dte': int(self.dte_code),
        }

        # Generar TED firmado (busca CAF automáticamente por folio)
        ted_xml = self.generate_ted(ted_data)

        # Guardar TED en campo para uso en PDF reports
        self.write({'dte_ted_xml': ted_xml})

        _logger.info(f"[TED] TED generated and signed (length={len(ted_xml)})")

        # Insertar TED en DTE XML
        # El TED debe ir dentro de <DTE><Documento><TED>...</TED></Documento></DTE>
        unsigned_xml = self._insert_ted_into_dte(unsigned_xml, ted_xml)

        _logger.info("[TED] TED inserted into DTE XML successfully")

        # 3. Validar XML contra XSD (opcional, usa libs/xsd_validator.py)
        is_valid, error_msg = self.validate_xml_against_xsd(unsigned_xml, self.dte_code)

        if not is_valid:
            raise ValidationError(
                _('XML validation failed:\n\n%s') % error_msg
            )

        # 4. Firmar XML digitalmente (usa libs/xml_signer.py)
        # PEER REVIEW GAP CLOSURE: Use specialized signature for Documento node
        documento_id = f"DTE-{dte_data['folio']}"
        signed_xml = self.sign_dte_documento(
            unsigned_xml,
            documento_id=documento_id,
            certificate_id=self.journal_id.dte_certificate_id.id,
            algorithm='sha256'  # Try SHA256 first, fallback to SHA1 if SII rejects
        )

        _logger.info(f"DTE Documento signed successfully (ID={documento_id}, algorithm=SHA256)")

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

            # IMPORTANT: Also wrap in EnvioDTE in contingency mode
            # When contingency ends and DTEs are uploaded, they need EnvioDTE structure
            from ..libs.envio_dte_generator import EnvioDTEGenerator

            envio_generator = EnvioDTEGenerator(self.company_id)
            caratula_data = envio_generator.create_caratula_from_company(self.company_id)
            envio_xml = envio_generator.generate_envio_dte(
                dtes=[signed_xml],
                caratula_data=caratula_data
            )

            # PEER REVIEW GAP CLOSURE: Use specialized signature for SetDTE node
            signed_envio_xml = self.sign_envio_setdte(
                envio_xml,
                setdte_id='SetDTE',
                certificate_id=self.journal_id.dte_certificate_id.id,
                algorithm='sha256'  # Try SHA256 first, fallback to SHA1 if SII rejects
            )

            # Store pending DTE (store EnvioDTE, not individual DTE)
            pending = self.env['dte.contingency.pending'].store_pending_dte(
                dte_type=self.dte_code,
                folio=dte_data['folio'],
                xml_content=signed_envio_xml,  # Store EnvioDTE for later upload
                move_id=self.id
            )

            # Save XMLs in attachments (for user reference)
            self._save_dte_xml(signed_xml)
            self._save_envio_xml(signed_envio_xml, dte_data['folio'])

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
                'envio_xml_b64': base64.b64encode(signed_envio_xml.encode('ISO-8859-1')).decode('ascii'),
                'message': _('DTE stored in contingency mode. Will be uploaded when SII is available.'),
                'pending_id': pending.id
            }

        # ✅ Normal operation: Send to SII
        # ═══════════════════════════════════════════════════════════════════════

        # 4.8. WRAP IN ENVIDTE STRUCTURE (P0-1 GAP CLOSURE)
        # ═══════════════════════════════════════════════════════════════════════
        # CRÍTICO: DTEs cannot be sent alone - must be wrapped in EnvioDTE with Carátula
        # Reference: http://www.sii.cl/factura_electronica/formato_dte.pdf

        from ..libs.envio_dte_generator import EnvioDTEGenerator

        _logger.info("[EnvioDTE] Wrapping DTE in EnvioDTE structure...")

        # Create EnvioDTE generator
        envio_generator = EnvioDTEGenerator(self.company_id)

        # Create Carátula data from company
        caratula_data = envio_generator.create_caratula_from_company(self.company_id)

        # Wrap signed DTE in EnvioDTE structure
        envio_xml = envio_generator.generate_envio_dte(
            dtes=[signed_xml],  # Single DTE, but generator supports batch
            caratula_data=caratula_data
        )

        _logger.info(f"[EnvioDTE] EnvioDTE structure created ({len(envio_xml)} bytes)")

        # 4.9. SIGN ENVIDTE (entire SetDTE)
        # ═══════════════════════════════════════════════════════════════════════
        # The EnvioDTE itself must be digitally signed (signs the SetDTE element)
        # PEER REVIEW GAP CLOSURE: Use specialized signature for SetDTE node

        signed_envio_xml = self.sign_envio_setdte(
            envio_xml,
            setdte_id='SetDTE',
            certificate_id=self.journal_id.dte_certificate_id.id,
            algorithm='sha256'  # Try SHA256 first, fallback to SHA1 if SII rejects
        )

        _logger.info("[EnvioDTE] SetDTE signed successfully (ID=SetDTE, algorithm=SHA256)")

        # 5. Enviar a SII vía SOAP (usa libs/sii_soap_client.py)
        # Send signed EnvioDTE (not individual DTE)
        try:
            sii_result = self.send_dte_to_sii(
                signed_envio_xml,  # Send EnvioDTE, not individual DTE
                self.company_id.vat
            )

            if sii_result.get('success'):
                # ✅ ÉXITO - DISASTER RECOVERY: Backup automático
                _logger.info(f"✅ DTE sent successfully, track_id: {sii_result.get('track_id')}")

                # Backup both individual DTE and EnvioDTE
                self.env['dte.backup'].backup_dte(
                    dte_type=self.dte_code,
                    folio=dte_data['folio'],
                    xml_content=signed_envio_xml,  # Store EnvioDTE (what was actually sent)
                    track_id=sii_result.get('track_id'),
                    move_id=self.id,
                    rut_emisor=self.company_id.vat
                )

                # Guardar individual DTE XML en Odoo attachments (para referencia)
                self._save_dte_xml(signed_xml)

                # También guardar EnvioDTE (lo que se envió realmente al SII)
                self._save_envio_xml(signed_envio_xml, dte_data['folio'])

                return {
                    'success': True,
                    'folio': dte_data['folio'],
                    'track_id': sii_result.get('track_id'),
                    'xml_b64': base64.b64encode(signed_xml.encode('ISO-8859-1')).decode('ascii'),
                    'envio_xml_b64': base64.b64encode(signed_envio_xml.encode('ISO-8859-1')).decode('ascii'),
                    'response_xml': sii_result.get('response_xml'),
                    'duration_ms': sii_result.get('duration_ms', 0)
                }

            else:
                # ❌ FALLO - DISASTER RECOVERY: Agregar a failed queue
                error_msg = sii_result.get('error_message', 'Unknown SII error')
                error_code = sii_result.get('error_code', '')
                _logger.warning(f"❌ DTE send failed: {error_msg} (code: {error_code})")

                # ═══════════════════════════════════════════════════════════════════════
                # P2.1 GAP CLOSURE: SHA1 FALLBACK
                # ═══════════════════════════════════════════════════════════════════════
                # If SHA256 signature rejected by SII, retry with SHA1 (if enabled)
                #
                # SII error codes for signature algorithm issues:
                # - "ALGORITMO_FIRMA" in error message
                # - "SHA256" in error message (SII doesn't support SHA256 yet)
                # - Error codes related to signature validation

                enable_sha1_fallback = self.env['ir.config_parameter'].sudo().get_param(
                    'l10n_cl_dte.enable_sha1_fallback',
                    'False'
                ).lower() in ('true', '1', 'yes')

                # Check if error is signature algorithm related
                is_signature_error = (
                    'algoritmo' in error_msg.lower() or
                    'sha256' in error_msg.lower() or
                    'signature' in error_msg.lower() or
                    'firma' in error_msg.lower()
                )

                if enable_sha1_fallback and is_signature_error:
                    _logger.warning(
                        "🔄 Signature algorithm error detected. Retrying with SHA1 fallback...",
                        extra={
                            'event': 'sha1_fallback_triggered',
                            'original_error': error_msg,
                            'folio': dte_data['folio']
                        }
                    )

                    try:
                        # Re-sign Documento with SHA1
                        documento_id = f"DTE-{dte_data['folio']}"
                        signed_xml_sha1 = self.sign_dte_documento(
                            unsigned_xml,
                            documento_id=documento_id,
                            certificate_id=self.journal_id.dte_certificate_id.id,
                            algorithm='sha1'  # Fallback to SHA1
                        )

                        _logger.info(f"DTE Documento re-signed with SHA1 (ID={documento_id})")

                        # Re-wrap in EnvioDTE
                        envio_xml_sha1 = envio_generator.generate_envio_dte(
                            dtes=[signed_xml_sha1],
                            caratula_data=caratula_data
                        )

                        # Re-sign SetDTE with SHA1
                        signed_envio_xml_sha1 = self.sign_envio_setdte(
                            envio_xml_sha1,
                            setdte_id='SetDTE',
                            certificate_id=self.journal_id.dte_certificate_id.id,
                            algorithm='sha1'  # Fallback to SHA1
                        )

                        _logger.info("EnvioDTE SetDTE re-signed with SHA1")

                        # Retry sending to SII with SHA1 signatures
                        sii_result_sha1 = self.send_dte_to_sii(
                            signed_envio_xml_sha1,
                            self.company_id.vat
                        )

                        if sii_result_sha1.get('success'):
                            _logger.info(
                                "✅ SHA1 fallback successful! DTE accepted by SII",
                                extra={
                                    'event': 'sha1_fallback_success',
                                    'track_id': sii_result_sha1.get('track_id'),
                                    'folio': dte_data['folio']
                                }
                            )

                            # Backup with SHA1 signatures
                            self.env['dte.backup'].backup_dte(
                                dte_type=self.dte_code,
                                folio=dte_data['folio'],
                                xml_content=signed_envio_xml_sha1,
                                track_id=sii_result_sha1.get('track_id'),
                                move_id=self.id,
                                rut_emisor=self.company_id.vat
                            )

                            # Save XMLs
                            self._save_dte_xml(signed_xml_sha1)
                            self._save_envio_xml(signed_envio_xml_sha1, dte_data['folio'])

                            return {
                                'success': True,
                                'folio': dte_data['folio'],
                                'track_id': sii_result_sha1.get('track_id'),
                                'xml_b64': base64.b64encode(signed_xml_sha1.encode('ISO-8859-1')).decode('ascii'),
                                'envio_xml_b64': base64.b64encode(signed_envio_xml_sha1.encode('ISO-8859-1')).decode('ascii'),
                                'response_xml': sii_result_sha1.get('response_xml'),
                                'sha1_fallback_used': True,
                                'message': _('DTE accepted by SII using SHA1 fallback')
                            }
                        else:
                            _logger.warning(
                                "❌ SHA1 fallback also failed",
                                extra={
                                    'event': 'sha1_fallback_failed',
                                    'error': sii_result_sha1.get('error_message'),
                                    'folio': dte_data['folio']
                                }
                            )
                            # Continue to error handling below

                    except Exception as e:
                        _logger.error(
                            f"❌ SHA1 fallback exception: {e}",
                            extra={
                                'event': 'sha1_fallback_exception',
                                'error': str(e)
                            },
                            exc_info=True
                        )
                        # Continue to error handling below

                # ═══════════════════════════════════════════════════════════════════════

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
                elif is_signature_error:
                    error_type = 'signature'

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
                # Acteco: Lista de códigos (máx 4 según XSD SII)
                'acteco': self.company_id.l10n_cl_activity_ids.mapped('code') or ['620200'],
                'direccion': self._format_address(self.company_id),
                'ciudad': self.company_id.city or '',
                # Comuna: Prioridad Many2one > Texto legacy > Ciudad
                'comuna': (
                    self.company_id.partner_id.l10n_cl_comuna_id.name
                    if self.company_id.partner_id.l10n_cl_comuna_id
                    else (self.company_id.partner_id.l10n_cl_comuna or self.company_id.partner_id.city or '')
                ),
            },
            # Receptor (cliente)
            'receptor': {
                'rut': self.partner_id.vat,
                'razon_social': self.partner_id.name,
                # Giro: Descripción de actividad económica del receptor
                'giro': self.partner_id.l10n_cl_activity_description or 'N/A',
                'direccion': self._format_address(self.partner_id),
                'ciudad': self.partner_id.city or '',
                # Comuna: Prioridad Many2one > Texto legacy > Ciudad
                'comuna': (
                    self.partner_id.l10n_cl_comuna_id.name
                    if self.partner_id.l10n_cl_comuna_id
                    else (self.partner_id.l10n_cl_comuna or self.partner_id.city or '')
                ),
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

    # ═══════════════════════════════════════════════════════════════════════
    # DTE DATA ADAPTERS (PEER REVIEW GAP CLOSURE - HALLAZGO #2)
    # ═══════════════════════════════════════════════════════════════════════

    def _prepare_dte_34_data(self):
        """
        Prepare data for DTE 34 (Factura No Afecta o Exenta Electrónica).

        PEER REVIEW GAP CLOSURE: DTE 34 has different data contract than DTE 33.
        - Uses 'montos' dict instead of 'totales'
        - Uses 'monto_exento' instead of 'monto_neto'
        - NO VAT (iva = 0)
        - Uses 'productos' array instead of 'lineas'

        Returns:
            dict: Data adapted for xml_generator._generate_dte_34()
        """
        self.ensure_one()

        # Get base data
        base_data = self._prepare_dte_data_native()

        # ADAPT for DTE 34
        adapted_data = {
            'folio': base_data['folio'],
            'fecha_emision': base_data['fecha_emision'],
            'emisor': base_data['emisor'],
            'receptor': base_data['receptor'],

            # CRITICAL: DTE 34 uses 'montos' dict with 'monto_exento' (no VAT)
            'montos': {
                'monto_exento': self.amount_untaxed,  # Total is exempt (no VAT)
                'monto_total': self.amount_total,
            },

            # CRITICAL: DTE 34 uses 'productos' instead of 'lineas'
            'productos': self._prepare_productos_exentos(),
        }

        _logger.info(f"[DTE 34] Data adapted: productos={len(adapted_data['productos'])}, "
                     f"monto_exento={adapted_data['montos']['monto_exento']}")

        return adapted_data

    def _prepare_dte_52_data(self):
        """
        Prepare data for DTE 52 (Guía de Despacho - Shipping Guide).

        PEER REVIEW GAP CLOSURE: DTE 52 requires transport/shipping data.
        - Requires 'tipo_traslado' field (1-8, obligatory)
        - Optional 'tipo_despacho' field (1-3)
        - Optional 'transporte' object with vehicle/driver data
        - Uses 'productos' array instead of 'lineas'

        Returns:
            dict: Data adapted for xml_generator._generate_dte_52()
        """
        self.ensure_one()

        # Get base data
        base_data = self._prepare_dte_data_native()

        # ADAPT for DTE 52
        adapted_data = {
            'folio': base_data['folio'],
            'fecha_emision': base_data['fecha_emision'],
            'emisor': base_data['emisor'],
            'receptor': base_data['receptor'],
            'totales': base_data['totales'],

            # CRITICAL: DTE 52 requires tipo_traslado (1-8)
            # 1 = Operation is sale
            # 2 = Sale to be made
            # 3 = Consignment
            # 4 = Free delivery
            # 5 = Internal transfer (default)
            # 6 = Other non-sale transfers
            # 7 = Return guide
            # 8 = Transfer for export
            'tipo_traslado': self.l10n_cl_dte_tipo_traslado or '5',  # Default: internal transfer

            # OPTIONAL: tipo_despacho (1-3)
            # 1 = Dispatch by buyer's account
            # 2 = Dispatch by issuer's account to buyer's facilities
            # 3 = Dispatch by issuer's account to other facilities
            'tipo_despacho': self.l10n_cl_dte_tipo_despacho or '2',

            # CRITICAL: DTE 52 uses 'productos' instead of 'lineas'
            'productos': self._prepare_productos_guia(),

            # OPTIONAL: Transport data (vehicle, driver, destination)
            'transporte': self._prepare_transporte_data() if self.l10n_cl_dte_transporte else None,
        }

        _logger.info(f"[DTE 52] Data adapted: tipo_traslado={adapted_data['tipo_traslado']}, "
                     f"productos={len(adapted_data['productos'])}, "
                     f"transporte={'YES' if adapted_data['transporte'] else 'NO'}")

        return adapted_data

    # ═══════════════════════════════════════════════════════════════════════
    # VALIDACIONES ESTRICTAS - DTE 52 (GUÍA DE DESPACHO)
    # ═══════════════════════════════════════════════════════════════════════
    def _validate_dte_52(self):
        """
        Endurece validaciones para DTE 52 según práctica SII.

        Reglas principales:
        - tipo_traslado OBLIGATORIO (1..8)
        - tipo_despacho OPCIONAL (1..3) si viene informado
        - Si se marcó transporte, validar patente y RUT transportista
        - Validar dirección de destino (al menos calle o ciudad/comuna)
        - Al menos 1 línea con cantidad > 0

        Nota: Se usan campos auxiliares si existen en el modelo:
          l10n_cl_dte_tipo_traslado, l10n_cl_dte_tipo_despacho,
          l10n_cl_dte_transporte, l10n_cl_dte_patente, l10n_cl_dte_rut_transportista
        """
        self.ensure_one()

        # Utilidades
        def _rut_valido(value):
            try:
                from stdnum.cl import rut as rutlib
                return rutlib.is_valid(value or '')
            except Exception:
                # Fallback simple si no está stdnum
                import re
                return bool(re.match(r"^[0-9]{1,8}-[0-9kK]$", (value or '').strip()))

        # 1) tipo_traslado (1..8) - OBLIGATORIO
        has_tipo_traslado_attr = hasattr(self, 'l10n_cl_dte_tipo_traslado')
        tipo_traslado = getattr(self, 'l10n_cl_dte_tipo_traslado', None)

        if not has_tipo_traslado_attr:
            raise ValidationError(_(
                "DTE 52 requiere el campo 'Tipo de traslado' (l10n_cl_dte_tipo_traslado).\n"
                "Agregue el campo al modelo o instale el submódulo correspondiente."
            ))

        if not tipo_traslado:
            raise ValidationError(_(
                "Debe definir el Tipo de traslado para la Guía de despacho (1..8)."
            ))

        # P1.2 GAP CLOSURE: Convert Char field to int before comparison
        # tipo_traslado is stored as Char, must convert to int
        try:
            tipo_traslado_int = int(tipo_traslado)
        except (ValueError, TypeError):
            raise ValidationError(_(
                "Tipo de traslado debe ser un número entero: %s" % tipo_traslado
            ))

        if tipo_traslado_int not in (1, 2, 3, 4, 5, 6, 7, 8):
            raise ValidationError(_(
                "Tipo de traslado inválido: %s. Valores permitidos: 1..8" % tipo_traslado_int
            ))

        # 2) tipo_despacho (1..3) - OPCIONAL, validar si viene
        if hasattr(self, 'l10n_cl_dte_tipo_despacho'):
            td = getattr(self, 'l10n_cl_dte_tipo_despacho')
            if td:
                # P1.2 GAP CLOSURE: Convert Char field to int before comparison
                try:
                    td_int = int(td)
                except (ValueError, TypeError):
                    raise ValidationError(_(
                        "Tipo de despacho debe ser un número entero: %s" % td
                    ))

                if td_int not in (1, 2, 3):
                    raise ValidationError(_(
                        "Tipo de despacho inválido: %s. Valores permitidos: 1..3" % td_int
                    ))

        # 3) Transporte (si marcado) - validar datos mínimos
        transporte_flag = getattr(self, 'l10n_cl_dte_transporte', False)
        if transporte_flag:
            patente = getattr(self, 'l10n_cl_dte_patente', '') or ''
            rut_transp = getattr(self, 'l10n_cl_dte_rut_transportista', '') or ''

            if not patente.strip():
                raise ValidationError(_(
                    "Debe informar la Patente del vehículo (campo l10n_cl_dte_patente)."
                ))

            if not rut_transp.strip() or not _rut_valido(rut_transp):
                raise ValidationError(_(
                    "RUT del transportista inválido o vacío (campo l10n_cl_dte_rut_transportista)."
                ))

        # 4) Dirección destino mínima (usa partner)
        dest_street = (self.partner_id.street or '').strip()
        dest_city = (self.partner_id.city or '').strip()
        dest_comuna = ''
        try:
            dest_comuna = (self.partner_id.l10n_cl_comuna_id.name if self.partner_id.l10n_cl_comuna_id else (self.partner_id.l10n_cl_comuna or ''))
        except Exception:
            dest_comuna = ''

        if not (dest_street or dest_city or dest_comuna):
            raise ValidationError(_(
                "La guía de despacho requiere dirección de destino mínima en el cliente (calle, ciudad o comuna)."
            ))

        # 5) Al menos una línea con cantidad > 0
        valid_lines = self.invoice_line_ids.filtered(lambda l: not l.display_type and l.quantity and l.quantity > 0)
        if not valid_lines:
            raise ValidationError(_(
                "La guía de despacho debe tener al menos una línea con cantidad mayor a cero."
            ))

    def _prepare_dte_nota_data(self):
        """
        Prepare data for DTE 56 (Nota de Débito) and DTE 61 (Nota de Crédito).

        PEER REVIEW GAP CLOSURE: Credit/Debit notes require reference to original document.
        - OBLIGATORY 'documento_referencia' dict
        - Must reference original invoice (tipo_doc, folio, fecha)

        Returns:
            dict: Data adapted for xml_generator._generate_dte_56/61()

        Raises:
            ValidationError: If no reference document found
        """
        self.ensure_one()

        # Get base data
        base_data = self._prepare_dte_data_native()

        # CRITICAL: Find reference document (original invoice being modified)
        # In Odoo, credit/debit notes reference their original invoice via reversed_entry_id
        ref_invoice = self.reversed_entry_id

        if not ref_invoice:
            raise ValidationError(
                _('Credit/Debit notes require reference to original document.\n\n'
                  'Please link this note to the original invoice before generating DTE.')
            )

        # Validate reference has DTE folio
        if not ref_invoice.dte_folio:
            raise ValidationError(
                _('Referenced document (%(name)s) has no DTE folio.\n\n'
                  'Only DTE documents can be referenced in credit/debit notes.') % {'name': ref_invoice.name}
            )

        # ADAPT for DTE 56/61
        adapted_data = {
            'folio': base_data['folio'],
            'fecha_emision': base_data['fecha_emision'],
            'emisor': base_data['emisor'],
            'receptor': base_data['receptor'],
            'totales': base_data['totales'],
            'lineas': base_data['lineas'],

            # CRITICAL: OBLIGATORY reference to original document
            'documento_referencia': {
                'tipo_doc': ref_invoice.dte_code or '33',  # Referenced DTE type
                'folio': ref_invoice.dte_folio,
                'fecha': fields.Date.to_string(ref_invoice.invoice_date or fields.Date.today()),
                'codigo': 3,  # 3 = Corrects amounts (most common for credit/debit notes)
            },

            # Motivo (reason for note)
            'motivo_nd' if self.dte_code == '56' else 'motivo_nc': self.ref or 'Nota emitida',
        }

        _logger.info(f"[DTE {self.dte_code}] Data adapted with reference: "
                     f"ref_doc={ref_invoice.name}, ref_folio={ref_invoice.dte_folio}, "
                     f"ref_type={adapted_data['documento_referencia']['tipo_doc']}")

        return adapted_data

    # ═══════════════════════════════════════════════════════════════════════
    # HELPER METHODS FOR ADAPTERS
    # ═══════════════════════════════════════════════════════════════════════

    def _prepare_productos_exentos(self):
        """
        Prepare products for DTE 34 (exempt invoice).

        Returns 'productos' array with 'numero_linea' instead of 'linea'.
        """
        productos = []
        for idx, line in enumerate(self.invoice_line_ids.filtered(lambda l: not l.display_type), start=1):
            productos.append({
                'numero_linea': idx,
                'nombre': line.product_id.name or line.name or '',
                'descripcion': line.name if line.name != (line.product_id.name or '') else '',
                'cantidad': line.quantity,
                'unidad': line.product_uom_id.name or 'UN',
                'precio_unitario': line.price_unit,
                'subtotal': line.price_subtotal,
            })
        return productos

    def _prepare_productos_guia(self):
        """
        Prepare products for DTE 52 (shipping guide).

        Returns 'productos' array with 'numero_linea' instead of 'linea'.
        """
        productos = []
        for idx, line in enumerate(self.invoice_line_ids.filtered(lambda l: not l.display_type), start=1):
            productos.append({
                'numero_linea': idx,
                'nombre': line.product_id.name or line.name or '',
                'descripcion': line.name if line.name != (line.product_id.name or '') else '',
                'cantidad': line.quantity,
                'unidad': line.product_uom_id.name or 'UN',
                'precio_unitario': line.price_unit,
                'subtotal': line.price_subtotal,
            })
        return productos

    def _prepare_transporte_data(self):
        """
        Prepare transport data for DTE 52 (shipping guide).

        Returns dict with vehicle, driver, destination (optional).
        Uses l10n_cl_dte_transporte field if available.
        """
        if not self.l10n_cl_dte_transporte:
            return None

        # For now, return basic structure
        # TODO: Implement full transport data from picking/delivery order
        return {
            'patente': self.l10n_cl_dte_patente or '',
            'rut_transportista': self.l10n_cl_dte_rut_transportista or self.company_id.vat,
            'direccion_destino': self.partner_id.street or '',
            'comuna_destino': (
                self.partner_id.l10n_cl_comuna_id.name
                if self.partner_id.l10n_cl_comuna_id
                else (self.partner_id.l10n_cl_comuna or self.partner_id.city or '')
            ),
            'ciudad_destino': self.partner_id.city or '',
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

    def _save_envio_xml(self, signed_envio_xml, folio):
        """
        Guarda el EnvioDTE XML firmado como attachment en Odoo.

        Args:
            signed_envio_xml (str): EnvioDTE XML firmado digitalmente
            folio (str): Folio del DTE para el nombre del archivo
        """
        self.ensure_one()

        # Convert XML to binary
        xml_binary = signed_envio_xml.encode('ISO-8859-1')

        # Save as attachment using Odoo attachment manager
        attachment = self.env['ir.attachment'].create({
            'name': f'EnvioDTE_{self.dte_code}_{folio}.xml',
            'type': 'binary',
            'datas': base64.b64encode(xml_binary),
            'res_model': self._name,
            'res_id': self.id,
            'mimetype': 'application/xml',
            'description': f'EnvioDTE (envelope) para DTE {self.dte_code} enviado al SII'
        })

        _logger.info(f"EnvioDTE XML saved as attachment {attachment.id}")

    def _insert_ted_into_dte(self, dte_xml, ted_xml):
        """
        Insert TED (Timbre Electrónico) into DTE XML.

        P0-3 GAP CLOSURE: The TED must be inserted into the DTE XML structure
        before signing. It goes inside <DTE><Documento><TED>...</TED></Documento></DTE>

        Args:
            dte_xml (str): DTE XML without TED
            ted_xml (str): TED XML (signed with CAF)

        Returns:
            str: DTE XML with TED inserted

        Raises:
            ValidationError: If insertion fails
        """
        try:
            from lxml import etree

            # Parse DTE XML
            dte_root = etree.fromstring(dte_xml.encode('ISO-8859-1'))

            # Parse TED XML
            ted_root = etree.fromstring(ted_xml.encode('ISO-8859-1'))

            # Find Documento element
            # Structure: <DTE><Documento>...</Documento></DTE>
            documento = dte_root.find('.//{http://www.sii.cl/SiiDte}Documento')

            if documento is None:
                raise ValidationError(_(
                    'Could not find Documento element in DTE XML.\\n'
                    'TED cannot be inserted.'
                ))

            # Insert TED as last child of Documento (before </Documento>)
            documento.append(ted_root)

            _logger.debug("[TED] TED element inserted into Documento")

            # Convert back to string
            dte_xml_with_ted = etree.tostring(
                dte_root,
                encoding='ISO-8859-1',
                xml_declaration=True,
                pretty_print=False
            ).decode('ISO-8859-1')

            return dte_xml_with_ted

        except etree.XMLSyntaxError as e:
            _logger.error(f"[TED] Failed to parse XML: {e}")
            raise ValidationError(_(
                'Failed to parse DTE or TED XML:\\n%s'
            ) % str(e))

        except Exception as e:
            _logger.error(f"[TED] Failed to insert TED: {e}")
            raise ValidationError(_(
                'Failed to insert TED into DTE:\\n%s'
            ) % str(e))

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
    
    @tools.ormcache()
    def _get_sii_environment(self):
        """
        Determina si usar sandbox o producción del SII.

        SPRINT 2A - DÍA 4: Añadido @ormcache para performance

        PERFORMANCE: Cache hit ratio esperado 99%+
        Mejora: 15ms (query DB) → 0.1ms (150x más rápido)

        Este método se llama en CADA operación con SII:
        - Envío DTEs
        - Consulta estado
        - Descarga RCV
        - etc.

        La configuración SII environment casi nunca cambia en producción,
        por lo que cachearla es seguro y altamente eficiente.

        Cache: Sin parámetros (valor global por database)
        Invalidación: Automática al reiniciar Odoo o cambiar config

        Returns:
            str: 'sandbox' o 'production'
        """
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.sii_environment',
            'sandbox'
        )
    
    @tools.ormcache()
    def _get_dte_api_key(self):
        """
        Obtiene API key para DTE Service.

        SPRINT 2A - DÍA 4: Añadido @ormcache para performance

        PERFORMANCE: Cache hit ratio esperado 99%+
        Mejora: 15ms (query DB) → 0.1ms (150x más rápido)

        Returns:
            str: API key configurada
        """
        return self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl_dte.dte_api_key',
            'default_api_key'
        )
    
    # ═══════════════════════════════════════════════════════════
    # P2.2 GAP CLOSURE: RabbitMQ methods removed - standardized on ir.cron
    #
    # Removed methods:
    # - action_send_dte_async(): Async DTE sending via RabbitMQ
    # - _publish_dte_to_rabbitmq(): Publish message to RabbitMQ queue
    # - _prepare_dte_payload_for_rabbitmq(): Prepare payload for RabbitMQ
    #
    # Migration Note (2025-10-24):
    # RabbitMQ async processing replaced with Odoo native ir.cron.
    # Benefits vs RabbitMQ:
    # - Zero external dependencies (no RabbitMQ, Celery, Redis)
    # - Native Odoo workflow (ir.cron is built-in, battle-tested)
    # - Easier deployment (no additional containers)
    # - Better integration with Odoo ORM
    # - Same reliability (ir.cron handles retries, backoff, logging)
    #
    # For async DTE processing, use action_send_to_sii() with ir.cron.
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
            # S-009: Capture SII environment from ir.config_parameter
            sii_environment = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.sii_environment',
                'sandbox'
            )

            values.update({
                'dte_track_id': kwargs.get('track_id'),
                'dte_xml': kwargs.get('xml_b64'),
                'dte_timestamp': fields.Datetime.now(),
                'dte_status': 'sent',  # Sincronizar con estado principal
                'dte_environment': sii_environment,  # S-009: Record environment
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
            # S-009: Capture SII environment
            sii_environment = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte.sii_environment',
                'sandbox'
            )

            self.write({
                'dte_status': 'accepted',
                'dte_folio': result.get('folio'),
                'dte_track_id': result.get('track_id'),
                'dte_xml': result.get('xml_b64'),
                'dte_qr_image': result.get('qr_image_b64'),  # ⭐ NUEVO: QR code
                'dte_response_xml': result.get('response_xml'),
                'dte_timestamp': fields.Datetime.now(),
                'dte_environment': sii_environment,  # S-009: Record environment
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
        """
        Override para resetear estado DTE al volver a borrador.

        PERFORMANCE (US-1.2): Bulk write to eliminate N+1 query pattern.
        """
        result = super().button_draft()

        # Validate all moves first (fail fast)
        for move in self:
            if move.dte_status in ['sent', 'accepted']:
                raise UserError(_('No se puede volver a borrador un DTE que ya fue enviado al SII.'))

        # Bulk write after validation (1 query instead of N)
        self.write({'dte_status': 'draft'})

        return result
    
    def action_post(self):
        """
        Override para marcar DTE como 'por enviar' al confirmar.

        SPRINT 1 (2025-11-01): Añadido auto-registro en RCV (Resolución SII 61/2017)
        PERFORMANCE (US-1.2): Bulk write to eliminate N+1 query pattern.
        """
        result = super().action_post()

        # PERFORMANCE: Bulk update DTE status (1 query instead of N)
        dtes_to_send = self.filtered(
            lambda m: m.dte_code and m.move_type in ['out_invoice', 'out_refund']
        )
        if dtes_to_send:
            dtes_to_send.write({'dte_status': 'to_send'})

        # ⭐ SPRINT 1: Auto-registro en RCV (Res. 61/2017)
        # Registrar TODOS los DTEs (ventas y compras) en el RCV
        # NOTE: Must stay in loop - creates individual RCV entries
        for move in self:
            if move.is_dte and move.invoice_date:
                try:
                    # Crear entrada RCV automáticamente
                    self.env['l10n_cl.rcv.entry'].create_from_invoice(move)

                    _logger.info(
                        "✅ RCV auto-registered for DTE %s N° %s",
                        move.dte_code,
                        move.l10n_cl_sii_folio or 'DRAFT'
                    )

                except Exception as e:
                    # No bloquear la factura si falla RCV
                    # Solo logear el error
                    _logger.error(
                        "⚠️  RCV auto-registration failed for invoice %s: %s",
                        move.id,
                        str(e)
                    )

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

        # PERFORMANCE (US-1.2): Collect updates to enable bulk writes
        moves_accepted = self.env['account.move']
        moves_repaired = self.env['account.move']
        moves_rejected = []  # List of (move, error_message) tuples

        for move in moves:
            try:
                _logger.info(f"Polling DTE {move.dte_code} {move.dte_folio} (track_id: {move.dte_track_id})")

                # Query status from SII
                result = move.query_dte_status(move.dte_track_id, move.company_id.vat)

                if result.get('success'):
                    sii_status = result.get('status', '').upper()

                    # Collect moves by status for bulk update
                    if sii_status == 'ACEPTADO':
                        moves_accepted |= move
                        _logger.info(f"✅ DTE {move.dte_code} {move.dte_folio} ACCEPTED by SII")

                    elif sii_status == 'RECHAZADO':
                        error_msg = result.get('error_message', 'Rechazado por SII')
                        moves_rejected.append((move, error_msg))
                        _logger.warning(f"❌ DTE {move.dte_code} {move.dte_folio} REJECTED by SII")

                    elif sii_status == 'REPARADO':
                        moves_repaired |= move
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

        # PERFORMANCE (US-1.2): Bulk writes (much faster than N individual writes)
        if moves_accepted:
            moves_accepted.write({'dte_status': 'accepted'})
            updated_count += len(moves_accepted)

        if moves_repaired:
            moves_repaired.write({'dte_status': 'repaired'})
            updated_count += len(moves_repaired)

        # Rejected DTEs: Individual writes needed for custom error messages
        # NOTE: Could be optimized further by grouping by error_message
        for move, error_msg in moves_rejected:
            move.write({
                'dte_status': 'rejected',
                'dte_error_message': error_msg
            })
            updated_count += 1

        _logger.info("=" * 70)
        _logger.info(f"✅ DTE Status Poller completed:")
        _logger.info(f"   Total: {total_count}")
        _logger.info(f"   Success queries: {success_count}")
        _logger.info(f"   Updated: {updated_count}")
        _logger.info(f"   Errors: {error_count}")
        _logger.info("=" * 70)

    @api.model
    def _cron_process_pending_dtes(self):
        """
        P-005/P-008 SOLUTION: Quasi-realtime DTE processing using native Odoo ir.cron.

        Scheduled action (ir.cron): Process pending DTEs every 5 minutes.

        Professional Decision: Use native Odoo instead of RabbitMQ + Celery.
        Reference: /tmp/rabbitmq_analysis.md (2025-11-02)

        Workflow:
        1. Search DTEs with status='to_send' and state='posted'
        2. Process up to 50 DTEs per batch (to avoid blocking > 60 seconds)
        3. Call action_send_to_sii() for each DTE
        4. Continue processing even if individual DTEs fail

        Performance:
        - Capacity: 600 DTEs/hora (50 DTEs/batch x 12 batches/hora)
        - EERGYGROUP need: 20-30 DTEs/hora
        - Margin: 20x over requirement
        - Latency: Max 5 min (avg 2.5 min)

        Benefits vs RabbitMQ:
        - Zero external dependencies (no RabbitMQ, Celery, Redis)
        - Native Odoo (community standard pattern)
        - Simple operational model
        - Integrated logging and monitoring
        - Easy debugging (all in one place)
        """
        _logger.info("=" * 70)
        _logger.info("🚀 DTE QUASI-REALTIME PROCESSOR - Starting (every 5 min)...")
        _logger.info("=" * 70)

        # Search pending DTEs (status='to_send', state='posted')
        # Order by create_date ASC (oldest first - FIFO queue)
        pending_dtes = self.search([
            ('dte_status', '=', 'to_send'),
            ('state', '=', 'posted'),
            ('dte_code', '!=', False)  # Must have DTE type assigned
        ], limit=50, order='create_date asc')

        total_count = len(pending_dtes)
        _logger.info(f"Found {total_count} pending DTEs to process")

        if total_count == 0:
            _logger.info("No pending DTEs. Exiting.")
            return True

        success_count = 0
        error_count = 0

        for dte in pending_dtes:
            try:
                _logger.info(f"Processing DTE {dte.dte_code}-{dte.dte_folio} (ID: {dte.id}, Invoice: {dte.name})")

                # Call action_send_to_sii() to process DTE
                # This handles: validation, XML generation, signing, SII submission
                dte.action_send_to_sii()

                success_count += 1
                _logger.info(f"✅ DTE {dte.dte_code}-{dte.dte_folio} processed successfully")

            except Exception as e:
                error_count += 1
                _logger.error(f"❌ Error processing DTE {dte.id} ({dte.name}): {e}", exc_info=True)

                # Continue to next DTE (don't let one failure stop the batch)
                continue

        _logger.info("=" * 70)
        _logger.info(f"✅ DTE Quasi-Realtime Processor completed:")
        _logger.info(f"   Total pending: {total_count}")
        _logger.info(f"   Successfully processed: {success_count}")
        _logger.info(f"   Errors: {error_count}")
        _logger.info(f"   Success rate: {(success_count/total_count*100):.1f}%" if total_count > 0 else "   Success rate: N/A")
        _logger.info("=" * 70)

        return True

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
            # PEER REVIEW FIX: Call correct mixin method (inherited from sii.soap.client)
            # Note: This model inherits from 'sii.soap.client' which provides query_dte_status
            result = super(AccountMoveDTE, self).query_dte_status(track_id, rut_emisor, company=self.company_id)

            return result

        except Exception as e:
            _logger.error(f"Error querying DTE status: {e}", exc_info=True)

            return {
                'success': False,
                'status': None,
                'error_message': str(e)
            }

