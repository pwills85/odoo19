# -*- coding: utf-8 -*-
"""
DTE Inbox Model
===============

Modelo para gestionar DTEs recibidos de proveedores.

Based on Odoo 18: l10n_cl_fe/models/mail_dte.py (450 LOC)
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
import requests
import json
import logging
from datetime import datetime
import base64
from lxml import etree

# S-005: Protección XXE (Gap Closure P0)
from odoo.addons.l10n_cl_dte.libs.safe_xml_parser import fromstring_safe

# SPRINT 4 (2025-10-24): Import native validators
from ..libs.dte_structure_validator import DTEStructureValidator
from ..libs.ted_validator import TEDValidator

_logger = logging.getLogger(__name__)


class DTEInbox(models.Model):
    _name = 'dte.inbox'
    _description = 'Received DTEs Inbox'
    _order = 'received_date desc'
    _inherit = [
        'mail.thread',
        'mail.activity.mixin',
        'dte.ai.client'  # SPRINT 4 (2025-10-24): AI-powered validation
    ]

    # ═══════════════════════════════════════════════════════════
    # FIELDS - IDENTIFICACIÓN
    # ═══════════════════════════════════════════════════════════

    active = fields.Boolean(
        string='Active',
        default=True,
        help='Set to False to archive this DTE'
    )

    name = fields.Char(
        string='Name',
        compute='_compute_name',
        store=True
    )

    folio = fields.Char(
        string='Folio',
        required=True,
        tracking=True
    )

    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('34', 'Liquidación Honorarios'),
        ('39', 'Boleta Electrónica'),
        ('41', 'Boleta Exenta'),
        ('46', 'Factura Compra Electrónica'),
        ('52', 'Guía de Despacho'),
        ('56', 'Nota de Débito'),
        ('61', 'Nota de Crédito'),
        ('70', 'Boleta Honorarios Electrónica'),
    ], string='DTE Type', required=True, tracking=True)

    # ═══════════════════════════════════════════════════════════
    # FIELDS - EMISOR (SUPPLIER)
    # ═══════════════════════════════════════════════════════════

    partner_id = fields.Many2one(
        'res.partner',
        string='Supplier',
        tracking=True
    )

    emisor_rut = fields.Char(
        string='Emisor RUT',
        required=True
    )

    emisor_name = fields.Char(
        string='Emisor Name',
        required=True
    )

    emisor_address = fields.Char('Emisor Address')
    emisor_city = fields.Char('Emisor City')
    emisor_phone = fields.Char('Emisor Phone')
    emisor_email = fields.Char('Emisor Email')

    # ═══════════════════════════════════════════════════════════
    # FIELDS - DATOS DTE
    # ═══════════════════════════════════════════════════════════

    fecha_emision = fields.Date(
        string='Emission Date',
        required=True,
        tracking=True
    )

    monto_neto = fields.Monetary(
        string='Net Amount',
        currency_field='currency_id'
    )

    monto_iva = fields.Monetary(
        string='IVA',
        currency_field='currency_id'
    )

    monto_exento = fields.Monetary(
        string='Exempt Amount',
        currency_field='currency_id'
    )

    monto_total = fields.Monetary(
        string='Total Amount',
        currency_field='currency_id',
        required=True,
        tracking=True
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Currency',
        default=lambda self: self.env.ref('base.CLP')
    )

    # ═══════════════════════════════════════════════════════════
    # FIELDS - XML Y DATOS
    # ═══════════════════════════════════════════════════════════

    raw_xml = fields.Text(
        string='Raw XML',
        required=True
    )

    parsed_data = fields.Text(
        string='Parsed Data (JSON)',
        help='Structured DTE data in JSON format'
    )

    # ═══════════════════════════════════════════════════════════
    # FIELDS - ESTADO
    # ═══════════════════════════════════════════════════════════

    state = fields.Selection([
        ('new', 'New'),
        ('validated', 'Validated'),
        ('matched', 'Matched with PO'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('claimed', 'Claimed'),
        ('invoiced', 'Invoice Created'),
        ('error', 'Error'),
    ], string='State', default='new', required=True, tracking=True)

    # ═══════════════════════════════════════════════════════════
    # FIELDS - MATCHING
    # ═══════════════════════════════════════════════════════════

    purchase_order_id = fields.Many2one(
        'purchase.order',
        string='Matched Purchase Order',
        tracking=True
    )

    po_match_confidence = fields.Float(
        string='PO Match Confidence',
        help='AI confidence score for PO matching (0-100)'
    )

    invoice_id = fields.Many2one(
        'account.move',
        string='Created Invoice',
        tracking=True
    )

    # ═══════════════════════════════════════════════════════════
    # FIELDS - COMMERCIAL RESPONSE
    # ═══════════════════════════════════════════════════════════

    response_code = fields.Selection([
        ('0', 'Accept Document'),
        ('1', 'Reject Document'),
        ('2', 'Claim - Accept with Observations'),
    ], string='Commercial Response')

    response_reason = fields.Text('Response Reason')
    response_sent = fields.Boolean('Response Sent', default=False)
    response_date = fields.Datetime('Response Sent Date')
    response_track_id = fields.Char('SII Track ID')

    # ═══════════════════════════════════════════════════════════
    # FIELDS - METADATA
    # ═══════════════════════════════════════════════════════════

    received_date = fields.Datetime(
        string='Received Date',
        default=fields.Datetime.now,
        required=True
    )

    received_via = fields.Selection([
        ('email', 'Email (IMAP)'),
        ('sii', 'SII Download'),
        ('manual', 'Manual Upload'),
    ], string='Received Via', default='email')

    processed_date = fields.Datetime('Processed Date')

    fecha_recepcion_sii = fields.Datetime(
        string='Fecha Recepción SII',
        default=fields.Datetime.now,
        required=True,
        help='Fecha y hora en que se recibió el DTE desde el SII (plazo legal 8 días).'
    )

    digest_value = fields.Char(
        string='Digest XML',
        help='Valor Digest del Documento (Referencia/ DigestValue) para respuesta comercial.'
    )

    envio_dte_id = fields.Char(
        string='ID EnvioDTE',
        help='Identificador del SetDTE/EnvioDTE recibido.'
    )

    documento_signature = fields.Text(
        string='Firma Digital Documento',
        help='Nodo <ds:Signature> del Documento DTE para verificación criptográfica.'
    )

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            raw_xml = vals.get('raw_xml')
            if raw_xml and not vals.get('digest_value'):
                try:
                    parsed = self._parse_dte_xml(raw_xml)
                except Exception as exc:
                    _logger.warning("Failed to enrich DTE metadata during create: %s", exc)
                else:
                    vals.setdefault('digest_value', parsed.get('digest_value'))
                    vals.setdefault('envio_dte_id', parsed.get('envio_dte_id'))
                    vals.setdefault('documento_signature', parsed.get('documento_signature'))
                    vals.setdefault(
                        'fecha_recepcion_sii',
                        fields.Datetime.to_string(fields.Datetime.now())
                    )
        return super().create(vals_list)

    validation_errors = fields.Text('Validation Errors')
    validation_warnings = fields.Text('Validation Warnings')

    # ═══════════════════════════════════════════════════════════
    # FIELDS - AI-POWERED VALIDATION (SPRINT 4 - 2025-10-24)
    # ═══════════════════════════════════════════════════════════

    ai_validated = fields.Boolean(
        string='AI Validated',
        default=False,
        help='True if DTE was validated by AI Service'
    )

    ai_confidence = fields.Float(
        string='AI Confidence',
        digits=(5, 2),
        help='AI confidence score (0-100)'
    )

    ai_recommendation = fields.Selection([
        ('accept', 'Accept'),
        ('review', 'Review Manually'),
        ('reject', 'Reject'),
    ], string='AI Recommendation')

    ai_anomalies = fields.Text(
        string='AI Detected Anomalies',
        help='Anomalies detected by AI (semantic, amounts, etc.)'
    )

    native_validation_passed = fields.Boolean(
        string='Native Validation Passed',
        default=False,
        help='True if passed native validation (structure, RUT, TED, etc.)'
    )

    ted_validated = fields.Boolean(
        string='TED Validated',
        default=False,
        help='True if TED (Timbre Electrónico) validation passed'
    )

    company_id = fields.Many2one(
        'res.company',
        string='Company',
        default=lambda self: self.env.company,
        required=True
    )

    # ═══════════════════════════════════════════════════════════
    # COMPUTE METHODS
    # ═══════════════════════════════════════════════════════════

    @api.depends('dte_type', 'folio')
    def _compute_name(self):
        """Compute display name."""
        for record in self:
            if record.dte_type and record.folio:
                record.name = f"DTE {record.dte_type} - {record.folio}"
            else:
                record.name = "New DTE"

    # ═══════════════════════════════════════════════════════════
    # EMAIL PROCESSING (SPRINT 4 - 2025-10-25)
    # ═══════════════════════════════════════════════════════════

    @api.model
    def message_process(self, msg_dict, custom_values=None):
        """
        Process incoming email from fetchmail_server.

        Called automatically by Odoo's native fetchmail when email arrives from dte@sii.cl.

        This method implements the Odoo standard pattern for email-enabled models
        (models inheriting from mail.thread).

        Flow:
        1. Extract XML attachments from email
        2. Parse XML to extract DTE data
        3. Search for supplier by RUT
        4. Create dte.inbox record in 'new' state
        5. Post message in chatter

        Args:
            msg_dict (dict): Email message dictionary with keys:
                - subject (str): Email subject
                - from (str): Sender email
                - to (str): Recipient email
                - date (datetime): Email date
                - body (str): Email body (HTML or plain text)
                - attachments (list): List of tuples (filename, content_base64)
                - message_id (str): Email message ID

            custom_values (dict, optional): Additional values to set on record

        Returns:
            int: ID of created dte.inbox record (required by fetchmail)
                 Returns False if processing failed

        Raises:
            Does NOT raise exceptions - creates error record instead to prevent
            email from being lost.

        References:
            - Odoo fetchmail: odoo/addons/fetchmail/models/fetchmail.py
            - mail.thread: odoo/addons/mail/models/mail_thread.py
            - Architecture doc: ROUTING_EMAIL_TO_AI_MICROSERVICE_COMPLETE_FLOW.md
        """
        _logger.info(f"📧 Processing incoming DTE email: {msg_dict.get('subject', 'No subject')}")

        # 1. Extract XML attachments
        xml_attachments = []
        for attachment_tuple in msg_dict.get('attachments', []):
            # attachment_tuple can be (filename, content) or just content
            if isinstance(attachment_tuple, tuple):
                filename, content_base64 = attachment_tuple
            else:
                # Fallback if format is different
                _logger.warning(f"Unexpected attachment format: {type(attachment_tuple)}")
                continue

            # Check if it's an XML file
            if filename and filename.lower().endswith('.xml'):
                try:
                    # Decode base64 content
                    xml_string = base64.b64decode(content_base64).decode('ISO-8859-1')
                    xml_attachments.append({
                        'filename': filename,
                        'content': xml_string
                    })
                    _logger.info(f"✅ Extracted XML attachment: {filename} ({len(xml_string)} bytes)")
                except Exception as e:
                    _logger.error(f"Failed to decode attachment {filename}: {e}")
                    continue

        if not xml_attachments:
            _logger.warning(f"❌ No XML attachments found in email from {msg_dict.get('from')}")
            # Create error record to track this email
            error_record = self.create({
                'name': f"Error: {msg_dict.get('subject', 'Sin XML adjunto')}",
                'folio': 'ERROR',
                'dte_type': '33',  # Default
                'emisor_rut': '00000000-0',
                'emisor_name': msg_dict.get('from', 'Unknown'),
                'fecha_emision': fields.Date.today(),
                'monto_total': 0,
                'monto_neto': 0,
                'monto_iva': 0,
                'state': 'error',
                'validation_errors': f"No XML attachments found in email\n\nSubject: {msg_dict.get('subject')}\nFrom: {msg_dict.get('from')}",
                'received_date': fields.Datetime.now(),
                'received_via': 'email'
            })
            return error_record.id

        # 2. Parse first XML (normally only one DTE per email)
        xml_data = xml_attachments[0]

        try:
            email_date = msg_dict.get('date')
            if isinstance(email_date, datetime):
                reception_dt = email_date
            else:
                try:
                    reception_dt = fields.Datetime.from_string(email_date) if email_date else None
                except Exception:
                    reception_dt = None
            if not reception_dt:
                reception_dt = fields.Datetime.now()
            reception_dt_str = fields.Datetime.to_string(reception_dt)

            # Parse DTE XML
            parsed_data = self._parse_dte_xml(xml_data['content'])

            # 3. Search for supplier by RUT
            partner = self.env['res.partner'].search([
                ('vat', '=', parsed_data['rut_emisor'])
            ], limit=1)

            if not partner:
                _logger.warning(f"⚠️ Supplier not found for RUT {parsed_data['rut_emisor']}, creating without partner")

            # 4. Check if DTE already exists (avoid duplicates)
            existing = self.search([
                ('emisor_rut', '=', parsed_data['rut_emisor']),
                ('dte_type', '=', str(parsed_data['tipo_dte'])),
                ('folio', '=', parsed_data['folio']),
            ], limit=1)

            if existing:
                _logger.info(f"ℹ️ DTE already exists: {existing.name}, updating from email")
                # Update raw_xml if it was missing
                write_vals = {}
                if not existing.raw_xml:
                    write_vals['raw_xml'] = xml_data['content']
                if parsed_data.get('digest_value') and not existing.digest_value:
                    write_vals['digest_value'] = parsed_data['digest_value']
                if parsed_data.get('envio_dte_id') and not existing.envio_dte_id:
                    write_vals['envio_dte_id'] = parsed_data['envio_dte_id']
                if parsed_data.get('documento_signature') and not existing.documento_signature:
                    write_vals['documento_signature'] = parsed_data['documento_signature']
                if reception_dt_str and not existing.fecha_recepcion_sii:
                    write_vals['fecha_recepcion_sii'] = reception_dt_str
                if write_vals:
                    existing.write(write_vals)
                return existing.id

            # 5. Create dte.inbox record
            vals = {
                'folio': parsed_data['folio'],
                'dte_type': str(parsed_data['tipo_dte']),
                'fecha_emision': parsed_data['fecha_emision'],
                'emisor_rut': parsed_data['rut_emisor'],
                'emisor_name': parsed_data['razon_social_emisor'],
                'emisor_address': parsed_data.get('direccion_emisor', ''),
                'emisor_city': parsed_data.get('ciudad_emisor', ''),
                'emisor_email': parsed_data.get('email_emisor', ''),
                'partner_id': partner.id if partner else False,
                'monto_total': parsed_data['monto_total'],
                'monto_neto': parsed_data['monto_neto'],
                'monto_iva': parsed_data['monto_iva'],
                'monto_exento': parsed_data.get('monto_exento', 0.0),
                'raw_xml': xml_data['content'],
                'parsed_data': json.dumps(parsed_data, ensure_ascii=False),
                'state': 'new',
                'received_date': fields.Datetime.now(),
                'fecha_recepcion_sii': reception_dt_str,
                'received_via': 'email',
                'native_validation_passed': False,
                'ai_validated': False,
                'digest_value': parsed_data.get('digest_value'),
                'envio_dte_id': parsed_data.get('envio_dte_id'),
                'documento_signature': parsed_data.get('documento_signature'),
            }

            # Merge custom_values if provided
            if custom_values:
                vals.update(custom_values)

            # Create record
            inbox_record = self.create(vals)

            # 6. Post message in chatter
            inbox_record.message_post(
                body=_(
                    '<p><strong>DTE received via email</strong></p>'
                    '<ul>'
                    '<li><strong>From:</strong> %(from)s</li>'
                    '<li><strong>Subject:</strong> %(subject)s</li>'
                    '<li><strong>Attachment:</strong> %(filename)s</li>'
                    '<li><strong>Supplier:</strong> %(supplier)s</li>'
                    '</ul>'
                ) % {
                    'from': msg_dict.get('from', 'Unknown'),
                    'subject': msg_dict.get('subject', 'No subject'),
                    'filename': xml_data['filename'],
                    'supplier': partner.name if partner else 'Not found (RUT: %s)' % parsed_data['rut_emisor']
                },
                subject=msg_dict.get('subject'),
                message_type='comment'
            )

            _logger.info(
                f"✅ DTE inbox record created: ID={inbox_record.id}, "
                f"Type={inbox_record.dte_type}, Folio={inbox_record.folio}, "
                f"Supplier={partner.name if partner else 'Unknown'}, "
                f"Amount=${inbox_record.monto_total:,.0f}"
            )

            return inbox_record.id

        except Exception as e:
            _logger.error(f"❌ Error processing DTE email: {e}", exc_info=True)

            # Create error record to preserve the email data
            error_record = self.create({
                'name': f"Parse Error: {msg_dict.get('subject', 'Unknown')}",
                'folio': 'PARSE_ERROR',
                'dte_type': '33',  # Default
                'emisor_rut': '00000000-0',
                'emisor_name': msg_dict.get('from', 'Unknown'),
                'fecha_emision': fields.Date.today(),
                'monto_total': 0,
                'monto_neto': 0,
                'monto_iva': 0,
                'state': 'error',
                'validation_errors': f"XML parsing failed: {str(e)}\n\nSee server logs for details.",
                'raw_xml': xml_data['content'],  # Preserve XML for manual review
                'received_date': fields.Datetime.now(),
                'received_via': 'email'
            })

            return error_record.id

    def _parse_dte_xml(self, xml_string):
        """
        Parse DTE XML and extract relevant data.

        Uses lxml to parse Chilean SII DTE XML format.

        Args:
            xml_string (str): XML content in ISO-8859-1 encoding

        Returns:
            dict: Parsed DTE data with keys:
                - tipo_dte (str): DTE type code (33, 34, etc.)
                - folio (str): DTE folio number
                - fecha_emision (date): Emission date
                - rut_emisor (str): Supplier RUT (formatted XX.XXX.XXX-X)
                - razon_social_emisor (str): Supplier name
                - giro_emisor (str): Supplier business activity
                - direccion_emisor (str): Supplier address
                - ciudad_emisor (str): Supplier city
                - monto_neto (float): Net amount
                - monto_iva (float): VAT amount
                - monto_total (float): Total amount
                - monto_exento (float): Exempt amount
                - lineas (list): Detail lines

        Raises:
            Exception: If XML parsing fails
        """
        try:
            # S-005: Parse XML con protección XXE (DTE recibido de proveedor - fuente no confiable)
            root = fromstring_safe(xml_string.encode('ISO-8859-1'))

            namespaces = {k if k else 'sii': v for k, v in root.nsmap.items() if v}
            if 'ds' not in namespaces:
                namespaces['ds'] = 'http://www.w3.org/2000/09/xmldsig#'

            # Helper function to extract text
            def extract_text(xpath, default=''):
                element = root.find(xpath)
                return element.text.strip() if element is not None and element.text else default

            # Extract header data
            tipo_dte = extract_text('.//IdDoc/TipoDTE')
            folio = extract_text('.//IdDoc/Folio')
            fecha_str = extract_text('.//IdDoc/FchEmis')

            # Parse date (format: YYYY-MM-DD)
            fecha_emision = datetime.strptime(fecha_str, '%Y-%m-%d').date() if fecha_str else fields.Date.today()

            # Extract supplier (emisor) data
            rut_emisor = extract_text('.//Emisor/RUTEmisor')
            razon_social_emisor = extract_text('.//Emisor/RznSoc')
            giro_emisor = extract_text('.//Emisor/GiroEmis')
            direccion_emisor = extract_text('.//Emisor/DirOrigen')
            ciudad_emisor = extract_text('.//Emisor/CmnaOrigen')

            # Extract envelope metadata
            envio_dte_id = None
            setdte_element = None
            documento_element = root.find('.//sii:Documento', namespaces) or root.find('.//Documento')

            if root.tag.endswith('EnvioDTE'):
                envio_dte_id = root.get('ID')
                setdte_element = root.find('.//sii:SetDTE', namespaces) or root.find('.//SetDTE')
            else:
                setdte_element = root.find('.//sii:SetDTE', namespaces) or root.find('.//SetDTE')

            if setdte_element is not None and not envio_dte_id:
                envio_dte_id = setdte_element.get('ID')

            # Extract digital signature info
            signature_element = None
            if documento_element is not None:
                signature_element = documento_element.find('.//ds:Signature', namespaces) or documento_element.find(
                    './/{http://www.w3.org/2000/09/xmldsig#}Signature'
                )
            if signature_element is None:
                signature_element = root.find('.//ds:Signature', namespaces) or root.find(
                    './/{http://www.w3.org/2000/09/xmldsig#}Signature'
                )
            digest_value = None
            signature_xml = None

            if signature_element is not None:
                digest_element = signature_element.find('.//ds:DigestValue', namespaces) or signature_element.find(
                    './/{http://www.w3.org/2000/09/xmldsig#}DigestValue'
                )
                if digest_element is not None and digest_element.text:
                    digest_value = digest_element.text.strip()
                signature_xml = etree.tostring(signature_element, encoding='unicode')

            # Extract amounts
            monto_neto = float(extract_text('.//Totales/MntNeto', '0'))
            monto_iva = float(extract_text('.//Totales/IVA', '0'))
            monto_total = float(extract_text('.//Totales/MntTotal', '0'))
            monto_exento = float(extract_text('.//Totales/MntExe', '0'))

            # Extract detail lines
            lineas = []
            detalle_elements = root.findall('.//Detalle')
            for detalle in detalle_elements:
                linea = {
                    'numero': detalle.findtext('NroLinDet', ''),
                    'nombre': detalle.findtext('NmbItem', ''),
                    'descripcion': detalle.findtext('DscItem', ''),
                    'cantidad': float(detalle.findtext('QtyItem', '0')),
                    'precio_unitario': float(detalle.findtext('PrcItem', '0')),
                    'monto_total': float(detalle.findtext('MontoItem', '0')),
                }
                lineas.append(linea)

            return {
                'tipo_dte': tipo_dte,
                'folio': folio,
                'fecha_emision': fecha_emision,
                'rut_emisor': rut_emisor,
                'razon_social_emisor': razon_social_emisor,
                'giro_emisor': giro_emisor,
                'direccion_emisor': direccion_emisor,
                'ciudad_emisor': ciudad_emisor,
                'monto_neto': monto_neto,
                'monto_iva': monto_iva,
                'monto_total': monto_total,
                'monto_exento': monto_exento,
                'lineas': lineas,
                'items': lineas,
                'digest_value': digest_value,
                'envio_dte_id': envio_dte_id,
                'documento_signature': signature_xml,
            }

        except Exception as e:
            _logger.error(f"XML parsing failed: {e}", exc_info=True)
            raise Exception(f"Failed to parse DTE XML: {str(e)}")

    # ═══════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════

    def action_validate(self):
        """
        SPRINT 4 (2025-10-24): Dual Validation (Native + AI).

        Validación optimizada en 2 fases:
        1. NATIVE (rápida, sin costo): Estructura, RUT, montos, TED
        2. AI (semántica, anomalías): Solo si pasa fase 1

        Luego intenta matching PO usando AI.

        Returns:
            Action notification or raises UserError
        """
        self.ensure_one()

        if self.state != 'new':
            raise UserError(_('Only new DTEs can be validated'))

        _logger.info(f"🔍 Starting DUAL validation for DTE {self.name}")

        errors = []
        warnings = []

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 1: NATIVE VALIDATION (Fast, no AI cost)
        # ═══════════════════════════════════════════════════════════════════════

        try:
            parsed_data = json.loads(self.parsed_data) if self.parsed_data else {}

            # Preparar datos para validadores
            dte_data = {
                'tipo_dte': self.dte_type,
                'folio': self.folio,
                'fecha_emision': self.fecha_emision,
                'rut_emisor': self.emisor_rut,
                'razon_social_emisor': self.emisor_name,
                'monto_total': float(self.monto_total),
                'monto_neto': float(self.monto_neto),
                'monto_iva': float(self.monto_iva),
                'monto_exento': float(self.monto_exento)
            }

            # 1.1. Structure validation
            structure_result = DTEStructureValidator.validate_dte(
                dte_data=dte_data,
                xml_string=self.raw_xml
            )

            if not structure_result['valid']:
                errors.extend(structure_result['errors'])
                _logger.warning(f"❌ Native structure validation FAILED: {len(errors)} errors")
            else:
                _logger.info("✅ Native structure validation PASSED")

            warnings.extend(structure_result.get('warnings', []))

            # 1.2. TED validation (SPRINT 2A: Ahora incluye validación firma RSA)
            if self.raw_xml:
                ted_result = TEDValidator.validate_ted(
                    xml_string=self.raw_xml,
                    dte_data=dte_data,
                    env=self.env  # SPRINT 2A: Pasar env para validación firma
                )

                if ted_result['valid']:
                    self.ted_validated = True
                    _logger.info("✅ TED validation PASSED (including RSA signature)")
                else:
                    errors.extend(ted_result['errors'])
                    _logger.warning(f"❌ TED validation FAILED")

                warnings.extend(ted_result.get('warnings', []))

            # Update native validation flag
            self.native_validation_passed = len(errors) == 0

            # Si falla validación nativa → STOP
            if not self.native_validation_passed:
                self.validation_errors = '\n'.join(errors)
                self.validation_warnings = '\n'.join(warnings) if warnings else False
                self.state = 'error'
                self.processed_date = fields.Datetime.now()

                raise UserError(
                    _('Native validation failed:\n\n%s') % '\n'.join(errors)
                )

        except UserError:
            raise  # Re-raise UserError
        except Exception as e:
            _logger.error(f"Native validation exception: {e}", exc_info=True)
            self.state = 'error'
            self.validation_errors = f"Native validation error: {str(e)}"
            raise UserError(_('Validation error: %s') % str(e))

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 2: AI VALIDATION (Semantic, anomalies)
        # ═══════════════════════════════════════════════════════════════════════

        try:
            # Get vendor history for anomaly detection
            vendor_history = self._get_vendor_history()

            # AI validation (usa método heredado de dte.ai.client)
            ai_result = self.validate_received_dte(
                dte_data=dte_data,
                vendor_history=vendor_history
            )

            # Save AI results
            self.ai_validated = True
            self.ai_confidence = ai_result.get('confidence', 0)
            self.ai_recommendation = ai_result.get('recommendation', 'review')

            ai_anomalies = ai_result.get('anomalies', [])
            ai_warnings = ai_result.get('warnings', [])

            if ai_anomalies:
                self.ai_anomalies = '\n'.join(ai_anomalies)
                warnings.extend(ai_anomalies)

            warnings.extend(ai_warnings)

            _logger.info(
                f"✅ AI validation completed: confidence={self.ai_confidence:.1f}%, "
                f"recommendation={self.ai_recommendation}"
            )

        except Exception as e:
            _logger.warning(f"AI validation failed (non-blocking): {e}")
            # AI validation failure is non-blocking
            self.ai_validated = False
            self.ai_recommendation = 'review'
            warnings.append(f"AI validation unavailable: {str(e)[:50]}")

        # ═══════════════════════════════════════════════════════════════════════
        # FASE 3: PO MATCHING (AI-powered)
        # ═══════════════════════════════════════════════════════════════════════

        try:
            # Get pending POs
            pending_pos = self._get_pending_purchase_orders()

            if pending_pos:
                # Preparar datos para matching
                dte_received_data = {
                    'partner_id': self.partner_id.id if self.partner_id else None,
                    'partner_vat': self.emisor_rut,
                    'partner_name': self.emisor_name,
                    'total_amount': float(self.monto_total),
                    'date': self.fecha_emision.isoformat() if self.fecha_emision else None,
                    'reference': self.folio,
                    'lines': parsed_data.get('items', [])
                }

                # AI PO matching (usa método heredado de dte.ai.client)
                match_result = self.match_purchase_order_ai(
                    dte_received_data=dte_received_data,
                    pending_pos=pending_pos
                )

                if match_result.get('matched_po_id'):
                    # PO match found
                    self.purchase_order_id = match_result['matched_po_id']
                    self.po_match_confidence = match_result.get('confidence', 0)
                    self.state = 'matched'

                    self.message_post(
                        body=_('✅ Matched with PO: %s (AI Confidence: %.1f%%)') % (
                            self.purchase_order_id.name,
                            self.po_match_confidence
                        )
                    )

                    _logger.info(f"✅ PO matching: {self.purchase_order_id.name} ({self.po_match_confidence:.1f}%)")
                else:
                    # No match
                    self.state = 'validated'
                    _logger.info("No PO match found")
            else:
                # No pending POs
                self.state = 'validated'
                _logger.info("No pending POs for matching")

        except Exception as e:
            _logger.warning(f"PO matching failed (non-blocking): {e}")
            # PO matching failure is non-blocking
            self.state = 'validated'

        # ═══════════════════════════════════════════════════════════════════════
        # FINALIZE
        # ═══════════════════════════════════════════════════════════════════════

        self.validation_warnings = '\n'.join(warnings) if warnings else False
        self.processed_date = fields.Datetime.now()

        # Return notification
        notification_type = 'success'
        title = _('DTE Validated Successfully')
        message_parts = [
            f"Native validation: ✅ PASSED",
            f"TED validation: {'✅ PASSED' if self.ted_validated else '⚠️ SKIPPED'}",
        ]

        if self.ai_validated:
            message_parts.append(
                f"AI confidence: {self.ai_confidence:.1f}% ({self.ai_recommendation})"
            )

        if self.state == 'matched':
            message_parts.append(
                f"PO matched: {self.purchase_order_id.name} ({self.po_match_confidence:.1f}%)"
            )

        if warnings:
            notification_type = 'warning'
            message_parts.append(f"\n⚠️ Warnings: {len(warnings)}")

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': title,
                'message': '\n'.join(message_parts),
                'type': notification_type,
                'sticky': False
            }
        }

    def action_create_invoice(self):
        """
        Create draft invoice from DTE.

        Steps:
        1. Parse DTE data
        2. Create invoice header
        3. Create invoice lines (with analytic from PO if matched)
        4. Link to DTE inbox record
        5. ALWAYS create as DRAFT (never post automatically)
        """
        self.ensure_one()

        if self.state not in ['validated', 'matched']:
            raise UserError(_('DTE must be validated before creating invoice'))

        if self.invoice_id:
            raise UserError(_('Invoice already created for this DTE'))

        try:
            parsed_data = json.loads(self.parsed_data) if self.parsed_data else {}

            # Find or create supplier
            if not self.partner_id:
                partner = self.env['res.partner'].search([
                    ('vat', '=', self.emisor_rut)
                ], limit=1)

                if not partner:
                    # Create supplier
                    partner = self.env['res.partner'].create({
                        'name': self.emisor_name,
                        'vat': self.emisor_rut,
                        'supplier_rank': 1,
                        'street': self.emisor_address,
                        'city': self.emisor_city,
                        'phone': self.emisor_phone,
                        'email': self.emisor_email,
                        'country_id': self.env.ref('base.cl').id,
                    })

                self.partner_id = partner

            # Create invoice
            invoice_vals = {
                'move_type': 'in_invoice',
                'partner_id': self.partner_id.id,
                'invoice_date': self.fecha_emision,
                'date': self.fecha_emision,
                'ref': f"DTE {self.dte_type} - {self.folio}",
                'state': 'draft',  # ALWAYS DRAFT
                'company_id': self.company_id.id,
                'currency_id': self.currency_id.id,
            }

            # Link to PO if matched
            if self.purchase_order_id:
                invoice_vals['purchase_id'] = self.purchase_order_id.id

            invoice = self.env['account.move'].create(invoice_vals)

            # Create invoice lines from DTE items
            items = parsed_data.get('items', [])

            for item_data in items:
                # Find or create product
                product = self._find_or_create_product(item_data)

                # Get analytic account from matched PO line if available
                analytic_distribution = {}
                if self.purchase_order_id:
                    po_line = self._match_po_line(item_data, self.purchase_order_id)
                    if po_line and po_line.analytic_distribution:
                        analytic_distribution = po_line.analytic_distribution

                line_vals = {
                    'move_id': invoice.id,
                    'product_id': product.id if product else False,
                    'name': item_data.get('nombre') or item_data.get('descripcion') or 'Unknown',
                    'quantity': item_data.get('cantidad', 1.0),
                    'price_unit': item_data.get('precio_unitario', 0.0),
                    'analytic_distribution': analytic_distribution,
                }

                # Link to PO line if found
                if self.purchase_order_id:
                    po_line = self._match_po_line(item_data, self.purchase_order_id)
                    if po_line:
                        line_vals['purchase_line_id'] = po_line.id

                self.env['account.move.line'].create(line_vals)

            # Link invoice to DTE inbox
            self.invoice_id = invoice.id
            self.state = 'invoiced'

            self.message_post(
                body=_('Draft invoice created: %s') % invoice.name
            )

            _logger.info(f"Created invoice {invoice.name} from DTE {self.name}")

            return {
                'type': 'ir.actions.act_window',
                'res_model': 'account.move',
                'res_id': invoice.id,
                'view_mode': 'form',
                'target': 'current',
            }

        except Exception as e:
            _logger.error(f"Failed to create invoice from DTE {self.name}: {e}")
            raise UserError(_('Failed to create invoice: %s') % str(e))

    def action_open_commercial_response_wizard(self):
        """Open wizard to send commercial response."""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Commercial Response'),
            'res_model': 'dte.commercial.response.wizard',
            'view_mode': 'form',
            'target': 'new',
            'context': {
                'default_dte_inbox_id': self.id,
            }
        }

    # ═══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════

    def _find_or_create_product(self, item_data):
        """Find or create product from DTE item data."""
        # Try to find by product codes
        codigos = item_data.get('codigos', [])

        for codigo in codigos:
            product = self.env['product.product'].search([
                ('default_code', '=', codigo.get('valor'))
            ], limit=1)
            if product:
                return product

        # Try to find by name
        nombre = item_data.get('nombre')
        if nombre:
            product = self.env['product.product'].search([
                ('name', 'ilike', nombre)
            ], limit=1)
            if product:
                return product

        # Create new product
        return self.env['product.product'].create({
            'name': nombre or 'Unknown Product',
            'type': 'product',
            'purchase_ok': True,
        })

    def _get_pending_purchase_orders(self):
        """
        Obtener órdenes de compra pendientes del proveedor.

        Returns:
            list: Lista de dict con datos de POs pendientes
        """
        if not self.partner_id:
            return []

        # Buscar POs confirmadas pero no completamente facturadas
        pos = self.env['purchase.order'].search([
            ('partner_id', '=', self.partner_id.id),
            ('state', 'in', ['purchase', 'done']),
            ('invoice_status', '!=', 'invoiced')
        ], limit=10, order='date_order desc')

        result = []
        for po in pos:
            result.append({
                'id': po.id,
                'name': po.name,
                'amount_total': float(po.amount_total),
                'date_order': po.date_order.isoformat() if po.date_order else None,
                'currency': po.currency_id.name if po.currency_id else 'CLP',
                'lines': [{
                    'product_id': line.product_id.id if line.product_id else None,
                    'product_name': line.product_id.name if line.product_id else line.name,
                    'qty': float(line.product_qty),
                    'price_unit': float(line.price_unit),
                    'subtotal': float(line.price_subtotal)
                } for line in po.order_line]
            })

        return result

    def _get_vendor_history(self, limit=20):
        """
        Get vendor's DTE history for anomaly detection.

        SPRINT 4 (2025-10-24): Helper method for AI validation.

        Args:
            limit (int): Max DTEs to retrieve

        Returns:
            list: List of dict with historical DTE data
        """
        if not self.partner_id:
            return []

        # Get accepted DTEs from this vendor (last 20)
        history_dtes = self.env['dte.inbox'].search([
            ('partner_id', '=', self.partner_id.id),
            ('state', 'in', ['validated', 'matched', 'accepted', 'invoiced']),
            ('id', '!=', self.id)  # Exclude current DTE
        ], limit=limit, order='fecha_emision desc')

        result = []
        for dte in history_dtes:
            result.append({
                'tipo_dte': dte.dte_type,
                'folio': dte.folio,
                'fecha_emision': dte.fecha_emision.isoformat() if dte.fecha_emision else None,
                'monto_total': float(dte.monto_total),
                'monto_neto': float(dte.monto_neto),
                'monto_iva': float(dte.monto_iva),
                'monto_exento': float(dte.monto_exento)
            })

        return result

    def _match_po_line(self, item_data, purchase_order):
        """Match DTE item with PO line."""
        # Try to match by product
        codigos = item_data.get('codigos', [])

        for codigo in codigos:
            product = self.env['product.product'].search([
                ('default_code', '=', codigo.get('valor'))
            ], limit=1)

            if product:
                po_line = purchase_order.order_line.filtered(
                    lambda l: l.product_id == product
                )
                if po_line:
                    return po_line[0]

        # Try to match by name/description
        nombre = item_data.get('nombre')
        if nombre:
            po_line = purchase_order.order_line.filtered(
                lambda l: nombre.lower() in (l.name or '').lower()
            )
            if po_line:
                return po_line[0]

        return None

    # ═══════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════

    def _create_inbox_record(self, dte_data):
        """Create DTE inbox record from parsed data."""
        # Check if already exists
        existing = self.search([
            ('emisor_rut', '=', dte_data.get('emisor', {}).get('rut')),
            ('dte_type', '=', dte_data.get('dte_type')),
            ('folio', '=', dte_data.get('folio')),
        ], limit=1)

        if existing:
            _logger.info(f"DTE already exists: {existing.name}")
            return existing

        # Create new record
        totales = dte_data.get('totales', {})
        emisor = dte_data.get('emisor', {})
        fecha_recepcion = dte_data.get('fecha_recepcion_sii')

        if isinstance(fecha_recepcion, datetime):
            fecha_recepcion = fields.Datetime.to_string(fecha_recepcion)

        vals = {
            'folio': dte_data.get('folio'),
            'dte_type': dte_data.get('dte_type'),
            'emisor_rut': emisor.get('rut'),
            'emisor_name': emisor.get('razon_social'),
            'emisor_address': emisor.get('direccion'),
            'emisor_city': emisor.get('ciudad'),
            'emisor_phone': emisor.get('telefono'),
            'emisor_email': emisor.get('email'),
            'fecha_emision': dte_data.get('fecha_emision'),
            'monto_neto': totales.get('monto_neto', 0),
            'monto_iva': totales.get('iva', 0),
            'monto_exento': totales.get('monto_exento', 0),
            'monto_total': totales.get('total', 0),
            'raw_xml': dte_data.get('raw_xml'),
            'parsed_data': json.dumps(dte_data),
            'received_via': 'email' if dte_data.get('email_id') else 'sii',
            'state': 'new',
            'fecha_recepcion_sii': fecha_recepcion or fields.Datetime.to_string(fields.Datetime.now()),
            'digest_value': dte_data.get('digest_value'),
            'envio_dte_id': dte_data.get('envio_dte_id'),
            'documento_signature': dte_data.get('documento_signature'),
        }

        record = self.create(vals)

        _logger.info(f"Created DTE inbox record: {record.name}")

        return record
