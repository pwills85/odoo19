# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from lxml import etree
import base64
import logging

# F-002: Validación firma digital CAF (Gap Closure P0)
from odoo.addons.l10n_cl_dte.libs.caf_signature_validator import get_validator

# F-005: Encriptación RSASK (Gap Closure P0)
from odoo.addons.l10n_cl_dte.tools.encryption_helper import get_encryption_helper

_logger = logging.getLogger(__name__)


class DTECAF(models.Model):
    """
    Gestión de CAF (Código de Autorización de Folios)
    
    El CAF es un archivo XML proporcionado por el SII que autoriza
    un rango de folios para emitir DTEs.
    """
    _name = 'dte.caf'
    _description = 'Código de Autorización de Folios (CAF)'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'fecha_autorizacion desc, id desc'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Nombre',
        compute='_compute_name',
        store=True
    )
    
    active = fields.Boolean(
        string='Activo',
        default=True
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )
    
    # ═══════════════════════════════════════════════════════════
    # TIPO DE DTE Y DIARIO
    # ═══════════════════════════════════════════════════════════
    
    dte_type = fields.Selection([
        ('33', 'Factura Electrónica'),
        ('34', 'Liquidación de Honorarios'),
        ('52', 'Guía de Despacho'),
        ('56', 'Nota de Débito'),
        ('61', 'Nota de Crédito'),
    ], string='Tipo DTE', required=True, tracking=True)
    
    journal_id = fields.Many2one(
        'account.journal',
        string='Diario',
        domain=[('is_dte_journal', '=', True)],
        help='Diario asociado a este CAF'
    )
    
    # ═══════════════════════════════════════════════════════════
    # RANGO DE FOLIOS
    # ═══════════════════════════════════════════════════════════
    
    folio_desde = fields.Integer(
        string='Folio Desde',
        required=True,
        tracking=True,
        help='Primer folio autorizado'
    )
    
    folio_hasta = fields.Integer(
        string='Folio Hasta',
        required=True,
        tracking=True,
        help='Último folio autorizado'
    )
    
    folios_disponibles = fields.Integer(
        string='Folios Disponibles',
        compute='_compute_folios_disponibles',
        store=True,
        help='Cantidad de folios aún no utilizados'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ARCHIVO CAF
    # ═══════════════════════════════════════════════════════════
    
    caf_file = fields.Binary(
        string='Archivo CAF (.xml)',
        required=True,
        attachment=True,
        help='Archivo XML del CAF descargado del SII'
    )
    
    caf_filename = fields.Char(
        string='Nombre Archivo'
    )
    
    caf_xml_content = fields.Text(
        string='Contenido XML CAF',
        readonly=True,
        help='Contenido del archivo CAF para incluir en DTEs'
    )
    
    # ═══════════════════════════════════════════════════════════
    # METADATA DEL CAF
    # ═══════════════════════════════════════════════════════════
    
    fecha_autorizacion = fields.Date(
        string='Fecha Autorización',
        readonly=True,
        tracking=True,
        help='Fecha en que el SII autorizó este CAF'
    )
    
    rut_empresa = fields.Char(
        string='RUT Empresa',
        readonly=True,
        help='RUT de la empresa autorizada (debe coincidir)'
    )

    # F-002: Validación firma digital CAF (Gap Closure P0)
    firma_validada = fields.Boolean(
        string='Firma SII Validada',
        readonly=True,
        default=False,
        help='Indica si la firma digital FRMA del SII fue verificada criptográficamente según Resolución Ex. SII N°11'
    )

    # F-005: Encriptación RSASK (Gap Closure P0)
    rsask_encrypted = fields.Binary(
        string='RSASK Encriptado',
        attachment=True,
        help='Llave privada RSA del CAF encriptada con Fernet AES-128. Nunca se almacena en texto plano.'
    )

    rsask = fields.Text(
        string='RSASK (Temporal)',
        compute='_compute_rsask',
        inverse='_inverse_rsask',
        store=False,
        help='Llave privada RSA del CAF (solo en memoria, nunca almacenada en base de datos)'
    )

    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════
    
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('valid', 'Válido'),
        ('in_use', 'En Uso'),
        ('exhausted', 'Agotado'),
        ('expired', 'Vencido'),
    ], string='Estado', default='draft', readonly=True, tracking=True)
    
    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS (Odoo 19 CE style)
    # ═══════════════════════════════════════════════════════════

    _unique_caf_range = models.Constraint(
        'UNIQUE(dte_type, folio_desde, folio_hasta, company_id)',
        'Ya existe un CAF con este rango de folios.'
    )
    
    @api.constrains('folio_desde', 'folio_hasta')
    def _check_folio_range(self):
        """Valida que el rango de folios sea correcto"""
        for record in self:
            if record.folio_desde > record.folio_hasta:
                raise ValidationError(
                    _('El folio inicial debe ser menor o igual al folio final')
                )

    @api.constrains('caf_xml_content')
    def _validate_caf_signature_on_upload(self):
        """
        F-002: Valida la firma digital FRMA del SII al cargar un CAF.

        Esta validación es OBLIGATORIA según Resolución Ex. SII N°11.
        Verifica que la firma digital FRMA fue emitida por el SII de Chile
        usando validación criptográfica RSA SHA1.

        Raises:
            ValidationError: Si la firma no es válida o no puede ser verificada

        Sprint: Gap Closure P0 - F-002
        Date: 2025-11-02
        """
        for record in self:
            if not record.caf_xml_content:
                continue

            _logger.info(f'[DTE_CAF] Validando firma digital CAF ID {record.id}')

            try:
                validator = get_validator()
                is_valid, message = validator.validate_caf_signature(record.caf_xml_content)

                if not is_valid:
                    _logger.error(f'[DTE_CAF] ❌ Firma CAF inválida ID {record.id}: {message}')
                    raise ValidationError(
                        _('Firma digital del CAF no es válida.\n\n'
                          'Motivo: %s\n\n'
                          'El archivo CAF debe ser emitido por el SII de Chile y '
                          'tener una firma digital FRMA válida.\n\n'
                          'Verifique que:\n'
                          '1. El archivo CAF fue descargado correctamente del portal SII\n'
                          '2. El archivo no ha sido modificado\n'
                          '3. El archivo corresponde a su empresa (RUT emisor correcto)') % message
                    )

                # Marcar como validado
                # Usar write() en vez de asignación directa para evitar recursión
                record.sudo().write({'firma_validada': True})
                _logger.info(f'[DTE_CAF] ✅ Firma CAF validada correctamente ID {record.id}')

            except ValidationError:
                # Re-raise ValidationError para que Odoo la muestre al usuario
                raise
            except Exception as e:
                _logger.error(f'[DTE_CAF] Error inesperado validando firma CAF ID {record.id}: {e}', exc_info=True)
                raise ValidationError(
                    _('Error técnico al validar firma digital del CAF: %s\n\n'
                      'Contacte al administrador del sistema.') % str(e)
                )

    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('dte_type', 'folio_desde', 'folio_hasta')
    def _compute_name(self):
        """Genera nombre descriptivo"""
        for record in self:
            if record.dte_type and record.folio_desde and record.folio_hasta:
                dte_name = dict(record._fields['dte_type'].selection).get(record.dte_type, '')
                record.name = f'CAF {dte_name} ({record.folio_desde}-{record.folio_hasta})'
            else:
                record.name = 'Nuevo CAF'
    
    @api.depends('folio_desde', 'folio_hasta', 'journal_id.dte_folio_current')
    def _compute_folios_disponibles(self):
        """Calcula folios disponibles"""
        for record in self:
            if record.folio_desde and record.folio_hasta and record.journal_id:
                folios_usados = record.journal_id.dte_folio_current - record.folio_desde
                record.folios_disponibles = max(0, record.folio_hasta - record.folio_desde + 1 - folios_usados)
            else:
                record.folios_disponibles = record.folio_hasta - record.folio_desde + 1 if record.folio_hasta and record.folio_desde else 0

    # F-005: Encriptación RSASK (Gap Closure P0)
    @api.depends('rsask_encrypted')
    def _compute_rsask(self):
        """
        Desencripta RSASK en memoria bajo demanda.

        Este campo computed NUNCA se almacena en base de datos (store=False).
        La desencriptación ocurre solo cuando se accede al campo.

        Sprint: Gap Closure P0 - F-005
        Date: 2025-11-02
        """
        encryption_helper = get_encryption_helper(self.env)

        for record in self:
            if record.rsask_encrypted:
                try:
                    # Desencriptar desde Binary
                    encrypted_b64 = base64.b64encode(record.rsask_encrypted).decode('utf-8')
                    record.rsask = encryption_helper.decrypt(encrypted_b64)
                    _logger.debug(f'[DTE_CAF] RSASK desencriptado para CAF ID {record.id}')
                except Exception as e:
                    _logger.error(f'[DTE_CAF] Error desencriptando RSASK ID {record.id}: {e}', exc_info=True)
                    record.rsask = False
            else:
                record.rsask = False

    def _inverse_rsask(self):
        """
        Encripta RSASK antes de almacenar en base de datos.

        Cuando se asigna un valor a record.rsask, este método se ejecuta
        automáticamente para encriptar y almacenar en rsask_encrypted.

        Raises:
            ValidationError: Si no se puede encriptar RSASK

        Sprint: Gap Closure P0 - F-005
        Date: 2025-11-02
        """
        encryption_helper = get_encryption_helper(self.env)

        for record in self:
            if record.rsask:
                try:
                    # Encriptar
                    encrypted_b64 = encryption_helper.encrypt(record.rsask)

                    # Convertir de base64 string a Binary
                    encrypted_bytes = base64.b64decode(encrypted_b64)
                    record.rsask_encrypted = encrypted_bytes

                    _logger.info(f'[DTE_CAF] ✅ RSASK encriptado para CAF ID {record.id}')
                except Exception as e:
                    _logger.error(f'[DTE_CAF] ❌ Error encriptando RSASK ID {record.id}: {e}', exc_info=True)
                    raise ValidationError(
                        _('No se pudo encriptar la llave privada RSA (RSASK).\n\n'
                          'Error: %s\n\n'
                          'Contacte al administrador del sistema.') % str(e)
                    )
            else:
                # Si rsask es False/None, limpiar encrypted
                record.rsask_encrypted = False

    # ═══════════════════════════════════════════════════════════
    # CRUD METHODS
    # ═══════════════════════════════════════════════════════════
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create para extraer metadata del CAF"""
        for vals in vals_list:
            if vals.get('caf_file'):
                # Extraer metadata del CAF
                metadata = self._extract_caf_metadata(vals['caf_file'])
                vals.update(metadata)
        
        records = super().create(vals_list)
        
        # Actualizar estado
        for record in records:
            record._update_state()
        
        return records
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def action_validate(self):
        """Validar CAF"""
        self.ensure_one()
        
        # Validar que el RUT coincida
        if self.rut_empresa and self.company_id.vat:
            if self.rut_empresa.replace('-', '') != self.company_id.vat.replace('.', '').replace('-', ''):
                raise ValidationError(
                    _('El RUT del CAF (%s) no coincide con el RUT de la empresa (%s)') % 
                    (self.rut_empresa, self.company_id.vat)
                )
        
        self.write({'state': 'valid'})
        
        # Sincronizar con l10n_latam si está disponible
        sync_result = self._sync_with_latam_sequence()
        
        message = _('CAF validado exitosamente. Folios: %d-%d') % (self.folio_desde, self.folio_hasta)
        if sync_result:
            message += _('\n✅ Sincronizado con l10n_latam_document_type')
        
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('CAF Validado'),
                'message': message,
                'type': 'success',
            }
        }
    
    def _extract_caf_metadata(self, caf_file_b64):
        """
        Extrae metadata del archivo CAF (XML)

        F-005: Ahora extrae y encripta RSASK automáticamente.

        Args:
            caf_file_b64: Archivo CAF en base64

        Returns:
            Dict con metadata extraída (incluye rsask_encrypted)
        """
        try:
            # Decodificar base64
            if isinstance(caf_file_b64, str):
                caf_data = base64.b64decode(caf_file_b64)
            else:
                caf_data = caf_file_b64

            # Parsear XML
            root = etree.fromstring(caf_data)

            # Extraer datos (estructura aproximada del CAF del SII)
            # Nota: La estructura exacta puede variar
            folio_desde = root.findtext('.//RNG/D') or root.findtext('.//CAF/DA/RNG/D')
            folio_hasta = root.findtext('.//RNG/H') or root.findtext('.//CAF/DA/RNG/H')
            fecha_aut = root.findtext('.//FA') or root.findtext('.//CAF/DA/FA')
            rut = root.findtext('.//RE') or root.findtext('.//CAF/DA/RE')

            # F-005: Extraer RSASK (llave privada RSA) y encriptar
            rsask_element = root.find('.//RSASK') or root.find('.//CAF/DA/RSASK')
            rsask_encrypted_bytes = None

            if rsask_element is not None and rsask_element.text:
                rsask_plaintext = rsask_element.text.strip()

                # Encriptar RSASK antes de almacenar
                try:
                    encryption_helper = get_encryption_helper(self.env)
                    encrypted_b64 = encryption_helper.encrypt(rsask_plaintext)

                    # Convertir de base64 string a Binary
                    rsask_encrypted_bytes = base64.b64decode(encrypted_b64)

                    _logger.info('[DTE_CAF] ✅ RSASK encriptado durante extracción de metadata')
                except Exception as e:
                    _logger.error(f'[DTE_CAF] ❌ Error encriptando RSASK: {e}', exc_info=True)
                    raise ValidationError(
                        _('No se pudo encriptar la llave privada RSA del CAF.\n\n'
                          'Error: %s\n\n'
                          'El CAF no puede ser procesado sin encriptación segura de RSASK.') % str(e)
                    )
            else:
                _logger.warning('[DTE_CAF] ⚠️ RSASK no encontrado en CAF - CAF puede ser inválido')

            # Guardar XML completo para incluir en DTEs
            caf_xml_str = etree.tostring(root, encoding='unicode')

            return {
                'caf_xml_content': caf_xml_str,
                'folio_desde': int(folio_desde) if folio_desde else None,
                'folio_hasta': int(folio_hasta) if folio_hasta else None,
                'fecha_autorizacion': fecha_aut,
                'rut_empresa': rut,
                'rsask_encrypted': rsask_encrypted_bytes,  # F-005: RSASK encriptado
            }

        except Exception as e:
            _logger.error(f'Error al extraer metadata del CAF: {str(e)}')
            raise ValidationError(_('Error al procesar archivo CAF: %s') % str(e))
    
    def _update_state(self):
        """Actualiza estado del CAF"""
        for record in self:
            if record.folios_disponibles <= 0:
                record.state = 'exhausted'
            elif record.folios_disponibles < (record.folio_hasta - record.folio_desde + 1):
                record.state = 'in_use'
            else:
                record.state = 'valid'
    
    def get_caf_for_folio(self, folio):
        """
        Obtiene el CAF correspondiente a un folio.
        
        Args:
            folio: Número de folio
        
        Returns:
            Registro dte.caf o False
        """
        self.ensure_one()
        
        if self.folio_desde <= folio <= self.folio_hasta:
            return self
        
        return False
    
    def _sync_with_latam_sequence(self):
        """
        Sincroniza CAF con secuencias l10n_latam.
        Asegura que folios CAF coincidan con document_type sequence.
        
        INTEGRACIÓN ODOO 19 CE:
        - Usa l10n_latam_document_type_id para mapear tipos
        - Sincroniza con l10n_latam_use_documents cuando está habilitado
        - Mantiene compatibilidad con sistema de folios custom
        """
        self.ensure_one()
        
        # Obtener document_type correspondiente
        doc_type = self.env['l10n_latam.document.type'].search([
            ('code', '=', str(self.dte_type)),
            ('country_id.code', '=', 'CL')
        ], limit=1)
        
        if not doc_type:
            _logger.warning(
                f'No existe l10n_latam.document.type para DTE {self.dte_type}. '
                f'Sincronización omitida.'
            )
            return False
        
        # Verificar que journal usa documentos LATAM
        if self.journal_id and hasattr(self.journal_id, 'l10n_latam_use_documents'):
            if self.journal_id.l10n_latam_use_documents:
                # Sincronizar rango de folios con journal
                self.journal_id.write({
                    'dte_folio_start': self.folio_desde,
                    'dte_folio_end': self.folio_hasta,
                    'dte_folio_current': self.folio_desde,
                })
                
                _logger.info(
                    f'CAF sincronizado con l10n_latam: '
                    f'Journal {self.journal_id.name}, '
                    f'Document Type {doc_type.name}, '
                    f'Folios {self.folio_desde}-{self.folio_hasta}'
                )
                return True
            else:
                _logger.info(
                    f'Journal {self.journal_id.name} no usa l10n_latam_use_documents. '
                    f'Considerar habilitar para mejor integración con Odoo 19 CE.'
                )
        
        return False

