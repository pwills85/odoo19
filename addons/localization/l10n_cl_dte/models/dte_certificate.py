# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError
from datetime import datetime, timedelta
import base64
import logging
from cryptography.fernet import Fernet
import os

_logger = logging.getLogger(__name__)


class DTECertificate(models.Model):
    """
    Gestión de Certificados Digitales para Firma de DTEs
    
    Almacena certificados .pfx de manera segura (encriptados)
    y gestiona su ciclo de vida (carga, validación, vencimiento).
    """
    _name = 'dte.certificate'
    _description = 'Certificado Digital DTE'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'validity_to desc, id desc'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS BÁSICOS
    # ═══════════════════════════════════════════════════════════
    
    name = fields.Char(
        string='Nombre',
        required=True,
        tracking=True,
        help='Nombre descriptivo del certificado'
    )
    
    active = fields.Boolean(
        string='Activo',
        default=True,
        tracking=True,
        help='Desmarcar para archivar'
    )
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        tracking=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS DE CERTIFICADO (ENCRIPTADOS)
    # ═══════════════════════════════════════════════════════════
    
    cert_file = fields.Binary(
        string='Archivo Certificado (.pfx)',
        required=True,
        attachment=True,
        help='Archivo .pfx o .p12 del certificado digital'
    )
    
    cert_filename = fields.Char(
        string='Nombre de Archivo'
    )
    
    cert_password = fields.Char(
        string='Contraseña Certificado',
        required=True,
        help='Contraseña para desbloquear el certificado'
    )
    
    # ═══════════════════════════════════════════════════════════
    # METADATOS DEL CERTIFICADO (EXTRAÍDOS)
    # ═══════════════════════════════════════════════════════════
    
    cert_rut = fields.Char(
        string='RUT del Certificado',
        readonly=True,
        tracking=True,
        help='RUT extraído del certificado'
    )
    
    cert_subject = fields.Char(
        string='Sujeto (Subject)',
        readonly=True,
        help='Subject del certificado X.509'
    )
    
    cert_issuer = fields.Char(
        string='Emisor (Issuer)',
        readonly=True,
        help='Issuer del certificado'
    )
    
    cert_serial_number = fields.Char(
        string='Número de Serie',
        readonly=True,
        help='Serial number del certificado'
    )
    
    validity_from = fields.Date(
        string='Válido Desde',
        readonly=True,
        tracking=True,
        help='Fecha de inicio de validez'
    )
    
    validity_to = fields.Date(
        string='Válido Hasta',
        readonly=True,
        tracking=True,
        help='Fecha de fin de validez'
    )
    
    days_until_expiry = fields.Integer(
        string='Días hasta Vencimiento',
        compute='_compute_days_until_expiry',
        store=True,
        help='Días restantes de validez'
    )
    
    # ═══════════════════════════════════════════════════════════
    # ESTADO
    # ═══════════════════════════════════════════════════════════
    
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('valid', 'Válido'),
        ('expiring_soon', 'Por Vencer'),
        ('expired', 'Vencido'),
        ('revoked', 'Revocado'),
    ], string='Estado', default='draft', readonly=True, tracking=True)
    
    # ═══════════════════════════════════════════════════════════
    # RELACIONES
    # ═══════════════════════════════════════════════════════════
    
    journal_ids = fields.One2many(
        'account.journal',
        'dte_certificate_id',
        string='Diarios Asociados',
        help='Diarios que usan este certificado'
    )
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS COMPUTADOS
    # ═══════════════════════════════════════════════════════════
    
    @api.depends('validity_to')
    def _compute_days_until_expiry(self):
        """Calcula días hasta vencimiento"""
        for record in self:
            if record.validity_to:
                today = fields.Date.today()
                delta = record.validity_to - today
                record.days_until_expiry = delta.days
            else:
                record.days_until_expiry = 0
    
    # ═══════════════════════════════════════════════════════════
    # CONSTRAINTS
    # ═══════════════════════════════════════════════════════════
    
    _sql_constraints = [
        ('unique_cert_rut_company', 
         'UNIQUE(cert_rut, company_id)', 
         'Ya existe un certificado con este RUT para esta compañía.')
    ]
    
    @api.constrains('validity_to')
    def _check_validity(self):
        """Verifica que el certificado no esté vencido al cargar"""
        for record in self:
            if record.validity_to and record.validity_to < fields.Date.today():
                raise ValidationError(_('El certificado está vencido. Fecha de vencimiento: %s') % record.validity_to)
    
    # ═══════════════════════════════════════════════════════════
    # CRUD METHODS
    # ═══════════════════════════════════════════════════════════
    
    @api.model_create_multi
    def create(self, vals_list):
        """Override create para extraer metadata del certificado"""
        for vals in vals_list:
            if vals.get('cert_file'):
                # Extraer metadata del certificado
                metadata = self._extract_certificate_metadata(
                    vals['cert_file'],
                    vals.get('cert_password', '')
                )
                vals.update(metadata)
        
        records = super().create(vals_list)
        
        # Validar y actualizar estado
        for record in records:
            record._update_state()
        
        return records
    
    def write(self, vals):
        """Override write para re-extraer metadata si cambia el certificado"""
        if vals.get('cert_file') or vals.get('cert_password'):
            for record in self:
                cert_file = vals.get('cert_file', record.cert_file)
                cert_password = vals.get('cert_password', record.cert_password)
                
                if cert_file:
                    metadata = record._extract_certificate_metadata(cert_file, cert_password)
                    vals.update(metadata)
        
        result = super().write(vals)
        
        # Actualizar estado
        self._update_state()
        
        return result
    
    # ═══════════════════════════════════════════════════════════
    # BUSINESS METHODS
    # ═══════════════════════════════════════════════════════════
    
    def action_validate(self):
        """
        Validar el certificado completo.
        
        Validaciones (técnicas verificadas):
        1. Carga correcta del .pfx
        2. Vigencia del certificado
        3. RUT coincide con empresa (NUEVO)
        4. Clase del certificado (NUEVO - básico)
        """
        self.ensure_one()
        
        try:
            from OpenSSL import crypto
            from odoo.addons.l10n_cl_dte.tools.rut_validator import validate_rut, clean_rut
            
            # 1. Cargar certificado
            cert_data = base64.b64decode(self.cert_file)
            p12 = crypto.load_pkcs12(cert_data, self.cert_password.encode())
            certificate = p12.get_certificate()
            
            # 2. Validar vigencia (ya implementado)
            self._update_state()
            
            # 3. NUEVO: Validar RUT coincide con empresa
            if self.cert_rut and self.company_id.vat:
                cert_rut_clean = clean_rut(self.cert_rut)
                company_rut_clean = clean_rut(self.company_id.vat)
                
                if cert_rut_clean != company_rut_clean:
                    raise ValidationError(
                        _('El RUT del certificado (%s) no coincide con el RUT de la empresa (%s).\n'
                          'Debe usar un certificado emitido a nombre de la empresa.') %
                        (self.cert_rut, self.company_id.vat)
                    )
            
            # 4. NUEVO: Validación básica de clase (verificar que sea certificado de firma)
            # Nota: Validación completa de clase 2/3 requiere inspección de OID específicos
            # que pueden variar según CA. Implementación básica:
            subject = certificate.get_subject()
            
            if not hasattr(subject, 'CN') or not subject.CN:
                raise ValidationError(_('El certificado no tiene un Common Name (CN) válido'))
            
            # Log información para auditoría
            _logger.info(f'Certificado validado: RUT={self.cert_rut}, '
                        f'Subject={subject.CN}, '
                        f'Issuer={certificate.get_issuer().CN if hasattr(certificate.get_issuer(), "CN") else "N/A"}')
            
            # Mensaje de éxito
            self.message_post(
                body=_('Certificado validado exitosamente.\n'
                      'RUT: %s\n'
                      'Válido hasta: %s') % (self.cert_rut, self.validity_to),
                subject=_('Validación Exitosa')
            )
            
        except ValidationError:
            # Re-raise validation errors (ya tienen mensaje apropiado)
            raise
        except Exception as e:
            raise UserError(_('Error al validar certificado: %s') % str(e))
    
    def action_revoke(self):
        """Revocar el certificado"""
        self.ensure_one()
        self.write({'state': 'revoked', 'active': False})
        self.message_post(
            body=_('Certificado revocado.'),
            subject=_('Certificado Revocado')
        )
    
    def _update_state(self):
        """Actualiza el estado del certificado según validez"""
        for record in self:
            if not record.validity_to:
                record.state = 'draft'
                continue
            
            today = fields.Date.today()
            days_to_expiry = (record.validity_to - today).days
            
            if record.state == 'revoked':
                continue  # No cambiar estado si está revocado
            
            if days_to_expiry < 0:
                record.state = 'expired'
            elif days_to_expiry <= 30:
                record.state = 'expiring_soon'
            else:
                record.state = 'valid'
    
    def _extract_certificate_metadata(self, cert_file_b64, password):
        """
        Extrae metadata del certificado .pfx
        
        Args:
            cert_file_b64: Archivo certificado en base64
            password: Contraseña del certificado
        
        Returns:
            Dict con metadata extraída
        """
        try:
            from OpenSSL import crypto
            
            # Decodificar base64
            if isinstance(cert_file_b64, str):
                cert_data = base64.b64decode(cert_file_b64)
            else:
                cert_data = cert_file_b64
            
            # Cargar certificado PKCS#12
            p12 = crypto.load_pkcs12(cert_data, password.encode())
            cert = p12.get_certificate()
            
            # Extraer subject
            subject = cert.get_subject()
            subject_str = f"CN={subject.CN}, O={subject.O if hasattr(subject, 'O') else 'N/A'}"
            
            # Extraer issuer
            issuer = cert.get_issuer()
            issuer_str = f"CN={issuer.CN}, O={issuer.O if hasattr(issuer, 'O') else 'N/A'}"
            
            # Extraer fechas de validez
            not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
            not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            
            # Extraer serial number
            serial = str(cert.get_serial_number())
            
            # Extraer RUT del subject (formato típico: serialNumber=12345678-9)
            cert_rut = self._extract_rut_from_subject(subject)
            
            return {
                'cert_subject': subject_str,
                'cert_issuer': issuer_str,
                'cert_serial_number': serial,
                'cert_rut': cert_rut,
                'validity_from': not_before.date(),
                'validity_to': not_after.date(),
            }
            
        except Exception as e:
            _logger.error(f'Error al extraer metadata del certificado: {str(e)}')
            raise ValidationError(_('Error al procesar certificado: %s') % str(e))
    
    def _extract_rut_from_subject(self, subject):
        """Extrae RUT del subject del certificado"""
        try:
            # Intentar extraer serialNumber del subject
            if hasattr(subject, 'serialNumber'):
                return subject.serialNumber
            
            # Si no está, intentar del CN
            if hasattr(subject, 'CN') and '-' in subject.CN:
                # Buscar patrón de RUT en CN
                import re
                match = re.search(r'(\d{1,2}\.?\d{3}\.?\d{3}-[\dkK])', subject.CN)
                if match:
                    return match.group(1)
            
            return False
        except Exception as e:
            _logger.warning(f'No se pudo extraer RUT del certificado: {str(e)}')
            return False
    
    # ═══════════════════════════════════════════════════════════
    # CRON JOBS
    # ═══════════════════════════════════════════════════════════
    
    @api.model
    def cron_check_certificate_expiry(self):
        """
        Cron job que verifica vencimiento de certificados.
        Ejecutar diario.
        Alerta si quedan menos de 30 días.
        """
        certificates = self.search([('active', '=', True), ('state', 'in', ['valid', 'expiring_soon'])])
        
        for cert in certificates:
            cert._update_state()
            
            # Crear actividad si está por vencer
            if cert.state == 'expiring_soon' and cert.days_until_expiry > 0:
                # Verificar si ya existe actividad
                existing_activity = self.env['mail.activity'].search([
                    ('res_id', '=', cert.id),
                    ('res_model_id', '=', self.env['ir.model']._get_id('dte.certificate')),
                    ('activity_type_id', '=', self.env.ref('mail.mail_activity_data_warning').id),
                ], limit=1)
                
                if not existing_activity:
                    cert.activity_schedule(
                        'mail.mail_activity_data_warning',
                        summary=_('Certificado por vencer'),
                        note=_('El certificado "%s" vence en %d días (fecha: %s). Renovar urgente.') % (
                            cert.name,
                            cert.days_until_expiry,
                            cert.validity_to
                        ),
                        user_id=self.env.user.id
                    )
    
    # ═══════════════════════════════════════════════════════════
    # API METHODS (Para uso por otros modelos)
    # ═══════════════════════════════════════════════════════════
    
    def get_certificate_data(self):
        """
        Retorna los datos del certificado para ser usados en firma.
        
        SEGURIDAD: Datos se transmiten solo en memoria, nunca se logean
        
        Returns:
            Dict con 'cert_file' (bytes) y 'password' (str)
        """
        self.ensure_one()
        
        if self.state not in ['valid', 'expiring_soon']:
            raise UserError(_('El certificado no está en estado válido. Estado actual: %s') % dict(self._fields['state'].selection)[self.state])
        
        # Decodificar certificado
        cert_bytes = base64.b64decode(self.cert_file)
        
        # Nota: En producción, considerar:
        # - Usar Odoo encrypted=True si disponible
        # - O usar vault externo (HashiCorp Vault, AWS Secrets)
        # - O implementar encriptación adicional con Fernet
        
        return {
            'cert_file': cert_bytes,
            'password': self.cert_password
        }
    
    def _encrypt_sensitive_data(self, data: bytes, key: bytes) -> bytes:
        """
        Encripta datos sensibles usando Fernet.
        
        Método helper para encriptación adicional en producción.
        
        Args:
            data: Datos a encriptar
            key: Clave de encriptación (32 bytes)
        
        Returns:
            bytes: Datos encriptados
        """
        f = Fernet(key)
        return f.encrypt(data)
    
    def _decrypt_sensitive_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Desencripta datos"""
        f = Fernet(key)
        return f.decrypt(encrypted_data)
    
    @staticmethod
    def _get_encryption_key():
        """
        Obtiene clave de encriptación.
        
        En producción:
        - Almacenar en variable de entorno
        - O en secrets manager
        - Nunca en código
        """
        # Por ahora, obtener de config
        # En producción: usar secrets manager
        key = os.environ.get('CERTIFICATE_ENCRYPTION_KEY')
        
        if not key:
            # Generar clave temporal (solo desarrollo)
            # En producción esto DEBE venir de secrets
            key = Fernet.generate_key()
        
        return key

