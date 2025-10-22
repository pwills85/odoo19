# -*- coding: utf-8 -*-

from odoo import models, fields, _


class UploadCertificateWizard(models.TransientModel):
    """Wizard para cargar certificado digital"""
    _name = 'upload.certificate.wizard'
    _description = 'Cargar Certificado Digital'
    
    name = fields.Char(string='Nombre Certificado', required=True)
    cert_file = fields.Binary(string='Archivo .pfx', required=True, attachment=False)
    cert_filename = fields.Char(string='Nombre Archivo')
    cert_password = fields.Char(string='Contraseña', required=True)
    company_id = fields.Many2one('res.company', default=lambda self: self.env.company)
    
    def action_upload(self):
        """Crear certificado desde wizard"""
        self.ensure_one()
        
        cert = self.env['dte.certificate'].create({
            'name': self.name,
            'cert_file': self.cert_file,
            'cert_filename': self.cert_filename,
            'cert_password': self.cert_password,
            'company_id': self.company_id.id,
        })
        
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'dte.certificate',
            'res_id': cert.id,
            'view_mode': 'form',
            'target': 'current',
        }

