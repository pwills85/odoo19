# -*- coding: utf-8 -*-
"""
XML Digital Signature - Integrated into Odoo 19 CE
===================================================

Professional XMLDSig signature using PKCS#1 standard for Chilean DTEs.

Features:
- PKCS#1 digital signature with xmlsec library
- Certificate management from Odoo database
- Secure password handling (no plaintext storage)
- SHA-256 + RSA encryption
- Compliant with SII signature requirements

Migration: Migrated from odoo-eergy-services/signers/ (2025-10-24)
Security: Direct DB access (more secure than HTTP transmission)
"""

import xmlsec
from lxml import etree
from odoo import api, models, _
from odoo.exceptions import ValidationError
import logging
import tempfile
import os
import base64

_logger = logging.getLogger(__name__)


class XMLSigner(models.AbstractModel):
    """
    XMLDSig digital signature for DTEs.

    Mixin pattern for use in account.move, purchase.order, stock.picking
    """
    _name = 'xml.signer'
    _description = 'XML Digital Signature'

    # ═══════════════════════════════════════════════════════════
    # DIGITAL SIGNATURE - XMLDSig
    # ═══════════════════════════════════════════════════════════

    @api.model
    def sign_xml_dte(self, xml_string, certificate_id=None):
        """
        Sign XML DTE with digital certificate.

        Args:
            xml_string (str): Unsigned XML
            certificate_id (int): dte.certificate record ID (optional)

        Returns:
            str: Digitally signed XML

        Raises:
            ValidationError: If certificate invalid or signature fails
        """
        _logger.info("Starting XML digital signature process")

        # Get certificate
        if not certificate_id:
            certificate_id = self._get_active_certificate()

        if not certificate_id:
            raise ValidationError(
                _('No active digital certificate found.\n\n'
                  'Please upload and activate a certificate in Configuration → DTE Certificates.')
            )

        certificate = self.env['dte.certificate'].browse(certificate_id)

        if not certificate.exists():
            raise ValidationError(_('Certificate not found (ID: %s)') % certificate_id)

        if certificate.state != 'active':
            raise ValidationError(
                _('Certificate is not active.\n\nState: %s') % certificate.state
            )

        # Validate certificate not expired
        if certificate.date_end:
            from datetime import date
            if date.today() > certificate.date_end:
                raise ValidationError(
                    _('Certificate has expired.\n\nExpiration date: %s') % certificate.date_end
                )

        # Sign XML
        try:
            signed_xml = self._sign_xml_with_certificate(
                xml_string,
                certificate.certificate_file,
                certificate.password
            )

            _logger.info("XML signed successfully")

            return signed_xml

        except Exception as e:
            _logger.error(f"XML signature failed: {str(e)}")
            raise ValidationError(
                _('XML signature failed:\n\n%s') % str(e)
            )

    @api.model
    def _sign_xml_with_certificate(self, xml_string, cert_file_b64, password):
        """
        Internal method to sign XML using certificate.

        Args:
            xml_string (str): Unsigned XML
            cert_file_b64 (str): Certificate file in base64
            password (str): Certificate password

        Returns:
            str: Signed XML

        Raises:
            Exception: If signature fails
        """
        # Decode certificate from base64
        cert_data = base64.b64decode(cert_file_b64)

        # Create temporary files for certificate and XML
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pfx') as cert_file, \
             tempfile.NamedTemporaryFile(delete=False, suffix='.xml', mode='w', encoding='ISO-8859-1') as xml_file:

            try:
                # Write certificate to temp file
                cert_file.write(cert_data)
                cert_file.flush()
                cert_path = cert_file.name

                # Write XML to temp file
                xml_file.write(xml_string)
                xml_file.flush()
                xml_path = xml_file.name

                # Load XML
                xml_tree = etree.parse(xml_path)
                xml_root = xml_tree.getroot()

                # Find signature node (or create if not exists)
                signature_node = xml_root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')

                if signature_node is None:
                    # Create signature template
                    signature_node = xmlsec.template.create(
                        xml_root,
                        xmlsec.constants.TransformExclC14N,
                        xmlsec.constants.TransformRsaSha256
                    )

                    # Add reference to document
                    ref = xmlsec.template.add_reference(
                        signature_node,
                        xmlsec.constants.TransformSha256,
                        uri=""
                    )

                    # Add KeyInfo
                    key_info = xmlsec.template.ensure_key_info(signature_node)
                    xmlsec.template.add_x509_data(key_info)

                    xml_root.append(signature_node)

                # Create signature context
                ctx = xmlsec.SignatureContext()

                # Load certificate
                ctx.key = xmlsec.Key.from_file(
                    cert_path,
                    xmlsec.constants.KeyDataFormatPkcs12,
                    password
                )

                if ctx.key is None:
                    raise Exception("Failed to load certificate key")

                # Load certificate to key info
                ctx.key.load_cert_from_file(
                    cert_path,
                    xmlsec.constants.KeyDataFormatPkcs12
                )

                # Sign XML
                ctx.sign(signature_node)

                # Convert signed XML to string
                signed_xml = etree.tostring(
                    xml_root,
                    pretty_print=True,
                    xml_declaration=True,
                    encoding='ISO-8859-1'
                ).decode('ISO-8859-1')

                return signed_xml

            finally:
                # Clean up temporary files
                try:
                    os.unlink(cert_path)
                    os.unlink(xml_path)
                except:
                    pass

    @api.model
    def _get_active_certificate(self):
        """
        Get active digital certificate for current company.

        Returns:
            int: Certificate ID or False
        """
        company = self.env.company

        certificate = self.env['dte.certificate'].search([
            ('company_id', '=', company.id),
            ('state', '=', 'active')
        ], limit=1)

        if certificate:
            return certificate.id

        # Fallback: Get any active certificate
        certificate = self.env['dte.certificate'].search([
            ('state', '=', 'active')
        ], limit=1)

        return certificate.id if certificate else False
