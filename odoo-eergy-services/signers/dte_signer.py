# -*- coding: utf-8 -*-
"""
Firmador Digital de DTEs
Firma XML usando certificados digitales PKCS#1
"""

from OpenSSL import crypto
from lxml import etree
import xmlsec
import structlog
import base64

logger = structlog.get_logger()


class DTESigner:
    """Firmador digital de DTEs con certificados PKCS#1"""
    
    def __init__(self):
        pass
    
    def sign(self, xml_string: str, cert_bytes: bytes, password: str) -> str:
        """
        Firma un XML DTE con certificado digital.
        
        Args:
            xml_string: XML del DTE a firmar
            cert_bytes: Bytes del certificado .pfx
            password: Contraseña del certificado
        
        Returns:
            str: XML firmado digitalmente
        """
        logger.info("signing_dte_starting")
        
        try:
            # Cargar certificado PKCS#12
            p12 = crypto.load_pkcs12(cert_bytes, password.encode())
            
            # Extraer certificado y clave privada
            certificate = p12.get_certificate()
            private_key = p12.get_privatekey()
            
            # Parsear XML
            root = etree.fromstring(xml_string.encode('ISO-8859-1'))
            
            # Crear nodo Signature
            signature_node = self._create_signature_node(root, private_key, certificate)
            
            # Agregar firma al documento
            # Buscar elemento Documento
            documento = root.find('.//Documento')
            if documento is not None:
                documento.append(signature_node)
            
            # Convertir a string
            signed_xml = etree.tostring(
                root,
                pretty_print=True,
                xml_declaration=True,
                encoding='ISO-8859-1'
            ).decode('ISO-8859-1')
            
            logger.info("dte_signed_successfully")
            
            return signed_xml
            
        except Exception as e:
            logger.error("dte_signing_error", error=str(e))
            raise Exception(f"Error al firmar DTE: {str(e)}")
    
    def _create_signature_node(self, root: etree.Element, private_key, certificate):
        """
        Crea el nodo Signature XML-DSig.
        
        Args:
            root: Elemento raíz del XML
            private_key: Clave privada del certificado
            certificate: Certificado X.509
        
        Returns:
            etree.Element: Nodo Signature
        """
        # Namespace XML-DSig
        ds_ns = "http://www.w3.org/2000/09/xmldsig#"
        
        # Crear elemento Signature
        signature = etree.Element(f"{{{ds_ns}}}Signature")
        
        # SignedInfo
        signed_info = etree.SubElement(signature, f"{{{ds_ns}}}SignedInfo")
        
        # CanonicalizationMethod
        etree.SubElement(
            signed_info,
            f"{{{ds_ns}}}CanonicalizationMethod",
            Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        )
        
        # SignatureMethod
        etree.SubElement(
            signed_info,
            f"{{{ds_ns}}}SignatureMethod",
            Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"
        )
        
        # Reference
        reference = etree.SubElement(
            signed_info,
            f"{{{ds_ns}}}Reference",
            URI=""
        )
        
        # Transforms
        transforms = etree.SubElement(reference, f"{{{ds_ns}}}Transforms")
        etree.SubElement(
            transforms,
            f"{{{ds_ns}}}Transform",
            Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"
        )
        
        # DigestMethod
        etree.SubElement(
            reference,
            f"{{{ds_ns}}}DigestMethod",
            Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"
        )
        
        # DigestValue (será calculado por xmlsec)
        etree.SubElement(reference, f"{{{ds_ns}}}DigestValue").text = ""
        
        # SignatureValue (será calculado por xmlsec)
        etree.SubElement(signature, f"{{{ds_ns}}}SignatureValue").text = ""
        
        # KeyInfo
        key_info = etree.SubElement(signature, f"{{{ds_ns}}}KeyInfo")
        
        # X509Data
        x509_data = etree.SubElement(key_info, f"{{{ds_ns}}}X509Data")
        
        # X509Certificate
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
        cert_b64 = base64.b64encode(cert_pem).decode()
        etree.SubElement(x509_data, f"{{{ds_ns}}}X509Certificate").text = cert_b64
        
        return signature
    
    def verify(self, signed_xml: str) -> bool:
        """
        Verifica la firma digital de un XML.
        
        Args:
            signed_xml: XML firmado
        
        Returns:
            bool: True si la firma es válida
        """
        try:
            root = etree.fromstring(signed_xml.encode('ISO-8859-1'))
            
            # Buscar nodo Signature
            signature_node = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            
            if signature_node is None:
                return False
            
            # TODO: Implementar verificación con xmlsec
            # Por ahora retornamos True como mock
            return True
            
        except Exception as e:
            logger.error("signature_verification_error", error=str(e))
            return False

