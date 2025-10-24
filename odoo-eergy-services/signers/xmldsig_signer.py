# -*- coding: utf-8 -*-
"""
Firmador XMLDsig Real usando xmlsec
Implementa firma digital según W3C XML-Signature y norma SII
"""

from lxml import etree
import xmlsec
from OpenSSL import crypto
import base64
import structlog

logger = structlog.get_logger()


class XMLDsigSigner:
    """
    Firmador XMLDsig profesional usando xmlsec library.
    
    Implementa firma según:
    - W3C XML-Signature Syntax and Processing
    - Especificación técnica SII Chile
    """
    
    def __init__(self):
        # Inicializar xmlsec
        xmlsec.enable_debug_trace(False)
    
    def sign_xml(self, xml_string: str, cert_bytes: bytes, password: str) -> str:
        """
        Firma un XML usando XMLDsig con certificado PKCS#12.
        
        Args:
            xml_string: XML a firmar
            cert_bytes: Bytes del certificado .pfx
            password: Contraseña del certificado
        
        Returns:
            str: XML firmado digitalmente
        """
        logger.info("xmldsig_signing_started")
        
        try:
            # 1. Cargar certificado PKCS#12
            p12 = crypto.load_pkcs12(cert_bytes, password.encode())
            certificate = p12.get_certificate()
            private_key = p12.get_privatekey()
            
            # 2. Convertir clave privada a PEM
            private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
            
            # 3. Parsear XML
            root = etree.fromstring(xml_string.encode('ISO-8859-1'))
            
            # 4. Crear nodo Signature si no existe, o encontrarlo
            signature_node = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            
            if signature_node is None:
                # Crear signature template
                signature_node = self._create_signature_template(root, certificate)
                
                # Buscar dónde insertar (al final del Documento)
                documento = root.find('.//Documento')
                if documento is not None:
                    documento.append(signature_node)
                else:
                    root.append(signature_node)
            
            # 5. Crear contexto de firma con xmlsec
            ctx = xmlsec.SignatureContext()
            
            # 6. Cargar clave privada
            key = xmlsec.Key.from_memory(private_key_pem, xmlsec.KeyDataFormatPem)
            ctx.key = key
            
            # 7. Firmar
            ctx.sign(signature_node)
            
            # 8. Retornar XML firmado
            signed_xml = etree.tostring(
                root,
                pretty_print=True,
                xml_declaration=True,
                encoding='ISO-8859-1'
            ).decode('ISO-8859-1')
            
            logger.info("xmldsig_signing_completed")
            
            return signed_xml
            
        except Exception as e:
            logger.error("xmldsig_signing_error", error=str(e))
            raise Exception(f"Error en firma XMLDsig: {str(e)}")
    
    def _create_signature_template(self, root: etree.Element, certificate) -> etree.Element:
        """
        Crea el template de Signature según W3C XML-Signature.
        
        Args:
            root: Elemento raíz del XML
            certificate: Certificado X.509
        
        Returns:
            etree.Element: Nodo Signature
        """
        # Namespace XML-DSig
        ds_ns = "http://www.w3.org/2000/09/xmldsig#"
        
        # Crear elemento Signature
        signature = etree.Element(f"{{{ds_ns}}}Signature", Id="SignatureDTE")
        
        # SignedInfo
        signed_info = xmlsec.template.create(
            root,
            xmlsec.Transform.EXCL_C14N,  # Canonicalización
            xmlsec.Transform.RSA_SHA1    # Algoritmo de firma
        )
        
        # Reference (referencia al documento completo)
        ref = xmlsec.template.add_reference(
            signed_info,
            xmlsec.Transform.SHA1,  # Algoritmo de digest
            uri=""  # Referencia al documento completo
        )
        
        # Transform enveloped-signature
        xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
        
        # KeyInfo con certificado X.509
        key_info = xmlsec.template.ensure_key_info(signed_info)
        x509_data = xmlsec.template.add_x509_data(key_info)
        
        # Agregar certificado en base64
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
        # Remover headers PEM y convertir a base64 puro
        cert_b64 = base64.b64encode(
            crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)
        ).decode('ascii')
        
        x509_cert = etree.SubElement(x509_data, f"{{{ds_ns}}}X509Certificate")
        x509_cert.text = cert_b64
        
        return signed_info
    
    def verify_signature(self, signed_xml: str) -> bool:
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
                logger.error("signature_node_not_found")
                return False
            
            # Crear contexto de verificación
            ctx = xmlsec.SignatureContext()
            
            # Verificar
            ctx.verify(signature_node)
            
            logger.info("signature_verified")
            return True
            
        except Exception as e:
            logger.error("signature_verification_failed", error=str(e))
            return False

