# -*- coding: utf-8 -*-
"""
Generador de TED (Timbre Electrónico DTE)
Según especificación técnica del SII de Chile

El TED es un sello electrónico que se incluye en el DTE y permite
verificar su autenticidad mediante un código QR.
"""

from lxml import etree
import hashlib
import base64
import qrcode
from io import BytesIO
import structlog

logger = structlog.get_logger()


class TEDGenerator:
    """Generador de Timbre Electrónico (TED) para DTEs"""
    
    def __init__(self):
        pass
    
    def generate_ted(self, dte_data: dict, private_key_pem: bytes) -> tuple:
        """
        Genera el Timbre Electrónico (TED) completo.
        
        Args:
            dte_data: Datos del DTE (folio, fecha, RUT, montos, etc)
            private_key_pem: Clave privada en formato PEM para firmar
        
        Returns:
            tuple: (ted_xml_string, qr_image_base64)
        """
        logger.info("generating_ted", folio=dte_data.get('folio'))
        
        # 1. Calcular DD (Digest del Documento)
        dd_value = self._calculate_dd(dte_data)
        
        # 2. Generar XML TED
        ted_xml = self._create_ted_xml(dte_data, dd_value)
        
        # 3. Firmar TED con RSA (FRMT)
        ted_xml_signed = self._sign_ted(ted_xml, private_key_pem)
        
        # 4. Generar QR code
        qr_image_b64 = self._generate_qr_code(ted_xml_signed)
        
        logger.info("ted_generated", folio=dte_data.get('folio'))
        
        return (ted_xml_signed, qr_image_b64)
    
    def _calculate_dd(self, dte_data: dict) -> str:
        """
        Calcula el DD (Digest del Documento) según norma SII.
        
        DD = SHA-1 de concatenación de campos clave
        
        Args:
            dte_data: Datos del DTE
        
        Returns:
            str: Hash SHA-1 en base64
        """
        # Campos que componen el DD según SII
        # Formato: RUT_EMISOR|TIPO_DTE|FOLIO|FECHA_EMISION|MONTO_TOTAL|RUT_RECEPTOR
        
        rut_emisor = dte_data.get('rut_emisor', '').replace('.', '').replace(' ', '')
        tipo_dte = str(dte_data.get('tipo_dte', '33'))
        folio = str(dte_data.get('folio', ''))
        fecha = dte_data.get('fecha_emision', '')
        monto = str(int(dte_data.get('monto_total', 0)))
        rut_receptor = dte_data.get('rut_receptor', '').replace('.', '').replace(' ', '')
        
        # Concatenar según formato SII
        dd_string = f"{rut_emisor}{tipo_dte}{folio}{fecha}{monto}{rut_receptor}"
        
        # Calcular hash SHA-1
        dd_hash = hashlib.sha1(dd_string.encode('ISO-8859-1')).digest()
        
        # Retornar en base64
        dd_b64 = base64.b64encode(dd_hash).decode('ascii')
        
        logger.debug("dd_calculated", dd=dd_b64[:20])
        
        return dd_b64
    
    def _create_ted_xml(self, dte_data: dict, dd_value: str) -> str:
        """
        Crea la estructura XML del TED según norma SII.
        
        Args:
            dte_data: Datos del DTE
            dd_value: Hash DD calculado
        
        Returns:
            str: XML del TED (sin firmar aún)
        """
        # Crear elemento raíz TED
        ted = etree.Element('TED', version="1.0")
        
        # DD: Datos del Documento
        dd = etree.SubElement(ted, 'DD')
        
        # RE: RUT Emisor
        etree.SubElement(dd, 'RE').text = dte_data.get('rut_emisor', '').replace('.', '')
        
        # TD: Tipo de Documento
        etree.SubElement(dd, 'TD').text = str(dte_data.get('tipo_dte', '33'))
        
        # F: Folio
        etree.SubElement(dd, 'F').text = str(dte_data.get('folio', ''))
        
        # FE: Fecha Emisión
        etree.SubElement(dd, 'FE').text = dte_data.get('fecha_emision', '')
        
        # RR: RUT Receptor
        etree.SubElement(dd, 'RR').text = dte_data.get('rut_receptor', '').replace('.', '')
        
        # RSR: Razón Social Receptor
        etree.SubElement(dd, 'RSR').text = dte_data.get('razon_social_receptor', '')[:40]  # Max 40 chars
        
        # MNT: Monto Total
        etree.SubElement(dd, 'MNT').text = str(int(dte_data.get('monto_total', 0)))
        
        # IT1: Item 1 (descripción primer ítem)
        if dte_data.get('primer_item'):
            etree.SubElement(dd, 'IT1').text = dte_data['primer_item'][:40]  # Max 40 chars
        
        # CAF: Incluir datos del CAF (rango de folios)
        caf = etree.SubElement(dd, 'CAF')
        da = etree.SubElement(caf, 'DA')
        
        rng = etree.SubElement(da, 'RNG')
        etree.SubElement(rng, 'D').text = str(dte_data.get('caf_folio_desde', ''))
        etree.SubElement(rng, 'H').text = str(dte_data.get('caf_folio_hasta', ''))
        
        # TSTED: Timestamp
        etree.SubElement(dd, 'TSTED').text = dte_data.get('timestamp', '')
        
        # Convertir DD a string para firmar
        dd_string = etree.tostring(dd, encoding='ISO-8859-1').decode('ISO-8859-1')
        
        # FRMT: Firma del TED (se agregará después de firmar)
        # Por ahora, placeholder
        etree.SubElement(ted, 'FRMT', algoritmo="SHA1withRSA").text = "PENDIENTE_FIRMA"
        
        # Convertir a string
        ted_string = etree.tostring(
            ted,
            pretty_print=True,
            xml_declaration=False,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        return ted_string
    
    def _sign_ted(self, ted_xml: str, private_key_pem: bytes) -> str:
        """
        Firma el TED con la clave privada (algoritmo RSA-SHA1).
        
        Args:
            ted_xml: XML del TED sin firmar
            private_key_pem: Clave privada en PEM
        
        Returns:
            str: XML del TED firmado
        """
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        
        # Parsear TED
        root = etree.fromstring(ted_xml.encode('ISO-8859-1'))
        
        # Extraer elemento DD para firmar
        dd = root.find('DD')
        dd_string = etree.tostring(dd, encoding='ISO-8859-1')
        
        # Cargar clave privada
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        # Firmar DD con RSA-SHA1
        signature = private_key.sign(
            dd_string,
            padding.PKCS1v15(),
            hashes.SHA1()
        )
        
        # Convertir firma a base64
        signature_b64 = base64.b64encode(signature).decode('ascii')
        
        # Actualizar elemento FRMT
        frmt = root.find('FRMT')
        frmt.text = signature_b64
        
        # Retornar TED firmado
        ted_signed = etree.tostring(
            root,
            pretty_print=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        return ted_signed
    
    def _generate_qr_code(self, ted_xml: str) -> str:
        """
        Genera código QR del TED.
        
        Args:
            ted_xml: XML del TED firmado
        
        Returns:
            str: Imagen QR en base64
        """
        # Crear QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        
        # Agregar datos del TED
        qr.add_data(ted_xml)
        qr.make(fit=True)
        
        # Crear imagen
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convertir a base64
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_b64 = base64.b64encode(buffer.getvalue()).decode('ascii')
        
        return img_b64

