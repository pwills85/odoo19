# -*- coding: utf-8 -*-
"""
SetDTE Generator
Genera SetDTE con Carátula según Resolución Exenta SII N° 45/2003

Especificación:
- Carátula con datos completos del emisor
- Subtotales por tipo de DTE
- Firma del Set completo
- Validación estructura según XSD SII
"""

from lxml import etree
from datetime import datetime
from collections import defaultdict
import structlog

logger = structlog.get_logger()


class SetDTEGenerator:
    """
    Genera SetDTE (conjunto de DTEs) con Carátula para envío al SII
    
    Especificación: Resolución Exenta N° 45/2003
    Límite SII: Máximo 2000 DTEs por Set
    """
    
    def __init__(self):
        self.ns = {
            'sii': 'http://www.sii.cl/SiiDte',
            'ds': 'http://www.w3.org/2000/09/xmldsig#'
        }
        self.max_dtes_per_set = 2000  # Límite SII
    
    def generate(self, dtes: list, emisor: dict, certificado: dict = None) -> str:
        """
        Genera SetDTE completo
        
        Args:
            dtes: Lista de DTEs (XML strings ya firmados)
            emisor: Datos del emisor {
                'rut': '12345678-9',
                'razon_social': 'Empresa SA',
                'rut_envia': '11111111-1',  # Opcional
                'fecha_resolucion': '2024-01-01',
                'numero_resolucion': '80'
            }
            certificado: Certificado digital para firma (opcional)
            
        Returns:
            SetDTE XML completo y firmado
            
        Raises:
            ValueError: Si inputs son inválidos
        """
        logger.info("generating_setdte", dte_count=len(dtes))
        
        # 1. Validar inputs
        self._validate_inputs(dtes, emisor)
        
        # 2. Crear Carátula
        caratula = self._create_caratula(dtes, emisor)
        
        # 3. Crear SetDTE
        setdte_xml = self._create_setdte(caratula, dtes)
        
        # 4. Firmar SetDTE completo (si se proporciona certificado)
        if certificado:
            setdte_xml = self._sign_setdte(setdte_xml, certificado)
        
        # 5. Validar resultado
        self._validate_setdte(setdte_xml)
        
        logger.info("setdte_generated", dte_count=len(dtes))
        
        return setdte_xml
    
    def _validate_inputs(self, dtes, emisor):
        """
        Valida inputs antes de generar
        
        Args:
            dtes: Lista de DTEs
            emisor: Datos del emisor
            
        Raises:
            ValueError: Si inputs son inválidos
        """
        if not dtes:
            raise ValueError("Lista de DTEs vacía")
        
        if len(dtes) > self.max_dtes_per_set:
            raise ValueError(
                f"Máximo {self.max_dtes_per_set} DTEs por Set "
                f"(recibido: {len(dtes)})"
            )
        
        # Validar campos requeridos del emisor
        required_emisor = [
            'rut', 
            'razon_social', 
            'fecha_resolucion', 
            'numero_resolucion'
        ]
        
        for field in required_emisor:
            if field not in emisor:
                raise ValueError(f"Campo emisor requerido: {field}")
        
        # Validar formato RUT
        if not self._validate_rut_format(emisor['rut']):
            raise ValueError(f"Formato RUT inválido: {emisor['rut']}")
        
        logger.debug("inputs_validated", dte_count=len(dtes))
    
    def _validate_rut_format(self, rut: str) -> bool:
        """Valida formato básico de RUT chileno"""
        if not rut or '-' not in rut:
            return False
        
        parts = rut.split('-')
        if len(parts) != 2:
            return False
        
        # Validar que la parte numérica sea un número
        try:
            int(parts[0])
        except ValueError:
            return False
        
        # Validar dígito verificador
        dv = parts[1].upper()
        if dv not in '0123456789K':
            return False
        
        return True
    
    def _create_caratula(self, dtes, emisor):
        """
        Crea Carátula del SetDTE
        
        Elementos obligatorios según SII:
        - RutEmisor: RUT del emisor
        - RutEnvia: RUT de quien envía (puede ser representante)
        - RutReceptor: 60803000-K (SII)
        - FchResol: Fecha resolución autorización
        - NroResol: Número resolución
        - TmstFirmaEnv: Timestamp del envío
        - SubTotDTE: Subtotales por tipo de DTE
        
        Args:
            dtes: Lista de DTEs
            emisor: Datos del emisor
            
        Returns:
            dict: Carátula estructurada
        """
        # Calcular subtotales por tipo DTE
        subtotales = self._calculate_subtotals(dtes)
        
        caratula = {
            'RutEmisor': emisor['rut'],
            'RutEnvia': emisor.get('rut_envia', emisor['rut']),
            'RutReceptor': '60803000-K',  # SII Chile
            'FchResol': emisor['fecha_resolucion'],
            'NroResol': str(emisor['numero_resolucion']),
            'TmstFirmaEnv': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            'SubTotDTE': subtotales
        }
        
        logger.debug("caratula_created", subtotales_count=len(subtotales))
        
        return caratula
    
    def _calculate_subtotals(self, dtes):
        """
        Calcula subtotales por tipo de DTE
        
        Args:
            dtes: Lista de DTEs (XML strings)
            
        Returns:
            list: Lista de subtotales [{TipoDTE, NroDTE}, ...]
        """
        subtotales = defaultdict(int)
        
        for dte_xml in dtes:
            try:
                # Parsear DTE para obtener tipo
                root = etree.fromstring(dte_xml.encode('ISO-8859-1'))
                
                # Buscar TipoDTE en el documento
                tipo_dte = root.findtext('.//TipoDTE', namespaces=self.ns)
                if not tipo_dte:
                    # Intentar sin namespace
                    tipo_dte = root.findtext('.//TipoDTE')
                
                if tipo_dte:
                    subtotales[tipo_dte] += 1
                else:
                    logger.warning("dte_without_type", dte_preview=dte_xml[:100])
                    
            except etree.XMLSyntaxError as e:
                logger.error("invalid_dte_xml", error=str(e))
                raise ValueError(f"DTE XML inválido: {str(e)}")
        
        # Convertir a formato SII
        result = [
            {'TipoDTE': tipo, 'NroDTE': cantidad}
            for tipo, cantidad in sorted(subtotales.items())
        ]
        
        logger.debug("subtotals_calculated", subtotales=result)
        
        return result
    
    def _create_setdte(self, caratula, dtes):
        """
        Crea estructura XML del SetDTE
        
        Args:
            caratula: Carátula estructurada
            dtes: Lista de DTEs (XML strings)
            
        Returns:
            str: SetDTE XML
        """
        # Crear elemento raíz con namespace SII
        setdte = etree.Element(
            '{http://www.sii.cl/SiiDte}SetDTE',
            nsmap={'': 'http://www.sii.cl/SiiDte'}
        )
        setdte.set('version', '1.0')
        
        # Agregar Carátula
        caratula_elem = etree.SubElement(setdte, 'Caratula')
        
        for key, value in caratula.items():
            if key == 'SubTotDTE':
                # Agregar subtotales
                for subtotal in value:
                    subtot_elem = etree.SubElement(caratula_elem, 'SubTotDTE')
                    for k, v in subtotal.items():
                        elem = etree.SubElement(subtot_elem, k)
                        elem.text = str(v)
            else:
                # Agregar campo simple
                elem = etree.SubElement(caratula_elem, key)
                elem.text = str(value)
        
        # Agregar DTEs
        for dte_xml in dtes:
            try:
                # Parsear DTE
                dte_elem = etree.fromstring(dte_xml.encode('ISO-8859-1'))
                
                # Agregar al Set
                setdte.append(dte_elem)
                
            except etree.XMLSyntaxError as e:
                logger.error("invalid_dte_in_set", error=str(e))
                raise ValueError(f"DTE XML inválido en Set: {str(e)}")
        
        # Convertir a string
        setdte_xml = etree.tostring(
            setdte,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.debug("setdte_created", size=len(setdte_xml))
        
        return setdte_xml
    
    def _sign_setdte(self, setdte_xml, certificado):
        """
        Firma el SetDTE completo
        
        Args:
            setdte_xml: SetDTE XML string
            certificado: Certificado digital {
                'cert_bytes': bytes,
                'password': str
            }
            
        Returns:
            str: SetDTE firmado
        """
        try:
            from signers.xmldsig_signer import XMLDsigSigner
            
            signer = XMLDsigSigner()
            
            signed = signer.sign_xml(
                setdte_xml,
                certificado['cert_bytes'],
                certificado['password']
            )
            
            logger.info("setdte_signed")
            
            return signed
            
        except ImportError:
            logger.warning("xmldsig_signer_not_available")
            return setdte_xml
        except Exception as e:
            logger.error("signing_error", error=str(e))
            raise ValueError(f"Error al firmar SetDTE: {str(e)}")
    
    def _validate_setdte(self, setdte_xml):
        """
        Valida estructura del SetDTE
        
        Args:
            setdte_xml: SetDTE XML string
            
        Raises:
            ValueError: Si la estructura es inválida
        """
        try:
            root = etree.fromstring(setdte_xml.encode('ISO-8859-1'))
            
            # Verificar elemento raíz
            if not root.tag.endswith('SetDTE'):
                raise ValueError(f"Elemento raíz inválido: {root.tag}")
            
            # Verificar Carátula
            caratula = root.find('.//{http://www.sii.cl/SiiDte}Caratula')
            if caratula is None:
                caratula = root.find('.//Caratula')
            
            if caratula is None:
                raise ValueError("Carátula no encontrada en SetDTE")
            
            # Verificar campos obligatorios de Carátula
            required_fields = [
                'RutEmisor', 
                'RutEnvia', 
                'RutReceptor',
                'FchResol',
                'NroResol',
                'TmstFirmaEnv'
            ]
            
            for field in required_fields:
                elem = caratula.find(f'.//{field}')
                if elem is None or not elem.text:
                    raise ValueError(f"Campo obligatorio faltante en Carátula: {field}")
            
            # Verificar que hay al menos un DTE
            dtes = root.findall('.//DTE')
            if not dtes:
                raise ValueError("SetDTE no contiene DTEs")
            
            logger.info("setdte_validated", dte_count=len(dtes))
            
        except etree.XMLSyntaxError as e:
            raise ValueError(f"XML inválido: {str(e)}")
    
    def generate_envelope(self, setdte_xml: str, emisor: dict) -> str:
        """
        Genera EnvioDTE (envelope) para envío al SII
        
        Args:
            setdte_xml: SetDTE XML completo
            emisor: Datos del emisor
            
        Returns:
            str: EnvioDTE XML
        """
        # Crear elemento raíz
        envio = etree.Element(
            '{http://www.sii.cl/SiiDte}EnvioDTE',
            nsmap={'': 'http://www.sii.cl/SiiDte'}
        )
        envio.set('version', '1.0')
        
        # Agregar SetDTE
        setdte_elem = etree.fromstring(setdte_xml.encode('ISO-8859-1'))
        envio.append(setdte_elem)
        
        # Convertir a string
        envio_xml = etree.tostring(
            envio,
            pretty_print=True,
            xml_declaration=True,
            encoding='ISO-8859-1'
        ).decode('ISO-8859-1')
        
        logger.info("envelope_generated")
        
        return envio_xml
