# -*- coding: utf-8 -*-
"""
Manejador de CAF (Código de Autorización de Folios)
Incluye el CAF en el XML del DTE según norma SII
"""

from lxml import etree
import structlog

logger = structlog.get_logger()


class CAFHandler:
    """Manejador de CAF para inclusión en DTEs"""
    
    def __init__(self):
        pass
    
    def include_caf_in_dte(self, dte_xml: str, caf_xml: str) -> str:
        """
        Incluye el CAF dentro del XML del DTE.
        
        El CAF debe incluirse dentro del elemento <Documento> del DTE,
        después de los detalles y antes de la firma.
        
        Args:
            dte_xml: XML del DTE sin CAF
            caf_xml: XML del CAF (del archivo .xml del SII)
        
        Returns:
            str: XML del DTE con CAF incluido
        """
        logger.info("including_caf_in_dte")
        
        try:
            # Parsear DTE
            dte_root = etree.fromstring(dte_xml.encode('ISO-8859-1'))
            
            # Parsear CAF
            caf_root = etree.fromstring(caf_xml.encode('ISO-8859-1'))
            
            # Buscar elemento <Documento> en el DTE
            # Estructura típica: <DTE><Documento>...</Documento></DTE>
            documento = dte_root.find('.//Documento')
            
            if documento is None:
                raise ValueError("No se encontró elemento <Documento> en el DTE")
            
            # El CAF debe insertarse después del último <Detalle> y antes de cualquier firma
            # Buscamos dónde insertar
            detalle_elements = documento.findall('Detalle')
            
            if detalle_elements:
                # Insertar después del último detalle
                last_detalle = detalle_elements[-1]
                index = list(documento).index(last_detalle) + 1
            else:
                # Si no hay detalles, insertar al final antes de firma
                index = len(list(documento))
            
            # Insertar CAF
            documento.insert(index, caf_root)
            
            # Retornar XML completo con CAF
            dte_with_caf = etree.tostring(
                dte_root,
                pretty_print=True,
                xml_declaration=True,
                encoding='ISO-8859-1'
            ).decode('ISO-8859-1')
            
            logger.info("caf_included_successfully")
            
            return dte_with_caf
            
        except Exception as e:
            logger.error("caf_inclusion_error", error=str(e))
            raise Exception(f"Error al incluir CAF en DTE: {str(e)}")
    
    def validate_folio_in_caf(self, folio: int, caf_xml: str) -> bool:
        """
        Valida que un folio esté dentro del rango autorizado del CAF.
        
        Args:
            folio: Número de folio a validar
            caf_xml: XML del CAF
        
        Returns:
            bool: True si el folio está en el rango del CAF
        """
        try:
            # Parsear CAF
            caf_root = etree.fromstring(caf_xml.encode('ISO-8859-1'))
            
            # Extraer rango de folios
            # Estructura puede variar: <CAF><DA><RNG><D> y <H>
            folio_desde_elem = caf_root.find('.//RNG/D') or caf_root.find('.//CAF/DA/RNG/D')
            folio_hasta_elem = caf_root.find('.//RNG/H') or caf_root.find('.//CAF/DA/RNG/H')
            
            if folio_desde_elem is not None and folio_hasta_elem is not None:
                folio_desde = int(folio_desde_elem.text)
                folio_hasta = int(folio_hasta_elem.text)
                
                is_valid = folio_desde <= folio <= folio_hasta
                
                if not is_valid:
                    logger.warning("folio_out_of_caf_range",
                                 folio=folio,
                                 caf_range=f"{folio_desde}-{folio_hasta}")
                
                return is_valid
            else:
                logger.error("caf_range_not_found_in_xml")
                return False
                
        except Exception as e:
            logger.error("caf_validation_error", error=str(e))
            return False

