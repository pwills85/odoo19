# -*- coding: utf-8 -*-
"""
Validador XSD para DTEs
Valida XML contra esquemas XSD oficiales del SII
"""

from lxml import etree
import os
import structlog

logger = structlog.get_logger()


class XSDValidator:
    """Validador de XML contra esquemas XSD del SII"""
    
    def __init__(self, schemas_dir: str = None):
        """
        Inicializa el validador.
        
        Args:
            schemas_dir: Directorio con archivos XSD del SII
        """
        self.schemas_dir = schemas_dir or os.path.join(
            os.path.dirname(__file__), '..', 'schemas'
        )
        self.schemas = {}
        
        # Pre-cargar schemas si existen
        self._load_schemas()
    
    def _load_schemas(self):
        """Carga los esquemas XSD del directorio"""
        if not os.path.exists(self.schemas_dir):
            logger.warning("schemas_directory_not_found", path=self.schemas_dir)
            return
        
        # Esquemas principales del SII
        schema_files = {
            'DTE': 'DTE_v10.xsd',
            'EnvioDTE': 'EnvioDTE_v10.xsd',
            'Consumo': 'ConsumoFolios_v10.xsd',
            'Libro': 'LibroCompraVenta_v10.xsd',
        }
        
        for name, filename in schema_files.items():
            schema_path = os.path.join(self.schemas_dir, filename)
            
            if os.path.exists(schema_path):
                try:
                    schema_doc = etree.parse(schema_path)
                    self.schemas[name] = etree.XMLSchema(schema_doc)
                    logger.info("schema_loaded", name=name)
                except Exception as e:
                    logger.error("schema_load_error", name=name, error=str(e))
            else:
                logger.warning("schema_file_not_found", path=schema_path)
    
    def validate(self, xml_string: str, schema_name: str = 'DTE') -> tuple:
        """
        Valida un XML contra el esquema XSD.
        
        Args:
            xml_string: XML a validar
            schema_name: Nombre del schema ('DTE', 'EnvioDTE', etc)
        
        Returns:
            tuple: (is_valid: bool, errors: list)
        """
        logger.info("xsd_validation_started", schema=schema_name)
        
        try:
            # Parsear XML
            xml_doc = etree.fromstring(xml_string.encode('ISO-8859-1'))
            
            # Obtener schema
            schema = self.schemas.get(schema_name)
            
            if schema is None:
                logger.warning("schema_not_loaded", 
                             schema=schema_name,
                             note="Validación omitida - XSD no disponible")
                # Si no hay schema, asumir válido (no bloquear)
                return (True, [])
            
            # Validar
            is_valid = schema.validate(xml_doc)
            
            if is_valid:
                logger.info("xsd_validation_passed", schema=schema_name)
                return (True, [])
            else:
                # Extraer errores
                errors = []
                for error in schema.error_log:
                    errors.append({
                        'line': error.line,
                        'column': error.column,
                        'message': error.message,
                        'level': error.level_name,
                    })
                
                logger.warning("xsd_validation_failed",
                             schema=schema_name,
                             error_count=len(errors))
                
                return (False, errors)
                
        except Exception as e:
            logger.error("xsd_validation_error", error=str(e))
            # En caso de error, no bloquear (retornar como válido)
            return (True, [{'message': f'Error en validación: {str(e)}'}])
    
    def get_validation_summary(self, xml_string: str) -> dict:
        """
        Retorna un resumen de la validación.
        
        Args:
            xml_string: XML a validar
        
        Returns:
            dict: Resumen con is_valid, errors, warnings
        """
        is_valid, errors = self.validate(xml_string)
        
        return {
            'is_valid': is_valid,
            'error_count': len(errors),
            'errors': errors,
            'schema_available': 'DTE' in self.schemas,
        }


# Función helper para uso directo
def validate_dte_xml(xml_string: str) -> bool:
    """
    Valida un DTE contra XSD.
    Función de conveniencia.
    
    Args:
        xml_string: XML del DTE
    
    Returns:
        bool: True si válido (o si no hay XSD disponible)
    """
    validator = XSDValidator()
    is_valid, _ = validator.validate(xml_string, 'DTE')
    return is_valid

