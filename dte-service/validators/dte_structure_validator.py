# -*- coding: utf-8 -*-
"""
Validador de Estructura DTE
Valida estructura completa DTE según normativa SII Chile

Referencias:
- Resolución Ex. SII N° 45 del 2003
- Circular N° 45 del 2007
- Manual DTE SII v1.0
"""

from lxml import etree
import structlog

logger = structlog.get_logger()


class DTEStructureValidator:
    """
    Valida estructura completa DTE según normativa SII.
    
    Verifica que el XML del DTE contenga todos los elementos
    requeridos por el SII para cada tipo de documento.
    """
    
    # Elementos requeridos por tipo de DTE según normativa SII
    REQUIRED_ELEMENTS = {
        '33': [  # Factura Electrónica
            'Documento/Encabezado/IdDoc/TipoDTE',
            'Documento/Encabezado/IdDoc/Folio',
            'Documento/Encabezado/IdDoc/FchEmis',
            'Documento/Encabezado/Emisor/RUTEmisor',
            'Documento/Encabezado/Emisor/RznSoc',
            'Documento/Encabezado/Emisor/GiroEmis',
            'Documento/Encabezado/Emisor/Acteco',
            'Documento/Encabezado/Emisor/DirOrigen',
            'Documento/Encabezado/Emisor/CmnaOrigen',
            'Documento/Encabezado/Receptor/RUTRecep',
            'Documento/Encabezado/Receptor/RznSocRecep',
            'Documento/Encabezado/Receptor/DirRecep',
            'Documento/Encabezado/Receptor/CmnaRecep',
            'Documento/Encabezado/Totales/MntNeto',
            'Documento/Encabezado/Totales/TasaIVA',
            'Documento/Encabezado/Totales/IVA',
            'Documento/Encabezado/Totales/MntTotal',
            'Documento/Detalle',
            'Documento/TED',  # ⭐ CRÍTICO: Timbre Electrónico Digital
        ],
        '34': [  # Liquidación de Honorarios (Factura de Compra Electrónica)
            'Documento/Encabezado/IdDoc/TipoDTE',
            'Documento/Encabezado/IdDoc/Folio',
            'Documento/Encabezado/IdDoc/FchEmis',
            'Documento/Encabezado/Emisor/RUTEmisor',
            'Documento/Encabezado/Emisor/RznSoc',
            'Documento/Encabezado/Receptor/RUTRecep',
            'Documento/Encabezado/Receptor/RznSocRecep',
            'Documento/Encabezado/Totales/MntBruto',
            'Documento/Encabezado/Totales/MntRetenciones',
            'Documento/Encabezado/Totales/MntTotal',
            'Documento/Detalle',
            'Documento/TED',
        ],
        '52': [  # Guía de Despacho Electrónica
            'Documento/Encabezado/IdDoc/TipoDTE',
            'Documento/Encabezado/IdDoc/Folio',
            'Documento/Encabezado/IdDoc/FchEmis',
            'Documento/Encabezado/IdDoc/IndTraslado',  # Indicador tipo de traslado
            'Documento/Encabezado/Emisor/RUTEmisor',
            'Documento/Encabezado/Emisor/RznSoc',
            'Documento/Encabezado/Receptor/RUTRecep',
            'Documento/Encabezado/Receptor/RznSocRecep',
            'Documento/Detalle',
            'Documento/TED',
        ],
        '56': [  # Nota de Débito Electrónica
            'Documento/Encabezado/IdDoc/TipoDTE',
            'Documento/Encabezado/IdDoc/Folio',
            'Documento/Encabezado/IdDoc/FchEmis',
            'Documento/Encabezado/Emisor/RUTEmisor',
            'Documento/Encabezado/Emisor/RznSoc',
            'Documento/Encabezado/Receptor/RUTRecep',
            'Documento/Encabezado/Receptor/RznSocRecep',
            'Documento/Encabezado/Totales/MntTotal',
            'Documento/Detalle',
            'Documento/TED',
            'Documento/Referencia',  # Referencia al documento original
        ],
        '61': [  # Nota de Crédito Electrónica
            'Documento/Encabezado/IdDoc/TipoDTE',
            'Documento/Encabezado/IdDoc/Folio',
            'Documento/Encabezado/IdDoc/FchEmis',
            'Documento/Encabezado/Emisor/RUTEmisor',
            'Documento/Encabezado/Emisor/RznSoc',
            'Documento/Encabezado/Receptor/RUTRecep',
            'Documento/Encabezado/Receptor/RznSocRecep',
            'Documento/Encabezado/Totales/MntTotal',
            'Documento/Detalle',
            'Documento/TED',
            'Documento/Referencia',  # Referencia al documento original
        ],
    }
    
    def __init__(self):
        """Inicializa el validador de estructura"""
        self.errors = []
        self.warnings = []
    
    def validate(self, xml_string: str, dte_type: str) -> tuple:
        """
        Valida que XML tenga todos los elementos requeridos por SII.
        
        Args:
            xml_string: XML del DTE
            dte_type: Tipo de DTE ('33', '34', '52', '56', '61')
        
        Returns:
            tuple: (is_valid: bool, errors: list, warnings: list)
        """
        logger.info("dte_structure_validation_started", dte_type=dte_type)
        
        self.errors = []
        self.warnings = []
        
        try:
            # Parsear XML
            tree = etree.fromstring(xml_string.encode('ISO-8859-1'))
            
            # Obtener elementos requeridos para este tipo de DTE
            required = self.REQUIRED_ELEMENTS.get(dte_type, [])
            
            if not required:
                self.warnings.append({
                    'dte_type': dte_type,
                    'message': f'No hay validación definida para DTE tipo {dte_type}',
                    'severity': 'warning'
                })
                logger.warning("no_validation_defined", dte_type=dte_type)
                return (True, self.errors, self.warnings)
            
            # Validar elementos requeridos
            missing = []
            for xpath in required:
                elements = tree.xpath(f'//{xpath}')
                if not elements:
                    missing.append(xpath)
            
            if missing:
                self.errors.append({
                    'dte_type': dte_type,
                    'message': f'DTE {dte_type} falta elementos requeridos por SII',
                    'severity': 'critical',
                    'missing_elements': missing,
                    'missing_count': len(missing)
                })
                logger.error("dte_missing_elements",
                           dte_type=dte_type,
                           count=len(missing),
                           elements=missing)
            
            # Validaciones adicionales específicas por tipo
            self._validate_specific_rules(tree, dte_type)
            
            # Determinar si es válido
            is_valid = len(self.errors) == 0
            
            if is_valid:
                logger.info("dte_structure_validation_passed",
                          dte_type=dte_type,
                          warnings=len(self.warnings))
            else:
                logger.warning("dte_structure_validation_failed",
                             dte_type=dte_type,
                             errors=len(self.errors),
                             warnings=len(self.warnings))
            
            return (is_valid, self.errors, self.warnings)
            
        except Exception as e:
            logger.error("dte_structure_validation_error", error=str(e))
            self.errors.append({
                'dte_type': dte_type,
                'message': f'Error al validar estructura DTE: {str(e)}',
                'severity': 'critical'
            })
            return (False, self.errors, self.warnings)
    
    def _validate_specific_rules(self, tree, dte_type: str):
        """Validaciones específicas por tipo de DTE"""
        
        if dte_type == '33':
            # Factura Electrónica: Validar IVA
            self._validate_iva(tree)
        
        elif dte_type == '34':
            # Liquidación Honorarios: Validar retenciones
            self._validate_retenciones(tree)
        
        elif dte_type == '52':
            # Guía de Despacho: Validar tipo de traslado
            self._validate_tipo_traslado(tree)
        
        elif dte_type in ['56', '61']:
            # Notas: Validar referencia
            self._validate_referencia(tree)
    
    def _validate_iva(self, tree):
        """Valida cálculo de IVA en factura"""
        try:
            mnt_neto = tree.findtext('.//Totales/MntNeto')
            tasa_iva = tree.findtext('.//Totales/TasaIVA')
            iva = tree.findtext('.//Totales/IVA')
            
            if mnt_neto and tasa_iva and iva:
                neto = float(mnt_neto)
                tasa = float(tasa_iva)
                iva_calculado = round(neto * tasa / 100)
                iva_declarado = float(iva)
                
                if abs(iva_calculado - iva_declarado) > 1:  # Tolerancia de 1 peso
                    self.warnings.append({
                        'element': 'Totales/IVA',
                        'message': f'IVA calculado ({iva_calculado}) difiere del declarado ({iva_declarado})',
                        'severity': 'warning'
                    })
        except (ValueError, TypeError) as e:
            self.warnings.append({
                'element': 'Totales',
                'message': f'Error al validar IVA: {str(e)}',
                'severity': 'warning'
            })
    
    def _validate_retenciones(self, tree):
        """Valida retenciones en liquidación de honorarios"""
        mnt_retenciones = tree.findtext('.//Totales/MntRetenciones')
        
        if not mnt_retenciones:
            self.warnings.append({
                'element': 'Totales/MntRetenciones',
                'message': 'Liquidación de honorarios sin retenciones especificadas',
                'severity': 'warning'
            })
    
    def _validate_tipo_traslado(self, tree):
        """Valida tipo de traslado en guía de despacho"""
        ind_traslado = tree.findtext('.//IdDoc/IndTraslado')
        
        # Tipos válidos según SII: 1-9
        if ind_traslado:
            try:
                tipo = int(ind_traslado)
                if tipo < 1 or tipo > 9:
                    self.errors.append({
                        'element': 'IdDoc/IndTraslado',
                        'message': f'Tipo de traslado inválido: {tipo}. Debe estar entre 1 y 9',
                        'severity': 'error'
                    })
            except ValueError:
                self.errors.append({
                    'element': 'IdDoc/IndTraslado',
                    'message': f'Tipo de traslado no es un número: {ind_traslado}',
                    'severity': 'error'
                })
    
    def _validate_referencia(self, tree):
        """Valida referencia en notas de crédito/débito"""
        referencias = tree.xpath('.//Referencia')
        
        if not referencias:
            self.errors.append({
                'element': 'Referencia',
                'message': 'Nota de crédito/débito debe tener al menos una referencia al documento original',
                'severity': 'critical'
            })
            return
        
        # Validar que tenga los campos mínimos
        for idx, ref in enumerate(referencias, 1):
            tipo_doc_ref = ref.findtext('TpoDocRef')
            folio_ref = ref.findtext('FolioRef')
            
            if not tipo_doc_ref:
                self.errors.append({
                    'element': f'Referencia[{idx}]/TpoDocRef',
                    'message': 'Referencia debe tener tipo de documento',
                    'severity': 'error'
                })
            
            if not folio_ref:
                self.errors.append({
                    'element': f'Referencia[{idx}]/FolioRef',
                    'message': 'Referencia debe tener folio del documento',
                    'severity': 'error'
                })
    
    def get_validation_summary(self, xml_string: str, dte_type: str) -> dict:
        """
        Retorna un resumen de la validación de estructura.
        
        Args:
            xml_string: XML del DTE
            dte_type: Tipo de DTE
        
        Returns:
            dict: Resumen con is_valid, errors, warnings
        """
        is_valid, errors, warnings = self.validate(xml_string, dte_type)
        
        return {
            'is_valid': is_valid,
            'dte_type': dte_type,
            'error_count': len(errors),
            'warning_count': len(warnings),
            'errors': errors,
            'warnings': warnings,
            'validator': 'DTEStructureValidator',
            'references': [
                'Resolución Ex. SII N° 45 del 2003',
                'Circular N° 45 del 2007',
                'Manual DTE SII v1.0'
            ]
        }


# Función helper para uso directo
def validate_dte_structure(xml_string: str, dte_type: str) -> bool:
    """
    Valida estructura de un DTE.
    Función de conveniencia.
    
    Args:
        xml_string: XML del DTE
        dte_type: Tipo de DTE ('33', '34', '52', '56', '61')
    
    Returns:
        bool: True si estructura es válida
    """
    validator = DTEStructureValidator()
    is_valid, _, _ = validator.validate(xml_string, dte_type)
    return is_valid
