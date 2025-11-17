# -*- coding: utf-8 -*-
"""
Validador TED (Timbre Electrónico Digital)
Valida estructura TED según normativa SII Chile

Referencia: Resolución Ex. SII N° 45 del 2003
"""

from lxml import etree
import structlog

logger = structlog.get_logger()


class TEDValidator:
    """
    Valida estructura TED según normativa SII.
    
    El TED (Timbre Electrónico Digital) es un elemento crítico del DTE
    que contiene el resumen del documento y debe incluir el CAF.
    
    Referencia: Resolución Ex. SII N° 45 del 2003
    """
    
    # Elementos requeridos según normativa SII
    REQUIRED_TED_ELEMENTS = [
        'DD/RE',           # RUT Emisor
        'DD/TD',           # Tipo DTE
        'DD/F',            # Folio
        'DD/FE',           # Fecha Emisión
        'DD/RR',           # RUT Receptor
        'DD/RSR',          # Razón Social Receptor
        'DD/MNT',          # Monto Total
        'DD/IT1',          # Item 1 (descripción primer item)
        'DD/CAF',          # ⭐ CRÍTICO: CAF incluido
        'DD/CAF/DA',       # Datos CAF
        'DD/CAF/FRMA',     # Firma CAF
        'DD/TSTED',        # Timestamp TED
        'FRMT',            # Firma TED
    ]
    
    # Algoritmo de firma requerido por SII
    REQUIRED_SIGNATURE_ALGORITHM = 'SHA1withRSA'
    
    def __init__(self):
        """Inicializa el validador TED"""
        self.errors = []
        self.warnings = []
    
    def validate(self, xml_string: str) -> tuple:
        """
        Valida que TED tenga estructura correcta según SII.
        
        Args:
            xml_string: XML del DTE completo
        
        Returns:
            tuple: (is_valid: bool, errors: list, warnings: list)
        """
        logger.info("ted_validation_started")
        
        self.errors = []
        self.warnings = []
        
        try:
            # Parsear XML
            tree = etree.fromstring(xml_string.encode('ISO-8859-1'))
            
            # Buscar elemento TED
            ted = tree.find('.//TED')
            
            if ted is None:
                self.errors.append({
                    'element': 'TED',
                    'message': 'XML no contiene elemento TED',
                    'severity': 'critical'
                })
                logger.error("ted_not_found")
                return (False, self.errors, self.warnings)
            
            # Validar elementos requeridos
            self._validate_required_elements(ted)
            
            # Validar algoritmo de firma
            self._validate_signature_algorithm(ted)
            
            # Validar estructura CAF
            self._validate_caf_structure(ted)
            
            # Validar formato de datos
            self._validate_data_format(ted)
            
            # Determinar si es válido
            is_valid = len(self.errors) == 0
            
            if is_valid:
                logger.info("ted_validation_passed", 
                          warnings=len(self.warnings))
            else:
                logger.warning("ted_validation_failed",
                             error_count=len(self.errors),
                             warning_count=len(self.warnings))
            
            return (is_valid, self.errors, self.warnings)
            
        except Exception as e:
            logger.error("ted_validation_error", error=str(e))
            self.errors.append({
                'element': 'TED',
                'message': f'Error al validar TED: {str(e)}',
                'severity': 'critical'
            })
            return (False, self.errors, self.warnings)
    
    def _validate_required_elements(self, ted):
        """Valida que todos los elementos requeridos estén presentes"""
        missing = []
        
        for xpath in self.REQUIRED_TED_ELEMENTS:
            element = ted.find(xpath)
            if element is None:
                missing.append(xpath)
        
        if missing:
            self.errors.append({
                'element': 'TED',
                'message': f'TED falta elementos requeridos SII: {", ".join(missing)}',
                'severity': 'critical',
                'missing_elements': missing
            })
            logger.error("ted_missing_elements", elements=missing)
    
    def _validate_signature_algorithm(self, ted):
        """Valida que el algoritmo de firma sea correcto"""
        frmt = ted.find('FRMT')
        
        if frmt is not None:
            algoritmo = frmt.get('algoritmo')
            
            if algoritmo != self.REQUIRED_SIGNATURE_ALGORITHM:
                self.errors.append({
                    'element': 'FRMT',
                    'message': f'Algoritmo TED incorrecto: {algoritmo}. '
                              f'Debe ser {self.REQUIRED_SIGNATURE_ALGORITHM}',
                    'severity': 'critical',
                    'found': algoritmo,
                    'expected': self.REQUIRED_SIGNATURE_ALGORITHM
                })
                logger.error("ted_invalid_algorithm", 
                           found=algoritmo,
                           expected=self.REQUIRED_SIGNATURE_ALGORITHM)
        else:
            self.errors.append({
                'element': 'FRMT',
                'message': 'Elemento FRMT (firma TED) no encontrado',
                'severity': 'critical'
            })
    
    def _validate_caf_structure(self, ted):
        """Valida que el CAF esté presente y tenga estructura correcta"""
        caf = ted.find('DD/CAF')
        
        if caf is None:
            self.errors.append({
                'element': 'CAF',
                'message': 'CAF no encontrado en TED. El CAF es obligatorio según SII.',
                'severity': 'critical'
            })
            return
        
        # Validar elementos del CAF
        da = caf.find('DA')
        frma = caf.find('FRMA')
        
        if da is None:
            self.errors.append({
                'element': 'CAF/DA',
                'message': 'Datos del CAF (DA) no encontrados',
                'severity': 'critical'
            })
        
        if frma is None:
            self.errors.append({
                'element': 'CAF/FRMA',
                'message': 'Firma del CAF (FRMA) no encontrada',
                'severity': 'critical'
            })
    
    def _validate_data_format(self, ted):
        """Valida formato de datos en TED"""
        dd = ted.find('DD')
        
        if dd is None:
            return
        
        # Validar RUT emisor
        re_element = dd.find('RE')
        if re_element is not None and re_element.text:
            if not self._validate_rut_format(re_element.text):
                self.warnings.append({
                    'element': 'DD/RE',
                    'message': f'Formato RUT emisor puede ser inválido: {re_element.text}',
                    'severity': 'warning'
                })
        
        # Validar RUT receptor
        rr_element = dd.find('RR')
        if rr_element is not None and rr_element.text:
            if not self._validate_rut_format(rr_element.text):
                self.warnings.append({
                    'element': 'DD/RR',
                    'message': f'Formato RUT receptor puede ser inválido: {rr_element.text}',
                    'severity': 'warning'
                })
        
        # Validar monto
        mnt_element = dd.find('MNT')
        if mnt_element is not None and mnt_element.text:
            try:
                monto = int(mnt_element.text)
                if monto <= 0:
                    self.warnings.append({
                        'element': 'DD/MNT',
                        'message': f'Monto debe ser mayor a 0: {monto}',
                        'severity': 'warning'
                    })
            except ValueError:
                self.errors.append({
                    'element': 'DD/MNT',
                    'message': f'Monto no es un número válido: {mnt_element.text}',
                    'severity': 'error'
                })
    
    def _validate_rut_format(self, rut: str) -> bool:
        """
        Validación básica de formato RUT.
        
        NOTA: Esta es una validación simple de formato.
        La validación completa de RUT la hace l10n_cl.
        """
        if not rut:
            return False
        
        # Formato esperado: 12345678-9
        if '-' not in rut:
            return False
        
        parts = rut.split('-')
        if len(parts) != 2:
            return False
        
        # Parte numérica debe ser número
        try:
            int(parts[0])
        except ValueError:
            return False
        
        # Dígito verificador debe ser número o K
        if not (parts[1].isdigit() or parts[1].upper() == 'K'):
            return False
        
        return True
    
    def get_validation_summary(self, xml_string: str) -> dict:
        """
        Retorna un resumen de la validación TED.
        
        Args:
            xml_string: XML del DTE
        
        Returns:
            dict: Resumen con is_valid, errors, warnings
        """
        is_valid, errors, warnings = self.validate(xml_string)
        
        return {
            'is_valid': is_valid,
            'error_count': len(errors),
            'warning_count': len(warnings),
            'errors': errors,
            'warnings': warnings,
            'validator': 'TEDValidator',
            'reference': 'Resolución Ex. SII N° 45 del 2003'
        }


# Función helper para uso directo
def validate_ted(xml_string: str) -> bool:
    """
    Valida TED de un DTE.
    Función de conveniencia.
    
    Args:
        xml_string: XML del DTE
    
    Returns:
        bool: True si TED es válido
    """
    validator = TEDValidator()
    is_valid, _, _ = validator.validate(xml_string)
    return is_valid
