# -*- coding: utf-8 -*-
"""
Receiver de DTEs - Polling y descarga de DTEs recibidos desde el SII
"""

from clients.sii_soap_client import SIISoapClient
import structlog
from typing import List, Dict

logger = structlog.get_logger()


class DTEReceiver:
    """
    Receptor de DTEs del SII.
    
    Realiza polling periódico al SII para descargar DTEs recibidos
    de proveedores y los procesa automáticamente.
    """
    
    def __init__(self, sii_wsdl_url: str, timeout: int = 60):
        """
        Inicializa el receiver.
        
        Args:
            sii_wsdl_url: URL del WSDL del SII
            timeout: Timeout para operaciones SOAP
        """
        self.client = SIISoapClient(sii_wsdl_url, timeout)
        logger.info("dte_receiver_initialized")
    
    def poll_received_dtes(self, rut_receptor: str) -> List[Dict]:
        """
        Consulta al SII por DTEs recibidos pendientes de procesar.
        
        Este método se ejecuta periódicamente (ej: cada 30 minutos)
        mediante un cron job.
        
        Args:
            rut_receptor: RUT de la empresa receptora
        
        Returns:
            List[Dict]: Lista de DTEs recibidos
        """
        logger.info("polling_received_dtes", rut_receptor=rut_receptor)
        
        try:
            # Llamar método SOAP del SII para obtener DTEs recibidos
            # Nota: El método exacto puede variar según versión WSDL
            
            # TODO: Implementar llamada SOAP real
            # response = self.client.client.service.QueryDTEsReceived(
            #     rutReceptor=rut_receptor,
            #     dvReceptor=self._extract_dv(rut_receptor)
            # )
            
            # Por ahora, retornar lista vacía (no bloquear)
            dtes_recibidos = []
            
            logger.info("polling_completed",
                       rut_receptor=rut_receptor,
                       dtes_count=len(dtes_recibidos))
            
            return dtes_recibidos
            
        except Exception as e:
            logger.error("polling_error", error=str(e), rut_receptor=rut_receptor)
            return []
    
    def download_dte(self, track_id: str, rut_receptor: str) -> str:
        """
        Descarga un DTE específico desde el SII.
        
        Args:
            track_id: ID de seguimiento del DTE
            rut_receptor: RUT del receptor
        
        Returns:
            str: XML del DTE descargado
        """
        logger.info("downloading_dte", track_id=track_id)
        
        try:
            # Llamar método SOAP para descargar DTE
            # TODO: Implementar descarga real
            
            # Por ahora, retornar None
            return None
            
        except Exception as e:
            logger.error("download_error", error=str(e), track_id=track_id)
            return None
    
    def process_received_dte(self, dte_xml: str, rut_receptor: str) -> Dict:
        """
        Procesa un DTE recibido.
        
        Flujo:
        1. Parsear XML (usando xml_parser)
        2. Validar firma
        3. Extraer datos
        4. Llamar AI Service para matching con POs
        5. Callback a Odoo con resultado
        
        Args:
            dte_xml: XML del DTE recibido
            rut_receptor: RUT del receptor
        
        Returns:
            Dict: Resultado del procesamiento
        """
        logger.info("processing_received_dte")
        
        try:
            # 1. Parsear XML
            from receivers.xml_parser import XMLParser
            parser = XMLParser()
            dte_data = parser.parse_dte(dte_xml)
            
            # 2. Validar firma (opcional pero recomendado)
            from signers.xmldsig_signer import XMLDsigSigner
            signer = XMLDsigSigner()
            
            is_valid = signer.verify_signature(dte_xml)
            if not is_valid:
                logger.warning("dte_signature_invalid")
                # Continuar de todos modos (puede ser DTE antiguo)
            
            # 3. Llamar AI Service para reconciliación
            # (si está configurado)
            
            # 4. Callback a Odoo
            # TODO: Implementar callback HTTP a Odoo
            
            logger.info("dte_processed", folio=dte_data.get('folio'))
            
            return {
                'success': True,
                'dte_data': dte_data,
                'validated': is_valid
            }
            
        except Exception as e:
            logger.error("processing_error", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_dv(self, rut: str) -> str:
        """Extrae dígito verificador del RUT"""
        if '-' in rut:
            return rut.split('-')[-1]
        return rut[-1]

