# -*- coding: utf-8 -*-
"""
Cliente SOAP para comunicación con el SII
"""

from zeep import Client
from zeep.transports import Transport
from zeep.exceptions import Fault
from requests import Session
from requests.exceptions import ConnectionError, Timeout
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import structlog
import time

logger = structlog.get_logger()


class SIISoapClient:
    """Cliente SOAP para comunicación con servicios web del SII"""
    
    def __init__(self, wsdl_url: str, timeout: int = 60):
        """
        Inicializa el cliente SOAP.
        
        Args:
            wsdl_url: URL del WSDL del SII
            timeout: Timeout en segundos
        """
        self.wsdl_url = wsdl_url
        self.timeout = timeout
        
        # Configurar session con timeout
        session = Session()
        session.timeout = timeout
        transport = Transport(session=session)
        
        # Crear cliente SOAP
        self.client = Client(wsdl=wsdl_url, transport=transport)
        
        logger.info("sii_soap_client_initialized", wsdl=wsdl_url)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((ConnectionError, Timeout)),
        reraise=True
    )
    def send_dte(self, signed_xml: str, rut_emisor: str) -> dict:
        """
        Envía un DTE al SII con retry automático.
        
        Retry logic:
        - 3 intentos máximo
        - Backoff exponencial: 4s, 8s, 10s
        - Solo en errores de red (ConnectionError, Timeout)
        
        Args:
            signed_xml: XML firmado digitalmente
            rut_emisor: RUT del emisor (empresa)
        
        Returns:
            dict: Respuesta del SII con track_id y status
        """
        start_time = time.time()
        
        logger.info("sending_dte_to_sii", rut_emisor=rut_emisor)
        
        try:
            # Llamar método SOAP del SII
            # Nota: El método exacto puede variar según versión del WSDL
            # Este es un ejemplo simplificado
            
            response = self.client.service.EnvioDTE(
                rutEmisor=rut_emisor,
                dvEmisor=self._extract_dv(rut_emisor),
                rutEnvia=rut_emisor,  # Generalmente el mismo
                dvEnvia=self._extract_dv(rut_emisor),
                archivo=signed_xml
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            logger.info("dte_sent_successfully",
                       rut_emisor=rut_emisor,
                       duration_ms=duration_ms,
                       track_id=getattr(response, 'TRACKID', None))
            
            return {
                'success': True,
                'track_id': getattr(response, 'TRACKID', None),
                'status': getattr(response, 'ESTADO', 'unknown'),
                'response_xml': str(response),
                'duration_ms': duration_ms
            }
            
        except Fault as e:
            logger.error("sii_soap_fault", error=str(e), rut_emisor=rut_emisor)
            
            # Interpretar código de error del SII
            from utils.sii_error_codes import interpret_sii_error
            
            error_code = e.code if hasattr(e, 'code') else 'UNKNOWN'
            error_info = interpret_sii_error(error_code)
            
            return {
                'success': False,
                'error_code': error_code,
                'error_message': error_info['user_message'],
                'error_level': error_info['level'],
                'error_action': error_info['action'],
                'response_xml': str(e)
            }
        
        except Exception as e:
            logger.error("sii_soap_error", error=str(e), rut_emisor=rut_emisor)
            
            return {
                'success': False,
                'error_message': str(e)
            }
    
    def query_status(self, track_id: str, rut_emisor: str) -> dict:
        """
        Consulta el estado de un DTE en el SII.
        
        Args:
            track_id: ID de seguimiento retornado al enviar
            rut_emisor: RUT del emisor
        
        Returns:
            dict: Estado del DTE
        """
        logger.info("querying_dte_status", track_id=track_id)
        
        try:
            response = self.client.service.QueryEstDte(
                rutEmisor=rut_emisor,
                dvEmisor=self._extract_dv(rut_emisor),
                trackId=track_id
            )
            
            return {
                'success': True,
                'track_id': track_id,
                'status': getattr(response, 'ESTADO', 'unknown'),
                'response_xml': str(response)
            }
            
        except Exception as e:
            logger.error("sii_status_query_error", error=str(e), track_id=track_id)
            
            return {
                'success': False,
                'error_message': str(e)
            }
    
    def get_received_dte(self, rut_receptor: str, dte_type: str = None) -> list:
        """
        Descarga DTEs recibidos desde el SII (método GetDTE).
        
        Args:
            rut_receptor: RUT de la empresa receptora
            dte_type: Filtro por tipo DTE (opcional)
        
        Returns:
            list: DTEs recibidos pendientes de procesar
        """
        logger.info("getting_received_dtes", rut_receptor=rut_receptor)
        
        try:
            # Llamar método SOAP GetDTE del SII
            response = self.client.service.GetDTE(
                rutReceptor=rut_receptor,
                dvReceptor=self._extract_dv(rut_receptor),
                tipoDTE=dte_type or ''
            )
            
            # Parsear respuesta (estructura depende del WSDL)
            dtes = []
            
            # TODO: Parsear XML de respuesta según estructura real del SII
            # Por ahora, estructura básica
            
            logger.info("dtes_retrieved", count=len(dtes))
            
            return dtes
            
        except Exception as e:
            logger.error("get_dte_error", error=str(e), rut_receptor=rut_receptor)
            return []
    
    def _extract_dv(self, rut: str) -> str:
        """Extrae dígito verificador del RUT"""
        if '-' in rut:
            return rut.split('-')[-1]
        return rut[-1]

