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
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((ConnectionError, Timeout)),
        reraise=True
    )
    def get_received_dte(self, rut_receptor: str, dte_type: str = None, fecha_desde: str = None) -> dict:
        """
        Descarga DTEs recibidos desde el SII (método GetDTE).

        Este método permite descargar DTEs que otros contribuyentes han enviado
        a nuestra empresa y que están disponibles en el SII.

        Args:
            rut_receptor: RUT de la empresa receptora
            dte_type: Filtro por tipo DTE (33, 34, 52, 56, 61) - opcional
            fecha_desde: Fecha inicio búsqueda formato YYYY-MM-DD - opcional

        Returns:
            dict: {
                'success': bool,
                'dtes': list[dict],  # Lista de DTEs recibidos
                'count': int,
                'errors': list
            }
        """
        start_time = time.time()

        logger.info("getting_received_dtes",
                   rut_receptor=rut_receptor,
                   dte_type=dte_type,
                   fecha_desde=fecha_desde)

        try:
            # Llamar método SOAP GetDTE del SII
            # Nota: La estructura exacta puede variar según WSDL
            # Este es el formato más común según documentación SII

            response = self.client.service.GetDTE(
                rutReceptor=rut_receptor,
                dvReceptor=self._extract_dv(rut_receptor),
                tipoDTE=dte_type if dte_type else '',
                fechaDesde=fecha_desde if fecha_desde else ''
            )

            duration_ms = int((time.time() - start_time) * 1000)

            # Parsear respuesta XML
            from lxml import etree

            dtes_list = []

            # El SII retorna XML con DTEs en elementos <DTE>
            if hasattr(response, 'DTE'):
                # Si es lista de DTEs
                dte_elements = response.DTE if isinstance(response.DTE, list) else [response.DTE]

                for dte_elem in dte_elements:
                    try:
                        # Extraer información básica del DTE
                        dte_info = {
                            'folio': getattr(dte_elem, 'Folio', None),
                            'tipo_dte': getattr(dte_elem, 'TipoDTE', None),
                            'rut_emisor': getattr(dte_elem, 'RUTEmisor', None),
                            'fecha_emision': getattr(dte_elem, 'FechaEmision', None),
                            'monto_total': getattr(dte_elem, 'MontoTotal', None),
                            'xml': str(dte_elem) if dte_elem else None,
                            'estado': getattr(dte_elem, 'Estado', 'RECIBIDO')
                        }

                        dtes_list.append(dte_info)

                    except Exception as parse_error:
                        logger.warning("error_parsing_dte",
                                      error=str(parse_error),
                                      dte_index=len(dtes_list))
                        continue

            logger.info("dtes_retrieved_successfully",
                       count=len(dtes_list),
                       duration_ms=duration_ms,
                       rut_receptor=rut_receptor)

            return {
                'success': True,
                'dtes': dtes_list,
                'count': len(dtes_list),
                'errors': [],
                'duration_ms': duration_ms
            }

        except Fault as e:
            logger.error("sii_get_dte_fault",
                        error=str(e),
                        rut_receptor=rut_receptor)

            # Interpretar código de error
            from utils.sii_error_codes import interpret_sii_error

            error_code = e.code if hasattr(e, 'code') else 'UNKNOWN'
            error_info = interpret_sii_error(error_code)

            return {
                'success': False,
                'dtes': [],
                'count': 0,
                'errors': [error_info['user_message']],
                'error_code': error_code
            }

        except Exception as e:
            logger.error("get_dte_error",
                        error=str(e),
                        rut_receptor=rut_receptor)

            return {
                'success': False,
                'dtes': [],
                'count': 0,
                'errors': [str(e)]
            }

    def send_libro(self, libro_xml: str, tipo_libro: str, rut_emisor: str, environment: str = 'sandbox') -> tuple:
        """
        Envía un Libro (Compra/Venta/Guías) al SII.

        Args:
            libro_xml: XML firmado del libro
            tipo_libro: Tipo de libro ('compra', 'venta', 'guias')
            rut_emisor: RUT del emisor
            environment: 'sandbox' o 'production'

        Returns:
            tuple: (track_id, response_xml)
        """
        start_time = time.time()

        logger.info("sending_libro_to_sii",
                   tipo_libro=tipo_libro,
                   rut_emisor=rut_emisor,
                   environment=environment)

        try:
            # Llamar método SOAP del SII para envío de libros
            # El método varía según tipo de libro
            if tipo_libro == 'guias':
                response = self.client.service.EnvioLibro(
                    rutEmisor=rut_emisor,
                    dvEmisor=self._extract_dv(rut_emisor),
                    rutEnvia=rut_emisor,
                    dvEnvia=self._extract_dv(rut_emisor),
                    archivo=libro_xml
                )
            else:
                # Para libros de compra/venta usar el mismo método
                response = self.client.service.EnvioLibro(
                    rutEmisor=rut_emisor,
                    dvEmisor=self._extract_dv(rut_emisor),
                    rutEnvia=rut_emisor,
                    dvEnvia=self._extract_dv(rut_emisor),
                    archivo=libro_xml
                )

            duration_ms = int((time.time() - start_time) * 1000)

            track_id = getattr(response, 'TRACKID', None)
            response_xml = str(response)

            logger.info("libro_sent_successfully",
                       tipo_libro=tipo_libro,
                       rut_emisor=rut_emisor,
                       track_id=track_id,
                       duration_ms=duration_ms)

            return track_id, response_xml

        except Fault as e:
            logger.error("sii_libro_soap_fault",
                        error=str(e),
                        tipo_libro=tipo_libro,
                        rut_emisor=rut_emisor)

            # Interpretar código de error del SII
            from utils.sii_error_codes import interpret_sii_error

            error_code = e.code if hasattr(e, 'code') else 'UNKNOWN'
            error_info = interpret_sii_error(error_code)

            raise Exception(
                f"Error SII enviando libro {tipo_libro}: "
                f"{error_info['user_message']} (Código: {error_code})"
            )

        except Exception as e:
            logger.error("sii_libro_send_error",
                        error=str(e),
                        tipo_libro=tipo_libro,
                        rut_emisor=rut_emisor)

            raise Exception(f"Error enviando libro {tipo_libro} al SII: {str(e)}")

    def _extract_dv(self, rut: str) -> str:
        """Extrae dígito verificador del RUT"""
        if '-' in rut:
            return rut.split('-')[-1]
        return rut[-1]

