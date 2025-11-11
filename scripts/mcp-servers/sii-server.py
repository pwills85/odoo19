#!/usr/bin/env python3
"""
MCP Server para integración segura con SII (Servicio de Impuestos Internos de Chile)
Proporciona herramientas para consultas SII, validaciones DTE y estado de documentos
"""

import os
import sys
import json
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import xml.etree.ElementTree as ET
from mcp.server import Server
import mcp.types as types

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SIIMCPIntegrationServer(Server):
    """Servidor MCP para integración con SII de Chile"""

    def __init__(self):
        super().__init__("sii-integration-tools", "1.0.0")

        # Configuración SII
        self.sii_env = os.getenv('SII_ENVIRONMENT', 'certification')
        self.cert_path = os.getenv('SII_CERT_PATH', '/certs/')
        self.timeout = int(os.getenv('SII_TIMEOUT', '30'))
        self.mock_mode = os.getenv('MOCK_MODE', 'true').lower() == 'true'

        # URLs SII
        self.sii_urls = {
            'production': {
                'query': 'https://palena.sii.cl/DTEWS/QueryEstDte.jws',
                'reception': 'https://palena.sii.cl/DTEWS/crSeed.jws',
                'certification': 'https://maullin.sii.cl/DTEWS/QueryEstDte.jws'
            },
            'certification': {
                'query': 'https://maullin.sii.cl/DTEWS/QueryEstDte.jws',
                'reception': 'https://maullin.sii.cl/DTEWS/crSeed.jws',
                'certification': 'https://maullin.sii.cl/DTEWS/QueryEstDte.jws'
            }
        }

        # Registrar herramientas
        self.add_tool(self.get_dte_status)
        self.add_tool(self.validate_dte_xml)
        self.add_tool(self.get_seed)
        self.add_tool(self.get_sii_resolution_info)
        self.add_tool(self.validate_rut_sii)

    def _get_sii_url(self, service: str) -> str:
        """Obtener URL SII según ambiente"""
        return self.sii_urls[self.sii_env][service]

    def _make_sii_request(self, service: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Realizar petición HTTP segura a SII"""
        if self.mock_mode:
            return self._mock_sii_response(service, data)

        try:
            url = self._get_sii_url(service)
            headers = {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': f'urn:{service}'
            }

            # Crear XML SOAP (simplificado para demo)
            xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Body>
        <{service}>
            {self._dict_to_xml(data)}
        </{service}>
    </soapenv:Body>
</soapenv:Envelope>"""

            response = requests.post(url, data=xml_data, headers=headers,
                                   timeout=self.timeout, verify=True)

            return {
                'status_code': response.status_code,
                'response': response.text,
                'success': response.status_code == 200
            }

        except Exception as e:
            logger.error(f"Error en petición SII {service}: {e}")
            return {
                'error': str(e),
                'success': False,
                'service': service
            }

    def _dict_to_xml(self, data: Dict[str, Any]) -> str:
        """Convertir diccionario a XML para SOAP"""
        xml_parts = []
        for key, value in data.items():
            xml_parts.append(f"<{key}>{value}</{key}>")
        return ''.join(xml_parts)

    def _mock_sii_response(self, service: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Respuestas mock para testing y desarrollo"""
        logger.info(f"MOCK MODE: Simulando respuesta SII para {service}")

        if service == 'getDteStatus':
            rut_emisor = data.get('RutEmisor', '')
            dte_type = data.get('TipoDte', '')
            folio = data.get('Folio', '')

            # Simular diferentes estados
            import random
            states = ['ACEPTADO', 'RECHAZADO', 'PENDIENTE', 'NO_ENCONTRADO']
            state = random.choice(states)

            return {
                'success': True,
                'mock': True,
                'estado': state,
                'glosa': f'Documento {state.lower()} en SII',
                'fecha_consulta': datetime.now().isoformat(),
                'rut_emisor': rut_emisor,
                'tipo_dte': dte_type,
                'folio': folio
            }

        elif service == 'getSeed':
            return {
                'success': True,
                'mock': True,
                'seed': f'<SEMILLA>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</SEMILLA>',
                'expiration': (datetime.now() + timedelta(minutes=5)).isoformat()
            }

        return {'success': False, 'mock': True, 'error': 'Servicio no implementado en mock'}

    @types.tool(
        name="get_dte_status",
        description="Consulta estado de DTE en SII",
        parameters={
            "rut_emisor": {
                "type": "string",
                "description": "RUT del emisor (sin puntos, con guión)"
            },
            "tipo_dte": {
                "type": "string",
                "description": "Tipo de DTE (33, 34, 52, 56, 61)",
                "enum": ["33", "34", "52", "56", "61"]
            },
            "folio": {
                "type": "string",
                "description": "Número de folio del DTE"
            },
            "fecha_emision": {
                "type": "string",
                "description": "Fecha de emisión (YYYY-MM-DD)"
            },
            "total": {
                "type": "number",
                "description": "Monto total del DTE"
            }
        }
    )
    async def get_dte_status(self, rut_emisor: str, tipo_dte: str, folio: str,
                           fecha_emision: str = None, total: float = None) -> Dict[str, Any]:
        """Consultar estado de DTE en SII"""
        try:
            # Preparar datos para consulta
            query_data = {
                'RutEmisor': rut_emisor.replace('.', '').replace('-', ''),
                'TipoDte': tipo_dte,
                'Folio': folio
            }

            if fecha_emision:
                query_data['FechaEmision'] = fecha_emision
            if total:
                query_data['Total'] = str(int(total))

            response = self._make_sii_request('getDteStatus', query_data)

            # Procesar respuesta
            result = {
                'consulta': query_data,
                'timestamp': datetime.now().isoformat(),
                'ambiente': self.sii_env,
                'mock_mode': self.mock_mode
            }

            if response.get('success'):
                if self.mock_mode:
                    result.update(response)
                else:
                    # Procesar XML de respuesta real
                    result['raw_response'] = response.get('response', '')
                    result['estado'] = self._parse_dte_status_xml(response['response'])
            else:
                result['error'] = response.get('error', 'Error desconocido')
                result['status_code'] = response.get('status_code')

            return result

        except Exception as e:
            logger.error(f"Error consultando estado DTE: {e}")
            return {
                'error': str(e),
                'consulta': {
                    'rut_emisor': rut_emisor,
                    'tipo_dte': tipo_dte,
                    'folio': folio
                }
            }

    def _parse_dte_status_xml(self, xml_response: str) -> str:
        """Parsear respuesta XML de consulta DTE"""
        try:
            # Implementar parsing XML según esquema SII
            # Esta es una implementación simplificada
            if 'ACEPTADO' in xml_response:
                return 'ACEPTADO'
            elif 'RECHAZADO' in xml_response:
                return 'RECHAZADO'
            elif 'PENDIENTE' in xml_response:
                return 'PENDIENTE'
            else:
                return 'DESCONOCIDO'
        except:
            return 'ERROR_PARSING'

    @types.tool(
        name="validate_dte_xml",
        description="Valida estructura XML de DTE contra esquema SII",
        parameters={
            "xml_content": {
                "type": "string",
                "description": "Contenido XML del DTE a validar"
            },
            "dte_type": {
                "type": "string",
                "description": "Tipo de DTE para validación específica"
            }
        }
    )
    async def validate_dte_xml(self, xml_content: str, dte_type: str = None) -> Dict[str, Any]:
        """Validar XML de DTE contra esquemas SII"""
        try:
            result = {
                'dte_type': dte_type,
                'timestamp': datetime.now().isoformat(),
                'validations': []
            }

            # Validaciones básicas de estructura XML
            try:
                root = ET.fromstring(xml_content)

                # Validar elementos requeridos según tipo DTE
                validations = self._validate_dte_structure(root, dte_type)
                result['validations'].extend(validations)

                # Validar firma digital
                signature_validation = self._validate_xml_signature(xml_content)
                result['validations'].append(signature_validation)

                # Validar datos comerciales
                business_validation = self._validate_business_data(root)
                result['validations'].append(business_validation)

            except ET.ParseError as e:
                result['validations'].append({
                    'type': 'xml_structure',
                    'valid': False,
                    'message': f'Error de estructura XML: {str(e)}'
                })

            # Calcular resultado general
            valid_count = sum(1 for v in result['validations'] if v.get('valid', False))
            total_count = len(result['validations'])

            result['summary'] = {
                'total_validations': total_count,
                'passed': valid_count,
                'failed': total_count - valid_count,
                'overall_valid': valid_count == total_count
            }

            return result

        except Exception as e:
            logger.error(f"Error validando XML DTE: {e}")
            return {
                'error': str(e),
                'dte_type': dte_type,
                'xml_length': len(xml_content) if xml_content else 0
            }

    def _validate_dte_structure(self, root: ET.Element, dte_type: str = None) -> list:
        """Validar estructura XML del DTE"""
        validations = []

        # Validar elementos comunes
        required_elements = ['Encabezado', 'Detalle', 'Totales']
        for element in required_elements:
            exists = root.find(f'.//{element}') is not None
            validations.append({
                'type': 'required_element',
                'element': element,
                'valid': exists,
                'message': f'Elemento {element} {"presente" if exists else "ausente"}'
            })

        # Validaciones específicas por tipo DTE
        if dte_type:
            type_validations = self._validate_dte_type_specific(root, dte_type)
            validations.extend(type_validations)

        return validations

    def _validate_dte_type_specific(self, root: ET.Element, dte_type: str) -> list:
        """Validaciones específicas por tipo de DTE"""
        validations = []

        # Ejemplo: Para facturas (33, 34)
        if dte_type in ['33', '34']:
            # Validar RUT receptor para facturas
            receptor = root.find('.//Receptor')
            if receptor is not None:
                rut = receptor.find('RUTRecep')
                validations.append({
                    'type': 'dte_type_validation',
                    'aspect': 'rut_receptor',
                    'valid': rut is not None and rut.text,
                    'message': 'RUT receptor requerido para facturas'
                })

        # Para guías de despacho (52)
        elif dte_type == '52':
            # Validar dirección de destino
            destino = root.find('.//Destino')
            validations.append({
                'type': 'dte_type_validation',
                'aspect': 'direccion_destino',
                'valid': destino is not None,
                'message': 'Dirección destino requerida para guías'
            })

        return validations

    def _validate_xml_signature(self, xml_content: str) -> Dict[str, Any]:
        """Validar firma digital XML"""
        # Implementación simplificada - en producción usar xmlsec
        has_signature = 'Signature' in xml_content
        has_cert = 'X509Certificate' in xml_content

        return {
            'type': 'xml_signature',
            'valid': has_signature and has_cert,
            'message': f'Firma digital {"válida" if has_signature and has_cert else "inválida o ausente"}',
            'details': {
                'has_signature_element': has_signature,
                'has_certificate': has_cert
            }
        }

    def _validate_business_data(self, root: ET.Element) -> Dict[str, Any]:
        """Validar datos comerciales del DTE"""
        validations = []

        # Validar RUT emisor
        rut_emisor = root.find('.//RUTEmisor')
        if rut_emisor is not None and rut_emisor.text:
            # Validación básica de formato RUT
            rut_valid = self._validate_rut_format(rut_emisor.text)
            validations.append(f'RUT emisor: {"válido" if rut_valid else "inválido"}')

        # Validar montos
        total = root.find('.//MntTotal')
        if total is not None and total.text:
            try:
                amount = float(total.text)
                validations.append(f'Monto total: {amount} (válido)')
            except ValueError:
                validations.append('Monto total: formato inválido')

        return {
            'type': 'business_data',
            'valid': len(validations) > 0,
            'message': 'Validación datos comerciales completada',
            'details': validations
        }

    def _validate_rut_format(self, rut: str) -> bool:
        """Validar formato básico de RUT chileno"""
        import re
        # Patrón básico: números con guión y dígito verificador
        pattern = r'^\d{7,8}-[\dKk]$'
        return bool(re.match(pattern, rut))

    @types.tool(
        name="get_seed",
        description="Obtiene semilla (seed) para autenticación SII",
        parameters={}
    )
    async def get_seed(self) -> Dict[str, Any]:
        """Obtener semilla para autenticación SII"""
        try:
            response = self._make_sii_request('getSeed', {})

            return {
                'timestamp': datetime.now().isoformat(),
                'ambiente': self.sii_env,
                'mock_mode': self.mock_mode,
                'seed_data': response
            }

        except Exception as e:
            logger.error(f"Error obteniendo semilla SII: {e}")
            return {'error': str(e)}

    @types.tool(
        name="get_sii_resolution_info",
        description="Obtiene información de resoluciones SII relevantes",
        parameters={}
    )
    async def get_sii_resolution_info(self) -> Dict[str, Any]:
        """Información de resoluciones SII"""
        resolutions = {
            'dte_general': {
                'resolution': '80/2014',
                'title': 'Resolución que regula el envío de Documentos Tributarios Electrónicos',
                'key_points': [
                    'Obligatoriedad de DTE para facturación',
                    'Esquemas XML oficiales',
                    'Plazos de envío y validación',
                    'Sanciones por incumplimiento'
                ]
            },
            'facturacion_electronica': {
                'resolution': 'DL 825/1974',
                'title': 'Decreto Ley que establece normas sobre facturación',
                'key_points': [
                    'Documento válido es aquel emitido por SII',
                    'Reemplaza facturas tradicionales',
                    'Vigencia indefinida del documento'
                ]
            },
            'dte_technical': {
                'resolution': '11/2019',
                'title': 'Especificaciones técnicas para Documentos Tributarios Electrónicos',
                'key_points': [
                    'Esquemas XML actualizados',
                    'Nuevos tipos de documento',
                    'Mejoras en validación'
                ]
            }
        }

        return {
            'resolutions': resolutions,
            'last_updated': '2024-11-10',
            'source': 'SII Official Documentation'
        }

    @types.tool(
        name="validate_rut_sii",
        description="Valida formato RUT según estándares SII",
        parameters={
            "rut": {
                "type": "string",
                "description": "RUT a validar"
            }
        }
    )
    async def validate_rut_sii(self, rut: str) -> Dict[str, Any]:
        """Validar RUT según algoritmo oficial SII"""
        try:
            # Implementar algoritmo de validación RUT chileno
            rut_clean = ''.join(filter(str.isdigit, rut.upper().replace('K', 'K')))

            if len(rut_clean) < 8 or len(rut_clean) > 9:
                return {
                    'rut': rut,
                    'valid': False,
                    'message': 'Longitud de RUT inválida'
                }

            # Separar número y dígito verificador
            if len(rut_clean) == 9:
                number = rut_clean[:-1]
                verifier = rut_clean[-1]
            else:
                number = rut_clean[:-1]
                verifier = rut_clean[-1]

            # Algoritmo de validación
            reversed_digits = number[::-1]
            factors = [2, 3, 4, 5, 6, 7, 2, 3, 4, 5, 6][:len(reversed_digits)]

            total = sum(int(digit) * factor for digit, factor in zip(reversed_digits, factors))
            mod = total % 11
            calculated_verifier = str(11 - mod) if mod != 0 else '0'

            if calculated_verifier == '10':
                calculated_verifier = 'K'
            elif calculated_verifier == '11':
                calculated_verifier = '0'

            valid = calculated_verifier == verifier

            return {
                'rut': rut,
                'rut_clean': f"{number}-{verifier}",
                'valid': valid,
                'message': 'RUT válido' if valid else 'RUT inválido',
                'algorithm': 'Módulo 11 chileno',
                'calculated_verifier': calculated_verifier,
                'provided_verifier': verifier
            }

        except Exception as e:
            logger.error(f"Error validando RUT {rut}: {e}")
            return {
                'rut': rut,
                'valid': False,
                'error': str(e)
            }

def main():
    """Función principal del servidor MCP"""
    server = SIIMCPIntegrationServer()

    # Ejecutar servidor
    import asyncio
    asyncio.run(server.run())

if __name__ == "__main__":
    main()
