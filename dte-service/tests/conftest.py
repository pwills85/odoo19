# -*- coding: utf-8 -*-
"""
Configuración pytest para DTE Service
"""

import pytest
import sys
import os

# Agregar path del DTE service al PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@pytest.fixture
def sample_dte_xml():
    """XML de prueba para tests"""
    return """<?xml version="1.0" encoding="ISO-8859-1"?>
<DTE version="1.0">
    <Documento>
        <Encabezado>
            <IdDoc>
                <TipoDTE>33</TipoDTE>
                <Folio>1</Folio>
                <FchEmis>2025-10-21</FchEmis>
            </IdDoc>
            <Emisor>
                <RUTEmisor>76123456-K</RUTEmisor>
                <RznSoc>Test Company</RznSoc>
            </Emisor>
            <Receptor>
                <RUTRecep>12345678-5</RUTRecep>
                <RznSocRecep>Test Client</RznSocRecep>
            </Receptor>
            <Totales>
                <MntTotal>119000</MntTotal>
            </Totales>
        </Encabezado>
        <TED>
            <DD>
                <RE>76123456-K</RE>
                <TD>33</TD>
                <F>1</F>
                <FE>2025-10-21</FE>
                <RR>12345678-5</RR>
                <RSR>Test Client</RSR>
                <MNT>119000</MNT>
                <IT1>Test Item</IT1>
                <CAF>
                    <DA></DA>
                    <FRMA></FRMA>
                </CAF>
                <TSTED>2025-10-21T10:00:00</TSTED>
            </DD>
            <FRMT algoritmo="SHA1withRSA"></FRMT>
        </TED>
    </Documento>
</DTE>
"""


@pytest.fixture
def sample_invoice_data():
    """Datos de factura de prueba"""
    return {
        "dte_type": "33",
        "invoice_data": {
            "folio": 1,
            "fecha_emision": "2025-10-21",
            "emisor": {
                "rut": "76123456-K",
                "razon_social": "Test Company",
                "giro": "Servicios",
            },
            "receptor": {
                "rut": "12345678-5",
                "razon_social": "Test Client",
            },
            "totales": {
                "monto_neto": 100000,
                "iva": 19000,
                "monto_total": 119000,
            },
        },
    }
