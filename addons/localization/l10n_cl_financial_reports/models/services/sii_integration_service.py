# -*- coding: utf-8 -*-
"""
SII Integration Service - Pure Python Implementation
Provides integration with Chilean SII for financial reports
Compatible with Odoo 18 CE
"""

import logging
from datetime import datetime, date
from typing import Dict, List, Optional, Any
import json

_logger = logging.getLogger(__name__)


class SIIIntegrationService:
    """Pure Python service for SII integration."""
    
    def __init__(self):
        """Initialize the service."""
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def prepare_f29_data(
        self,
        tax_data: Dict[str, float],
        period: str,
        company_rut: str
    ) -> Dict[str, Any]:
        """
        Prepare tax data for F29 form submission.
        
        Args:
            tax_data: Dictionary with tax amounts by code
            period: Period in format YYYYMM
            company_rut: Company RUT
            
        Returns:
            Dictionary with formatted F29 data
        """
        try:
            # F29 standard codes mapping
            f29_mapping = {
                # Ventas y servicios
                '503': tax_data.get('ventas_gravadas', 0),
                '502': tax_data.get('ventas_exentas', 0),
                '501': tax_data.get('exportaciones', 0),
                
                # IVA
                '511': tax_data.get('iva_debito_fiscal', 0),
                '521': tax_data.get('iva_credito_fiscal', 0),
                '525': tax_data.get('iva_remanente', 0),
                
                # Retenciones
                '538': tax_data.get('retencion_honorarios', 0),
                '539': tax_data.get('retencion_dietas', 0),
                
                # PPM
                '563': tax_data.get('ppm_obligatorio', 0),
                '115': tax_data.get('ppm_voluntario', 0),
                
                # Base imponible
                '547': tax_data.get('base_imponible', 0),
                
                # Total a pagar
                '089': tax_data.get('total_a_pagar', 0),
            }
            
            # Remove zero values
            f29_data = {k: v for k, v in f29_mapping.items() if v != 0}
            
            return {
                'form_type': 'F29',
                'period': period,
                'company_rut': company_rut,
                'codes': f29_data,
                'prepared_at': datetime.now().isoformat(),
                'status': 'prepared'
            }
            
        except Exception as e:
            self.logger.error(f"Error preparing F29 data: {str(e)}")
            raise
    
    def prepare_f22_data(
        self,
        income_data: Dict[str, float],
        year: int,
        company_rut: str
    ) -> Dict[str, Any]:
        """
        Prepare income tax data for F22 form.
        
        Args:
            income_data: Dictionary with income/expense amounts
            year: Tax year
            company_rut: Company RUT
            
        Returns:
            Dictionary with formatted F22 data
        """
        try:
            # Calculate taxable income
            total_income = income_data.get('total_income', 0)
            total_expenses = income_data.get('total_expenses', 0)
            taxable_income = total_income - total_expenses
            
            # F22 codes
            f22_mapping = {
                # Ingresos
                '628': total_income,
                '629': income_data.get('sales_income', 0),
                '630': income_data.get('service_income', 0),
                '631': income_data.get('other_income', 0),
                
                # Costos y gastos
                '632': total_expenses,
                '633': income_data.get('cost_of_sales', 0),
                '634': income_data.get('operating_expenses', 0),
                '635': income_data.get('financial_expenses', 0),
                
                # Base imponible
                '636': taxable_income,
                
                # Impuesto
                '637': self._calculate_corporate_tax(taxable_income),
                
                # Créditos
                '638': income_data.get('tax_credits', 0),
                
                # PPM pagados
                '639': income_data.get('ppm_paid', 0),
            }
            
            # Remove zero values
            f22_data = {k: v for k, v in f22_mapping.items() if v != 0}
            
            return {
                'form_type': 'F22',
                'tax_year': year,
                'company_rut': company_rut,
                'codes': f22_data,
                'taxable_income': taxable_income,
                'prepared_at': datetime.now().isoformat(),
                'status': 'prepared'
            }
            
        except Exception as e:
            self.logger.error(f"Error preparing F22 data: {str(e)}")
            raise
    
    def validate_tax_consistency(
        self,
        f29_monthly_data: List[Dict[str, Any]],
        f22_annual_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate consistency between monthly F29 and annual F22.
        
        Args:
            f29_monthly_data: List of monthly F29 data
            f22_annual_data: Annual F22 data
            
        Returns:
            Dictionary with validation results
        """
        try:
            validations = []
            
            # Sum monthly values
            monthly_totals = {
                'sales': 0,
                'iva_debito': 0,
                'iva_credito': 0,
                'ppm_paid': 0
            }
            
            for month_data in f29_monthly_data:
                codes = month_data.get('codes', {})
                monthly_totals['sales'] += codes.get('503', 0)
                monthly_totals['iva_debito'] += codes.get('511', 0)
                monthly_totals['iva_credito'] += codes.get('521', 0)
                monthly_totals['ppm_paid'] += codes.get('563', 0)
            
            # Get annual values
            annual_codes = f22_annual_data.get('codes', {})
            annual_sales = annual_codes.get('629', 0)
            annual_ppm = annual_codes.get('639', 0)
            
            # Validate sales consistency
            sales_diff = abs(monthly_totals['sales'] - annual_sales)
            if sales_diff > 1:  # Allow 1 peso difference for rounding
                validations.append({
                    'field': 'sales',
                    'status': 'error',
                    'message': f"Sales mismatch: Monthly total {monthly_totals['sales']} vs Annual {annual_sales}",
                    'difference': sales_diff
                })
            else:
                validations.append({
                    'field': 'sales',
                    'status': 'ok',
                    'message': 'Sales totals match'
                })
            
            # Validate PPM consistency
            ppm_diff = abs(monthly_totals['ppm_paid'] - annual_ppm)
            if ppm_diff > 1:
                validations.append({
                    'field': 'ppm',
                    'status': 'error',
                    'message': f"PPM mismatch: Monthly total {monthly_totals['ppm_paid']} vs Annual {annual_ppm}",
                    'difference': ppm_diff
                })
            else:
                validations.append({
                    'field': 'ppm',
                    'status': 'ok',
                    'message': 'PPM totals match'
                })
            
            # Calculate IVA consistency
            net_iva = monthly_totals['iva_debito'] - monthly_totals['iva_credito']
            validations.append({
                'field': 'iva',
                'status': 'info',
                'message': f"Net IVA for year: {net_iva}",
                'iva_debito_total': monthly_totals['iva_debito'],
                'iva_credito_total': monthly_totals['iva_credito']
            })
            
            # Overall status
            has_errors = any(v['status'] == 'error' for v in validations)
            
            return {
                'is_valid': not has_errors,
                'validations': validations,
                'monthly_totals': monthly_totals,
                'validated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error validating tax consistency: {str(e)}")
            raise
    
    def generate_libro_compras_ventas(
        self,
        invoices: List[Dict[str, Any]],
        book_type: str,
        period: str
    ) -> Dict[str, Any]:
        """
        Generate Libro de Compras o Ventas for SII.
        
        Args:
            invoices: List of invoice data
            book_type: 'compras' or 'ventas'
            period: Period in format YYYYMM
            
        Returns:
            Dictionary with book data
        """
        try:
            # Group by document type
            by_doc_type = {}
            totals = {
                'neto': 0,
                'iva': 0,
                'exento': 0,
                'total': 0,
                'count': len(invoices)
            }
            
            for invoice in invoices:
                doc_type = invoice.get('document_type_code', '33')
                if doc_type not in by_doc_type:
                    by_doc_type[doc_type] = {
                        'invoices': [],
                        'subtotals': {
                            'neto': 0,
                            'iva': 0,
                            'exento': 0,
                            'total': 0,
                            'count': 0
                        }
                    }
                
                # Add to document type group
                by_doc_type[doc_type]['invoices'].append(invoice)
                
                # Update subtotals
                neto = invoice.get('amount_untaxed', 0)
                iva = invoice.get('amount_tax', 0)
                exento = invoice.get('amount_exempt', 0)
                total = invoice.get('amount_total', 0)
                
                by_doc_type[doc_type]['subtotals']['neto'] += neto
                by_doc_type[doc_type]['subtotals']['iva'] += iva
                by_doc_type[doc_type]['subtotals']['exento'] += exento
                by_doc_type[doc_type]['subtotals']['total'] += total
                by_doc_type[doc_type]['subtotals']['count'] += 1
                
                # Update grand totals
                totals['neto'] += neto
                totals['iva'] += iva
                totals['exento'] += exento
                totals['total'] += total
            
            return {
                'book_type': book_type,
                'period': period,
                'by_document_type': by_doc_type,
                'totals': totals,
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error generating libro {book_type}: {str(e)}")
            raise
    
    def _calculate_corporate_tax(self, taxable_income: float) -> float:
        """
        Calculate Chilean corporate tax.
        
        Current rate: 27% (Primera Categoría)
        """
        if taxable_income <= 0:
            return 0
        
        tax_rate = 0.27
        return round(taxable_income * tax_rate, 0)
    
    def format_rut(self, rut: str) -> str:
        """
        Format RUT for SII submission.
        
        Args:
            rut: RUT string
            
        Returns:
            Formatted RUT without dots or dashes
        """
        if not rut:
            return ''
        
        # Remove all non-alphanumeric characters
        rut = ''.join(c for c in rut if c.isalnum())
        
        # Ensure uppercase for 'K'
        return rut.upper()
    
    def validate_period_format(self, period: str) -> bool:
        """
        Validate period format (YYYYMM).
        
        Args:
            period: Period string
            
        Returns:
            True if valid format
        """
        if not period or len(period) != 6:
            return False
        
        try:
            year = int(period[:4])
            month = int(period[4:])
            
            if year < 2000 or year > 2100:
                return False
            
            if month < 1 or month > 12:
                return False
            
            return True
            
        except ValueError:
            return False
    
    def get_sii_document_name(self, doc_type_code: str) -> str:
        """
        Get SII document name from code.
        
        Args:
            doc_type_code: Document type code
            
        Returns:
            Document name
        """
        doc_types = {
            '30': 'Factura',
            '32': 'Factura de Ventas y Servicios No Afectos o Exentos',
            '33': 'Factura Electrónica',
            '34': 'Factura No Afecta o Exenta Electrónica',
            '35': 'Boleta',
            '38': 'Boleta Exenta',
            '39': 'Boleta Electrónica',
            '40': 'Liquidación Factura',
            '41': 'Boleta Exenta Electrónica',
            '43': 'Liquidación Factura Electrónica',
            '45': 'Factura de Compra',
            '46': 'Factura de Compra Electrónica',
            '48': 'Pago Electrónico',
            '52': 'Guía de Despacho',
            '53': 'Guía de Despacho Electrónica',
            '55': 'Nota de Débito',
            '56': 'Nota de Débito Electrónica',
            '60': 'Nota de Crédito',
            '61': 'Nota de Crédito Electrónica',
            '103': 'Liquidación',
            '110': 'Factura de Exportación',
            '111': 'Nota de Débito de Exportación',
            '112': 'Nota de Crédito de Exportación',
            '801': 'Orden de Compra',
            '802': 'Nota de Pedido',
            '803': 'Contrato',
            '804': 'Resolución',
            '805': 'Proceso ChileCompra',
            '806': 'Ficha ChileCompra',
            '807': 'DUS',
            '808': 'B/L (Conocimiento de Embarque)',
            '809': 'AWB (Air Waybill)',
            '810': 'MIC/DTA',
            '811': 'Carta de Porte',
            '812': 'Resolución del SNA donde califica Servicios de Exportación',
            '813': 'Pasaporte',
            '814': 'Certificado de Depósito Bolsa Prod. Chile',
            '815': 'Vale de Prenda Bolsa Prod. Chile'
        }
        
        return doc_types.get(str(doc_type_code), f'Documento Tipo {doc_type_code}')


# Factory function
def create_sii_integration_service() -> SIIIntegrationService:
    """Factory function to create service instance."""
    return SIIIntegrationService()