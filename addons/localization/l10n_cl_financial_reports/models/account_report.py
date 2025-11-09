# -*- coding: utf-8 -*-
from odoo import models, fields, api


class AccountReport(models.Model):
    """Extensión básica para reportes chilenos"""
    _inherit = 'account.report'

    # Campos específicos para localización chilena
    is_chilean_report = fields.Boolean(
        string='Reporte Chileno',
        default=False,
        help='Indica si es un reporte específico para Chile'
    )

    sii_compliance = fields.Boolean(
        string='Cumplimiento SII',
        default=False,
        help='Indica si el reporte cumple con normativas SII'
    )

    @api.model
    def get_chilean_reports(self):
        """Obtener reportes específicos para Chile"""
        return self.search([('is_chilean_report', '=', True)])

    def get_pdf_context(self, options=None):
        """
        Prepara contexto dinámico para templates PDF de reportes financieros chilenos.

        Este método centraliza la lógica de preparación de datos para PDFs,
        permitiendo que los templates QWeb accedan a valores reales calculados
        por el engine de reportes de Odoo.

        Args:
            options (dict): Opciones del reporte (filtros, fechas, comparación, etc.)

        Returns:
            dict: Contexto con datos estructurados para el template PDF
                - lines: Lista de líneas del reporte con valores
                - lines_by_code: Dict de líneas indexadas por code para acceso rápido
                - totals: Dict con totales principales
                - period_info: Información del período
                - company_info: Información de la compañía

        Example:
            >>> report = self.env.ref('l10n_cl_financial_reports.report_balance_sheet_cl')
            >>> options = report.get_options()
            >>> context = report.get_pdf_context(options)
            >>> total_assets = context['lines_by_code']['CL_ASSETS']['columns'][0]['no_format']
        """
        self.ensure_one()

        if options is None:
            options = self.get_options()

        # Obtener líneas del reporte con valores calculados
        lines = self._get_lines(options)

        # Construir índice por code para acceso rápido en templates
        lines_by_code = {}

        def _index_lines(lines_list, parent_code=None):
            """Recursivamente indexa líneas por code"""
            for line in lines_list:
                code = line.get('line_code')
                if code:
                    lines_by_code[code] = line

                # Procesar children recursivamente
                if line.get('unfoldable') and line.get('unfolded'):
                    children = line.get('lines', [])
                    _index_lines(children, code)

        _index_lines(lines)

        # Extraer totales principales (útil para resúmenes rápidos)
        totals = {}
        for code, line in lines_by_code.items():
            if line.get('columns'):
                # Primer columna es generalmente el valor principal
                col_value = line['columns'][0]
                totals[code] = {
                    'formatted': col_value.get('name', ''),
                    'raw': col_value.get('no_format', 0.0),
                }

        # Información del período
        period_info = {
            'date_from': options.get('date', {}).get('date_from'),
            'date_to': options.get('date', {}).get('date_to'),
            'filter_label': options.get('date', {}).get('filter', 'custom'),
        }

        # Información de la compañía
        company = self.env.company
        company_info = {
            'name': company.name,
            'vat': company.vat or '',
            'street': company.street or '',
            'city': company.city or '',
            'country': company.country_id.name if company.country_id else '',
        }

        return {
            'lines': lines,
            'lines_by_code': lines_by_code,
            'totals': totals,
            'period_info': period_info,
            'company_info': company_info,
            'options': options,
        }

    def _get_line_value(self, lines_by_code, line_code, column_index=0, formatted=True):
        """
        Helper para extraer valor de una línea específica en templates.

        Args:
            lines_by_code (dict): Dict retornado por get_pdf_context()
            line_code (str): Code de la línea (ej: 'CL_ASSETS', 'CL_NET_PROFIT')
            column_index (int): Índice de columna (0 = principal, 1+ = comparaciones)
            formatted (bool): Si True retorna string formateado, si False retorna float

        Returns:
            str|float: Valor de la celda (formateado o raw)

        Example en template QWeb:
            <span t-esc="o._get_line_value(lines_by_code, 'CL_ASSETS')"/>
        """
        line = lines_by_code.get(line_code)
        if not line or not line.get('columns'):
            return '0.00' if formatted else 0.0

        if column_index >= len(line['columns']):
            return '0.00' if formatted else 0.0

        column = line['columns'][column_index]
        return column.get('name', '0.00') if formatted else column.get('no_format', 0.0)
