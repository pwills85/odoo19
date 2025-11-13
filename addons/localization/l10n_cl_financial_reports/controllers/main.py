# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request

class FinancialReportController(http.Controller):

    @http.route('/financial_reports/get_report_data', type='jsonrpc', auth='user')
    def get_report_data(self, report_options):
        """
        Endpoint centralizado para obtener datos de informes financieros.
        """
        try:
            report_model = report_options.get('report_model')
            report_id = report_options.get('report_id')
            report_code = report_options.get('report_code') # new parameter

            report = request.env[report_model].browse(report_id)
            service = request.env['financial.report.service']
            
            data_map = {
                'balance_8_columns': service.get_balance_eight_columns_data,
                'balance_sheet': service.get_balance_sheet_data,
                'income_statement': service.get_income_statement_data,
                'trial_balance': service.get_trial_balance_data,
                'general_ledger': service.get_general_ledger_data,
            }

            if report_code in data_map:
                lines, totals = data_map[report_code](report)
                return {
                    'lines': lines,
                    'totals': totals,
                    'report_name': report.name,
                    'company_name': report.company_id.name,
                }
            else:
                return {'error': f'Report code "{report_code}" not supported'}

        except Exception as e:
            _logger.error(f"Error: {e}", exc_info=True)
            return {'error': str(e)}