# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
import json
import base64
import xlsxwriter
import io
from datetime import datetime
import logging

_logger = logging.getLogger(__name__)


class AnalyticReportController(http.Controller):
    """Controlador para reportes analíticos de proyectos"""
    
    @http.route('/account_financial_report/analytic/export', type='json', auth='user')
    def export_analytic_report(self, project_ids, date_from, date_to, 
                              include_timesheet=True, group_by_account=True):
        """
        Exporta reporte analítico a Excel
        
        :param project_ids: Lista de IDs de proyectos
        :param date_from: Fecha inicio
        :param date_to: Fecha fin
        :param include_timesheet: Incluir datos de timesheet
        :param group_by_account: Agrupar por cuenta contable
        :return: Archivo Excel en base64
        """
        try:
            # Obtener servicio
            service = request.env['analytic.report.service'].sudo()
            
            # Obtener datos del reporte
            report_data = service.get_analytic_report_data(
                project_ids, date_from, date_to,
                include_timesheet, group_by_account, True
            )
            
            if not report_data['success']:
                return {'success': False, 'error': report_data.get('error', 'Error desconocido')}
            
            # Crear archivo Excel
            output = io.BytesIO()
            workbook = xlsxwriter.Workbook(output, {'in_memory': True})
            
            # Formatos
            formats = self._get_excel_formats(workbook)
            
            # Hoja de resumen
            self._create_summary_sheet(workbook, report_data, formats)
            
            # Hoja por cada proyecto
            for project_id, project_data in report_data['data'].items():
                sheet_name = f"{project_data['analytic_account_code'][:20]}"
                self._create_project_sheet(workbook, sheet_name, project_data, formats)
            
            # Hoja de comparación
            self._create_comparison_sheet(workbook, report_data, formats)
            
            # Hoja de timesheet consolidado
            if include_timesheet:
                self._create_timesheet_sheet(workbook, report_data, formats)
            
            workbook.close()
            output.seek(0)
            
            # Convertir a base64
            file_data = base64.b64encode(output.read()).decode()
            filename = f"reporte_analitico_{date_from}_{date_to}.xlsx"
            
            return {
                'success': True,
                'file': file_data,
                'filename': filename
            }
            
        except Exception as e:
            _logger.error(f"Error exportando reporte analítico: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _get_excel_formats(self, workbook):
        """Define formatos para Excel"""
        return {
            'header': workbook.add_format({
                'bold': True,
                'bg_color': '#1f497d',
                'font_color': 'white',
                'align': 'center',
                'valign': 'vcenter',
                'border': 1
            }),
            'subheader': workbook.add_format({
                'bold': True,
                'bg_color': '#d9e2f3',
                'border': 1
            }),
            'title': workbook.add_format({
                'bold': True,
                'font_size': 16,
                'align': 'center'
            }),
            'subtitle': workbook.add_format({
                'bold': True,
                'font_size': 12,
                'align': 'left'
            }),
            'currency': workbook.add_format({
                'num_format': '$#,##0',
                'align': 'right'
            }),
            'currency_bold': workbook.add_format({
                'num_format': '$#,##0',
                'align': 'right',
                'bold': True
            }),
            'percent': workbook.add_format({
                'num_format': '0.0%',
                'align': 'right'
            }),
            'number': workbook.add_format({
                'num_format': '#,##0.00',
                'align': 'right'
            }),
            'date': workbook.add_format({
                'num_format': 'dd/mm/yyyy',
                'align': 'center'
            }),
            'text_center': workbook.add_format({
                'align': 'center'
            }),
            'total': workbook.add_format({
                'bold': True,
                'bg_color': '#f2f2f2',
                'border_top': 2
            }),
            'positive': workbook.add_format({
                'font_color': '#006100',
                'num_format': '$#,##0'
            }),
            'negative': workbook.add_format({
                'font_color': '#9c0006',
                'num_format': '$#,##0'
            })
        }
    
    def _create_summary_sheet(self, workbook, report_data, formats):
        """Crea hoja de resumen general"""
        worksheet = workbook.add_worksheet('Resumen')
        
        # Configurar anchos de columna
        worksheet.set_column('A:A', 40)
        worksheet.set_column('B:F', 15)
        
        row = 0
        
        # Título
        worksheet.merge_range(row, 0, row, 5, 'REPORTE ANALÍTICO DE PROYECTOS', formats['title'])
        row += 1
        
        # Período
        period_text = f"Período: {report_data['filters']['date_from']} al {report_data['filters']['date_to']}"
        worksheet.merge_range(row, 0, row, 5, period_text, formats['text_center'])
        row += 2
        
        # Resumen de proyectos
        worksheet.write(row, 0, 'RESUMEN DE PROYECTOS', formats['subtitle'])
        row += 2
        
        # Encabezados
        headers = ['Proyecto', 'Ingresos', 'Costos', 'Margen', 'Margen %', 'Horas']
        for col, header in enumerate(headers):
            worksheet.write(row, col, header, formats['header'])
        row += 1
        
        # Datos de proyectos
        total_revenue = 0
        total_costs = 0
        total_hours = 0
        
        for project_id, project_data in report_data['data'].items():
            revenue = project_data['totals']['credit']
            costs = project_data['totals']['debit']
            margin = revenue - costs
            margin_percent = (margin / revenue) if revenue > 0 else 0
            hours = project_data['timesheet']['total_hours']
            
            worksheet.write(row, 0, f"{project_data['analytic_account_code']} - {project_data['analytic_account_name']}")
            worksheet.write(row, 1, revenue, formats['positive'])
            worksheet.write(row, 2, costs, formats['negative'])
            worksheet.write(row, 3, margin, formats['positive'] if margin > 0 else formats['negative'])
            worksheet.write(row, 4, margin_percent, formats['percent'])
            worksheet.write(row, 5, hours, formats['number'])
            
            total_revenue += revenue
            total_costs += costs
            total_hours += hours
            row += 1
        
        # Totales
        worksheet.write(row, 0, 'TOTALES', formats['total'])
        worksheet.write(row, 1, total_revenue, formats['currency_bold'])
        worksheet.write(row, 2, total_costs, formats['currency_bold'])
        worksheet.write(row, 3, total_revenue - total_costs, formats['currency_bold'])
        worksheet.write(row, 4, (total_revenue - total_costs) / total_revenue if total_revenue > 0 else 0, formats['percent'])
        worksheet.write(row, 5, total_hours, formats['number'])
        
        # KPIs
        row += 3
        worksheet.write(row, 0, 'INDICADORES CLAVE', formats['subtitle'])
        row += 1
        
        kpis = report_data['totals']['kpis']
        worksheet.write(row, 0, 'Costo promedio por hora:')
        worksheet.write(row, 1, kpis.get('average_hourly_cost', 0), formats['currency'])
        row += 1
        
        worksheet.write(row, 0, 'Margen de ganancia promedio:')
        worksheet.write(row, 1, kpis.get('profit_margin', 0) / 100, formats['percent'])
        row += 1
        
        worksheet.write(row, 0, 'Costo promedio por proyecto:')
        worksheet.write(row, 1, kpis.get('cost_per_project', 0), formats['currency'])
    
    def _create_project_sheet(self, workbook, sheet_name, project_data, formats):
        """Crea hoja detallada para un proyecto"""
        worksheet = workbook.add_worksheet(sheet_name)
        
        # Configurar anchos
        worksheet.set_column('A:A', 12)  # Fecha
        worksheet.set_column('B:B', 40)  # Descripción
        worksheet.set_column('C:C', 20)  # Partner
        worksheet.set_column('D:D', 15)  # Cuenta
        worksheet.set_column('E:G', 15)  # Montos
        
        row = 0
        
        # Título del proyecto
        title = f"{project_data['analytic_account_code']} - {project_data['analytic_account_name']}"
        worksheet.merge_range(row, 0, row, 6, title, formats['title'])
        row += 2
        
        # Resumen
        worksheet.write(row, 0, 'RESUMEN', formats['subtitle'])
        row += 1
        
        worksheet.write(row, 0, 'Total Ingresos:', formats['subheader'])
        worksheet.write(row, 1, project_data['totals']['credit'], formats['positive'])
        row += 1
        
        worksheet.write(row, 0, 'Total Costos:', formats['subheader'])
        worksheet.write(row, 1, project_data['totals']['debit'], formats['negative'])
        row += 1
        
        worksheet.write(row, 0, 'Margen:', formats['subheader'])
        margin = project_data['totals']['credit'] - project_data['totals']['debit']
        worksheet.write(row, 1, margin, formats['positive'] if margin > 0 else formats['negative'])
        row += 2
        
        # Detalle por cuenta contable
        if project_data.get('accounts'):
            worksheet.write(row, 0, 'DETALLE POR CUENTA CONTABLE', formats['subtitle'])
            row += 1
            
            # Encabezados
            headers = ['Cuenta', 'Descripción', 'Débito', 'Crédito', 'Balance']
            for col, header in enumerate(headers):
                worksheet.write(row, col, header, formats['header'])
            row += 1
            
            # Datos
            for account_code, account_data in project_data['accounts'].items():
                worksheet.write(row, 0, account_code)
                worksheet.write(row, 1, account_data.get('name', ''))
                worksheet.write(row, 2, account_data['debit'], formats['currency'])
                worksheet.write(row, 3, account_data['credit'], formats['currency'])
                worksheet.write(row, 4, account_data['balance'], 
                              formats['positive'] if account_data['balance'] < 0 else formats['negative'])
                row += 1
            
            row += 2
        
        # Detalle de timesheet
        if project_data['timesheet']['employees']:
            worksheet.write(row, 0, 'DETALLE DE HORAS', formats['subtitle'])
            row += 1
            
            # Encabezados
            headers = ['Empleado', 'Horas', 'Costo/Hr', 'Costo Total', 'Días']
            for col, header in enumerate(headers):
                worksheet.write(row, col, header, formats['header'])
            row += 1
            
            # Datos
            for emp in project_data['timesheet']['employees']:
                worksheet.write(row, 0, emp['employee_name'])
                worksheet.write(row, 1, emp['total_hours'], formats['number'])
                worksheet.write(row, 2, emp['hourly_cost'], formats['currency'])
                worksheet.write(row, 3, emp['total_cost'], formats['currency'])
                worksheet.write(row, 4, emp['days_worked'], formats['number'])
                row += 1
            
            # Total
            worksheet.write(row, 0, 'TOTAL', formats['total'])
            worksheet.write(row, 1, project_data['timesheet']['total_hours'], formats['number'])
            worksheet.write(row, 3, project_data['timesheet']['total_cost'], formats['currency_bold'])
    
    def _create_comparison_sheet(self, workbook, report_data, formats):
        """Crea hoja de comparación entre proyectos"""
        worksheet = workbook.add_worksheet('Comparación')
        
        # Configurar anchos
        worksheet.set_column('A:A', 30)
        worksheet.set_column('B:H', 15)
        
        row = 0
        
        # Título
        worksheet.merge_range(row, 0, row, 7, 'COMPARACIÓN DE PROYECTOS', formats['title'])
        row += 2
        
        # Crear lista de proyectos ordenados por margen
        projects = []
        for project_id, project_data in report_data['data'].items():
            revenue = project_data['totals']['credit']
            costs = project_data['totals']['debit']
            margin = revenue - costs
            margin_percent = (margin / revenue * 100) if revenue > 0 else 0
            
            projects.append({
                'code': project_data['analytic_account_code'],
                'name': project_data['analytic_account_name'],
                'revenue': revenue,
                'costs': costs,
                'margin': margin,
                'margin_percent': margin_percent,
                'hours': project_data['timesheet']['total_hours'],
                'timesheet_cost': project_data['timesheet']['total_cost']
            })
        
        # Ordenar por margen descendente
        projects.sort(key=lambda x: x['margin'], reverse=True)
        
        # Encabezados
        headers = ['Proyecto', 'Ingresos', 'Costos', 'Margen', 'Margen %', 'Horas', 'Costo HH', 'Estado']
        for col, header in enumerate(headers):
            worksheet.write(row, col, header, formats['header'])
        row += 1
        
        # Datos
        for proj in projects:
            worksheet.write(row, 0, f"{proj['code']} - {proj['name']}")
            worksheet.write(row, 1, proj['revenue'], formats['positive'])
            worksheet.write(row, 2, proj['costs'], formats['negative'])
            worksheet.write(row, 3, proj['margin'], 
                          formats['positive'] if proj['margin'] > 0 else formats['negative'])
            worksheet.write(row, 4, proj['margin_percent'] / 100, formats['percent'])
            worksheet.write(row, 5, proj['hours'], formats['number'])
            worksheet.write(row, 6, proj['timesheet_cost'], formats['currency'])
            worksheet.write(row, 7, 'Rentable' if proj['margin'] > 0 else 'Pérdida',
                          formats['positive'] if proj['margin'] > 0 else formats['negative'])
            row += 1
        
        # Gráfico de barras
        if len(projects) > 0:
            chart = workbook.add_chart({'type': 'column'})
            
            # Configurar series
            chart.add_series({
                'name': 'Ingresos',
                'categories': ['Comparación', 1, 0, len(projects), 0],
                'values': ['Comparación', 1, 1, len(projects), 1],
                'fill': {'color': '#70AD47'}
            })
            
            chart.add_series({
                'name': 'Costos',
                'categories': ['Comparación', 1, 0, len(projects), 0],
                'values': ['Comparación', 1, 2, len(projects), 2],
                'fill': {'color': '#ED7D31'}
            })
            
            chart.add_series({
                'name': 'Margen',
                'categories': ['Comparación', 1, 0, len(projects), 0],
                'values': ['Comparación', 1, 3, len(projects), 3],
                'fill': {'color': '#5B9BD5'}
            })
            
            # Configurar gráfico
            chart.set_title({'name': 'Comparación de Proyectos'})
            chart.set_x_axis({'name': 'Proyectos'})
            chart.set_y_axis({'name': 'Monto ($)'})
            chart.set_size({'width': 720, 'height': 480})
            
            # Insertar gráfico
            worksheet.insert_chart(row + 2, 0, chart)
    
    def _create_timesheet_sheet(self, workbook, report_data, formats):
        """Crea hoja consolidada de timesheet"""
        worksheet = workbook.add_worksheet('Timesheet Consolidado')
        
        # Configurar anchos
        worksheet.set_column('A:A', 30)
        worksheet.set_column('B:B', 25)
        worksheet.set_column('C:F', 15)
        
        row = 0
        
        # Título
        worksheet.merge_range(row, 0, row, 5, 'TIMESHEET CONSOLIDADO', formats['title'])
        row += 2
        
        # Recopilar todos los empleados
        employee_data = {}
        
        for project_id, project_data in report_data['data'].items():
            project_name = f"{project_data['analytic_account_code']} - {project_data['analytic_account_name']}"
            
            for emp in project_data['timesheet']['employees']:
                emp_name = emp['employee_name']
                if emp_name not in employee_data:
                    employee_data[emp_name] = {
                        'projects': {},
                        'total_hours': 0,
                        'total_cost': 0
                    }
                
                employee_data[emp_name]['projects'][project_name] = {
                    'hours': emp['total_hours'],
                    'cost': emp['total_cost'],
                    'hourly_cost': emp['hourly_cost']
                }
                employee_data[emp_name]['total_hours'] += emp['total_hours']
                employee_data[emp_name]['total_cost'] += emp['total_cost']
        
        # Encabezados
        headers = ['Empleado', 'Proyecto', 'Horas', 'Costo/Hr', 'Costo Total']
        for col, header in enumerate(headers):
            worksheet.write(row, col, header, formats['header'])
        row += 1
        
        # Datos por empleado
        grand_total_hours = 0
        grand_total_cost = 0
        
        for emp_name, emp_info in sorted(employee_data.items()):
            first_row = True
            emp_start_row = row
            
            for project_name, project_info in emp_info['projects'].items():
                if first_row:
                    worksheet.write(row, 0, emp_name)
                    first_row = False
                
                worksheet.write(row, 1, project_name)
                worksheet.write(row, 2, project_info['hours'], formats['number'])
                worksheet.write(row, 3, project_info['hourly_cost'], formats['currency'])
                worksheet.write(row, 4, project_info['cost'], formats['currency'])
                row += 1
            
            # Subtotal por empleado
            if len(emp_info['projects']) > 1:
                worksheet.write(row, 1, f'Subtotal {emp_name}', formats['subheader'])
                worksheet.write(row, 2, emp_info['total_hours'], formats['number'])
                worksheet.write(row, 4, emp_info['total_cost'], formats['currency_bold'])
                row += 1
            
            grand_total_hours += emp_info['total_hours']
            grand_total_cost += emp_info['total_cost']
            row += 1
        
        # Gran total
        worksheet.write(row, 0, 'GRAN TOTAL', formats['total'])
        worksheet.write(row, 2, grand_total_hours, formats['number'])
        worksheet.write(row, 4, grand_total_cost, formats['currency_bold'])
    
    @http.route('/account_financial_report/analytic/dashboard_data', type='json', auth='user')
    def get_dashboard_data(self, project_ids=None, months=6):
        """
        Obtiene datos para el dashboard de proyectos
        
        :param project_ids: IDs de proyectos (None = todos)
        :param months: Número de meses hacia atrás
        :return: Datos del dashboard
        """
        try:
            service = request.env['analytic.report.service'].sudo()
            result = service.get_project_dashboard_data(project_ids, months)
            return result
            
        except Exception as e:
            _logger.error(f"Error obteniendo datos del dashboard: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    @http.route('/account_financial_report/analytic/project_details/<int:project_id>', 
                type='json', auth='user')
    def get_project_details(self, project_id, date_from=None, date_to=None):
        """
        Obtiene detalles de un proyecto específico
        
        :param project_id: ID del proyecto
        :param date_from: Fecha inicio (opcional)
        :param date_to: Fecha fin (opcional)
        :return: Detalles del proyecto
        """
        try:
            from datetime import date
            from dateutil.relativedelta import relativedelta
            
            # Fechas por defecto: últimos 6 meses
            if not date_to:
                date_to = date.today().strftime('%Y-%m-%d')
            if not date_from:
                date_from = (date.today() - relativedelta(months=6)).strftime('%Y-%m-%d')
            
            service = request.env['analytic.report.service'].sudo()
            result = service.get_analytic_report_data(
                [project_id], date_from, date_to,
                include_timesheet=True, group_by_account=True
            )
            
            if result['success'] and project_id in result['data']:
                return {
                    'success': True,
                    'data': result['data'][project_id],
                    'filters': result['filters']
                }
            else:
                return {'success': False, 'error': 'Proyecto no encontrado'}
                
        except Exception as e:
            _logger.error(f"Error obteniendo detalles del proyecto: {str(e)}")
            return {'success': False, 'error': str(e)}
