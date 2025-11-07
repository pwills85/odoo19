# -*- coding: utf-8 -*-
from odoo import _
from odoo.exceptions import UserError
import logging
import base64
import io
from collections import defaultdict

_logger = logging.getLogger(__name__)


class TrialBalanceService:
    """
    Servicio para cálculo y exportación del Balance de Comprobación.
    Implementa lógica optimizada para manejo de grandes volúmenes.
    """
    
    def __init__(self, env):
        self.env = env
        self._cache = {}
        
    def compute_trial_balance(self, date_from, date_to, company_id, 
                            target_move='posted', hide_zero_balance=True,
                            show_initial_balance=True, hierarchy_level='all',
                            comparison_enabled=False, previous_date_from=None,
                            previous_date_to=None):
        """
        Calcula el balance de comprobación con todas las opciones.
        
        Returns:
            dict: Datos del balance con líneas y totales
        """
        try:
            # Obtener datos principales
            lines_data = self._get_trial_balance_data(
                date_from, date_to, company_id, target_move,
                show_initial_balance
            )
            
            # Si hay comparación, obtener datos del período anterior
            if comparison_enabled and previous_date_from and previous_date_to:
                previous_data = self._get_trial_balance_data(
                    previous_date_from, previous_date_to, company_id, 
                    target_move, False
                )
                # Merge con datos actuales
                lines_data = self._merge_comparison_data(lines_data, previous_data)
            
            # Aplicar filtros
            if hide_zero_balance:
                lines_data = self._filter_zero_balances(lines_data)
            
            # Aplicar jerarquía
            lines_data = self._apply_hierarchy_filter(lines_data, hierarchy_level)
            
            # Agregar líneas de grupo si es necesario
            if hierarchy_level in ['1', '2', '3']:
                lines_data = self._add_group_lines(lines_data, int(hierarchy_level))
            
            # Calcular totales
            totals = self._calculate_totals(lines_data)
            
            return {
                'lines': lines_data,
                'totals': totals,
                'is_balanced': abs(totals['ending_debit'] - totals['ending_credit']) < 0.01
            }
            
        except Exception as e:
            _logger.error(f"Error computing trial balance: {str(e)}")
            raise UserError(_(
                "Error al calcular el balance de comprobación: %s"
            ) % str(e))
    
    def _get_trial_balance_data(self, date_from, date_to, company_id, 
                               target_move, show_initial_balance):
        """
        Obtiene los datos del balance usando el ORM de Odoo y search_fetch.
        """
        AccountMoveLine = self.env['account.move.line']
        
        base_domain = [
            ('company_id', '=', company_id),
            ('account_id.include_initial_balance', '=', True),
        ]
        if target_move == 'posted':
            base_domain.append(('move_id.state', '=', 'posted'))

        initial_balances = defaultdict(lambda: {'initial_debit': 0, 'initial_credit': 0})
        if show_initial_balance:
            initial_domain = base_domain + [('date', '<', date_from)]
            initial_data = AccountMoveLine.read_group(
                initial_domain, ['debit', 'credit'], ['account_id']
            )
            for data in initial_data:
                initial_balances[data['account_id'][0]] = {
                    'initial_debit': data['debit'],
                    'initial_credit': data['credit'],
                }

        period_domain = base_domain + [('date', '>=', date_from), ('date', '<=', date_to)]
        period_data_groups = AccountMoveLine.read_group(
            period_domain, ['debit', 'credit'], ['account_id']
        )
        period_balances = {data['account_id'][0]: data for data in period_data_groups}

        all_account_ids = list(set(initial_balances.keys()) | set(period_balances.keys()))
        
        # Usar search_fetch para obtener datos de cuentas de forma eficiente
        accounts_data = self.env['account.account'].search_fetch(
            [('id', 'in', all_account_ids)],
            ['code', 'name', 'account_type'])
        
        lines = []
        for acc_id, code, name, acc_type in accounts_data:
            initial = initial_balances[acc_id]
            period = period_balances.get(acc_id, {'debit': 0, 'credit': 0})

            ending_debit = initial['initial_debit'] + period['debit']
            ending_credit = initial['initial_credit'] + period['credit']
            
            lines.append({
                'account_id': acc_id,
                'account_code': code,
                'account_name': name,
                'account_type': acc_type,
                'hierarchy_level': len(code.split('.')),
                'is_group_line': False,
                'initial_debit': initial['initial_debit'],
                'initial_credit': initial['initial_credit'],
                'initial_balance': initial['initial_debit'] - initial['initial_credit'],
                'period_debit': period['debit'],
                'period_credit': period['credit'],
                'period_balance': period['debit'] - period['credit'],
                'ending_debit': ending_debit,
                'ending_credit': ending_credit,
                'ending_balance': ending_debit - ending_credit,
            })
            
        return sorted(lines, key=lambda x: x['account_code'])
    
    def _merge_comparison_data(self, current_data, previous_data):
        """
        Combina datos del período actual con el anterior para comparación.
        """
        # Crear índice de datos anteriores
        previous_index = {
            line['account_code']: line['ending_balance'] 
            for line in previous_data
        }
        
        # Actualizar líneas actuales con comparación
        for line in current_data:
            previous_balance = previous_index.get(line['account_code'], 0.0)
            variation = line['ending_balance'] - previous_balance
            
            line['previous_ending_balance'] = previous_balance
            line['variation_amount'] = variation
            
            # Calcular porcentaje de variación
            if previous_balance != 0:
                line['variation_percent'] = (variation / abs(previous_balance)) * 100
            else:
                line['variation_percent'] = 100.0 if variation != 0 else 0.0
        
        return current_data
    
    def _filter_zero_balances(self, lines_data):
        """
        Filtra cuentas con saldo cero.
        """
        return [
            line for line in lines_data
            if abs(line['ending_balance']) > 0.01 or
               abs(line['period_debit']) > 0.01 or
               abs(line['period_credit']) > 0.01
        ]
    
    def _apply_hierarchy_filter(self, lines_data, hierarchy_level):
        """
        Aplica filtro de nivel jerárquico.
        """
        if hierarchy_level == 'all':
            return lines_data
        elif hierarchy_level == 'detail':
            # Solo cuentas de detalle (sin subcuentas)
            detail_codes = self._get_detail_account_codes(lines_data)
            return [l for l in lines_data if l['account_code'] in detail_codes]
        else:
            # Filtrar por nivel específico
            level = int(hierarchy_level)
            return [
                l for l in lines_data 
                if l['hierarchy_level'] <= level
            ]
    
    def _get_detail_account_codes(self, lines_data):
        """
        Identifica cuentas de detalle (sin subcuentas).
        """
        all_codes = {l['account_code'] for l in lines_data}
        parent_codes = set()
        
        for code in all_codes:
            # Un código es padre si algún otro código empieza con él
            for other_code in all_codes:
                if other_code != code and other_code.startswith(code + '.'):
                    parent_codes.add(code)
                    break
        
        return all_codes - parent_codes
    
    def _add_group_lines(self, lines_data, max_level):
        """
        Agrega líneas de grupo/subtotal según nivel jerárquico.
        """
        # Organizar por nivel y código
        by_level = defaultdict(list)
        for line in lines_data:
            if line['hierarchy_level'] <= max_level:
                by_level[line['hierarchy_level']].append(line)
        
        # Crear grupos desde el nivel más bajo hacia arriba
        result = []
        groups_added = set()
        
        for level in range(max_level, 0, -1):
            level_lines = by_level.get(level, [])
            
            for line in sorted(level_lines, key=lambda x: x['account_code']):
                # Agregar la línea
                result.append(line)
                
                # Si es nivel > 1, crear grupo padre si no existe
                if level > 1:
                    parent_code = '.'.join(line['account_code'].split('.')[:-1])
                    if parent_code and parent_code not in groups_added:
                        # Calcular totales del grupo
                        group_lines = [
                            l for l in lines_data
                            if l['account_code'].startswith(parent_code + '.')
                        ]
                        
                        if group_lines:
                            group_line = self._create_group_line(
                                parent_code, group_lines, level - 1
                            )
                            result.append(group_line)
                            groups_added.add(parent_code)
        
        # Ordenar resultado final
        return sorted(result, key=lambda x: x['account_code'])
    
    def _create_group_line(self, group_code, child_lines, level):
        """
        Crea una línea de grupo con totales.
        """
        # Sumar totales de líneas hijas
        totals = {
            'initial_debit': sum(l['initial_debit'] for l in child_lines),
            'initial_credit': sum(l['initial_credit'] for l in child_lines),
            'period_debit': sum(l['period_debit'] for l in child_lines),
            'period_credit': sum(l['period_credit'] for l in child_lines),
            'ending_debit': sum(l['ending_debit'] for l in child_lines),
            'ending_credit': sum(l['ending_credit'] for l in child_lines),
        }
        
        # Determinar nombre del grupo
        group_name = self._get_group_name(group_code)
        
        return {
            'account_id': False,
            'account_code': group_code,
            'account_name': f"TOTAL {group_name}",
            'account_type': 'group',
            'hierarchy_level': level,
            'is_group_line': True,
            'initial_debit': totals['initial_debit'],
            'initial_credit': totals['initial_credit'],
            'initial_balance': totals['initial_debit'] - totals['initial_credit'],
            'period_debit': totals['period_debit'],
            'period_credit': totals['period_credit'],
            'period_balance': totals['period_debit'] - totals['period_credit'],
            'ending_debit': totals['ending_debit'],
            'ending_credit': totals['ending_credit'],
            'ending_balance': totals['ending_debit'] - totals['ending_credit'],
            'previous_ending_balance': 0.0,
            'variation_amount': 0.0,
            'variation_percent': 0.0,
        }
    
    def _get_group_name(self, group_code):
        """
        Obtiene el nombre del grupo según el código.
        """
        # Mapeo básico de grupos principales
        group_map = {
            '1': 'ACTIVOS',
            '2': 'PASIVOS',
            '3': 'PATRIMONIO',
            '4': 'INGRESOS',
            '5': 'COSTOS',
            '6': 'GASTOS',
            '11': 'ACTIVO CORRIENTE',
            '12': 'ACTIVO NO CORRIENTE',
            '21': 'PASIVO CORRIENTE',
            '22': 'PASIVO NO CORRIENTE',
        }
        
        # Intentar mapeo directo
        if group_code in group_map:
            return group_map[group_code]
        
        # Si no, usar el código como nombre
        return f"GRUPO {group_code}"
    
    def _calculate_totals(self, lines_data):
        """
        Calcula los totales generales del balance.
        """
        # Filtrar solo cuentas (no grupos) para totales
        account_lines = [l for l in lines_data if not l.get('is_group_line', False)]
        
        return {
            'initial_debit': sum(l['initial_debit'] for l in account_lines),
            'initial_credit': sum(l['initial_credit'] for l in account_lines),
            'period_debit': sum(l['period_debit'] for l in account_lines),
            'period_credit': sum(l['period_credit'] for l in account_lines),
            'ending_debit': sum(l['ending_debit'] for l in account_lines),
            'ending_credit': sum(l['ending_credit'] for l in account_lines),
        }
    
    def export_to_excel(self, report):
        """
        Exporta el balance de 8 columnas a Excel.
        """
        # Optimización: usar with_context para prefetch
        report = report.with_context(prefetch_fields=False)

        try:
            from xlsxwriter import Workbook
            output = io.BytesIO()
            workbook = Workbook(output, {'in_memory': True})
            worksheet = workbook.add_worksheet('Balance 8 Columnas')
            formats = self._get_excel_formats(workbook)

            # Escribir encabezado
            worksheet.merge_range(0, 0, 0, 11, "BALANCE DE 8 COLUMNAS", formats['header'])
            worksheet.merge_range(1, 0, 1, 11, report.company_id.name, formats['subheader'])
            period_text = f"Del {report.date_from.strftime('%d/%m/%Y')} al {report.date_to.strftime('%d/%m/%Y')}"
            worksheet.merge_range(2, 0, 2, 11, period_text, formats['subheader'])
            
            # Escribir títulos de columnas
            headers = [
                'Código', 'Cuenta', 'Deudor Inicial', 'Acreedor Inicial', 'Debe', 'Haber',
                'Deudor Final', 'Acreedor Final', 'Activo', 'Pasivo', 'Pérdida', 'Ganancia'
            ]
            for col, header in enumerate(headers):
                worksheet.write(3, col, header, formats['column_header'])

            # Escribir líneas
            lines, totals = self.get_report_data(report)
            row = 4
            for line in lines:
                worksheet.write(row, 0, line['code'], formats['account_line'])
                worksheet.write(row, 1, line['name'], formats['account_line'])
                worksheet.write(row, 2, line['initial_debit'], formats['account_line'])
                worksheet.write(row, 3, line['initial_credit'], formats['account_line'])
                worksheet.write(row, 4, line['period_debit'], formats['account_line'])
                worksheet.write(row, 5, line['period_credit'], formats['account_line'])
                worksheet.write(row, 6, line['final_debit'], formats['account_line'])
                worksheet.write(row, 7, line['final_credit'], formats['account_line'])
                worksheet.write(row, 8, line['asset'], formats['account_line'])
                worksheet.write(row, 9, line['liability'], formats['account_line'])
                worksheet.write(row, 10, line['loss'], formats['account_line'])
                worksheet.write(row, 11, line['gain'], formats['account_line'])
                row += 1

            # Escribir totales
            worksheet.write(row, 1, 'TOTALES', formats['total_line'])
            worksheet.write(row, 2, totals['initial_debit'], formats['total_line'])
            worksheet.write(row, 3, totals['initial_credit'], formats['total_line'])
            worksheet.write(row, 4, totals['period_debit'], formats['total_line'])
            worksheet.write(row, 5, totals['period_credit'], formats['total_line'])
            worksheet.write(row, 6, totals['final_debit'], formats['total_line'])
            worksheet.write(row, 7, totals['final_credit'], formats['total_line'])
            worksheet.write(row, 8, totals['asset'], formats['total_line'])
            worksheet.write(row, 9, totals['liability'], formats['total_line'])
            worksheet.write(row, 10, totals['loss'], formats['total_line'])
            worksheet.write(row, 11, totals['gain'], formats['total_line'])

            # Escribir resultado del ejercicio
            row += 2
            worksheet.write(row, 9, 'Resultado Ejercicio', formats['subheader'])
            worksheet.write(row, 10, totals['result_balance'], formats['total_line'])
            
            workbook.close()
            output.seek(0)
            
            filename = f"Balance_8_Columnas_{report.company_id.name}_{report.date_to}.xlsx"
            attachment = self.env['ir.attachment'].create({
                'name': filename,
                'type': 'binary',
                'datas': base64.b64encode(output.read()),
                'res_model': report._name,
                'res_id': report.id,
                'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            })
            
            return {
                'type': 'ir.actions.act_url',
                'url': f'/web/content/{attachment.id}/{filename}?download=true',
                'target': 'self',
            }
            
        except ImportError:
            raise UserError(_("La librería xlsxwriter no está instalada."))
        except Exception as e:
            _logger.error(f"Error exporting to Excel: {str(e)}")
            raise UserError(_("Error al exportar a Excel: %s") % str(e))
    
    def _get_excel_formats(self, workbook):
        """
        Define formatos para Excel.
        """
        return {
            'header': workbook.add_format({
                'bold': True,
                'font_size': 16,
                'align': 'center',
                'valign': 'vcenter',
                'bg_color': '#1B5E8C',
                'font_color': 'white',
                'border': 1
            }),
            'subheader': workbook.add_format({
                'bold': True,
                'font_size': 12,
                'align': 'center',
                'valign': 'vcenter',
                'bg_color': '#E8F0F7',
                'border': 1
            }),
            'column_header': workbook.add_format({
                'bold': True,
                'font_size': 11,
                'align': 'center',
                'valign': 'vcenter',
                'bg_color': '#4A90E2',
                'font_color': 'white',
                'border': 1,
                'text_wrap': True
            }),
            'group_line': workbook.add_format({
                'bold': True,
                'font_size': 10,
                'bg_color': '#F5F5F5',
                'border': 1,
                'num_format': '#,##0.00'
            }),
            'account_line': workbook.add_format({
                'font_size': 10,
                'border': 1,
                'num_format': '#,##0.00'
            }),
            'total_line': workbook.add_format({
                'bold': True,
                'font_size': 11,
                'bg_color': '#FFE599',
                'border': 2,
                'num_format': '#,##0.00'
            }),
            'date': workbook.add_format({
                'font_size': 10,
                'align': 'center',
                'border': 1,
                'num_format': 'dd/mm/yyyy'
            }),
            'percent': workbook.add_format({
                'font_size': 10,
                'align': 'right',
                'border': 1,
                'num_format': '0.00%'
            }),
            'positive_var': workbook.add_format({
                'font_size': 10,
                'align': 'right',
                'border': 1,
                'font_color': '#006400',
                'num_format': '#,##0.00'
            }),
            'negative_var': workbook.add_format({
                'font_size': 10,
                'align': 'right',
                'border': 1,
                'font_color': '#B22222',
                'num_format': '#,##0.00'
            }),
        }
    
    def _write_excel_header(self, worksheet, balance, formats):
        """
        Escribe el encabezado del reporte.
        """
        # Optimización: usar with_context para prefetch
        balance = balance.with_context(prefetch_fields=False)

        # Título principal
        worksheet.merge_range(0, 0, 0, 11, 
            "BALANCE DE COMPROBACIÓN Y SALDOS", 
            formats['header'])
        
        # Información de la empresa
        worksheet.merge_range(1, 0, 1, 11, 
            balance.company_id.name, 
            formats['subheader'])
        
        # Período
        period_text = f"Del {balance.date_from.strftime('%d/%m/%Y')} al {balance.date_to.strftime('%d/%m/%Y')}"
        worksheet.merge_range(2, 0, 2, 11, 
            period_text, 
            formats['subheader'])
        
        return 4
    
    def _write_column_headers(self, worksheet, balance, row, formats):
        """
        Escribe los encabezados de columnas.
        """
        headers = [
            ('Código', 15),
            ('Cuenta', 40),
        ]
        
        # Columnas de saldo inicial si están habilitadas
        if balance.show_initial_balance:
            headers.extend([
                ('Débito\nInicial', 15),
                ('Crédito\nInicial', 15),
            ])
        
        # Columnas del período
        headers.extend([
            ('Débitos\nPeríodo', 15),
            ('Créditos\nPeríodo', 15),
            ('Débito\nFinal', 15),
            ('Crédito\nFinal', 15),
            ('Saldo\nDeudor', 15),
            ('Saldo\nAcreedor', 15),
        ])
        
        # Columnas de comparación si están habilitadas
        if balance.comparison_enabled:
            headers.extend([
                ('Saldo\nAnterior', 15),
                ('Variación', 15),
                ('Var %', 10),
            ])
        
        # Escribir headers
        col = 0
        for header, width in headers:
            worksheet.write(row, col, header, formats['column_header'])
            worksheet.set_column(col, col, width)
            col += 1
        
        return row + 1
    
    def _write_balance_lines(self, worksheet, balance, row, formats):
        """
        Escribe las líneas del balance.
        """
        for line in balance.line_ids:
            col = 0
            
            # Determinar formato según tipo de línea
            if line.is_group_line:
                line_format = formats['group_line']
                # Indentar grupos
                account_name = "  " * (3 - line.hierarchy_level) + line.account_name
            else:
                line_format = formats['account_line']
                account_name = "    " + line.account_name
            
            # Código y nombre
            worksheet.write(row, col, line.account_code, line_format)
            col += 1
            worksheet.write(row, col, account_name, line_format)
            col += 1
            
            # Saldos iniciales si están habilitados
            if balance.show_initial_balance:
                worksheet.write(row, col, line.initial_debit, line_format)
                col += 1
                worksheet.write(row, col, line.initial_credit, line_format)
                col += 1
            
            # Movimientos del período
            worksheet.write(row, col, line.period_debit, line_format)
            col += 1
            worksheet.write(row, col, line.period_credit, line_format)
            col += 1
            
            # Saldos finales
            worksheet.write(row, col, line.ending_debit, line_format)
            col += 1
            worksheet.write(row, col, line.ending_credit, line_format)
            col += 1
            
            # Saldo deudor/acreedor
            if line.ending_balance > 0:
                worksheet.write(row, col, line.ending_balance, line_format)
                worksheet.write(row, col + 1, 0, line_format)
            else:
                worksheet.write(row, col, 0, line_format)
                worksheet.write(row, col + 1, abs(line.ending_balance), line_format)
            col += 2
            
            # Comparación si está habilitada
            if balance.comparison_enabled:
                worksheet.write(row, col, line.previous_ending_balance, line_format)
                col += 1
                
                # Variación con color
                var_format = formats['positive_var'] if line.variation_amount >= 0 else formats['negative_var']
                worksheet.write(row, col, line.variation_amount, var_format)
                col += 1
                
                # Porcentaje
                worksheet.write(row, col, line.variation_percent / 100, formats['percent'])
                col += 1
            
            row += 1
        
        return row
    
    def _write_totals(self, worksheet, balance, row, formats):
        """
        Escribe los totales finales.
        """
        row += 1  # Línea en blanco
        
        col = 0
        worksheet.write(row, col, "TOTALES", formats['total_line'])
        worksheet.write(row, col + 1, "", formats['total_line'])
        col = 2
        
        # Totales de cada columna
        if balance.show_initial_balance:
            worksheet.write(row, col, balance.total_initial_debit, formats['total_line'])
            worksheet.write(row, col + 1, balance.total_initial_credit, formats['total_line'])
            col += 2
        
        worksheet.write(row, col, balance.total_period_debit, formats['total_line'])
        worksheet.write(row, col + 1, balance.total_period_credit, formats['total_line'])
        worksheet.write(row, col + 2, balance.total_ending_debit, formats['total_line'])
        worksheet.write(row, col + 3, balance.total_ending_credit, formats['total_line'])
        
        # Verificación de cuadratura
        row += 2
        if balance.is_balanced:
            worksheet.merge_range(row, 0, row, 5, 
                "✓ BALANCE CUADRADO", 
                formats['subheader'])
        else:
            worksheet.merge_range(row, 0, row, 5, 
                f"✗ DESCUADRE: {balance.currency_id.symbol} {balance.balance_difference:,.2f}", 
                formats['header'])
    
    def _adjust_column_widths(self, worksheet, balance):
        """
        Ajusta anchos de columna según contenido.
        """
        # Ya configurado en _write_column_headers
        pass
    
    def _add_comparison_sheet(self, workbook, balance, formats):
        """
        Agrega hoja de análisis de variaciones.
        """
        worksheet = workbook.add_worksheet('Análisis de Variaciones')
        
        # Título
        worksheet.merge_range(0, 0, 0, 4, 
            "ANÁLISIS DE VARIACIONES", 
            formats['header'])
        
        # Filtrar líneas con variaciones significativas
        significant_lines = [
            line for line in balance.line_ids
            if not line.is_group_line and abs(line.variation_percent) > 10
        ]
        
        # Ordenar por variación absoluta
        significant_lines.sort(key=lambda x: abs(x.variation_amount), reverse=True)
        
        # Headers
        headers = [
            ('Código', 15),
            ('Cuenta', 40),
            ('Saldo Actual', 15),
            ('Saldo Anterior', 15),
            ('Variación', 15),
            ('Var %', 10),
        ]
        
        row = 2
        col = 0
        for header, width in headers:
            worksheet.write(row, col, header, formats['column_header'])
            worksheet.set_column(col, col, width)
            col += 1
        
        # Datos
        row = 3
        for line in significant_lines[:50]:  # Top 50 variaciones
            worksheet.write(row, 0, line.account_code, formats['account_line'])
            worksheet.write(row, 1, line.account_name, formats['account_line'])
            worksheet.write(row, 2, line.ending_balance, formats['account_line'])
            worksheet.write(row, 3, line.previous_ending_balance, formats['account_line'])
            
            var_format = formats['positive_var'] if line.variation_amount >= 0 else formats['negative_var']
            worksheet.write(row, 4, line.variation_amount, var_format)
            worksheet.write(row, 5, line.variation_percent / 100, formats['percent'])
            
            row += 1