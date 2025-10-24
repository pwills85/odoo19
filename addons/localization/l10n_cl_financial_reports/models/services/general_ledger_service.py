# -*- coding: utf-8 -*-
from odoo import models, api, _
from odoo.exceptions import UserError
from datetime import datetime
import logging
import base64
import io
import xlsxwriter

_logger = logging.getLogger(__name__)


class GeneralLedgerService(models.AbstractModel):
    """
    Service layer para el Mayor Analítico (General Ledger).
    Contiene toda la lógica de negocio optimizada para performance.
    """
    _name = 'account.general.ledger.service'
    _description = 'Servicio Mayor Analítico'
    
    @api.model
    def compute_general_ledger(self, date_from, date_to, company_id, 
                             account_ids=None, account_group_ids=None,
                             partner_ids=None, show_initial_balance=True,
                             show_partner_details=False, show_analytic_details=False,
                             centralize_journals=False, include_unposted=False):
        """
        Método principal para calcular el mayor analítico.
        Optimizado para performance con consultas SQL directas.
        """
        start_time = datetime.now()
        
        # Obtener cuentas a procesar
        accounts = self._get_accounts_to_process(
            company_id, account_ids, account_group_ids
        )
        
        result_accounts = []
        
        
        # TODO: Refactorizar para usar browse en batch fuera del loop
        for account in accounts:
            account_data = {
                'account_id': account.id,
                'account_code': account.code,
                'account_name': account.name,
                'moves': [],
                'initial_balance': 0.0,
                'total_debit': 0.0,
                'total_credit': 0.0,
            }
            
            # Calcular saldo inicial si se requiere
            if show_initial_balance:
                account_data['initial_balance'] = self._get_initial_balance(
                    account.id, date_from, company_id, partner_ids, include_unposted
                )
            
            # Obtener movimientos del período
            moves = self._get_account_moves(
                account.id, date_from, date_to, company_id,
                partner_ids, show_partner_details, show_analytic_details,
                centralize_journals, include_unposted
            )
            
            # Procesar movimientos
            for move in moves:
                account_data['moves'].append(move)
                account_data['total_debit'] += move['debit']
                account_data['total_credit'] += move['credit']
            
            # Solo agregar cuentas con movimientos o saldo inicial
            if account_data['moves'] or account_data['initial_balance'] != 0:
                result_accounts.append(account_data)
        
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        return {
            'accounts': result_accounts,
            'processing_time': processing_time,
            'account_count': len(result_accounts)
        }
    
    @api.model
    def _get_accounts_to_process(self, company_id, account_ids=None, account_group_ids=None):
        """
        Obtiene las cuentas a procesar según los filtros.
        """
        domain = [('company_id', '=', company_id)]
        
        if account_ids:
            domain.append(('id', 'in', account_ids))
        
        if account_group_ids:
            domain.append(('group_id', 'in', account_group_ids))
        
        # Ordenar por código para mejor presentación
        return self.env['account.account'].search(domain, order='code')
    
    @api.model
    def _get_initial_balance(self, account_id, date_from, company_id, 
                           partner_ids=None, include_unposted=False):
        """
        Calcula el saldo inicial de una cuenta antes de date_from.
        """
        domain = [
            ('account_id', '=', account_id),
            ('company_id', '=', company_id),
            ('date', '<', date_from),
        ]
        if partner_ids:
            domain.append(('partner_id', 'in', partner_ids))
        
        if include_unposted:
            domain.append(('move_id.state', 'in', ['posted', 'draft']))
        else:
            domain.append(('move_id.state', '=', 'posted'))

        read_group_res = self.env['account.move.line'].read_group(
            domain,
            ['debit', 'credit'],
            []
        )
        
        if not read_group_res:
            return 0.0
            
        balance = read_group_res[0]['debit'] - read_group_res[0]['credit']
        return balance if balance else 0.0
    
    @api.model
    def _get_account_moves(self, account_id, date_from, date_to, company_id,
                          partner_ids=None, show_partner_details=False,
                          show_analytic_details=False, centralize_journals=False,
                          include_unposted=False):
        """
        Obtiene los movimientos de una cuenta en el período especificado.
        """
        if centralize_journals:
            return self._get_centralized_moves(
                account_id, date_from, date_to, company_id,
                partner_ids, include_unposted
            )
        
        domain = [
            ('account_id', '=', account_id),
            ('company_id', '=', company_id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
        ]
        
        if include_unposted:
            domain.append(('move_id.state', 'in', ['posted', 'draft']))
        else:
            domain.append(('move_id.state', '=', 'posted'))

        if partner_ids:
            domain.append(('partner_id', 'in', partner_ids))

        fields_to_read = [
            'id', 'move_id', 'date', 'name', 'ref', 'debit', 'credit',
            'partner_id', 'analytic_distribution'
        ]
        
        order = 'partner_id, date, move_id' if show_partner_details else 'date, move_id'
        
        move_lines_data = self.env['account.move.line'].search_read(domain, fields_to_read, order=order)
        
        # Prefetch related data to avoid N+1 queries inside the loop
        if move_lines_data:
            move_ids = [rec['move_id'][0] for rec in move_lines_data if rec.get('move_id')]
            partner_ids = [rec['partner_id'][0] for rec in move_lines_data if rec.get('partner_id')]
            self.env['account.move'].browse(list(set(move_ids))).read(['name', 'journal_id'])
            self.env['res.partner'].browse(list(set(partner_ids))).read(['name'])

        # Post-procesamiento para campos relacionales y analíticos
        for line in move_lines_data:
            line['move_line_id'] = line.pop('id')
            move = self.env['account.move'].browse(line['move_id'][0]) if line.get('move_id') else None
            if move:
                line['move_name'] = move.name
                line['journal_code'] = move.journal_id.code
            else:
                line['move_name'] = ''
                line['journal_code'] = ''
            
            if show_partner_details and line.get('partner_id'):
                line['partner_name'] = line['partner_id'][1]
            
            if show_analytic_details and line.get('analytic_distribution'):
                analytic_names = []
                analytic_account_ids = [int(k) for k in line['analytic_distribution'].keys()]
                if analytic_account_ids:
                    # This can still be N+1 if analytic accounts are not cached.
                    # A more advanced prefetch would be needed for very large analytic distributions.
                    analytic_accounts = self.env['account.analytic.account'].browse(analytic_account_ids)
                    analytic_names = analytic_accounts.mapped('name')
                line['analytic_account_name'] = ', '.join(analytic_names)

        return move_lines_data
    
    @api.model
    def _get_centralized_moves(self, account_id, date_from, date_to, company_id,
                             partner_ids=None, include_unposted=False):
        """
        Obtiene movimientos centralizados por diario y mes.
        """
        domain = [
            ('account_id', '=', account_id),
            ('company_id', '=', company_id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
        ]
        
        if include_unposted:
            domain.append(('move_id.state', 'in', ['posted', 'draft']))
        else:
            domain.append(('move_id.state', '=', 'posted'))

        if partner_ids:
            domain.append(('partner_id', 'in', partner_ids))

        read_group_res = self.env['account.move.line'].read_group(
            domain,
            ['debit', 'credit', 'move_id'],
            ['date:month', 'journal_id']
        )
        
        moves = []
        for group in read_group_res:
            journal = self.env['account.journal'].browse(group['journal_id'][0])
            month_date = fields.Date.from_string(group['date:month'] + "-01")
            moves.append({
                'date': month_date,
                'journal_code': journal.code,
                'name': f"{journal.name} - {group['move_id_count']} movimientos",
                'ref': f"Centralizado {month_date.strftime('%B %Y')}",
                'debit': group['debit'],
                'credit': group['credit'],
            })
        
        return sorted(moves, key=lambda m: (m['date'], m['journal_code']))
    
    @api.model
    def export_to_excel(self, ledger_record):
        """
        Exporta el mayor analítico a Excel con formato profesional.
        """
        # Optimización: usar with_context para prefetch
        ledger_record = ledger_record.with_context(prefetch_fields=False)

        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})
        
        # Formatos
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#1f4788',
            'font_color': 'white',
            'border': 1,
            'align': 'center',
            'valign': 'vcenter'
        })
        
        title_format = workbook.add_format({
            'bold': True,
            'font_size': 16,
            'align': 'center'
        })
        
        subtitle_format = workbook.add_format({
            'bold': True,
            'font_size': 12,
            'align': 'left',
            'bg_color': '#e0e0e0'
        })
        
        date_format = workbook.add_format({
            'num_format': 'dd/mm/yyyy',
            'border': 1
        })
        
        number_format = workbook.add_format({
            'num_format': '#,##0.00',
            'border': 1
        })
        
        total_format = workbook.add_format({
            'bold': True,
            'num_format': '#,##0.00',
            'border': 1,
            'bg_color': '#f0f0f0'
        })
        
        initial_format = workbook.add_format({
            'italic': True,
            'border': 1,
            'bg_color': '#f5f5f5'
        })
        
        # Crear hoja
        worksheet = workbook.add_worksheet('Mayor Analítico')
        
        # Título
        worksheet.merge_range('A1:I1', 'MAYOR ANALÍTICO / GENERAL LEDGER', title_format)
        worksheet.merge_range('A2:I2', f'{ledger_record.company_id.name}', title_format)
        worksheet.merge_range('A3:I3', f'Período: {ledger_record.date_from} al {ledger_record.date_to}', title_format)
        
        # Headers
        headers = ['Fecha', 'Diario', 'Número', 'Descripción', 'Ref.', 
                  'Socio', 'Debe', 'Haber', 'Saldo']
        
        current_row = 5
        
        # Escribir por cuenta
        current_account = None
        for line in ledger_record.line_ids:
            # Nueva cuenta - escribir header de cuenta
            if line.account_id != current_account:
                if current_account:
                    current_row += 1  # Espacio entre cuentas
                
                current_account = line.account_id
                worksheet.merge_range(
                    current_row, 0, current_row, 8,
                    f'{line.account_code} - {line.account_name}',
                    subtitle_format
                )
                current_row += 1
                
                # Headers de columnas
                for col, header in enumerate(headers):
                    worksheet.write(current_row, col, header, header_format)
                current_row += 1
            
            # Escribir línea
            if line.line_type == 'initial':
                # Saldo inicial
                worksheet.write(current_row, 0, line.date, date_format)
                worksheet.merge_range(current_row, 1, current_row, 5, 
                                    'SALDO INICIAL', initial_format)
                worksheet.write(current_row, 6, '', initial_format)
                worksheet.write(current_row, 7, '', initial_format)
                worksheet.write(current_row, 8, line.cumulative_balance, number_format)
            
            elif line.line_type == 'move':
                # Movimiento normal
                worksheet.write(current_row, 0, line.date, date_format)
                worksheet.write(current_row, 1, line.journal_code or '')
                worksheet.write(current_row, 2, line.move_name or '')
                worksheet.write(current_row, 3, line.name)
                worksheet.write(current_row, 4, line.ref or '')
                worksheet.write(current_row, 5, line.partner_name or '')
                worksheet.write(current_row, 6, line.debit, number_format)
                worksheet.write(current_row, 7, line.credit, number_format)
                worksheet.write(current_row, 8, line.cumulative_balance, number_format)
            
            elif line.line_type == 'total':
                # Total de cuenta
                worksheet.merge_range(current_row, 0, current_row, 5,
                                    line.name, total_format)
                worksheet.write(current_row, 6, line.debit, total_format)
                worksheet.write(current_row, 7, line.credit, total_format)
                worksheet.write(current_row, 8, line.cumulative_balance, total_format)
            
            current_row += 1
        
        # Totales generales
        current_row += 2
        worksheet.merge_range(current_row, 0, current_row, 5,
                            'TOTALES GENERALES', header_format)
        worksheet.write(current_row, 6, ledger_record.total_debit, total_format)
        worksheet.write(current_row, 7, ledger_record.total_credit, total_format)
        worksheet.write(current_row, 8, ledger_record.total_balance, total_format)
        
        # Ajustar anchos de columna
        worksheet.set_column('A:A', 12)  # Fecha
        worksheet.set_column('B:B', 10)  # Diario
        worksheet.set_column('C:C', 15)  # Número
        worksheet.set_column('D:D', 40)  # Descripción
        worksheet.set_column('E:E', 15)  # Ref
        worksheet.set_column('F:F', 25)  # Socio
        worksheet.set_column('G:I', 15)  # Valores
        
        workbook.close()
        output.seek(0)
        
        # Crear attachment
        attachment = self.env['ir.attachment'].create({
            'name': f'Mayor_Analitico_{ledger_record.company_id.name}_{ledger_record.date_to}.xlsx',
            'type': 'binary',
            'datas': base64.b64encode(output.read()),
            'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'res_model': ledger_record._name,
            'res_id': ledger_record.id,
        })
        
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment.id}?download=true',
            'target': 'self',
        }