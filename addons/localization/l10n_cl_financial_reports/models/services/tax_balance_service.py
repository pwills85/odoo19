# -*- coding: utf-8 -*-
from odoo import models, api
from datetime import datetime
import logging
import base64
import io
import xlsxwriter
import json

_logger = logging.getLogger(__name__)


class TaxBalanceService(models.AbstractModel):
    """
    Service layer para el Balance Tributario.
    Maneja la lógica de cálculo de impuestos para declaraciones SII.
    """
    _name = 'account.tax.balance.service'
    _description = 'Servicio Balance Tributario'
    
    # Mapeo de códigos SII oficiales
    SII_CODE_MAPPING = {
        # F29 - IVA Débito Fiscal
        '502': 'Ventas Internas Afectas',
        '503': 'Ventas Internas Exentas',
        '519': 'Total Débito Fiscal',
        
        # F29 - IVA Crédito Fiscal
        '520': 'Total Crédito Fiscal',
        '521': 'Crédito Fiscal por Compras',
        '525': 'Crédito Fiscal Activo Fijo',
        
        # F29 - PPM
        '563': 'PPM Obligatorio',
        '115': 'PPM Voluntario',
        
        # F29 - Retenciones
        '48': 'Retención Honorarios 10%',
        '151': 'Retención 2da Categoría',
        
        # F22 - Base Imponible
        '628': 'Base Imponible Primera Categoría',
        '629': 'Pérdida Tributaria',
        '630': 'Gratificaciones',
        '631': 'Gastos Rechazados',
        
        # F22 - Impuesto Primera Categoría
        '30': 'Impuesto Primera Categoría',
        '304': 'PPM Acreditado',
        '31': 'Impuesto a Pagar',
    }
    
    @api.model
    def compute_tax_balance(self, date_from, date_to, company_id, 
                          declaration_type='f29', include_draft_moves=False):
        """
        Método principal para calcular el balance tributario.
        Optimizado para cumplir con los requerimientos SII.
        """
        start_time = datetime.now()
        
        # Obtener movimientos con impuestos
        tax_data, sii_codes_dict = self._get_tax_movements(
            date_from, date_to, company_id, include_draft_moves
        )
        
        # Añadir Impuesto Único de Nómina
        sii_codes_dict = self._add_payroll_tax(
            sii_codes_dict, date_from, date_to, company_id, include_draft_moves
        )
        
        # Procesar líneas detalladas
        lines = []
        
        # TODO: Refactorizar para usar browse en batch fuera del loop
        for tax_info in tax_data:
            # Process tax data (placeholder - to be implemented)
            lines.append(tax_info)
            
        # Agregar códigos SII calculados
        if declaration_type == 'f29':
            self._add_calculated_sii_codes_f29(sii_codes_dict)
        elif declaration_type == 'f22':
            self._add_calculated_sii_codes_f22(sii_codes_dict)
        
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        return {
            'lines': lines,
            'sii_codes': list(sii_codes_dict.values()),
            'processing_time': processing_time,
            'line_count': len(lines)
        }

    @api.model
    def _add_payroll_tax(self, sii_codes_dict, date_from, date_to, company_id, include_draft_moves):
        """Añade el Impuesto Único de Segunda Categoría desde la cuenta de nómina."""
        company = self.env['res.company'].browse(company_id)
        tax_account = company.l10n_cl_payroll_tax_account_id
        
        if not tax_account:
            return sii_codes_dict # No hacer nada si no está configurado

        domain = [
            ('account_id', '=', tax_account.id),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
            ('company_id', '=', company_id),
        ]
        if not include_draft_moves:
            domain.append(('parent_state', '=', 'posted'))

        # Usar read_group para obtener el saldo de la cuenta
        read_group_res = self.env['account.move.line'].read_group(
            domain,
            ['balance:sum'],
            []
        )
        
        if read_group_res and read_group_res[0]['balance']:
            # El saldo será negativo (pasivo), lo necesitamos en positivo
            tax_amount = -read_group_res[0]['balance']
            
            # Código SII para Retención de 2da Categoría
            sii_code = '151' 
            
            if sii_code not in sii_codes_dict:
                sii_codes_dict[sii_code] = {
                    'code': sii_code,
                    'name': self.SII_CODE_MAPPING.get(sii_code, 'Ret. Imp. 2da Cat.'),
                    'amount': 0.0,
                    'base_amount': 0.0,
                    'line_count': 0
                }
            
            sii_codes_dict[sii_code]['amount'] += tax_amount
            sii_codes_dict[sii_code]['line_count'] += 1 # Representa una línea consolidada

        return sii_codes_dict
    
    @api.model
    def _get_tax_movements(self, date_from, date_to, company_id, include_draft_moves=False):
        """
        Obtiene los movimientos con impuestos del período.
        """
        query = """
            WITH tax_moves AS (
                SELECT 
                    at.id as tax_id,
                    at.name as tax_name,
                    at.type_tax_use as tax_type,
                    at.l10n_cl_sii_code as sii_code,
                    aml.account_id,
                    SUM(aml.balance) as tax_amount,
                    SUM(COALESCE(aml_base.balance, 0)) as base_amount,
                    COUNT(DISTINCT am.partner_id) as partner_count,
                    COUNT(DISTINCT am.id) as invoice_count
                FROM 
                    account_move_line aml
                    INNER JOIN account_move am ON aml.move_id = am.id
                    INNER JOIN account_tax at ON at.id = ANY(aml.tax_ids)
                    LEFT JOIN account_move_line aml_base ON (
                        aml_base.move_id = aml.move_id 
                        AND aml_base.tax_line_id IS NULL
                        AND aml_base.tax_ids && aml.tax_ids
                    )
                WHERE 
                    WHERE 
            am.company_id = %(company_id)s
            AND am.date >= %(date_from)s
            AND am.date <= %(date_to)s
            AND aml.tax_line_id = at.id
            AND am.state = 'posted'
            AND am.move_type IN ('out_invoice', 'out_refund', 'in_invoice', 'in_refund')
            AND (am.move_type != 'in_invoice' OR am.l10n_cl_dte_credit_usable = TRUE)
        GROUP BY 
            at.id, at.name, at.type_tax_use, at.l10n_cl_sii_code, aml.account_id
    )
    SELECT * FROM tax_moves
    ORDER BY tax_type DESC, sii_code, tax_name
        """
        
        params = {
            'company_id': company_id,
            'date_from': date_from,
            'date_to': date_to,
            'state': 'posted' if not include_draft_moves else 'draft',
        }
        
        if include_draft_moves:
            query = query.replace("AND am.state = %(state)s", "AND am.state IN ('posted', 'draft')")
        
        self.env.self.env.cr.execute(query, params)
        
        return self.env.cr.dictfetchall()
    
    @api.model
    def _add_calculated_sii_codes_f29(self, sii_codes_dict):
        """
        Agrega códigos SII calculados para F29.
        """
        # Calcular total débito fiscal (519)
        debito_codes = ['502', '503']  # Ventas afectas y exentas
        total_debito = sum(sii_codes_dict.get(c, {}).get('amount', 0) for c in debito_codes)
        
        if total_debito > 0 and '519' not in sii_codes_dict:
            sii_codes_dict['519'] = {
                'code': '519',
                'name': 'Total Débito Fiscal',
                'amount': total_debito,
                'base_amount': 0.0,
                'line_count': 0
            }
        
        # Calcular total crédito fiscal (520)
        credito_codes = ['521', '525']  # Compras y activo fijo
        total_credito = sum(sii_codes_dict.get(c, {}).get('amount', 0) for c in credito_codes)
        
        if total_credito > 0 and '520' not in sii_codes_dict:
            sii_codes_dict['520'] = {
                'code': '520',
                'name': 'Total Crédito Fiscal',
                'amount': total_credito,
                'base_amount': 0.0,
                'line_count': 0
            }
    
    @api.model
    def _add_calculated_sii_codes_f22(self, sii_codes_dict):
        """
        Agrega códigos SII calculados para F22.
        """
        # Implementar cálculos específicos de renta anual
        pass
    
    @api.model
    def export_f29_format(self, balance_record):
        """
        Exporta el balance en formato F29 para carga en SII.
        """
        # Optimización: usar with_context para prefetch
        balance_record = balance_record.with_context(prefetch_fields=False)

        # Preparar datos en formato JSON para F29
        f29_data = {
            'rut_contribuyente': balance_record.company_id.vat,
            'periodo': balance_record.date_to.strftime('%Y%m'),
            'formulario': 'F29',
            'valores': {}
        }
        
        # Mapear códigos SII a valores
        for code in balance_record.sii_code_ids:
            f29_data['valores'][code.code] = int(abs(code.amount))
        
        # Agregar campos calculados
        f29_data['valores']['89'] = int(balance_record.total_a_pagar)  # Total a pagar
        
        # Crear archivo JSON
        json_content = json.dumps(f29_data, indent=2, ensure_ascii=False)
        
        # Crear attachment
        attachment = self.env['ir.attachment'].create({
            'name': f'F29_{balance_record.company_id.vat}_{balance_record.date_to.strftime("%Y%m")}.json',
            'type': 'binary',
            'datas': base64.b64encode(json_content.encode('utf-8')),
            'mimetype': 'application/json',
            'res_model': balance_record._name,
            'res_id': balance_record.id,
        })
        
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment.id}?download=true',
            'target': 'self',
        }
    
    @api.model
    def export_to_excel(self, balance_record):
        """
        Exporta el balance tributario a Excel con formato profesional.
        """
        # Optimización: usar with_context para prefetch
        balance_record = balance_record.with_context(prefetch_fields=False)

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
            'bg_color': '#e0e0e0'
        })
        
        number_format = workbook.add_format({
            'num_format': '#,##0',
            'border': 1
        })
        
        total_format = workbook.add_format({
            'bold': True,
            'num_format': '#,##0',
            'border': 1,
            'bg_color': '#f0f0f0'
        })
        
        # Hoja principal
        worksheet = workbook.add_worksheet('Balance Tributario')
        
        # Título
        type_name = dict(balance_record._fields['declaration_type'].selection).get(
            balance_record.declaration_type, ''
        )
        worksheet.merge_range('A1:H1', f'BALANCE TRIBUTARIO - {type_name}', title_format)
        worksheet.merge_range('A2:H2', balance_record.company_id.name, title_format)
        worksheet.merge_range('A3:H3', f'RUT: {balance_record.company_id.vat}', title_format)
        worksheet.merge_range('A4:H4', 
                            f'Período: {balance_record.date_from} al {balance_record.date_to}', 
                            title_format)
        
        # Resumen por Código SII
        row = 6
        worksheet.merge_range(row, 0, row, 7, 'RESUMEN POR CÓDIGO SII', subtitle_format)
        row += 1
        
        headers = ['Código', 'Descripción', 'Base Imponible', 'Monto']
        for col, header in enumerate(headers):
            worksheet.write(row, col, header, header_format)
        row += 1
        
        # Datos por código SII
        for code in balance_record.sii_code_ids:
            worksheet.write(row, 0, code.code)
            worksheet.write(row, 1, code.name)
            worksheet.write(row, 2, code.base_amount, number_format)
            worksheet.write(row, 3, code.amount, number_format)
            row += 1
        
        # Totales principales
        row += 2
        worksheet.merge_range(row, 0, row, 7, 'RESUMEN TRIBUTARIO', subtitle_format)
        row += 1
        
        summary_data = [
            ('IVA Débito Fiscal', balance_record.iva_debito_fiscal),
            ('IVA Crédito Fiscal', balance_record.iva_credito_fiscal),
            ('IVA a Pagar', balance_record.iva_a_pagar),
            ('Remanente Crédito Fiscal', balance_record.remanente_credito_fiscal),
            ('PPM Obligatorio', balance_record.ppm_obligatorio),
            ('PPM Voluntario', balance_record.ppm_voluntario),
            ('Retención Honorarios', balance_record.retencion_honorarios),
            ('Retención 2da Categoría', balance_record.retencion_segunda_categoria),
            ('TOTAL A PAGAR', balance_record.total_a_pagar),
        ]
        
        for desc, amount in summary_data:
            if desc == 'TOTAL A PAGAR':
                worksheet.write(row, 0, desc, total_format)
                worksheet.write(row, 3, amount, total_format)
            else:
                worksheet.write(row, 0, desc)
                worksheet.write(row, 3, amount, number_format)
            row += 1
        
        # Detalle por impuesto
        worksheet2 = workbook.add_worksheet('Detalle por Impuesto')
        
        worksheet2.merge_range('A1:I1', 'DETALLE POR IMPUESTO', title_format)
        
        row = 3
        headers2 = ['Impuesto', 'Tipo', 'Código SII', 'Base Imponible', 
                   'Monto Impuesto', 'Total', 'Cuenta', 'Nº Documentos', 'Nº Socios']
        
        for col, header in enumerate(headers2):
            worksheet2.write(row, col, header, header_format)
        row += 1
        
        # Datos detallados
        for line in balance_record.line_ids:
            worksheet2.write(row, 0, line.tax_name)
            worksheet2.write(row, 1, dict(line._fields['tax_type'].selection).get(line.tax_type, ''))
            worksheet2.write(row, 2, line.sii_code or '')
            worksheet2.write(row, 3, line.base_amount, number_format)
            worksheet2.write(row, 4, line.tax_amount, number_format)
            worksheet2.write(row, 5, line.total_amount, number_format)
            worksheet2.write(row, 6, line.account_id.code if line.account_id else '')
            worksheet2.write(row, 7, line.invoice_count)
            worksheet2.write(row, 8, line.partner_count)
            row += 1
        
        # Ajustar anchos de columna
        worksheet.set_column('A:A', 15)
        worksheet.set_column('B:B', 40)
        worksheet.set_column('C:H', 20)
        
        worksheet2.set_column('A:A', 30)
        worksheet2.set_column('B:B', 15)
        worksheet2.set_column('C:C', 15)
        worksheet2.set_column('D:F', 20)
        worksheet2.set_column('G:G', 15)
        worksheet2.set_column('H:I', 15)
        
        workbook.close()
        output.seek(0)
        
        # Crear attachment
        attachment = self.env['ir.attachment'].create({
            'name': f'Balance_Tributario_{balance_record.company_id.vat}_{balance_record.date_to}.xlsx',
            'type': 'binary',
            'datas': base64.b64encode(output.read()),
            'mimetype': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'res_model': balance_record._name,
            'res_id': balance_record.id,
        })
        
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment.id}?download=true',
            'target': 'self',
        }