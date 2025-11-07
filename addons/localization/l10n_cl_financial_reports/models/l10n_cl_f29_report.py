# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from dateutil.relativedelta import relativedelta
import logging

_logger = logging.getLogger(__name__)


class L10nClF29Report(models.Model):
    """
    Reporte F29 - Formulario de Declaración Mensual de IVA
    Hereda de account.report para integrarse con el framework de reportes de Odoo 18
    
    Este modelo proporciona la estructura y lógica para generar el reporte F29
    utilizando el sistema nativo de reportes de Odoo 18 CE.
    """
    _name = 'l10n_cl.f29.report'
    _description = 'Reporte F29 - Declaración Mensual IVA'
    _inherit = 'account.report'
    _auto = False
    
    # ========== CONFIGURACIÓN DEL REPORTE ==========
    filter_date = {'mode': 'range', 'filter': 'this_month'}
    filter_company = True
    # filter_multi_company = 'selector'  # No soportado en Odoo 18 CE
    # filter_hierarchy = False  # No soportado en Odoo 18 CE
    # filter_unfold_all = False  # No soportado en Odoo 18 CE
    
    # ========== MÉTODOS PRINCIPALES DEL REPORTE ==========
    
    @api.model
    def _get_report_name(self):
        """Retorna el nombre del reporte"""
        return _('Formulario 29 - Declaración Mensual de IVA')
    
    @api.model
    def _get_templates(self):
        """Define las plantillas a usar"""
        templates = super()._get_templates()
        templates['main_template'] = 'l10n_cl_financial_reports.f29_report_template'
        return templates
    
    def _get_columns(self, options):
        """
        Define las columnas del reporte F29
        
        Estructura:
        - Código: Código SII del concepto
        - Glosa: Descripción del concepto
        - Monto: Valor monetario
        """
        return [
            {'name': _('Código'), 'class': 'text-left', 'style': 'width: 15%'},
            {'name': _('Glosa'), 'class': 'text-left', 'style': 'width: 60%'},
            {'name': _('Monto'), 'class': 'number', 'style': 'width: 25%'},
        ]
    
    def _get_lines(self, options, line_id=None):
        """
        Genera las líneas del reporte F29 con los códigos SII correspondientes
        
        Los códigos están organizados según la estructura oficial del F29:
        - Débito Fiscal (Ventas)
        - Crédito Fiscal (Compras)
        - Ajustes y Remanentes
        - Determinación del impuesto
        """
        lines = []
        
        # Obtener datos del F29 si existe
        f29_data = self._get_f29_data(options)
        
        # Obtener formato de moneda
        company = self.env.company
        currency = company.currency_id
        
        def format_value(amount):
            """Formatea valores monetarios"""
            return self.format_value(amount, currency=currency)
        
        # ========== SECCIÓN 1: DÉBITO FISCAL (VENTAS) ==========
        lines.append({
            'id': 'debito_fiscal',
            'name': _('DÉBITO FISCAL'),
            'level': 1,
            'columns': [
                {'name': ''},
                {'name': ''},
                {'name': ''},
            ],
            'unfoldable': False,
            'unfolded': True,
            'class': 'total',
        })
        
        # Código 503: Ventas y servicios gravados
        lines.append({
            'id': 'codigo_503',
            'parent_id': 'debito_fiscal',
            'name': '503',
            'level': 2,
            'columns': [
                {'name': '503'},
                {'name': _('Ventas y/o Servicios prestados del giro (Neto)')},
                {'name': format_value(f29_data.get('ventas_gravadas', 0.0))},
            ],
        })
        
        # Código 502: Ventas exentas
        lines.append({
            'id': 'codigo_502',
            'parent_id': 'debito_fiscal',
            'name': '502',
            'level': 2,
            'columns': [
                {'name': '502'},
                {'name': _('Ventas y/o Servicios exentos')},
                {'name': format_value(f29_data.get('ventas_exentas', 0.0))},
            ],
        })
        
        # Código 142: Total débito fiscal
        lines.append({
            'id': 'codigo_142',
            'parent_id': 'debito_fiscal',
            'name': '142',
            'level': 2,
            'columns': [
                {'name': '142'},
                {'name': _('Débito Fiscal')},
                {'name': format_value(f29_data.get('iva_debito', 0.0))},
            ],
            'class': 'o_account_reports_totals_below_sections',
        })
        
        # ========== SECCIÓN 2: CRÉDITO FISCAL (COMPRAS) ==========
        lines.append({
            'id': 'credito_fiscal',
            'name': _('CRÉDITO FISCAL'),
            'level': 1,
            'columns': [
                {'name': ''},
                {'name': ''},
                {'name': ''},
            ],
            'unfoldable': False,
            'unfolded': True,
            'class': 'total',
        })
        
        # Código 519: Compras gravadas internas
        lines.append({
            'id': 'codigo_519',
            'parent_id': 'credito_fiscal',
            'name': '519',
            'level': 2,
            'columns': [
                {'name': '519'},
                {'name': _('Compras del giro con derecho a Crédito Fiscal (Neto)')},
                {'name': format_value(f29_data.get('compras_gravadas', 0.0))},
            ],
        })
        
        # Código 520: Compras exentas
        lines.append({
            'id': 'codigo_520',
            'parent_id': 'credito_fiscal',
            'name': '520',
            'level': 2,
            'columns': [
                {'name': '520'},
                {'name': _('Compras exentas del giro')},
                {'name': format_value(f29_data.get('compras_exentas', 0.0))},
            ],
        })
        
        # Código 525: Total crédito fiscal por compras
        lines.append({
            'id': 'codigo_525',
            'parent_id': 'credito_fiscal',
            'name': '525',
            'level': 2,
            'columns': [
                {'name': '525'},
                {'name': _('Crédito Fiscal por compras del giro')},
                {'name': format_value(f29_data.get('iva_credito', 0.0))},
            ],
            'class': 'o_account_reports_totals_below_sections',
        })
        
        # ========== SECCIÓN 3: AJUSTES Y REMANENTES ==========
        lines.append({
            'id': 'ajustes',
            'name': _('AJUSTES Y REMANENTES'),
            'level': 1,
            'columns': [
                {'name': ''},
                {'name': ''},
                {'name': ''},
            ],
            'unfoldable': False,
            'unfolded': True,
            'class': 'total',
        })
        
        # Código 504: Remanente crédito fiscal mes anterior
        lines.append({
            'id': 'codigo_504',
            'parent_id': 'ajustes',
            'name': '504',
            'level': 2,
            'columns': [
                {'name': '504'},
                {'name': _('Remanente Crédito Fiscal mes anterior')},
                {'name': format_value(f29_data.get('remanente_anterior', 0.0))},
            ],
        })
        
        # Si hay ajustes manuales, mostrarlos
        if f29_data.get('ajuste_debito', 0.0) != 0:
            lines.append({
                'id': 'ajuste_debito',
                'parent_id': 'ajustes',
                'name': 'AJ+',
                'level': 2,
                'columns': [
                    {'name': 'AJ+'},
                    {'name': _('Ajuste al Débito Fiscal')},
                    {'name': format_value(f29_data.get('ajuste_debito', 0.0))},
                ],
            })
        
        if f29_data.get('ajuste_credito', 0.0) != 0:
            lines.append({
                'id': 'ajuste_credito',
                'parent_id': 'ajustes',
                'name': 'AJ-',
                'level': 2,
                'columns': [
                    {'name': 'AJ-'},
                    {'name': _('Ajuste al Crédito Fiscal')},
                    {'name': format_value(f29_data.get('ajuste_credito', 0.0))},
                ],
            })
        
        # ========== SECCIÓN 4: DETERMINACIÓN DEL IMPUESTO ==========
        lines.append({
            'id': 'determinacion',
            'name': _('DETERMINACIÓN DEL IMPUESTO'),
            'level': 1,
            'columns': [
                {'name': ''},
                {'name': ''},
                {'name': ''},
            ],
            'unfoldable': False,
            'unfolded': True,
            'class': 'total',
        })
        
        # Código 537: Total a pagar
        total_debito = f29_data.get('total_debito', 0.0)
        total_credito = f29_data.get('total_credito', 0.0)
        
        lines.append({
            'id': 'codigo_537',
            'parent_id': 'determinacion',
            'name': '537',
            'level': 2,
            'columns': [
                {'name': '537'},
                {'name': _('Total Débito Fiscal')},
                {'name': format_value(total_debito)},
            ],
        })
        
        lines.append({
            'id': 'codigo_538',
            'parent_id': 'determinacion',
            'name': '538',
            'level': 2,
            'columns': [
                {'name': '538'},
                {'name': _('Total Crédito Fiscal')},
                {'name': format_value(total_credito)},
            ],
        })
        
        # Código 547: IVA determinado (a pagar)
        if f29_data.get('iva_a_pagar', 0.0) > 0:
            lines.append({
                'id': 'codigo_547',
                'parent_id': 'determinacion',
                'name': '547',
                'level': 2,
                'columns': [
                    {'name': '547'},
                    {'name': _('IVA Determinado (a pagar)')},
                    {'name': format_value(f29_data.get('iva_a_pagar', 0.0))},
                ],
                'class': 'o_account_reports_totals_below_sections total',
            })
        
        # Código 548: Remanente para período siguiente
        if f29_data.get('remanente_siguiente', 0.0) > 0:
            lines.append({
                'id': 'codigo_548',
                'parent_id': 'determinacion',
                'name': '548',
                'level': 2,
                'columns': [
                    {'name': '548'},
                    {'name': _('Remanente Crédito Fiscal para período siguiente')},
                    {'name': format_value(f29_data.get('remanente_siguiente', 0.0))},
                ],
                'class': 'o_account_reports_totals_below_sections',
            })
        
        # ========== SECCIÓN 5: INFORMACIÓN ADICIONAL ==========
        if f29_data.get('f29_id'):
            lines.append({
                'id': 'info_adicional',
                'name': _('INFORMACIÓN ADICIONAL'),
                'level': 1,
                'columns': [
                    {'name': ''},
                    {'name': ''},
                    {'name': ''},
                ],
                'unfoldable': False,
                'unfolded': True,
                'class': 'total',
            })
            
            # Período
            lines.append({
                'id': 'periodo',
                'parent_id': 'info_adicional',
                'name': '',
                'level': 2,
                'columns': [
                    {'name': ''},
                    {'name': _('Período')},
                    {'name': f29_data.get('period_string', '')},
                ],
            })
            
            # Estado
            lines.append({
                'id': 'estado',
                'parent_id': 'info_adicional',
                'name': '',
                'level': 2,
                'columns': [
                    {'name': ''},
                    {'name': _('Estado')},
                    {'name': f29_data.get('state_display', '')},
                ],
            })
            
            # Folio SII
            if f29_data.get('folio'):
                lines.append({
                    'id': 'folio',
                    'parent_id': 'info_adicional',
                    'name': '',
                    'level': 2,
                    'columns': [
                        {'name': ''},
                        {'name': _('Folio SII')},
                        {'name': f29_data.get('folio', '')},
                    ],
                })
        
        return lines
    
    def _get_f29_data(self, options):
        """
        Obtiene los datos del F29 para el período seleccionado
        
        Busca un registro de l10n_cl.f29 existente o calcula los valores
        desde los movimientos contables.
        """
        # Obtener fechas del período
        date_from = fields.Date.from_string(options['date']['date_from'])
        date_to = fields.Date.from_string(options['date']['date_to'])
        
        # Ajustar al primer día del mes para buscar F29
        period_date = date_from.replace(day=1)
        
        # Obtener compañía
        company_id = self._get_company_id(options)
        company = self.env['res.company'].browse(company_id)
        
        # Buscar F29 existente
        f29 = self.env['l10n_cl.f29'].search([
            ('company_id', '=', company_id),
            ('period_date', '=', period_date),
            ('state', '!=', 'replaced')
        ], limit=1)
        
        if f29:
            # Usar datos del F29 existente
            state_display = dict(f29._fields['state'].selection).get(f29.state, f29.state)
            
            return {
                'f29_id': f29.id,
                'period_string': f29.period_string,
                'state': f29.state,
                'state_display': state_display,
                'folio': f29.folio,
                'ventas_gravadas': f29.ventas_gravadas,
                'ventas_exentas': f29.ventas_exentas,
                'compras_gravadas': f29.compras_gravadas,
                'compras_exentas': f29.compras_exentas,
                'iva_debito': f29.iva_debito,
                'iva_credito': f29.iva_credito,
                'ajuste_debito': f29.ajuste_debito,
                'ajuste_credito': f29.ajuste_credito,
                'remanente_anterior': f29.remanente_anterior,
                'total_debito': f29.total_debito,
                'total_credito': f29.total_credito,
                'iva_a_pagar': f29.iva_a_pagar,
                'remanente_siguiente': f29.remanente_siguiente,
            }
        else:
            # Calcular datos desde movimientos contables
            return self._calculate_f29_data(company, date_from, date_to)
    
    def _calculate_f29_data(self, company, date_from, date_to):
        """
        Calcula los datos del F29 desde los movimientos contables
        cuando no existe un registro F29 guardado
        """
        # Usar el servicio de integración SII si está disponible
        try:
            sii_service = self.env['account.financial.report.sii.integration.service']
            f29_data = sii_service.generate_f29_data(company, date_from, date_to)
            data = f29_data.get('data', {})
        except:
            # Fallback: cálculo básico
            data = self._calculate_basic_f29_data(company, date_from, date_to)
        
        # Buscar remanente anterior
        previous_date = date_from - relativedelta(months=1, day=1)
        previous_f29 = self.env['l10n_cl.f29'].search([
            ('company_id', '=', company.id),
            ('period_date', '=', previous_date),
            ('state', 'in', ['validated', 'sent', 'accepted'])
        ], limit=1)
        
        remanente_anterior = previous_f29.remanente_siguiente if previous_f29 else 0.0
        
        # Calcular totales
        total_debito = data.get('iva_debito', 0.0)
        total_credito = data.get('iva_credito', 0.0) + remanente_anterior
        
        diferencia = total_debito - total_credito
        iva_a_pagar = diferencia if diferencia > 0 else 0.0
        remanente_siguiente = abs(diferencia) if diferencia < 0 else 0.0
        
        return {
            'f29_id': False,
            'period_string': date_from.strftime('%Y-%m'),
            'state': 'draft',
            'state_display': _('Borrador'),
            'folio': '',
            'ventas_gravadas': data.get('ventas_gravadas', 0.0),
            'ventas_exentas': data.get('ventas_exentas', 0.0),
            'compras_gravadas': data.get('compras_gravadas', 0.0),
            'compras_exentas': data.get('compras_exentas', 0.0),
            'iva_debito': data.get('iva_debito', 0.0),
            'iva_credito': data.get('iva_credito', 0.0),
            'ajuste_debito': 0.0,
            'ajuste_credito': 0.0,
            'remanente_anterior': remanente_anterior,
            'total_debito': total_debito,
            'total_credito': total_credito,
            'iva_a_pagar': iva_a_pagar,
            'remanente_siguiente': remanente_siguiente,
        }
    
    def _calculate_basic_f29_data(self, company, date_from, date_to):
        """
        Cálculo básico de datos F29 desde account.move.line
        """
        # Dominios base
        base_domain = [
            ('company_id', '=', company.id),
            ('parent_state', '=', 'posted'),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
        ]
        
        # Buscar líneas de IVA
        tax_lines = self.env['account.move.line'].search(base_domain + [
            ('tax_line_id', '!=', False),
            ('tax_line_id.type_tax_use', 'in', ['sale', 'purchase']),
        ])
        
        data = {
            'ventas_gravadas': 0.0,
            'ventas_exentas': 0.0,
            'compras_gravadas': 0.0,
            'compras_exentas': 0.0,
            'iva_debito': 0.0,
            'iva_credito': 0.0,
        }
        
        for line in tax_lines:
            tax = line.tax_line_id
            if tax.type_tax_use == 'sale':
                if tax.amount > 0:
                    data['iva_debito'] += abs(line.balance)
                    # Estimar base gravada (asumiendo 19% IVA)
                    data['ventas_gravadas'] += abs(line.balance) / 0.19
            elif tax.type_tax_use == 'purchase':
                if tax.amount > 0:
                    data['iva_credito'] += abs(line.balance)
                    # Estimar base gravada (asumiendo 19% IVA)
                    data['compras_gravadas'] += abs(line.balance) / 0.19
        
        return data
    
    def _get_company_id(self, options):
        """Obtiene el ID de la compañía desde las opciones"""
        return options.get('company_id') or self.env.company.id
    
    @api.model
    def action_create_f29(self, options):
        """
        Acción para crear un registro F29 desde el reporte
        """
        # Obtener datos del período
        date_from = fields.Date.from_string(options['date']['date_from'])
        period_date = date_from.replace(day=1)
        company_id = self._get_company_id(options)
        
        # Verificar si ya existe
        existing = self.env['l10n_cl.f29'].search([
            ('company_id', '=', company_id),
            ('period_date', '=', period_date),
            ('state', '!=', 'replaced')
        ], limit=1)
        
        if existing:
            # Abrir el F29 existente
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'l10n_cl.f29',
                'res_id': existing.id,
                'view_mode': 'form',
                'target': 'current',
            }
        else:
            # Crear nuevo F29
            f29 = self.env['l10n_cl.f29'].create({
                'company_id': company_id,
                'period_date': period_date,
            })
            
            # Calcular valores
            f29.action_calculate()
            
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'l10n_cl.f29',
                'res_id': f29.id,
                'view_mode': 'form',
                'target': 'current',
            }