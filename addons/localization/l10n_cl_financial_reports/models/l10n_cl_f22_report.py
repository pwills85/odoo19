# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)


class L10nClF22Report(models.Model):
    """
    Reporte F22 - Formulario de Declaración Anual de Impuesto a la Renta
    Hereda de account.report para integrarse con el framework de reportes de Odoo 18
    
    Este modelo proporciona la estructura y lógica para generar el reporte F22
    utilizando el sistema nativo de reportes de Odoo 18 CE.
    """
    _name = 'l10n_cl.f22.report'
    _description = 'Reporte F22 - Declaración Anual de Impuesto a la Renta'
    _inherit = 'account.report'
    _auto = False
    
    # ========== CONFIGURACIÓN DEL REPORTE ==========
    filter_date = {'mode': 'range', 'filter': 'this_year'}
    filter_company = True
    # filter_multi_company = 'selector'  # No soportado en Odoo 18 CE
    # filter_hierarchy = False  # No soportado en Odoo 18 CE
    # filter_unfold_all = False  # No soportado en Odoo 18 CE
    
    # ========== MÉTODOS PRINCIPALES DEL REPORTE ==========
    
    @api.model
    def _get_report_name(self):
        """Retorna el nombre del reporte"""
        return _('Formulario 22 - Declaración Anual de Impuesto a la Renta')
    
    @api.model
    def _get_templates(self):
        """Define las plantillas a usar"""
        templates = super()._get_templates()
        templates['main_template'] = 'l10n_cl_financial_reports.f22_report_template'
        return templates
    
    def _get_columns(self, options):
        """
        Define las columnas del reporte F22
        
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
        Genera las líneas del reporte F22 con los códigos SII correspondientes
        
        Los códigos están organizados según la estructura oficial del F22:
        - Ingresos del giro
        - Costos y gastos
        - Base imponible
        - Impuesto determinado
        """
        lines = []
        
        # Obtener datos del F22 si existe
        f22_data = self._get_f22_data(options)
        
        # Obtener formato de moneda
        company = self.env.company
        currency = company.currency_id
        
        def format_value(amount):
            """Formatea valores monetarios"""
            return self.format_value(amount, currency=currency)
        
        # ========== SECCIÓN 1: INGRESOS DEL GIRO ==========
        lines.append({
            'id': 'ingresos',
            'name': _('INGRESOS DEL GIRO'),
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
        
        # Código 628: Ingresos del giro percibidos o devengados
        lines.append({
            'id': 'codigo_628',
            'parent_id': 'ingresos',
            'name': '628',
            'level': 2,
            'columns': [
                {'name': '628'},
                {'name': _('Ingresos del giro percibidos o devengados')},
                {'name': format_value(f22_data.get('ingresos_operacionales', 0.0))},
            ],
        })
        
        # Código 851: Ingresos no constitutivos de renta
        lines.append({
            'id': 'codigo_851',
            'parent_id': 'ingresos',
            'name': '851',
            'level': 2,
            'columns': [
                {'name': '851'},
                {'name': _('Ingresos no constitutivos de renta')},
                {'name': format_value(f22_data.get('ingresos_no_renta', 0.0))},
            ],
        })
        
        # Código 629: Total ingresos
        lines.append({
            'id': 'codigo_629',
            'parent_id': 'ingresos',
            'name': '629',
            'level': 2,
            'columns': [
                {'name': '629'},
                {'name': _('Total Ingresos')},
                {'name': format_value(f22_data.get('ingresos_totales', 0.0))},
            ],
            'class': 'o_account_reports_totals_below_sections',
        })
        
        # ========== SECCIÓN 2: COSTOS Y GASTOS ==========
        lines.append({
            'id': 'costos_gastos',
            'name': _('COSTOS Y GASTOS'),
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
        
        # Código 630: Costo directo de bienes y servicios
        lines.append({
            'id': 'codigo_630',
            'parent_id': 'costos_gastos',
            'name': '630',
            'level': 2,
            'columns': [
                {'name': '630'},
                {'name': _('Costo directo de bienes y servicios del giro')},
                {'name': format_value(f22_data.get('costos_directos', 0.0))},
            ],
        })
        
        # Código 631: Remuneraciones y otros gastos del personal
        lines.append({
            'id': 'codigo_631',
            'parent_id': 'costos_gastos',
            'name': '631',
            'level': 2,
            'columns': [
                {'name': '631'},
                {'name': _('Remuneraciones y otros gastos del personal')},
                {'name': format_value(f22_data.get('gastos_personal', 0.0))},
            ],
        })
        
        # Código 633: Depreciación
        lines.append({
            'id': 'codigo_633',
            'parent_id': 'costos_gastos',
            'name': '633',
            'level': 2,
            'columns': [
                {'name': '633'},
                {'name': _('Depreciación')},
                {'name': format_value(f22_data.get('depreciacion', 0.0))},
            ],
        })
        
        # Código 635: Gastos financieros
        lines.append({
            'id': 'codigo_635',
            'parent_id': 'costos_gastos',
            'name': '635',
            'level': 2,
            'columns': [
                {'name': '635'},
                {'name': _('Gastos financieros')},
                {'name': format_value(f22_data.get('gastos_financieros', 0.0))},
            ],
        })
        
        # Código 636: Otros gastos deducibles
        lines.append({
            'id': 'codigo_636',
            'parent_id': 'costos_gastos',
            'name': '636',
            'level': 2,
            'columns': [
                {'name': '636'},
                {'name': _('Otros gastos deducibles')},
                {'name': format_value(f22_data.get('otros_gastos', 0.0))},
            ],
        })
        
        # Código 637: Total costos y gastos
        lines.append({
            'id': 'codigo_637',
            'parent_id': 'costos_gastos',
            'name': '637',
            'level': 2,
            'columns': [
                {'name': '637'},
                {'name': _('Total Costos y Gastos')},
                {'name': format_value(f22_data.get('gastos_totales', 0.0))},
            ],
            'class': 'o_account_reports_totals_below_sections',
        })
        
        # ========== SECCIÓN 3: RENTA LÍQUIDA ==========
        lines.append({
            'id': 'renta_liquida',
            'name': _('RENTA LÍQUIDA'),
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
        
        # Código 638: Renta líquida (o pérdida tributaria)
        lines.append({
            'id': 'codigo_638',
            'parent_id': 'renta_liquida',
            'name': '638',
            'level': 2,
            'columns': [
                {'name': '638'},
                {'name': _('Renta líquida (o pérdida tributaria)')},
                {'name': format_value(f22_data.get('resultado_antes_impuesto', 0.0))},
            ],
        })
        
        # ========== SECCIÓN 4: CORRECCIÓN MONETARIA Y AJUSTES ==========
        lines.append({
            'id': 'ajustes',
            'name': _('CORRECCIÓN MONETARIA Y AJUSTES'),
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
        
        # Código 817: Gastos rechazados (Art. 21)
        lines.append({
            'id': 'codigo_817',
            'parent_id': 'ajustes',
            'name': '817',
            'level': 2,
            'columns': [
                {'name': '817'},
                {'name': _('Gastos rechazados (Art. 21)')},
                {'name': format_value(f22_data.get('agregados_gastos_rechazados', 0.0))},
            ],
        })
        
        # Código 832: Otros agregados
        lines.append({
            'id': 'codigo_832',
            'parent_id': 'ajustes',
            'name': '832',
            'level': 2,
            'columns': [
                {'name': '832'},
                {'name': _('Otros agregados a la RLI')},
                {'name': format_value(f22_data.get('agregados_otros', 0.0))},
            ],
        })
        
        # Total agregados
        lines.append({
            'id': 'total_agregados',
            'parent_id': 'ajustes',
            'name': '',
            'level': 2,
            'columns': [
                {'name': ''},
                {'name': _('Total Agregados')},
                {'name': format_value(f22_data.get('total_agregados', 0.0))},
            ],
            'class': 'o_account_reports_totals_below_sections',
        })
        
        # Código 833: Pérdidas de ejercicios anteriores
        lines.append({
            'id': 'codigo_833',
            'parent_id': 'ajustes',
            'name': '833',
            'level': 2,
            'columns': [
                {'name': '833'},
                {'name': _('Pérdidas de ejercicios anteriores')},
                {'name': format_value(f22_data.get('deducciones_perdidas_anteriores', 0.0))},
            ],
        })
        
        # Código 834: Otras deducciones
        lines.append({
            'id': 'codigo_834',
            'parent_id': 'ajustes',
            'name': '834',
            'level': 2,
            'columns': [
                {'name': '834'},
                {'name': _('Otras deducciones de la RLI')},
                {'name': format_value(f22_data.get('deducciones_otros', 0.0))},
            ],
        })
        
        # Total deducciones
        lines.append({
            'id': 'total_deducciones',
            'parent_id': 'ajustes',
            'name': '',
            'level': 2,
            'columns': [
                {'name': ''},
                {'name': _('Total Deducciones')},
                {'name': format_value(f22_data.get('total_deducciones', 0.0))},
            ],
            'class': 'o_account_reports_totals_below_sections',
        })
        
        # ========== SECCIÓN 5: BASE IMPONIBLE ==========
        lines.append({
            'id': 'base_imponible',
            'name': _('BASE IMPONIBLE'),
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
        
        # Código 639: Renta líquida imponible (o pérdida)
        lines.append({
            'id': 'codigo_639',
            'parent_id': 'base_imponible',
            'name': '639',
            'level': 2,
            'columns': [
                {'name': '639'},
                {'name': _('Renta líquida imponible (o pérdida)')},
                {'name': format_value(f22_data.get('renta_liquida_imponible', 0.0))},
            ],
            'class': 'o_account_reports_totals_below_sections',
        })
        
        # ========== SECCIÓN 6: IMPUESTO PRIMERA CATEGORÍA ==========
        lines.append({
            'id': 'impuesto',
            'name': _('IMPUESTO PRIMERA CATEGORÍA'),
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
        
        # Código 18: Impuesto primera categoría (27%)
        lines.append({
            'id': 'codigo_18',
            'parent_id': 'impuesto',
            'name': '18',
            'level': 2,
            'columns': [
                {'name': '18'},
                {'name': _('Impuesto Primera Categoría (27%)')},
                {'name': format_value(f22_data.get('impuesto_primera_categoria', 0.0))},
            ],
        })
        
        # ========== SECCIÓN 7: CRÉDITOS ==========
        lines.append({
            'id': 'creditos',
            'name': _('CRÉDITOS CONTRA EL IMPUESTO'),
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
        
        # Código 20: Crédito por PPM
        lines.append({
            'id': 'codigo_20',
            'parent_id': 'creditos',
            'name': '20',
            'level': 2,
            'columns': [
                {'name': '20'},
                {'name': _('Crédito por Pagos Provisionales Mensuales (PPM)')},
                {'name': format_value(f22_data.get('credito_ppm', 0.0))},
            ],
        })
        
        # Código 129: Otros créditos imputables
        lines.append({
            'id': 'codigo_129',
            'parent_id': 'creditos',
            'name': '129',
            'level': 2,
            'columns': [
                {'name': '129'},
                {'name': _('Otros créditos imputables')},
                {'name': format_value(f22_data.get('credito_otros', 0.0))},
            ],
        })
        
        # Total créditos
        lines.append({
            'id': 'total_creditos',
            'parent_id': 'creditos',
            'name': '',
            'level': 2,
            'columns': [
                {'name': ''},
                {'name': _('Total Créditos')},
                {'name': format_value(f22_data.get('total_creditos', 0.0))},
            ],
            'class': 'o_account_reports_totals_below_sections',
        })
        
        # ========== SECCIÓN 8: DETERMINACIÓN DEL IMPUESTO ==========
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
        
        # Código 30: Impuesto a pagar
        if f22_data.get('impuesto_a_pagar', 0.0) > 0:
            lines.append({
                'id': 'codigo_30',
                'parent_id': 'determinacion',
                'name': '30',
                'level': 2,
                'columns': [
                    {'name': '30'},
                    {'name': _('Impuesto a pagar')},
                    {'name': format_value(f22_data.get('impuesto_a_pagar', 0.0))},
                ],
                'class': 'o_account_reports_totals_below_sections total',
            })
        
        # Código 31: Devolución solicitada
        if f22_data.get('devolucion', 0.0) > 0:
            lines.append({
                'id': 'codigo_31',
                'parent_id': 'determinacion',
                'name': '31',
                'level': 2,
                'columns': [
                    {'name': '31'},
                    {'name': _('Devolución solicitada')},
                    {'name': format_value(f22_data.get('devolucion', 0.0))},
                ],
                'class': 'o_account_reports_totals_below_sections',
            })
        
        # ========== SECCIÓN 9: INFORMACIÓN ADICIONAL ==========
        if f22_data.get('f22_id'):
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
            
            # Año tributario
            lines.append({
                'id': 'ano_tributario',
                'parent_id': 'info_adicional',
                'name': '',
                'level': 2,
                'columns': [
                    {'name': ''},
                    {'name': _('Año Tributario')},
                    {'name': str(f22_data.get('fiscal_year', ''))},
                ],
            })
            
            # Período de renta
            lines.append({
                'id': 'periodo_renta',
                'parent_id': 'info_adicional',
                'name': '',
                'level': 2,
                'columns': [
                    {'name': ''},
                    {'name': _('Período de Renta')},
                    {'name': f22_data.get('period_string', '')},
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
                    {'name': f22_data.get('state_display', '')},
                ],
            })
            
            # Folio SII
            if f22_data.get('folio'):
                lines.append({
                    'id': 'folio',
                    'parent_id': 'info_adicional',
                    'name': '',
                    'level': 2,
                    'columns': [
                        {'name': ''},
                        {'name': _('Folio SII')},
                        {'name': f22_data.get('folio', '')},
                    ],
                })
        
        return lines
    
    def _get_f22_data(self, options):
        """
        Obtiene los datos del F22 para el período seleccionado
        
        Busca un registro de l10n_cl.f22 existente o calcula los valores
        desde los movimientos contables.
        """
        # Obtener fechas del período
        date_from = fields.Date.from_string(options['date']['date_from'])
        date_to = fields.Date.from_string(options['date']['date_to'])
        
        # Obtener año tributario (el año del date_to + 1)
        fiscal_year = date_to.year + 1
        
        # Obtener compañía
        company_id = self._get_company_id(options)
        company = self.env['res.company'].browse(company_id)
        
        # Buscar F22 existente
        f22 = self.env['l10n_cl.f22'].search([
            ('company_id', '=', company_id),
            ('fiscal_year', '=', fiscal_year),
            ('state', '!=', 'replaced')
        ], limit=1)
        
        if f22:
            # Usar datos del F22 existente
            state_display = dict(f22._fields['state'].selection).get(f22.state, f22.state)
            period_string = f"{f22.period_start.strftime('%d/%m/%Y')} - {f22.period_end.strftime('%d/%m/%Y')}"
            
            # Calcular gastos de personal y otros gastos desde gastos operacionales
            gastos_personal = f22.gastos_operacionales * 0.6  # Estimación: 60% son gastos de personal
            otros_gastos = f22.gastos_operacionales * 0.4  # Estimación: 40% son otros gastos
            
            return {
                'f22_id': f22.id,
                'fiscal_year': f22.fiscal_year,
                'period_string': period_string,
                'state': f22.state,
                'state_display': state_display,
                'folio': f22.folio,
                'ingresos_operacionales': f22.ingresos_operacionales,
                'ingresos_no_operacionales': f22.ingresos_no_operacionales,
                'ingresos_no_renta': 0.0,  # Por ahora no se maneja en el modelo
                'ingresos_totales': f22.ingresos_totales,
                'costos_directos': f22.costos_directos,
                'gastos_personal': gastos_personal,
                'gastos_operacionales': f22.gastos_operacionales,
                'gastos_financieros': f22.gastos_financieros,
                'depreciacion': f22.depreciacion,
                'otros_gastos': otros_gastos,
                'gastos_totales': f22.gastos_totales,
                'resultado_antes_impuesto': f22.resultado_antes_impuesto,
                'agregados_gastos_rechazados': f22.agregados_gastos_rechazados,
                'agregados_otros': f22.agregados_otros,
                'total_agregados': f22.total_agregados,
                'deducciones_perdidas_anteriores': f22.deducciones_perdidas_anteriores,
                'deducciones_otros': f22.deducciones_otros,
                'total_deducciones': f22.total_deducciones,
                'renta_liquida_imponible': f22.renta_liquida_imponible,
                'impuesto_primera_categoria': f22.impuesto_primera_categoria,
                'credito_ppm': f22.credito_ppm,
                'credito_otros': f22.credito_otros,
                'total_creditos': f22.total_creditos,
                'impuesto_a_pagar': f22.impuesto_a_pagar,
                'devolucion': f22.devolucion,
            }
        else:
            # Calcular datos desde movimientos contables
            return self._calculate_f22_data(company, date_from, date_to, fiscal_year)
    
    def _calculate_f22_data(self, company, date_from, date_to, fiscal_year):
        """
        Calcula los datos del F22 desde los movimientos contables
        cuando no existe un registro F22 guardado
        """
        # Usar el servicio de integración SII si está disponible
        try:
            sii_service = self.env['account.financial.report.sii.integration.service']
            f22_data = sii_service.generate_f22_data(company, fiscal_year)
            data = f22_data.get('data', {})
        except:
            # Fallback: cálculo básico
            data = self._calculate_basic_f22_data(company, date_from, date_to)
        
        # Formato de período
        period_string = f"{date_from.strftime('%d/%m/%Y')} - {date_to.strftime('%d/%m/%Y')}"
        
        # Calcular totales
        ingresos_totales = data.get('ingresos_operacionales', 0.0) + data.get('ingresos_no_operacionales', 0.0)
        gastos_totales = (
            data.get('costos_directos', 0.0) +
            data.get('gastos_operacionales', 0.0) +
            data.get('gastos_financieros', 0.0) +
            data.get('depreciacion', 0.0)
        )
        resultado_antes_impuesto = ingresos_totales - gastos_totales
        
        # Ajustes tributarios (valores por defecto)
        agregados_gastos_rechazados = data.get('gastos_rechazados', 0.0)
        agregados_otros = 0.0
        total_agregados = agregados_gastos_rechazados + agregados_otros
        
        deducciones_perdidas_anteriores = 0.0
        deducciones_otros = 0.0
        total_deducciones = deducciones_perdidas_anteriores + deducciones_otros
        
        # Renta líquida imponible
        renta_liquida_imponible = max(0, resultado_antes_impuesto + total_agregados - total_deducciones)
        
        # Impuesto (27%)
        impuesto_primera_categoria = renta_liquida_imponible * 0.27
        
        # Créditos (valores por defecto)
        credito_ppm = data.get('credito_ppm', 0.0)
        credito_otros = 0.0
        total_creditos = credito_ppm + credito_otros
        
        # Determinación final
        diferencia = impuesto_primera_categoria - total_creditos
        impuesto_a_pagar = diferencia if diferencia > 0 else 0.0
        devolucion = abs(diferencia) if diferencia < 0 else 0.0
        
        # Estimar gastos de personal y otros gastos
        gastos_personal = data.get('gastos_operacionales', 0.0) * 0.6
        otros_gastos = data.get('gastos_operacionales', 0.0) * 0.4
        
        return {
            'f22_id': False,
            'fiscal_year': fiscal_year,
            'period_string': period_string,
            'state': 'draft',
            'state_display': _('Borrador'),
            'folio': '',
            'ingresos_operacionales': data.get('ingresos_operacionales', 0.0),
            'ingresos_no_operacionales': data.get('ingresos_no_operacionales', 0.0),
            'ingresos_no_renta': 0.0,
            'ingresos_totales': ingresos_totales,
            'costos_directos': data.get('costos_directos', 0.0),
            'gastos_personal': gastos_personal,
            'gastos_operacionales': data.get('gastos_operacionales', 0.0),
            'gastos_financieros': data.get('gastos_financieros', 0.0),
            'depreciacion': data.get('depreciacion', 0.0),
            'otros_gastos': otros_gastos,
            'gastos_totales': gastos_totales,
            'resultado_antes_impuesto': resultado_antes_impuesto,
            'agregados_gastos_rechazados': agregados_gastos_rechazados,
            'agregados_otros': agregados_otros,
            'total_agregados': total_agregados,
            'deducciones_perdidas_anteriores': deducciones_perdidas_anteriores,
            'deducciones_otros': deducciones_otros,
            'total_deducciones': total_deducciones,
            'renta_liquida_imponible': renta_liquida_imponible,
            'impuesto_primera_categoria': impuesto_primera_categoria,
            'credito_ppm': credito_ppm,
            'credito_otros': credito_otros,
            'total_creditos': total_creditos,
            'impuesto_a_pagar': impuesto_a_pagar,
            'devolucion': devolucion,
        }
    
    def _calculate_basic_f22_data(self, company, date_from, date_to):
        """
        Cálculo básico de datos F22 desde account.move.line
        """
        # Dominios base
        base_domain = [
            ('company_id', '=', company.id),
            ('parent_state', '=', 'posted'),
            ('date', '>=', date_from),
            ('date', '<=', date_to),
        ]
        
        data = {
            'ingresos_operacionales': 0.0,
            'ingresos_no_operacionales': 0.0,
            'costos_directos': 0.0,
            'gastos_operacionales': 0.0,
            'gastos_financieros': 0.0,
            'depreciacion': 0.0,
            'gastos_rechazados': 0.0,
            'credito_ppm': 0.0,
        }
        
        # Obtener cuentas de ingresos (grupo 4xx)
        income_lines = self.env['account.move.line'].search(base_domain + [
            ('account_id.code', '=like', '4%'),
        ])
        
        for line in income_lines:
            # Ingresos operacionales (41x)
            if line.account_id.code.startswith('41'):
                data['ingresos_operacionales'] += abs(line.balance)
            # Otros ingresos (42x, 43x, etc.)
            else:
                data['ingresos_no_operacionales'] += abs(line.balance)
        
        # Obtener cuentas de costos y gastos (grupo 5xx, 6xx)
        expense_lines = self.env['account.move.line'].search(base_domain + [
            '|',
            ('account_id.code', '=like', '5%'),
            ('account_id.code', '=like', '6%'),
        ])
        
        for line in expense_lines:
            # Costos directos (51x)
            if line.account_id.code.startswith('51'):
                data['costos_directos'] += abs(line.balance)
            # Gastos financieros (52x)
            elif line.account_id.code.startswith('52'):
                data['gastos_financieros'] += abs(line.balance)
            # Depreciación (53x)
            elif line.account_id.code.startswith('53'):
                data['depreciacion'] += abs(line.balance)
            # Otros gastos operacionales
            else:
                data['gastos_operacionales'] += abs(line.balance)
        
        # Buscar PPM pagados durante el año
        ppm_lines = self.env['account.move.line'].search(base_domain + [
            ('name', 'ilike', 'PPM'),
            ('account_id.code', '=like', '11%'),  # Cuentas de activo
        ])
        
        for line in ppm_lines:
            if line.debit > 0:
                data['credito_ppm'] += line.debit
        
        # Estimar gastos rechazados (5% de gastos operacionales como aproximación)
        data['gastos_rechazados'] = data['gastos_operacionales'] * 0.05
        
        return data
    
    def _get_company_id(self, options):
        """Obtiene el ID de la compañía desde las opciones"""
        return options.get('company_id') or self.env.company.id
    
    @api.model
    def action_create_f22(self, options):
        """
        Acción para crear un registro F22 desde el reporte
        """
        # Obtener datos del período
        date_to = fields.Date.from_string(options['date']['date_to'])
        fiscal_year = date_to.year + 1
        company_id = self._get_company_id(options)
        
        # Verificar si ya existe
        existing = self.env['l10n_cl.f22'].search([
            ('company_id', '=', company_id),
            ('fiscal_year', '=', fiscal_year),
            ('state', '!=', 'replaced')
        ], limit=1)
        
        if existing:
            # Abrir el F22 existente
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'l10n_cl.f22',
                'res_id': existing.id,
                'view_mode': 'form',
                'target': 'current',
            }
        else:
            # Crear nuevo F22
            f22 = self.env['l10n_cl.f22'].create({
                'company_id': company_id,
                'fiscal_year': fiscal_year,
            })
            
            # Calcular valores
            f22.action_calculate()
            
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'l10n_cl.f22',
                'res_id': f22.id,
                'view_mode': 'form',
                'target': 'current',
            }