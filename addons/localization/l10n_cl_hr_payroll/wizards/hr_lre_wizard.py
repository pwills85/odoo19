# -*- coding: utf-8 -*-

"""
Wizard - Generación Libro de Remuneraciones Electrónico (LRE)

Genera el archivo CSV del LRE para declaración mensual en la Dirección del Trabajo.
"""

from odoo import models, fields, api, _
from odoo.exceptions import UserError, ValidationError
from datetime import datetime
import base64
import logging

_logger = logging.getLogger(__name__)


class HrLreWizard(models.TransientModel):
    """
    Wizard para generar el Libro de Remuneraciones Electrónico (LRE)
    
    El LRE es el reporte mensual obligatorio que se presenta a la
    Dirección del Trabajo con el detalle de las remuneraciones.
    
    Referencias:
    - https://www.dt.gob.cl/portal/1626/w3-propertyvalue-22110.html
    """
    _name = 'hr.lre.wizard'
    _description = 'Generar Libro de Remuneraciones Electrónico'
    
    # ═══════════════════════════════════════════════════════════
    # CAMPOS
    # ═══════════════════════════════════════════════════════════
    
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        readonly=True
    )
    
    period_month = fields.Selection([
        ('1', 'Enero'),
        ('2', 'Febrero'),
        ('3', 'Marzo'),
        ('4', 'Abril'),
        ('5', 'Mayo'),
        ('6', 'Junio'),
        ('7', 'Julio'),
        ('8', 'Agosto'),
        ('9', 'Septiembre'),
        ('10', 'Octubre'),
        ('11', 'Noviembre'),
        ('12', 'Diciembre'),
    ], string='Mes', required=True, default=lambda self: str(datetime.now().month))
    
    period_year = fields.Integer(
        string='Año',
        required=True,
        default=lambda self: datetime.now().year
    )
    
    payslip_run_id = fields.Many2one(
        'hr.payslip.run',
        string='Lote de Nóminas',
        help='Opcional: Filtrar por lote específico'
    )
    
    state = fields.Selection([
        ('draft', 'Configuración'),
        ('done', 'Generado')
    ], default='draft', string='Estado')
    
    # Archivo generado
    lre_file = fields.Binary(
        string='Archivo LRE',
        readonly=True,
        attachment=True
    )
    
    lre_filename = fields.Char(
        string='Nombre Archivo',
        readonly=True
    )
    
    # Estadísticas
    total_payslips = fields.Integer(
        string='Liquidaciones Procesadas',
        readonly=True
    )
    
    total_employees = fields.Integer(
        string='Empleados',
        readonly=True
    )
    
    total_remuneraciones = fields.Monetary(
        string='Total Remuneraciones',
        currency_field='currency_id',
        readonly=True
    )
    
    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        readonly=True
    )
    
    # ═══════════════════════════════════════════════════════════
    # MÉTODOS
    # ═══════════════════════════════════════════════════════════
    
    def action_generate_lre(self):
        """
        Generar archivo LRE
        
        Proceso:
        1. Buscar liquidaciones del período
        2. Generar CSV con formato DT
        3. Ofrecer descarga
        """
        self.ensure_one()
        
        # Validar que existan liquidaciones
        payslips = self._get_payslips()
        if not payslips:
            raise UserError(_(
                'No se encontraron liquidaciones para el período %s/%s.'
            ) % (self.period_month, self.period_year))
        
        # Generar CSV
        csv_content = self._generate_csv(payslips)
        
        # Guardar archivo
        filename = 'LRE_%s_%s_%s.csv' % (
            self.company_id.vat or 'SIN_RUT',
            self.period_year,
            self.period_month.zfill(2)
        )
        
        self.write({
            'lre_file': base64.b64encode(csv_content.encode('utf-8')),
            'lre_filename': filename,
            'total_payslips': len(payslips),
            'total_employees': len(payslips.mapped('employee_id')),
            'total_remuneraciones': sum(payslips.mapped('gross_wage')),
            'state': 'done'
        })
        
        # Retornar vista con resultado
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'hr.lre.wizard',
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }
    
    def _get_payslips(self):
        """Obtener liquidaciones del período seleccionado"""
        domain = [
            ('date_from', '>=', '%s-%s-01' % (self.period_year, self.period_month.zfill(2))),
            ('date_to', '<=', self._get_last_day_of_month()),
            ('state', 'in', ['done', 'verify']),
            ('company_id', '=', self.company_id.id)
        ]
        
        if self.payslip_run_id:
            domain.append(('payslip_run_id', '=', self.payslip_run_id.id))
        
        return self.env['hr.payslip'].search(domain, order='employee_id, date_from')
    
    def _get_last_day_of_month(self):
        """Obtener último día del mes seleccionado"""
        month = int(self.period_month)
        year = self.period_year
        
        if month == 12:
            next_month = datetime(year + 1, 1, 1)
        else:
            next_month = datetime(year, month + 1, 1)
        
        from datetime import timedelta
        last_day = next_month - timedelta(days=1)
        return last_day.strftime('%Y-%m-%d')
    
    def _generate_csv(self, payslips):
        """
        Generar CSV con formato LRE de la Dirección del Trabajo
        
        Formato LRE 2025 (Columnas principales):
        - RUT Empleador
        - Período (YYYYMM)
        - RUT Trabajador
        - Apellido Paterno
        - Apellido Materno
        - Nombres
        - Sueldo Base
        - Horas Extras
        - Gratificación
        - Total Haberes Imponibles
        - Total Haberes No Imponibles
        - Total Haberes
        - AFP
        - Salud
        - Impuesto Único
        - Total Descuentos
        - Alcance Líquido
        - ... (más columnas según normativa)
        
        Ref: https://www.dt.gob.cl/portal/1626/articles-95677_recurso_2.pdf
        """
        csv_lines = []
        
        # Header
        header = self._get_csv_header()
        csv_lines.append(header)
        
        # Datos
        for payslip in payslips:
            line = self._get_csv_line(payslip)
            csv_lines.append(line)
        
        return '\n'.join(csv_lines)
    
    def _get_csv_header(self):
        """
        Header del CSV LRE - 105 Campos Completos

        Columnas según DT Circular 1 - Formato Previred Oficial
        Referencia: wizards/LRE_105_CAMPOS_ESPECIFICACION.md

        P0-2: Corrección brecha auditoría (29 → 105 campos)
        """
        columns = [
            # ═══════════════════════════════════════════════════════════
            # SECCIÓN A: DATOS EMPRESA (10 campos)
            # ═══════════════════════════════════════════════════════════
            'RUT_EMPLEADOR',
            'PERIODO',
            'NOMBRE_EMPRESA',
            'DIRECCION_EMPRESA',
            'COMUNA_EMPRESA',
            'CIUDAD_EMPRESA',
            'TELEFONO_EMPRESA',
            'EMAIL_EMPRESA',
            'ACTIVIDAD_ECONOMICA',
            'REGIMEN_PREVISIONAL',

            # ═══════════════════════════════════════════════════════════
            # SECCIÓN B: DATOS TRABAJADOR (19 campos)
            # ═══════════════════════════════════════════════════════════
            'RUT_TRABAJADOR',
            'DV_TRABAJADOR',
            'APELLIDO_PATERNO',
            'APELLIDO_MATERNO',
            'NOMBRES',
            'FECHA_NACIMIENTO',
            'SEXO',
            'NACIONALIDAD',
            'DIRECCION_TRABAJADOR',
            'COMUNA_TRABAJADOR',
            'CIUDAD_TRABAJADOR',
            'FECHA_INGRESO',
            'FECHA_TERMINO',
            'TIPO_CONTRATO',
            'JORNADA_TRABAJO',
            'CARGO',
            'CODIGO_AFP',
            'CODIGO_SALUD',
            'CARGAS_FAMILIARES',

            # ═══════════════════════════════════════════════════════════
            # SECCIÓN C: REMUNERACIONES IMPONIBLES DETALLADAS (15 campos)
            # P0-2: IMPLEMENTADO
            # ═══════════════════════════════════════════════════════════
            'SUELDO_BASE',
            'HORAS_EXTRAS',
            'COMISIONES',
            'SEMANA_CORRIDA',
            'PARTICIPACION',
            'GRATIFICACION_MENSUAL',
            'AGUINALDO',
            'BONO_PRODUCCION',
            'REEMPLAZO_FERIADO',
            'REEMPLAZO_PERMISO',
            'TURNOS',
            'REMUNERACION_VARIABLE_1',
            'REMUNERACION_VARIABLE_2',
            'OTROS_IMPONIBLES',
            'TOTAL_HABERES_IMPONIBLES',

            # ═══════════════════════════════════════════════════════════
            # SECCIÓN D: DESCUENTOS LEGALES (12 campos)
            # P0-2: IMPLEMENTADO
            # ═══════════════════════════════════════════════════════════
            'COTIZACION_AFP',
            'COMISION_AFP',
            'COTIZACION_SALUD',
            'ADICIONAL_ISAPRE_UF',
            'SEGURO_CESANTIA_TRABAJADOR',
            'IMPUESTO_UNICO',
            'OTROS_DESCUENTOS_LEGALES_1',
            'OTROS_DESCUENTOS_LEGALES_2',
            'OTROS_DESCUENTOS_LEGALES_3',
            'PRESTAMO_EMPRESA',
            'ANTICIPO_SUELDO',
            'TOTAL_DESCUENTOS_LEGALES',

            # ═══════════════════════════════════════════════════════════
            # SECCIÓN E: DESCUENTOS VOLUNTARIOS (8 campos)
            # P0-2: IMPLEMENTADO
            # ═══════════════════════════════════════════════════════════
            'APV_REGIMEN_A',
            'APV_REGIMEN_B',
            'APVC',
            'DEPOSITO_CONVENIDO',
            'SEGURO_VIDA_VOLUNTARIO',
            'CUOTA_SINDICAL',
            'CAJA_COMPENSACION',
            'TOTAL_DESCUENTOS_VOLUNTARIOS',

            # ═══════════════════════════════════════════════════════════
            # SECCIÓN F: HABERES NO IMPONIBLES (10 campos)
            # P0-2: IMPLEMENTADO
            # ═══════════════════════════════════════════════════════════
            'ASIGNACION_FAMILIAR',
            'ASIGNACION_MOVILIZACION',
            'ASIGNACION_COLACION',
            'ASIGNACION_DESGASTE_HERRAMIENTAS',
            'ASIGNACION_PERDIDA_CAJA',
            'VIATICOS',
            'ASIGNACION_ZONA_EXTREMA',
            'BONOS_NO_IMPONIBLES',
            'OTROS_NO_IMPONIBLES',
            'TOTAL_HABERES_NO_IMPONIBLES',

            # ═══════════════════════════════════════════════════════════
            # SECCIÓN G: OTROS MOVIMIENTOS (18 campos)
            # P0-2: IMPLEMENTADO
            # ═══════════════════════════════════════════════════════════
            'LICENCIA_MEDICA_DIAS',
            'LICENCIA_MEDICA_MONTO',
            'SUBSIDIO_INCAPACIDAD_LABORAL',
            'SUBSIDIO_MATERNAL',
            'VACACIONES_PROGRESIVAS_DIAS',
            'VACACIONES_PROPORCIONALES_DIAS',
            'INDEMNIZACION_AÑOS_SERVICIO',
            'INDEMNIZACION_AVISO_PREVIO',
            'INDEMNIZACION_VOLUNTARIA',
            'GRATIFICACION_LEGAL_ANUAL',
            'AGUINALDO_FIESTAS_PATRIAS',
            'AGUINALDO_NAVIDAD',
            'BONO_TERMINO_CONFLICTO',
            'FINIQUITO_OTROS_CONCEPTOS',
            'ATRASOS_DESCUENTO',
            'INASISTENCIAS_DESCUENTO',
            'PERMISOS_SIN_GOCE',
            'TOTAL_OTROS_MOVIMIENTOS',

            # ═══════════════════════════════════════════════════════════
            # SECCIÓN H: APORTES EMPLEADOR (13 campos)
            # P0-2: IMPLEMENTADO - Incluye Reforma 2025 SOPA
            # ═══════════════════════════════════════════════════════════
            'SEGURO_CESANTIA_EMPLEADOR',
            'SEGURO_ACCIDENTES_TRABAJO',
            'ADICIONAL_RIESGO_EMPRESA',
            'APORTE_SOLIDARIO_AFP',
            'COTIZACION_ESPERANZA_VIDA',
            'APORTE_SOPA_BASE',
            'APORTE_SOPA_PROGRESIVO',
            'INDEMNIZACION_EMPLEADOR_AÑO',
            'MUTUAL_SEGURIDAD',
            'CAJA_COMPENSACION_EMPLEADOR',
            'OTROS_APORTES_EMPLEADOR',
            'TOTAL_APORTES_EMPLEADOR',
            'ALCANCE_LIQUIDO_FINAL',
        ]

        return ';'.join(columns)
    
    def _get_csv_line(self, payslip):
        """
        Generar línea CSV para una liquidación - 105 Campos Completos

        P0-2: Implementación completa según DT Circular 1

        Mapea valores desde hr.payslip.line usando códigos de reglas salariales
        definidos en data/hr_salary_rules_p1.xml
        """
        employee = payslip.employee_id
        contract = payslip.contract_id
        company = self.company_id

        # Extraer valores de líneas de liquidación
        values = self._extract_payslip_values(payslip)

        # RUT empleador y período
        rut_empleador = company.vat or ''
        periodo = '%s%s' % (self.period_year, self.period_month.zfill(2))

        # RUT trabajador
        rut_parts = self._split_rut(employee.identification_id or '')

        # Nombres
        apellido_paterno = employee.lastname or ''
        apellido_materno = employee.mothers_name or ''
        nombres = employee.firstname or employee.name or ''

        # Helper: Formatear entero
        def fmt(value):
            """Formato DT: entero sin decimales"""
            return str(int(round(value, 0)))

        def fmt_date(date_obj):
            """Formato fecha DT: YYYYMMDD"""
            return date_obj.strftime('%Y%m%d') if date_obj else ''

        # ═══════════════════════════════════════════════════════════
        # CONSTRUCCIÓN LÍNEA 105 CAMPOS
        # ═══════════════════════════════════════════════════════════

        data = [
            # SECCIÓN A: DATOS EMPRESA (10 campos)
            rut_empleador,
            periodo,
            company.name or '',
            company.street or '',
            company.city or '',
            company.state_id.name if company.state_id else '',
            company.phone or '',
            company.email or '',
            company.partner_id.industry_id.name if company.partner_id.industry_id else '',
            'AFP',  # Régimen previsional (AFP es default Chile)

            # SECCIÓN B: DATOS TRABAJADOR (19 campos)
            rut_parts['rut'],
            rut_parts['dv'],
            apellido_paterno,
            apellido_materno,
            nombres,
            fmt_date(employee.birthday),
            employee.gender or 'male',
            employee.country_id.code if employee.country_id else 'CL',
            employee.address_home_id.street if employee.address_home_id else '',
            employee.address_home_id.city if employee.address_home_id else '',
            employee.address_home_id.state_id.name if employee.address_home_id and employee.address_home_id.state_id else '',
            fmt_date(contract.date_start),
            fmt_date(contract.date_end) if contract.date_end else '',
            contract.contract_type_id.name if contract.contract_type_id else 'Indefinido',
            fmt(contract.resource_calendar_id.hours_per_day * 5) if contract.resource_calendar_id else '45',  # Jornada semanal
            employee.job_id.name if employee.job_id else '',
            contract.afp_id.code if contract.afp_id else '',
            contract.isapre_id.code if contract.isapre_id else '07',  # FONASA
            fmt(contract.l10n_cl_dependent_count or 0),

            # SECCIÓN C: REMUNERACIONES IMPONIBLES (15 campos)
            fmt(values.get('BASIC', 0)),
            fmt(values.get('HEX', 0)),
            fmt(values.get('COMISION', 0)),
            fmt(values.get('SEMANA_CORRIDA', 0)),
            fmt(values.get('PARTICIPACION', 0)),
            fmt(values.get('GRAT', 0)),
            fmt(values.get('AGUINALDO', 0)),
            fmt(values.get('BONO_PROD', 0)),
            fmt(values.get('REEMPLAZO_FERIADO', 0)),
            fmt(values.get('REEMPLAZO_PERMISO', 0)),
            fmt(values.get('TURNOS', 0)),
            fmt(values.get('VARIABLE_1', 0)),
            fmt(values.get('VARIABLE_2', 0)),
            fmt(values.get('OTROS_IMP', 0)),
            fmt(values.get('TOTAL_IMPONIBLE', 0)),

            # SECCIÓN D: DESCUENTOS LEGALES (12 campos)
            fmt(abs(values.get('AFP', 0))),
            fmt(abs(values.get('COMISION_AFP', 0))),
            fmt(abs(values.get('SALUD', 0))),
            fmt(abs(values.get('ISAPRE_ADICIONAL', 0))),
            fmt(abs(values.get('AFC', 0))),
            fmt(abs(values.get('IMPUESTO', 0))),
            fmt(abs(values.get('DESC_LEGAL_1', 0))),
            fmt(abs(values.get('DESC_LEGAL_2', 0))),
            fmt(abs(values.get('DESC_LEGAL_3', 0))),
            fmt(abs(values.get('PRESTAMO', 0))),
            fmt(abs(values.get('ANTICIPO', 0))),
            fmt(abs(values.get('TOTAL_DESC_LEGAL', 0))),

            # SECCIÓN E: DESCUENTOS VOLUNTARIOS (8 campos)
            fmt(abs(values.get('APV_A', 0))),
            fmt(abs(values.get('APV_B', 0))),
            fmt(abs(values.get('APVC', 0))),
            fmt(abs(values.get('DEP_CONVENIDO', 0))),
            fmt(abs(values.get('SEGURO_VIDA', 0))),
            fmt(abs(values.get('CUOTA_SINDICAL', 0))),
            fmt(abs(values.get('CAJA_COMP', 0))),
            fmt(abs(values.get('TOTAL_DESC_VOL', 0))),

            # SECCIÓN F: HABERES NO IMPONIBLES (10 campos)
            fmt(values.get('ASIG_FAM', 0)),
            fmt(values.get('MOVILIZACION', 0)),
            fmt(values.get('COLACION', 0)),
            fmt(values.get('DESG_HERRAM', 0)),
            fmt(values.get('PERD_CAJA', 0)),
            fmt(values.get('VIATICOS', 0)),
            fmt(values.get('ZONA_EXTREMA', 0)),
            fmt(values.get('BONO_NO_IMP', 0)),
            fmt(values.get('OTROS_NO_IMP', 0)),
            fmt(values.get('TOTAL_NO_IMPONIBLE', 0)),

            # SECCIÓN G: OTROS MOVIMIENTOS (18 campos)
            fmt(values.get('LIC_MED_DIAS', 0)),
            fmt(values.get('LIC_MED_MONTO', 0)),
            fmt(values.get('SUB_INCAP', 0)),
            fmt(values.get('SUB_MATERNAL', 0)),
            fmt(values.get('VAC_PROG_DIAS', 0)),
            fmt(values.get('VAC_PROP_DIAS', 0)),
            fmt(values.get('INDEM_AÑOS', 0)),
            fmt(values.get('INDEM_AVISO', 0)),
            fmt(values.get('INDEM_VOL', 0)),
            fmt(values.get('GRAT_ANUAL', 0)),
            fmt(values.get('AGUIN_FP', 0)),
            fmt(values.get('AGUIN_NAV', 0)),
            fmt(values.get('BONO_CONFLICTO', 0)),
            fmt(values.get('FINIQUITO_OTROS', 0)),
            fmt(abs(values.get('ATRASOS', 0))),
            fmt(abs(values.get('INASISTENCIAS', 0))),
            fmt(abs(values.get('PERMISOS_SIN_GOCE', 0))),
            fmt(values.get('TOTAL_OTROS_MOV', 0)),

            # SECCIÓN H: APORTES EMPLEADOR (13 campos) - Reforma 2025 SOPA
            fmt(values.get('SEG_CES_EMP', contract.wage * 0.024)),  # 2.4%
            fmt(values.get('SEG_ACC_TRAB', contract.wage * 0.0093)),  # 0.93% base
            fmt(values.get('ADIC_RIESGO', 0)),
            fmt(values.get('APORTE_SOLIDARIO', 0)),
            fmt(values.get('COT_ESP_VIDA', 0)),
            fmt(values.get('SOPA_BASE', 0)),
            fmt(values.get('SOPA_PROG', 0)),
            fmt(values.get('INDEM_EMP_AÑO', 0)),
            fmt(values.get('MUTUAL', 0)),
            fmt(values.get('CAJA_COMP_EMP', 0)),
            fmt(values.get('OTROS_APORTE_EMP', 0)),
            fmt(values.get('TOTAL_APORTE_EMP', 0)),
            fmt(values.get('NET', 0)),  # Alcance líquido final
        ]

        return ';'.join(data)
    
    def _extract_payslip_values(self, payslip):
        """Extraer valores de las líneas de liquidación por código"""
        values = {}
        
        for line in payslip.line_ids:
            values[line.code] = line.total
        
        return values
    
    def _split_rut(self, rut):
        """Separar RUT en número y DV"""
        if not rut:
            return {'rut': '', 'dv': ''}
        
        # Limpiar formato
        rut = rut.replace('.', '').replace('-', '').upper()
        
        if len(rut) < 2:
            return {'rut': rut, 'dv': ''}
        
        return {
            'rut': rut[:-1],
            'dv': rut[-1]
        }
    
    def _get_working_days(self, payslip):
        """Calcular días trabajados en el período"""
        # Simplificado: diferencia de días
        delta = payslip.date_to - payslip.date_from
        return delta.days + 1
    
    def action_download_file(self):
        """Descargar archivo generado"""
        self.ensure_one()
        
        if not self.lre_file:
            raise UserError(_('No hay archivo generado. Ejecute la generación primero.'))
        
        return {
            'type': 'ir.actions.act_url',
            'url': '/web/content/hr.lre.wizard/%s/lre_file/%s?download=true' % (
                self.id, self.lre_filename
            ),
            'target': 'self',
        }
