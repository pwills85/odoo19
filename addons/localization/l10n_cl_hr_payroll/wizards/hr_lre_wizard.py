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
        Header del CSV LRE
        
        Columnas según normativa DT 2025
        """
        columns = [
            'RUT_EMPLEADOR',
            'PERIODO',
            'RUT_TRABAJADOR',
            'DV_TRABAJADOR',
            'APELLIDO_PATERNO',
            'APELLIDO_MATERNO',
            'NOMBRES',
            'SUELDO_BASE',
            'HORAS_EXTRAS',
            'COMISIONES',
            'BONOS',
            'GRATIFICACION',
            'AGUINALDOS',
            'ASIG_FAMILIAR',
            'COLACION',
            'MOVILIZACION',
            'TOTAL_HAB_IMPONIBLES',
            'TOTAL_HAB_NO_IMPONIBLES',
            'TOTAL_HABERES',
            'AFP',
            'SALUD',
            'SEGURO_CESANTIA',
            'IMPUESTO_UNICO',
            'OTROS_DESCUENTOS',
            'TOTAL_DESCUENTOS',
            'ALCANCE_LIQUIDO',
            'DIAS_TRABAJADOS',
            'CODIGO_AFP',
            'CODIGO_SALUD',
        ]
        
        return ';'.join(columns)
    
    def _get_csv_line(self, payslip):
        """Generar línea CSV para una liquidación"""
        employee = payslip.employee_id
        
        # Extraer valores de las líneas de liquidación
        values = self._extract_payslip_values(payslip)
        
        # RUT empleador
        rut_empleador = self.company_id.vat or ''
        
        # Período (YYYYMM)
        periodo = '%s%s' % (self.period_year, self.period_month.zfill(2))
        
        # RUT trabajador
        rut_trabajador = employee.identification_id or ''
        rut_parts = self._split_rut(rut_trabajador)
        
        # Nombres
        apellido_paterno = employee.lastname or ''
        apellido_materno = employee.mothers_name or ''
        nombres = employee.firstname or employee.name or ''
        
        # Valores
        data = [
            rut_empleador,
            periodo,
            rut_parts['rut'],
            rut_parts['dv'],
            apellido_paterno,
            apellido_materno,
            nombres,
            str(int(values.get('BASIC', 0))),
            str(int(values.get('HEX', 0))),
            str(int(values.get('COMISION', 0))),
            str(int(values.get('BONO', 0))),
            str(int(values.get('GRAT', 0))),
            str(int(values.get('AGUINALDO', 0))),
            str(int(values.get('ASIG_FAM', 0))),
            str(int(values.get('COLACION', 0))),
            str(int(values.get('MOVILIZACION', 0))),
            str(int(values.get('HABERES_IMPONIBLES', 0))),
            str(int(values.get('HABERES_NO_IMPONIBLES', 0))),
            str(int(values.get('TOTAL_HABERES', 0))),
            str(int(abs(values.get('AFP', 0)))),
            str(int(abs(values.get('SALUD', 0)))),
            str(int(abs(values.get('AFC', 0)))),
            str(int(abs(values.get('IMPUESTO_UNICO', 0)))),
            str(int(abs(values.get('OTROS_DESC', 0)))),
            str(int(abs(values.get('TOTAL_DESCUENTOS', 0)))),
            str(int(values.get('NET', 0))),
            str(self._get_working_days(payslip)),
            payslip.contract_id.afp_id.code if payslip.contract_id.afp_id else '',
            payslip.contract_id.isapre_id.code if payslip.contract_id.isapre_id else 'FONASA',
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
