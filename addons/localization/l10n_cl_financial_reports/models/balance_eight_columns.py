# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo import tools
from odoo.exceptions import UserError
import json
import logging

_logger = logging.getLogger(__name__)


class BalanceEightColumns(models.Model):
    """
    Modelo para el Balance de 8 Columnas según normativa SII Chile.
    """
    _name = 'account.balance.eight.columns'
    _description = 'Balance de 8 Columnas - Chile SII'
    _order = 'create_date desc'

    # Override del campo name para computado
    name = fields.Char(
        string='Nombre del Reporte',
        compute='_compute_name',
        store=True
    )

    # Campos de Configuración
    date_from = fields.Date(
        string='Fecha Desde',
        required=True,
        default=lambda self: fields.Date.today(self).replace(day=1)
    )
    date_to = fields.Date(
        string='Fecha Hasta',
        required=True,
        default=fields.Date.context_today
    )

    # Opciones de Visualización
    show_zero_balance = fields.Boolean(
        string='Mostrar cuentas sin movimiento',
        default=False,
        help='Incluir cuentas con saldo cero en el reporte'
    )
    account_level = fields.Selection([
        ('all', 'Todas las cuentas'),
        ('detail', 'Solo cuentas de detalle'),
        ('parent', 'Solo cuentas padre')
    ], string='Nivel de Cuentas', default='all', required=True)

    # Plan de Cuentas SII
    chart_of_accounts = fields.Selection([
        ('sii_pyme', 'Plan de Cuentas SII PyME'),
        ('sii_general', 'Plan de Cuentas SII General'),
        ('custom', 'Plan Personalizado')
    ], string='Plan de Cuentas', default='sii_pyme', required=True)

    # Estado del reporte
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('computing', 'Calculando'),
        ('computed', 'Calculado'),
        ('error', 'Error')
    ], string='Estado', default='draft', required=True)

    # Compañía
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company
    )

    # Líneas del Balance
    line_ids = fields.One2many(
        'account.balance.eight.columns.line',
        'balance_id',
        string='Líneas del Balance'
    )

    # Totales Calculados
    total_debit = fields.Monetary(
        string='Total Débitos',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_credit = fields.Monetary(
        string='Total Créditos',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_debit_balance = fields.Monetary(
        string='Total Saldo Deudor',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_credit_balance = fields.Monetary(
        string='Total Saldo Acreedor',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_assets = fields.Monetary(
        string='Total Activos',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_liabilities = fields.Monetary(
        string='Total Pasivos',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_loss = fields.Monetary(
        string='Total Pérdidas',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )
    total_profit = fields.Monetary(
        string='Total Ganancias',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # Validaciones SII
    is_balanced = fields.Boolean(
        string='Balance Cuadrado',
        compute='_compute_validations',
        store=True
    )
    validation_errors = fields.Text(
        string='Errores de Validación',
        compute='_compute_validations',
        store=True
    )

    # Cache y Performance
    cache_key = fields.Char(string='Cache Key', compute='_compute_cache_key')
    last_compute = fields.Datetime(string='Última Actualización')

    # Moneda
    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        string='Moneda'
    )

    @api.depends_context('company')
    @api.depends('date_from', 'date_to', 'company_id')
    def _compute_name(self):
        for record in self:
            if record.date_from and record.date_to:
                record.name = f"Balance 8 Columnas - {record.company_id.name}: {record.date_from} al {record.date_to}"
            else:
                record.name = f"Balance 8 Columnas - {record.company_id.name}"

    @api.depends_context('company')
    @api.depends('date_from', 'date_to', 'company_id', 'show_zero_balance')
    def _compute_cache_key(self):
        for record in self:
            key_data = {
                'date_from': str(record.date_from),
                'date_to': str(record.date_to),
                'company_id': record.company_id.id,
                'show_zero': record.show_zero_balance
            }
            record.cache_key = json.dumps(key_data, sort_keys=True)
    @tools.ormcache_context('self.id', keys=('company_id'))

    @api.depends('line_ids', 'line_ids.debit', 'line_ids.credit',
                 'line_ids.debit_balance', 'line_ids.credit_balance',
                 'line_ids.assets', 'line_ids.liabilities',
                 'line_ids.loss', 'line_ids.profit')
    def _compute_totals(self):
        """Calcula los totales de las 8 columnas"""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        for record in self:
            record.total_debit = sum(record.line_ids.mapped('debit'))
            record.total_credit = sum(record.line_ids.mapped('credit'))
            record.total_debit_balance = sum(record.line_ids.mapped('debit_balance'))
            record.total_credit_balance = sum(record.line_ids.mapped('credit_balance'))
            record.total_assets = sum(record.line_ids.mapped('assets'))
            record.total_liabilities = sum(record.line_ids.mapped('liabilities'))
            record.total_loss = sum(record.line_ids.mapped('loss'))
            record.total_profit = sum(record.line_ids.mapped('profit'))

    @api.depends('total_debit', 'total_credit', 'total_debit_balance',
                 'total_credit_balance', 'total_assets', 'total_liabilities',
                 'total_loss', 'total_profit')
    def _compute_validations(self):
        """Valida que el balance cuadre según normativa SII"""
        for record in self:
            errors = []

            # Validación 1: Débitos = Créditos
            if abs(record.total_debit - record.total_credit) > 0.01:
                errors.append(f"Débitos ({record.total_debit:,.2f}) ≠ Créditos ({record.total_credit:,.2f})")

            # Validación 2: Deudor = Acreedor
            if abs(record.total_debit_balance - record.total_credit_balance) > 0.01:
                errors.append(f"Saldo Deudor ({record.total_debit_balance:,.2f}) ≠ Saldo Acreedor ({record.total_credit_balance:,.2f})")

            # Validación 3: Activos = Pasivos + Patrimonio
            patrimonio = record.total_profit - record.total_loss
            if abs(record.total_assets - (record.total_liabilities + patrimonio)) > 0.01:
                errors.append(f"Activos ({record.total_assets:,.2f}) ≠ Pasivos ({record.total_liabilities:,.2f}) + Patrimonio ({patrimonio:,.2f})")

            # Validación 4: Resultado = Ganancias - Pérdidas
            resultado_esperado = record.total_profit - record.total_loss
            resultado_real = record.total_credit_balance - record.total_debit_balance
            if abs(resultado_esperado - resultado_real) > 0.01:
                errors.append(f"Resultado por columnas ({resultado_esperado:,.2f}) ≠ Resultado por saldos ({resultado_real:,.2f})")

            record.validation_errors = '\n'.join(errors) if errors else False
            record.is_balanced = not bool(errors)

    def action_compute_balance(self):
        """
        Acción principal para calcular el balance de 8 columnas.
        Llama al service layer para obtener los datos optimizados.
        """
        self.ensure_one()

        try:
            # Cambiar estado a computing
            self.write({'state': 'computing', 'last_compute': fields.Datetime.now()})

            # Limpiar líneas anteriores
            self.line_ids.unlink()

            # Obtener el servicio
            from .services.balance_eight_columns_service import BalanceEightColumnsService
            service = BalanceEightColumnsService(self.env)

            # Calcular el balance
            result = service.compute_balance_eight_columns(
                date_from=self.date_from,
                date_to=self.date_to,
                company_id=self.company_id.id,
                show_zero_balance=self.show_zero_balance,
                account_level=self.account_level,
                chart_of_accounts=self.chart_of_accounts
            )

            # Crear las líneas usando batch operation
            batch_service = self.env.service('l10n_cl.batch.operation')

            lines_vals_list = []
            for line_data in result['lines']:
                lines_vals_list.append({
                    'balance_id': self.id,
                    'account_id': line_data['account_id'],
                    'account_code': line_data['account_code'],
                    'account_name': line_data['account_name'],
                    'account_type': line_data['account_type'],
                    'parent_path': line_data.get('parent_path', ''),
                    'hierarchy_level': line_data.get('hierarchy_level', 0),
                    'debit': line_data['debit'],
                    'credit': line_data['credit'],
                    'debit_balance': line_data['debit_balance'],
                    'credit_balance': line_data['credit_balance'],
                    'assets': line_data['assets'],
                    'liabilities': line_data['liabilities'],
                    'loss': line_data['loss'],
                    'profit': line_data['profit'],
                    'is_parent_account': line_data.get('is_parent_account', False),
                })

            if lines_vals_list:
                batch_service.batch_create('account.balance.eight.columns.line', lines_vals_list)

            # Actualizar estado
            self.write({'state': 'computed'})

            # Retornar acción para mostrar el reporte
            return {
                'type': 'ir.actions.client',
                'tag': 'balance_eight_columns_report',
                'context': {
                    'active_id': self.id,
                    'active_model': self._name,
                }
            }

        except Exception as e:
            _logger.error(f"Error computing balance: {str(e)}")
            self.write({
                'state': 'error',
                'validation_errors': str(e)
            })
            raise UserError(_("Error al calcular el balance: %s") % str(e))

    def action_export_excel(self):
        """Exporta el balance a Excel con formato profesional"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular el balance antes de exportar."))

        # Llamar al método del service
        from .services.balance_eight_columns_service import BalanceEightColumnsService
        service = BalanceEightColumnsService(self.env)
        return service.export_to_excel(self)

    def action_export_pdf(self):
        """Exporta el balance a PDF con formato SII"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular el balance antes de exportar."))

        return self.env.ref('l10n_cl_financial_reports.action_report_balance_eight_columns').report_action(self)

    def action_export_xml(self):
        """Exporta el balance a XML según esquema SII"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular el balance antes de exportar."))

        # Llamar al método del service
        from .services.balance_eight_columns_service import BalanceEightColumnsService
        service = BalanceEightColumnsService(self.env)
        return service.export_to_xml(self)

    def action_refresh(self):
        """Recalcula el balance"""
        return self.action_compute_balance()

    @api.model_create_multi
    def create(self, vals_list):
        """Override create para establecer valores por defecto"""
        for vals in vals_list:
            if 'company_id' not in vals:
                vals['company_id'] = self.env.company.id
        return super().create(vals_list)


class BalanceEightColumnsLine(models.Model):
    """Líneas del Balance de 8 Columnas"""
    _name = 'account.balance.eight.columns.line'
    _description = 'Línea de Balance 8 Columnas'
    _order = 'account_code'

    balance_id = fields.Many2one(
        'account.balance.eight.columns',
        string='Balance',
        required=True,
        ondelete='cascade'
    )

    # Datos de la cuenta
    account_id = fields.Many2one(
        'account.account',
        string='Cuenta',
        required=True
    )
    account_code = fields.Char(
        string='Código',
        required=True
    )
    account_name = fields.Char(
        string='Nombre',
        required=True
    )
    account_type = fields.Char(
        string='Tipo de Cuenta'
    )

    # Jerarquía
    parent_path = fields.Char(
        string='Ruta Padre',
        help='Ruta jerárquica de la cuenta'
    )
    hierarchy_level = fields.Integer(
        string='Nivel',
        default=0
    )
    is_parent_account = fields.Boolean(
        string='Es Cuenta Padre',
        default=False
    )

    # Las 8 columnas
    debit = fields.Monetary(
        string='Débitos',
        currency_field='currency_id'
    )
    credit = fields.Monetary(
        string='Créditos',
        currency_field='currency_id'
    )
    debit_balance = fields.Monetary(
        string='Saldo Deudor',
        currency_field='currency_id'
    )
    credit_balance = fields.Monetary(
        string='Saldo Acreedor',
        currency_field='currency_id'
    )
    assets = fields.Monetary(
        string='Activo',
        currency_field='currency_id'
    )
    liabilities = fields.Monetary(
        string='Pasivo',
        currency_field='currency_id'
    )
    loss = fields.Monetary(
        string='Pérdida',
        currency_field='currency_id'
    )
    profit = fields.Monetary(
        string='Ganancia',
        currency_field='currency_id'
    )

    # Moneda
    currency_id = fields.Many2one(
        'res.currency',
        related='balance_id.currency_id',
        string='Moneda'
    )

    # Clasificación SII
    sii_classification = fields.Selection([
        ('activo_circulante', 'Activo Circulante'),
        ('activo_fijo', 'Activo Fijo'),
        ('otros_activos', 'Otros Activos'),
        ('pasivo_circulante', 'Pasivo Circulante'),
        ('pasivo_largo_plazo', 'Pasivo Largo Plazo'),
        ('patrimonio', 'Patrimonio'),
        ('ingresos_operacionales', 'Ingresos Operacionales'),
        ('costos_operacionales', 'Costos Operacionales'),
        ('gastos_administracion', 'Gastos de Administración'),
        ('otros_ingresos_gastos', 'Otros Ingresos y Gastos'),
    ], string='Clasificación SII', compute='_compute_sii_classification')

    @api.depends('account_id', 'account_code')
    def _compute_sii_classification(self):
        """Calcula la clasificación SII basada en el código de cuenta"""
        for line in self:
            # Lógica simplificada de clasificación basada en código
            code = line.account_code
            if code.startswith('1'):
                if code.startswith('11'):
                    line.sii_classification = 'activo_circulante'
                elif code.startswith('12'):
                    line.sii_classification = 'activo_fijo'
                else:
                    line.sii_classification = 'otros_activos'
            elif code.startswith('2'):
                if code.startswith('21'):
                    line.sii_classification = 'pasivo_circulante'
                else:
                    line.sii_classification = 'pasivo_largo_plazo'
            elif code.startswith('3'):
                line.sii_classification = 'patrimonio'
            elif code.startswith('4'):
                line.sii_classification = 'ingresos_operacionales'
            elif code.startswith('5'):
                line.sii_classification = 'costos_operacionales'
            elif code.startswith('6'):
                line.sii_classification = 'gastos_administracion'
            else:
                line.sii_classification = 'otros_ingresos_gastos'
