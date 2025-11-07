# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
from odoo.exceptions import UserError
import json
import logging

_logger = logging.getLogger(__name__)


class GeneralLedger(models.Model):
    """
    Mayor Analítico (General Ledger) - Libro Mayor Detallado
    Muestra todos los movimientos contables por cuenta con saldos acumulados
    """
    _name = 'account.general.ledger'
    _description = 'Mayor Analítico / General Ledger'
    _inherit = []
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

    # Filtros
    account_ids = fields.Many2many(
        'account.account',
        string='Cuentas Específicas',
        help='Dejar vacío para incluir todas las cuentas'
    )
    account_group_ids = fields.Many2many(
        'account.group',
        string='Grupos de Cuentas',
        help='Filtrar por grupos de cuentas'
    )
    partner_ids = fields.Many2many(
        'res.partner',
        string='Socios Específicos',
        help='Dejar vacío para incluir todos los socios'
    )

    # Opciones de Visualización
    show_initial_balance = fields.Boolean(
        string='Mostrar Saldo Inicial',
        default=True,
        help='Incluir línea con saldo inicial por cuenta'
    )
    show_partner_details = fields.Boolean(
        string='Desglose por Socio',
        default=False,
        help='Mostrar movimientos agrupados por socio comercial'
    )
    show_analytic_details = fields.Boolean(
        string='Detalles Analíticos',
        default=False,
        help='Incluir información de cuentas analíticas'
    )
    centralize_journals = fields.Boolean(
        string='Centralizar Diarios',
        default=False,
        help='Agrupar movimientos por diario en una sola línea'
    )
    include_unposted = fields.Boolean(
        string='Incluir No Publicados',
        default=False,
        help='Incluir asientos en borrador'
    )

    # Estado del reporte
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('computing', 'Calculando'),
        ('computed', 'Calculado'),
        ('error', 'Error')
    ], string='Estado', default='draft', required=True)

    # Líneas del Mayor
    line_ids = fields.One2many(
        'account.general.ledger.line',
        'ledger_id',
        string='Líneas del Mayor'
    )

    # Resumen
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
    total_balance = fields.Monetary(
        string='Balance Total',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # Estadísticas
    account_count = fields.Integer(
        string='Número de Cuentas',
        compute='_compute_statistics',
        store=True
    )
    move_count = fields.Integer(
        string='Número de Movimientos',
        compute='_compute_statistics',
        store=True
    )

    # Cache y Performance
    cache_key = fields.Char(string='Cache Key', compute='_compute_cache_key')
    last_compute = fields.Datetime(string='Última Actualización')

    # Compañía
    company_id = fields.Many2one('res.company', string='Compañía', required=True, default=lambda self: self.env.company)

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
                record.name = f"Mayor Analítico - {record.company_id.name}: {record.date_from} al {record.date_to}"
            else:
                record.name = f"Mayor Analítico - {record.company_id.name}"

    @api.depends_context('company')
    @api.depends('date_from', 'date_to', 'company_id', 'account_ids', 'partner_ids')
    def _compute_cache_key(self):
        for record in self:
            key_data = {
                'date_from': str(record.date_from),
                'date_to': str(record.date_to),
                'company_id': record.company_id.id,
                'account_ids': record.account_ids.ids,
                'partner_ids': record.partner_ids.ids,
                'show_partner': record.show_partner_details,
                'include_unposted': record.include_unposted
            }
            record.cache_key = json.dumps(key_data, sort_keys=True)

    @api.depends('line_ids', 'line_ids.debit', 'line_ids.credit', 'line_ids.balance')
    def _compute_totals(self):
        """Calcula los totales generales"""
        # Optimización: usar with_context para prefetch
        record = record.with_context(prefetch_fields=False)

        for record in self:
            # Filtrar solo líneas de movimiento (no saldos iniciales ni totales)
            move_lines = record.line_ids.filtered(lambda l: l.line_type == 'move')
            record.total_debit = sum(move_lines.mapped('debit'))
            record.total_credit = sum(move_lines.mapped('credit'))
            record.total_balance = record.total_debit - record.total_credit

    @api.depends('line_ids')
    def _compute_statistics(self):
        """Calcula estadísticas del reporte"""
        for record in self:
            # Contar cuentas únicas
            accounts = record.line_ids.mapped('account_id')
            record.account_count = len(accounts)

            # Contar movimientos
            move_lines = record.line_ids.filtered(lambda l: l.line_type == 'move')
            record.move_count = len(move_lines)

    def action_compute_ledger(self):
        """
        Acción principal para calcular el mayor analítico.
        Llama al service layer para obtener los datos optimizados.
        """
        # Optimización: usar with_context para prefetch
        self = self.with_context(prefetch_fields=False)

        self.ensure_one()

        try:
            # Cambiar estado a computing
            self.write({'state': 'computing', 'last_compute': fields.Datetime.now()})

            # Limpiar líneas anteriores
            self.line_ids.unlink()

            # Obtener el servicio
            from .services.general_ledger_service import GeneralLedgerService
            service = GeneralLedgerService(self.env)

            # Preparar filtros
            filters = {
                'date_from': self.date_from,
                'date_to': self.date_to,
                'company_id': self.company_id.id,
                'account_ids': self.account_ids.ids,
                'account_group_ids': self.account_group_ids.ids,
                'partner_ids': self.partner_ids.ids,
                'show_initial_balance': self.show_initial_balance,
                'show_partner_details': self.show_partner_details,
                'show_analytic_details': self.show_analytic_details,
                'centralize_journals': self.centralize_journals,
                'include_unposted': self.include_unposted,
            }

            # Calcular el mayor
            result = service.compute_general_ledger(**filters)

            # Crear las líneas
            sequence = 1
            for account_data in result['accounts']:
                # Saldo inicial si aplica
                if self.show_initial_balance and account_data.get('initial_balance'):
                    self.env['account.general.ledger.line'].create({
                        'ledger_id': self.id,
                        'sequence': sequence,
                        'account_id': account_data['account_id'],
                        'account_code': account_data['account_code'],
                        'account_name': account_data['account_name'],
                        'date': self.date_from,
                        'name': 'Saldo Inicial',
                        'line_type': 'initial',
                        'debit': 0.0,
                        'credit': 0.0,
                        'balance': account_data['initial_balance'],
                        'cumulative_balance': account_data['initial_balance'],
                    })
                    sequence += 1

                # Movimientos de la cuenta
                cumulative_balance = account_data.get('initial_balance', 0.0)

                for move in account_data['moves']:
                    cumulative_balance += (move['debit'] - move['credit'])

                    self.env['account.general.ledger.line'].create({
                        'ledger_id': self.id,
                        'sequence': sequence,
                        'account_id': account_data['account_id'],
                        'account_code': account_data['account_code'],
                        'account_name': account_data['account_name'],
                        'move_id': move.get('move_id'),
                        'move_line_id': move.get('move_line_id'),
                        'date': move['date'],
                        'journal_code': move.get('journal_code', ''),
                        'move_name': move.get('move_name', ''),
                        'name': move['name'],
                        'partner_id': move.get('partner_id'),
                        'partner_name': move.get('partner_name', ''),
                        'ref': move.get('ref', ''),
                        'line_type': 'move',
                        'debit': move['debit'],
                        'credit': move['credit'],
                        'balance': move['debit'] - move['credit'],
                        'cumulative_balance': cumulative_balance,
                        'analytic_account_id': move.get('analytic_account_id'),
                        'analytic_account_name': move.get('analytic_account_name', ''),
                    })
                    sequence += 1

                # Total por cuenta
                self.env['account.general.ledger.line'].create({
                    'ledger_id': self.id,
                    'sequence': sequence,
                    'account_id': account_data['account_id'],
                    'account_code': account_data['account_code'],
                    'account_name': account_data['account_name'],
                    'date': self.date_to,
                    'name': f"Total {account_data['account_name']}",
                    'line_type': 'total',
                    'debit': account_data['total_debit'],
                    'credit': account_data['total_credit'],
                    'balance': account_data['total_debit'] - account_data['total_credit'],
                    'cumulative_balance': cumulative_balance,
                    'is_total_line': True,
                })
                sequence += 1

            # Actualizar estado
            self.write({'state': 'computed'})

            # Retornar acción para mostrar el reporte
            return {
                'type': 'ir.actions.client',
                'tag': 'general_ledger_report',
                'context': {
                    'active_id': self.id,
                    'active_model': self._name,
                }
            }

        except Exception as e:
            _logger.error(f"Error computing general ledger: {str(e)}")
            self.write({
                'state': 'error',
                'validation_errors': str(e)
            })
            raise UserError(_("Error al calcular el mayor analítico: %s") % str(e))

    def action_export_excel(self):
        """Exporta el mayor a Excel con formato profesional"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular el mayor antes de exportar."))

        # Llamar al método del service
        from .services.general_ledger_service import GeneralLedgerService
        service = GeneralLedgerService(self.env)
        return service.export_to_excel(self)

    def action_export_pdf(self):
        """Exporta el mayor a PDF"""
        self.ensure_one()
        if self.state != 'computed':
            raise UserError(_("Debe calcular el mayor antes de exportar."))

        return self.env.ref('l10n_cl_financial_reports.action_report_general_ledger').report_action(self)

    def action_refresh(self):
        """Recalcula el mayor"""
        return self.action_compute_ledger()

    def action_print_by_partner(self):
        """Imprime el mayor agrupado por socio"""
        self.ensure_one()
        self.show_partner_details = True
        return self.action_compute_ledger()

    @api.model_create_multi
    def create(self, vals_list):
        """Override create para establecer valores por defecto en batch"""
        for vals in vals_list:
            if 'company_id' not in vals:
                vals['company_id'] = self.env.company.id
        return super().create(vals_list)


class GeneralLedgerLine(models.Model):
    """Líneas del Mayor Analítico"""
    _name = 'account.general.ledger.line'
    _description = 'Línea de Mayor Analítico'
    _order = 'sequence, date, id'

    ledger_id = fields.Many2one(
        'account.general.ledger',
        string='Mayor',
        required=True,
        ondelete='cascade'
    )

    sequence = fields.Integer(
        string='Secuencia',
        default=10
    )

    # Tipo de línea
    line_type = fields.Selection([
        ('initial', 'Saldo Inicial'),
        ('move', 'Movimiento'),
        ('total', 'Total Cuenta')
    ], string='Tipo', required=True, default='move')

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
        string='Nombre Cuenta',
        required=True
    )

    # Datos del movimiento
    move_id = fields.Many2one(
        'account.move',
        string='Asiento'
    )
    move_line_id = fields.Many2one(
        'account.move.line',
        string='Apunte Contable'
    )
    date = fields.Date(
        string='Fecha',
        required=True
    )
    journal_code = fields.Char(
        string='Diario'
    )
    move_name = fields.Char(
        string='Número'
    )
    name = fields.Char(
        string='Descripción',
        required=True
    )
    ref = fields.Char(
        string='Referencia'
    )

    # Datos del socio
    partner_id = fields.Many2one(
        'res.partner',
        string='Socio'
    )
    partner_name = fields.Char(
        string='Nombre Socio'
    )

    # Valores monetarios
    debit = fields.Monetary(
        string='Debe',
        currency_field='currency_id'
    )
    credit = fields.Monetary(
        string='Haber',
        currency_field='currency_id'
    )
    balance = fields.Monetary(
        string='Balance',
        currency_field='currency_id',
        help='Diferencia entre debe y haber'
    )
    cumulative_balance = fields.Monetary(
        string='Saldo Acumulado',
        currency_field='currency_id',
        help='Saldo acumulado hasta esta línea'
    )

    # Datos analíticos
    analytic_account_id = fields.Many2one(
        'account.analytic.account',
        string='Cuenta Analítica'
    )
    analytic_account_name = fields.Char(
        string='Nombre Cuenta Analítica'
    )

    # Moneda
    currency_id = fields.Many2one(
        'res.currency',
        related='ledger_id.currency_id',
        string='Moneda'
    )

    # Indicadores
    is_total_line = fields.Boolean(
        string='Es Línea de Total',
        default=False
    )

    def action_open_move(self):
        """Abre el asiento contable relacionado"""
        self.ensure_one()
        if self.move_id:
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'account.move',
                'res_id': self.move_id.id,
                'view_mode': 'form',
                'target': 'current',
            }
        return False
