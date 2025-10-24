# -*- coding: utf-8 -*-
from odoo import api, models, _
from odoo.exceptions import UserError
import logging
from collections import defaultdict

_logger = logging.getLogger(__name__)

class FinancialReportService(models.AbstractModel):
    _name = 'financial.report.service'
    _description = 'Servicio para Reportes Financieros'

    def get_balance_eight_columns_data(self, report):
        """
        Punto de entrada principal para calcular los datos del informe.
        """
        # 1. Obtener saldos iniciales y del período usando ORM
        account_lines = self._get_account_balances(report)

        # 2. Clasificar saldos en las 8 columnas
        classified_lines = self._classify_balances(account_lines)

        # 3. Calcular totales
        totals = self._calculate_totals(classified_lines)

        return classified_lines, totals

    def _get_account_balances(self, report):
        """
        Obtiene los saldos usando read_group y search_fetch para máxima eficiencia.
        """
        # Optimización: usar with_context para prefetch
        report = report.with_context(prefetch_fields=False)

        AccountMoveLine = self.env['account.move.line']
        
        base_domain = [('company_id', '=', report.company_id.id)]
        if report.target_move == 'posted':
            base_domain.append(('move_id.state', '=', 'posted'))

        # Saldos iniciales
        initial_domain = base_domain + [('date', '<', report.date_from)]
        initial_data = AccountMoveLine.read_group(
            initial_domain, ['debit', 'credit'], ['account_id']
        )
        initial_balances = {
            data['account_id'][0]: {
                'debit': data['debit'], 'credit': data['credit']
            } for data in initial_data
        }

        # Movimientos del período
        period_domain = base_domain + [('date', '>=', report.date_from), ('date', '<=', report.date_to)]
        period_data = AccountMoveLine.read_group(
            period_domain, ['debit', 'credit'], ['account_id']
        )
        period_balances = {
            data['account_id'][0]: {
                'debit': data['debit'], 'credit': data['credit']
            } for data in period_data
        }

        # Combinar y obtener datos de cuentas
        all_account_ids = list(set(initial_balances.keys()) | set(period_balances.keys()))
        accounts_data = self.env['account.account'].search_fetch(
            [('id', 'in', all_account_ids)],
            ['code', 'name', 'account_type'])
        
        lines = {}
        for acc_id, code, name, acc_type in accounts_data:
            initial = initial_balances.get(acc_id, {'debit': 0, 'credit': 0})
            period = period_balances.get(acc_id, {'debit': 0, 'credit': 0})
            
            lines[acc_id] = {
                'id': acc_id,
                'code': code,
                'name': name,
                'account_type': acc_type,
                'initial_debit': initial['debit'],
                'initial_credit': initial['credit'],
                'period_debit': period['debit'],
                'period_credit': period['credit'],
            }
        return lines

    def _classify_balances(self, account_lines):
        """
        Clasifica los saldos en las 8 columnas según la normativa chilena.
        """
        classified_lines = []
        for acc_id, line in account_lines.items():
            # Calcular saldos finales
            final_debit = line['initial_debit'] + line['period_debit']
            final_credit = line['initial_credit'] + line['period_credit']
            final_balance = final_debit - final_credit

            line.update({
                'final_debit': final_debit if final_balance > 0 else 0,
                'final_credit': abs(final_balance) if final_balance < 0 else 0,
                'asset': 0, 'liability': 0, 'loss': 0, 'gain': 0,
            })

            # Clasificar en Activo/Pasivo (Inventario) o Pérdida/Ganancia (Resultados)
            asset_types = ('asset_receivable', 'asset_current', 'asset_non_current', 'asset_prepayment', 'asset_fixed')
            liability_types = ('liability_payable', 'liability_credit_card', 'liability_current', 'liability_non_current')
            equity_types = ('equity', 'equity_unaffected')
            income_types = ('income', 'income_other')
            expense_types = ('expense', 'expense_depreciation', 'expense_direct_cost')

            if line['account_type'] in asset_types:
                line['asset'] = final_balance
            elif line['account_type'] in liability_types or line['account_type'] in equity_types:
                line['liability'] = abs(final_balance)
            elif line['account_type'] in expense_types:
                line['loss'] = final_balance
            elif line['account_type'] in income_types:
                line['gain'] = abs(final_balance)
            
            classified_lines.append(line)
        
        return sorted(classified_lines, key=lambda x: x['code'])

    def _calculate_totals(self, classified_lines):
        """Calcula los totales para todas las columnas."""
        totals = defaultdict(float)
        for line in classified_lines:
            for key, value in line.items():
                if isinstance(value, (int, float)):
                    totals[key] += value
        
        # Validar cuadratura
        result_balance = totals['gain'] - totals['loss']
        inventory_balance = totals['asset'] - totals['liability']
        
        totals['result_balance'] = result_balance
        totals['inventory_balance'] = inventory_balance
        totals['is_balanced'] = abs(result_balance - inventory_balance) < 0.01
        
        return totals

    def get_balance_sheet_data(self, report):
        """
        Genera los datos para un Balance General Estándar.
        Reutiliza la lógica del balance de 8 columnas.
        """
        _, totals = self.get_balance_eight_columns_data(report)
        
        balance_sheet = {
            'asset': {'name': 'Activo', 'total': totals['asset'], 'lines': []},
            'liability': {'name': 'Pasivo', 'total': totals['liability'], 'lines': []},
            'equity': {'name': 'Patrimonio', 'total': totals['result_balance'], 'lines': []},
        }
        # Esta es una simplificación. Un reporte real agruparía por tipo de cuenta.
        return balance_sheet

    def get_income_statement_data(self, report):
        """
        Genera los datos para un Estado de Resultados.
        Reutiliza la lógica del balance de 8 columnas.
        """
        _, totals = self.get_balance_eight_columns_data(report)
        
        income_statement = {
            'income': {'name': 'Ingresos', 'total': totals['gain'], 'lines': []},
            'expense': {'name': 'Costos y Gastos', 'total': totals['loss'], 'lines': []},
            'result': {'name': 'Resultado del Ejercicio', 'total': totals['result_balance']},
        }
        return income_statement

    def get_trial_balance_data(self, report):
        """
        Genera los datos para un Balance de Comprobación y Saldos (6 columnas).
        """
        lines, totals = self.get_balance_eight_columns_data(report)
        
        # Simplemente seleccionamos las columnas relevantes
        trial_balance_lines = []
        for line in lines:
            trial_balance_lines.append({
                'code': line['code'],
                'name': line['name'],
                'initial_debit': line['initial_debit'],
                'initial_credit': line['initial_credit'],
                'period_debit': line['period_debit'],
                'period_credit': line['period_credit'],
                'final_debit': line['final_debit'],
                'final_credit': line['final_credit'],
            })
        
        return trial_balance_lines, totals

    def get_general_ledger_data(self, report):
        """
        Genera los datos para el Libro Mayor.
        """
        # Optimización: usar with_context para prefetch
        line = line.with_context(prefetch_fields=False)

        # Optimización: usar with_context para prefetch
        line = line.with_context(prefetch_fields=False)

        AccountMoveLine = self.env['account.move.line']
        domain = [
            ('company_id', '=', report.company_id.id),
            ('date', '>=', report.date_from),
            ('date', '<=', report.date_to),
        ]
        if report.target_move == 'posted':
            domain.append(('move_id.state', '=', 'posted'))
            
        lines = AccountMoveLine.search(domain, order='date, move_id')
        
        # Esta es una simplificación. Un libro mayor real agruparía por cuenta.
        ledger_lines = []
        for line in lines:
            ledger_lines.append({
                'date': line.date,
                'move': line.move_id.name,
                'journal': line.journal_id.name,
                'account': line.account_id.code,
                'partner': line.partner_id.name,
                'label': line.name,
                'debit': line.debit,
                'credit': line.credit,
                'balance': line.balance,
            })
            
        return ledger_lines, {} # El libro mayor no suele tener una única línea de total