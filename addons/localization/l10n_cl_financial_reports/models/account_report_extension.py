# -*- coding: utf-8 -*-
from odoo import models, fields, api, _
import logging

_logger = logging.getLogger(__name__)

class AccountReportLine(models.Model):
    """ Inherits account.report.line to add KPI management capabilities. """
    _inherit = "account.report.line"

    is_kpi = fields.Boolean(
        string="Is KPI",
        compute="_compute_is_kpi",
        compute_sudo=True, 
        inverse="_inverse_is_kpi",
        help="True if this report line is configured as a KPI for the current user."
    )

    def _compute_is_kpi(self):
        """Método compute optimizado con manejo de errores"""
        _logger.debug("Computing _compute_is_kpi for %d records", len(self))
        
        try:
            """ Check if a KPI exists for this line and the current user. """
            if not self.ids:
                self.is_kpi = False
                return
        except Exception as e:
            _logger.error("Error in _compute_is_kpi: %s", str(e))
            # Mantener valores por defecto en caso de error

        kpi_line_ids = self.env['financial.report.kpi'].search([
            ('user_id', '=', self.env.user.id),
            ('report_line_id', 'in', self.ids)
        ]).mapped('report_line_id').ids

        for line in self.with_context(prefetch_fields=False):
            line.is_kpi = line.id in kpi_line_ids

    def _inverse_is_kpi(self):
        """ Create or delete a KPI based on the is_kpi flag. """
        for line in self.with_context(prefetch_fields=False):
            # Search for an existing KPI for the current user and line
            kpi = self.env['financial.report.kpi'].search([
                ('user_id', '=', self.env.user.id),
                ('report_line_id', '=', line.id)
            ], limit=1)

            if line.is_kpi and not kpi:
                # If is_kpi is True and no KPI exists, create one.
                self.env['financial.report.kpi'].create({
                    'name': line.name or _('Untitled KPI'),
                    'report_line_id': line.id,
                    # user_id is handled by default in financial.report.kpi model
                })
            elif not line.is_kpi and kpi:
                # If is_kpi is False and a KPI exists, delete it.
                kpi.unlink()

class AccountReport(models.Model):
    _inherit = 'account.report'

    def _get_options(self, previous_options=None):
        options = super()._get_options(previous_options)
        # Add budget columns only to the main Profit and Loss report
        if self.id == self.env.ref('account.profit_and_loss').id:
            options['budgets'] = True
        return options

    def _get_report_line_dict(self, options, line_id_val, financial_line, level_offset):
        res = super()._get_report_line_dict(options, line_id_val, financial_line, level_offset)
        
        # Add the database ID and KPI status to the dictionary for the frontend
        res['res_id'] = financial_line.id
        res['is_kpi'] = financial_line.is_kpi
        
        return res

