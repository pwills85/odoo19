# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo import fields, models, api


class FinancialReportKpi(models.Model):
    """ Represents a Key Performance Indicator (KPI) that can be displayed on a dashboard.

    A KPI is essentially a saved reference to a specific line in a financial report,
    allowing for quick visualization of key figures.
    """
    _name = "financial.report.kpi"
    _description = "Financial Report KPI"
    _order = "sequence, id"

    name = fields.Char(string="Name", required=True, translate=True)
    sequence = fields.Integer(default=10)

    report_line_id = fields.Many2one(
        comodel_name="account.report.line",
        string="Report Line",
        required=True,
        ondelete="cascade",
        help="The specific financial report line this KPI is based on.")

    user_id = fields.Many2one(
        comodel_name="res.users",
        string="User",
        required=True,
        default=lambda self: self.env.user,
        ondelete="cascade",
        help="The user who owns this KPI. KPIs are personal to each user.")

    @api.model
    def get_kpi_values(self, kpi_ids):
        """
        Computes the values for a given set of KPIs by delegating to the KPI service.
        """
        kpi_service = self.env['afr.kpi.service'](self.env)
        return kpi_service.get_kpi_values(kpi_ids)
