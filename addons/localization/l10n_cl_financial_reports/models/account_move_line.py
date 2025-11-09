# -*- coding: utf-8 -*-
# Copyright 2019 ACSONE SA/NV (<http://acsone.eu>)
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).-
from collections import defaultdict
import logging

from odoo import api, fields, models
from odoo.fields import Command

_logger = logging.getLogger(__name__)

class AccountMoveLine(models.Model):
    _inherit = "account.move.line"

    analytic_account_ids = fields.Many2many("account.analytic.account",
        compute="_compute_analytic_account_ids",
        compute_sudo=True,
        store=True,
        string="Analytic Accounts",
        index=True,
        help="Campo computado analytic_account_ids")

    @api.depends("analytic_distribution")
    def _compute_analytic_account_ids(self):
        # Prefetch all involved analytic accounts
        lines_by_analytic_account = defaultdict(lambda: self.env["account.move.line"])
        for line in self.filtered("analytic_distribution"):
            for account_id_str in line.analytic_distribution:
                # In Odoo 18, analytic_distribution keys are strings of account IDs
                try:
                    account_id = int(account_id_str)
                    lines_by_analytic_account[account_id] += line
                except (ValueError, TypeError):
                    # Handle cases where the key is not a simple integer ID
                    continue

        # Use a single search to find all existing analytic accounts at once
        existing_account_ids = set(
            self.env["account.analytic.account"]
            .search([("id", "in", list(lines_by_analytic_account.keys()))])
            .ids
        )

        # Update the records in batches per analytic account
        for account_id, lines in lines_by_analytic_account.items():
            if account_id in existing_account_ids:
                # Use Command.set for efficiency to replace all existing records
                lines.write({"analytic_account_ids": [Command.set([account_id])]})
            else:
                # If account was deleted, ensure the relation is cleared
                lines.write({"analytic_account_ids": [Command.clear()]})

        # Clear the field for lines that no longer have analytic distribution
        (self - self.filtered("analytic_distribution")).analytic_account_ids = [
            Command.clear()
        ]

    def init(self):
        """
            The join between accounts_partners subquery and account_move_line
            can be heavy to compute on big databases.
            Join sample:
                JOIN
                    account_move_line ml
                        ON ap.account_id = ml.account_id
                        AND ml.date < '2018-12-30'
                        AND ap.partner_id = ml.partner_id
                        AND ap.include_initial_balance = TRUE
            By adding the following index, performances are strongly increased.
        :return:
        """
        self._cr.execute(
            "SELECT indexname FROM pg_indexes WHERE indexname = %s",
            ("account_move_line_account_id_partner_id_index",))
        if not self._cr.fetchone():
            self._cr.execute(
                """
            CREATE INDEX account_move_line_account_id_partner_id_index
            ON account_move_line (account_id, partner_id)"""
            )

    @api.model
    def search_count(self, domain, limit=None):
        # In Big DataBase every time you change the domain widget this method
        # takes a lot of time. This improves performance
        if self.env.context.get("skip_search_count"):
            return 0
        return super().search_count(domain, limit=limit)
