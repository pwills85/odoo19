# -*- coding: utf-8 -*-
import logging
from odoo import models, api, _

_logger = logging.getLogger(__name__)

class KpiService(models.AbstractModel):
    """
    Service layer to handle the business logic related to Financial KPIs.
    """
    _name = 'afr.kpi.service'
    _description = 'Financial Report KPI Service'

    def get_kpi_values(self, kpi_ids):
        """
        Computes the values for a given set of KPIs efficiently.

        :param kpi_ids: A list of IDs of the KPIs to compute.
        :return: A dictionary mapping KPI ID to its computed value and other info.
        """
        # Optimización: usar with_context para prefetch
        kpi = kpi.with_context(prefetch_fields=False)

        kpis = self.env['financial.report.kpi'].browse(kpi_ids)
        kpi_values = {}
        
        # TODO: Refactorizar para usar browse en batch fuera del loop
        
        # Group KPIs by report to process them in batches
        kpis_by_report = {}
        for kpi in kpis:
            report_id = kpi.report_line_id.report_id.id
            if report_id not in kpis_by_report:
                kpis_by_report[report_id] = []
            kpis_by_report[report_id].append(kpi)

        # Process each batch
        for report_id, report_kpis in kpis_by_report.items():
            report = self.env['account.report'].browse(report_id)
            options = report._get_options(None)
            lines = report._get_lines(options)
            
            # Create a mapping of line_id -> line for quick lookup
            lines_map = {line.get('id'): line for line in lines}

            for kpi in report_kpis:
                target_line_id_str = kpi.report_line_id._get_report_line_id_str()
                target_line = lines_map.get(target_line_id_str)

                value = 0.0
                formatted_value = ""
                if target_line and target_line.get('columns'):
                    first_column = target_line['columns'][0]
                    value = first_column.get('no_format', 0.0)
                    formatted_value = first_column.get('name', '')

                kpi_values[kpi.id] = {
                    'name': kpi.name,
                    'value': formatted_value,
                    'raw_value': value,
                    'report_id': report.id,
                    'report_line_id': kpi.report_line_id.id,
                    'report_name': report.name,
                }
        
        return kpi_values
