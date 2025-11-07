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


# ========== FASE 1: Dashboard KPI Service with Cache Integration ==========


from odoo.exceptions import UserError
from datetime import datetime, date
import json
import time


class FinancialReportKpiService(models.Model):
    """
    Servicio para cálculo de KPIs financieros del dashboard basados en F29.

    Calcula indicadores clave de rendimiento (KPIs) basados en los formularios
    F29 (IVA mensual) y utiliza cache para optimizar performance.

    KPIs disponibles:
    - IVA Débito Fiscal: Total IVA débito del período
    - IVA Crédito Fiscal: Total IVA crédito del período
    - Ventas Netas: Total ventas (afectas + exentas) del período
    - Compras Netas: Total compras (afectas + exentas + activo fijo) del período
    - PPM Pagado: Total pagos provisionales mensuales del período
    """

    _name = 'account.financial.report.kpi.service'
    _description = 'Servicio de Cálculo de KPIs Dashboard'

    @api.model
    def compute_kpis(self, company, period_start, period_end):
        """
        Calcula KPIs financieros para un período determinado con cache.

        Args:
            company (res.company): Compañía para la cual calcular KPIs
            period_start (date or str): Fecha inicio del período (YYYY-MM-DD)
            period_end (date or str): Fecha fin del período (YYYY-MM-DD)

        Returns:
            dict: Diccionario con KPIs calculados:
                {
                    'iva_debito_fiscal': float,
                    'iva_credito_fiscal': float,
                    'ventas_netas': float,
                    'compras_netas': float,
                    'ppm_pagado': float,
                    'cache_hit': bool,  # Indica si se usó cache
                    'calculation_time_ms': int,  # Tiempo de cálculo en ms
                    'period_start': str,  # Período consultado
                    'period_end': str,
                    'company_id': int,
                    'company_name': str,
                }

        Example:
            >>> kpi_service = env['account.financial.report.kpi.service']
            >>> kpis = kpi_service.compute_kpis(
            ...     company=env.company,
            ...     period_start='2024-01-01',
            ...     period_end='2024-12-31'
            ... )
            >>> print(f"Ventas Netas: {kpis['ventas_netas']}")
        """
        start_time = time.time()

        # Normalizar fechas a string YYYY-MM-DD
        if isinstance(period_start, date):
            period_start = period_start.strftime('%Y-%m-%d')
        if isinstance(period_end, date):
            period_end = period_end.strftime('%Y-%m-%d')

        # Validar inputs
        if not company:
            raise UserError(_('Debe especificar una compañía para calcular KPIs.'))

        try:
            datetime.strptime(period_start, '%Y-%m-%d')
            datetime.strptime(period_end, '%Y-%m-%d')
        except ValueError:
            raise UserError(
                _('Las fechas deben estar en formato YYYY-MM-DD.\n'
                  'Inicio: %s, Fin: %s') % (period_start, period_end)
            )

        # Intentar obtener desde cache
        from odoo.addons.l10n_cl_financial_reports.models.services.cache_service import get_cache_service

        cache = get_cache_service()
        cache_key = f"kpi_dashboard_{period_start}_{period_end}"

        cached_result = cache.get(cache_key, company_id=company.id)
        if cached_result:
            cached_result['cache_hit'] = True
            cached_result['calculation_time_ms'] = int((time.time() - start_time) * 1000)
            _logger.info(
                "KPI Dashboard: Cache HIT para company=%s, period=%s to %s (tiempo=%dms)",
                company.id, period_start, period_end,
                cached_result['calculation_time_ms']
            )
            return cached_result

        # Cache MISS: Calcular KPIs desde datos
        _logger.info(
            "KPI Dashboard: Cache MISS para company=%s, period=%s to %s. Calculando...",
            company.id, period_start, period_end
        )

        kpis = self._calculate_kpis_from_f29(company, period_start, period_end)

        # Agregar metadata
        kpis['cache_hit'] = False
        kpis['calculation_time_ms'] = int((time.time() - start_time) * 1000)
        kpis['period_start'] = period_start
        kpis['period_end'] = period_end
        kpis['company_id'] = company.id
        kpis['company_name'] = company.name

        # Guardar en cache (TTL 900s = 15 minutos)
        cache.set(cache_key, kpis, ttl=900, company_id=company.id)

        _logger.info(
            "KPI Dashboard: Calculado y cacheado para company=%s (tiempo=%dms)",
            company.id, kpis['calculation_time_ms']
        )

        # Logging estructurado JSON
        log_data = {
            "module": "l10n_cl_financial_reports",
            "action": "compute_kpis",
            "company_id": company.id,
            "period_start": period_start,
            "period_end": period_end,
            "duration_ms": kpis['calculation_time_ms'],
            "cache_hit": False,
            "status": "success",
            "kpis": {
                "iva_debito_fiscal": kpis['iva_debito_fiscal'],
                "iva_credito_fiscal": kpis['iva_credito_fiscal'],
                "ventas_netas": kpis['ventas_netas'],
                "compras_netas": kpis['compras_netas'],
                "ppm_pagado": kpis['ppm_pagado'],
            }
        }
        _logger.info(json.dumps(log_data))

        return kpis

    @api.model
    def _calculate_kpis_from_f29(self, company, period_start, period_end):
        """
        Calcula KPIs desde registros F29 usando SQL optimizado.

        Args:
            company (res.company): Compañía
            period_start (str): Fecha inicio (YYYY-MM-DD)
            period_end (str): Fecha fin (YYYY-MM-DD)

        Returns:
            dict: KPIs calculados (sin metadata)
        """
        # Buscar registros F29 en el período
        f29_records = self.env['l10n_cl.f29'].search([
            ('company_id', '=', company.id),
            ('period_date', '>=', period_start),
            ('period_date', '<=', period_end),
            ('state', 'in', ['confirmed', 'sent', 'accepted']),  # Solo declaraciones válidas
        ])

        if not f29_records:
            _logger.warning(
                "KPI Dashboard: No se encontraron registros F29 válidos para "
                "company=%s, period=%s to %s",
                company.id, period_start, period_end
            )
            # Retornar KPIs en 0
            return {
                'iva_debito_fiscal': 0.0,
                'iva_credito_fiscal': 0.0,
                'ventas_netas': 0.0,
                'compras_netas': 0.0,
                'ppm_pagado': 0.0,
            }

        # Calcular KPIs mediante agregación
        iva_debito_fiscal = sum(f29_records.mapped('debito_fiscal'))
        iva_credito_fiscal = sum(f29_records.mapped('credito_fiscal'))

        # Ventas Netas: afectas + exentas + exportación
        ventas_netas = sum(
            f29_records.mapped('ventas_afectas')
        ) + sum(
            f29_records.mapped('ventas_exentas')
        ) + sum(
            f29_records.mapped('ventas_exportacion')
        )

        # Compras Netas: afectas + exentas + activo fijo
        compras_netas = sum(
            f29_records.mapped('compras_afectas')
        ) + sum(
            f29_records.mapped('compras_exentas')
        ) + sum(
            f29_records.mapped('compras_activo_fijo')
        )

        # PPM Pagado: mes + voluntario
        ppm_pagado = sum(
            f29_records.mapped('ppm_mes')
        ) + sum(
            f29_records.mapped('ppm_voluntario')
        )

        return {
            'iva_debito_fiscal': float(iva_debito_fiscal),
            'iva_credito_fiscal': float(iva_credito_fiscal),
            'ventas_netas': float(ventas_netas),
            'compras_netas': float(compras_netas),
            'ppm_pagado': float(ppm_pagado),
        }

    @api.model
    def invalidate_kpi_cache(self, company, period_start=None, period_end=None):
        """
        Invalida el cache de KPIs para un período específico o toda la compañía.

        Se debe llamar cuando se actualice/cree/elimine un F29 para mantener
        el cache sincronizado.

        Args:
            company (res.company): Compañía
            period_start (str, optional): Fecha inicio. Si no se especifica, invalida todo.
            period_end (str, optional): Fecha fin. Si no se especifica, invalida todo.

        Example:
            >>> kpi_service = env['account.financial.report.kpi.service']
            >>> # Invalidar cache de un período específico
            >>> kpi_service.invalidate_kpi_cache(
            ...     company=env.company,
            ...     period_start='2024-01-01',
            ...     period_end='2024-12-31'
            ... )
            >>> # Invalidar TODO el cache de KPIs de la compañía
            >>> kpi_service.invalidate_kpi_cache(company=env.company)
        """
        from odoo.addons.l10n_cl_financial_reports.models.services.cache_service import get_cache_service

        cache = get_cache_service()

        if period_start and period_end:
            # Invalidar cache de un período específico
            cache_key = f"kpi_dashboard_{period_start}_{period_end}"
            cache.invalidate(f"finrep:{company.id}:{cache_key}")
            _logger.info(
                "KPI Dashboard: Cache invalidado para company=%s, period=%s to %s",
                company.id, period_start, period_end
            )
        else:
            # Invalidar TODO el cache de KPIs de la compañía
            cache.invalidate(f"finrep:{company.id}:kpi_dashboard_*")
            _logger.info(
                "KPI Dashboard: Cache invalidado COMPLETO para company=%s",
                company.id
            )

    @api.model
    def get_kpi_trends(self, company, period_start, period_end, granularity='month'):
        """
        Calcula tendencias de KPIs (serie temporal) para el dashboard.

        Args:
            company (res.company): Compañía
            period_start (str): Fecha inicio (YYYY-MM-DD)
            period_end (str): Fecha fin (YYYY-MM-DD)
            granularity (str): Granularidad ('month', 'quarter', 'year')

        Returns:
            list: Lista de diccionarios con KPIs por período:
                [
                    {
                        'period': '2024-01',
                        'iva_debito_fiscal': 1000000,
                        'iva_credito_fiscal': 800000,
                        ...
                    },
                    ...
                ]

        Example:
            >>> kpi_service = env['account.financial.report.kpi.service']
            >>> trends = kpi_service.get_kpi_trends(
            ...     company=env.company,
            ...     period_start='2024-01-01',
            ...     period_end='2024-12-31',
            ...     granularity='month'
            ... )
            >>> for trend in trends:
            ...     print(f"{trend['period']}: Ventas {trend['ventas_netas']}")
        """
        from dateutil.relativedelta import relativedelta

        # Convertir a datetime
        start_date = datetime.strptime(period_start, '%Y-%m-%d')
        end_date = datetime.strptime(period_end, '%Y-%m-%d')

        trends = []

        if granularity == 'month':
            delta = relativedelta(months=1)
            date_format = '%Y-%m'
        elif granularity == 'quarter':
            delta = relativedelta(months=3)
            date_format = '%Y-Q'
        elif granularity == 'year':
            delta = relativedelta(years=1)
            date_format = '%Y'
        else:
            raise UserError(_('Granularidad inválida: %s. Use month, quarter o year.') % granularity)

        current_date = start_date
        while current_date <= end_date:
            # Calcular período end (último día del mes/quarter/año)
            if granularity == 'month':
                period_end_date = current_date + relativedelta(months=1, days=-1)
            elif granularity == 'quarter':
                period_end_date = current_date + relativedelta(months=3, days=-1)
            else:  # year
                period_end_date = current_date + relativedelta(years=1, days=-1)

            # No exceder end_date
            if period_end_date > end_date:
                period_end_date = end_date

            # Calcular KPIs para este sub-período
            kpis = self.compute_kpis(
                company=company,
                period_start=current_date.strftime('%Y-%m-%d'),
                period_end=period_end_date.strftime('%Y-%m-%d')
            )

            trend_data = {
                'period': current_date.strftime(date_format),
                'period_start': current_date.strftime('%Y-%m-%d'),
                'period_end': period_end_date.strftime('%Y-%m-%d'),
                'iva_debito_fiscal': kpis['iva_debito_fiscal'],
                'iva_credito_fiscal': kpis['iva_credito_fiscal'],
                'ventas_netas': kpis['ventas_netas'],
                'compras_netas': kpis['compras_netas'],
                'ppm_pagado': kpis['ppm_pagado'],
            }
            trends.append(trend_data)

            # Avanzar al siguiente período
            current_date += delta

        return trends
