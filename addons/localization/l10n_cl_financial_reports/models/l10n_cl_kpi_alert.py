# -*- coding: utf-8 -*-

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging
from datetime import datetime, timedelta

_logger = logging.getLogger(__name__)


class L10nClKpiAlert(models.Model):
    """
    Sistema de alertas automáticas para KPIs financieros.

    Permite configurar umbrales para diferentes KPIs y enviar notificaciones
    cuando se superan los límites establecidos.
    """

    _name = 'l10n_cl.kpi.alert'
    _description = 'Alerta de KPI Financiero'
    _order = 'priority desc, kpi_type, company_id'

    name = fields.Char(
        string='Nombre Alerta',
        required=True,
        compute='_compute_name',
        store=True,
        help='Nombre descriptivo de la alerta'
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        help='Compañía a la cual aplicar esta alerta'
    )

    kpi_type = fields.Selection([
        ('iva_debito_fiscal', 'IVA Débito Fiscal'),
        ('iva_credito_fiscal', 'IVA Crédito Fiscal'),
        ('ventas_netas', 'Ventas Netas'),
        ('compras_netas', 'Compras Netas'),
        ('ppm_pagado', 'PPM Pagado'),
    ], string='KPI a Monitorear', required=True, help='Tipo de KPI a monitorear')

    threshold_type = fields.Selection([
        ('above', 'Mayor que'),
        ('below', 'Menor que'),
    ], string='Tipo de Umbral', required=True, default='above',
       help='Condición de disparo de la alerta')

    threshold_value = fields.Monetary(
        string='Valor Umbral',
        required=True,
        currency_field='currency_id',
        help='Valor límite para disparar la alerta'
    )

    alert_level = fields.Selection([
        ('info', 'Información'),
        ('warning', 'Advertencia'),
        ('critical', 'Crítico'),
    ], string='Nivel de Alerta', required=True, default='warning',
       help='Nivel de severidad de la alerta')

    priority = fields.Selection([
        ('0', 'Baja'),
        ('1', 'Media'),
        ('2', 'Alta'),
        ('3', 'Urgente'),
    ], string='Prioridad', default='1', required=True)

    active = fields.Boolean(
        string='Activa',
        default=True,
        help='Si está desactivada, no se evaluará en el cron job'
    )

    notification_user_ids = fields.Many2many(
        'res.users',
        'l10n_cl_kpi_alert_user_rel',
        'alert_id',
        'user_id',
        string='Usuarios a Notificar',
        help='Usuarios que recibirán notificaciones cuando se dispare la alerta'
    )

    last_triggered_date = fields.Datetime(
        string='Última Activación',
        readonly=True,
        help='Fecha de la última vez que se disparó esta alerta'
    )

    triggered_count = fields.Integer(
        string='Veces Activada',
        readonly=True,
        default=0,
        help='Número de veces que se ha disparado esta alerta'
    )

    currency_id = fields.Many2one(
        'res.currency',
        string='Moneda',
        related='company_id.currency_id',
        readonly=True
    )

    notes = fields.Text(
        string='Notas',
        help='Notas adicionales sobre esta alerta'
    )

    @api.depends('kpi_type', 'threshold_type', 'threshold_value', 'company_id')
    def _compute_name(self):
        """Genera un nombre descriptivo automáticamente"""
        for alert in self:
            kpi_label = dict(self._fields['kpi_type'].selection).get(alert.kpi_type, 'KPI')
            threshold_label = dict(self._fields['threshold_type'].selection).get(alert.threshold_type, '')

            alert.name = _(
                '%(kpi)s %(condition)s %(value)s - %(company)s'
            ) % {
                'kpi': kpi_label,
                'condition': threshold_label,
                'value': alert.currency_id.format(alert.threshold_value) if alert.currency_id else alert.threshold_value,
                'company': alert.company_id.name or ''
            }

    @api.constrains('threshold_value')
    def _check_threshold_value(self):
        """Valida que el valor umbral sea positivo"""
        for alert in self:
            if alert.threshold_value < 0:
                raise ValidationError(
                    _('El valor umbral debe ser positivo. Valor actual: %s') % alert.threshold_value
                )

    @api.model
    def _cron_check_kpi_alerts(self):
        """
        Cron job que se ejecuta diariamente para verificar alertas.

        Verifica todas las alertas activas y envía notificaciones cuando
        se superan los umbrales configurados.
        """
        _logger.info('Iniciando verificación de alertas de KPI...')

        # Obtener todas las alertas activas
        active_alerts = self.search([('active', '=', True)])

        if not active_alerts:
            _logger.info('No hay alertas activas para procesar')
            return

        # Calcular periodo (último mes completo)
        today = datetime.now().date()
        first_day_this_month = today.replace(day=1)
        last_day_last_month = first_day_this_month - timedelta(days=1)
        first_day_last_month = last_day_last_month.replace(day=1)

        period_start = first_day_last_month.strftime('%Y-%m-%d')
        period_end = last_day_last_month.strftime('%Y-%m-%d')

        _logger.info('Verificando alertas para período: %s - %s', period_start, period_end)

        # Agrupar alertas por compañía para optimizar
        alerts_by_company = {}
        for alert in active_alerts:
            if alert.company_id.id not in alerts_by_company:
                alerts_by_company[alert.company_id.id] = []
            alerts_by_company[alert.company_id.id].append(alert)

        triggered_alerts = 0

        # Procesar alertas por compañía
        for company_id, company_alerts in alerts_by_company.items():
            company = self.env['res.company'].browse(company_id)

            # Obtener KPIs de la compañía
            kpi_service = self.env['account.financial.report.kpi.service']

            try:
                kpis = kpi_service.compute_kpis(
                    company=company,
                    period_start=period_start,
                    period_end=period_end
                )
            except Exception as e:
                _logger.error(
                    'Error al calcular KPIs para compañía %s: %s',
                    company.name, str(e)
                )
                continue

            # Verificar cada alerta
            for alert in company_alerts:
                kpi_value = kpis.get(alert.kpi_type, 0.0)

                # Evaluar condición
                should_trigger = self._evaluate_alert_condition(
                    alert.threshold_type,
                    kpi_value,
                    alert.threshold_value
                )

                if should_trigger:
                    _logger.info(
                        'Alerta disparada: %s (Valor: %s, Umbral: %s)',
                        alert.name, kpi_value, alert.threshold_value
                    )

                    # Enviar notificación
                    alert._send_alert_notification(kpi_value, period_start, period_end)

                    # Actualizar estadísticas
                    alert.write({
                        'last_triggered_date': fields.Datetime.now(),
                        'triggered_count': alert.triggered_count + 1,
                    })

                    triggered_alerts += 1

        _logger.info(
            'Verificación de alertas completada. Alertas disparadas: %d de %d',
            triggered_alerts, len(active_alerts)
        )

    @api.model
    def _evaluate_alert_condition(self, threshold_type, current_value, threshold_value):
        """
        Evalúa si una condición de alerta se cumple.

        Args:
            threshold_type: 'above' o 'below'
            current_value: Valor actual del KPI
            threshold_value: Valor umbral configurado

        Returns:
            bool: True si la alerta debe dispararse
        """
        if threshold_type == 'above':
            return current_value > threshold_value
        elif threshold_type == 'below':
            return current_value < threshold_value
        return False

    def _send_alert_notification(self, kpi_value, period_start, period_end):
        """
        Envía notificación de alerta mediante mail.activity.

        Args:
            kpi_value: Valor actual del KPI que disparó la alerta
            period_start: Fecha inicio del período
            period_end: Fecha fin del período
        """
        self.ensure_one()

        # Determinar destinatarios
        users = self.notification_user_ids or self.company_id.user_ids

        if not users:
            _logger.warning('No hay usuarios configurados para recibir alerta: %s', self.name)
            return

        # Construir mensaje
        kpi_label = dict(self._fields['kpi_type'].selection).get(self.kpi_type, 'KPI')

        message = _(
            '<p><strong>⚠️ Alerta de KPI Financiero</strong></p>'
            '<ul>'
            '<li><strong>KPI:</strong> %(kpi)s</li>'
            '<li><strong>Valor Actual:</strong> %(current)s</li>'
            '<li><strong>Umbral:</strong> %(threshold)s</li>'
            '<li><strong>Condición:</strong> %(condition)s</li>'
            '<li><strong>Nivel:</strong> %(level)s</li>'
            '<li><strong>Período:</strong> %(start)s - %(end)s</li>'
            '</ul>'
            '<p>%(notes)s</p>'
        ) % {
            'kpi': kpi_label,
            'current': self.currency_id.format(kpi_value),
            'threshold': self.currency_id.format(self.threshold_value),
            'condition': dict(self._fields['threshold_type'].selection).get(self.threshold_type, ''),
            'level': dict(self._fields['alert_level'].selection).get(self.alert_level, ''),
            'start': period_start,
            'end': period_end,
            'notes': self.notes or ''
        }

        # Crear actividad para cada usuario
        activity_type = self.env.ref('mail.mail_activity_data_warning')

        for user in users:
            self.env['mail.activity'].create({
                'activity_type_id': activity_type.id,
                'summary': _('Alerta KPI: %s') % kpi_label,
                'note': message,
                'user_id': user.id,
                'res_model_id': self.env['ir.model']._get_id('l10n_cl.kpi.alert'),
                'res_id': self.id,
            })

        _logger.info('Notificación enviada a %d usuario(s) para alerta: %s', len(users), self.name)

    def action_test_alert(self):
        """
        Acción para probar manualmente una alerta.

        Calcula los KPIs actuales y verifica si la alerta se dispararía.
        """
        self.ensure_one()

        # Calcular periodo (último mes)
        today = datetime.now().date()
        first_day_this_month = today.replace(day=1)
        last_day_last_month = first_day_this_month - timedelta(days=1)
        first_day_last_month = last_day_last_month.replace(day=1)

        period_start = first_day_last_month.strftime('%Y-%m-%d')
        period_end = last_day_last_month.strftime('%Y-%m-%d')

        # Obtener KPIs
        kpi_service = self.env['account.financial.report.kpi.service']
        kpis = kpi_service.compute_kpis(
            company=self.company_id,
            period_start=period_start,
            period_end=period_end
        )

        kpi_value = kpis.get(self.kpi_type, 0.0)

        # Evaluar condición
        should_trigger = self._evaluate_alert_condition(
            self.threshold_type,
            kpi_value,
            self.threshold_value
        )

        if should_trigger:
            # Enviar notificación de prueba
            self._send_alert_notification(kpi_value, period_start, period_end)

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Alerta Disparada'),
                    'message': _(
                        'La alerta se ha disparado. Valor actual: %s (Umbral: %s)'
                    ) % (
                        self.currency_id.format(kpi_value),
                        self.currency_id.format(self.threshold_value)
                    ),
                    'type': 'warning',
                    'sticky': False,
                }
            }
        else:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': _('Alerta NO Disparada'),
                    'message': _(
                        'La condición no se cumple. Valor actual: %s (Umbral: %s)'
                    ) % (
                        self.currency_id.format(kpi_value),
                        self.currency_id.format(self.threshold_value)
                    ),
                    'type': 'info',
                    'sticky': False,
                }
            }
