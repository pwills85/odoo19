# -*- coding: utf-8 -*-
"""
Modelo de Tasas de Retención IUE (Impuesto Único Segunda Categoría)
Gestiona tasas históricas de retención para Boletas de Honorarios

Histórico Chile:
- 2018-2019: 10.0%
- 2020: 10.75%
- 2021: 11.5%
- 2022: 12.25%
- 2023: 13.0%
- 2024: 13.75%
- 2025+: 14.5%
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
from datetime import date
import logging

_logger = logging.getLogger(__name__)


class RetencionIUETasa(models.Model):
    _name = 'l10n_cl.retencion_iue.tasa'
    _description = 'Tasas Históricas de Retención IUE'
    _order = 'fecha_inicio desc'
    _rec_name = 'display_name'

    # Campos Básicos
    name = fields.Char(
        string='Nombre',
        compute='_compute_name',
        store=True,
        help='Nombre descriptivo de la tasa de retención'
    )

    display_name = fields.Char(
        string='Nombre Completo',
        compute='_compute_display_name',
        store=True
    )

    # Rango de Vigencia
    fecha_inicio = fields.Date(
        string='Fecha Inicio Vigencia',
        required=True,
        help='Fecha desde la cual aplica esta tasa de retención'
    )

    fecha_termino = fields.Date(
        string='Fecha Término Vigencia',
        help='Fecha hasta la cual aplica esta tasa (dejar vacío si es vigente actual)'
    )

    # Tasa de Retención
    tasa_retencion = fields.Float(
        string='Tasa de Retención (%)',
        required=True,
        digits=(5, 2),
        help='Porcentaje de retención sobre honorarios brutos'
    )

    # Estado
    active = fields.Boolean(
        string='Activo',
        default=True,
        help='Si está inactivo, no se mostrará en listados'
    )

    es_vigente = fields.Boolean(
        string='Es Vigente Actual',
        compute='_compute_es_vigente',
        store=True,
        help='Indica si esta tasa es la vigente a la fecha actual'
    )

    # Información Legal
    referencia_legal = fields.Char(
        string='Referencia Legal',
        help='Ley, decreto o circular que establece esta tasa (ej: Ley 21.133)'
    )

    notas = fields.Text(
        string='Notas',
        help='Observaciones sobre esta tasa de retención'
    )

    # Auditoría
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        default=lambda self: self.env.company,
        required=True
    )

    # Computed Fields

    @api.depends('fecha_inicio', 'tasa_retencion')
    def _compute_name(self):
        """Nombre descriptivo: Retención 14.5% (desde 2025-01-01)"""
        for record in self:
            if record.fecha_inicio and record.tasa_retencion:
                record.name = f"Retención {record.tasa_retencion}% (desde {record.fecha_inicio})"
            else:
                record.name = 'Tasa de Retención IUE'

    @api.depends('name', 'fecha_termino', 'es_vigente')
    def _compute_display_name(self):
        """Display name con indicador de vigencia"""
        for record in self:
            base_name = record.name or 'Tasa de Retención IUE'
            if record.es_vigente:
                record.display_name = f"{base_name} [VIGENTE]"
            elif record.fecha_termino:
                record.display_name = f"{base_name} (hasta {record.fecha_termino})"
            else:
                record.display_name = base_name

    @api.depends('fecha_inicio', 'fecha_termino')
    def _compute_es_vigente(self):
        """Verifica si la tasa es vigente a la fecha actual"""
        today = date.today()
        for record in self:
            if not record.fecha_inicio:
                record.es_vigente = False
                continue

            inicio_ok = record.fecha_inicio <= today
            termino_ok = not record.fecha_termino or record.fecha_termino >= today

            record.es_vigente = inicio_ok and termino_ok

    # Constraints

    @api.constrains('tasa_retencion')
    def _check_tasa_retencion(self):
        """Valida que la tasa esté en rango válido"""
        for record in self:
            if record.tasa_retencion < 0 or record.tasa_retencion > 100:
                raise ValidationError(
                    _("La tasa de retención debe estar entre 0%% y 100%%. Valor ingresado: %.2f%%") % record.tasa_retencion
                )

    @api.constrains('fecha_inicio', 'fecha_termino')
    def _check_fechas_vigencia(self):
        """Valida que fecha_termino sea posterior a fecha_inicio"""
        for record in self:
            if record.fecha_inicio and record.fecha_termino:
                if record.fecha_termino < record.fecha_inicio:
                    raise ValidationError(
                        _("La fecha de término (%s) no puede ser anterior a la fecha de inicio (%s)") % (record.fecha_termino, record.fecha_inicio)
                    )

    # Métodos de Negocio

    @api.model
    def get_tasa_vigente(self, fecha=None, company_id=None):
        """
        Obtiene la tasa de retención vigente para una fecha específica.

        Args:
            fecha (date): Fecha para la cual se busca la tasa vigente.
                         Si es None, usa la fecha actual.
            company_id (int): ID de la compañía. Si es None, usa la compañía actual.

        Returns:
            float: Tasa de retención vigente (porcentaje)

        Raises:
            ValidationError: Si no se encuentra tasa vigente para la fecha
        """
        if fecha is None:
            fecha = date.today()

        if company_id is None:
            company_id = self.env.company.id

        # Buscar tasa vigente
        domain = [
            ('company_id', '=', company_id),
            ('fecha_inicio', '<=', fecha),
            ('active', '=', True),
            '|',
            ('fecha_termino', '=', False),
            ('fecha_termino', '>=', fecha)
        ]

        tasa = self.search(domain, limit=1, order='fecha_inicio desc')

        if not tasa:
            _logger.warning(f"No se encontró tasa de retención IUE vigente para fecha {fecha}")
            raise ValidationError(
                _("No se encontró tasa de retención IUE vigente para la fecha %s. Por favor, configure las tasas en Configuración > Facturación Electrónica > Tasas de Retención.") % fecha
            )

        return tasa.tasa_retencion

    @api.model
    def get_tasa_record_vigente(self, fecha=None, company_id=None):
        """
        Similar a get_tasa_vigente, pero retorna el record completo.

        Args:
            fecha (date): Fecha para la cual se busca la tasa vigente
            company_id (int): ID de la compañía

        Returns:
            l10n_cl.retencion_iue.tasa: Record de la tasa vigente
        """
        if fecha is None:
            fecha = date.today()

        if company_id is None:
            company_id = self.env.company.id

        domain = [
            ('company_id', '=', company_id),
            ('fecha_inicio', '<=', fecha),
            ('active', '=', True),
            '|',
            ('fecha_termino', '=', False),
            ('fecha_termino', '>=', fecha)
        ]

        tasa = self.search(domain, limit=1, order='fecha_inicio desc')

        if not tasa:
            raise ValidationError(
                _("No se encontró tasa de retención IUE vigente para la fecha %s.") % fecha
            )

        return tasa

    @api.model
    def calcular_retencion(self, monto_bruto, fecha=None, company_id=None):
        """
        Calcula el monto de retención para un monto bruto dado.

        Args:
            monto_bruto (float): Monto bruto de honorarios
            fecha (date): Fecha para la cual se calcula (usa tasa vigente a esa fecha)
            company_id (int): ID de la compañía

        Returns:
            dict: {
                'monto_bruto': float,
                'tasa_retencion': float,
                'monto_retencion': float,
                'monto_liquido': float,
                'fecha_calculo': date
            }
        """
        if fecha is None:
            fecha = date.today()

        tasa = self.get_tasa_vigente(fecha=fecha, company_id=company_id)

        monto_retencion = round(monto_bruto * tasa / 100, 0)  # Sin decimales (pesos chilenos)
        monto_liquido = monto_bruto - monto_retencion

        return {
            'monto_bruto': monto_bruto,
            'tasa_retencion': tasa,
            'monto_retencion': monto_retencion,
            'monto_liquido': monto_liquido,
            'fecha_calculo': fecha
        }

    @api.model
    def crear_tasas_historicas_chile(self, company_id=None):
        """
        Crea las tasas históricas de retención IUE de Chile desde 2018.

        Útil para inicialización de datos en migración.

        Args:
            company_id (int): ID de la compañía. Si es None, usa la compañía actual.

        Returns:
            list: Records de tasas creadas
        """
        if company_id is None:
            company_id = self.env.company.id

        tasas_historicas = [
            {
                'fecha_inicio': date(2018, 1, 1),
                'fecha_termino': date(2019, 12, 31),
                'tasa_retencion': 10.0,
                'referencia_legal': 'Ley 20.780 (Reforma Tributaria 2014)',
                'notas': 'Tasa inicial post-reforma tributaria 2014'
            },
            {
                'fecha_inicio': date(2020, 1, 1),
                'fecha_termino': date(2020, 12, 31),
                'tasa_retencion': 10.75,
                'referencia_legal': 'Ley 20.780 - Aumento gradual',
                'notas': 'Primer aumento gradual de la tasa'
            },
            {
                'fecha_inicio': date(2021, 1, 1),
                'fecha_termino': date(2021, 12, 31),
                'tasa_retencion': 11.5,
                'referencia_legal': 'Ley 20.780 - Aumento gradual',
                'notas': 'Segundo aumento gradual de la tasa'
            },
            {
                'fecha_inicio': date(2022, 1, 1),
                'fecha_termino': date(2022, 12, 31),
                'tasa_retencion': 12.25,
                'referencia_legal': 'Ley 20.780 - Aumento gradual',
                'notas': 'Tercer aumento gradual de la tasa'
            },
            {
                'fecha_inicio': date(2023, 1, 1),
                'fecha_termino': date(2023, 12, 31),
                'tasa_retencion': 13.0,
                'referencia_legal': 'Ley 20.780 - Aumento gradual',
                'notas': 'Cuarto aumento gradual de la tasa'
            },
            {
                'fecha_inicio': date(2024, 1, 1),
                'fecha_termino': date(2024, 12, 31),
                'tasa_retencion': 13.75,
                'referencia_legal': 'Ley 21.210 (Modernización Tributaria)',
                'notas': 'Penúltimo aumento gradual'
            },
            {
                'fecha_inicio': date(2025, 1, 1),
                'fecha_termino': False,  # Vigente actual (sin término)
                'tasa_retencion': 14.5,
                'referencia_legal': 'Ley 21.210 - Tasa final',
                'notas': 'Tasa final de retención según Ley de Modernización Tributaria'
            }
        ]

        created_records = []
        for tasa_data in tasas_historicas:
            tasa_data['company_id'] = company_id

            # Verificar si ya existe
            existing = self.search([
                ('company_id', '=', company_id),
                ('fecha_inicio', '=', tasa_data['fecha_inicio']),
                ('tasa_retencion', '=', tasa_data['tasa_retencion'])
            ], limit=1)

            if existing:
                # Actualizar si ya existe
                existing.write(tasa_data)
                created_records.append(existing)
                _logger.info(f"Actualizada tasa {tasa_data['tasa_retencion']}% desde {tasa_data['fecha_inicio']}")
            else:
                # Crear nuevo
                tasa = self.create(tasa_data)
                created_records.append(tasa)
                _logger.info(f"Creada tasa {tasa_data['tasa_retencion']}% desde {tasa_data['fecha_inicio']}")

        return created_records
