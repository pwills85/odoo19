# -*- coding: utf-8 -*-
from odoo import models, fields, api, _

from odoo.exceptions import ValidationError, UserError
from datetime import datetime
import logging
import os

_logger = logging.getLogger(__name__)


class L10nClF22(models.Model):
    """
    Formulario 22 - Declaración Anual de Impuesto a la Renta
    Modelo persistente para gestionar el ciclo de vida completo del F22


    @api.constrains('year', 'company_id')
    def _validate_sii_format(self):
        '''Validate F22 SII format compliance'''
        for record in self:
            if not record.company_id.vat:
                raise ValidationError(_("Company must have valid RUT"))

            if not record.year or record.year < 2020 or record.year > 2030:
                raise ValidationError(_("Invalid tax year"))

    🔗 REFERENCIAS UTILIZADAS:

    **DOCUMENTACIÓN OFICIAL ODOO 18:**
    - ORM Models: https://www.odoo.com/documentation/18.0/developer/reference/backend/orm.html#models
    - Fields: https://www.odoo.com/documentation/18.0/developer/reference/backend/orm.html#fields
    - Computed Fields: https://www.odoo.com/documentation/18.0/developer/reference/backend/orm.html#computed-fields

    **DOCUMENTACIÓN INTERNA:**
    - GUIA_TECNICA_DESARROLLO_MODULOS_ODOO18_CE.md: Service Layer Pattern - Sección 3.2
    - CODING_GUIDELINES_ODOO18_OFICIAL.md: Naming Conventions - Sección 2.1
    """
    _name = 'l10n_cl.f22'
    _description = 'Formulario 22 - Declaración Anual de Impuesto a la Renta'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _rec_name = 'display_name'
    _order = 'fiscal_year desc, id desc'

    # ========== CAMPOS DE IDENTIFICACIÓN ==========
    display_name = fields.Char(
        string='Nombre',
        compute='_compute_display_name',
        store=True
    )

    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        readonly=True,
        default=lambda self: self.env.company
    )

    fiscal_year = fields.Integer(
        string='Año Tributario',
        required=True,
        readonly=True,
        help='Año tributario (renta del año anterior)'
    )

    period_start = fields.Date(
        string='Inicio Período',
        compute='_compute_period_dates',
        store=True
    )

    period_end = fields.Date(
        string='Fin Período',
        compute='_compute_period_dates',
        store=True
    )

    folio = fields.Char(
        string='Folio F22',
        readonly=True,
        copy=False,
        help='Número de folio asignado por el SII'
    )

    # ========== ESTADOS Y FLUJO ==========
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('review', 'En Revisión'),
        ('validated', 'Validado'),
        ('sent', 'Enviado al SII'),
        ('accepted', 'Aceptado'),
        ('rejected', 'Rechazado'),
        ('replaced', 'Reemplazado')
    ], string='Estado', default='draft', required=True, readonly=True,
       tracking=True, copy=False)

    # ========== DATOS BASE IMPONIBLE ==========
    # Ingresos
    ingresos_operacionales = fields.Monetary(
        string='Ingresos Operacionales',
        currency_field='currency_id',
        readonly=True,
        tracking=True
    )

    ingresos_no_operacionales = fields.Monetary(
        string='Ingresos No Operacionales',
        currency_field='currency_id',
        readonly=True
    )

    ingresos_totales = fields.Monetary(
        string='Total Ingresos',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # Costos y Gastos
    costos_directos = fields.Monetary(
        string='Costos Directos',
        currency_field='currency_id',
        readonly=True,
        tracking=True
    )

    gastos_operacionales = fields.Monetary(
        string='Gastos Operacionales',
        currency_field='currency_id',
        readonly=True
    )

    gastos_financieros = fields.Monetary(
        string='Gastos Financieros',
        currency_field='currency_id',
        readonly=True
    )

    depreciacion = fields.Monetary(
        string='Depreciación',
        currency_field='currency_id',
        readonly=True
    )

    gastos_totales = fields.Monetary(
        string='Total Gastos',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # Resultado Tributario
    resultado_antes_impuesto = fields.Monetary(
        string='Resultado Antes de Impuesto',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # ========== AJUSTES TRIBUTARIOS ==========
    # Agregados
    agregados_gastos_rechazados = fields.Monetary(
        string='Gastos Rechazados (+)',
        currency_field='currency_id',
        readonly=True,
        help='Gastos no aceptados tributariamente'
    )

    agregados_otros = fields.Monetary(
        string='Otros Agregados (+)',
        currency_field='currency_id',
        readonly=True
    )

    total_agregados = fields.Monetary(
        string='Total Agregados',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # Deducciones
    deducciones_perdidas_anteriores = fields.Monetary(
        string='Pérdidas Tributarias Anteriores (-)',
        currency_field='currency_id',
        readonly=True
    )

    deducciones_otros = fields.Monetary(
        string='Otras Deducciones (-)',
        currency_field='currency_id',
        readonly=True
    )

    total_deducciones = fields.Monetary(
        string='Total Deducciones',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # ========== DETERMINACIÓN DEL IMPUESTO ==========
    renta_liquida_imponible = fields.Monetary(
        string='Renta Líquida Imponible',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        tracking=True
    )

    impuesto_primera_categoria = fields.Monetary(
        string='Impuesto Primera Categoría (27%)',
        compute='_compute_tax',
        store=True,
        currency_field='currency_id',
        tracking=True
    )

    # Créditos
    credito_ppm = fields.Monetary(
        string='Crédito PPM',
        currency_field='currency_id',
        readonly=True,
        help='Crédito por Pagos Provisionales Mensuales'
    )

    credito_otros = fields.Monetary(
        string='Otros Créditos',
        currency_field='currency_id',
        readonly=True
    )

    total_creditos = fields.Monetary(
        string='Total Créditos',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # Resultado Final
    impuesto_a_pagar = fields.Monetary(
        string='Impuesto a Pagar',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id',
        tracking=True
    )

    devolucion = fields.Monetary(
        string='Devolución',
        compute='_compute_totals',
        store=True,
        currency_field='currency_id'
    )

    # ========== RELACIONES ==========
    currency_id = fields.Many2one(
        'res.currency',
        related='company_id.currency_id',
        store=True,
        readonly=True
    )

    provision_move_id = fields.Many2one(
        'account.move',
        string='Asiento de Provisión',
        readonly=True,
        copy=False,
        help='Asiento contable generado al validar el F22'
    )

    payment_id = fields.Many2one(
        'account.payment',
        string='Pago Asociado',
        readonly=True,
        copy=False
    )

    # ========== INTEGRACIÓN SII ==========
    sii_track_id = fields.Char(
        string='Track ID SII',
        readonly=True,
        copy=False,
        help='Identificador de seguimiento del SII'
    )

    sii_send_date = fields.Datetime(
        string='Fecha Envío SII',
        readonly=True,
        copy=False
    )

    sii_response = fields.Text(
        string='Respuesta SII',
        readonly=True,
        copy=False
    )

    # ========== OBSERVACIONES ==========
    observaciones = fields.Text(
        string='Observaciones',
        readonly=True
    )

    # ========== COMPUTED FIELDS ==========
    @api.depends('company_id', 'fiscal_year')
    def _compute_display_name(self):
        """Calcula el nombre mostrado del F22"""
        for record in self:
            if record.company_id and record.fiscal_year:
                record.display_name = f"F22 {record.company_id.name} - AT{record.fiscal_year}"
            else:
                record.display_name = "F22 Borrador"

    @api.depends('fiscal_year')
    def _compute_period_dates(self):
        """Calcula las fechas del período fiscal"""
        for record in self:
            if record.fiscal_year:
                # El período es el año anterior al tributario
                year = record.fiscal_year - 1
                record.period_start = fields.Date.from_string(f'{year}-01-01')
                record.period_end = fields.Date.from_string(f'{year}-12-31')
            else:
                record.period_start = False
                record.period_end = False

    @api.depends(
        'ingresos_operacionales', 'ingresos_no_operacionales',
        'costos_directos', 'gastos_operacionales', 'gastos_financieros', 'depreciacion',
        'agregados_gastos_rechazados', 'agregados_otros',
        'deducciones_perdidas_anteriores', 'deducciones_otros',
        'credito_ppm', 'credito_otros', 'impuesto_primera_categoria'
    )
    def _compute_totals(self):
        """Calcula todos los totales del formulario"""
        for record in self:
            # Totales principales
            record.ingresos_totales = record.ingresos_operacionales + record.ingresos_no_operacionales
            record.gastos_totales = (
                record.costos_directos +
                record.gastos_operacionales +
                record.gastos_financieros +
                record.depreciacion
            )

            # Resultado antes de impuesto
            record.resultado_antes_impuesto = record.ingresos_totales - record.gastos_totales

            # Ajustes tributarios
            record.total_agregados = record.agregados_gastos_rechazados + record.agregados_otros
            record.total_deducciones = record.deducciones_perdidas_anteriores + record.deducciones_otros

            # Renta líquida imponible
            record.renta_liquida_imponible = max(0,
                record.resultado_antes_impuesto +
                record.total_agregados -
                record.total_deducciones
            )

            # Créditos
            record.total_creditos = record.credito_ppm + record.credito_otros

            # Determinación final
            diferencia = record.impuesto_primera_categoria - record.total_creditos

            if diferencia > 0:
                record.impuesto_a_pagar = diferencia
                record.devolucion = 0.0
            else:
                record.impuesto_a_pagar = 0.0
                record.devolucion = abs(diferencia)

    @api.depends('renta_liquida_imponible')
    def _compute_tax(self):
        """Calcula el impuesto de primera categoría"""
        for record in self:
            # Tasa de impuesto primera categoría: 27%
            record.impuesto_primera_categoria = record.renta_liquida_imponible * 0.27

    # ========== CONSTRAINTS ==========
    @api.constrains('fiscal_year', 'company_id')
    def _check_unique_year(self):
        """Verifica que no exista otro F22 para el mismo año"""
        for record in self:
            domain = [
                ('company_id', '=', record.company_id.id),
                ('fiscal_year', '=', record.fiscal_year),
                ('id', '!=', record.id),
                ('state', '!=', 'replaced')
            ]
            if self.search_count(domain) > 0:
                raise ValidationError(
                    _('Ya existe un F22 para el año tributario %s en esta compañía') %
                    record.fiscal_year
                )


    # ========== READONLY COMPUTATION ==========
    @api.depends('state')
    def _compute_readonly_fields(self):
        """Compute readonly state for fields based on record state."""
        for record in self:
            if record.state in ['draft']:
                record.readonly_state = False
            elif record.state in ['review']:
                record.readonly_partial = False
            else:
                record.readonly_state = True
                record.readonly_partial = True

    readonly_state = fields.Boolean(
        compute='_compute_readonly_fields',
        store=False
    )

    readonly_partial = fields.Boolean(
        compute='_compute_readonly_fields',
        store=False
    )

    # ========== BUSINESS METHODS ==========
    def action_calculate(self):
        """
        Calcula/recalcula los valores del F22 desde los datos contables REALES
        Conecta con account.move.line para extraer datos contables del período
        """
        import time
        import json
        start_time = time.time()

        self.ensure_one()

        if self.state not in ['draft', 'review']:
            raise UserError(_('Solo se pueden recalcular F22 en estado Borrador o En Revisión'))

        # Obtener servicio de cálculo REAL
        sii_service = self.env['account.financial.report.sii.integration.service']

        # Generar datos REALES desde contabilidad
        try:
            f22_data = sii_service.generate_f22_data(
                self.company_id,
                self.fiscal_year
            )

            # Actualizar campos con datos REALES calculados
            self.write({
                'ingresos_operacionales': f22_data.get('ingresos_operacionales', 0.0),
                'ingresos_no_operacionales': f22_data.get('ingresos_no_operacionales', 0.0),
                'costos_directos': f22_data.get('costos_directos', 0.0),
                'gastos_operacionales': f22_data.get('gastos_operacionales', 0.0),
                'gastos_financieros': f22_data.get('gastos_financieros', 0.0),
                'depreciacion': f22_data.get('depreciacion', 0.0),
                'agregados_gastos_rechazados': f22_data.get('agregados_gastos_rechazados', 0.0),
                'deducciones_perdidas_anteriores': f22_data.get('deducciones_perdidas_anteriores', 0.0),
                'credito_ppm': f22_data.get('credito_ppm', 0.0),
            })

            # Los campos computed se recalcularán automáticamente

            # Logging estructurado JSON
            duration_ms = int((time.time() - start_time) * 1000)
            log_data = {
                "module": "l10n_cl_financial_reports",
                "action": "f22_calculate",
                "company_id": self.company_id.id,
                "fiscal_year": self.fiscal_year,
                "duration_ms": duration_ms,
                "records_processed": f22_data.get('records_processed', 0),
                "status": "success",
                "totals": {
                    "ingresos_totales": float(self.ingresos_totales),
                    "gastos_totales": float(self.gastos_totales),
                    "renta_liquida_imponible": float(self.renta_liquida_imponible),
                    "impuesto_primera_categoria": float(self.impuesto_primera_categoria)
                }
            }
            _logger.info(json.dumps(log_data))

            message = _(
                'F22 calculado desde datos contables REALES:<br/>'
                '• Ingresos Totales: {:,.0f}<br/>'
                '• Gastos Totales: {:,.0f}<br/>'
                '• Renta Líquida Imponible: {:,.0f}<br/>'
                '• Impuesto Primera Categoría: {:,.0f}<br/>'
                '• Tiempo: {}ms'
            ).format(
                self.ingresos_totales,
                self.gastos_totales,
                self.renta_liquida_imponible,
                self.impuesto_primera_categoria,
                duration_ms
            )

            self.message_post(
                body=message,
                message_type='notification'
            )

        except Exception as e:
            # Logging de error
            duration_ms = int((time.time() - start_time) * 1000)
            log_data = {
                "module": "l10n_cl_financial_reports",
                "action": "f22_calculate",
                "company_id": self.company_id.id,
                "fiscal_year": self.fiscal_year,
                "duration_ms": duration_ms,
                "status": "error",
                "error": str(e)
            }
            _logger.error(json.dumps(log_data))
            raise UserError(_('Error al calcular F22 desde contabilidad: %s') % str(e))

    def action_to_review(self):
        """Pasa el F22 a revisión"""
        self.ensure_one()
        if self.state != 'draft':
            raise UserError(_('Solo se pueden pasar a revisión F22 en borrador'))

        self.state = 'review'
        self.message_post(
            body=_('F22 pasado a revisión'),
            message_type='notification'
        )

    def action_validate(self):
        """
        Valida el F22 y genera los efectos contables
        """
        self.ensure_one()

        if self.state not in ['draft', 'review']:
            raise UserError(_('Solo se pueden validar F22 en estado Borrador o En Revisión'))

        # Validar que hay datos
        if not self.ingresos_totales:
            raise UserError(_('No hay ingresos registrados para este período'))

        # Crear asiento contable de provisión si hay impuesto a pagar
        if self.impuesto_a_pagar > 0:
            self.env.create_provision_move()

        # Cambiar estado
        self.write({
            'state': 'validated',
        })

        if self.impuesto_a_pagar > 0:
            message = _('F22 validado. Impuesto a pagar: %s %s') % (self.impuesto_a_pagar, self.currency_id.symbol)
        else:
            message = _('F22 validado. Devolución solicitada: %s %s') % (self.devolucion, self.currency_id.symbol)

        self.message_post(
            body=message,
            message_type='notification'
        )

    def _create_provision_move(self):
        """
        Crea el asiento contable de provisión de impuesto a la renta
        """
        self.ensure_one()

        # Obtener cuentas desde la configuración
        impuesto_por_pagar = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl.account_impuesto_renta_por_pagar_id'
        )
        if not impuesto_por_pagar:
            raise UserError(_('No se ha configurado la cuenta de Impuesto Renta por pagar'))

        gasto_impuesto = self.env['ir.config_parameter'].sudo().get_param(
            'l10n_cl.account_gasto_impuesto_renta_id'
        )
        if not gasto_impuesto:
            raise UserError(_('No se ha configurado la cuenta de Gasto por Impuesto Renta'))

        # Crear asiento
        move_vals = {
            'journal_id': self.env['account.journal'].search([
                ('type', '=', 'general'),
                ('company_id', '=', self.company_id.id)
            ], limit=1).id,
            'date': fields.Date.today(),
            'ref': f'Provisión Impuesto Renta F22 - AT{self.fiscal_year}',
            'company_id': self.company_id.id,
            'line_ids': [
                (0, 0, {
                    'name': f'Gasto Impuesto Renta AT{self.fiscal_year}',
                    'account_id': int(gasto_impuesto),
                    'debit': self.impuesto_a_pagar,
                    'credit': 0.0,
                }),
                (0, 0, {
                    'name': f'Provisión Impuesto Renta AT{self.fiscal_year}',
                    'account_id': int(impuesto_por_pagar),
                    'debit': 0.0,
                    'credit': self.impuesto_a_pagar,
                }),
            ]
        }

        move = self.env['account.move'].create(move_vals)
        move.action_post()

        self.provision_move_id = move

    def action_send_sii(self):
        """
        Envía el F22 al SII
        """
        self.ensure_one()

        if self.state != 'validated':
            raise UserError(_('Solo se pueden enviar al SII F22 validados'))

        # Preparar datos para envío
        f22_data = {
            'form_type': 'F22',
            'fiscal_year': self.fiscal_year,
            'company_rut': self.company_id.vat,
            'data': {
                'ingresos_brutos': self.ingresos_totales,
                'costos_directos': self.costos_directos,
                'gastos_operacionales': self.gastos_operacionales,
                'resultado_tributario': self.renta_liquida_imponible,
                'impuesto_primera_categoria': self.impuesto_primera_categoria,
            }
        }

        try:
            # Usar servicio SII real integrado
            sii_service = self.env['account.financial.report.sii.integration.service']
            response = sii_service.send_f22(self.company_id, f22_data)

            # Actualizar con respuesta
            self.write({
                'state': 'sent',
                'sii_track_id': response.get('track_id'),
                'sii_send_date': fields.Datetime.now(),
                'sii_response': str(response),
            })

            self.message_post(
                body=_('F22 enviado al SII. Track ID: %s') % response.get('track_id'),
                message_type='notification'
            )

        except Exception as e:
            _logger.error(f"Error enviando F22 al SII: {str(e)}")
            raise UserError(_('Error al enviar F22 al SII: %s') % str(e))

    @api.model
    def create_annual_f22(self):
        """
        Cron job para crear F22 anualmente
        Se ejecuta el 1 de marzo de cada año para el año anterior
        """
        # Calcular año tributario (año actual)
        current_year = fields.Date.today().year

        # Para cada compañía activa
        companies = self.env['res.company'].search([
            ('l10n_cl_sii_enabled', '=', True)
        ])

        for company in companies:
            # Verificar si ya existe
            existing = self.search([
                ('company_id', '=', company.id),
                ('fiscal_year', '=', current_year),
                ('state', '!=', 'replaced')
            ], limit=1)

            if not existing:
                # Crear nuevo F22
                f22 = self.create({
                    'company_id': company.id,
                    'fiscal_year': current_year,
                })

                # Calcular valores
                f22.action_calculate()

                _logger.info(f"F22 creado automáticamente: {f22.display_name}")

    def _validate_sii_compliance(self):
        """Validación completa de compliance SII para F22"""
        self.ensure_one()

        # Validar certificado digital
        self._check_digital_certificate()

        # Validar formato RUT
        if not self.company_id.vat or not self._validate_rut_format(self.company_id.vat):
            raise ValidationError(_("El RUT de la empresa no tiene formato válido para SII"))

        # Validar año fiscal
        current_year = datetime.now().year
        if not self.fiscal_year or self.fiscal_year < 2000 or self.fiscal_year > current_year + 1:
            raise ValidationError(_("El año tributario no es válido para declaración F22"))

        # Validar montos
        self._validate_amount_limits()

        # Validar coherencia de datos
        self._validate_data_coherence()

        return True

    def _check_digital_certificate(self):
        """Verificar certificado digital para envío SII"""
        cert_path = f'/mnt/certificates/{self.company_id.vat}.p12'
        if not os.path.exists(cert_path):
            raise UserError(_("Certificado digital no encontrado para la empresa"))

        # Validar expiración del certificado
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            # Verificar expiración
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            if cert.not_valid_after < datetime.now():
                raise UserError(_("El certificado digital ha expirado"))
        except ImportError:
            _logger.warning("Librería cryptography no disponible para validar certificado")
        except Exception as e:
            raise UserError(_("Error validando certificado: %s") % str(e))

    def _validate_rut_format(self, rut):
        """Validar formato de RUT chileno"""
        if not rut:
            return False

        # Remover puntos y guión
        rut = rut.replace('.', '').replace('-', '').upper()

        # Validar formato básico
        if len(rut) < 8 or len(rut) > 10:
            return False

        # Validar dígito verificador
        try:
            rut_number = rut[:-1]
            dv = rut[-1]

            # Algoritmo módulo 11
            suma = 0
            multiplo = 2

            for i in range(len(rut_number) - 1, -1, -1):
                suma += int(rut_number[i]) * multiplo
                multiplo += 1
                if multiplo > 7:
                    multiplo = 2

            resto = suma % 11
            dv_calculado = 11 - resto

            if dv_calculado == 11:
                dv_calculado = '0'
            elif dv_calculado == 10:
                dv_calculado = 'K'
            else:
                dv_calculado = str(dv_calculado)

            return dv == dv_calculado

        except (ValueError, IndexError):
            return False

    def _validate_amount_limits(self):
        """Validar límites de montos según normativa SII"""
        # Límite máximo SII para montos
        MAX_AMOUNT = 999999999999

        # Validar montos principales
        amounts_to_check = [
            ('ingresos_totales', self.ingresos_totales),
            ('gastos_totales', self.gastos_totales),
            ('renta_liquida_imponible', self.renta_liquida_imponible),
            ('impuesto_primera_categoria', self.impuesto_primera_categoria),
        ]

        for field_name, amount in amounts_to_check:
            if abs(amount) > MAX_AMOUNT:
                raise ValidationError(
                    _("El monto de %s excede el límite permitido por SII") % field_name
                )

        return True

    def _validate_data_coherence(self):
        """Validar coherencia de datos del F22"""
        # Validar que si hay ingresos, debe haber algún tipo de resultado
        if self.ingresos_totales > 0 and self.renta_liquida_imponible == 0:
            if not self.deducciones_perdidas_anteriores:
                _logger.warning(
                    "F22 con ingresos pero sin renta líquida imponible y sin pérdidas anteriores"
                )

        # Validar que el impuesto no puede ser mayor que la renta
        if self.impuesto_primera_categoria > self.renta_liquida_imponible:
            raise ValidationError(
                _("El impuesto no puede ser mayor que la renta líquida imponible")
            )

        # Validar que los créditos no pueden ser negativos
        if self.credito_ppm < 0 or self.credito_otros < 0:
            raise ValidationError(_("Los créditos no pueden ser negativos"))

        return True

    def action_validate_sii(self):
        """Acción para validar compliance SII antes del envío"""
        self._validate_sii_compliance()

        # Si pasa todas las validaciones, marcar como listo para envío
        self.write({'state': 'validated'})

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Validación SII Exitosa'),
                'message': _('El formulario F22 cumple con todos los requisitos SII y está listo para envío'),
                'type': 'success',
                'sticky': False,
            }
        }
