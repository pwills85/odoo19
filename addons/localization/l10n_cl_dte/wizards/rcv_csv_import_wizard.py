# -*- coding: utf-8 -*-
"""
Wizard para Importación y Validación CSV RCV del SII

Permite al usuario:
1. Descargar CSV RCV manualmente desde portal SII
2. Subir archivo CSV a Odoo mediante este wizard
3. Sistema compara automáticamente vs registros Odoo
4. Detecta y reporta discrepancias

Ventajas vs Web Scraping:
- No depende de cambios en portal SII
- Más robusto y mantenible
- Práctica estándar en ERPs enterprise (SAP, Oracle, NetSuite)
- Mismo beneficio: validación Odoo vs SII
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError, UserError
import base64
import csv
from io import StringIO
import logging

_logger = logging.getLogger(__name__)


class RCVCSVImportWizard(models.TransientModel):
    """
    Wizard para importar y validar CSV RCV desde SII.

    Flujo:
    1. Usuario descarga CSV desde https://www4.sii.cl/registrocompraven taoperacionesconsulta/
    2. Usuario sube CSV mediante este wizard
    3. Wizard parsea CSV y compara vs l10n_cl.rcv.entry
    4. Wizard muestra discrepancias encontradas
    5. Usuario puede revisar y corregir
    """
    _name = 'rcv.csv.import.wizard'
    _description = 'Importar CSV RCV desde SII'

    # ========================
    # PASO 1: UPLOAD CSV
    # ========================
    company_id = fields.Many2one(
        'res.company',
        string='Compañía',
        required=True,
        default=lambda self: self.env.company,
        help='Compañía para la cual se importa el RCV'
    )

    period_date = fields.Date(
        string='Período RCV',
        required=True,
        default=fields.Date.today,
        help='Primer día del mes del período a validar'
    )

    csv_file = fields.Binary(
        string='Archivo CSV SII',
        required=True,
        help='Archivo CSV descargado desde portal SII (registrocompraven taoperacionesconsulta)'
    )

    csv_filename = fields.Char(
        string='Nombre Archivo'
    )

    # ========================
    # PASO 2: RESULTADOS
    # ========================
    state = fields.Selection([
        ('upload', 'Subir CSV'),
        ('result', 'Resultados'),
    ], string='Estado', default='upload')

    # Estadísticas
    sii_records_count = fields.Integer(
        string='Registros en SII',
        readonly=True
    )

    odoo_records_count = fields.Integer(
        string='Registros en Odoo',
        readonly=True
    )

    matched_count = fields.Integer(
        string='Registros Coincidentes',
        readonly=True
    )

    discrepancy_count = fields.Integer(
        string='Discrepancias Encontradas',
        readonly=True
    )

    # Resultados detallados
    result_message = fields.Html(
        string='Resultado',
        readonly=True
    )

    discrepancy_ids = fields.Many2many(
        'l10n_cl.rcv.entry',
        string='Entradas con Discrepancias',
        readonly=True,
        help='Entradas RCV que tienen discrepancias con SII'
    )

    # ========================
    # MÉTODOS
    # ========================
    @api.constrains('period_date')
    def _check_period_date_first_of_month(self):
        """Valida que period_date sea primer día del mes."""
        for wizard in self:
            if wizard.period_date and wizard.period_date.day != 1:
                raise ValidationError(_(
                    'El período debe ser el primer día del mes.\n'
                    'Recibido: %s\n'
                    'Use: %s'
                ) % (
                    wizard.period_date,
                    wizard.period_date.replace(day=1)
                ))

    def action_import_and_validate(self):
        """
        Importa CSV del SII y valida vs registros Odoo.

        Returns:
            dict: Action para mostrar resultados
        """
        self.ensure_one()

        if not self.csv_file:
            raise ValidationError(_('Debe subir un archivo CSV'))

        try:
            # PASO 1: Parsear CSV del SII
            # ===========================
            sii_records = self._parse_sii_csv(self.csv_file, self.csv_filename)

            _logger.info(
                "📥 Parsed %s records from SII CSV: %s",
                len(sii_records),
                self.csv_filename
            )

            # PASO 2: Obtener registros Odoo del período
            # ==========================================
            odoo_entries = self._get_odoo_rcv_entries(
                self.period_date,
                self.company_id.id
            )

            _logger.info(
                "📊 Found %s RCV entries in Odoo for period %s",
                len(odoo_entries),
                self.period_date
            )

            # PASO 3: Comparar registros
            # ===========================
            comparison_result = self._compare_records(sii_records, odoo_entries)

            # PASO 4: Actualizar wizard con resultados
            # =========================================
            self.write({
                'state': 'result',
                'sii_records_count': len(sii_records),
                'odoo_records_count': len(odoo_entries),
                'matched_count': comparison_result['matched_count'],
                'discrepancy_count': comparison_result['discrepancy_count'],
                'result_message': comparison_result['html_report'],
                'discrepancy_ids': [(6, 0, comparison_result['discrepancy_ids'])],
            })

            # PASO 5: Retornar acción para mostrar resultados
            # ================================================
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'rcv.csv.import.wizard',
                'view_mode': 'form',
                'res_id': self.id,
                'target': 'new',
                'context': self.env.context,
            }

        except Exception as e:
            _logger.error(
                "❌ Error importing RCV CSV: %s",
                str(e),
                exc_info=True
            )
            raise UserError(_(
                'Error procesando archivo CSV:\n%s\n\n'
                'Verifique que el archivo sea CSV válido descargado del SII.'
            ) % str(e))

    def _parse_sii_csv(self, csv_file_b64, filename):
        """
        Parsea CSV del SII a lista de diccionarios.

        Formato CSV SII RCV (ejemplo):
        Tipo Doc;Folio;Fecha;RUT;Razón Social;Neto;IVA;Total
        33;12345;01-11-2025;12345678-9;ACME SA;100000;19000;119000

        Args:
            csv_file_b64 (str): Archivo CSV en base64
            filename (str): Nombre del archivo

        Returns:
            list: Lista de diccionarios con datos RCV del SII
        """
        # Decodificar base64
        csv_content = base64.b64decode(csv_file_b64).decode('latin1')

        # Parsear CSV
        csv_reader = csv.DictReader(
            StringIO(csv_content),
            delimiter=';'  # SII usa punto y coma
        )

        records = []
        for row in csv_reader:
            # Normalizar nombres de columnas (SII puede variar)
            normalized_row = self._normalize_sii_row(row)

            if normalized_row:  # Skip empty rows
                records.append(normalized_row)

        return records

    def _normalize_sii_row(self, row):
        """
        Normaliza fila CSV del SII a formato estándar.

        Mapea variaciones de nombres de columnas del SII.
        """
        # Mapping de columnas SII → estándar
        tipo_doc = row.get('Tipo Doc') or row.get('Tipo Documento') or row.get('tipo_doc')
        folio = row.get('Folio') or row.get('folio')
        rut = row.get('RUT') or row.get('Rut') or row.get('rut')
        monto_total = row.get('Total') or row.get('Monto Total') or row.get('monto_total') or 0

        # Si falta dato esencial, skip
        if not (tipo_doc and folio and rut):
            return None

        # Limpiar RUT (remover puntos y guiones)
        rut_clean = rut.replace('.', '').replace('-', '')

        # Limpiar montos (remover separadores)
        try:
            monto_total = float(str(monto_total).replace('.', '').replace(',', '.'))
        except (ValueError, AttributeError):
            monto_total = 0.0

        return {
            'tipo_doc': str(tipo_doc).strip(),
            'folio': int(folio),
            'rut': rut_clean,
            'monto_total': monto_total,
        }

    def _get_odoo_rcv_entries(self, period_date, company_id):
        """
        Obtiene entradas RCV de Odoo para el período.

        Args:
            period_date (date): Período (primer día del mes)
            company_id (int): ID de la compañía

        Returns:
            l10n_cl.rcv.entry: Recordset
        """
        period = self.env['l10n_cl.rcv.period'].search([
            ('company_id', '=', company_id),
            ('period_date', '=', period_date),
        ], limit=1)

        if not period:
            # No hay período → no hay entradas
            return self.env['l10n_cl.rcv.entry']

        return period.entry_ids

    def _compare_records(self, sii_records, odoo_entries):
        """
        Compara registros SII vs Odoo y marca discrepancias.

        Args:
            sii_records (list): Registros del CSV SII
            odoo_entries (l10n_cl.rcv.entry): Registros Odoo

        Returns:
            dict: Resultado de la comparación
        """
        matched_count = 0
        discrepancy_count = 0
        discrepancy_ids = []
        discrepancies_detail = []

        # Crear índice de registros SII
        sii_index = {}
        for sii_rec in sii_records:
            key = (
                sii_rec['tipo_doc'],
                sii_rec['folio'],
                sii_rec['rut']
            )
            sii_index[key] = sii_rec

        # Comparar cada entrada Odoo
        for odoo_entry in odoo_entries:
            # Construir clave
            key = (
                str(odoo_entry.document_type_id.code),
                odoo_entry.folio,
                odoo_entry.partner_vat.replace('.', '').replace('-', '')
            )

            if key not in sii_index:
                # DISCREPANCIA: En Odoo pero NO en SII
                odoo_entry.write({
                    'sii_discrepancy': True,
                    'sii_discrepancy_detail': 'Documento NO encontrado en CSV del SII',
                    'sii_sync_date': fields.Datetime.now(),
                })

                discrepancy_count += 1
                discrepancy_ids.append(odoo_entry.id)

                discrepancies_detail.append({
                    'type': 'missing_in_sii',
                    'doc_type': odoo_entry.document_type_id.name,
                    'folio': odoo_entry.folio,
                    'partner': odoo_entry.partner_name,
                    'amount': odoo_entry.amount_total,
                })

            else:
                # Registro existe en ambos - verificar montos
                sii_rec = sii_index[key]

                # Tolerancia: 1 peso chileno
                if abs(sii_rec['monto_total'] - odoo_entry.amount_total) > 1:
                    # DISCREPANCIA: Monto diferente
                    odoo_entry.write({
                        'sii_discrepancy': True,
                        'sii_discrepancy_detail': f'Monto diferente: SII=${sii_rec["monto_total"]:,.0f} vs Odoo=${odoo_entry.amount_total:,.0f}',
                        'sii_sync_date': fields.Datetime.now(),
                    })

                    discrepancy_count += 1
                    discrepancy_ids.append(odoo_entry.id)

                    discrepancies_detail.append({
                        'type': 'amount_mismatch',
                        'doc_type': odoo_entry.document_type_id.name,
                        'folio': odoo_entry.folio,
                        'partner': odoo_entry.partner_name,
                        'sii_amount': sii_rec['monto_total'],
                        'odoo_amount': odoo_entry.amount_total,
                    })

                else:
                    # TODO OK - limpiar discrepancia previa si existe
                    odoo_entry.write({
                        'sii_discrepancy': False,
                        'sii_discrepancy_detail': False,
                        'sii_sync_date': fields.Datetime.now(),
                        'sii_state': 'accepted',
                    })
                    matched_count += 1

        # Verificar registros en SII que NO están en Odoo
        odoo_keys = {
            (
                str(entry.document_type_id.code),
                entry.folio,
                entry.partner_vat.replace('.', '').replace('-', '')
            )
            for entry in odoo_entries
        }

        for key, sii_rec in sii_index.items():
            if key not in odoo_keys:
                # DISCREPANCIA: En SII pero NO en Odoo
                discrepancy_count += 1

                discrepancies_detail.append({
                    'type': 'missing_in_odoo',
                    'doc_type': sii_rec['tipo_doc'],
                    'folio': sii_rec['folio'],
                    'rut': sii_rec['rut'],
                    'amount': sii_rec['monto_total'],
                })

        # Generar reporte HTML
        html_report = self._generate_html_report(
            len(sii_records),
            len(odoo_entries),
            matched_count,
            discrepancy_count,
            discrepancies_detail
        )

        return {
            'matched_count': matched_count,
            'discrepancy_count': discrepancy_count,
            'discrepancy_ids': discrepancy_ids,
            'html_report': html_report,
        }

    def _generate_html_report(self, sii_count, odoo_count, matched, discrepancies, details):
        """Genera reporte HTML con resultados."""

        # Determinar clase CSS según resultado
        if discrepancies == 0:
            alert_class = 'alert-success'
            icon = '✅'
            title = 'Validación Exitosa'
        elif discrepancies < 5:
            alert_class = 'alert-warning'
            icon = '⚠️'
            title = 'Discrepancias Menores'
        else:
            alert_class = 'alert-danger'
            icon = '❌'
            title = 'Discrepancias Significativas'

        html = f"""
        <div class="alert {alert_class}" role="status">
            <h4>{icon} {title}</h4>
            <hr/>
            <p><strong>Resumen de Validación:</strong></p>
            <ul>
                <li>Registros en SII: <strong>{sii_count}</strong></li>
                <li>Registros en Odoo: <strong>{odoo_count}</strong></li>
                <li>Coincidentes: <strong>{matched}</strong></li>
                <li>Discrepancias: <strong>{discrepancies}</strong></li>
            </ul>
        </div>
        """

        if discrepancies > 0:
            html += """
            <div class="mt-3">
                <h5>Detalle de Discrepancias:</h5>
                <table class="table table-sm table-bordered">
                    <thead>
                        <tr>
                            <th>Tipo</th>
                            <th>Doc</th>
                            <th>Folio</th>
                            <th>Cliente/Proveedor</th>
                            <th>Detalle</th>
                        </tr>
                    </thead>
                    <tbody>
            """

            for disc in details[:20]:  # Mostrar max 20
                if disc['type'] == 'missing_in_sii':
                    html += f"""
                    <tr class="table-warning">
                        <td>NO en SII</td>
                        <td>{disc['doc_type']}</td>
                        <td>{disc['folio']}</td>
                        <td>{disc['partner']}</td>
                        <td>${disc['amount']:,.0f}</td>
                    </tr>
                    """
                elif disc['type'] == 'amount_mismatch':
                    html += f"""
                    <tr class="table-danger">
                        <td>Monto ≠</td>
                        <td>{disc['doc_type']}</td>
                        <td>{disc['folio']}</td>
                        <td>{disc['partner']}</td>
                        <td>SII: ${disc['sii_amount']:,.0f} | Odoo: ${disc['odoo_amount']:,.0f}</td>
                    </tr>
                    """
                elif disc['type'] == 'missing_in_odoo':
                    html += f"""
                    <tr class="table-info">
                        <td>NO en Odoo</td>
                        <td>{disc['doc_type']}</td>
                        <td>{disc['folio']}</td>
                        <td>{disc['rut']}</td>
                        <td>${disc['amount']:,.0f}</td>
                    </tr>
                    """

            html += """
                    </tbody>
                </table>
            </div>
            """

            if len(details) > 20:
                html += f"""
                <p class="text-muted">
                    <small>Mostrando 20 de {len(details)} discrepancias.
                    Use el botón "Ver Discrepancias" para ver todas.</small>
                </p>
                """

        return html

    # ========================
    # ACCIONES
    # ========================
    def action_view_discrepancies(self):
        """Abre lista de entradas con discrepancias."""
        self.ensure_one()

        return {
            'type': 'ir.actions.act_window',
            'name': _('Discrepancias RCV'),
            'res_model': 'l10n_cl.rcv.entry',
            'view_mode': 'tree,form',
            'domain': [('id', 'in', self.discrepancy_ids.ids)],
            'context': self.env.context,
        }

    def action_reset(self):
        """Resetea wizard para nueva importación."""
        self.write({
            'state': 'upload',
            'csv_file': False,
            'csv_filename': False,
            'result_message': False,
            'discrepancy_ids': [(5, 0, 0)],
        })

        return {
            'type': 'ir.actions.act_window',
            'res_model': 'rcv.csv.import.wizard',
            'view_mode': 'form',
            'res_id': self.id,
            'target': 'new',
            'context': self.env.context,
        }
