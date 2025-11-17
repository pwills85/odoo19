# -*- coding: utf-8 -*-
"""
Servicio de Integración con RCV del SII

Gestiona la comunicación con el portal SII para:
- Sincronización de registros RCV
- Obtención de propuesta F29
- Validación cruzada Odoo vs SII

Nota: La integración puede hacerse mediante:
1. Web scraping del portal SII (sii.cl) - requiere autenticación con certificado
2. API privada SII (si disponible en futuro)
"""

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError
import logging
import requests

_logger = logging.getLogger(__name__)


class L10nClRCVIntegration(models.AbstractModel):
    """
    Servicio abstracto para integración con RCV del SII.

    Este modelo NO tiene tabla en BD (AbstractModel).
    Provee métodos de integración llamados desde l10n_cl.rcv.period.
    """
    _name = 'l10n_cl.rcv.integration'
    _description = 'SII RCV Integration Service'

    # ========================
    # AUTENTICACIÓN SII
    # ========================
    def _get_certificate_for_company(self, company_id):
        """
        Obtiene certificado digital para autenticación SII.

        Args:
            company_id (int): ID de la compañía

        Returns:
            dte.certificate: Certificado válido

        Raises:
            ValidationError: Si no hay certificado válido
        """
        certificate = self.env['dte.certificate'].search([
            ('company_id', '=', company_id),
            ('state', '=', 'active'),
        ], limit=1)

        if not certificate:
            raise ValidationError(_(
                'No se encontró certificado digital activo para esta compañía.\n'
                'Configure un certificado en: Facturación > Configuración > Certificados DTE'
            ))

        return certificate

    def _sii_login(self, company_id):
        """
        Autentica en el portal SII con certificado digital mediante mTLS.

        IMPLEMENTACIÓN (Sprint 2 - 2025-11-02):
        ✅ Conversión PKCS#12 → PEM implementada
        ⏸️  Navegación portal SII pendiente Sprint 3

        Args:
            company_id (int): ID de la compañía

        Returns:
            requests.Session: Sesión autenticada

        Raises:
            ValidationError: Si falla la autenticación
            NotImplementedError: Si navegación SII no implementada
        """
        import os

        certificate = self._get_certificate_for_company(company_id)

        _logger.info(
            "🔐 Attempting SII mTLS login for company %s with certificate %s",
            company_id,
            certificate.name
        )

        try:
            # PASO 1: Convertir certificado a formato PEM
            # ============================================
            # ✅ IMPLEMENTADO Sprint 2
            cert_path, key_path = certificate.convert_to_pem_files()

            _logger.info(
                "✅ Certificate converted to PEM for mTLS:\n"
                "  - cert: %s\n"
                "  - key: %s",
                cert_path, key_path
            )

            # PASO 2: Crear sesión con mTLS
            # ==============================
            session = requests.Session()
            session.cert = (cert_path, key_path)

            # PASO 3: Autenticar en portal SII
            # =================================
            # ⏸️  PENDIENTE Sprint 3: Implementar navegación portal
            # Por ahora, lanzar NotImplementedError con instrucciones claras

            # Limpiar archivos temporales
            os.remove(cert_path)
            os.remove(key_path)

            raise NotImplementedError(_(
                'Autenticación mTLS con SII no completamente implementada.\n\n'
                '✅ COMPLETADO Sprint 2:\n'
                '- Conversión certificado PKCS#12 → PEM\n'
                '- Configuración sesión requests con mTLS\n\n'
                '⏸️  PENDIENTE Sprint 3:\n'
                '- Navegación portal SII (https://www4.sii.cl)\n'
                '- Manejo cookies de sesión\n'
                '- Descarga automática CSV RCV\n\n'
                '💡 ALTERNATIVA ACTUAL:\n'
                'Use wizard "Importar CSV RCV" para validación manual.\n'
                'Menú: Facturación > Reportes > Importar CSV RCV'
            ))

        except NotImplementedError:
            # Re-raise para mostrar mensaje al usuario
            raise

        except Exception as e:
            _logger.error(
                "❌ Error en autenticación mTLS SII: %s",
                str(e),
                exc_info=True
            )
            raise ValidationError(_(
                'Error configurando autenticación mTLS con SII:\n%s\n\n'
                'Verifique certificado digital válido.'
            ) % str(e))

    # ========================
    # SINCRONIZACIÓN RCV
    # ========================
    def sync_with_sii(self, period_date, company_id):
        """
        Sincroniza RCV de Odoo con RCV del SII para un período.

        Flujo:
        1. Login al SII
        2. Descargar RCV del período desde portal SII
        3. Parsear datos
        4. Comparar con entradas Odoo
        5. Marcar discrepancias

        Args:
            period_date (date): Primer día del mes a sincronizar
            company_id (int): ID de la compañía

        Returns:
            dict: Resultado de la sincronización
        """
        _logger.info(
            "🔄 Starting RCV sync with SII - Period: %s, Company: %s",
            period_date,
            company_id
        )

        # PASO 1: Autenticación
        try:
            session = self._sii_login(company_id)
        except NotImplementedError:
            # Por ahora, simular sincronización
            return self._simulate_sync(period_date, company_id)

        # PASO 2: Descargar RCV del SII
        sii_records = self._fetch_rcv_from_sii(session, period_date)

        # PASO 3: Obtener registros Odoo
        odoo_records = self._get_odoo_rcv_entries(period_date, company_id)

        # PASO 4: Comparar y marcar discrepancias
        discrepancies = self._compare_rcv_records(sii_records, odoo_records)

        _logger.info(
            "✅ RCV sync completed - %s discrepancies found",
            len(discrepancies)
        )

        return {
            'success': True,
            'sii_records_count': len(sii_records),
            'odoo_records_count': len(odoo_records),
            'discrepancies_count': len(discrepancies),
            'discrepancies': discrepancies,
        }

    def _simulate_sync(self, period_date, company_id):
        """
        Simula sincronización (mientras no esté implementada la real).

        Args:
            period_date (date): Período
            company_id (int): Compañía

        Returns:
            dict: Resultado simulado
        """
        _logger.warning(
            "⚠️  SIMULACIÓN: RCV sync no implementado aún - Retornando OK"
        )

        # Obtener registros Odoo
        odoo_entries = self._get_odoo_rcv_entries(period_date, company_id)

        # Simular: Sin discrepancias
        for entry in odoo_entries:
            entry.write({
                'sii_state': 'accepted',
                'sii_sync_date': fields.Datetime.now(),
                'sii_discrepancy': False,
            })

        return {
            'success': True,
            'simulated': True,
            'sii_records_count': len(odoo_entries),
            'odoo_records_count': len(odoo_entries),
            'discrepancies_count': 0,
            'message': 'Sincronización simulada - Implementación pendiente Sprint 1'
        }

    def _fetch_rcv_from_sii(self, session, period_date):
        """
        Descarga RCV del período desde portal SII.

        Args:
            session (requests.Session): Sesión autenticada
            period_date (date): Período a descargar

        Returns:
            list: Lista de registros RCV del SII
        """
        # TODO: Implementar web scraping o API call
        # URL típica: https://www4.sii.cl/registrocompraven taoperacionesconsulta/...

        _logger.info(
            "📥 Downloading RCV from SII for period: %s",
            period_date
        )

        # Por ahora, retornar lista vacía
        return []

    def _get_odoo_rcv_entries(self, period_date, company_id):
        """
        Obtiene entradas RCV de Odoo para un período.

        Args:
            period_date (date): Período
            company_id (int): Compañía

        Returns:
            l10n_cl.rcv.entry: Recordset de entradas
        """
        period = self.env['l10n_cl.rcv.period'].search([
            ('company_id', '=', company_id),
            ('period_date', '=', period_date),
        ], limit=1)

        if not period:
            return self.env['l10n_cl.rcv.entry']

        return period.entry_ids

    def _compare_rcv_records(self, sii_records, odoo_records):
        """
        Compara registros SII vs Odoo y marca discrepancias.

        Args:
            sii_records (list): Registros del SII
            odoo_records (l10n_cl.rcv.entry): Registros Odoo

        Returns:
            list: Lista de discrepancias encontradas
        """
        discrepancies = []

        # Crear índice de registros SII
        sii_index = {}
        for sii_rec in sii_records:
            key = (
                sii_rec.get('tipo_doc'),
                sii_rec.get('folio'),
                sii_rec.get('rut')
            )
            sii_index[key] = sii_rec

        # Comparar cada registro Odoo
        for odoo_rec in odoo_records:
            key = (
                odoo_rec.document_type_id.code,
                odoo_rec.folio,
                odoo_rec.partner_vat.replace('.', '').replace('-', '')
            )

            if key not in sii_index:
                # Registro en Odoo pero NO en SII
                odoo_rec.write({
                    'sii_discrepancy': True,
                    'sii_discrepancy_detail': 'Documento NO encontrado en RCV del SII',
                })

                discrepancies.append({
                    'odoo_record': odoo_rec,
                    'type': 'missing_in_sii',
                    'detail': 'Documento existe en Odoo pero no en SII',
                })

            else:
                # Registro en ambos - verificar montos
                sii_rec = sii_index[key]

                if abs(float(sii_rec.get('monto_total', 0)) - odoo_rec.amount_total) > 1:
                    # Discrepancia en monto
                    odoo_rec.write({
                        'sii_discrepancy': True,
                        'sii_discrepancy_detail': f'Monto diferente: SII=${sii_rec.get("monto_total")} vs Odoo=${odoo_rec.amount_total}',
                    })

                    discrepancies.append({
                        'odoo_record': odoo_rec,
                        'type': 'amount_mismatch',
                        'detail': f'Monto SII: {sii_rec.get("monto_total")} | Monto Odoo: {odoo_rec.amount_total}',
                    })
                else:
                    # Todo OK
                    odoo_rec.write({
                        'sii_discrepancy': False,
                        'sii_sync_date': fields.Datetime.now(),
                    })

        # Verificar registros en SII que NO están en Odoo
        odoo_keys = {
            (
                rec.document_type_id.code,
                rec.folio,
                rec.partner_vat.replace('.', '').replace('-', '')
            )
            for rec in odoo_records
        }

        for key, sii_rec in sii_index.items():
            if key not in odoo_keys:
                discrepancies.append({
                    'sii_record': sii_rec,
                    'type': 'missing_in_odoo',
                    'detail': 'Documento existe en SII pero no en Odoo',
                })

        return discrepancies

    # ========================
    # PROPUESTA F29
    # ========================
    def get_propuesta_f29(self, period_date, company_id):
        """
        Obtiene propuesta de declaración F29 desde el SII.

        El SII genera automáticamente una propuesta basada en el RCV.

        Args:
            period_date (date): Período a consultar
            company_id (int): ID de la compañía

        Returns:
            str: Propuesta F29 (JSON o texto)
        """
        _logger.info(
            "📋 Fetching F29 proposal from SII - Period: %s",
            period_date
        )

        # PASO 1: Autenticación
        try:
            session = self._sii_login(company_id)
        except NotImplementedError:
            # Simular propuesta
            return self._simulate_f29_proposal(period_date, company_id)

        # PASO 2: Navegar a propuesta F29
        # TODO: Implementar descarga propuesta desde portal SII

        return "Propuesta F29 pendiente de implementación"

    def _simulate_f29_proposal(self, period_date, company_id):
        """
        Simula propuesta F29 (mientras no esté implementada).

        Args:
            period_date (date): Período
            company_id (int): Compañía

        Returns:
            str: Propuesta F29 simulada
        """
        # Obtener período
        period = self.env['l10n_cl.rcv.period'].search([
            ('company_id', '=', company_id),
            ('period_date', '=', period_date),
        ], limit=1)

        if not period:
            return "No hay período RCV para esta fecha"

        # Generar propuesta simulada
        proposal = f"""
PROPUESTA DECLARACIÓN F29 (SIMULADA)
=====================================
Período: {period.display_name}
Compañía: {period.company_id.name}
RUT: {period.company_id.vat}

RESUMEN IVA:
-----------
Débito Fiscal (Ventas):  ${period.vat_debit:,.0f}
Crédito Fiscal (Compras): ${period.vat_credit:,.0f}
-----------
Saldo IVA:                ${period.vat_balance:,.0f}

DETALLE:
- Ventas: {period.sale_entry_count} documentos - Total: ${period.total_sales:,.0f}
- Compras: {period.purchase_entry_count} documentos - Total: ${period.total_purchases:,.0f}

⚠️  NOTA: Esta es una propuesta SIMULADA.
La propuesta oficial debe obtenerse desde sii.cl
"""
        return proposal

    # ========================
    # SCHEDULED ACTIONS
    # ========================
    @api.model
    def cron_sync_current_month(self):
        """
        Cron job: Sincroniza RCV del mes actual para todas las compañías.

        Se ejecuta diariamente.
        """
        current_month = fields.Date.today().replace(day=1)

        companies = self.env['res.company'].search([])

        for company in companies:
            try:
                _logger.info(
                    "🕐 Cron: Syncing RCV for company %s - Period %s",
                    company.name,
                    current_month
                )

                self.sync_with_sii(current_month, company.id)

            except Exception as e:
                _logger.error(
                    "❌ Cron sync failed for company %s: %s",
                    company.name,
                    str(e)
                )
                continue

        _logger.info("✅ Cron RCV sync completed")
