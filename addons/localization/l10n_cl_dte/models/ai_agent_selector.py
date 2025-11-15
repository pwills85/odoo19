# -*- coding: utf-8 -*-
"""
AI Agent Selector - RBAC-Aware Plugin Selection
================================================

Intelligent plugin selection system that respects user permissions.

Features:
- RBAC enforcement (user groups → allowed plugins)
- Context-aware selection (active_model, query keywords)
- Fallback strategies (if no match found)
- Permission validation before AI calls

Author: EERGYGROUP - Phase 2 Enhancement 2025-10-24
"""

from odoo import models, api, _
from odoo.exceptions import AccessError
import logging

_logger = logging.getLogger(__name__)


class AIAgentSelector(models.AbstractModel):
    """
    Abstract model for intelligent AI agent/plugin selection.

    Used by ai.chat.wizard and other AI integration points to select
    the appropriate AI Service plugin based on:
    1. User permissions (RBAC)
    2. Query context (keywords, active_model)
    3. Explicit hints

    Competitive advantage: SAP/Oracle/NetSuite don't have RBAC-aware AI.
    """
    _name = 'ai.agent.selector'
    _description = 'AI Agent Selector (RBAC-Aware)'

    # ═══════════════════════════════════════════════════════════════════
    # RBAC MAPPING: Odoo Groups → AI Plugins
    # ═══════════════════════════════════════════════════════════════════

    GROUP_PLUGIN_MAP = {
        # Accounting
        'account.group_account_user': ['account', 'l10n_cl_dte'],
        'account.group_account_manager': ['account', 'l10n_cl_dte', 'purchase', 'sale'],

        # Purchase
        'purchase.group_purchase_user': ['purchase', 'stock'],
        'purchase.group_purchase_manager': ['purchase', 'stock', 'account'],

        # Stock
        'stock.group_stock_user': ['stock', 'purchase'],
        'stock.group_stock_manager': ['stock', 'purchase', 'sale'],

        # Sales
        'sale.group_sale_user': ['sale', 'stock'],
        'sale.group_sale_manager': ['sale', 'stock', 'account'],

        # HR Payroll
        'hr.group_hr_user': ['hr_payroll'],
        'hr_payroll.group_hr_payroll_user': ['hr_payroll'],

        # Project
        'project.group_project_user': ['project'],
        'project.group_project_manager': ['project', 'account'],

        # Chilean DTE
        'l10n_cl_dte.group_dte_user': ['l10n_cl_dte'],
        'l10n_cl_dte.group_dte_manager': ['l10n_cl_dte', 'account'],

        # System Admin: all plugins
        'base.group_system': ['account', 'purchase', 'stock', 'sale',
                             'hr_payroll', 'project', 'l10n_cl_dte'],
    }

    # ═══════════════════════════════════════════════════════════════════
    # MODEL → PLUGIN MAPPING
    # ═══════════════════════════════════════════════════════════════════

    MODEL_PLUGIN_MAP = {
        'account.move': 'account',
        'account.payment': 'account',
        'account.bank.statement': 'account',
        'account.journal': 'account',

        'purchase.order': 'purchase',
        'purchase.order.line': 'purchase',

        'stock.picking': 'stock',
        'stock.move': 'stock',
        'stock.quant': 'stock',
        'stock.warehouse': 'stock',

        'sale.order': 'sale',
        'sale.order.line': 'sale',

        'hr.payslip': 'hr_payroll',
        'hr.employee': 'hr_payroll',

        'project.project': 'project',
        'project.task': 'project',

        # DTE models
        'dte.inbox': 'l10n_cl_dte',
        'dte.certificate': 'l10n_cl_dte',
        'dte.caf': 'l10n_cl_dte',
        'dte.libro': 'l10n_cl_dte',
    }

    # ═══════════════════════════════════════════════════════════════════
    # PLUGIN SELECTION
    # ═══════════════════════════════════════════════════════════════════

    @api.model
    def get_allowed_plugins(self, user=None):
        """
        Get list of AI plugins user is allowed to access.

        Args:
            user (res.users, optional): User to check (defaults to current user)

        Returns:
            list: Plugin names user can access (e.g., ['account', 'l10n_cl_dte'])
        """
        if user is None:
            user = self.env.user

        # Get user groups (XML IDs)
        user_group_ids = user.groups_id
        user_group_xmlids = set()

        for group in user_group_ids:
            xmlid = self.env['ir.model.data'].search([
                ('model', '=', 'res.groups'),
                ('res_id', '=', group.id)
            ], limit=1)

            if xmlid:
                full_xmlid = f"{xmlid.module}.{xmlid.name}"
                user_group_xmlids.add(full_xmlid)

        # Map groups to plugins
        allowed_plugins = set()

        for group_xmlid in user_group_xmlids:
            if group_xmlid in self.GROUP_PLUGIN_MAP:
                plugins = self.GROUP_PLUGIN_MAP[group_xmlid]
                allowed_plugins.update(plugins)

        _logger.info(
            "User %s has access to plugins: %s (from groups: %s)",
            user.login,
            list(allowed_plugins),
            list(user_group_xmlids)
        )

        return list(allowed_plugins)

    @api.model
    def select_plugin(self, query='', context=None, user=None):
        """
        Intelligent plugin selection with RBAC enforcement.

        Selection strategy:
        1. Get allowed plugins for user (RBAC)
        2. Check explicit context hint (context['plugin'])
        3. Check active_model hint (context['active_model'])
        4. Keyword matching in query
        5. Fallback to default plugin

        Args:
            query (str): User query text
            context (dict): Context with hints (active_model, plugin, etc.)
            user (res.users, optional): User (defaults to current)

        Returns:
            str: Selected plugin name (e.g., 'account')

        Raises:
            AccessError: If user has no access to any plugin
        """
        if user is None:
            user = self.env.user

        if context is None:
            context = {}

        # 1. Get allowed plugins (RBAC)
        allowed_plugins = self.get_allowed_plugins(user)

        if not allowed_plugins:
            _logger.error(
                "User %s has no access to any AI plugins (groups: %s)",
                user.login,
                user.groups_id.mapped('name')
            )
            raise AccessError(_(
                'No tienes permisos para usar el asistente AI.\n'
                'Contacta al administrador para obtener acceso.'
            ))

        _logger.info(
            "Plugin selection for user=%s, query='%s', context=%s",
            user.login,
            query[:100] if query else '',
            context
        )

        # 2. Explicit context hint
        if context.get('plugin'):
            requested_plugin = context['plugin']

            if requested_plugin in allowed_plugins:
                _logger.info("✅ Plugin selected: %s (explicit hint)", requested_plugin)
                return requested_plugin
            else:
                _logger.warning(
                    "⚠️ User %s requested plugin '%s' but has no access. "
                    "Allowed: %s. Falling back.",
                    user.login,
                    requested_plugin,
                    allowed_plugins
                )

        # 3. Active model hint
        active_model = context.get('active_model')

        if active_model and active_model in self.MODEL_PLUGIN_MAP:
            suggested_plugin = self.MODEL_PLUGIN_MAP[active_model]

            if suggested_plugin in allowed_plugins:
                _logger.info(
                    "✅ Plugin selected: %s (from active_model=%s)",
                    suggested_plugin,
                    active_model
                )
                return suggested_plugin

        # 4. Keyword matching in query
        if query:
            plugin_scores = self._score_plugins_by_query(query, allowed_plugins)

            if plugin_scores:
                best_plugin = max(plugin_scores, key=plugin_scores.get)
                best_score = plugin_scores[best_plugin]

                if best_score > 0:
                    _logger.info(
                        "✅ Plugin selected: %s (keyword match, score=%d)",
                        best_plugin,
                        best_score
                    )
                    return best_plugin

        # 5. Fallback to default plugin (first in allowed list)
        default_plugin = self._get_default_plugin(allowed_plugins)

        _logger.info(
            "✅ Plugin selected: %s (fallback, no clear match)",
            default_plugin
        )

        return default_plugin

    @api.model
    def _score_plugins_by_query(self, query, allowed_plugins):
        """
        Score plugins based on keyword matching in query.

        Args:
            query (str): User query
            allowed_plugins (list): Plugins user can access

        Returns:
            dict: {plugin_name: score}
        """
        query_lower = query.lower()

        # Keywords per plugin (Spanish + English)
        KEYWORDS = {
            'account': [
                # Spanish
                'contabilidad', 'asiento', 'diario', 'cuenta', 'balance',
                'conciliación', 'conciliacion', 'estado de resultados',
                'libro mayor', 'impuesto', 'iva', 'reporte financiero',
                # English
                'accounting', 'journal', 'account', 'balance sheet',
                'reconciliation', 'tax', 'financial report'
            ],

            'purchase': [
                # Spanish
                'compra', 'orden de compra', 'proveedor', 'cotización',
                'cotizacion', 'solicitud de compra', 'recepción', 'recepcion',
                'factura de proveedor', 'pago a proveedor',
                # English
                'purchase', 'purchase order', 'vendor', 'supplier',
                'quotation', 'receipt', 'bill'
            ],

            'stock': [
                # Spanish
                'inventario', 'stock', 'producto', 'almacén', 'almacen',
                'picking', 'transferencia', 'bodega', 'ubicación', 'ubicacion',
                'entrada', 'salida', 'ajuste de inventario', 'lote', 'serie',
                # English
                'inventory', 'warehouse', 'product', 'location',
                'transfer', 'delivery', 'receipt', 'lot', 'serial'
            ],

            'sale': [
                # Spanish
                'venta', 'orden de venta', 'cliente', 'cotización',
                'cotizacion', 'pedido', 'despacho', 'factura de venta',
                'cobro', 'presupuesto',
                # English
                'sale', 'sales order', 'customer', 'quotation',
                'delivery', 'invoice'
            ],

            'hr_payroll': [
                # Spanish
                'liquidación', 'liquidacion', 'sueldo', 'nómina', 'nomina',
                'payroll', 'afp', 'isapre', 'salud', 'previred',
                'gratificación', 'gratificacion', 'bono', 'descuento',
                'imponible', 'horas extras', 'asignación familiar',
                # English
                'payslip', 'salary', 'wage', 'deduction', 'bonus'
            ],

            'project': [
                # Spanish
                'proyecto', 'tarea', 'milestone', 'hito', 'gantt',
                'planificación', 'planificacion', 'recurso',
                'timesheet', 'hoja de tiempo', 'avance', 'progreso',
                # English
                'project', 'task', 'milestone', 'planning', 'tracking',
                'timesheet', 'progress'
            ],

            'l10n_cl_dte': [
                # Spanish
                'dte', 'factura', 'boleta', 'guía', 'guia', 'nota de crédito',
                'nota de credito', 'nota de débito', 'nota de debito',
                'sii', 'folio', 'caf', 'certificado digital', 'timbre',
                'enviar al sii', 'rechazar', 'anular', 'envío', 'envio',
                'facturación electrónica', 'facturacion electronica',
                # English
                'electronic invoice', 'invoice', 'credit note', 'debit note',
                'shipping guide', 'send to sii'
            ]
        }

        scores = {}

        for plugin in allowed_plugins:
            if plugin not in KEYWORDS:
                continue

            keywords = KEYWORDS[plugin]
            score = sum(1 for kw in keywords if kw in query_lower)

            if score > 0:
                scores[plugin] = score

        return scores

    @api.model
    def _get_default_plugin(self, allowed_plugins):
        """
        Get default plugin from allowed list.

        Priority:
        1. l10n_cl_dte (most specific)
        2. account (most common)
        3. First in list

        Args:
            allowed_plugins (list): Plugins user can access

        Returns:
            str: Default plugin name
        """
        # Priority order
        priority_order = ['l10n_cl_dte', 'account', 'purchase', 'stock', 'sale']

        for plugin in priority_order:
            if plugin in allowed_plugins:
                return plugin

        # Fallback to first available
        return allowed_plugins[0] if allowed_plugins else 'l10n_cl_dte'

    @api.model
    def validate_plugin_access(self, plugin, user=None):
        """
        Validate user has access to plugin.

        Args:
            plugin (str): Plugin name
            user (res.users, optional): User to check

        Returns:
            bool: True if user has access

        Raises:
            AccessError: If user has no access
        """
        allowed_plugins = self.get_allowed_plugins(user)

        if plugin not in allowed_plugins:
            _logger.error(
                "User %s tried to access plugin '%s' without permission. Allowed: %s",
                (user or self.env.user).login,
                plugin,
                allowed_plugins
            )
            raise AccessError(_(
                'No tienes permisos para usar el módulo de IA "%s".\n'
                'Contacta al administrador del sistema.'
            ) % plugin)

        return True
