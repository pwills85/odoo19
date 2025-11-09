# -*- coding: utf-8 -*-
"""
Account Move Extension for EERGYGROUP DTE Customizations
=========================================================

This module extends account.move to add EERGYGROUP-specific fields
for Chilean electronic invoicing (DTE).

Key Features:
- contact_id: Customer contact person (Many2one res.partner)
- forma_pago: Custom payment terms description (Char)
- cedible: Flag to enable CEDIBLE section for factoring (Boolean)
- reference_ids: SII document references (One2many)

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.1.0.0
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, UserError


class AccountMove(models.Model):
    """
    Extension of account.move for EERGYGROUP DTE customizations.

    Adds Chilean-specific fields and business logic for:
    - Contact person tracking
    - Custom payment terms
    - CEDIBLE support (factoring/credit assignment)
    - SII document references (mandatory for NC/ND)

    Technical Implementation:
    - Follows Odoo 19 CE best practices
    - Full constraint validation
    - Computed fields with caching
    - Onchange methods for UX
    - Business methods for workflows
    """
    _inherit = 'account.move'

    # ========================================================================
    # FIELDS
    # ========================================================================

    contact_id = fields.Many2one(
        comodel_name='res.partner',
        string='Contact Person',
        domain="[('type', '=', 'contact'), '|', ('parent_id', '=', partner_id), ('id', '=', partner_id)]",
        help='Contact person at the customer for this invoice. '
             'Automatically populated from customer default contact.',
        tracking=True,
        copy=False,
        index=True,
    )

    forma_pago = fields.Char(
        string='Custom Payment Terms',
        help='Additional payment terms description beyond standard payment terms. '
             'Example: "50%% upfront, 50%% on delivery". '
             'Auto-populated from payment term but can be overridden.',
        tracking=True,
        copy=False,
    )

    cedible = fields.Boolean(
        string='Print as CEDIBLE',
        default=False,
        help='Enable CEDIBLE section on PDF report for factoring/credit assignment. '
             'Only applicable to customer invoices and credit notes. '
             'Adds signature fields and legal text per Ley 19.983.',
        tracking=True,
        copy=False,
    )

    reference_ids = fields.One2many(
        comodel_name='account.move.reference',
        inverse_name='move_id',
        string='SII Document References',
        help='References to other fiscal documents as required by SII. '
             'Mandatory for Credit Notes (DTE 61) and Debit Notes (DTE 56) '
             'to reference the original invoice.',
        copy=False,
    )

    # Computed field: check if references are required
    reference_required = fields.Boolean(
        string='References Required',
        compute='_compute_reference_required',
        store=False,
        help='Technical field: TRUE if this document type requires SII references '
             '(DTE 56: Debit Note, DTE 61: Credit Note)'
    )

    # Computed field: reference count for smart button
    reference_count = fields.Integer(
        string='Reference Count',
        compute='_compute_reference_count',
        store=False,
        help='Number of SII document references attached to this invoice'
    )

    # ========================================================================
    # COMPUTED FIELDS
    # ========================================================================

    @api.depends('dte_code', 'move_type')
    def _compute_reference_required(self):
        """
        Compute if references are required based on DTE type.

        SII Resolution 80 (2014) requires references for:
        - DTE 56: Nota de Débito (must reference original invoice)
        - DTE 61: Nota de Crédito (must reference original invoice)

        Other document types: references are optional but recommended.

        Technical Note:
        - Not stored to avoid DB overhead
        - Recomputed on form load for UI visibility
        """
        for move in self:
            # Referencias obligatorias para Notas Crédito/Débito
            move.reference_required = move.dte_code in ('56', '61')

    @api.depends('reference_ids')
    def _compute_reference_count(self):
        """
        Compute number of SII references for smart button display.

        Returns:
            int: Count of reference_ids records

        Technical Note:
        - Used by stat button widget in form view
        - Recomputed automatically when references added/removed
        """
        for move in self:
            move.reference_count = len(move.reference_ids)

    # ========================================================================
    # ONCHANGE METHODS
    # ========================================================================

    @api.onchange('partner_id')
    def _onchange_partner_id_contact(self):
        """
        Auto-populate contact_id when partner changes.

        Logic:
        1. Find all contact-type children of selected partner
        2. Use first contact as default
        3. User can override manually

        UX Note: Improves data entry speed for B2B invoices
        """
        if self.partner_id:
            # Buscar contacto por defecto (main contact)
            default_contact = self.partner_id.child_ids.filtered(
                lambda c: c.type == 'contact'
            )[:1]
            if default_contact:
                self.contact_id = default_contact
            else:
                # Clear if no contact exists
                self.contact_id = False

    @api.onchange('invoice_payment_term_id')
    def _onchange_payment_term_forma_pago(self):
        """
        Auto-populate forma_pago based on payment term name.

        Logic:
        1. Only populate if forma_pago is empty (no override)
        2. Use payment term name as default
        3. User can modify to add details

        Example:
        - Payment Term: "30 días"
        - forma_pago auto: "30 días"
        - User can change to: "30 días, 50% anticipo, 50% contra entrega"
        """
        if self.invoice_payment_term_id and not self.forma_pago:
            self.forma_pago = self.invoice_payment_term_id.name

    # ========================================================================
    # CONSTRAINTS
    # ========================================================================

    @api.constrains('reference_ids', 'dte_code', 'state')
    def _check_references_required(self):
        """
        Validate that Notas Crédito/Débito have at least one reference.

        SII Requirement:
        - DTE 56/61 MUST reference the original document
        - Validation only on posted documents (state='posted')

        Raises:
            ValidationError: If references are missing for NC/ND

        Technical Note:
        - Validation on state change prevents user from posting invalid docs
        - Allows draft documents without references for data entry
        """
        for move in self:
            if move.state == 'posted' and move.reference_required and not move.reference_ids:
                raise ValidationError(_(
                    "DTE type '%s' (%s) requires at least one document reference.\n\n"
                    "Please add a reference to the original invoice in the 'SII References' tab "
                    "before posting this document.\n\n"
                    "This is a mandatory SII requirement per Resolution 80 (2014)."
                ) % (move.dte_code, move.l10n_latam_document_type_id.name or 'N/A'))

    @api.constrains('cedible', 'move_type')
    def _check_cedible_conditions(self):
        """
        Validate CEDIBLE can only be enabled for customer invoices.

        Business Rule:
        - CEDIBLE (factoring) only applies to customer-facing documents
        - Not applicable to vendor bills or journal entries

        Raises:
            ValidationError: If trying to enable CEDIBLE on wrong document type

        Technical Note:
        - Prevents data inconsistency
        - Improves report performance (no conditional checks on vendor bills)
        """
        for move in self:
            if move.cedible and move.move_type not in ('out_invoice', 'out_refund'):
                raise ValidationError(_(
                    "CEDIBLE can only be enabled for customer invoices and credit notes.\n\n"
                    "Current document type: %s\n"
                    "Allowed types: Customer Invoice, Customer Credit Note"
                ) % dict(self._fields['move_type'].selection).get(move.move_type))

    # ========================================================================
    # BUSINESS METHODS
    # ========================================================================

    def action_add_reference(self):
        """
        Open wizard to add a new document reference.

        Workflow:
        1. User clicks "Add Reference" button
        2. Opens form view in dialog mode
        3. Pre-fills move_id with current invoice
        4. User fills: document type, folio, date, reason
        5. On save, reference is added to One2many

        Returns:
            dict: Action to open wizard dialog

        UX Note: Provides guided data entry for SII references
        """
        self.ensure_one()
        return {
            'name': _('Add Document Reference'),
            'type': 'ir.actions.act_window',
            'res_model': 'account.move.reference',
            'view_mode': 'form',
            'view_id': self.env.ref('l10n_cl_dte_enhanced.view_account_move_reference_form').id,
            'target': 'new',
            'context': {
                'default_move_id': self.id,
                'default_date': fields.Date.today(),
            },
        }

    def action_view_sii_references(self):
        """
        Open list view of SII document references for this invoice.

        Smart Button Action:
        - Displays all references in tree/form view
        - Allows inline editing
        - Shows reference count badge

        Returns:
            dict: Action to open references view

        UX Note: Quick access to manage document references
        """
        self.ensure_one()
        return {
            'name': _('SII References'),
            'type': 'ir.actions.act_window',
            'res_model': 'account.move.reference',
            'view_mode': 'tree,form',
            'domain': [('move_id', '=', self.id)],
            'context': {
                'default_move_id': self.id,
                'default_date': fields.Date.today(),
            },
        }

    def action_view_contact(self):
        """
        Open contact person form view.

        Smart Button Action:
        - Opens contact person in form view
        - Allows quick editing of contact details
        - Returns to invoice after save

        Returns:
            dict: Action to open contact form

        UX Note: Quick access to contact information without leaving invoice
        """
        self.ensure_one()
        if not self.contact_id:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'message': _('No contact person selected for this invoice.'),
                    'type': 'warning',
                    'sticky': False,
                }
            }
        return {
            'name': _('Contact Person'),
            'type': 'ir.actions.act_window',
            'res_model': 'res.partner',
            'view_mode': 'form',
            'res_id': self.contact_id.id,
            'target': 'current',
        }

    def _get_report_base_filename(self):
        """
        Override to include CEDIBLE in PDF filename.

        Logic:
        1. Call super() to get base filename
        2. If CEDIBLE enabled, append '_CEDIBLE' suffix
        3. Return modified filename

        Example:
        - Base: "DTE-33-899"
        - CEDIBLE: "DTE-33-899_CEDIBLE"

        Returns:
            str: Filename for PDF report

        Technical Note:
        - Helps users identify factoring documents in file system
        - No functional impact on SII validation
        """
        self.ensure_one()
        filename = super()._get_report_base_filename()

        if self.cedible:
            filename += '_CEDIBLE'

        return filename

    # ========================================================================
    # OVERRIDE METHODS
    # ========================================================================

    def _post(self, soft=True):
        """
        Override post to validate references before posting NC/ND.

        Workflow:
        1. Check if document requires references (DTE 56/61)
        2. Validate at least one reference exists
        3. Raise error if missing (prevent posting)
        4. Call super() to complete posting

        Args:
            soft (bool): Soft post flag (Odoo standard)

        Returns:
            bool: Post result

        Raises:
            UserError: If references are missing on NC/ND

        Technical Note:
        - Validation happens BEFORE posting (prevents bad data)
        - Uses UserError (user-facing) not ValidationError (constraint)
        - Provides actionable error message with solution
        """
        # Validar referencias antes de validar documento
        for move in self:
            if move.reference_required and not move.reference_ids:
                raise UserError(_(
                    "Cannot post %s without SII document references.\n\n"
                    "Action Required:\n"
                    "1. Go to 'SII References' tab\n"
                    "2. Click 'Add a line'\n"
                    "3. Select document type and enter folio\n"
                    "4. Try posting again\n\n"
                    "This is mandatory for DTE %s per SII Resolution 80."
                ) % (move.name or 'this document', move.dte_code))

        return super()._post(soft=soft)

    @api.model
    def _get_default_contact_id(self, partner_id):
        """
        Helper method: Get default contact for a partner.

        Used by:
        - Form views (compute_default_contact)
        - API calls
        - Automated invoice creation

        Args:
            partner_id (int): Partner ID

        Returns:
            int: Contact ID or False

        Technical Note:
        - Extracted as separate method for reusability
        - Can be called from external modules
        - Does not modify state (pure function)
        """
        if not partner_id:
            return False

        partner = self.env['res.partner'].browse(partner_id)
        default_contact = partner.child_ids.filtered(
            lambda c: c.type == 'contact'
        )[:1]

        return default_contact.id if default_contact else False

    # ========================================================================
    # API METHODS (for external integration)
    # ========================================================================

    @api.model
    def create_with_eergygroup_defaults(self, vals):
        """
        Create invoice with EERGYGROUP defaults applied.

        Convenience method for external integrations (e.g., EDI, API).

        Applies:
        - contact_id from partner default
        - forma_pago from payment term
        - cedible from system parameter

        Args:
            vals (dict): Invoice values

        Returns:
            recordset: Created invoice

        Example:
            invoice = env['account.move'].create_with_eergygroup_defaults({
                'partner_id': 123,
                'invoice_line_ids': [...],
            })
        """
        # Apply defaults
        if 'partner_id' in vals and 'contact_id' not in vals:
            vals['contact_id'] = self._get_default_contact_id(vals['partner_id'])

        if 'invoice_payment_term_id' in vals and 'forma_pago' not in vals:
            term = self.env['account.payment.term'].browse(vals['invoice_payment_term_id'])
            vals['forma_pago'] = term.name

        if 'cedible' not in vals:
            # Check system parameter
            enable_default = self.env['ir.config_parameter'].sudo().get_param(
                'l10n_cl_dte_eergygroup.enable_cedible_by_default', 'False'
            )
            vals['cedible'] = enable_default == 'True'

        return self.create(vals)
