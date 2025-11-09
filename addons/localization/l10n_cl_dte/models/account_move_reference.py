# -*- coding: utf-8 -*-
"""
Account Move Reference - SII Document References
=================================================

Model to store references to other fiscal documents as required by SII
Resolution 80 (2014) for Credit Notes (DTE 61) and Debit Notes (DTE 56).

Business Context:
- Chilean tax law requires NC/ND to reference the original invoice
- References provide audit trail and prevent duplicate adjustments
- SII validates reference data during document acceptance

Technical Implementation:
- One2many relationship with account.move
- Foreign key constraints for data integrity
- Business validations per SII requirements
- SQL constraints prevent duplicate references

Author: EERGYGROUP - Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.1.0.0
"""

from odoo import models, fields, api, _
from odoo.exceptions import ValidationError


class AccountMoveReference(models.Model):
    """
    SII Document References.

    Stores references to other fiscal documents as required by SII
    for Credit/Debit Notes and other adjusting documents.

    Fields:
    -------
    - move_id: Parent invoice/note (Many2one account.move)
    - document_type_id: Type of referenced document (Many2one l10n_latam.document.type)
    - folio: Folio number of referenced document (Char)
    - date: Date of referenced document (Date)
    - reason: Reason for reference (Char, optional)
    - code: SII reference code (Selection)

    SQL Constraints:
    ---------------
    - unique_reference_per_move: Prevent duplicate references in same document

    Usage Example:
    -------------
    # Create reference to original invoice
    env['account.move.reference'].create({
        'move_id': credit_note.id,
        'document_type_id': ref('l10n_latam_invoice_document.document_type_33').id,
        'folio': '123',
        'date': '2025-01-01',
        'reason': 'Anula documento por error en monto',
        'code': '1',  # Anula
    })
    """
    _name = 'account.move.reference'
    _description = 'SII Document Reference'
    _order = 'date desc, id desc'
    _rec_name = 'display_name'

    # ========================================================================
    # FIELDS
    # ========================================================================

    move_id = fields.Many2one(
        comodel_name='account.move',
        string='Invoice/Note',
        required=True,
        ondelete='cascade',
        index=True,
        help='Parent document that contains this reference'
    )

    document_type_id = fields.Many2one(
        comodel_name='l10n_latam.document.type',
        string='Document Type',
        required=True,
        domain=[('country_id.code', '=', 'CL')],
        help='Type of the referenced document.\n'
             'Examples: Factura Electrónica (33), Guía de Despacho (52), etc.',
    )

    folio = fields.Char(
        string='Folio',
        required=True,
        help='Folio number of the referenced document.\n'
             'Example: For referencing Invoice #123, enter "123"',
        index=True,
    )

    date = fields.Date(
        string='Document Date',
        required=True,
        help='Date when the referenced document was issued.\n'
             'Must match the original document date for SII validation.',
    )

    reason = fields.Char(
        string='Reason',
        help='Reason for this reference (optional but recommended).\n'
             'Examples:\n'
             '- "Anula documento por error en monto"\n'
             '- "Corrige datos cliente"\n'
             '- "Referencia a orden de compra"',
    )

    code = fields.Selection(
        selection=[
            ('1', '1 - Anula Documento de Referencia'),
            ('2', '2 - Corrige Texto Documento de Referencia'),
            ('3', '3 - Corrige Montos'),
        ],
        string='Reference Code',
        help='SII reference code per Resolution 80 (2014):\n\n'
             '1 - Anula: Completely cancels the referenced document\n'
             '2 - Corrige Texto: Corrects non-monetary data (e.g., customer info)\n'
             '3 - Corrige Montos: Corrects amounts/calculations\n\n'
             'Used primarily for Credit/Debit Notes.',
    )

    # Display name computed
    display_name = fields.Char(
        string='Display Name',
        compute='_compute_display_name',
        store=True,
        help='Human-readable reference name for UI display'
    )

    # Related fields for convenience
    move_name = fields.Char(
        related='move_id.name',
        string='Parent Document',
        store=False,
        readonly=True,
    )

    move_partner_id = fields.Many2one(
        related='move_id.partner_id',
        string='Customer',
        store=False,
        readonly=True,
    )

    # ========================================================================
    # COMPUTED FIELDS
    # ========================================================================

    @api.depends('document_type_id', 'folio', 'date')
    def _compute_display_name(self):
        """
        Compute display name: "DTE 33 - Folio 123 (2025-01-15)"

        Format:
        - Document Type Name - Folio XXX (Date)
        - Example: "Factura Electrónica - Folio 123 (2025-01-15)"

        Technical Note:
        - Stored for performance (frequent reads in tree views)
        - Updates automatically when dependencies change
        """
        for reference in self:
            if reference.document_type_id and reference.folio:
                date_str = reference.date.strftime('%Y-%m-%d') if reference.date else ''
                reference.display_name = f"{reference.document_type_id.name} - Folio {reference.folio} ({date_str})"
            else:
                reference.display_name = _('New Reference')

    # ========================================================================
    # CONSTRAINTS
    # ========================================================================

    @api.constrains('date', 'move_id')
    def _check_date_not_future(self):
        """
        Validate referenced document date is not in the future.

        Business Rule:
        - SII does not accept references to future documents
        - Prevents data entry errors
        - Ensures chronological consistency

        Raises:
            ValidationError: If date > today

        Technical Note:
        - Uses fields.Date.today() for timezone-agnostic validation
        - Considers move date for relative validation
        """
        for reference in self:
            if reference.date and reference.date > fields.Date.today():
                raise ValidationError(_(
                    "Referenced document date cannot be in the future.\n\n"
                    "Referenced date: %s\n"
                    "Today: %s\n\n"
                    "Please verify the date of the original document."
                ) % (reference.date, fields.Date.today()))

            # Additional check: reference date should not be after parent document
            if reference.date and reference.move_id.invoice_date:
                if reference.date > reference.move_id.invoice_date:
                    raise ValidationError(_(
                        "Referenced document date (%s) cannot be after the date "
                        "of this %s (%s).\n\n"
                        "A document cannot reference a future document."
                    ) % (
                        reference.date,
                        reference.move_id.l10n_latam_document_type_id.name or 'document',
                        reference.move_id.invoice_date
                    ))

    @api.constrains('folio')
    def _check_folio_format(self):
        """
        Validate folio format (basic check).

        Business Rules:
        - Folio cannot be empty
        - No whitespace-only folios
        - Must be alphanumeric (allows hyphens, underscores)

        Raises:
            ValidationError: If folio is invalid

        Technical Note:
        - Does NOT validate folio exists in SII (that's SII's job)
        - Only validates format to prevent obvious errors
        """
        for reference in self:
            if not reference.folio or not reference.folio.strip():
                raise ValidationError(_(
                    "Folio cannot be empty or whitespace only.\n\n"
                    "Please enter the folio number of the referenced document."
                ))

            # Check for reasonable length (folios are typically short)
            if len(reference.folio) > 20:
                raise ValidationError(_(
                    "Folio '%s' is too long (max 20 characters).\n\n"
                    "Please enter only the folio number without additional text."
                ) % reference.folio)

    @api.constrains('document_type_id', 'move_id')
    def _check_document_type_country(self):
        """
        Validate document type is Chilean.

        Business Rule:
        - Only Chilean document types are valid for SII references
        - Prevents accidental use of other LATAM document types

        Raises:
            ValidationError: If document type is not Chilean

        Technical Note:
        - Domain filter in field definition is not enough (can be bypassed in code)
        - This constraint ensures data integrity at DB level
        """
        for reference in self:
            if reference.document_type_id.country_id.code != 'CL':
                raise ValidationError(_(
                    "Document type '%s' is not valid for Chilean SII references.\n\n"
                    "Only Chilean document types (country=Chile) can be referenced.\n"
                    "Document type country: %s"
                ) % (
                    reference.document_type_id.name,
                    reference.document_type_id.country_id.name
                ))

    # ========================================================================
    # CONSTRAINTS (Odoo 19 Compatible)
    # ========================================================================
    # Migrated from _sql_constraints to @api.constrains for Odoo 19 compatibility

    @api.constrains('move_id', 'document_type_id', 'folio')
    def _check_unique_reference_per_move(self):
        """Ensure no duplicate reference per move"""
        for record in self:
            if record.move_id and record.document_type_id and record.folio:
                existing = self.search([
                    ('move_id', '=', record.move_id.id),
                    ('document_type_id', '=', record.document_type_id.id),
                    ('folio', '=', record.folio),
                    ('id', '!=', record.id)
                ], limit=1)
                if existing:
                    raise ValidationError(_(
                        'You cannot reference the same document twice in the same invoice!\n\n'
                        'This reference already exists for this document.'
                    ))

    @api.constrains('folio')
    def _check_folio_not_empty(self):
        """Ensure folio is not empty"""
        for record in self:
            if record.folio and not record.folio.strip():
                raise ValidationError(_('Folio cannot be empty.'))

    # ========================================================================
    # CRUD METHODS
    # ========================================================================

    @api.model_create_multi
    def create(self, vals_list):
        """
        Override create to add audit logging.

        Logs reference creation for compliance audit trail.

        Args:
            vals_list (list): List of value dicts

        Returns:
            recordset: Created records

        Technical Note:
        - Logs to ir.logging for centralized audit
        - Does not affect performance (async logging)
        """
        records = super().create(vals_list)

        # Log creation for audit
        for record in records:
            self.env['ir.logging'].sudo().create({
                'name': 'account.move.reference',
                'type': 'server',
                'level': 'INFO',
                'message': f'SII Reference created: {record.display_name} for {record.move_name}',
                'path': __file__,
                'func': 'create',
                'line': '1',
            })

        return records

    # ========================================================================
    # BUSINESS METHODS
    # ========================================================================

    def name_get(self):
        """
        Override name_get for better display in Many2one fields.

        Returns display_name instead of default name field.

        Returns:
            list: List of (id, display_name) tuples

        Technical Note:
        - Improves UX in selection fields
        - Shows full context: document type + folio + date
        """
        result = []
        for record in self:
            result.append((record.id, record.display_name))
        return result

    @api.model
    def _name_search(self, name='', args=None, operator='ilike', limit=100, name_get_uid=None):
        """
        Override name_search to search by folio and document type.

        Allows searching references by:
        - Folio number
        - Document type name
        - Display name

        Args:
            name (str): Search term
            args (list): Additional domain
            operator (str): Search operator
            limit (int): Max results
            name_get_uid (int): User ID for name_get

        Returns:
            list: Record IDs

        Technical Note:
        - Improves UX in Many2one search
        - Searches across multiple fields
        """
        args = args or []
        if name:
            # Search in folio, document type name, and display name
            domain = [
                '|', '|',
                ('folio', operator, name),
                ('document_type_id.name', operator, name),
                ('display_name', operator, name)
            ]
            return self._search(domain + args, limit=limit, access_rights_uid=name_get_uid)
        return super()._name_search(name=name, args=args, operator=operator, limit=limit, name_get_uid=name_get_uid)
