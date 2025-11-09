# -*- coding: utf-8 -*-
"""
Post-installation hooks for l10n_cl_dte_enhanced

Handles database migrations and constraint creation for Odoo 19 compatibility.
"""

import logging
from odoo import api, SUPERUSER_ID

_logger = logging.getLogger(__name__)


def post_init_hook(env):
    """
    Post-installation hook to create SQL constraints manually.

    Context:
    --------
    Odoo 19.0 has a known bug where _sql_constraints defined in models
    are NOT created in PostgreSQL. This is a regression from Odoo 18.

    The new models.Constraint() API is also non-functional in 19.0.

    This hook manually creates the constraints to ensure data integrity.

    References:
    -----------
    - https://github.com/odoo/odoo/issues/xxxxx (Odoo 19 constraint bug)
    - Internal testing: account_move_reference constraints not created

    Args:
        env: Odoo environment (cr, uid, context)
    """
    _logger.info("=" * 80)
    _logger.info("Running post_init_hook for l10n_cl_dte_enhanced")
    _logger.info("=" * 80)

    # Create SQL constraints manually for account.move.reference
    _create_account_move_reference_constraints(env)

    _logger.info("=" * 80)
    _logger.info("Post-init hook completed successfully")
    _logger.info("=" * 80)


def _create_account_move_reference_constraints(env):
    """
    Create SQL constraints for account.move.reference model.

    Constraints:
    -----------
    1. UNIQUE(move_id, document_type_id, folio)
       - Prevents duplicate references in same invoice
       - Critical for SII compliance

    2. CHECK(LENGTH(TRIM(folio)) > 0)
       - Prevents empty folio values
       - Ensures data quality
    """
    _logger.info("Creating SQL constraints for account.move.reference...")

    cr = env.cr

    # Check if UNIQUE constraint already exists
    cr.execute("""
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'account_move_reference'::regclass
          AND conname = 'account_move_reference_unique_reference_per_move'
    """)

    if not cr.fetchone():
        _logger.info("Creating UNIQUE constraint: unique_reference_per_move")
        try:
            cr.execute("""
                ALTER TABLE account_move_reference
                ADD CONSTRAINT account_move_reference_unique_reference_per_move
                UNIQUE (move_id, document_type_id, folio)
            """)
            _logger.info("✅ UNIQUE constraint created successfully")
        except Exception as e:
            _logger.warning(f"⚠️ Could not create UNIQUE constraint: {e}")
    else:
        _logger.info("✅ UNIQUE constraint already exists")

    # Check if CHECK constraint already exists
    cr.execute("""
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'account_move_reference'::regclass
          AND conname = 'account_move_reference_check_folio_not_empty'
    """)

    if not cr.fetchone():
        _logger.info("Creating CHECK constraint: check_folio_not_empty")
        try:
            cr.execute("""
                ALTER TABLE account_move_reference
                ADD CONSTRAINT account_move_reference_check_folio_not_empty
                CHECK (LENGTH(TRIM(folio)) > 0)
            """)
            _logger.info("✅ CHECK constraint created successfully")
        except Exception as e:
            _logger.warning(f"⚠️ Could not create CHECK constraint: {e}")
    else:
        _logger.info("✅ CHECK constraint already exists")

    # Verify all constraints
    cr.execute("""
        SELECT conname, contype, pg_get_constraintdef(oid) as definition
        FROM pg_constraint
        WHERE conrelid = 'account_move_reference'::regclass
          AND contype IN ('u', 'c')
        ORDER BY conname
    """)

    constraints = cr.fetchall()
    _logger.info(f"Verified {len(constraints)} constraint(s) in PostgreSQL:")
    for conname, contype, definition in constraints:
        _logger.info(f"  - {conname} ({contype}): {definition}")
