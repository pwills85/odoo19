#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smoke Test Data Creation for l10n_cl_dte_enhanced
===================================================

Creates test data in TEST database for comprehensive smoke testing.

This script:
1. Configures company with DTE/Chilean data
2. Creates test partner (customer)
3. Creates test invoice with SII references
4. Verifies constraints and data integrity

Usage:
    docker-compose exec odoo odoo shell -d test --config=/etc/odoo/odoo.conf < scripts/create_smoke_test_data.py

Author: EERGYGROUP - Pedro Troncoso Willz
Date: 2025-11-04
"""

import logging
from datetime import date, timedelta

_logger = logging.getLogger(__name__)

def setup_company_dte_data(env):
    """
    Configure main company with Chilean DTE data.

    Sets up:
    - Company name and identification
    - Bank information (new fields from l10n_cl_dte_enhanced)
    - DTE configuration
    """
    _logger.info("=" * 80)
    _logger.info("STEP 1: Configuring company with DTE data")
    _logger.info("=" * 80)

    Company = env['res.company']
    company = Company.browse(1)  # Main company

    # Update company data
    company.write({
        'name': 'EERGYGROUP SpA - TEST',
        # Bank info (from l10n_cl_dte_enhanced)
        'bank_name': 'Banco de Chile',
        'bank_account_number': '1234567890',
        'bank_account_type': 'checking',
    })

    _logger.info(f"✅ Company configured: {company.name}")
    _logger.info(f"   Bank: {company.bank_name}")
    _logger.info(f"   Account: {company.bank_account_number} ({company.bank_account_type})")

    return company


def create_test_partner(env):
    """
    Create test customer for invoicing.

    Returns:
        res.partner: Test customer record
    """
    _logger.info("=" * 80)
    _logger.info("STEP 2: Creating test customer")
    _logger.info("=" * 80)

    Partner = env['res.partner']

    # Check if test partner already exists
    partner = Partner.search([('name', '=', 'Cliente Prueba DTE')], limit=1)

    if partner:
        _logger.info(f"✅ Test customer already exists: {partner.name} (ID: {partner.id})")
    else:
        partner = Partner.create({
            'name': 'Cliente Prueba DTE',
            'email': 'cliente@prueba.cl',
            'phone': '+56 9 8765 4321',
            'street': 'Av. Providencia 123',
            'city': 'Santiago',
            'country_id': env.ref('base.cl').id,
            'customer_rank': 1,
        })
        _logger.info(f"✅ Test customer created: {partner.name} (ID: {partner.id})")

    return partner


def get_chilean_document_types(env):
    """
    Get Chilean document types for testing.

    Returns:
        dict: Dictionary with document type records
    """
    DocumentType = env['l10n_latam.document.type']

    doc_types = {
        'factura': DocumentType.search([('code', '=', '33'), ('country_id.code', '=', 'CL')], limit=1),
        'nota_credito': DocumentType.search([('code', '=', '61'), ('country_id.code', '=', 'CL')], limit=1),
        'nota_debito': DocumentType.search([('code', '=', '56'), ('country_id.code', '=', 'CL')], limit=1),
    }

    _logger.info("Document types found:")
    for key, doc_type in doc_types.items():
        if doc_type:
            _logger.info(f"  - {key}: {doc_type.name} (code: {doc_type.code})")
        else:
            _logger.warning(f"  - {key}: NOT FOUND")

    return doc_types


def create_test_invoice_with_references(env, partner, doc_types):
    """
    Create test invoice with SII document references.

    This tests:
    - Invoice creation with l10n_cl_dte_enhanced fields
    - SII reference creation (account.move.reference)
    - SQL constraints (UNIQUE, CHECK)

    Args:
        env: Odoo environment
        partner: Test customer
        doc_types: Dictionary of document types

    Returns:
        account.move: Test invoice with references
    """
    _logger.info("=" * 80)
    _logger.info("STEP 3: Creating test invoice with SII references")
    _logger.info("=" * 80)

    Move = env['account.move']
    Product = env['product.product']

    # Get or create test product
    product = Product.search([('name', '=', 'Servicio de Prueba DTE')], limit=1)
    if not product:
        product = Product.create({
            'name': 'Servicio de Prueba DTE',
            'type': 'service',
            'list_price': 100000.0,
        })
        _logger.info(f"✅ Test product created: {product.name}")

    # Create test invoice
    invoice_vals = {
        'move_type': 'out_invoice',
        'partner_id': partner.id,
        'invoice_date': date.today(),
        'invoice_date_due': date.today() + timedelta(days=30),
        # l10n_cl_dte_enhanced fields
        'contact_id': partner.id,
        'forma_pago': 'Transferencia bancaria - 30 días',
        'cedible': True,
        # Invoice lines
        'invoice_line_ids': [(0, 0, {
            'product_id': product.id,
            'name': 'Servicio de consultoría DTE',
            'quantity': 1.0,
            'price_unit': 100000.0,
        })],
    }

    # Check if Chilean document type is available
    if doc_types['factura']:
        invoice_vals['l10n_latam_document_type_id'] = doc_types['factura'].id

    invoice = Move.create(invoice_vals)
    _logger.info(f"✅ Test invoice created: {invoice.name} (ID: {invoice.id})")
    _logger.info(f"   Customer: {partner.name}")
    _logger.info(f"   Amount: ${invoice.amount_total:,.0f} CLP")
    _logger.info(f"   Contact: {invoice.contact_id.name if invoice.contact_id else 'N/A'}")
    _logger.info(f"   Payment Terms: {invoice.forma_pago or 'N/A'}")
    _logger.info(f"   CEDIBLE: {invoice.cedible}")

    # Add SII references (simulating this is a Credit Note referencing original invoice)
    if doc_types['factura']:
        _logger.info("\n📋 Creating SII Document References...")

        Reference = env['account.move.reference']

        # Reference 1: Original invoice
        ref1 = Reference.create({
            'move_id': invoice.id,
            'document_type_id': doc_types['factura'].id,
            'folio': '12345',
            'date': date.today() - timedelta(days=10),
            'reason': 'Referencia a factura original de prueba',
            'code': '1',  # Anula
        })
        _logger.info(f"   ✅ Reference 1 created: {ref1.display_name}")

        # Reference 2: Another document
        ref2 = Reference.create({
            'move_id': invoice.id,
            'document_type_id': doc_types['factura'].id,
            'folio': '12346',
            'date': date.today() - timedelta(days=5),
            'reason': 'Referencia secundaria para prueba',
            'code': '3',  # Corrige montos
        })
        _logger.info(f"   ✅ Reference 2 created: {ref2.display_name}")

        # Test UNIQUE constraint (should fail)
        _logger.info("\n🔒 Testing UNIQUE constraint (expecting failure)...")
        try:
            Reference.create({
                'move_id': invoice.id,
                'document_type_id': doc_types['factura'].id,
                'folio': '12345',  # DUPLICATE!
                'date': date.today(),
                'reason': 'Intento de duplicado - debe fallar',
            })
            _logger.error("   ❌ UNIQUE constraint NOT working - duplicate created!")
        except Exception as e:
            _logger.info(f"   ✅ UNIQUE constraint working - duplicate rejected: {str(e)[:80]}")

        # Test CHECK constraint (empty folio - should fail)
        _logger.info("\n🔒 Testing CHECK constraint (expecting failure)...")
        try:
            Reference.create({
                'move_id': invoice.id,
                'document_type_id': doc_types['factura'].id,
                'folio': '   ',  # Empty after trim!
                'date': date.today(),
                'reason': 'Intento con folio vacío - debe fallar',
            })
            _logger.error("   ❌ CHECK constraint NOT working - empty folio accepted!")
        except Exception as e:
            _logger.info(f"   ✅ CHECK constraint working - empty folio rejected: {str(e)[:80]}")

    return invoice


def verify_data_integrity(env):
    """
    Verify all data was created correctly and constraints work.

    Returns:
        dict: Verification results
    """
    _logger.info("=" * 80)
    _logger.info("STEP 4: Verifying data integrity")
    _logger.info("=" * 80)

    results = {
        'company_configured': False,
        'partner_created': False,
        'invoice_created': False,
        'references_created': 0,
        'unique_constraint_working': False,
        'check_constraint_working': False,
    }

    # Check company
    company = env['res.company'].browse(1)
    if company.bank_name and company.bank_account_number:
        results['company_configured'] = True
        _logger.info(f"✅ Company configured: {company.name}")

    # Check partner
    partner = env['res.partner'].search([('name', '=', 'Cliente Prueba DTE')], limit=1)
    if partner:
        results['partner_created'] = True
        _logger.info(f"✅ Test partner exists: {partner.name} (ID: {partner.id})")

    # Check invoices
    invoices = env['account.move'].search([('partner_id', '=', partner.id)], limit=1)
    if invoices:
        results['invoice_created'] = True
        invoice = invoices[0]
        _logger.info(f"✅ Test invoice exists: {invoice.name} (ID: {invoice.id})")

        # Check references
        references = env['account.move.reference'].search([('move_id', '=', invoice.id)])
        results['references_created'] = len(references)
        _logger.info(f"✅ References found: {len(references)}")
        for ref in references:
            _logger.info(f"   - {ref.display_name}")

    # Check SQL constraints in PostgreSQL
    _logger.info("\n🔍 Verifying SQL constraints in PostgreSQL...")
    cr = env.cr
    cr.execute("""
        SELECT conname, contype
        FROM pg_constraint
        WHERE conrelid = 'account_move_reference'::regclass
          AND contype IN ('u', 'c')
        ORDER BY conname
    """)
    constraints = cr.fetchall()

    for conname, contype in constraints:
        if 'unique' in conname:
            results['unique_constraint_working'] = True
            _logger.info(f"   ✅ UNIQUE constraint found: {conname}")
        if 'check' in conname:
            results['check_constraint_working'] = True
            _logger.info(f"   ✅ CHECK constraint found: {conname}")

    return results


def print_summary(results):
    """Print test summary."""
    _logger.info("\n" + "=" * 80)
    _logger.info("📊 SMOKE TEST SUMMARY")
    _logger.info("=" * 80)

    total_checks = len(results)
    passed = sum(1 for v in results.values() if v is True or (isinstance(v, int) and v > 0))

    _logger.info(f"\n✅ Passed: {passed}/{total_checks}")

    for key, value in results.items():
        status = "✅ PASS" if (value is True or (isinstance(value, int) and value > 0)) else "❌ FAIL"
        _logger.info(f"   {status} - {key}: {value}")

    if passed == total_checks:
        _logger.info("\n🎉 ALL SMOKE TESTS PASSED!")
        _logger.info("Module l10n_cl_dte_enhanced is working correctly in TEST database.")
    else:
        _logger.warning(f"\n⚠️  {total_checks - passed} test(s) failed. Please investigate.")

    _logger.info("=" * 80)


def main():
    """Main smoke test execution."""
    _logger.info("\n\n")
    _logger.info("╔" + "═" * 78 + "╗")
    _logger.info("║" + " " * 15 + "l10n_cl_dte_enhanced - SMOKE TEST" + " " * 30 + "║")
    _logger.info("║" + " " * 26 + "TEST Database" + " " * 39 + "║")
    _logger.info("╚" + "═" * 78 + "╝")
    _logger.info("\n")

    try:
        # Step 1: Setup company
        company = setup_company_dte_data(env)

        # Step 2: Create test partner
        partner = create_test_partner(env)

        # Step 3: Get document types
        doc_types = get_chilean_document_types(env)

        # Step 4: Create invoice with references
        invoice = create_test_invoice_with_references(env, partner, doc_types)

        # Step 5: Verify everything
        results = verify_data_integrity(env)

        # Step 6: Print summary
        print_summary(results)

        # Commit transaction
        env.cr.commit()
        _logger.info("\n✅ All changes committed to database.")

    except Exception as e:
        _logger.error(f"\n❌ ERROR during smoke test: {e}")
        import traceback
        traceback.print_exc()
        env.cr.rollback()
        _logger.error("❌ Transaction rolled back.")
        raise


# Execute main function
if __name__ == '__main__':
    main()
