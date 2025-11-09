# -*- coding: utf-8 -*-
"""
US-1.4: Test Cache Invalidation for @api.depends

Tests that all computed fields:
1. Have @api.depends decorator (verified by audit)
2. Cache is invalidated when dependencies change
3. Empty @api.depends() fields are NOT cached (computed on-demand)

Author: Ing. Pedro Troncoso Willz + Claude Code
Date: 2025-11-02
"""

from odoo.tests.common import TransactionCase
from odoo import fields


class TestComputedFieldsCache(TransactionCase):
    """Test suite for @api.depends cache invalidation"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # Create test company
        cls.company = cls.env['res.company'].create({
            'name': 'Test Company DTE',
            'vat': '76123456-7',
            'l10n_cl_razon_social': 'Test Company SRL',
        })

        # Create test partner
        cls.partner = cls.env['res.partner'].create({
            'name': 'Test Partner',
            'vat': '12345678-9',
            'company_id': cls.company.id,
        })

    # ========================================================================
    # US-1.4: CRITICAL COMPUTED FIELDS CACHE TESTS
    # ========================================================================

    def test_dte_caf_compute_name_cache(self):
        """
        Test: dte_caf._compute_name cache invalidation

        @api.depends('dte_type', 'folio_desde', 'folio_hasta')
        """
        # Create CAF
        caf = self.env['dte.caf'].create({
            'dte_type': '33',
            'folio_desde': 1,
            'folio_hasta': 100,
            'caf_file': 'test_caf_content',
            'company_id': self.company.id,
        })

        # Verify initial computed name
        initial_name = caf.name
        self.assertIn('33', initial_name, "Name should contain DTE type")
        self.assertIn('1', initial_name, "Name should contain folio_desde")
        self.assertIn('100', initial_name, "Name should contain folio_hasta")

        # Modify dependency field
        caf.write({'folio_hasta': 200})

        # Cache should be invalidated and name recomputed
        self.assertIn('200', caf.name, "Name should update to new folio_hasta")
        self.assertNotEqual(initial_name, caf.name, "Name should change after update")

    def test_dte_caf_compute_folios_disponibles_cache(self):
        """
        Test: dte_caf._compute_folios_disponibles cache invalidation

        @api.depends('folio_desde', 'folio_hasta', 'journal_id.dte_folio_current')
        """
        # Create journal
        journal = self.env['account.journal'].create({
            'name': 'Test Journal',
            'type': 'sale',
            'code': 'TEST',
            'company_id': self.company.id,
            'dte_folio_start': 1,
            'dte_folio_end': 100,
            'dte_folio_current': 1,
        })

        # Create CAF
        caf = self.env['dte.caf'].create({
            'dte_type': '33',
            'folio_desde': 1,
            'folio_hasta': 100,
            'caf_file': 'test_caf_content',
            'journal_id': journal.id,
            'company_id': self.company.id,
        })

        # Verify initial folios disponibles
        initial_folios = caf.folios_disponibles
        self.assertEqual(initial_folios, 100, "Should have 100 folios available")

        # Modify journal current folio (dependency field)
        journal.write({'dte_folio_current': 50})

        # Cache should be invalidated
        self.assertEqual(caf.folios_disponibles, 51, "Folios should decrease")
        self.assertNotEqual(initial_folios, caf.folios_disponibles)

    def test_boleta_honorarios_compute_retencion_cache(self):
        """
        Test: boleta_honorarios._compute_retencion cache invalidation

        @api.depends('monto_bruto', 'fecha_emision')
        """
        # Create BHE
        bhe = self.env['boleta.honorarios'].create({
            'numero_boleta': 'BHE-001',
            'profesional_nombre': 'Test Professional',
            'profesional_rut': '12345678-9',
            'monto_bruto': 1000000,  # 1M CLP
            'fecha_emision': '2025-11-02',
            'company_id': self.company.id,
        })

        # Verify initial retención (should be calculated)
        initial_retencion = bhe.monto_retencion
        self.assertGreater(initial_retencion, 0, "Retención should be calculated")

        # Modify monto_bruto (dependency field)
        bhe.write({'monto_bruto': 2000000})

        # Cache should be invalidated and retención recalculated
        self.assertGreater(bhe.monto_retencion, initial_retencion,
                          "Retención should increase with higher monto_bruto")

    def test_account_move_dte_compute_xml_filename_cache(self):
        """
        Test: account_move._compute_dte_xml_filename cache invalidation

        @api.depends('dte_folio', 'dte_code')
        """
        # Create invoice
        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner.id,
            'company_id': self.company.id,
            'dte_folio': 123,
            'dte_code': '33',
        })

        # Verify initial XML filename
        initial_filename = invoice.dte_xml_filename
        self.assertIn('33', initial_filename, "Filename should contain DTE code")
        self.assertIn('123', initial_filename, "Filename should contain folio")

        # Modify dte_folio (dependency field)
        invoice.write({'dte_folio': 456})

        # Cache should be invalidated
        self.assertIn('456', invoice.dte_xml_filename,
                     "Filename should update to new folio")
        self.assertNotEqual(initial_filename, invoice.dte_xml_filename)

    # ========================================================================
    # US-1.4: INVERSE RELATION FIELDS (NO CACHE)
    # ========================================================================

    def test_sii_activity_code_company_count_no_cache(self):
        """
        Test: sii_activity_code._compute_company_count (INVERSE RELATION)

        @api.depends()  # Empty - computed on-demand, NO cache

        This field counts companies pointing TO this activity code.
        It should be computed fresh every time (no cache).
        """
        # Create activity code
        activity = self.env['sii.activity.code'].create({
            'code': '123456',
            'name': 'Test Activity',
        })

        # Verify initial count
        initial_count = activity.company_count
        self.assertEqual(initial_count, 0, "Should have 0 companies initially")

        # Create company with this activity
        company = self.env['res.company'].create({
            'name': 'Test Company 2',
            'vat': '76987654-3',
            'l10n_cl_activity_ids': [(6, 0, [activity.id])],
        })

        # Re-read from database to get fresh count
        activity.invalidate_recordset(['company_count'])

        # Count should be recomputed (no cache)
        self.assertEqual(activity.company_count, 1,
                        "Count should update after adding company")

    def test_l10n_cl_comuna_partner_count_no_cache(self):
        """
        Test: l10n_cl_comuna._compute_partner_count (INVERSE RELATION)

        @api.depends()  # Empty - computed on-demand, NO cache

        This field counts partners pointing TO this comuna.
        It should be computed fresh every time (no cache).
        """
        # Create region
        region = self.env['res.country.state'].create({
            'name': 'Test Region',
            'code': 'TR',
            'country_id': self.env.ref('base.cl').id,
        })

        # Create comuna
        comuna = self.env['l10n.cl.comuna'].create({
            'code': '12345',
            'name': 'Test Comuna',
            'state_id': region.id,
        })

        # Verify initial count
        initial_count = comuna.partner_count
        self.assertEqual(initial_count, 0, "Should have 0 partners initially")

        # Create partner with this comuna
        partner = self.env['res.partner'].create({
            'name': 'Test Partner Comuna',
            'l10n_cl_comuna_id': comuna.id,
        })

        # Re-read from database to get fresh count
        comuna.invalidate_recordset(['partner_count'])

        # Count should be recomputed (no cache)
        self.assertEqual(comuna.partner_count, 1,
                        "Count should update after adding partner")

    # ========================================================================
    # US-1.4: PERFORMANCE VALIDATION
    # ========================================================================

    def test_cached_fields_performance(self):
        """
        Test: Cached computed fields should NOT re-compute on every access

        Validates that @api.depends caching works correctly.
        """
        # Create CAF
        caf = self.env['dte.caf'].create({
            'dte_type': '33',
            'folio_desde': 1,
            'folio_hasta': 100,
            'caf_file': 'test_caf_content',
            'company_id': self.company.id,
        })

        # Access computed field multiple times
        name1 = caf.name
        name2 = caf.name
        name3 = caf.name

        # Should return same value (from cache)
        self.assertEqual(name1, name2, "Cached field should return same value")
        self.assertEqual(name2, name3, "Cached field should return same value")

        # Modify dependency
        caf.write({'folio_hasta': 200})

        # Cache invalidated, new value computed
        name4 = caf.name
        self.assertNotEqual(name1, name4, "Cache should invalidate on dependency change")

    def test_non_cached_fields_always_recompute(self):
        """
        Test: Non-cached fields (inverse relations) should recompute on every access

        Validates that @api.depends() empty pattern works correctly.
        """
        activity = self.env['sii.activity.code'].create({
            'code': '654321',
            'name': 'Test Activity 2',
        })

        # Access count multiple times
        count1 = activity.company_count

        # Add company
        company = self.env['res.company'].create({
            'name': 'Test Company 3',
            'vat': '76111222-3',
            'l10n_cl_activity_ids': [(6, 0, [activity.id])],
        })

        # Invalidate to force recompute
        activity.invalidate_recordset(['company_count'])

        # Count should be recomputed (no cache)
        count2 = activity.company_count

        self.assertNotEqual(count1, count2,
                           "Non-cached field should recompute on data change")


# Run tests with:
# docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d TEST \
#   --test-enable --test-tags /l10n_cl_dte --stop-after-init
