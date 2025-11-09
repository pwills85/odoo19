#!/bin/bash
################################################################################
# TEST SUITE: Menu Duplication Fix - l10n_cl_dte (v2 - Simplified)
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL=0; PASSED=0; FAILED=0; WARNINGS=0

print_header() { echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}\n${BLUE}$1${NC}\n${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"; }

test_pass() { TOTAL=$((TOTAL+1)); PASSED=$((PASSED+1)); echo -e "${GREEN}✅ PASS${NC} - Test $TOTAL: $1"; }
test_fail() { TOTAL=$((TOTAL+1)); FAILED=$((FAILED+1)); echo -e "${RED}❌ FAIL${NC} - Test $TOTAL: $1\n   ${RED}└─ $2${NC}"; }
test_warn() { TOTAL=$((TOTAL+1)); PASSED=$((PASSED+1)); WARNINGS=$((WARNINGS+1)); echo -e "${YELLOW}⚠️  WARN${NC} - Test $TOTAL: $1\n   ${YELLOW}└─ $2${NC}"; }

sql() { docker-compose exec -T db psql -U odoo -d odoo -t -A -c "$1" 2>/dev/null; }

print_header "TEST SUITE 1: Module Installation & Version"
[ "$(sql "SELECT state FROM ir_module_module WHERE name='l10n_cl_dte';")" == "installed" ] && test_pass "Module l10n_cl_dte is installed" || test_fail "Module l10n_cl_dte is installed" "Not installed"
[ "$(sql "SELECT latest_version FROM ir_module_module WHERE name='l10n_cl_dte';")" == "19.0.5.0.0" ] && test_pass "Module version is 19.0.5.0.0" || test_warn "Module version is 19.0.5.0.0" "Different version"

print_header "TEST SUITE 2: Duplicate Menus Hidden"
[ "$(sql "SELECT active FROM ir_ui_menu WHERE id=258;")" == "f" ] && test_pass "Sale Invoices (CL) menu is hidden" || test_fail "Sale Invoices (CL) menu is hidden" "Still active"
[ "$(sql "SELECT active FROM ir_ui_menu WHERE id=259;")" == "f" ] && test_pass "Vendor Bills (CL) menu is hidden" || test_fail "Vendor Bills (CL) menu is hidden" "Still active"

print_header "TEST SUITE 3: Standard Menus Active"
[ "$(sql "SELECT active FROM ir_ui_menu WHERE id=140;")" == "t" ] && test_pass "Standard Invoices menu is active" || test_fail "Standard Invoices menu is active" "Not active"
[ "$(sql "SELECT active FROM ir_ui_menu WHERE id=146;")" == "t" ] && test_pass "Standard Bills menu is active" || test_fail "Standard Bills menu is active" "Not active"
[ "$(sql "SELECT active FROM ir_ui_menu WHERE id=141;")" == "t" ] && test_pass "Standard Credit Notes menu is active" || test_fail "Standard Credit Notes menu is active" "Not active"
[ "$(sql "SELECT active FROM ir_ui_menu WHERE id=147;")" == "t" ] && test_pass "Standard Refunds menu is active" || test_fail "Standard Refunds menu is active" "Not active"

print_header "TEST SUITE 4: View Extensions Created"
[ "$(sql "SELECT COUNT(*) FROM ir_ui_view WHERE name='account.move.out.invoice.tree.inherit.cl.dte.fix';")" -eq "1" ] && test_pass "Customer Invoices view extension exists" || test_fail "Customer Invoices view extension exists" "Not found"
[ "$(sql "SELECT COUNT(*) FROM ir_ui_view WHERE name='account.move.in.invoice.tree.inherit.cl.dte.fix';")" -eq "1" ] && test_pass "Vendor Bills view extension exists" || test_fail "Vendor Bills view extension exists" "Not found"
[ "$(sql "SELECT COUNT(*) FROM ir_ui_view WHERE name='account.move.out.credit.tree.inherit.cl.dte.fix';")" -eq "1" ] && test_pass "Customer Credit Notes view extension exists" || test_fail "Customer Credit Notes view extension exists" "Not found"
[ "$(sql "SELECT COUNT(*) FROM ir_ui_view WHERE name='account.move.in.credit.tree.inherit.cl.dte.fix';")" -eq "1" ] && test_pass "Vendor Refunds view extension exists" || test_fail "Vendor Refunds view extension exists" "Not found"
[ "$(sql "SELECT COUNT(*) FROM ir_ui_view WHERE name LIKE '%.cl.dte.fix' AND active=true;")" -eq "4" ] && test_pass "All 4 view extensions are active" || test_fail "All 4 view extensions are active" "Some inactive"

print_header "TEST SUITE 5: View Inheritance Integrity"
[ "$(sql "SELECT inherit_id FROM ir_ui_view WHERE name='account.move.out.invoice.tree.inherit.cl.dte.fix';")" == "711" ] && test_pass "Customer Invoices inherits correctly (711)" || test_warn "Customer Invoices inherits correctly" "Different parent ID"
[ "$(sql "SELECT inherit_id FROM ir_ui_view WHERE name='account.move.in.invoice.tree.inherit.cl.dte.fix';")" == "713" ] && test_pass "Vendor Bills inherits correctly (713)" || test_warn "Vendor Bills inherits correctly" "Different parent ID"
[ "$(sql "SELECT inherit_id FROM ir_ui_view WHERE name='account.move.out.credit.tree.inherit.cl.dte.fix';")" == "712" ] && test_pass "Customer Credit Notes inherits correctly (712)" || test_warn "Customer Credit Notes inherits correctly" "Different parent ID"
[ "$(sql "SELECT inherit_id FROM ir_ui_view WHERE name='account.move.in.credit.tree.inherit.cl.dte.fix';")" == "715" ] && test_pass "Vendor Refunds inherits correctly (715)" || test_warn "Vendor Refunds inherits correctly" "Different parent ID"

print_header "TEST SUITE 6: Chilean Fields Available"
[ "$(sql "SELECT COUNT(*) FROM ir_model_fields WHERE model='account.move' AND name='l10n_latam_document_type_id';")" -ge "1" ] && test_pass "Field l10n_latam_document_type_id exists" || test_fail "Field l10n_latam_document_type_id exists" "Not found"
[ "$(sql "SELECT COUNT(*) FROM ir_model_fields WHERE model='account.move' AND name='l10n_latam_document_number';")" -ge "1" ] && test_pass "Field l10n_latam_document_number exists" || test_fail "Field l10n_latam_document_number exists" "Not found"
[ "$(sql "SELECT COUNT(*) FROM ir_model_fields WHERE model='account.move' AND name='dte_status';")" -ge "1" ] && test_pass "Field dte_status exists" || test_fail "Field dte_status exists" "Not found"

print_header "TEST SUITE 7: XML File Integrity"
[ -f "addons/localization/l10n_cl_dte/views/account_move_menu_fix.xml" ] && test_pass "account_move_menu_fix.xml file exists" || test_fail "account_move_menu_fix.xml file exists" "File not found"
grep -q "account_move_menu_fix.xml" addons/localization/l10n_cl_dte/__manifest__.py && test_pass "__manifest__.py includes account_move_menu_fix.xml" || test_fail "__manifest__.py includes menu fix" "Not referenced"
grep -q 'record id="l10n_cl.menu_sale_invoices_credit_notes"' addons/localization/l10n_cl_dte/views/account_move_menu_fix.xml && test_pass "XML contains menu_sale_invoices_credit_notes record" || test_fail "XML contains sale invoices record" "Not found"
grep -q 'record id="l10n_cl.menu_vendor_bills_and_refunds"' addons/localization/l10n_cl_dte/views/account_move_menu_fix.xml && test_pass "XML contains menu_vendor_bills_and_refunds record" || test_fail "XML contains vendor bills record" "Not found"

print_header "TEST SUITE 8: View Architecture Contains Chilean Fields"
view_arch=$(sql "SELECT arch_db FROM ir_ui_view WHERE name='account.move.out.invoice.tree.inherit.cl.dte.fix';")
[[ "$view_arch" == *"l10n_latam_document_type_id"* ]] && test_pass "Customer Invoices view includes Tipo DTE field" || test_fail "View includes Tipo DTE" "Field not in arch"
[[ "$view_arch" == *"l10n_latam_document_number"* ]] && test_pass "Customer Invoices view includes Folio field" || test_fail "View includes Folio" "Field not in arch"
[[ "$view_arch" == *"partner_id_vat"* ]] && test_pass "Customer Invoices view includes RUT field" || test_fail "View includes RUT" "Field not in arch"
[[ "$view_arch" == *"dte_status"* ]] && test_pass "Customer Invoices view includes Estado SII field" || test_fail "View includes Estado SII" "Field not in arch"

print_header "TEST SUITE 9: No Errors in Odoo Logs"
crit=$(docker-compose logs --tail=100 odoo 2>&1 | grep -c "CRITICAL" || true)
[ "$crit" -eq "0" ] && test_pass "No CRITICAL errors in recent logs" || test_warn "No CRITICAL errors in logs" "Found $crit CRITICAL entries"

print_header "TEST RESULTS SUMMARY"
echo -e "Total Tests:   ${BLUE}$TOTAL${NC}"
echo -e "Passed:        ${GREEN}$PASSED${NC}"
echo -e "Failed:        ${RED}$FAILED${NC}"
echo -e "Warnings:      ${YELLOW}$WARNINGS${NC}"
SUCCESS_RATE=$((PASSED * 100 / TOTAL))
echo -e "\nSuccess Rate:  ${BLUE}${SUCCESS_RATE}%${NC}\n"

if [ $FAILED -eq 0 ]; then
    if [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}✅ ALL TESTS PASSED - MENU FIX IS WORKING CORRECTLY${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
        exit 0
    else
        echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}⚠️  TESTS PASSED WITH WARNINGS - REVIEW WARNINGS ABOVE${NC}"
        echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
        exit 0
    fi
else
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}❌ TESTS FAILED - FIX REQUIRED${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    exit 1
fi
