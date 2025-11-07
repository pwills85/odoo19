#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple Post-Installation Test for account_financial_report
"""

import subprocess
import sys


def run_test():
    """Run simple module test"""
    print("Running simple module test...")
    
    # Test 1: Check if module is installed
    cmd1 = """docker exec odoo18-dev odoo shell -d odoo18_dev --no-http << EOF
# Check module state
module = env['ir.module.module'].search([('name', '=', 'account_financial_report')])
if module:
    print(f"Module found: {module.name}")
    print(f"State: {module.state}")
    print(f"Version: {module.latest_version}")
else:
    print("Module NOT FOUND")

# Check models
models = [
    'account.ratio.analysis.service',
    'resource.utilization.report', 
    'project.profitability.report',
    'financial.report.kpi'
]

print("\\nChecking models:")
for model_name in models:
    try:
        model = env[model_name]
        count = model.search_count([])
        print(f"  ✓ {model_name}: OK (records: {count})")
    except Exception as e:
        print(f"  ✗ {model_name}: ERROR - {str(e)}")

# Check menus
print("\\nChecking menus:")
menus = env['ir.ui.menu'].search([
    ('name', 'in', ['Financial Reports', 'Financial Dashboard', 'Ratio Analysis'])
])
for menu in menus:
    print(f"  ✓ Menu: {menu.name} (action: {menu.action.name if menu.action else 'No action'})")

# Test ratio analysis creation
print("\\nTesting ratio analysis creation:")
try:
    from datetime import datetime, timedelta
    ratio = env['account.ratio.analysis.service'].create({
        'name': 'Test Analysis',
        'analysis_type': 'liquidity',
        'company_id': env.company.id,
        'date_from': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'),
        'date_to': datetime.now().strftime('%Y-%m-%d'),
    })
    print(f"  ✓ Created ratio analysis: {ratio.name} (ID: {ratio.id})")
    ratio.unlink()
    print("  ✓ Cleanup successful")
except Exception as e:
    print(f"  ✗ Error: {str(e)}")

env.cr.commit()
exit()
EOF"""
    
    result = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
    
    print("\n" + "="*60)
    print("TEST OUTPUT:")
    print("="*60)
    print(result.stdout)
    
    if result.stderr:
        print("\nERRORS:")
        print(result.stderr)
    
    # Check results
    if "Module found: account_financial_report" in result.stdout and "State: installed" in result.stdout:
        print("\n✅ Module is properly installed!")
        return True
    else:
        print("\n❌ Module installation issues detected")
        return False


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)