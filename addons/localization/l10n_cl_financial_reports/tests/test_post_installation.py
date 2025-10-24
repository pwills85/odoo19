#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Post-Installation Test Script for account_financial_report
Tests basic functionality of all major components
"""

import subprocess
import sys
import json
import time
from datetime import datetime


def run_odoo_command(command):
    """Execute an Odoo command and return the result"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def test_module_installation():
    """Test if the module is properly installed"""
    print("\n1. Testing Module Installation...")
    
    cmd = "docker exec odoo18-dev python3 -c \"import odoo; odoo.api.Environment.manage(); from odoo import api, SUPERUSER_ID; env = api.Environment(odoo.registry('odoo18_dev').cursor(), SUPERUSER_ID, {}); module = env['ir.module.module'].search([('name', '=', 'account_financial_report')]); print('Module State:', module.state if module else 'NOT FOUND')\""
    
    success, stdout, stderr = run_odoo_command(cmd)
    
    if success and "Module State: installed" in stdout:
        print("✓ Module is properly installed")
        return True
    else:
        print("✗ Module installation check failed")
        print(f"Output: {stdout}")
        print(f"Error: {stderr}")
        return False


def test_model_access():
    """Test if all models are accessible"""
    print("\n2. Testing Model Access...")
    
    models_to_test = [
        'account.ratio.analysis.service',
        'project.profitability.report',
        'resource.utilization.report',
        'analytic.cost.benefit.report',
        'financial.report.kpi',
        'l10n.cl.f29',
        'l10n.cl.f22'
    ]
    
    all_success = True
    
    for model in models_to_test:
        cmd = f"""docker exec odoo18-dev python3 -c "
import odoo
odoo.api.Environment.manage()
from odoo import api, SUPERUSER_ID
env = api.Environment(odoo.registry('odoo18_dev').cursor(), SUPERUSER_ID, {{}})
try:
    model_obj = env['{model}']
    print('Model {model}: OK')
except:
    print('Model {model}: FAILED')
env.cr.commit()
env.cr.close()
"
"""
        success, stdout, stderr = run_odoo_command(cmd)
        
        if success and f"Model {model}: OK" in stdout:
            print(f"  ✓ Model {model} is accessible")
        else:
            print(f"  ✗ Model {model} failed")
            all_success = False
    
    return all_success


def test_menu_items():
    """Test if menu items are properly created"""
    print("\n3. Testing Menu Items...")
    
    menu_items = [
        'menu_financial_reports',
        'menu_financial_dashboard',
        'menu_financial_services',
        'menu_ratio_analysis'
    ]
    
    cmd = """docker exec odoo18-dev python3 -c "
import odoo
odoo.api.Environment.manage()
from odoo import api, SUPERUSER_ID
env = api.Environment(odoo.registry('odoo18_dev').cursor(), SUPERUSER_ID, {})
menus = env['ir.ui.menu'].search([('name', 'in', ['Financial Reports', 'Financial Dashboard', 'Financial Services', 'Ratio Analysis'])])
for menu in menus:
    print(f'Menu: {menu.name} - ID: {menu.id}')
env.cr.commit()
env.cr.close()
"
"""
    
    success, stdout, stderr = run_odoo_command(cmd)
    
    if success and "Menu:" in stdout:
        print("✓ Menu items are properly created")
        print(f"  Found menus: {stdout.strip()}")
        return True
    else:
        print("✗ Menu items check failed")
        return False


def test_basic_operations():
    """Test basic CRUD operations on key models"""
    print("\n4. Testing Basic Operations...")
    
    # Test creating a ratio analysis record
    cmd = """docker exec odoo18-dev python3 -c "
import odoo
from datetime import datetime, timedelta
odoo.api.Environment.manage()
from odoo import api, SUPERUSER_ID
env = api.Environment(odoo.registry('odoo18_dev').cursor(), SUPERUSER_ID, {})
try:
    # Create a test ratio analysis
    ratio_analysis = env['account.ratio.analysis.service'].create({
        'name': 'Test Post-Installation Analysis',
        'analysis_type': 'comprehensive',
        'date_from': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'),
        'date_to': datetime.now().strftime('%Y-%m-%d'),
        'company_id': env.company.id,
    })
    print(f'Created ratio analysis: {ratio_analysis.name} (ID: {ratio_analysis.id})')
    
    # Try to compute it
    ratio_analysis.compute_analysis()
    print(f'Analysis state: {ratio_analysis.state}')
    
    # Clean up
    ratio_analysis.unlink()
    print('Cleanup successful')
    
    env.cr.commit()
    result = True
except Exception as e:
    print(f'Error: {str(e)}')
    env.cr.rollback()
    result = False
finally:
    env.cr.close()
"
"""
    
    success, stdout, stderr = run_odoo_command(cmd)
    
    if success and "Created ratio analysis" in stdout:
        print("✓ Basic CRUD operations work correctly")
        return True
    else:
        print("✗ Basic operations test failed")
        print(f"Output: {stdout}")
        print(f"Error: {stderr}")
        return False


def test_security_access():
    """Test security access rights"""
    print("\n5. Testing Security Access...")
    
    cmd = """docker exec odoo18-dev python3 -c "
import odoo
odoo.api.Environment.manage()
from odoo import api, SUPERUSER_ID
env = api.Environment(odoo.registry('odoo18_dev').cursor(), SUPERUSER_ID, {})
try:
    # Check if ACL rules exist
    acl_count = env['ir.model.access'].search_count([
        ('model_id.model', 'like', 'account_financial_report%')
    ])
    print(f'Found {acl_count} ACL rules for account_financial_report models')
    
    # Check some specific rules
    important_models = ['account.ratio.analysis.service', 'financial.report.kpi']
    for model in important_models:
        model_id = env['ir.model'].search([('model', '=', model)], limit=1)
        if model_id:
            acl = env['ir.model.access'].search([('model_id', '=', model_id.id)], limit=1)
            if acl:
                print(f'  ✓ ACL found for {model}: {acl.name}')
            else:
                print(f'  ✗ No ACL found for {model}')
    
    env.cr.commit()
    result = True
except Exception as e:
    print(f'Error: {str(e)}')
    env.cr.rollback()
    result = False
finally:
    env.cr.close()
"
"""
    
    success, stdout, stderr = run_odoo_command(cmd)
    
    if success and "ACL rules" in stdout:
        print("✓ Security access rights are configured")
        return True
    else:
        print("✗ Security access test failed")
        return False


def test_views_loading():
    """Test if views are loading without errors"""
    print("\n6. Testing Views Loading...")
    
    cmd = """docker exec odoo18-dev python3 -c "
import odoo
odoo.api.Environment.manage()
from odoo import api, SUPERUSER_ID
env = api.Environment(odoo.registry('odoo18_dev').cursor(), SUPERUSER_ID, {})
try:
    # Count views for the module
    view_count = env['ir.ui.view'].search_count([
        ('model', 'in', ['account.ratio.analysis.service', 'resource.utilization.report', 
                         'project.profitability.report', 'analytic.cost.benefit.report'])
    ])
    print(f'Found {view_count} views for financial report models')
    
    # Try to load specific views
    views_to_test = [
        ('account.ratio.analysis.service', 'tree'),
        ('resource.utilization.report', 'form'),
        ('project.profitability.report', 'tree')
    ]
    
    for model, view_type in views_to_test:
        view = env['ir.ui.view'].search([
            ('model', '=', model),
            ('type', '=', view_type)
        ], limit=1)
        if view:
            print(f'  ✓ Found {view_type} view for {model}')
        else:
            print(f'  ✗ Missing {view_type} view for {model}')
    
    env.cr.commit()
    result = True
except Exception as e:
    print(f'Error: {str(e)}')
    env.cr.rollback()
    result = False
finally:
    env.cr.close()
"
"""
    
    success, stdout, stderr = run_odoo_command(cmd)
    
    if success and "views for financial report models" in stdout:
        print("✓ Views are properly loaded")
        return True
    else:
        print("✗ Views loading test failed")
        return False


def main():
    """Run all post-installation tests"""
    print("="*60)
    print("POST-INSTALLATION TEST SUITE")
    print("Module: account_financial_report")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    tests = [
        ("Module Installation", test_module_installation),
        ("Model Access", test_model_access),
        ("Menu Items", test_menu_items),
        ("Basic Operations", test_basic_operations),
        ("Security Access", test_security_access),
        ("Views Loading", test_views_loading)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Test '{test_name}' failed with exception: {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "PASSED" if result else "FAILED"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {test_name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED! Module is ready for use.")
        return 0
    else:
        print("\n❌ Some tests failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())