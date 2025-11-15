#!/usr/bin/env python3
"""
Script para corregir variables duplicadas en servicios
Busca y reemplaza: self.env.self.env.self.env.cr -> self.env.cr

Archivos afectados:
- analytic_report_service.py (3 líneas)
- financial_report_service_ext.py (4 líneas)
- multi_period_comparison_service.py (2 líneas)
- tax_balance_service.py (1 línea)
- bi_dashboard_service.py (7 líneas)
"""
import os
import re
import sys

FILES_TO_FIX = [
    'addons/localization/l10n_cl_financial_reports/models/services/analytic_report_service.py',
    'addons/localization/l10n_cl_financial_reports/models/services/financial_report_service_ext.py',
    'addons/localization/l10n_cl_financial_reports/models/services/multi_period_comparison_service.py',
    'addons/localization/l10n_cl_financial_reports/models/services/tax_balance_service.py',
    'addons/localization/l10n_cl_financial_reports/models/services/bi_dashboard_service.py',
]

def fix_file(filepath):
    """Fix duplicated self.env references in a file"""
    if not os.path.exists(filepath):
        print(f"⚠️  File not found: {filepath}")
        return False
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    fixes_applied = 0
    
    # Pattern 1: self.env.self.env.self.env.cr (triple duplication)
    pattern1 = r'self\.env\.self\.env\.self\.env\.cr'
    if re.search(pattern1, content):
        content = re.sub(pattern1, 'self.env.cr', content)
        fixes_applied += len(re.findall(pattern1, original_content))
        print(f"   - Fixed {len(re.findall(pattern1, original_content))} triple duplications")
    
    # Pattern 2: self.env.self.env.cr (double duplication)
    pattern2 = r'self\.env\.self\.env\.cr'
    if re.search(pattern2, content):
        content = re.sub(pattern2, 'self.env.cr', content)
        fixes_applied += len(re.findall(pattern2, original_content))
        print(f"   - Fixed {len(re.findall(pattern2, original_content))} double duplications")
    
    if content != original_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ Fixed: {filepath} ({fixes_applied} occurrences)")
        return True
    else:
        print(f"ℹ️  No duplications found: {filepath}")
        return False

def main():
    print("=" * 80)
    print("🔧 FIXING DUPLICATED VARIABLE REFERENCES")
    print("=" * 80)
    print()
    
    total_files_fixed = 0
    
    for file_path in FILES_TO_FIX:
        print(f"\n📄 Processing: {file_path}")
        if fix_file(file_path):
            total_files_fixed += 1
    
    print()
    print("=" * 80)
    print(f"✅ COMPLETED: {total_files_fixed} files fixed")
    print("=" * 80)

if __name__ == '__main__':
    main()
