#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lee reports/enterprise_catalog.json y produce resúmenes por dominio
según heurísticas de nombre/ruta/categoría.
Emite:
  - reports/summary_by_domain.json
  - reports/top_dependencies.csv (frecuencia de 'depends')
"""
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

DOMAINS = [
    ('ui_framework', re.compile(r'^(web_|website_|mail_enterprise|web_studio|web_gantt|web_grid|web_mobile|web_dashboard)')),
    ('accounting', re.compile(r'^(account_|l10n_.*_reports|.*taxcloud|.*yodlee|.*plaid|.*sepa)')),
    ('inventory_mrp', re.compile(r'^(stock_|mrp_|delivery_|quality_)')),
    ('sales_pos', re.compile(r'^(sale_|pos_)')),
    ('projects_helpdesk', re.compile(r'^(project_|helpdesk|timesheet_)')),
    ('documents_collab', re.compile(r'^(documents|sign|voip)')),
    ('iot', re.compile(r'^(iot|pos_iot|mrp_zebra|quality_iot)')),
    ('localizations', re.compile(r'^(l10n_.*_reports|.*intrastat)')),
    ('marketing', re.compile(r'^(marketing_automation|mass_mailing_themes|website_.*score|website_twitter_wall)')),
]


def classify(module_name: str, category: str, path: str):
    for dom, pattern in DOMAINS:
        if pattern.match(module_name):
            return dom
    # fallback por categoría
    if category:
        cat = category.lower()
        if 'account' in cat:
            return 'accounting'
        if 'stock' in cat or 'mrp' in cat:
            return 'inventory_mrp'
        if 'sale' in cat or 'point of sale' in cat:
            return 'sales_pos'
        if 'project' in cat or 'helpdesk' in cat:
            return 'projects_helpdesk'
        if 'website' in cat or 'web' in cat:
            return 'ui_framework'
    # por ruta
    if 'website_' in module_name or '/website_' in path:
        return 'ui_framework'
    return 'other'


def main():
    root = Path('.').resolve()
    catalog_path = root / 'reports' / 'enterprise_catalog.json'
    out_summary = root / 'reports' / 'summary_by_domain.json'
    out_deps = root / 'reports' / 'top_dependencies.csv'

    data = json.loads(catalog_path.read_text(encoding='utf-8'))

    by_domain = defaultdict(list)
    dep_counter = Counter()

    for row in data:
        mod = row['module']
        category = row.get('category') or ''
        path = row.get('path') or ''
        domain = classify(mod, category, path)
        by_domain[domain].append(mod)

        depends = (row.get('depends') or '').split(',') if row.get('depends') else []
        for d in depends:
            d = d.strip()
            if d:
                dep_counter[d] += 1

    # Escribir resumen por dominio
    summary = {
        'domains': {dom: sorted(mods) for dom, mods in by_domain.items()},
        'counts': {dom: len(mods) for dom, mods in by_domain.items()},
        'total_modules': len(data),
    }
    out_summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')

    # Escribir top dependencias
    with out_deps.open('w', encoding='utf-8') as f:
        f.write('dependency,count\n')
        for dep, cnt in dep_counter.most_common():
            f.write(f'{dep},{cnt}\n')

    print(f"OK: resumen generado.\n- {out_summary}\n- {out_deps}")


if __name__ == '__main__':
    main()
