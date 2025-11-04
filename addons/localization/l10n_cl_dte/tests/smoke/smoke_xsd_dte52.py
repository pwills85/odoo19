# -*- coding: utf-8 -*-
"""
Smoke XSD validation for DTE 52 (with and without Transporte)

Run standalone with system Python (no Odoo env needed):

    python addons/localization/l10n_cl_dte/tests/smoke/smoke_xsd_dte52.py

Requires: lxml installed (pip install lxml)
"""
from __future__ import annotations

import os
import sys
from lxml import etree


def module_root() -> str:
    # This file: addons/localization/l10n_cl_dte/tests/smoke/smoke_xsd_dte52.py
    # Module root: addons/localization/l10n_cl_dte
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, '..', '..'))


def get_paths():
    root = module_root()
    xsd_path = os.path.join(root, 'static', 'xsd', 'DTE_v10.xsd')
    fixture_dir = os.path.join(root, 'tests', 'fixtures')
    fx_without = os.path.join(fixture_dir, 'dte52_without_transport.xml')
    fx_with = os.path.join(fixture_dir, 'dte52_with_transport.xml')
    return xsd_path, fx_without, fx_with


def validate_xml(xsd_schema: etree.XMLSchema, xml_path: str) -> tuple[bool, str | None]:
    with open(xml_path, 'rb') as f:
        xml_doc = etree.parse(f)
    is_valid = xsd_schema.validate(xml_doc)
    if not is_valid:
        error_log = xsd_schema.error_log
        return False, '\n'.join([str(e) for e in error_log])
    return True, None


def main() -> int:
    xsd_path, fx_without, fx_with = get_paths()

    if not os.path.exists(xsd_path):
        print(f"[XSD SMOKE] ❌ XSD not found: {xsd_path}")
        return 1

    for fx in (fx_without, fx_with):
        if not os.path.exists(fx):
            print(f"[XSD SMOKE] ❌ Fixture not found: {fx}")
            return 1

    # Load XSD
    try:
        with open(xsd_path, 'rb') as xsd_file:
            xsd_doc = etree.parse(xsd_file)
            xsd_schema = etree.XMLSchema(xsd_doc)
    except Exception as e:
        print(f"[XSD SMOKE] ❌ Failed to load XSD: {e}")
        return 1

    # Validate fixtures
    ok1, err1 = validate_xml(xsd_schema, fx_without)
    print(f"[XSD SMOKE] DTE 52 without Transporte: {'✅ PASS' if ok1 else '❌ FAIL'}")
    if not ok1:
        print(err1)

    ok2, err2 = validate_xml(xsd_schema, fx_with)
    print(f"[XSD SMOKE] DTE 52 with Transporte: {'✅ PASS' if ok2 else '❌ FAIL'}")
    if not ok2:
        print(err2)

    return 0 if (ok1 and ok2) else 2


if __name__ == '__main__':
    sys.exit(main())
