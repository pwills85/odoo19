# -*- coding: utf-8 -*-
"""
Smoke XSD validation for DTE 56 (Nota de Débito)

Run standalone with system Python (no Odoo env needed):

    python addons/localization/l10n_cl_dte/tests/smoke/smoke_xsd_dte56.py

Requires: lxml installed (pip install lxml)
"""
from __future__ import annotations

import os
import sys
from lxml import etree


def module_root() -> str:
    # This file: addons/localization/l10n_cl_dte/tests/smoke/smoke_xsd_dte56.py
    # Module root: addons/localization/l10n_cl_dte
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, '..', '..'))


def get_paths():
    root = module_root()
    xsd_path = os.path.join(root, 'static', 'xsd', 'DTE_v10.xsd')
    fixture_path = os.path.join(root, 'tests', 'fixtures', 'dte56_nota_debito.xml')
    return xsd_path, fixture_path


def validate_xml(xsd_schema: etree.XMLSchema, xml_path: str) -> tuple[bool, str | None]:
    with open(xml_path, 'rb') as f:
        xml_doc = etree.parse(f)
    is_valid = xsd_schema.validate(xml_doc)
    if not is_valid:
        error_log = xsd_schema.error_log
        return False, '\n'.join([str(e) for e in error_log])
    return True, None


def main() -> int:
    xsd_path, fixture_path = get_paths()

    if not os.path.exists(xsd_path):
        print(f"[XSD SMOKE] ❌ XSD not found: {xsd_path}")
        return 1

    if not os.path.exists(fixture_path):
        print(f"[XSD SMOKE] ❌ Fixture not found: {fixture_path}")
        return 1

    # Load XSD
    try:
        with open(xsd_path, 'rb') as xsd_file:
            xsd_doc = etree.parse(xsd_file)
            xsd_schema = etree.XMLSchema(xsd_doc)
    except Exception as e:
        print(f"[XSD SMOKE] ❌ Failed to load XSD: {e}")
        return 1

    # Validate fixture
    ok, err = validate_xml(xsd_schema, fixture_path)
    print(f"[XSD SMOKE] DTE 56 (Nota de Débito): {'✅ PASS' if ok else '❌ FAIL'}")
    if not ok:
        print(err)

    return 0 if ok else 2


if __name__ == '__main__':
    sys.exit(main())
