#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XMLDSig Signature Verification for CI
======================================

P1-2 GAP CLOSURE: Verifica firmas XML digitales en CI usando xmlsec1.

Workflow:
1. Carga fixtures XML firmados (33, 34, 52, 56, 61)
2. Verifica cada firma usando xmlsec1 --verify
3. Falla si alguna verificación es inválida

Requires: xmlsec1, libxml2-utils (apt install xmlsec1 libxml2-utils)

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
"""

import os
import sys
import subprocess
from pathlib import Path


def get_module_root():
    """Get l10n_cl_dte module root directory."""
    # This script: scripts/verify_xmlsec_signatures.py
    # Module root: addons/localization/l10n_cl_dte
    here = Path(__file__).parent.absolute()
    repo_root = here.parent
    module_root = repo_root / "addons" / "localization" / "l10n_cl_dte"
    return module_root


def verify_xml_signature(xml_path: Path) -> tuple[bool, str]:
    """
    Verify XML signature using xmlsec1.

    Args:
        xml_path: Path to signed XML file

    Returns:
        (success, output): Tuple with verification result and xmlsec1 output

    Note: xmlsec1 exits with 0 if signature is valid, non-zero otherwise.
    """
    try:
        # xmlsec1 --verify <signed_xml>
        # For DTEs with embedded certificates, we don't need --trusted-pem
        result = subprocess.run(
            ["xmlsec1", "--verify", str(xml_path)],
            capture_output=True,
            text=True,
            timeout=10
        )

        success = (result.returncode == 0)
        output = result.stdout + result.stderr

        return success, output

    except FileNotFoundError:
        return False, "ERROR: xmlsec1 not found. Install with: sudo apt-get install xmlsec1"
    except subprocess.TimeoutExpired:
        return False, "ERROR: xmlsec1 verification timed out (>10s)"
    except Exception as e:
        return False, f"ERROR: Unexpected error: {e}"


def main():
    """
    Main verification workflow.

    Exit codes:
    - 0: All signatures valid
    - 1: Setup error (files not found, xmlsec1 not installed)
    - 2: One or more signatures invalid
    """
    print("=" * 70)
    print("🔒 XMLDSig Signature Verification (CI)")
    print("=" * 70)
    print()

    module_root = get_module_root()
    fixtures_dir = module_root / "tests" / "fixtures"

    # DTE fixtures to verify (must be signed XML files)
    # P2.3 GAP CLOSURE: Added DTE 52 (Guía de Despacho) - both variants
    fixtures = [
        ("DTE 33", "dte33_factura.xml"),
        ("DTE 34", "dte34_factura_exenta.xml"),
        ("DTE 52 (con transporte)", "dte52_with_transport.xml"),
        ("DTE 52 (sin transporte)", "dte52_without_transport.xml"),
        ("DTE 56", "dte56_nota_debito.xml"),
        ("DTE 61", "dte61_nota_credito.xml"),
    ]

    # Coverage: 5/5 DTE types (6 fixtures total, 2 variants of DTE 52)

    print(f"📂 Fixtures directory: {fixtures_dir}")
    print(f"📋 Verifying {len(fixtures)} XML signatures...")
    print()

    if not fixtures_dir.exists():
        print(f"❌ FAIL: Fixtures directory not found: {fixtures_dir}")
        return 1

    failed_count = 0
    verified_count = 0

    for dte_name, filename in fixtures:
        xml_path = fixtures_dir / filename

        if not xml_path.exists():
            print(f"⚠️  SKIP: {dte_name} - File not found: {filename}")
            continue

        print(f"Verifying {dte_name} ({filename})...")

        success, output = verify_xml_signature(xml_path)

        if success:
            print(f"  ✅ PASS: Signature valid")
            verified_count += 1
        else:
            print(f"  ❌ FAIL: Signature invalid or verification error")
            print(f"  Output: {output[:500]}")  # Truncate long output
            failed_count += 1

        print()

    # Summary
    print("=" * 70)
    print(f"📊 Summary:")
    print(f"  Total fixtures: {len(fixtures)}")
    print(f"  Verified: {verified_count}")
    print(f"  Failed: {failed_count}")
    print("=" * 70)

    if failed_count > 0:
        print()
        print("❌ SIGNATURE VERIFICATION FAILED")
        print()
        print("⚠️  Note: This may happen if:")
        print("   1. Fixtures are not signed (need to generate signed fixtures)")
        print("   2. Signatures are corrupted")
        print("   3. xmlsec1 version incompatibility")
        print()
        print("💡 To fix: Regenerate fixtures with valid signatures using")
        print("   the module's XML signer with test certificates.")
        return 2

    if verified_count == 0:
        print()
        print("⚠️  WARNING: No fixtures verified (all skipped)")
        print("   This may indicate missing fixture files.")
        return 1

    print()
    print("✅ ALL SIGNATURES VALID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
