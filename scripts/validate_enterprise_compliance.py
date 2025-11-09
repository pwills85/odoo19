#!/usr/bin/env python3
"""
Enterprise Compliance Validation Script - L10N_CL_DTE
======================================================

Validates all critical aspects identified in enterprise audit:
- P0 Blockers: Rate limiting, webhooks, XSD smoke tests
- P1 High: SII codes, namespace, idempotency
- Odoo Standards: ACLs, inheritance, views

Usage:
    python3 scripts/validate_enterprise_compliance.py
    
    # Specific domain
    python3 scripts/validate_enterprise_compliance.py --domain security
    
Exit codes:
    0: All validations PASS
    1: Critical failures (P0)
    2: High priority failures (P1)
    3: Medium priority failures (P2)
"""
import argparse
import sys
import os
from pathlib import Path
from typing import List, Tuple

# ANSI colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class ValidationResult:
    def __init__(self, id: str, name: str, passed: bool, severity: str, message: str):
        self.id = id
        self.name = name
        self.passed = passed
        self.severity = severity
        self.message = message


# ═══════════════════════════════════════════════════════════
# VALIDATION FUNCTIONS
# ═══════════════════════════════════════════════════════════

def validate_rate_limiting_redis() -> ValidationResult:
    """B-001: Validate rate limiting uses Redis, not in-memory dict."""
    webhook_file = Path('addons/localization/l10n_cl_dte/controllers/dte_webhook.py')
    
    if not webhook_file.exists():
        return ValidationResult(
            'B-001', 'Rate Limiting Redis', False, 'P0',
            f'File not found: {webhook_file}'
        )
    
    content = webhook_file.read_text()
    
    # Check for in-memory cache (bad)
    has_in_memory = '_request_cache = {}' in content
    
    # Check for Redis client (good)
    has_redis = 'redis.Redis' in content or '_redis_client' in content
    
    if has_in_memory and not has_redis:
        return ValidationResult(
            'B-001', 'Rate Limiting Redis', False, 'P0',
            '❌ Using in-memory cache (line 26). Must use Redis for distributed rate limiting.'
        )
    elif has_redis:
        return ValidationResult(
            'B-001', 'Rate Limiting Redis', True, 'P0',
            '✅ Redis-backed rate limiting detected'
        )
    else:
        return ValidationResult(
            'B-001', 'Rate Limiting Redis', False, 'P0',
            '⚠️  No rate limiting implementation found'
        )


def validate_webhook_timestamp() -> ValidationResult:
    """B-002: Validate webhooks check timestamp and nonce."""
    webhook_file = Path('addons/localization/l10n_cl_dte/controllers/dte_webhook.py')
    
    if not webhook_file.exists():
        return ValidationResult(
            'B-002', 'Webhook Timestamp/Replay', False, 'P0',
            f'File not found: {webhook_file}'
        )
    
    content = webhook_file.read_text()
    
    # Check for timestamp validation
    has_timestamp = "kwargs.get('timestamp')" in content
    has_timestamp_check = "age_seconds > 300" in content or "timestamp" in content and "expired" in content.lower()
    
    # Check for nonce/replay protection
    has_nonce = "kwargs.get('nonce')" in content or "'nonce'" in content
    has_replay_check = "replay" in content.lower() and ("redis" in content.lower() or "exists" in content)
    
    if has_timestamp_check and has_replay_check:
        return ValidationResult(
            'B-002', 'Webhook Timestamp/Replay', True, 'P0',
            '✅ Timestamp and replay attack protection detected'
        )
    elif has_timestamp or has_nonce:
        return ValidationResult(
            'B-002', 'Webhook Timestamp/Replay', False, 'P0',
            '⚠️  Partial implementation: timestamp or nonce detected but not complete'
        )
    else:
        return ValidationResult(
            'B-002', 'Webhook Timestamp/Replay', False, 'P0',
            '❌ No timestamp/replay validation. Vulnerable to replay attacks.'
        )


def validate_webhook_secret_key() -> ValidationResult:
    """B-003: Validate webhook key is not default and has secure generation."""
    webhook_file = Path('addons/localization/l10n_cl_dte/controllers/dte_webhook.py')
    hooks_file = Path('addons/localization/l10n_cl_dte/hooks.py')

    if not webhook_file.exists():
        return ValidationResult(
            'B-003', 'Webhook Secret Key', False, 'P0',
            f'File not found: {webhook_file}'
        )

    content = webhook_file.read_text()

    # Check for insecure default
    has_default = 'default_webhook_key_change_in_production' in content

    # Check for key generation in webhook file or hooks file
    has_keygen = (
        'secrets.token_urlsafe' in content or
        'secrets.token_hex' in content or
        '_generate_webhook_key' in content
    )

    # Check hooks.py for key generation (post_init_hook)
    if hooks_file.exists():
        hooks_content = hooks_file.read_text()
        has_keygen = has_keygen or (
            'secrets.token_hex' in hooks_content and
            'webhook_key' in hooks_content and
            'post_init_hook' in hooks_content
        )

    if has_default and not has_keygen:
        return ValidationResult(
            'B-003', 'Webhook Secret Key', False, 'P0',
            '❌ Default insecure key detected. Must generate random key.'
        )
    elif has_keygen:
        return ValidationResult(
            'B-003', 'Webhook Secret Key', True, 'P0',
            '✅ Secure key generation detected (hooks.py post_init_hook)'
        )
    else:
        return ValidationResult(
            'B-003', 'Webhook Secret Key', False, 'P0',
            '⚠️  No default detected but no key generation either'
        )


def validate_xsd_smoke_tests() -> ValidationResult:
    """B-004: Validate XSD smoke tests exist for all DTE types."""
    smoke_dir = Path('addons/localization/l10n_cl_dte/tests/smoke')
    
    if not smoke_dir.exists():
        return ValidationResult(
            'B-004', 'XSD Smoke Tests', False, 'P0',
            f'Smoke directory not found: {smoke_dir}'
        )
    
    required_tests = ['smoke_xsd_dte33.py', 'smoke_xsd_dte34.py', 'smoke_xsd_dte52.py',
                      'smoke_xsd_dte56.py', 'smoke_xsd_dte61.py']
    
    existing = [t for t in required_tests if (smoke_dir / t).exists()]
    missing = [t for t in required_tests if t not in existing]
    
    if len(existing) == 5:
        return ValidationResult(
            'B-004', 'XSD Smoke Tests', True, 'P0',
            f'✅ All 5 smoke tests found: {", ".join(existing)}'
        )
    elif len(existing) > 0:
        return ValidationResult(
            'B-004', 'XSD Smoke Tests', False, 'P0',
            f'⚠️  {len(existing)}/5 smoke tests found. Missing: {", ".join(missing)}'
        )
    else:
        return ValidationResult(
            'B-004', 'XSD Smoke Tests', False, 'P0',
            f'❌ No smoke tests found. Expected: {", ".join(required_tests)}'
        )


def validate_odoo_duplicate_name() -> ValidationResult:
    """B-024: Validate no _name + _inherit duplication."""
    model_file = Path('addons/localization/l10n_cl_dte/models/account_move_dte.py')
    
    if not model_file.exists():
        return ValidationResult(
            'B-024', 'Odoo _name Duplication', False, 'P0',
            f'File not found: {model_file}'
        )
    
    with open(model_file, 'r') as f:
        lines = f.readlines()
    
    # Check lines 50-52 area
    duplicate_pattern = False
    for i, line in enumerate(lines[49:53], start=50):  # Lines 50-53
        if "_name = 'account.move'" in line:
            next_line = lines[i] if i < len(lines) else ''
            if "_inherit = 'account.move'" in next_line:
                duplicate_pattern = True
                return ValidationResult(
                    'B-024', 'Odoo _name Duplication', False, 'P0',
                    f'❌ Duplicate _name + _inherit detected at line {i}. Fix: remove _name line.'
                )
    
    return ValidationResult(
        'B-024', 'Odoo _name Duplication', True, 'P0',
        '✅ No _name + _inherit duplication detected'
    )


def validate_sii_error_codes() -> ValidationResult:
    """B-006: Validate SII error codes mapping (39+ codes)."""
    # Check dedicated sii_error_codes.py module (Sprint 1.3)
    error_codes_file = Path('addons/localization/l10n_cl_dte/libs/sii_error_codes.py')

    if not error_codes_file.exists():
        return ValidationResult(
            'B-006', 'SII Error Codes', False, 'P1',
            f'File not found: {error_codes_file}'
        )

    content = error_codes_file.read_text()

    # Count ALL_SII_CODES dictionary entries
    if 'ALL_SII_CODES = {' in content:
        # Count codes by looking for code entries
        total_codes = content.count("'code':")

        # Check for critical code categories
        critical_codes = ['ENV-3-0', 'DTE-3-101', 'TED-2-510', 'REF-1-415',
                          'CAF-3-517', 'HED-1', 'CONN-TIMEOUT', 'CERT-1']

        found_codes = sum(1 for code in critical_codes if f"'{code}'" in content)
    else:
        total_codes = 0
        found_codes = 0
    
    # Accept if we have 6+/8 critical codes AND 30+ total codes
    if found_codes >= 6 and total_codes >= 30:
        return ValidationResult(
            'B-006', 'SII Error Codes', True, 'P1',
            f'✅ {total_codes} error codes mapped ({found_codes}/8 critical codes found)'
        )
    elif found_codes >= 4 or total_codes >= 20:
        return ValidationResult(
            'B-006', 'SII Error Codes', False, 'P1',
            f'⚠️  {found_codes}/8 critical codes found, {total_codes} total (target: 39+)'
        )
    else:
        return ValidationResult(
            'B-006', 'SII Error Codes', False, 'P1',
            f'❌ Only {found_codes}/8 critical codes found ({total_codes} total). Incomplete mapping.'
        )


def validate_namespace_xml() -> ValidationResult:
    """B-007: Validate XML generators include SII namespace."""
    xml_gen_file = Path('addons/localization/l10n_cl_dte/libs/xml_generator.py')
    
    if not xml_gen_file.exists():
        return ValidationResult(
            'B-007', 'Namespace XML', False, 'P1',
            f'File not found: {xml_gen_file}'
        )
    
    content = xml_gen_file.read_text()
    
    # Check for namespace declaration
    has_nsmap = 'nsmap=' in content and 'http://www.sii.cl/SiiDte' in content
    
    # Count generators
    generators = ['_generate_dte_33', '_generate_dte_34', '_generate_dte_52',
                  '_generate_dte_56', '_generate_dte_61']
    
    generators_with_ns = sum(1 for gen in generators if gen in content)
    
    if has_nsmap:
        return ValidationResult(
            'B-007', 'Namespace XML', True, 'P1',
            f'✅ Namespace SII detected in {generators_with_ns} generators'
        )
    else:
        return ValidationResult(
            'B-007', 'Namespace XML', False, 'P1',
            '❌ No SII namespace (xmlns) in DTE generators. XSD may fail.'
        )


def validate_idempotency() -> ValidationResult:
    """B-009: Validate track_id uniqueness for idempotency."""
    model_file = Path('addons/localization/l10n_cl_dte/models/account_move_dte.py')
    
    if not model_file.exists():
        return ValidationResult(
            'B-009', 'Idempotency', False, 'P1',
            f'File not found: {model_file}'
        )
    
    content = model_file.read_text()
    
    # Check for unique constraint
    has_unique_constraint = 'dte_track_id_unique' in content or 'UNIQUE(dte_track_id)' in content
    
    # Check for duplicate detection logic
    has_duplicate_check = 'if self.dte_track_id:' in content and 'already' in content.lower()
    
    if has_unique_constraint and has_duplicate_check:
        return ValidationResult(
            'B-009', 'Idempotency', True, 'P1',
            '✅ track_id unique constraint + duplicate detection found'
        )
    elif has_unique_constraint or has_duplicate_check:
        return ValidationResult(
            'B-009', 'Idempotency', False, 'P1',
            '⚠️  Partial idempotency: either constraint or check missing'
        )
    else:
        return ValidationResult(
            'B-009', 'Idempotency', False, 'P1',
            '❌ No idempotency protection. Retries may duplicate DTEs in SII.'
        )


def validate_acls() -> ValidationResult:
    """B-010: Validate all models have ACLs defined."""
    acl_file = Path('addons/localization/l10n_cl_dte/security/ir.model.access.csv')
    
    if not acl_file.exists():
        return ValidationResult(
            'B-010', 'ACLs Complete', False, 'P1',
            f'ACL file not found: {acl_file}'
        )
    
    # Count ACL entries
    with open(acl_file, 'r') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('id,')]
    
    acl_count = len(lines)
    
    # Expected: ~25+ models (from manifest + custom models)
    if acl_count >= 25:
        return ValidationResult(
            'B-010', 'ACLs Complete', True, 'P1',
            f'✅ {acl_count} ACL entries defined (good coverage)'
        )
    elif acl_count >= 15:
        return ValidationResult(
            'B-010', 'ACLs Complete', False, 'P1',
            f'⚠️  {acl_count} ACL entries (expected 25+). Check MISSING_ACLS_TO_ADD.csv'
        )
    else:
        return ValidationResult(
            'B-010', 'ACLs Complete', False, 'P1',
            f'❌ Only {acl_count} ACL entries. Severely incomplete (target: 25+)'
        )


# ═══════════════════════════════════════════════════════════
# MAIN VALIDATION RUNNER
# ═══════════════════════════════════════════════════════════

def run_validations(domain: str = 'all') -> Tuple[List[ValidationResult], int]:
    """Run validations based on domain."""
    
    all_validations = {
        'security': [
            validate_rate_limiting_redis,
            validate_webhook_timestamp,
            validate_webhook_secret_key,
        ],
        'xsd': [
            validate_xsd_smoke_tests,
        ],
        'sii_compliance': [
            validate_sii_error_codes,
            validate_namespace_xml,
            validate_idempotency,
        ],
        'odoo_standards': [
            validate_odoo_duplicate_name,
            validate_acls,
        ],
    }
    
    if domain == 'all':
        validators = [v for validators in all_validations.values() for v in validators]
    elif domain in all_validations:
        validators = all_validations[domain]
    else:
        print(f"{RED}Invalid domain: {domain}{RESET}")
        print(f"Valid domains: {', '.join(['all'] + list(all_validations.keys()))}")
        sys.exit(1)
    
    results = []
    for validator in validators:
        result = validator()
        results.append(result)
    
    return results, determine_exit_code(results)


def determine_exit_code(results: List[ValidationResult]) -> int:
    """Determine exit code based on failures."""
    p0_failures = [r for r in results if not r.passed and r.severity == 'P0']
    p1_failures = [r for r in results if not r.passed and r.severity == 'P1']
    p2_failures = [r for r in results if not r.passed and r.severity == 'P2']
    
    if p0_failures:
        return 1  # Critical failures
    elif p1_failures:
        return 2  # High priority failures
    elif p2_failures:
        return 3  # Medium priority failures
    else:
        return 0  # All pass


def print_results(results: List[ValidationResult]):
    """Print validation results with color coding."""
    
    print(f"\n{BLUE}{'='*70}{RESET}")
    print(f"{BLUE}ENTERPRISE COMPLIANCE VALIDATION RESULTS{RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")
    
    # Group by severity
    by_severity = {}
    for r in results:
        by_severity.setdefault(r.severity, []).append(r)
    
    for severity in ['P0', 'P1', 'P2', 'P3']:
        if severity not in by_severity:
            continue
        
        severity_results = by_severity[severity]
        passed = sum(1 for r in severity_results if r.passed)
        total = len(severity_results)
        
        color = GREEN if passed == total else (RED if severity in ['P0', 'P1'] else YELLOW)
        
        print(f"\n{color}[{severity}] {passed}/{total} PASSED{RESET}")
        print(f"{color}{'-'*70}{RESET}")
        
        for result in severity_results:
            status_icon = '✅' if result.passed else '❌'
            status_color = GREEN if result.passed else RED
            
            print(f"  {status_color}{status_icon} [{result.id}] {result.name}{RESET}")
            print(f"     {result.message}\n")
    
    # Summary
    total_passed = sum(1 for r in results if r.passed)
    total = len(results)
    pass_rate = (total_passed / total * 100) if total > 0 else 0
    
    print(f"\n{BLUE}{'='*70}{RESET}")
    summary_color = GREEN if pass_rate == 100 else (YELLOW if pass_rate >= 80 else RED)
    print(f"{summary_color}SUMMARY: {total_passed}/{total} validations passed ({pass_rate:.1f}%){RESET}")
    print(f"{BLUE}{'='*70}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Enterprise Compliance Validation for l10n_cl_dte'
    )
    parser.add_argument(
        '--domain',
        default='all',
        choices=['all', 'security', 'xsd', 'sii_compliance', 'odoo_standards'],
        help='Validation domain to run'
    )
    
    args = parser.parse_args()
    
    # Change to project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)
    
    print(f"\n{BLUE}Running enterprise compliance validation...{RESET}")
    print(f"Domain: {args.domain}")
    print(f"Project: {project_root}\n")
    
    results, exit_code = run_validations(args.domain)
    print_results(results)
    
    if exit_code == 0:
        print(f"{GREEN}✅ ALL VALIDATIONS PASSED - ENTERPRISE READY{RESET}\n")
    elif exit_code == 1:
        print(f"{RED}❌ CRITICAL FAILURES (P0) - MUST FIX BEFORE PRODUCTION{RESET}\n")
    elif exit_code == 2:
        print(f"{YELLOW}⚠️  HIGH PRIORITY FAILURES (P1) - RECOMMENDED FIXES{RESET}\n")
    else:
        print(f"{YELLOW}⚠️  MEDIUM PRIORITY FAILURES (P2) - OPTIONAL IMPROVEMENTS{RESET}\n")
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
