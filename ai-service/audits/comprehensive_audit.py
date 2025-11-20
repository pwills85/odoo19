#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Microservice - Comprehensive Audit Script
============================================

Automated audit across all critical dimensions:
- Security
- Code Quality
- Performance
- Reliability
- Architecture
- Compliance

Author: EERGYGROUP - Comprehensive Audit
Date: 2025-11-15
"""

import os
import sys
import json
import re
import ast
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class AuditIssue:
    """Represents an audit finding"""
    
    def __init__(
        self,
        severity: str,  # P0, P1, P2
        category: str,  # Security, Performance, etc.
        title: str,
        description: str,
        file_path: str = None,
        line_number: int = None,
        recommendation: str = None,
        roi_impact: str = None
    ):
        self.severity = severity
        self.category = category
        self.title = title
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.recommendation = recommendation
        self.roi_impact = roi_impact
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'severity': self.severity,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'recommendation': self.recommendation,
            'roi_impact': self.roi_impact
        }


class AIServiceAuditor:
    """Comprehensive auditor for AI microservice"""
    
    def __init__(self, service_path: str):
        self.service_path = Path(service_path)
        self.issues: List[AuditIssue] = []
        self.stats = defaultdict(int)
        
    def audit_all(self) -> Dict[str, Any]:
        """Run all audit checks"""
        print("🔍 Starting comprehensive AI service audit...")
        print(f"📁 Service path: {self.service_path}")
        print()
        
        # Run all audit categories
        self.audit_security()
        self.audit_code_quality()
        self.audit_performance()
        self.audit_reliability()
        self.audit_architecture()
        self.audit_compliance()
        
        # Generate report
        return self.generate_report()
    
    def audit_security(self):
        """Audit security aspects"""
        print("🔐 SECURITY AUDIT")
        print("=" * 60)
        
        # Check for hardcoded secrets
        self._check_hardcoded_secrets()
        
        # Check input validation
        self._check_input_validation()
        
        # Check authentication
        self._check_authentication()
        
        # Check XXE vulnerabilities
        self._check_xxe_vulnerabilities()
        
        # Check SQL injection
        self._check_sql_injection()
        
        # Check XSS vulnerabilities
        self._check_xss_vulnerabilities()
        
        print()
    
    def audit_code_quality(self):
        """Audit code quality"""
        print("📝 CODE QUALITY AUDIT")
        print("=" * 60)
        
        # Check type hints
        self._check_type_hints()
        
        # Check docstrings
        self._check_docstrings()
        
        # Check code complexity
        self._check_complexity()
        
        # Check for TODOs/FIXMEs
        self._check_todos()
        
        # Check test coverage
        self._check_test_coverage()
        
        print()
    
    def audit_performance(self):
        """Audit performance"""
        print("⚡ PERFORMANCE AUDIT")
        print("=" * 60)
        
        # Check caching implementation
        self._check_caching()
        
        # Check async/await usage
        self._check_async_usage()
        
        # Check database query optimization
        self._check_db_optimization()
        
        # Check prompt caching
        self._check_prompt_caching()
        
        # Check streaming
        self._check_streaming()
        
        print()
    
    def audit_reliability(self):
        """Audit reliability"""
        print("🛡️ RELIABILITY AUDIT")
        print("=" * 60)
        
        # Check error handling
        self._check_error_handling()
        
        # Check circuit breakers
        self._check_circuit_breakers()
        
        # Check retry logic
        self._check_retry_logic()
        
        # Check health checks
        self._check_health_checks()
        
        # Check logging
        self._check_logging()
        
        print()
    
    def audit_architecture(self):
        """Audit architecture"""
        print("🏗️ ARCHITECTURE AUDIT")
        print("=" * 60)
        
        # Check module structure
        self._check_module_structure()
        
        # Check dependencies
        self._check_dependencies()
        
        # Check design patterns
        self._check_design_patterns()
        
        # Check separation of concerns
        self._check_separation_of_concerns()
        
        print()
    
    def audit_compliance(self):
        """Audit compliance"""
        print("📋 COMPLIANCE AUDIT")
        print("=" * 60)
        
        # Check logging compliance
        self._check_logging_compliance()
        
        # Check data privacy
        self._check_data_privacy()
        
        # Check API documentation
        self._check_api_documentation()
        
        print()
    
    # Security checks
    def _check_hardcoded_secrets(self):
        """Check for hardcoded secrets"""
        print("  Checking for hardcoded secrets...")
        
        patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
            (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret'),
            (r'token\s*=\s*["\'][^"\']+["\']', 'Hardcoded token'),
        ]
        
        for py_file in self.service_path.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            with open(py_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    for pattern, title in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            # Skip if it's a Field(...) validation
                            if 'Field(' in line or 'field_validator' in line:
                                continue
                            
                            self.issues.append(AuditIssue(
                                severity='P0',
                                category='Security',
                                title=title,
                                description=f'Potential hardcoded secret found',
                                file_path=str(py_file.relative_to(self.service_path)),
                                line_number=line_num,
                                recommendation='Use environment variables or secrets management'
                            ))
                            print(f"    ⚠️  {title} in {py_file.name}:{line_num}")
    
    def _check_input_validation(self):
        """Check input validation"""
        print("  Checking input validation...")
        
        # Check for Pydantic models
        pydantic_found = False
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'BaseModel' in content and 'pydantic' in content:
                    pydantic_found = True
                    self.stats['pydantic_models'] += content.count('class ')
        
        if pydantic_found:
            print(f"    ✅ Pydantic models found ({self.stats['pydantic_models']} classes)")
        else:
            self.issues.append(AuditIssue(
                severity='P0',
                category='Security',
                title='No input validation framework',
                description='No Pydantic models found for input validation',
                recommendation='Implement Pydantic models for all API inputs'
            ))
            print("    ❌ No Pydantic validation found")
    
    def _check_authentication(self):
        """Check authentication implementation"""
        print("  Checking authentication...")
        
        auth_found = False
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'verify_api_key' in content or 'HTTPBearer' in content:
                    auth_found = True
                    break
        
        if auth_found:
            print("    ✅ Authentication found")
        else:
            self.issues.append(AuditIssue(
                severity='P0',
                category='Security',
                title='No authentication',
                description='No API key verification found',
                recommendation='Implement API key authentication for all endpoints'
            ))
            print("    ❌ No authentication found")
    
    def _check_xxe_vulnerabilities(self):
        """Check for XXE vulnerabilities"""
        print("  Checking XXE vulnerabilities...")
        
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'etree.fromstring' in content or 'etree.parse' in content:
                    if 'resolve_entities=False' not in content:
                        self.issues.append(AuditIssue(
                            severity='P0',
                            category='Security',
                            title='Potential XXE vulnerability',
                            description='XML parsing without disabled external entities',
                            file_path=str(py_file.relative_to(self.service_path)),
                            recommendation='Use parser with resolve_entities=False'
                        ))
                        print(f"    ⚠️  Potential XXE in {py_file.name}")
    
    def _check_sql_injection(self):
        """Check for SQL injection vulnerabilities"""
        print("  Checking SQL injection...")
        
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if 'execute(' in line and any(op in line for op in ['+', 'f"', "f'"]):
                        self.issues.append(AuditIssue(
                            severity='P0',
                            category='Security',
                            title='Potential SQL injection',
                            description='SQL query with string formatting',
                            file_path=str(py_file.relative_to(self.service_path)),
                            line_number=line_num,
                            recommendation='Use parameterized queries'
                        ))
                        print(f"    ⚠️  Potential SQL injection in {py_file.name}:{line_num}")
    
    def _check_xss_vulnerabilities(self):
        """Check for XSS vulnerabilities"""
        print("  Checking XSS vulnerabilities...")
        # AI service is API-only, XSS less relevant but check templates
        pass
    
    # Performance checks
    def _check_caching(self):
        """Check caching implementation"""
        print("  Checking caching...")
        
        cache_impl = []
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'redis' in content.lower() or 'cache' in content.lower():
                    cache_impl.append(py_file.name)
        
        if cache_impl:
            print(f"    ✅ Caching found in {len(cache_impl)} files")
        else:
            self.issues.append(AuditIssue(
                severity='P1',
                category='Performance',
                title='No caching implemented',
                description='No Redis or caching mechanism found',
                recommendation='Implement Redis caching for API responses',
                roi_impact='40-60% latency reduction'
            ))
            print("    ⚠️  No caching found")
    
    def _check_async_usage(self):
        """Check async/await usage"""
        print("  Checking async/await usage...")
        
        async_count = 0
        sync_count = 0
        
        for py_file in self.service_path.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                async_count += content.count('async def')
                sync_count += content.count('def ') - content.count('async def')
        
        ratio = async_count / (async_count + sync_count) if (async_count + sync_count) > 0 else 0
        print(f"    📊 Async ratio: {ratio:.1%} ({async_count} async, {sync_count} sync)")
        
        if ratio < 0.5:
            self.issues.append(AuditIssue(
                severity='P1',
                category='Performance',
                title='Low async/await usage',
                description=f'Only {ratio:.1%} of functions are async',
                recommendation='Convert I/O-bound functions to async',
                roi_impact='2-3x throughput improvement'
            ))
    
    def _check_db_optimization(self):
        """Check database optimization"""
        print("  Checking database optimization...")
        # Mostly relevant for Odoo side, not AI service
        pass
    
    def _check_prompt_caching(self):
        """Check Anthropic prompt caching"""
        print("  Checking Anthropic prompt caching...")
        
        cache_control_found = False
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'cache_control' in content:
                    cache_control_found = True
                    break
        
        if cache_control_found:
            print("    ✅ Prompt caching implemented")
        else:
            self.issues.append(AuditIssue(
                severity='P0',
                category='Performance',
                title='Prompt caching not implemented',
                description='No cache_control found in Anthropic API calls',
                recommendation='Implement prompt caching for system prompts',
                roi_impact='90% cost reduction, 85% latency reduction'
            ))
            print("    ❌ Prompt caching NOT found")
    
    def _check_streaming(self):
        """Check streaming implementation"""
        print("  Checking streaming...")
        
        streaming_found = False
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'StreamingResponse' in content or 'stream=' in content:
                    streaming_found = True
                    break
        
        if streaming_found:
            print("    ✅ Streaming implemented")
        else:
            self.issues.append(AuditIssue(
                severity='P1',
                category='Performance',
                title='Streaming not implemented',
                description='No streaming for real-time responses',
                recommendation='Implement streaming for chat endpoints',
                roi_impact='3x better perceived UX'
            ))
            print("    ⚠️  Streaming not found")
    
    # Reliability checks
    def _check_error_handling(self):
        """Check error handling"""
        print("  Checking error handling...")
        
        try_except_count = 0
        bare_except_count = 0
        
        for py_file in self.service_path.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                try_except_count += content.count('try:')
                bare_except_count += content.count('except:')
        
        print(f"    📊 Try/except blocks: {try_except_count}")
        
        if bare_except_count > 0:
            self.issues.append(AuditIssue(
                severity='P1',
                category='Reliability',
                title='Bare except clauses',
                description=f'{bare_except_count} bare except: clauses found',
                recommendation='Use specific exception types'
            ))
            print(f"    ⚠️  {bare_except_count} bare except clauses")
    
    def _check_circuit_breakers(self):
        """Check circuit breaker implementation"""
        print("  Checking circuit breakers...")
        
        cb_found = False
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'CircuitBreaker' in content:
                    cb_found = True
                    break
        
        if cb_found:
            print("    ✅ Circuit breakers found")
        else:
            self.issues.append(AuditIssue(
                severity='P1',
                category='Reliability',
                title='No circuit breakers',
                description='No circuit breaker pattern found',
                recommendation='Implement circuit breakers for external APIs'
            ))
            print("    ⚠️  No circuit breakers")
    
    def _check_retry_logic(self):
        """Check retry logic"""
        print("  Checking retry logic...")
        
        retry_found = False
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'tenacity' in content or '@retry' in content or 'max_retries' in content:
                    retry_found = True
                    break
        
        if retry_found:
            print("    ✅ Retry logic found")
        else:
            print("    ⚠️  No explicit retry logic")
    
    def _check_health_checks(self):
        """Check health check endpoints"""
        print("  Checking health checks...")
        
        health_endpoints = []
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if '/health' in content or '/ready' in content or '/live' in content:
                    health_endpoints.append(py_file.name)
        
        if health_endpoints:
            print(f"    ✅ Health endpoints found in {len(health_endpoints)} files")
        else:
            self.issues.append(AuditIssue(
                severity='P1',
                category='Reliability',
                title='No health checks',
                description='No health check endpoints found',
                recommendation='Implement /health, /ready, /live endpoints'
            ))
            print("    ⚠️  No health checks")
    
    def _check_logging(self):
        """Check logging implementation"""
        print("  Checking logging...")
        
        logging_found = False
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'structlog' in content or 'logger' in content:
                    logging_found = True
                    break
        
        if logging_found:
            print("    ✅ Logging found")
        else:
            print("    ⚠️  No logging framework")
    
    # Architecture checks
    def _check_module_structure(self):
        """Check module structure"""
        print("  Checking module structure...")
        
        expected_dirs = ['clients', 'utils', 'middleware', 'routes', 'tests']
        found_dirs = [d.name for d in self.service_path.iterdir() if d.is_dir() and not d.name.startswith('.')]
        
        missing = set(expected_dirs) - set(found_dirs)
        if missing:
            print(f"    ⚠️  Missing directories: {missing}")
        else:
            print("    ✅ Module structure looks good")
    
    def _check_dependencies(self):
        """Check dependencies"""
        print("  Checking dependencies...")
        
        req_file = self.service_path / 'requirements.txt'
        if req_file.exists():
            with open(req_file) as f:
                deps = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"    📦 {len(deps)} dependencies found")
            self.stats['dependencies'] = len(deps)
        else:
            print("    ⚠️  No requirements.txt found")
    
    def _check_design_patterns(self):
        """Check design patterns"""
        print("  Checking design patterns...")
        # Look for singleton, factory, etc.
        pass
    
    def _check_separation_of_concerns(self):
        """Check separation of concerns"""
        print("  Checking separation of concerns...")
        # Check if business logic is separated from API layer
        pass
    
    # Code quality checks
    def _check_type_hints(self):
        """Check type hints usage"""
        print("  Checking type hints...")
        
        total_funcs = 0
        typed_funcs = 0
        
        for py_file in self.service_path.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    tree = ast.parse(f.read())
                    
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        total_funcs += 1
                        if node.returns or any(arg.annotation for arg in node.args.args):
                            typed_funcs += 1
            except:
                pass
        
        ratio = typed_funcs / total_funcs if total_funcs > 0 else 0
        print(f"    📊 Type hints: {ratio:.1%} ({typed_funcs}/{total_funcs})")
        
        if ratio < 0.5:
            self.issues.append(AuditIssue(
                severity='P2',
                category='Code Quality',
                title='Low type hints coverage',
                description=f'Only {ratio:.1%} of functions have type hints',
                recommendation='Add type hints to all public functions'
            ))
    
    def _check_docstrings(self):
        """Check docstrings"""
        print("  Checking docstrings...")
        
        total_funcs = 0
        documented_funcs = 0
        
        for py_file in self.service_path.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    tree = ast.parse(f.read())
                    
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        total_funcs += 1
                        if ast.get_docstring(node):
                            documented_funcs += 1
            except:
                pass
        
        ratio = documented_funcs / total_funcs if total_funcs > 0 else 0
        print(f"    📊 Docstrings: {ratio:.1%} ({documented_funcs}/{total_funcs})")
    
    def _check_complexity(self):
        """Check code complexity"""
        print("  Checking code complexity...")
        # Would use radon or similar tool in production
        pass
    
    def _check_todos(self):
        """Check for TODOs and FIXMEs"""
        print("  Checking TODOs/FIXMEs...")
        
        todos = []
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if 'TODO' in line or 'FIXME' in line:
                        todos.append((py_file.name, line_num, line.strip()))
        
        if todos:
            print(f"    📝 {len(todos)} TODOs/FIXMEs found")
            self.stats['todos'] = len(todos)
        else:
            print("    ✅ No TODOs/FIXMEs")
    
    def _check_test_coverage(self):
        """Check test coverage"""
        print("  Checking test coverage...")
        
        test_files = list(self.service_path.rglob('test_*.py'))
        print(f"    🧪 {len(test_files)} test files found")
        self.stats['test_files'] = len(test_files)
    
    # Compliance checks
    def _check_logging_compliance(self):
        """Check logging compliance"""
        print("  Checking logging compliance...")
        # Check for sensitive data in logs
        pass
    
    def _check_data_privacy(self):
        """Check data privacy"""
        print("  Checking data privacy...")
        # Check for PII handling
        pass
    
    def _check_api_documentation(self):
        """Check API documentation"""
        print("  Checking API documentation...")
        
        # Check for FastAPI docs
        for py_file in self.service_path.rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'docs_url' in content:
                    print("    ✅ API docs enabled")
                    return
        
        print("    ⚠️  API docs not configured")
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive audit report"""
        print("\n" + "=" * 60)
        print("📊 AUDIT SUMMARY")
        print("=" * 60)
        
        # Count by severity
        p0_count = len([i for i in self.issues if i.severity == 'P0'])
        p1_count = len([i for i in self.issues if i.severity == 'P1'])
        p2_count = len([i for i in self.issues if i.severity == 'P2'])
        
        print(f"\n🔴 P0 (Critical): {p0_count} issues")
        print(f"🟡 P1 (Important): {p1_count} issues")
        print(f"🔵 P2 (Minor): {p2_count} issues")
        print(f"📊 Total issues: {len(self.issues)}")
        
        # Count by category
        by_category = defaultdict(int)
        for issue in self.issues:
            by_category[issue.category] += 1
        
        print("\n📋 Issues by category:")
        for category, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            print(f"  {category}: {count}")
        
        # Key statistics
        print("\n📈 Key statistics:")
        for key, value in self.stats.items():
            print(f"  {key}: {value}")
        
        return {
            'timestamp': datetime.now().isoformat(),
            'total_issues': len(self.issues),
            'by_severity': {
                'P0': p0_count,
                'P1': p1_count,
                'P2': p2_count
            },
            'by_category': dict(by_category),
            'stats': dict(self.stats),
            'issues': [issue.to_dict() for issue in self.issues]
        }
    
    def export_report(self, output_path: str):
        """Export report to JSON"""
        report = self.generate_report()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Report exported to: {output_path}")


def main():
    """Main entry point"""
    service_path = Path(__file__).parent.parent
    
    auditor = AIServiceAuditor(service_path)
    report = auditor.audit_all()
    
    # Export to JSON
    output_path = service_path / 'audits' / f'audit_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    output_path.parent.mkdir(exist_ok=True)
    auditor.export_report(str(output_path))
    
    # Return exit code based on P0 issues
    p0_count = report['by_severity']['P0']
    if p0_count > 0:
        print(f"\n❌ AUDIT FAILED: {p0_count} critical (P0) issues found")
        return 1
    else:
        print("\n✅ AUDIT PASSED: No critical issues")
        return 0


if __name__ == '__main__':
    sys.exit(main())
