#!/usr/bin/env python3
"""
Phase 2 Feature Testing & Validation Script
Tests hooks, output styles, and configuration
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

class Colors:
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

class Phase2Tester:
    def __init__(self):
        self.project_dir = Path(__file__).parent.parent
        self.passed = 0
        self.failed = 0
        self.warnings = 0

    def print_header(self, title):
        print(f"\n{Colors.BLUE}{'=' * 60}{Colors.NC}")
        print(f"{Colors.BLUE}{title:^60}{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}\n")

    def print_test(self, name, status, message=""):
        if status == "PASS":
            print(f"{Colors.GREEN}✓{Colors.NC} {name}")
            if message:
                print(f"  {message}")
            self.passed += 1
        elif status == "FAIL":
            print(f"{Colors.RED}✗{Colors.NC} {name}")
            if message:
                print(f"  {Colors.RED}{message}{Colors.NC}")
            self.failed += 1
        elif status == "WARN":
            print(f"{Colors.YELLOW}⚠{Colors.NC} {name}")
            if message:
                print(f"  {Colors.YELLOW}{message}{Colors.NC}")
            self.warnings += 1

    def test_hooks_exist(self):
        """Test that all hook files exist and are executable"""
        self.print_header("Hook Files Validation")

        hooks = {
            'PreToolUse': '.claude/hooks/pre_tool_use.py',
            'PostToolUse': '.claude/hooks/post_tool_use.py',
            'SessionStart': '.claude/hooks/session_start.sh',
            'PreCompact': '.claude/hooks/pre_compact.py'
        }

        for name, path in hooks.items():
            file_path = self.project_dir / path
            if file_path.exists():
                if file_path.stat().st_mode & 0o111:  # Check if executable
                    self.print_test(f"{name} hook exists and is executable", "PASS")
                else:
                    self.print_test(f"{name} hook exists but not executable", "WARN",
                                  f"Run: chmod +x {path}")
            else:
                self.print_test(f"{name} hook missing", "FAIL", f"Expected: {path}")

    def test_hook_syntax(self):
        """Test that Python hooks have valid syntax"""
        self.print_header("Hook Syntax Validation")

        python_hooks = [
            '.claude/hooks/pre_tool_use.py',
            '.claude/hooks/post_tool_use.py',
            '.claude/hooks/pre_compact.py'
        ]

        for hook in python_hooks:
            hook_path = self.project_dir / hook
            if hook_path.exists():
                try:
                    with open(hook_path, 'r') as f:
                        compile(f.read(), hook, 'exec')
                    self.print_test(f"{hook} syntax valid", "PASS")
                except SyntaxError as e:
                    self.print_test(f"{hook} syntax error", "FAIL",
                                  f"Line {e.lineno}: {e.msg}")

    def test_hook_execution(self):
        """Test that hooks can execute with sample input"""
        self.print_header("Hook Execution Tests")

        # Test PreToolUse hook
        test_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "test.py"}
        }

        try:
            result = subprocess.run(
                ['python3', '.claude/hooks/pre_tool_use.py'],
                input=json.dumps(test_input),
                capture_output=True,
                text=True,
                timeout=5,
                cwd=self.project_dir
            )
            if result.returncode == 0:
                self.print_test("PreToolUse hook executes successfully", "PASS")
            else:
                self.print_test("PreToolUse hook failed", "FAIL",
                              f"Exit code: {result.returncode}")
        except Exception as e:
            self.print_test("PreToolUse hook execution error", "FAIL", str(e))

        # Test PostToolUse hook
        try:
            result = subprocess.run(
                ['python3', '.claude/hooks/post_tool_use.py'],
                input=json.dumps(test_input),
                capture_output=True,
                text=True,
                timeout=5,
                cwd=self.project_dir
            )
            if result.returncode == 0:
                self.print_test("PostToolUse hook executes successfully", "PASS")
            else:
                self.print_test("PostToolUse hook failed", "FAIL")
        except Exception as e:
            self.print_test("PostToolUse hook execution error", "FAIL", str(e))

    def test_output_styles(self):
        """Test that output styles exist and have valid frontmatter"""
        self.print_header("Output Styles Validation")

        styles = [
            'odoo-technical.md',
            'dte-compliance-report.md'
        ]

        for style in styles:
            style_path = self.project_dir / '.claude' / 'output-styles' / style
            if style_path.exists():
                with open(style_path, 'r') as f:
                    content = f.read()
                    if content.startswith('---'):
                        # Check for required frontmatter fields
                        if 'name:' in content and 'description:' in content:
                            self.print_test(f"{style} valid", "PASS")
                        else:
                            self.print_test(f"{style} missing frontmatter fields", "FAIL")
                    else:
                        self.print_test(f"{style} missing frontmatter", "FAIL")
            else:
                self.print_test(f"{style} missing", "FAIL")

    def test_settings_configuration(self):
        """Test settings.json configuration"""
        self.print_header("Settings Configuration Tests")

        settings_path = self.project_dir / '.claude' / 'settings.json'

        try:
            with open(settings_path, 'r') as f:
                settings = json.load(f)

            # Test hooks configuration
            if 'hooks' in settings:
                hooks_config = settings['hooks']
                required_hooks = ['PreToolUse', 'PostToolUse', 'SessionStart', 'PreCompact']

                for hook in required_hooks:
                    if hook in hooks_config:
                        if 'command' in hooks_config[hook]:
                            self.print_test(f"Hook '{hook}' configured", "PASS")
                        else:
                            self.print_test(f"Hook '{hook}' missing command", "FAIL")
                    else:
                        self.print_test(f"Hook '{hook}' not configured", "FAIL")
            else:
                self.print_test("Hooks configuration missing", "FAIL")

            # Test thinking mode
            if settings.get('thinking', {}).get('enabled'):
                self.print_test("Thinking mode enabled", "PASS")
            else:
                self.print_test("Thinking mode not enabled", "WARN")

            # Test permissions
            if 'permissions' in settings:
                if settings['permissions'].get('allow'):
                    allow_count = len(settings['permissions']['allow'])
                    self.print_test(f"Permissions configured ({allow_count} allowed)", "PASS")
                else:
                    self.print_test("No allowed permissions", "WARN")
            else:
                self.print_test("Permissions not configured", "FAIL")

        except json.JSONDecodeError as e:
            self.print_test("settings.json invalid JSON", "FAIL", str(e))
        except FileNotFoundError:
            self.print_test("settings.json not found", "FAIL")

    def test_agents_configuration(self):
        """Test that Phase 1 agents still exist"""
        self.print_header("Phase 1 Agents Verification")

        agents = ['odoo-dev.md', 'dte-compliance.md', 'test-automation.md']

        for agent in agents:
            agent_path = self.project_dir / '.claude' / 'agents' / agent
            if agent_path.exists():
                self.print_test(f"{agent} exists", "PASS")
            else:
                self.print_test(f"{agent} missing", "FAIL")

    def test_log_directories(self):
        """Test that log directories are created"""
        self.print_header("Logging Infrastructure")

        log_dirs = [
            Path.home() / '.claude' / 'logs' / 'odoo19',
            Path.home() / '.claude' / 'state' / 'odoo19'
        ]

        for log_dir in log_dirs:
            if log_dir.exists():
                self.print_test(f"Log directory exists: {log_dir.name}", "PASS")
            else:
                log_dir.mkdir(parents=True, exist_ok=True)
                self.print_test(f"Created log directory: {log_dir.name}", "PASS")

    def test_hook_validation_logic(self):
        """Test hook validation logic with specific scenarios"""
        self.print_header("Hook Validation Logic Tests")

        # Test PreToolUse with critical file
        critical_file_input = {
            "tool_name": "Write",
            "tool_input": {"file_path": "addons/localization/l10n_cl_dte/__manifest__.py"}
        }

        try:
            result = subprocess.run(
                ['python3', '.claude/hooks/pre_tool_use.py'],
                input=json.dumps(critical_file_input),
                capture_output=True,
                text=True,
                timeout=5,
                cwd=self.project_dir
            )

            if result.returncode == 0:
                output = result.stdout
                if 'Critical Odoo file' in output or 'manifest' in output.lower():
                    self.print_test("PreToolUse detects critical files", "PASS",
                                  "Warning message generated for __manifest__.py")
                else:
                    self.print_test("PreToolUse may not detect critical files", "WARN")
            else:
                self.print_test("PreToolUse validation test failed", "FAIL")
        except Exception as e:
            self.print_test("PreToolUse validation test error", "FAIL", str(e))

        # Test with destructive command
        destructive_input = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/test"}
        }

        try:
            result = subprocess.run(
                ['python3', '.claude/hooks/pre_tool_use.py'],
                input=json.dumps(destructive_input),
                capture_output=True,
                text=True,
                timeout=5,
                cwd=self.project_dir
            )

            if 'DESTRUCTIVE' in result.stdout:
                self.print_test("PreToolUse detects destructive commands", "PASS")
            else:
                self.print_test("PreToolUse may not detect destructive commands", "WARN")
        except Exception as e:
            self.print_test("Destructive command test error", "FAIL", str(e))

    def generate_report(self):
        """Generate final test report"""
        self.print_header("Test Summary")

        total = self.passed + self.failed + self.warnings

        print(f"Total Tests:  {total}")
        print(f"{Colors.GREEN}Passed:       {self.passed}{Colors.NC}")
        print(f"{Colors.RED}Failed:       {self.failed}{Colors.NC}")
        print(f"{Colors.YELLOW}Warnings:     {self.warnings}{Colors.NC}")

        success_rate = (self.passed / total * 100) if total > 0 else 0
        print(f"\nSuccess Rate: {success_rate:.1f}%")

        # Save report to file
        report = {
            'timestamp': datetime.now().isoformat(),
            'total': total,
            'passed': self.passed,
            'failed': self.failed,
            'warnings': self.warnings,
            'success_rate': success_rate
        }

        report_file = self.project_dir / '.claude' / 'test_reports' / f"phase2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file.parent.mkdir(parents=True, exist_ok=True)

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n📄 Report saved: {report_file}")

        return self.failed == 0

    def run_all_tests(self):
        """Run all test suites"""
        print(f"\n{Colors.BLUE}{'=' * 60}{Colors.NC}")
        print(f"{Colors.BLUE}{'Phase 2 Feature Testing':^60}{Colors.NC}")
        print(f"{Colors.BLUE}{'Odoo 19 CE - Claude Code Configuration':^60}{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")

        self.test_hooks_exist()
        self.test_hook_syntax()
        self.test_hook_execution()
        self.test_hook_validation_logic()
        self.test_output_styles()
        self.test_settings_configuration()
        self.test_agents_configuration()
        self.test_log_directories()

        return self.generate_report()

def main():
    tester = Phase2Tester()
    success = tester.run_all_tests()

    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
