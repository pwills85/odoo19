#!/usr/bin/env python3
"""
Claude Code Performance Benchmarking Script
Measures success metrics for Phase 1 & 2 implementation
"""

import json
import subprocess
import time
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

class ClaudeCodeBenchmark:
    def __init__(self):
        self.project_dir = Path(__file__).parent.parent
        self.log_dir = Path.home() / '.claude' / 'logs' / 'odoo19'
        self.state_dir = Path.home() / '.claude' / 'state' / 'odoo19'
        self.results = {}

    def print_header(self, title):
        print(f"\n{'=' * 70}")
        print(f"{title:^70}")
        print(f"{'=' * 70}\n")

    def analyze_tool_usage_logs(self):
        """Analyze tool usage from PostToolUse logs"""
        self.print_header("Tool Usage Analysis")

        if not self.log_dir.exists():
            print("⚠️  No log directory found. Run some Claude Code sessions first.")
            return {}

        tool_usage = defaultdict(int)
        total_operations = 0

        for log_file in self.log_dir.glob('tools_*.jsonl'):
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        tool = entry.get('tool', 'unknown')
                        tool_usage[tool] += 1
                        total_operations += 1
                    except json.JSONDecodeError:
                        continue

        if total_operations > 0:
            print(f"📊 Total operations logged: {total_operations}")
            print("\nTool Usage Breakdown:")
            for tool, count in sorted(tool_usage.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_operations) * 100
                print(f"  {tool:20s}: {count:4d} ({percentage:5.1f}%)")
        else:
            print("⚠️  No tool usage data available yet")

        self.results['tool_usage'] = dict(tool_usage)
        self.results['total_operations'] = total_operations

        return tool_usage

    def measure_file_coverage(self):
        """Measure which files are being accessed"""
        self.print_header("File Access Coverage")

        accessed_files = set()

        if self.log_dir.exists():
            for log_file in self.log_dir.glob('tools_*.jsonl'):
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            tool_input = entry.get('input', {})

                            file_path = tool_input.get('file_path') or tool_input.get('path')
                            if file_path:
                                accessed_files.add(file_path)
                        except json.JSONDecodeError:
                            continue

        print(f"📁 Unique files accessed: {len(accessed_files)}")

        # Categorize files
        categories = {
            'models': 0,
            'views': 0,
            'controllers': 0,
            'tests': 0,
            'security': 0,
            'data': 0,
            'other': 0
        }

        for file_path in accessed_files:
            if 'models/' in file_path:
                categories['models'] += 1
            elif 'views/' in file_path or '.xml' in file_path:
                categories['views'] += 1
            elif 'controllers/' in file_path:
                categories['controllers'] += 1
            elif 'tests/' in file_path:
                categories['tests'] += 1
            elif 'security/' in file_path:
                categories['security'] += 1
            elif 'data/' in file_path:
                categories['data'] += 1
            else:
                categories['other'] += 1

        print("\nFile Category Breakdown:")
        for category, count in categories.items():
            if count > 0:
                print(f"  {category:15s}: {count:3d} files")

        self.results['file_coverage'] = {
            'total_files': len(accessed_files),
            'categories': categories
        }

        return accessed_files

    def check_agent_availability(self):
        """Check if custom agents are properly configured"""
        self.print_header("Custom Agents Status")

        agents_dir = self.project_dir / '.claude' / 'agents'
        agents = {}

        if agents_dir.exists():
            for agent_file in agents_dir.glob('*.md'):
                with open(agent_file, 'r') as f:
                    content = f.read()
                    # Extract name from frontmatter
                    if 'name:' in content:
                        name_line = [line for line in content.split('\n') if line.startswith('name:')][0]
                        agent_name = name_line.split(':', 1)[1].strip()
                        agents[agent_file.stem] = agent_name
                        print(f"✅ {agent_name} (@{agent_file.stem})")

        self.results['agents'] = agents
        return agents

    def check_hooks_performance(self):
        """Measure hooks execution time"""
        self.print_header("Hooks Performance")

        test_input = {
            "tool_name": "Read",
            "tool_input": {"file_path": "test.py"}
        }

        hooks = {
            'PreToolUse': '.claude/hooks/pre_tool_use.py',
            'PostToolUse': '.claude/hooks/post_tool_use.py',
            'PreCompact': '.claude/hooks/pre_compact.py'
        }

        execution_times = {}

        for hook_name, hook_path in hooks.items():
            try:
                start = time.time()
                result = subprocess.run(
                    ['python3', hook_path],
                    input=json.dumps(test_input),
                    capture_output=True,
                    text=True,
                    timeout=5,
                    cwd=self.project_dir
                )
                end = time.time()

                execution_time = (end - start) * 1000  # Convert to ms

                if result.returncode == 0:
                    execution_times[hook_name] = execution_time
                    status = "✅" if execution_time < 100 else "⚠️"
                    print(f"{status} {hook_name:15s}: {execution_time:6.2f}ms")
                else:
                    print(f"❌ {hook_name:15s}: Failed (exit {result.returncode})")

            except Exception as e:
                print(f"❌ {hook_name:15s}: Error - {e}")

        avg_time = sum(execution_times.values()) / len(execution_times) if execution_times else 0
        print(f"\n📊 Average hook execution time: {avg_time:.2f}ms")

        self.results['hooks_performance'] = execution_times

        return execution_times

    def estimate_cost_savings(self):
        """Estimate token/cost savings from Explore agent and optimizations"""
        self.print_header("Estimated Performance Improvements")

        # These are estimated improvements based on Claude Code features
        improvements = {
            'Explore Agent (Haiku)': {
                'description': 'Reduced context usage for codebase exploration',
                'estimated_saving': '70%',
                'impact': 'High'
            },
            'Custom Agents': {
                'description': 'Specialized knowledge reduces trial-and-error',
                'estimated_saving': '50%',
                'impact': 'High'
            },
            'Thinking Mode': {
                'description': 'Better planning reduces rework',
                'estimated_saving': '30%',
                'impact': 'Medium'
            },
            'Auto-compact': {
                'description': 'Infinite conversations without restart',
                'estimated_saving': 'Infinite context',
                'impact': 'High'
            },
            'Hooks Validation': {
                'description': 'Prevents errors before execution',
                'estimated_saving': '20% error reduction',
                'impact': 'Medium'
            }
        }

        for feature, data in improvements.items():
            print(f"🎯 {feature}")
            print(f"   Description: {data['description']}")
            print(f"   Saving:      {data['estimated_saving']}")
            print(f"   Impact:      {data['impact']}")
            print()

        self.results['improvements'] = improvements

    def check_configuration_quality(self):
        """Check quality of configuration"""
        self.print_header("Configuration Quality Assessment")

        scores = {}

        # Check settings.json
        settings_path = self.project_dir / '.claude' / 'settings.json'
        if settings_path.exists():
            with open(settings_path, 'r') as f:
                settings = json.load(f)

            score = 0
            max_score = 10

            if settings.get('thinking', {}).get('enabled'):
                score += 2
            if 'hooks' in settings and len(settings['hooks']) >= 3:
                score += 2
            if 'permissions' in settings and len(settings['permissions'].get('allow', [])) > 10:
                score += 2
            if settings.get('autoCompact', {}).get('enabled'):
                score += 2
            if 'bash' in settings:
                score += 2

            scores['settings'] = (score, max_score)
            print(f"⚙️  Settings Configuration: {score}/{max_score} ({score/max_score*100:.0f}%)")

        # Check agents
        agents_dir = self.project_dir / '.claude' / 'agents'
        agent_count = len(list(agents_dir.glob('*.md'))) if agents_dir.exists() else 0
        scores['agents'] = (agent_count, 3)
        print(f"🤖 Custom Agents:         {agent_count}/3 ({agent_count/3*100:.0f}%)")

        # Check hooks
        hooks_dir = self.project_dir / '.claude' / 'hooks'
        hook_count = len(list(hooks_dir.glob('*.py'))) + len(list(hooks_dir.glob('*.sh'))) if hooks_dir.exists() else 0
        scores['hooks'] = (hook_count, 4)
        print(f"🔗 Hooks Implemented:     {hook_count}/4 ({hook_count/4*100:.0f}%)")

        # Check output styles
        styles_dir = self.project_dir / '.claude' / 'output-styles'
        styles_count = len(list(styles_dir.glob('*.md'))) if styles_dir.exists() else 0
        scores['styles'] = (styles_count, 2)
        print(f"🎨 Output Styles:         {styles_count}/2 ({styles_count/2*100:.0f}%)")

        # Overall score
        total_score = sum(s[0] for s in scores.values())
        max_total = sum(s[1] for s in scores.values())
        overall = (total_score / max_total * 100) if max_total > 0 else 0

        print(f"\n🏆 Overall Configuration: {total_score}/{max_total} ({overall:.0f}%)")

        self.results['configuration_scores'] = scores
        self.results['overall_score'] = overall

        return overall

    def generate_recommendations(self):
        """Generate recommendations based on analysis"""
        self.print_header("Recommendations")

        recommendations = []

        # Check tool usage patterns
        if self.results.get('total_operations', 0) < 10:
            recommendations.append({
                'priority': 'Low',
                'area': 'Usage',
                'recommendation': 'Run more Claude Code sessions to gather meaningful metrics'
            })

        # Check agent usage
        agents_count = len(self.results.get('agents', {}))
        if agents_count < 3:
            recommendations.append({
                'priority': 'High',
                'area': 'Agents',
                'recommendation': 'Complete Phase 1: Create all 3 custom agents'
            })

        # Check hooks
        hooks_perf = self.results.get('hooks_performance', {})
        slow_hooks = [h for h, t in hooks_perf.items() if t > 100]
        if slow_hooks:
            recommendations.append({
                'priority': 'Medium',
                'area': 'Performance',
                'recommendation': f'Optimize slow hooks: {", ".join(slow_hooks)}'
            })

        # Check configuration
        overall_score = self.results.get('overall_score', 0)
        if overall_score < 90:
            recommendations.append({
                'priority': 'Medium',
                'area': 'Configuration',
                'recommendation': 'Complete remaining configuration items to reach 90%+'
            })

        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. [{rec['priority']}] {rec['area']}: {rec['recommendation']}")
        else:
            print("✅ Configuration is optimal! No recommendations at this time.")

        self.results['recommendations'] = recommendations

    def save_benchmark_report(self):
        """Save comprehensive benchmark report"""
        report_dir = self.project_dir / '.claude' / 'benchmark_reports'
        report_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = report_dir / f'benchmark_{timestamp}.json'

        report = {
            'timestamp': datetime.now().isoformat(),
            'project': 'Odoo 19 CE - l10n_cl_dte',
            'results': self.results
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n📄 Benchmark report saved: {report_file}")

        return report_file

    def run_benchmark(self):
        """Run complete benchmark suite"""
        print("\n" + "="*70)
        print(" Claude Code Configuration Benchmark ".center(70, "="))
        print(f" {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ".center(70, "="))
        print("="*70)

        self.check_agent_availability()
        self.check_hooks_performance()
        self.check_configuration_quality()
        self.analyze_tool_usage_logs()
        self.measure_file_coverage()
        self.estimate_cost_savings()
        self.generate_recommendations()

        report_file = self.save_benchmark_report()

        self.print_header("Benchmark Complete")
        print(f"📊 Overall Configuration Score: {self.results.get('overall_score', 0):.0f}%")
        print(f"📁 Full report: {report_file}")

def main():
    benchmark = ClaudeCodeBenchmark()
    benchmark.run_benchmark()

if __name__ == '__main__':
    main()
