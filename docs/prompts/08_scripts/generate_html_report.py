#!/usr/bin/env python3
"""
HTML Report Generator for Template Validation
Generates a styled HTML report from validation results

Usage:
    python generate_html_report.py [--input validation_report.json] [--output report.html]
"""

import argparse
import json
from datetime import datetime
from pathlib import Path
from string import Template
from typing import Dict, List


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Template Validation Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 1.1rem;
            opacity: 0.9;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }

        .metric-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            text-align: center;
            transition: transform 0.2s;
        }

        .metric-card:hover {
            transform: translateY(-5px);
        }

        .metric-value {
            font-size: 3rem;
            font-weight: bold;
            margin: 10px 0;
        }

        .metric-label {
            color: #666;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .metric-card.valid .metric-value { color: #10b981; }
        .metric-card.invalid .metric-value { color: #ef4444; }
        .metric-card.score .metric-value { color: #3b82f6; }

        .templates {
            padding: 40px;
        }

        .templates h2 {
            font-size: 2rem;
            margin-bottom: 30px;
            color: #1f2937;
        }

        .template-card {
            background: white;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: all 0.2s;
        }

        .template-card:hover {
            border-color: #667eea;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.15);
        }

        .template-card.valid {
            border-left: 4px solid #10b981;
        }

        .template-card.invalid {
            border-left: 4px solid #ef4444;
        }

        .template-header {
            padding: 20px;
            background: #f9fafb;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }

        .template-name {
            font-size: 1.2rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .status-badge.pass {
            background: #d1fae5;
            color: #065f46;
        }

        .status-badge.fail {
            background: #fee2e2;
            color: #991b1b;
        }

        .template-score {
            font-size: 1.5rem;
            font-weight: bold;
            color: #667eea;
        }

        .template-body {
            padding: 20px;
            border-top: 1px solid #e5e7eb;
        }

        .template-body.collapsed {
            display: none;
        }

        .issue-summary {
            display: flex;
            gap: 30px;
            margin-bottom: 20px;
        }

        .issue-count {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.95rem;
        }

        .issue-count .label {
            color: #666;
        }

        .issue-count .value {
            font-weight: 600;
        }

        .issue-count.errors .value { color: #ef4444; }
        .issue-count.warnings .value { color: #f59e0b; }
        .issue-count.infos .value { color: #3b82f6; }

        .issues-list {
            margin-top: 20px;
        }

        .issue-item {
            padding: 12px;
            margin-bottom: 8px;
            border-radius: 6px;
            border-left: 3px solid;
        }

        .issue-item.error {
            background: #fef2f2;
            border-color: #ef4444;
        }

        .issue-item.warning {
            background: #fffbeb;
            border-color: #f59e0b;
        }

        .issue-item.info {
            background: #eff6ff;
            border-color: #3b82f6;
        }

        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 6px;
        }

        .issue-rule {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .issue-line {
            font-size: 0.85rem;
            color: #666;
        }

        .issue-message {
            font-size: 0.9rem;
            color: #374151;
        }

        .metadata {
            margin-top: 15px;
            padding: 15px;
            background: #f9fafb;
            border-radius: 6px;
            font-size: 0.9rem;
        }

        .metadata-item {
            margin-bottom: 8px;
        }

        .metadata-item strong {
            color: #667eea;
        }

        .footer {
            padding: 30px;
            text-align: center;
            color: #666;
            font-size: 0.9rem;
            background: #f8f9fa;
            border-top: 1px solid #e5e7eb;
        }

        .toggle-icon {
            transition: transform 0.2s;
        }

        .toggle-icon.expanded {
            transform: rotate(180deg);
        }

        @media (max-width: 768px) {
            .summary {
                grid-template-columns: 1fr;
            }

            .header h1 {
                font-size: 1.8rem;
            }

            .template-header {
                flex-direction: column;
                align-items: start;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📋 Template Validation Report</h1>
            <p>Generated on $timestamp</p>
        </div>

        <div class="summary">
            <div class="metric-card">
                <div class="metric-label">Total Templates</div>
                <div class="metric-value">$total_templates</div>
            </div>
            <div class="metric-card valid">
                <div class="metric-label">Valid Templates</div>
                <div class="metric-value">$valid_templates</div>
            </div>
            <div class="metric-card invalid">
                <div class="metric-label">Invalid Templates</div>
                <div class="metric-value">$invalid_templates</div>
            </div>
            <div class="metric-card score">
                <div class="metric-label">Average Score</div>
                <div class="metric-value">$average_score%</div>
            </div>
        </div>

        <div class="templates">
            <h2>📄 Templates Details</h2>
            $templates_html
        </div>

        <div class="footer">
            <p>Generated by Template Validator v1.0</p>
            <p>Part of the Odoo 19 Prompt Engineering System</p>
        </div>
    </div>

    <script>
        function toggleTemplate(element) {{
            const body = element.nextElementSibling;
            const icon = element.querySelector('.toggle-icon');

            body.classList.toggle('collapsed');
            icon.classList.toggle('expanded');
        }}

        // Initialize - collapse invalid templates by default
        document.querySelectorAll('.template-body').forEach(body => {{
            const card = body.parentElement;
            if (!card.classList.contains('invalid')) {{
                body.classList.add('collapsed');
            }}
        }});
    </script>
</body>
</html>
"""


def generate_template_html(template: Dict) -> str:
    """Generate HTML for a single template"""
    is_valid = template['is_valid']
    name = template['name']
    score = template['score']
    issues = template['issues']
    metadata = template.get('metadata', {})

    # Status badge
    status_class = 'pass' if is_valid else 'fail'
    status_text = '✅ PASS' if is_valid else '❌ FAIL'

    # Issue counts
    errors_html = f'<div class="issue-count errors"><span class="label">Errors:</span> <span class="value">{issues["errors"]}</span></div>'
    warnings_html = f'<div class="issue-count warnings"><span class="label">Warnings:</span> <span class="value">{issues["warnings"]}</span></div>'
    infos_html = f'<div class="issue-count infos"><span class="label">Info:</span> <span class="value">{issues["infos"]}</span></div>'

    # Issues list
    issues_list_html = ""
    if issues['details']:
        issues_list_html = '<div class="issues-list">'
        for issue in issues['details']:
            severity = issue['severity']
            rule_id = issue['rule_id']
            message = issue['message']
            line_number = issue.get('line_number', '')

            line_info = f'<span class="issue-line">Line {line_number}</span>' if line_number else ''

            issues_list_html += f'''
            <div class="issue-item {severity}">
                <div class="issue-header">
                    <span class="issue-rule">{rule_id}</span>
                    {line_info}
                </div>
                <div class="issue-message">{message}</div>
            </div>
            '''
        issues_list_html += '</div>'

    # Metadata
    metadata_html = ""
    if metadata:
        metadata_html = '<div class="metadata">'
        if 'version' in metadata:
            metadata_html += f'<div class="metadata-item"><strong>Version:</strong> {metadata["version"]}</div>'
        if 'level' in metadata:
            metadata_html += f'<div class="metadata-item"><strong>Level:</strong> {metadata["level"]}</div>'
        if 'agent' in metadata:
            metadata_html += f'<div class="metadata-item"><strong>Agent:</strong> {metadata["agent"]}</div>'
        if 'variables' in metadata and metadata['variables']:
            vars_list = ', '.join([f'<code>{v}</code>' for v in metadata['variables'][:10]])
            metadata_html += f'<div class="metadata-item"><strong>Variables:</strong> {vars_list}</div>'
        metadata_html += '</div>'

    card_class = 'valid' if is_valid else 'invalid'

    return f'''
    <div class="template-card {card_class}">
        <div class="template-header" onclick="toggleTemplate(this)">
            <div class="template-name">
                <span>{name}</span>
                <span class="status-badge {status_class}">{status_text}</span>
            </div>
            <div>
                <span class="template-score">{score:.1f}/100</span>
                <span class="toggle-icon">▼</span>
            </div>
        </div>
        <div class="template-body">
            <div class="issue-summary">
                {errors_html}
                {warnings_html}
                {infos_html}
            </div>
            {issues_list_html}
            {metadata_html}
        </div>
    </div>
    '''


def generate_html_report(report_path: Path, output_path: Path):
    """Generate HTML report from JSON validation report"""
    # Read JSON report
    with open(report_path, 'r', encoding='utf-8') as f:
        report = json.load(f)

    # Generate templates HTML
    templates_html = ""
    for template in sorted(report['templates'], key=lambda t: (not t['is_valid'], -t['score'])):
        templates_html += generate_template_html(template)

    # Fill template using Template (avoids KeyError with CSS braces)
    template = Template(HTML_TEMPLATE)
    html = template.safe_substitute(
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        total_templates=report['total_templates'],
        valid_templates=report['valid_templates'],
        invalid_templates=report['total_templates'] - report['valid_templates'],
        average_score=f"{report['average_score']:.1f}",
        templates_html=templates_html
    )

    # Write HTML file
    output_path.write_text(html, encoding='utf-8')
    print(f"✅ HTML report generated: {output_path}")
    print(f"   Open with: open {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate HTML report from template validation results"
    )
    parser.add_argument(
        '--input',
        type=Path,
        default=Path('validation_report.json'),
        help='Input JSON report file (default: validation_report.json)'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('../06_outputs/TEMPLATES_VALIDATION_REPORT.html'),
        help='Output HTML report file (default: ../06_outputs/TEMPLATES_VALIDATION_REPORT.html)'
    )

    args = parser.parse_args()

    if not args.input.exists():
        print(f"❌ Error: Input file not found: {args.input}")
        print("   Run validation first: python validate_templates.py --all --json validation_report.json")
        return 1

    # Create output directory if needed
    args.output.parent.mkdir(parents=True, exist_ok=True)

    generate_html_report(args.input, args.output)
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
