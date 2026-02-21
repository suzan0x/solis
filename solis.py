#!/usr/bin/env python3
"""
SOLIS — System Security Auditor

Scans a Windows machine for common security misconfigurations
and generates an HTML report with a security score.

Usage:
    python solis.py                  # run scan
    python solis.py --open           # scan + open report in browser
    python solis.py --output ./out   # custom output dir
"""

import sys
import os
import argparse
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.core import SolisScanner
from scanner.report import generate_report
from scanner.console import ConsoleUI


def build_comparison(current, previous):
    """Compare current scan to a previous one and return the delta."""
    if not previous:
        return None

    comp = {
        'previous_time': previous.get('scan_time', '?'),
        'score_prev': previous.get('score', {}).get('value', 0),
        'score_curr': current.get('score', {}).get('value', 0),
    }
    comp['score_delta'] = comp['score_curr'] - comp['score_prev']

    prev_titles = {f['title'] for f in previous.get('findings', [])}
    curr_titles = {f['title'] for f in current.get('findings', [])}

    comp['new_issues'] = [f for f in current.get('findings', []) if f['title'] not in prev_titles]
    comp['resolved'] = [{'title': t} for t in prev_titles if t not in curr_titles]
    comp['persistent'] = [f for f in current.get('findings', []) if f['title'] in prev_titles]

    prev_checks = {s['check']: s['passed'] for s in previous.get('score', {}).get('details', [])}
    comp['check_changes'] = []
    for s in current.get('score', {}).get('details', []):
        prev_val = prev_checks.get(s['check'])
        if prev_val is not None and prev_val != s['passed']:
            comp['check_changes'].append({
                'check': s['check'], 'was': prev_val, 'now': s['passed'],
            })

    return comp


def main():
    parser = argparse.ArgumentParser(description="SOLIS — System Security Auditor")
    parser.add_argument('--open', action='store_true', help='Open report in browser after scan')
    parser.add_argument('--output', '-o', default='reports', help='Output directory (default: reports)')
    args = parser.parse_args()

    if sys.platform != 'win32':
        print("[!] SOLIS is built for Windows. Some checks may not work.")

    scanner = SolisScanner()
    results = scanner.run()

    # diff against last scan if one exists
    previous = SolisScanner.load_previous(output_dir=args.output)
    comparison = build_comparison(results, previous)

    scanner.save_json(output_dir=args.output)

    c = ConsoleUI.C
    report_path = generate_report(results, output_dir=args.output, comparison=comparison)

    if comparison:
        delta = comparison['score_delta']
        arrow = '↑' if delta > 0 else '↓' if delta < 0 else '='
        dc = c['green'] if delta > 0 else c['red'] if delta < 0 else c['dim']
        print(f"\n  {c['cyan']}📈 Comparison with previous scan ({comparison['previous_time']}){c['reset']}")
        print(f"  {dc}   Score: {comparison['score_prev']} → {comparison['score_curr']} ({arrow}{abs(delta)}){c['reset']}")
        if comparison['resolved']:
            print(f"  {c['green']}   ✓ {len(comparison['resolved'])} issue(s) resolved{c['reset']}")
        if comparison['new_issues']:
            print(f"  {c['red']}   ✗ {len(comparison['new_issues'])} new issue(s){c['reset']}")

    print(f"\n  {c['cyan']}{c['bold']}📄 Report: {report_path}{c['reset']}")
    print(f"  {c['dim']}Open this file in your browser.{c['reset']}\n")

    if args.open:
        webbrowser.open(f'file:///{report_path}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
