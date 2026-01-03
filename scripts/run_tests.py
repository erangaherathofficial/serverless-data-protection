#!/usr/bin/env python3
"""Test runner script for the data protection framework.

Provides commands to run different test suites:
- Unit tests
- Integration tests
- Security tests
- Performance tests
- All tests

Usage:
    python scripts/run_tests.py unit
    python scripts/run_tests.py integration
    python scripts/run_tests.py security
    python scripts/run_tests.py performance
    python scripts/run_tests.py all
    python scripts/run_tests.py coverage
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Project root directory
PROJECT_ROOT = Path(__file__).parent.parent
TESTS_DIR = PROJECT_ROOT / 'tests'


def run_command(cmd: list[str], description: str) -> int:
    """Run a command and return exit code."""
    print(f"\n{'=' * 60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('=' * 60 + '\n')

    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    return result.returncode


def run_unit_tests(verbose: bool = False) -> int:
    """Run unit tests."""
    cmd = ['pytest', 'tests/unit/', '-v']
    if verbose:
        cmd.append('-s')
    return run_command(cmd, 'Unit Tests')


def run_integration_tests(verbose: bool = False) -> int:
    """Run integration tests."""
    cmd = ['pytest', 'tests/integration/', '-v', '-m', 'integration']
    if verbose:
        cmd.append('-s')
    return run_command(cmd, 'Integration Tests')


def run_security_tests(verbose: bool = False) -> int:
    """Run security tests."""
    cmd = ['pytest', 'tests/security/', '-v']
    if verbose:
        cmd.append('-s')
    return run_command(cmd, 'Security Tests')


def run_performance_tests(verbose: bool = False) -> int:
    """Run performance tests."""
    cmd = ['pytest', 'tests/performance/', '-v', '-m', 'performance', '-s']
    return run_command(cmd, 'Performance Tests')


def run_all_tests(verbose: bool = False) -> int:
    """Run all tests."""
    cmd = ['pytest', 'tests/', '-v']
    if verbose:
        cmd.append('-s')
    return run_command(cmd, 'All Tests')


def run_coverage(verbose: bool = False) -> int:
    """Run tests with coverage report."""
    cmd = [
        'pytest', 'tests/',
        '--cov=src',
        '--cov-report=term-missing',
        '--cov-report=html:coverage_html',
        '-v'
    ]
    if verbose:
        cmd.append('-s')

    result = run_command(cmd, 'Tests with Coverage')

    if result == 0:
        report_path = PROJECT_ROOT / 'coverage_html' / 'index.html'
        print(f"\nCoverage report generated at: {report_path}")

    return result


def run_quick_tests(verbose: bool = False) -> int:
    """Run quick tests (excludes performance and slow tests)."""
    cmd = ['pytest', 'tests/', '-v', '-m', 'not slow and not performance']
    if verbose:
        cmd.append('-s')
    return run_command(cmd, 'Quick Tests')


def generate_test_data() -> int:
    """Generate synthetic test data."""
    cmd = ['python', 'tests/test_data/generate_test_data.py']
    return run_command(cmd, 'Generate Test Data')


def run_specific_test(test_path: str, verbose: bool = False) -> int:
    """Run a specific test file or function."""
    cmd = ['pytest', test_path, '-v']
    if verbose:
        cmd.append('-s')
    return run_command(cmd, f'Specific Test: {test_path}')


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Run tests for the data protection framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/run_tests.py unit
    python scripts/run_tests.py integration -v
    python scripts/run_tests.py coverage
    python scripts/run_tests.py test tests/unit/test_handlers.py
        """
    )

    choices = [
        'unit', 'integration', 'security', 'performance',
        'all', 'coverage', 'quick', 'generate', 'test'
    ]
    parser.add_argument(
        'command',
        choices=choices,
        help='Test suite to run'
    )

    parser.add_argument(
        'test_path',
        nargs='?',
        help='Specific test path (only with "test" command)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output (show print statements)'
    )

    args = parser.parse_args()

    # Ensure we're in the project root
    os.chdir(PROJECT_ROOT)

    # Map commands to functions
    commands = {
        'unit': run_unit_tests,
        'integration': run_integration_tests,
        'security': run_security_tests,
        'performance': run_performance_tests,
        'all': run_all_tests,
        'coverage': run_coverage,
        'quick': run_quick_tests,
        'generate': generate_test_data,
    }

    if args.command == 'test':
        if not args.test_path:
            parser.error("'test' command requires a test path argument")
        exit_code = run_specific_test(args.test_path, args.verbose)
    else:
        func = commands[args.command]
        if args.command == 'generate':
            exit_code = func()
        else:
            exit_code = func(args.verbose)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
