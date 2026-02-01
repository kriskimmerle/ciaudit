#!/usr/bin/env python3
"""
ciaudit - CI/CD Pipeline Security Scanner
A zero-dependency security scanner for GitHub Actions, GitLab CI, and CircleCI configurations.
"""

import re
import sys
import argparse
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from enum import Enum


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class Platform(Enum):
    GITHUB_ACTIONS = "gha"
    GITLAB_CI = "gitlab"
    CIRCLECI = "circleci"
    AUTO = "auto"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    line: int
    file: str
    description: str
    context: Optional[str] = None

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "line": self.line,
            "file": self.file,
            "description": self.description,
            "context": self.context,
        }


# Security rule definitions
RULES = {
    "CI001": {
        "title": "Unpinned action version",
        "severity": Severity.ERROR,
        "description": "Action uses tag instead of commit SHA, allowing supply chain attacks",
        "platforms": [Platform.GITHUB_ACTIONS],
    },
    "CI002": {
        "title": "Excessive permissions",
        "severity": Severity.ERROR,
        "description": "Workflow has write-all permissions or missing permissions key",
        "platforms": [Platform.GITHUB_ACTIONS],
    },
    "CI003": {
        "title": "Script injection vulnerability",
        "severity": Severity.ERROR,
        "description": "Using github.event.* directly in run steps allows code injection",
        "platforms": [Platform.GITHUB_ACTIONS],
    },
    "CI004": {
        "title": "Dangerous pull_request_target usage",
        "severity": Severity.ERROR,
        "description": "pull_request_target with checkout runs untrusted code with secrets",
        "platforms": [Platform.GITHUB_ACTIONS],
    },
    "CI005": {
        "title": "Hardcoded secrets",
        "severity": Severity.ERROR,
        "description": "Secrets/tokens in workflow instead of using secrets context",
        "platforms": [Platform.GITHUB_ACTIONS],
    },
    "CI006": {
        "title": "Unpinned image tag",
        "severity": Severity.WARNING,
        "description": "Using :latest or mutable tags instead of digest/specific version",
        "platforms": [Platform.GITLAB_CI],
    },
    "CI007": {
        "title": "Security job allows failure",
        "severity": Severity.WARNING,
        "description": "Security scanning job has allow_failure: true",
        "platforms": [Platform.GITLAB_CI],
    },
    "CI008": {
        "title": "Unprotected variables",
        "severity": Severity.WARNING,
        "description": "Variables that look like secrets without CI_ prefix or vault reference",
        "platforms": [Platform.GITLAB_CI],
    },
    "CI009": {
        "title": "Unpinned orb version",
        "severity": Severity.WARNING,
        "description": "Using @volatile or no version pin on orb",
        "platforms": [Platform.CIRCLECI],
    },
    "CI010": {
        "title": "SSH enabled in production",
        "severity": Severity.WARNING,
        "description": "SSH keys added in production deployment steps",
        "platforms": [Platform.CIRCLECI],
    },
    "CI011": {
        "title": "Missing security scanning",
        "severity": Severity.INFO,
        "description": "No SAST/DAST/dependency scanning detected",
        "platforms": [Platform.GITHUB_ACTIONS, Platform.GITLAB_CI, Platform.CIRCLECI],
    },
    "CI012": {
        "title": "Secrets in environment variables",
        "severity": Severity.ERROR,
        "description": "Hardcoded credentials in environment variable values",
        "platforms": [Platform.GITHUB_ACTIONS, Platform.GITLAB_CI, Platform.CIRCLECI],
    },
    "CI013": {
        "title": "Curl piped to shell",
        "severity": Severity.ERROR,
        "description": "Downloading and executing untrusted code via curl|bash or wget|sh",
        "platforms": [Platform.GITHUB_ACTIONS, Platform.GITLAB_CI, Platform.CIRCLECI],
    },
    "CI014": {
        "title": "Unrestricted artifact upload",
        "severity": Severity.INFO,
        "description": "Uploading artifacts without path restrictions",
        "platforms": [Platform.GITHUB_ACTIONS, Platform.GITLAB_CI, Platform.CIRCLECI],
    },
}


class CIAuditor:
    def __init__(self, platform: Platform = Platform.AUTO):
        self.platform = platform
        self.findings: List[Finding] = []

    def detect_platform(self, file_path: Path) -> Platform:
        """Auto-detect CI platform from file path"""
        if self.platform != Platform.AUTO:
            return self.platform

        path_str = str(file_path)
        if ".github/workflows" in path_str:
            return Platform.GITHUB_ACTIONS
        elif file_path.name == ".gitlab-ci.yml":
            return Platform.GITLAB_CI
        elif ".circleci" in path_str and file_path.name == "config.yml":
            return Platform.CIRCLECI
        
        # Fallback: try all platforms
        return Platform.AUTO

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single CI configuration file"""
        self.findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}", file=sys.stderr)
            return []

        platform = self.detect_platform(file_path)
        
        if platform == Platform.GITHUB_ACTIONS:
            self._scan_github_actions(lines, file_path)
        elif platform == Platform.GITLAB_CI:
            self._scan_gitlab_ci(lines, file_path)
        elif platform == Platform.CIRCLECI:
            self._scan_circleci(lines, file_path)
        else:
            # Try all platforms if auto-detect failed
            self._scan_github_actions(lines, file_path)
            self._scan_gitlab_ci(lines, file_path)
            self._scan_circleci(lines, file_path)
        
        # Always run cross-platform checks
        self._scan_cross_platform(lines, file_path)
        
        return self.findings

    def _get_indentation(self, line: str) -> int:
        """Get indentation level of a line"""
        return len(line) - len(line.lstrip())

    def _scan_github_actions(self, lines: List[str], file_path: Path):
        """Scan GitHub Actions workflow for security issues"""
        has_permissions = False
        has_pull_request_target = False
        has_checkout = False
        has_security_scan = False
        in_run_block = False
        run_start_line = 0
        run_content = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # CI001: Unpinned action versions
            uses_match = re.match(r'uses:\s*([^@\s]+)@([^\s]+)', stripped)
            if uses_match:
                action, ref = uses_match.groups()
                # Check if ref is not a commit SHA (40 hex chars)
                if not re.match(r'^[0-9a-f]{40}$', ref):
                    self.findings.append(Finding(
                        rule_id="CI001",
                        title=RULES["CI001"]["title"],
                        severity=RULES["CI001"]["severity"],
                        line=i,
                        file=str(file_path),
                        description=f"Action '{action}' uses tag '{ref}' instead of commit SHA",
                        context=stripped,
                    ))
            
            # CI002: Check for permissions
            if re.match(r'permissions:\s*$', stripped):
                has_permissions = True
            if re.match(r'permissions:\s*write-all', stripped):
                self.findings.append(Finding(
                    rule_id="CI002",
                    title=RULES["CI002"]["title"],
                    severity=RULES["CI002"]["severity"],
                    line=i,
                    file=str(file_path),
                    description="Workflow uses 'permissions: write-all' which grants excessive access",
                    context=stripped,
                ))
            
            # CI004: pull_request_target detection
            if 'pull_request_target' in stripped:
                has_pull_request_target = True
            if 'actions/checkout' in stripped and has_pull_request_target:
                has_checkout = True
            
            # Track run blocks for CI003
            if re.match(r'run:\s*[|>]?\s*$', stripped):
                in_run_block = True
                run_start_line = i
                run_content = []
            elif in_run_block:
                if stripped and not stripped.startswith('#'):
                    indent = self._get_indentation(line)
                    if indent > 0:
                        run_content.append(stripped)
                    else:
                        # End of run block
                        in_run_block = False
                        self._check_run_block('\n'.join(run_content), run_start_line, file_path)
            elif re.match(r'run:\s*.+', stripped):
                # Single-line run
                run_text = re.sub(r'run:\s*', '', stripped)
                self._check_run_block(run_text, i, file_path)
            
            # CI005: Hardcoded secrets
            secret_patterns = [
                r'(password|token|api[_-]?key|secret|credential)[\s:=]+["\']?[a-zA-Z0-9_\-]{16,}["\']?',
            ]
            for pattern in secret_patterns:
                if re.search(pattern, stripped, re.IGNORECASE):
                    # Exclude if using secrets context
                    if '${{' not in stripped or 'secrets.' not in stripped:
                        self.findings.append(Finding(
                            rule_id="CI005",
                            title=RULES["CI005"]["title"],
                            severity=RULES["CI005"]["severity"],
                            line=i,
                            file=str(file_path),
                            description="Potential hardcoded secret found",
                            context=stripped,
                        ))
            
            # Check for security scanning tools
            if any(tool in stripped.lower() for tool in ['semgrep', 'snyk', 'trivy', 'codeql', 'sonar', 'dependabot']):
                has_security_scan = True

        # CI002: Missing permissions key (check at workflow level)
        if not has_permissions and len(lines) > 5:  # Only for non-trivial workflows
            self.findings.append(Finding(
                rule_id="CI002",
                title=RULES["CI002"]["title"],
                severity=RULES["CI002"]["severity"],
                line=1,
                file=str(file_path),
                description="Workflow missing 'permissions:' key, defaults to broad access",
                context="(workflow level)",
            ))
        
        # CI004: Dangerous pull_request_target + checkout
        if has_pull_request_target and has_checkout:
            self.findings.append(Finding(
                rule_id="CI004",
                title=RULES["CI004"]["title"],
                severity=RULES["CI004"]["severity"],
                line=1,
                file=str(file_path),
                description="Workflow uses pull_request_target with checkout, exposing secrets to untrusted code",
                context="(workflow level)",
            ))
        
        # CI011: Missing security scanning
        if not has_security_scan:
            self.findings.append(Finding(
                rule_id="CI011",
                title=RULES["CI011"]["title"],
                severity=RULES["CI011"]["severity"],
                line=1,
                file=str(file_path),
                description="No security scanning step detected (SAST/DAST/dependency check)",
                context="(workflow level)",
            ))

    def _check_run_block(self, content: str, line: int, file_path: Path):
        """Check a run block for script injection (CI003)"""
        # CI003: Script injection via github.event.*
        if re.search(r'\$\{\{\s*github\.event\.', content):
            self.findings.append(Finding(
                rule_id="CI003",
                title=RULES["CI003"]["title"],
                severity=RULES["CI003"]["severity"],
                line=line,
                file=str(file_path),
                description="Using github.event.* directly in shell script allows injection attacks",
                context=content[:100],
            ))

    def _scan_gitlab_ci(self, lines: List[str], file_path: Path):
        """Scan GitLab CI configuration for security issues"""
        has_security_scan = False
        current_job = None
        job_has_allow_failure = False
        job_is_security = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Track current job
            if stripped and not stripped.startswith('#') and ':' in stripped and self._get_indentation(line) == 0:
                # Possible job definition
                job_name = stripped.split(':')[0].strip()
                if not job_name.startswith('.') and job_name not in ['stages', 'variables', 'default', 'workflow', 'include']:
                    current_job = job_name
                    job_has_allow_failure = False
                    job_is_security = any(sec in job_name.lower() for sec in ['security', 'sast', 'dast', 'scan', 'test'])
            
            # CI006: Unpinned image tags
            image_match = re.match(r'image:\s*([^:\s]+):([^\s]+)', stripped)
            if image_match:
                image, tag = image_match.groups()
                if tag in ['latest', 'stable', 'master', 'main'] or not re.match(r'^sha256:', tag):
                    self.findings.append(Finding(
                        rule_id="CI006",
                        title=RULES["CI006"]["title"],
                        severity=RULES["CI006"]["severity"],
                        line=i,
                        file=str(file_path),
                        description=f"Image '{image}' uses mutable tag '{tag}' instead of digest",
                        context=stripped,
                    ))
            
            # CI007: allow_failure on security jobs
            if 'allow_failure' in stripped:
                if 'true' in stripped.lower():
                    job_has_allow_failure = True
                    if job_is_security:
                        self.findings.append(Finding(
                            rule_id="CI007",
                            title=RULES["CI007"]["title"],
                            severity=RULES["CI007"]["severity"],
                            line=i,
                            file=str(file_path),
                            description=f"Security job '{current_job}' has allow_failure: true",
                            context=stripped,
                        ))
            
            # CI008: Unprotected variables
            var_match = re.match(r'([A-Z_][A-Z0-9_]*)\s*:\s*["\']?([^"\'#\s]+)', stripped)
            if var_match and self._get_indentation(line) > 0:
                var_name, var_value = var_match.groups()
                # Check if looks like a secret
                if any(secret in var_name.lower() for secret in ['password', 'token', 'key', 'secret', 'credential']):
                    # Not protected if no $CI_ or vault reference
                    if not var_value.startswith('$') and 'vault' not in var_value.lower():
                        self.findings.append(Finding(
                            rule_id="CI008",
                            title=RULES["CI008"]["title"],
                            severity=RULES["CI008"]["severity"],
                            line=i,
                            file=str(file_path),
                            description=f"Variable '{var_name}' looks like a secret but is not protected",
                            context=stripped,
                        ))
            
            # Check for security scanning
            if any(tool in stripped.lower() for tool in ['sast', 'dast', 'semgrep', 'snyk', 'trivy', 'sonar']):
                has_security_scan = True
        
        # CI011: Missing security scanning
        if not has_security_scan:
            self.findings.append(Finding(
                rule_id="CI011",
                title=RULES["CI011"]["title"],
                severity=RULES["CI011"]["severity"],
                line=1,
                file=str(file_path),
                description="No security scanning detected in pipeline",
                context="(pipeline level)",
            ))

    def _scan_circleci(self, lines: List[str], file_path: Path):
        """Scan CircleCI configuration for security issues"""
        has_security_scan = False
        in_deploy_job = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Track if we're in a deploy-related job
            if 'deploy' in stripped.lower() or 'production' in stripped.lower():
                in_deploy_job = True
            
            # CI009: Unpinned orb versions
            orb_match = re.match(r'([^/]+/[^@\s]+)@([^\s]+)', stripped)
            if orb_match and 'orbs:' in ''.join(lines[max(0, i-10):i]):
                orb, version = orb_match.groups()
                if version == 'volatile' or not re.match(r'^\d+\.\d+\.\d+$', version):
                    self.findings.append(Finding(
                        rule_id="CI009",
                        title=RULES["CI009"]["title"],
                        severity=RULES["CI009"]["severity"],
                        line=i,
                        file=str(file_path),
                        description=f"Orb '{orb}' uses unpinned version '{version}'",
                        context=stripped,
                    ))
            
            # CI010: SSH in production
            if 'add_ssh_keys' in stripped and in_deploy_job:
                self.findings.append(Finding(
                    rule_id="CI010",
                    title=RULES["CI010"]["title"],
                    severity=RULES["CI010"]["severity"],
                    line=i,
                    file=str(file_path),
                    description="SSH keys added in production/deploy workflow",
                    context=stripped,
                ))
            
            # Check for security scanning
            if any(tool in stripped.lower() for tool in ['security', 'sast', 'snyk', 'trivy', 'sonar']):
                has_security_scan = True
        
        # CI011: Missing security scanning
        if not has_security_scan:
            self.findings.append(Finding(
                rule_id="CI011",
                title=RULES["CI011"]["title"],
                severity=RULES["CI011"]["severity"],
                line=1,
                file=str(file_path),
                description="No security scanning detected in pipeline",
                context="(pipeline level)",
            ))

    def _scan_cross_platform(self, lines: List[str], file_path: Path):
        """Scan for cross-platform security issues"""
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # CI012: Secrets in environment variables
            env_patterns = [
                r'(PASSWORD|TOKEN|API_KEY|SECRET|CREDENTIAL)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
            ]
            for pattern in env_patterns:
                match = re.search(pattern, stripped)
                if match:
                    # Exclude if using variable references ($, ${, etc.)
                    if not re.search(r'[\$\{]', match.group(2)):
                        self.findings.append(Finding(
                            rule_id="CI012",
                            title=RULES["CI012"]["title"],
                            severity=RULES["CI012"]["severity"],
                            line=i,
                            file=str(file_path),
                            description=f"Hardcoded credential in environment variable",
                            context=stripped,
                        ))
            
            # CI013: Curl piped to shell
            if re.search(r'(curl|wget)\s+.*\|\s*(bash|sh)', stripped):
                self.findings.append(Finding(
                    rule_id="CI013",
                    title=RULES["CI013"]["title"],
                    severity=RULES["CI013"]["severity"],
                    line=i,
                    file=str(file_path),
                    description="Downloading and executing untrusted code via pipe to shell",
                    context=stripped,
                ))
            
            # CI014: Unrestricted artifact upload
            if re.search(r'(upload[_-]?artifact|artifacts:)', stripped, re.IGNORECASE):
                # Check if there's a path restriction nearby
                context_lines = lines[max(0, i-3):min(len(lines), i+3)]
                has_path = any(re.search(r'path\s*:', cl) for cl in context_lines)
                if not has_path:
                    self.findings.append(Finding(
                        rule_id="CI014",
                        title=RULES["CI014"]["title"],
                        severity=RULES["CI014"]["severity"],
                        line=i,
                        file=str(file_path),
                        description="Artifact upload without explicit path restrictions",
                        context=stripped,
                    ))


def format_text(findings: List[Finding], file_path: str = None) -> str:
    """Format findings as human-readable text"""
    if not findings:
        return "✓ No security issues found"
    
    output = []
    severity_colors = {
        Severity.ERROR: "🔴",
        Severity.WARNING: "🟡",
        Severity.INFO: "🔵",
    }
    
    # Group by file
    by_file = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    
    for file, file_findings in sorted(by_file.items()):
        output.append(f"\n{file}")
        output.append("=" * len(file))
        
        for finding in sorted(file_findings, key=lambda x: (x.severity.value, x.line)):
            icon = severity_colors.get(finding.severity, "⚪")
            output.append(f"\n{icon} {finding.rule_id}: {finding.title} [{finding.severity.value.upper()}]")
            output.append(f"   Line {finding.line}: {finding.description}")
            if finding.context:
                output.append(f"   Context: {finding.context}")
    
    summary = f"\n\nFound {len(findings)} issue(s)"
    by_severity = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    
    parts = []
    for sev in [Severity.ERROR, Severity.WARNING, Severity.INFO]:
        count = by_severity.get(sev, 0)
        if count > 0:
            parts.append(f"{count} {sev.value}")
    
    if parts:
        summary += f" ({', '.join(parts)})"
    
    output.append(summary)
    return "\n".join(output)


def format_json(findings: List[Finding]) -> str:
    """Format findings as JSON"""
    return json.dumps({
        "findings": [f.to_dict() for f in findings],
        "total": len(findings),
        "by_severity": {
            "error": len([f for f in findings if f.severity == Severity.ERROR]),
            "warning": len([f for f in findings if f.severity == Severity.WARNING]),
            "info": len([f for f in findings if f.severity == Severity.INFO]),
        }
    }, indent=2)


def list_rules():
    """Print all available rules"""
    print("Available Security Rules:\n")
    for rule_id, rule in sorted(RULES.items()):
        platforms = ", ".join([p.value for p in rule["platforms"]])
        print(f"{rule_id}: {rule['title']}")
        print(f"  Severity: {rule['severity'].value.upper()}")
        print(f"  Platforms: {platforms}")
        print(f"  {rule['description']}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ciaudit - CI/CD Pipeline Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ciaudit .github/workflows/ci.yml
  ciaudit --format json --severity error .gitlab-ci.yml
  ciaudit --recursive --check ./ci-configs/
  ciaudit --list-rules
        """
    )
    
    parser.add_argument('paths', nargs='*', help='Files or directories to scan')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--severity', choices=['info', 'warning', 'error'],
                        help='Minimum severity to show')
    parser.add_argument('--ignore', action='append', dest='ignore_rules',
                        help='Ignore specific rules (can be repeated)')
    parser.add_argument('--check', action='store_true',
                        help='Exit 1 if any issues found (CI mode)')
    parser.add_argument('--list-rules', action='store_true',
                        help='Show all available rules')
    parser.add_argument('--platform', choices=['gha', 'gitlab', 'circleci', 'auto'],
                        default='auto', help='Force platform detection (default: auto)')
    parser.add_argument('-r', '--recursive', action='store_true',
                        help='Scan directories recursively')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Only show errors')
    
    args = parser.parse_args()
    
    if args.list_rules:
        list_rules()
        return 0
    
    if not args.paths:
        parser.print_help()
        return 1
    
    # Convert platform string to enum
    platform_map = {
        'gha': Platform.GITHUB_ACTIONS,
        'gitlab': Platform.GITLAB_CI,
        'circleci': Platform.CIRCLECI,
        'auto': Platform.AUTO,
    }
    platform = platform_map[args.platform]
    
    # Convert severity filter
    severity_filter = None
    if args.severity:
        severity_filter = Severity(args.severity)
    elif args.quiet:
        severity_filter = Severity.ERROR
    
    # Collect files to scan
    files_to_scan = []
    for path_str in args.paths:
        path = Path(path_str)
        if path.is_file():
            files_to_scan.append(path)
        elif path.is_dir():
            if args.recursive:
                # Scan for CI config files
                files_to_scan.extend(path.rglob('.github/workflows/*.yml'))
                files_to_scan.extend(path.rglob('.github/workflows/*.yaml'))
                files_to_scan.extend(path.rglob('.gitlab-ci.yml'))
                files_to_scan.extend(path.rglob('.circleci/config.yml'))
            else:
                print(f"Skipping directory {path} (use --recursive to scan)", file=sys.stderr)
        else:
            print(f"Path not found: {path}", file=sys.stderr)
    
    if not files_to_scan:
        print("No files to scan", file=sys.stderr)
        return 1
    
    # Scan all files
    auditor = CIAuditor(platform=platform)
    all_findings = []
    
    for file_path in files_to_scan:
        findings = auditor.scan_file(file_path)
        
        # Apply filters
        if args.ignore_rules:
            findings = [f for f in findings if f.rule_id not in args.ignore_rules]
        
        if severity_filter:
            severity_order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}
            min_level = severity_order[severity_filter]
            findings = [f for f in findings if severity_order[f.severity] >= min_level]
        
        all_findings.extend(findings)
    
    # Output results
    if args.format == 'json':
        print(format_json(all_findings))
    else:
        print(format_text(all_findings))
    
    # Exit code for CI mode
    if args.check and all_findings:
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
