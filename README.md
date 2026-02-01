# ciaudit

**CI/CD Pipeline Security Scanner**

A zero-dependency security scanner for GitHub Actions, GitLab CI, and CircleCI configurations. Detects common security vulnerabilities in CI/CD pipelines using pattern matching—no external dependencies required.

## Features

- ✅ **Multi-platform support**: GitHub Actions, GitLab CI, CircleCI
- ✅ **Zero dependencies**: Pure Python stdlib only
- ✅ **14 security rules**: Covering common CI/CD security issues
- ✅ **Auto-detection**: Automatically detects platform from file paths
- ✅ **Multiple output formats**: Human-readable text or JSON
- ✅ **CI integration**: `--check` mode for failing builds on issues
- ✅ **Flexible filtering**: By severity, rule ID, or platform

## Installation

### Quick Install (Single File)

```bash
curl -o ciaudit.py https://raw.githubusercontent.com/kriskimmerle/ciaudit/main/ciaudit.py
chmod +x ciaudit.py
./ciaudit.py --help
```

### Clone Repository

```bash
git clone https://github.com/kriskimmerle/ciaudit.git
cd ciaudit
chmod +x ciaudit.py
```

### System-wide Install

```bash
# Copy to a directory in your PATH
sudo cp ciaudit.py /usr/local/bin/ciaudit
sudo chmod +x /usr/local/bin/ciaudit
ciaudit --help
```

## Usage

### Basic Scanning

```bash
# Scan a single workflow file
ciaudit .github/workflows/ci.yml

# Scan GitLab CI configuration
ciaudit .gitlab-ci.yml

# Scan CircleCI config
ciaudit .circleci/config.yml

# Scan a directory recursively
ciaudit --recursive ./ci-configs/
```

### Output Formats

```bash
# Human-readable text (default)
ciaudit .github/workflows/ci.yml

# JSON output for tooling integration
ciaudit --format json .github/workflows/ci.yml
```

### Filtering

```bash
# Show only errors (hide warnings and info)
ciaudit --severity error .github/workflows/ci.yml

# Show only errors (shorthand)
ciaudit --quiet .github/workflows/ci.yml

# Ignore specific rules
ciaudit --ignore CI001 --ignore CI011 .github/workflows/ci.yml
```

### CI Integration

```bash
# Exit with code 1 if any issues are found
ciaudit --check .github/workflows/*.yml
```

Example in GitHub Actions:

```yaml
- name: Scan CI configs
  run: |
    curl -o ciaudit.py https://raw.githubusercontent.com/kriskimmerle/ciaudit/main/ciaudit.py
    python3 ciaudit.py --check .github/workflows/*.yml
```

### Other Options

```bash
# List all available rules
ciaudit --list-rules

# Force platform detection
ciaudit --platform gha .github/workflows/ci.yml

# Get help
ciaudit --help
```

## Security Rules

### GitHub Actions

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| CI001 | Unpinned action version | ERROR | Action uses tag instead of commit SHA, allowing supply chain attacks |
| CI002 | Excessive permissions | ERROR | Workflow has `write-all` permissions or missing permissions key |
| CI003 | Script injection vulnerability | ERROR | Using `github.event.*` directly in run steps allows code injection |
| CI004 | Dangerous pull_request_target | ERROR | `pull_request_target` with checkout runs untrusted code with secrets |
| CI005 | Hardcoded secrets | ERROR | Secrets/tokens in workflow instead of using secrets context |

### GitLab CI

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| CI006 | Unpinned image tag | WARNING | Using `:latest` or mutable tags instead of digest/specific version |
| CI007 | Security job allows failure | WARNING | Security scanning job has `allow_failure: true` |
| CI008 | Unprotected variables | WARNING | Variables that look like secrets without `$CI_` prefix or vault reference |

### CircleCI

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| CI009 | Unpinned orb version | WARNING | Using `@volatile` or no version pin on orb |
| CI010 | SSH enabled in production | WARNING | SSH keys added in production deployment steps |

### Cross-Platform

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| CI011 | Missing security scanning | INFO | No SAST/DAST/dependency scanning detected in pipeline |
| CI012 | Secrets in environment variables | ERROR | Hardcoded credentials in environment variable values |
| CI013 | Curl piped to shell | ERROR | Downloading and executing untrusted code via `curl\|bash` or `wget\|sh` |
| CI014 | Unrestricted artifact upload | INFO | Uploading artifacts without path restrictions |

## Examples

See the `examples/` directory for sample CI configurations:

- `github_secure.yml` - A secure GitHub Actions workflow (should pass with 0 issues)
- `github_vulnerable.yml` - Vulnerable GitHub Actions workflow demonstrating multiple issues
- `gitlab_vulnerable.yml` - Vulnerable GitLab CI configuration
- `circleci_vulnerable.yml` - Vulnerable CircleCI configuration

### Run Against Examples

```bash
# Should find 0 issues
ciaudit examples/github_secure.yml

# Should find multiple issues
ciaudit examples/github_vulnerable.yml
ciaudit examples/gitlab_vulnerable.yml
ciaudit examples/circleci_vulnerable.yml
```

## How It Works

Unlike full YAML parsers, ciaudit uses **pattern matching** on the raw configuration files. This approach:

- ✅ Works without external dependencies (no PyYAML required)
- ✅ Is fast and lightweight
- ✅ Focuses on security-relevant patterns
- ✅ Handles the subset of YAML used in CI configs effectively

The scanner:
1. Reads files line-by-line
2. Tracks indentation to understand context
3. Uses regex to find security-relevant patterns
4. Matches against known vulnerability signatures

This is how many professional security scanners work—you don't need a full AST to find dangerous patterns.

## Why Zero Dependencies?

Security tools should be easy to audit and deploy:
- **Audit**: Single file, ~700 lines of readable Python
- **Deploy**: No pip install, no supply chain risk
- **Portable**: Works anywhere Python 3.7+ is installed
- **Fast**: Starts instantly, no dependency resolution

## Limitations

- **Pattern-based**: May miss complex or obfuscated issues
- **No fix suggestions**: Detects issues but doesn't auto-fix (yet)
- **YAML subset**: Works for CI configs but not general YAML parsing
- **Limited context**: Some checks may need broader code context

These trade-offs are intentional for a lightweight, dependency-free tool.

## Contributing

Contributions welcome! To add a new rule:

1. Add rule definition to `RULES` dict in `ciaudit.py`
2. Implement detection logic in the appropriate `_scan_*()` method
3. Add test case to relevant example file
4. Update this README with the new rule

## License

MIT License - see LICENSE file

## Author

Created by [@kriskimmerle](https://github.com/kriskimmerle)

## Related Tools

- [actionlint](https://github.com/rhysd/actionlint) - GitHub Actions linter (Go)
- [Semgrep](https://semgrep.dev/) - General SAST tool with CI rules
- [Checkov](https://www.checkov.io/) - Infrastructure-as-code scanner

ciaudit is designed to be simpler and more focused: just CI/CD security, zero dependencies.

---

**Security is not a feature, it's a requirement. Start scanning your CI/CD pipelines today.**
