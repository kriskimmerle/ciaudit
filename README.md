# ciaudit

**CI/CD Pipeline Efficiency & Cost Auditor** — find waste in your GitHub Actions workflows.

Static analysis focused on **performance**, **cost optimization**, and **best practices**. Complements [actionlint](https://github.com/rhysd/actionlint) (syntax checking) and security linters with efficiency-focused checks.

Zero dependencies. Stdlib only. Single file.

## Why?

GitHub Actions minutes cost money. Most workflows have easy wins:

- **Full git clones** when you only need the latest commit
- **Missing dependency caching** — downloading packages every single run
- **No timeout** — a hung job bills forever
- **No concurrency control** — pushing twice runs two full pipelines
- **No path filters** — editing README triggers a full build

ciaudit finds these issues and tells you how to fix them.

## Installation

```bash
# Just download it
curl -O https://raw.githubusercontent.com/kriskimmerle/ciaudit/main/ciaudit.py
chmod +x ciaudit.py

# Or clone
git clone https://github.com/kriskimmerle/ciaudit.git
cd ciaudit
```

No `pip install` needed. Runs on Python 3.10+.

## Usage

```bash
# Audit a specific workflow
python ciaudit.py .github/workflows/ci.yml

# Audit all workflows (auto-detect .github/workflows/)
python ciaudit.py

# Audit a directory of workflow files
python ciaudit.py .github/workflows/

# Show fix suggestions
python ciaudit.py ci.yml --verbose

# JSON output for automation
python ciaudit.py ci.yml --json

# CI mode: exit 1 if grade below B
python ciaudit.py ci.yml --check B

# Read from stdin
cat ci.yml | python ciaudit.py -

# Only show errors (skip warnings/info)
python ciaudit.py ci.yml --severity error

# Ignore specific rules
python ciaudit.py ci.yml --ignore CI001,CI006

# List all rules
python ciaudit.py --list-rules
```

## Rules

### ⚡ Speed (5 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| CI001 | WARNING | `actions/checkout` without `fetch-depth` (fetches entire git history) |
| CI002 | ERROR | Package install (pip/npm/yarn/cargo/go/gem/maven/gradle) without caching |
| CI003 | WARNING | `actions/setup-*` without `cache` parameter |
| CI004 | WARNING | `docker build` without layer caching strategy |
| CI005 | INFO | Matrix strategy with `fail-fast: false` |

### 💰 Cost (5 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| CI006 | ERROR | Jobs without `timeout-minutes` (can bill indefinitely) |
| CI007 | WARNING | No `concurrency` group on push/PR workflows |
| CI008 | WARNING | Push/PR triggers without `paths` or `branches` filter |
| CI009 | WARNING | Large matrix (10+ combos) without `max-parallel` |
| CI014 | WARNING | Concurrency group without `cancel-in-progress` |

### 📋 Best Practices (5 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| CI010 | WARNING | `npm install` instead of `npm ci` in CI |
| CI011 | INFO | Multiple `actions/checkout` in same job for same repo |
| CI012 | INFO | `apt-get install` every run without caching |
| CI013 | INFO | `pip install` in container without `--no-cache-dir` |
| CI015 | INFO | Full git clone inside container jobs |

## Grading

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 95-100 | Excellent — pipeline is well-optimized |
| A | 85-94 | Good — minor improvements possible |
| B | 70-84 | Decent — some optimization opportunities |
| C | 55-69 | Fair — several efficiency issues |
| D | 40-54 | Poor — significant waste detected |
| F | 0-39 | Failing — major optimization needed |

## Examples

### Before (Grade F)

```yaml
name: CI
on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4              # ← CI001: full clone
      - uses: actions/setup-python@v5          # ← CI003: no cache param
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt   # ← CI002: no caching
      - run: pytest                            # ← CI006: no timeout
```

### After (Grade A+)

```yaml
name: CI
on:
  push:
    branches: [main]
    paths: ['src/**', '*.py']
  pull_request:
    paths: ['src/**', '*.py']

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -r requirements.txt
      - run: pytest
```

## CI Integration

### GitHub Actions

```yaml
- name: Audit CI efficiency
  run: python ciaudit.py --check B
```

### Pre-commit

```bash
# In your CI workflow
python ciaudit.py .github/workflows/ --check B --json > ciaudit-report.json
```

## Output Formats

**Text** (default) — colored, human-readable:
```
ciaudit v1.0.0 — CI/CD Efficiency Auditor

File: .github/workflows/ci.yml
Grade: F (0/100)

⚡ Speed
  ❌ CI002: pip install detected without dependency caching
    L25 [test]

💰 Cost
  ❌ CI006: Job 'test' has no timeout-minutes; can run (and bill) indefinitely
    L11 [test]
```

**JSON** — structured for automation:
```json
{
  "version": "1.0.0",
  "file": "ci.yml",
  "grade": "F",
  "score": 0,
  "findings": [...],
  "summary": {"errors": 7, "warnings": 13, "info": 1, "total": 21}
}
```

## How it compares

| Tool | Focus | Language | Dependencies |
|------|-------|----------|-------------|
| **ciaudit** | Efficiency & cost | Python | Zero |
| actionlint | Syntax & correctness | Go | Go binary |
| ghaaudit | Security | Python | Zero |
| super-linter | Multi-language linting | Docker | Heavy |

ciaudit is specifically about **making your CI faster and cheaper**. It doesn't check syntax (actionlint does that) or security (ghaaudit does that). It checks whether you're wasting time and money.

## Limitations

- GitHub Actions only (no GitLab CI, CircleCI, Jenkins)
- YAML parsing is line-based (covers GHA workflow subset, not full YAML spec)
- Cannot detect all caching patterns (custom scripts, unusual setups)
- Static analysis only — doesn't measure actual run times

## License

MIT
