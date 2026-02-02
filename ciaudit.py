#!/usr/bin/env python3
"""ciaudit - CI/CD Pipeline Efficiency & Cost Auditor.

Static analysis for GitHub Actions workflows focused on performance,
cost optimization, and best practices. Complements actionlint (syntax)
and security linters with efficiency-focused checks.

Zero dependencies. Stdlib only. Single file.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any


__version__ = "1.0.0"

# ── Severity ──────────────────────────────────────────────────────────

class Severity(Enum):
    ERROR = "error"      # Definite waste / bad practice
    WARNING = "warning"  # Likely suboptimal
    INFO = "info"        # Suggestion / minor improvement


# ── Finding ───────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule: str
    severity: Severity
    message: str
    file: str
    line: int
    job: str = ""
    step: str = ""
    category: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ── Rule Registry ─────────────────────────────────────────────────────

@dataclass
class Rule:
    id: str
    name: str
    severity: Severity
    category: str
    description: str


RULES: dict[str, Rule] = {}


def rule(id: str, name: str, severity: Severity, category: str, description: str):
    """Register a rule."""
    RULES[id] = Rule(id=id, name=name, severity=severity, category=category, description=description)


# Speed rules
rule("CI001", "checkout-full-clone", Severity.WARNING, "speed",
     "actions/checkout without fetch-depth fetches entire git history")
rule("CI002", "no-dependency-cache", Severity.ERROR, "speed",
     "Package install detected without dependency caching")
rule("CI003", "setup-no-cache", Severity.WARNING, "speed",
     "actions/setup-* without cache parameter")
rule("CI004", "docker-no-cache", Severity.WARNING, "speed",
     "Docker build without layer caching strategy")
rule("CI005", "no-fail-fast", Severity.INFO, "speed",
     "Matrix strategy without fail-fast (all combos run even after failure)")

# Cost rules
rule("CI006", "no-timeout", Severity.ERROR, "cost",
     "Job without timeout-minutes can run (and bill) forever")
rule("CI007", "no-concurrency", Severity.WARNING, "cost",
     "Workflow without concurrency group; duplicate runs waste minutes")
rule("CI008", "no-path-filter", Severity.WARNING, "cost",
     "Push/PR trigger without paths filter; builds run on irrelevant changes")
rule("CI009", "large-matrix", Severity.WARNING, "cost",
     "Large matrix without max-parallel may exhaust runner allocation")

# Best practice rules
rule("CI010", "npm-install-not-ci", Severity.WARNING, "practice",
     "npm install instead of npm ci in CI (slower, non-deterministic)")
rule("CI011", "redundant-checkout", Severity.INFO, "practice",
     "Multiple actions/checkout steps in the same job")
rule("CI012", "apt-every-run", Severity.INFO, "practice",
     "apt-get install without caching; consider container image or cache")
rule("CI013", "pip-no-cache-dir", Severity.INFO, "practice",
     "pip install in Docker/container without --no-cache-dir wastes image space")
rule("CI014", "no-cancel-in-progress", Severity.WARNING, "cost",
     "Concurrency group without cancel-in-progress; stale runs queue instead of cancel")
rule("CI015", "checkout-in-container", Severity.INFO, "practice",
     "actions/checkout with full clone inside a container job")


# ── YAML Parser (GHA subset) ─────────────────────────────────────────

def _parse_yaml_line(line: str) -> tuple[int, str]:
    """Return (indent_level, content) for a YAML line."""
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    return indent, stripped


def parse_workflow(text: str) -> dict:
    """Parse a GitHub Actions workflow YAML into a structured dict.

    This is a line-based parser for the GHA workflow subset.
    It doesn't handle full YAML spec but covers what GHA workflows use.
    """
    lines = text.split("\n")
    result: dict[str, Any] = {}

    # Track line numbers for each key
    result["_lines"] = {}

    # State machine approach: track path through indentation
    path_stack: list[tuple[int, str, Any]] = []  # (indent, key, container)
    current = result

    i = 0
    while i < len(lines):
        raw_line = lines[i]
        indent, content = _parse_yaml_line(raw_line)

        # Skip empty lines, comments
        if not content or content.startswith("#"):
            i += 1
            continue

        # Handle list items
        is_list_item = content.startswith("- ")
        if is_list_item:
            content = content[2:]

        # Handle multiline strings (| and >)
        # We'll just collect the block as a single string
        if content.endswith("|") or content.endswith(">") or content.endswith("|+") or content.endswith(">-"):
            block_indent = indent
            block_lines = []
            i += 1
            while i < len(lines):
                bi, bc = _parse_yaml_line(lines[i])
                if bc and bi <= block_indent:
                    break
                block_lines.append(lines[i])
                i += 1
            # Store the block content under the key
            if ":" in content:
                key = content.split(":", 1)[0].strip()
                block_text = "\n".join(block_lines)
                current[key] = block_text
                result["_lines"][f"{_path_str(path_stack)}.{key}"] = i - len(block_lines)
            continue

        # Key: value pair
        if ":" in content and not is_list_item:
            parts = content.split(":", 1)
            key = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ""

            # Remove inline comments
            if value and " #" in value:
                value = value[:value.index(" #")].strip()

            # Remove quotes
            if value and value[0] in ('"', "'") and value[-1] == value[0]:
                value = value[1:-1]

            # Track line number (1-indexed)
            line_path = f"{_path_str(path_stack)}.{key}"
            result["_lines"][line_path] = i + 1

            # Pop stack to find parent
            while path_stack and path_stack[-1][0] >= indent:
                path_stack.pop()
                if path_stack:
                    current = path_stack[-1][2]
                else:
                    current = result

            if value:
                # Simple key: value
                current[key] = value
            else:
                # Key with sub-object
                new_obj: dict[str, Any] = {}
                current[key] = new_obj
                path_stack.append((indent, key, current))
                current = new_obj

        elif is_list_item:
            # List item
            while path_stack and path_stack[-1][0] >= indent:
                path_stack.pop()
                if path_stack:
                    current = path_stack[-1][2]
                else:
                    current = result

            # Find or create the list in parent
            # The parent key should already exist
            parent_key = None
            if path_stack:
                parent_key = path_stack[-1][1]

            # If content has key: value, it's a dict item in a list
            if ":" in content:
                parts = content.split(":", 1)
                item_key = parts[0].strip()
                item_value = parts[1].strip()
                if item_value and item_value[0] in ('"', "'") and item_value[-1] == item_value[0]:
                    item_value = item_value[1:-1]

                # Create list item dict
                item_dict = {item_key: item_value}
                result["_lines"][f"{_path_str(path_stack)}.{item_key}"] = i + 1

                # Find the list to append to
                if isinstance(current, dict):
                    # Check the last key added - it should be the list
                    for k in reversed(list(current.keys())):
                        if k.startswith("_"):
                            continue
                        if isinstance(current[k], list):
                            current[k].append(item_dict)
                            break
                        elif isinstance(current[k], dict) and not current[k]:
                            current[k] = [item_dict]
                            break
                        else:
                            # Not a list yet, might need to convert
                            break
            else:
                # Simple list item
                if content and content[0] in ('"', "'") and content[-1] == content[0]:
                    content = content[1:-1]

        i += 1

    return result


def _path_str(stack: list[tuple[int, str, Any]]) -> str:
    return ".".join(s[1] for s in stack)


# ── Better parsing: re-parse for practical use ────────────────────────
# The above parser is complex. Let's use a simpler line-scan approach
# that extracts exactly what we need for our rules.

@dataclass
class WorkflowStep:
    """A single step in a job."""
    uses: str = ""
    run: str = ""
    with_params: dict[str, str] = field(default_factory=dict)
    name: str = ""
    line: int = 0
    env: dict[str, str] = field(default_factory=dict)
    timeout_minutes: str = ""


@dataclass
class WorkflowJob:
    """A single job in a workflow."""
    name: str = ""
    key: str = ""
    runs_on: str = ""
    timeout_minutes: str = ""
    container: str = ""
    steps: list[WorkflowStep] = field(default_factory=list)
    strategy: dict[str, Any] = field(default_factory=dict)
    needs: list[str] = field(default_factory=list)
    line: int = 0
    services: dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """Parsed workflow structure."""
    name: str = ""
    triggers: list[str] = field(default_factory=list)
    trigger_details: dict[str, Any] = field(default_factory=dict)
    concurrency: dict[str, str] = field(default_factory=dict)
    jobs: list[WorkflowJob] = field(default_factory=list)
    file: str = ""
    raw_lines: list[str] = field(default_factory=list)


def parse_workflow_practical(text: str, filename: str = "") -> Workflow:
    """Parse a GHA workflow YAML into structured data for analysis.

    Line-based parser focused on extracting what ciaudit needs.
    """
    wf = Workflow(file=filename)
    lines = text.split("\n")
    wf.raw_lines = lines

    # Track state
    in_section = ""  # "on", "jobs", "concurrency"
    current_job: WorkflowJob | None = None
    current_step: WorkflowStep | None = None
    in_with = False
    in_strategy = False
    in_matrix = False
    in_env = False
    in_container = False
    in_services = False
    in_trigger_paths = False
    current_trigger = ""
    job_indent = 0
    step_indent = 0
    with_indent = 0
    strategy_indent = 0
    run_block = False
    run_indent = 0
    run_lines: list[str] = []
    trigger_indent = 0
    trigger_detail_indent = 0

    for i, raw_line in enumerate(lines):
        lineno = i + 1
        indent, content = _parse_yaml_line(raw_line)

        if not content or content.startswith("#"):
            if run_block and indent > run_indent:
                run_lines.append(raw_line)
            continue

        # Close run block if dedented
        if run_block and indent <= run_indent and not raw_line.strip() == "":
            if current_step:
                current_step.run = "\n".join(run_lines).strip()
            run_block = False
            run_lines = []

        # Top-level keys
        if indent == 0:
            # Save previous job
            if current_step and current_job:
                current_job.steps.append(current_step)
                current_step = None
            if current_job:
                wf.jobs.append(current_job)
                current_job = None

            in_with = False
            in_strategy = False
            in_matrix = False
            in_env = False
            in_container = False
            in_services = False
            in_trigger_paths = False

            if content.startswith("name:"):
                wf.name = content.split(":", 1)[1].strip().strip("'\"")
                in_section = ""
            elif content.startswith("on:") or content == "on:":
                in_section = "on"
                # Inline triggers: on: [push, pull_request]
                val = content.split(":", 1)[1].strip()
                if val:
                    if val.startswith("["):
                        triggers = [t.strip().strip("'\"") for t in val.strip("[]").split(",")]
                        wf.triggers = triggers
                    else:
                        wf.triggers = [val.strip("'\"")]
                trigger_indent = 0
            elif content == "true:" and in_section == "on":
                # 'on: true' is actually the boolean true, skip
                # This is 'true:' at indent 0, which is the YAML key 'true'
                # In context of 'on:', 'push:' etc appear at indent 2
                pass
            elif content.startswith("jobs:") or content == "jobs:":
                in_section = "jobs"
            elif content.startswith("concurrency:") or content == "concurrency:":
                in_section = "concurrency"
                val = content.split(":", 1)[1].strip()
                if val:
                    wf.concurrency = {"group": val.strip("'\"")}
            else:
                in_section = ""
            continue

        # ── on: section ─────────────────────────────────────
        if in_section == "on":
            if indent == 2 and content.endswith(":"):
                trigger_name = content[:-1].strip()
                wf.triggers.append(trigger_name)
                current_trigger = trigger_name
                wf.trigger_details[trigger_name] = {}
                trigger_indent = indent
                in_trigger_paths = False
            elif indent == 2 and ":" in content:
                parts = content.split(":", 1)
                trigger_name = parts[0].strip()
                wf.triggers.append(trigger_name)
                current_trigger = trigger_name
                wf.trigger_details[trigger_name] = {}
                trigger_indent = indent
            elif current_trigger and indent > trigger_indent:
                td = wf.trigger_details.get(current_trigger, {})
                if content.startswith("paths:") or content.startswith("paths-ignore:"):
                    key = content.split(":")[0].strip()
                    td[key] = True
                    in_trigger_paths = True
                elif content.startswith("branches:") or content.startswith("branches-ignore:"):
                    key = content.split(":")[0].strip()
                    td[key] = True
                elif content.startswith("types:"):
                    td["types"] = True
                wf.trigger_details[current_trigger] = td
            continue

        # ── concurrency: section ────────────────────────────
        if in_section == "concurrency":
            if "group:" in content:
                wf.concurrency["group"] = content.split(":", 1)[1].strip().strip("'\"")
            elif "cancel-in-progress:" in content:
                wf.concurrency["cancel-in-progress"] = content.split(":", 1)[1].strip()
            continue

        # ── jobs: section ───────────────────────────────────
        if in_section == "jobs":
            # Job-level key (indent 2)
            if indent == 2 and content.endswith(":"):
                # Save previous job
                if current_step and current_job:
                    current_job.steps.append(current_step)
                    current_step = None
                if current_job:
                    wf.jobs.append(current_job)

                job_key = content[:-1].strip()
                current_job = WorkflowJob(key=job_key, line=lineno)
                in_with = False
                in_strategy = False
                in_matrix = False
                in_env = False
                in_container = False
                in_services = False
                continue

            if not current_job:
                continue

            # Job properties (indent 4)
            if indent == 4:
                in_with = False
                in_env = False

                if content.startswith("name:"):
                    current_job.name = content.split(":", 1)[1].strip().strip("'\"")
                elif content.startswith("runs-on:"):
                    current_job.runs_on = content.split(":", 1)[1].strip().strip("'\"")
                elif content.startswith("timeout-minutes:"):
                    current_job.timeout_minutes = content.split(":", 1)[1].strip()
                elif content.startswith("container:"):
                    val = content.split(":", 1)[1].strip()
                    current_job.container = val if val else "true"
                    in_container = True
                elif content.startswith("needs:"):
                    val = content.split(":", 1)[1].strip()
                    if val:
                        if val.startswith("["):
                            current_job.needs = [n.strip().strip("'\"") for n in val.strip("[]").split(",")]
                        else:
                            current_job.needs = [val.strip("'\"")]
                elif content.startswith("services:") or content == "services:":
                    in_services = True
                elif content.startswith("strategy:") or content == "strategy:":
                    in_strategy = True
                    strategy_indent = indent
                elif content.startswith("steps:") or content == "steps:":
                    in_strategy = False
                    in_container = False
                    in_services = False

            # Strategy section
            if in_strategy and indent > 4:
                if "fail-fast:" in content:
                    current_job.strategy["fail-fast"] = content.split(":", 1)[1].strip()
                elif "max-parallel:" in content:
                    current_job.strategy["max-parallel"] = content.split(":", 1)[1].strip()
                elif "matrix:" in content:
                    current_job.strategy["matrix"] = True
                    in_matrix = True
                elif in_matrix:
                    # Count matrix dimensions
                    if content.startswith("- "):
                        current_job.strategy.setdefault("_matrix_items", 0)
                        current_job.strategy["_matrix_items"] = current_job.strategy.get("_matrix_items", 0) + 1
                    elif ":" in content and not content.startswith("-"):
                        key = content.split(":")[0].strip()
                        val = content.split(":", 1)[1].strip()
                        if val.startswith("["):
                            items = [x.strip() for x in val.strip("[]").split(",") if x.strip()]
                            current_job.strategy.setdefault("_matrix_dims", {})
                            current_job.strategy["_matrix_dims"][key] = len(items)
                continue

            # Steps
            if content.startswith("- uses:") or content.startswith("- name:") or content.startswith("- run:"):
                # Save previous step
                if current_step and current_job:
                    current_job.steps.append(current_step)

                current_step = WorkflowStep(line=lineno)
                in_with = False
                in_env = False
                step_indent = indent

                if content.startswith("- uses:"):
                    current_step.uses = content.split(":", 1)[1].strip().strip("'\"")
                elif content.startswith("- name:"):
                    current_step.name = content.split(":", 1)[1].strip().strip("'\"")
                elif content.startswith("- run:"):
                    run_val = content.split(":", 1)[1].strip()
                    if run_val in ("|", ">", "|+", ">-", "|-"):
                        run_block = True
                        run_indent = indent
                        run_lines = []
                    else:
                        current_step.run = run_val.strip("'\"")
                continue

            if current_step and indent > step_indent:
                if content.startswith("uses:"):
                    current_step.uses = content.split(":", 1)[1].strip().strip("'\"")
                elif content.startswith("name:"):
                    current_step.name = content.split(":", 1)[1].strip().strip("'\"")
                elif content.startswith("run:"):
                    run_val = content.split(":", 1)[1].strip()
                    if run_val in ("|", ">", "|+", ">-", "|-"):
                        run_block = True
                        run_indent = indent
                        run_lines = []
                    else:
                        current_step.run = run_val.strip("'\"")
                elif content.startswith("with:"):
                    in_with = True
                    with_indent = indent
                elif content.startswith("env:"):
                    in_env = True
                    with_indent = indent
                elif content.startswith("timeout-minutes:"):
                    current_step.timeout_minutes = content.split(":", 1)[1].strip()
                elif in_with and indent > with_indent:
                    if ":" in content:
                        k, v = content.split(":", 1)
                        current_step.with_params[k.strip()] = v.strip().strip("'\"")
                elif in_env and indent > with_indent:
                    if ":" in content:
                        k, v = content.split(":", 1)
                        current_step.env[k.strip()] = v.strip().strip("'\"")

    # Flush last step/job
    if run_block and current_step:
        current_step.run = "\n".join(run_lines).strip()
    if current_step and current_job:
        current_job.steps.append(current_step)
    if current_job:
        wf.jobs.append(current_job)

    return wf


# ── Analysis Engine ───────────────────────────────────────────────────

def analyze_workflow(wf: Workflow, ignore: set[str] | None = None) -> list[Finding]:
    """Run all checks on a parsed workflow."""
    findings: list[Finding] = []
    ignore = ignore or set()

    for rule_id, checker in CHECKERS.items():
        if rule_id in ignore:
            continue
        findings.extend(checker(wf))

    return findings


# ── Individual Checks ─────────────────────────────────────────────────

CHECKERS: dict[str, Any] = {}


def checker(rule_id: str):
    """Decorator to register a checker function."""
    def decorator(fn):
        CHECKERS[rule_id] = fn
        return fn
    return decorator


@checker("CI001")
def check_checkout_full_clone(wf: Workflow) -> list[Finding]:
    """Detect actions/checkout without fetch-depth."""
    findings = []
    for job in wf.jobs:
        for step in job.steps:
            if _uses_action(step, "actions/checkout"):
                if "fetch-depth" not in step.with_params:
                    findings.append(Finding(
                        rule="CI001",
                        severity=Severity.WARNING,
                        message=f"actions/checkout without fetch-depth fetches entire git history",
                        file=wf.file,
                        line=step.line,
                        job=job.key,
                        step=step.name or step.uses,
                        category="speed",
                        fix="Add 'with: fetch-depth: 1' for shallow clone (or 0 if you need full history)",
                    ))
    return findings


@checker("CI002")
def check_no_dependency_cache(wf: Workflow) -> list[Finding]:
    """Detect package installs without caching."""
    findings = []

    # Package managers to detect and their cache solutions
    pkg_patterns = [
        (r"\bpip install\b", "pip", "Add 'actions/cache' for pip cache dir or use 'actions/setup-python' with 'cache: pip'"),
        (r"\bnpm install\b", "npm", "Use 'npm ci' and 'actions/setup-node' with 'cache: npm'"),
        (r"\bnpm ci\b", "npm", "Add 'actions/setup-node' with 'cache: npm' for automatic caching"),
        (r"\byarn install\b", "yarn", "Add 'actions/setup-node' with 'cache: yarn'"),
        (r"\bpnpm install\b", "pnpm", "Add 'actions/setup-node' with 'cache: pnpm'"),
        (r"\bbundle install\b", "gem", "Add 'actions/cache' for bundler cache or 'ruby/setup-ruby' with 'bundler-cache: true'"),
        (r"\bcargo build\b", "cargo", "Add 'actions/cache' for ~/.cargo and target/ directories"),
        (r"\bgo build\b|\bgo test\b|\bgo install\b", "go", "Add 'actions/setup-go' with 'cache: true'"),
        (r"\bmvn\b.*install|mvn\b.*package|mvn\b.*verify", "maven", "Add 'actions/setup-java' with 'cache: maven'"),
        (r"\bgradle\b", "gradle", "Add 'actions/setup-java' with 'cache: gradle'"),
        (r"\bcomposer install\b", "composer", "Add 'actions/cache' for composer cache directory"),
    ]

    for job in wf.jobs:
        # Check if job has any cache-related steps
        has_cache = _job_has_cache(job)

        for step in job.steps:
            if not step.run:
                continue

            for pattern, pkg, fix in pkg_patterns:
                if re.search(pattern, step.run):
                    # Check if this specific package manager has caching
                    if not has_cache and not _step_has_specific_cache(job, pkg):
                        findings.append(Finding(
                            rule="CI002",
                            severity=Severity.ERROR,
                            message=f"{pkg} install detected without dependency caching",
                            file=wf.file,
                            line=step.line,
                            job=job.key,
                            step=step.name or f"run: {step.run[:50]}",
                            category="speed",
                            fix=fix,
                        ))
                    break  # Only report once per step

    return findings


@checker("CI003")
def check_setup_no_cache(wf: Workflow) -> list[Finding]:
    """Detect actions/setup-* without cache parameter."""
    findings = []

    setup_actions = {
        "actions/setup-node": "cache: 'npm' (or yarn/pnpm)",
        "actions/setup-python": "cache: 'pip' (or pipenv/poetry)",
        "actions/setup-java": "cache: 'maven' (or gradle/sbt)",
        "actions/setup-go": "cache: true",
    }

    for job in wf.jobs:
        for step in job.steps:
            for action, cache_hint in setup_actions.items():
                if _uses_action(step, action):
                    if "cache" not in step.with_params:
                        findings.append(Finding(
                            rule="CI003",
                            severity=Severity.WARNING,
                            message=f"{action} without cache parameter; dependencies re-downloaded every run",
                            file=wf.file,
                            line=step.line,
                            job=job.key,
                            step=step.name or step.uses,
                            category="speed",
                            fix=f"Add 'with: {cache_hint}'",
                        ))

    return findings


@checker("CI004")
def check_docker_no_cache(wf: Workflow) -> list[Finding]:
    """Detect docker build without caching strategy."""
    findings = []

    for job in wf.jobs:
        for step in job.steps:
            if not step.run:
                continue

            if "docker build" in step.run or "docker buildx build" in step.run:
                has_cache = any(flag in step.run for flag in [
                    "--cache-from", "--cache-to",
                    "DOCKER_BUILDKIT", "BUILDKIT_INLINE_CACHE",
                    "--mount=type=cache",
                ])
                # Also check if docker/build-push-action is used (it handles caching)
                if not has_cache:
                    findings.append(Finding(
                        rule="CI004",
                        severity=Severity.WARNING,
                        message="Docker build without layer caching; rebuilds all layers every run",
                        file=wf.file,
                        line=step.line,
                        job=job.key,
                        step=step.name or f"run: docker build ...",
                        category="speed",
                        fix="Use 'docker buildx build --cache-from type=gha --cache-to type=gha' or 'docker/build-push-action' with cache config",
                    ))

            # Also check docker/build-push-action without cache
            if _uses_action(step, "docker/build-push-action"):
                has_cache = "cache-from" in step.with_params or "cache-to" in step.with_params
                if not has_cache:
                    findings.append(Finding(
                        rule="CI004",
                        severity=Severity.WARNING,
                        message="docker/build-push-action without cache-from/cache-to",
                        file=wf.file,
                        line=step.line,
                        job=job.key,
                        step=step.name or step.uses,
                        category="speed",
                        fix="Add 'cache-from: type=gha' and 'cache-to: type=gha,mode=max'",
                    ))

    return findings


@checker("CI005")
def check_no_fail_fast(wf: Workflow) -> list[Finding]:
    """Detect matrix strategy without fail-fast."""
    findings = []

    for job in wf.jobs:
        if "matrix" in job.strategy:
            ff = job.strategy.get("fail-fast", "")
            if ff == "false":
                # Explicitly disabled — that's a choice, but worth noting
                findings.append(Finding(
                    rule="CI005",
                    severity=Severity.INFO,
                    message="Matrix fail-fast explicitly disabled; all combinations run even after a failure",
                    file=wf.file,
                    line=job.line,
                    job=job.key,
                    category="speed",
                    fix="Consider 'fail-fast: true' to stop on first failure and save CI minutes",
                ))

    return findings


@checker("CI006")
def check_no_timeout(wf: Workflow) -> list[Finding]:
    """Detect jobs without timeout-minutes."""
    findings = []

    for job in wf.jobs:
        if not job.timeout_minutes:
            findings.append(Finding(
                rule="CI006",
                severity=Severity.ERROR,
                message=f"Job '{job.key}' has no timeout-minutes; can run (and bill) indefinitely",
                file=wf.file,
                line=job.line,
                job=job.key,
                category="cost",
                fix="Add 'timeout-minutes: 30' (or appropriate value) to prevent runaway jobs",
            ))

    return findings


@checker("CI007")
def check_no_concurrency(wf: Workflow) -> list[Finding]:
    """Detect workflows without concurrency control."""
    findings = []

    # Only relevant for push/PR triggers
    has_ci_trigger = any(t in wf.triggers for t in ["push", "pull_request", "pull_request_target"])

    if has_ci_trigger and not wf.concurrency:
        findings.append(Finding(
            rule="CI007",
            severity=Severity.WARNING,
            message="Workflow has push/PR triggers but no concurrency group; duplicate runs waste minutes",
            file=wf.file,
            line=1,
            category="cost",
            fix="Add 'concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }'",
        ))

    return findings


@checker("CI008")
def check_no_path_filter(wf: Workflow) -> list[Finding]:
    """Detect push/PR triggers without paths filter."""
    findings = []

    for trigger in ["push", "pull_request"]:
        if trigger in wf.triggers:
            details = wf.trigger_details.get(trigger, {})
            has_paths = details.get("paths") or details.get("paths-ignore")
            if not has_paths and not details.get("branches") and not details.get("branches-ignore"):
                # No path or branch filter at all
                findings.append(Finding(
                    rule="CI008",
                    severity=Severity.WARNING,
                    message=f"'{trigger}' trigger has no paths or branches filter; workflow runs on ALL changes",
                    file=wf.file,
                    line=1,
                    category="cost",
                    fix=f"Add 'paths:' to limit when workflow runs (e.g., paths: ['src/**', '*.py'])",
                ))
            elif not has_paths:
                # Has branch filter but no path filter
                findings.append(Finding(
                    rule="CI008",
                    severity=Severity.INFO,
                    message=f"'{trigger}' trigger has branch filter but no paths filter; runs on doc changes too",
                    file=wf.file,
                    line=1,
                    category="cost",
                    fix=f"Add 'paths-ignore: [\"docs/**\", \"*.md\", \"LICENSE\"]' to skip irrelevant changes",
                ))

    return findings


@checker("CI009")
def check_large_matrix(wf: Workflow) -> list[Finding]:
    """Detect large matrix combinations without max-parallel."""
    findings = []

    for job in wf.jobs:
        if "matrix" in job.strategy and "_matrix_dims" in job.strategy:
            dims = job.strategy["_matrix_dims"]
            total = 1
            for dim_size in dims.values():
                total *= dim_size

            if total >= 10 and "max-parallel" not in job.strategy:
                findings.append(Finding(
                    rule="CI009",
                    severity=Severity.WARNING,
                    message=f"Matrix generates ~{total} combinations without max-parallel; may exhaust runner pool",
                    file=wf.file,
                    line=job.line,
                    job=job.key,
                    category="cost",
                    fix=f"Add 'max-parallel: 4' (or appropriate value) to limit concurrent runners",
                ))

    return findings


@checker("CI010")
def check_npm_install_not_ci(wf: Workflow) -> list[Finding]:
    """Detect npm install instead of npm ci in CI."""
    findings = []

    for job in wf.jobs:
        for step in job.steps:
            if not step.run:
                continue

            # Match 'npm install' but not 'npm install -g' (global installs are fine)
            if re.search(r"\bnpm install\b(?!\s+-g)", step.run):
                findings.append(Finding(
                    rule="CI010",
                    severity=Severity.WARNING,
                    message="'npm install' in CI; use 'npm ci' for faster, deterministic installs",
                    file=wf.file,
                    line=step.line,
                    job=job.key,
                    step=step.name or f"run: npm install",
                    category="practice",
                    fix="Replace 'npm install' with 'npm ci' (uses package-lock.json, skips node_modules if clean)",
                ))

    return findings


@checker("CI011")
def check_redundant_checkout(wf: Workflow) -> list[Finding]:
    """Detect multiple checkout steps in the same job."""
    findings = []

    for job in wf.jobs:
        checkouts = [s for s in job.steps if _uses_action(s, "actions/checkout")]
        if len(checkouts) > 1:
            # Check if they checkout different repos/refs (that's legitimate)
            refs = set()
            repos = set()
            for co in checkouts:
                refs.add(co.with_params.get("ref", ""))
                repos.add(co.with_params.get("repository", ""))

            if len(repos) <= 1 and len(refs) <= 1:
                findings.append(Finding(
                    rule="CI011",
                    severity=Severity.INFO,
                    message=f"Job '{job.key}' has {len(checkouts)} checkout steps for the same repo/ref",
                    file=wf.file,
                    line=checkouts[1].line,
                    job=job.key,
                    category="practice",
                    fix="Remove duplicate checkout; code persists across steps in the same job",
                ))

    return findings


@checker("CI012")
def check_apt_every_run(wf: Workflow) -> list[Finding]:
    """Detect apt-get install that runs every time without caching."""
    findings = []

    for job in wf.jobs:
        for step in job.steps:
            if not step.run:
                continue

            if re.search(r"\bapt-get\s+install\b|\bapt\s+install\b", step.run):
                # Check if there's any caching for apt
                has_apt_cache = any(
                    "apt" in s.with_params.get("path", "").lower() or
                    "apt" in s.with_params.get("key", "").lower()
                    for s in job.steps if _uses_action(s, "actions/cache")
                )
                # Also check for awalber/cache-apt-pkgs or similar
                has_apt_action = any(
                    "cache-apt" in s.uses.lower() or "apt-cache" in s.uses.lower()
                    for s in job.steps if s.uses
                )

                if not has_apt_cache and not has_apt_action:
                    findings.append(Finding(
                        rule="CI012",
                        severity=Severity.INFO,
                        message="apt-get install runs every workflow; consider caching or a custom container image",
                        file=wf.file,
                        line=step.line,
                        job=job.key,
                        step=step.name or f"run: apt-get install ...",
                        category="practice",
                        fix="Use 'awalber/cache-apt-pkgs-action' or a container image with packages preinstalled",
                    ))

    return findings


@checker("CI013")
def check_pip_no_cache_dir(wf: Workflow) -> list[Finding]:
    """Detect pip install in container/Docker context without --no-cache-dir."""
    findings = []

    for job in wf.jobs:
        if not job.container:
            continue

        for step in job.steps:
            if not step.run:
                continue

            if re.search(r"\bpip install\b", step.run) and "--no-cache-dir" not in step.run:
                findings.append(Finding(
                    rule="CI013",
                    severity=Severity.INFO,
                    message="pip install in container job without --no-cache-dir; pip cache wastes container space",
                    file=wf.file,
                    line=step.line,
                    job=job.key,
                    step=step.name or f"run: pip install ...",
                    category="practice",
                    fix="Add '--no-cache-dir' to pip install when running in a container",
                ))

    return findings


@checker("CI014")
def check_no_cancel_in_progress(wf: Workflow) -> list[Finding]:
    """Detect concurrency group without cancel-in-progress."""
    findings = []

    if wf.concurrency and wf.concurrency.get("group"):
        cip = wf.concurrency.get("cancel-in-progress", "")
        if cip != "true":
            findings.append(Finding(
                rule="CI014",
                severity=Severity.WARNING,
                message="Concurrency group defined but cancel-in-progress not enabled; stale runs queue instead of cancelling",
                file=wf.file,
                line=1,
                category="cost",
                fix="Add 'cancel-in-progress: true' to cancel superseded runs",
            ))

    return findings


@checker("CI015")
def check_checkout_in_container(wf: Workflow) -> list[Finding]:
    """Detect full checkout inside container jobs."""
    findings = []

    for job in wf.jobs:
        if not job.container:
            continue

        for step in job.steps:
            if _uses_action(step, "actions/checkout"):
                if "fetch-depth" not in step.with_params:
                    findings.append(Finding(
                        rule="CI015",
                        severity=Severity.INFO,
                        message="Full git clone inside container job; network overhead is higher in containers",
                        file=wf.file,
                        line=step.line,
                        job=job.key,
                        step=step.name or step.uses,
                        category="practice",
                        fix="Add 'fetch-depth: 1' — especially important in container jobs where git isn't cached",
                    ))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────

def _uses_action(step: WorkflowStep, action_prefix: str) -> bool:
    """Check if a step uses a specific action (ignoring version tag)."""
    return step.uses.split("@")[0] == action_prefix


def _job_has_cache(job: WorkflowJob) -> bool:
    """Check if a job has any cache-related steps."""
    for step in job.steps:
        if _uses_action(step, "actions/cache"):
            return True
        if step.uses and "cache" in step.uses.lower():
            return True
        # setup-* actions with cache param
        if step.uses.startswith("actions/setup-") and "cache" in step.with_params:
            return True
    return False


def _step_has_specific_cache(job: WorkflowJob, pkg: str) -> bool:
    """Check if a job has caching for a specific package manager."""
    pkg_cache_map = {
        "pip": ["pip", "python", "pip-"],
        "npm": ["npm", "node", "node_modules"],
        "yarn": ["yarn", "node"],
        "pnpm": ["pnpm", "node"],
        "gem": ["gem", "ruby", "bundler"],
        "cargo": ["cargo", "rust", "target"],
        "go": ["go", "go-build"],
        "maven": ["maven", ".m2"],
        "gradle": ["gradle", ".gradle"],
        "composer": ["composer", "vendor"],
    }

    keywords = pkg_cache_map.get(pkg, [pkg])

    for step in job.steps:
        # Check actions/cache path/key
        if _uses_action(step, "actions/cache"):
            path = step.with_params.get("path", "").lower()
            key = step.with_params.get("key", "").lower()
            for kw in keywords:
                if kw in path or kw in key:
                    return True

        # Check setup-* actions with cache param
        if "cache" in step.with_params:
            cache_val = step.with_params["cache"].lower()
            for kw in keywords:
                if kw in cache_val or kw in step.uses.lower():
                    return True

    return False


# ── Grading ───────────────────────────────────────────────────────────

def calculate_grade(findings: list[Finding]) -> tuple[str, int]:
    """Calculate grade from findings."""
    score = 100

    for f in findings:
        if f.severity == Severity.ERROR:
            score -= 15
        elif f.severity == Severity.WARNING:
            score -= 8
        elif f.severity == Severity.INFO:
            score -= 3

    score = max(0, score)

    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return grade, score


# ── Output Formatting ─────────────────────────────────────────────────

SEVERITY_SYMBOLS = {
    Severity.ERROR: "❌",
    Severity.WARNING: "⚠️ ",
    Severity.INFO: "ℹ️ ",
}

SEVERITY_COLORS = {
    Severity.ERROR: "\033[91m",  # Red
    Severity.WARNING: "\033[93m",  # Yellow
    Severity.INFO: "\033[94m",  # Blue
}

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

GRADE_COLORS = {
    "A+": "\033[92m",
    "A": "\033[92m",
    "B": "\033[93m",
    "C": "\033[93m",
    "D": "\033[91m",
    "F": "\033[91m",
}


def _supports_color() -> bool:
    """Check if terminal supports color."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def format_text(findings: list[Finding], grade: str, score: int,
                filename: str, verbose: bool = False, color: bool = True) -> str:
    """Format findings as human-readable text."""
    lines = []
    c = color

    if c:
        gc = GRADE_COLORS.get(grade, "")
        lines.append(f"{BOLD}ciaudit v{__version__}{RESET} — CI/CD Efficiency Auditor")
        lines.append("")
        lines.append(f"File: {filename}")
        lines.append(f"Grade: {gc}{BOLD}{grade}{RESET} ({score}/100)")
    else:
        lines.append(f"ciaudit v{__version__} — CI/CD Efficiency Auditor")
        lines.append("")
        lines.append(f"File: {filename}")
        lines.append(f"Grade: {grade} ({score}/100)")

    lines.append("")

    if not findings:
        lines.append("✅ No issues found — your CI pipeline looks efficient!")
        return "\n".join(lines)

    # Group by category
    categories = {"speed": "⚡ Speed", "cost": "💰 Cost", "practice": "📋 Best Practices"}
    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    for cat_key, cat_label in categories.items():
        cat_findings = by_category.get(cat_key, [])
        if not cat_findings:
            continue

        if c:
            lines.append(f"{BOLD}{cat_label}{RESET}")
        else:
            lines.append(cat_label)

        for f in cat_findings:
            sym = SEVERITY_SYMBOLS.get(f.severity, "?")
            sc = SEVERITY_COLORS.get(f.severity, "") if c else ""
            rc = RESET if c else ""
            loc = f"L{f.line}" if f.line else ""
            job_info = f" [{f.job}]" if f.job else ""

            lines.append(f"  {sym} {sc}{f.rule}{rc}: {f.message}")
            if loc or job_info:
                dim = DIM if c else ""
                lines.append(f"    {dim}{loc}{job_info}{rc}")

            if verbose and f.fix:
                lines.append(f"    → {f.fix}")

        lines.append("")

    # Summary
    errors = sum(1 for f in findings if f.severity == Severity.ERROR)
    warnings = sum(1 for f in findings if f.severity == Severity.WARNING)
    infos = sum(1 for f in findings if f.severity == Severity.INFO)
    lines.append(f"Summary: {errors} errors, {warnings} warnings, {infos} info")

    # Estimated savings hint
    if errors + warnings > 0:
        lines.append("")
        if c:
            lines.append(f"{DIM}Fix errors and warnings to improve CI speed and reduce costs.{RESET}")
        else:
            lines.append("Fix errors and warnings to improve CI speed and reduce costs.")

    return "\n".join(lines)


def format_json(findings: list[Finding], grade: str, score: int,
                filename: str) -> str:
    """Format findings as JSON."""
    result = {
        "version": __version__,
        "file": filename,
        "grade": grade,
        "score": score,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "errors": sum(1 for f in findings if f.severity == Severity.ERROR),
            "warnings": sum(1 for f in findings if f.severity == Severity.WARNING),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
            "total": len(findings),
        },
    }
    return json.dumps(result, indent=2)


# ── File Discovery ────────────────────────────────────────────────────

def find_workflows(path: str = ".") -> list[str]:
    """Find GitHub Actions workflow files."""
    workflows = []

    # Check standard location
    gh_dir = os.path.join(path, ".github", "workflows")
    if os.path.isdir(gh_dir):
        for f in sorted(os.listdir(gh_dir)):
            if f.endswith((".yml", ".yaml")):
                workflows.append(os.path.join(gh_dir, f))

    return workflows


# ── CLI ───────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ciaudit",
        description="CI/CD Pipeline Efficiency & Cost Auditor — find waste in your GitHub Actions workflows",
        epilog="Examples:\n"
               "  ciaudit .github/workflows/ci.yml          # Audit a specific workflow\n"
               "  ciaudit .github/workflows/                 # Audit all workflows in directory\n"
               "  ciaudit                                    # Auto-detect .github/workflows/\n"
               "  ciaudit ci.yml --verbose                   # Show fix suggestions\n"
               "  ciaudit ci.yml --json                      # JSON output for automation\n"
               "  ciaudit ci.yml --check B                   # CI mode: exit 1 if grade below B\n"
               "  ciaudit --list-rules                       # Show all rules\n"
               "  cat ci.yml | ciaudit -                     # Read from stdin\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("files", nargs="*", default=[],
                        help="Workflow files or directories to audit (default: auto-detect)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show fix suggestions for each finding")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--check", metavar="GRADE", nargs="?", const="B",
                        help="CI mode: exit 1 if grade is below GRADE (default: B)")
    parser.add_argument("--ignore", metavar="RULES",
                        help="Comma-separated rule IDs to ignore (e.g., CI001,CI006)")
    parser.add_argument("--severity", metavar="LEVEL",
                        choices=["error", "warning", "info"],
                        help="Only show findings at this severity or above")
    parser.add_argument("--list-rules", action="store_true",
                        help="List all rules and exit")
    parser.add_argument("--version", action="version",
                        version=f"ciaudit {__version__}")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # List rules
    if args.list_rules:
        print(f"ciaudit v{__version__} — {len(RULES)} rules\n")
        categories = {"speed": "⚡ Speed", "cost": "💰 Cost", "practice": "📋 Best Practices"}
        by_cat: dict[str, list[Rule]] = {}
        for r in RULES.values():
            by_cat.setdefault(r.category, []).append(r)

        for cat_key, cat_label in categories.items():
            rules_in_cat = by_cat.get(cat_key, [])
            if not rules_in_cat:
                continue
            print(f"{cat_label}")
            for r in rules_in_cat:
                sev = r.severity.value.upper()
                print(f"  {r.id} [{sev:7s}] {r.name}: {r.description}")
            print()
        return 0

    # Parse ignore list
    ignore = set()
    if args.ignore:
        ignore = {r.strip().upper() for r in args.ignore.split(",")}

    # Severity filter
    severity_filter = None
    if args.severity:
        severity_map = {"error": 0, "warning": 1, "info": 2}
        severity_filter = severity_map[args.severity]

    # Find files
    files: list[str] = []
    if args.files:
        for f in args.files:
            if f == "-":
                files.append("-")
            elif os.path.isdir(f):
                for entry in sorted(os.listdir(f)):
                    if entry.endswith((".yml", ".yaml")):
                        files.append(os.path.join(f, entry))
            elif os.path.isfile(f):
                files.append(f)
            else:
                print(f"Error: {f} not found", file=sys.stderr)
                return 1
    else:
        # Auto-detect
        files = find_workflows(".")
        if not files:
            print("No workflow files found. Specify files or run from a repo root.", file=sys.stderr)
            print("Usage: ciaudit .github/workflows/ci.yml", file=sys.stderr)
            return 1

    # Process files
    all_findings: list[Finding] = []
    all_results: list[dict] = []
    worst_grade = "A+"
    worst_score = 100
    color = _supports_color() and not args.json_output

    grade_order = ["A+", "A", "B", "C", "D", "F"]

    for filepath in files:
        if filepath == "-":
            text = sys.stdin.read()
            filename = "<stdin>"
        else:
            try:
                with open(filepath, "r") as fh:
                    text = fh.read()
                filename = filepath
            except (OSError, IOError) as e:
                print(f"Error reading {filepath}: {e}", file=sys.stderr)
                continue

        wf = parse_workflow_practical(text, filename)
        findings = analyze_workflow(wf, ignore)

        # Apply severity filter
        if severity_filter is not None:
            severity_levels = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}
            findings = [f for f in findings if severity_levels[f.severity] <= severity_filter]

        grade, score = calculate_grade(findings)
        all_findings.extend(findings)

        if grade_order.index(grade) > grade_order.index(worst_grade):
            worst_grade = grade
            worst_score = score

        if args.json_output:
            result = json.loads(format_json(findings, grade, score, filename))
            all_results.append(result)
        else:
            if len(files) > 1:
                print(f"{'─' * 60}")
            print(format_text(findings, grade, score, filename, args.verbose, color))
            if len(files) > 1:
                print()

    # JSON output
    if args.json_output:
        if len(all_results) == 1:
            print(json.dumps(all_results[0], indent=2))
        else:
            print(json.dumps({
                "version": __version__,
                "files": all_results,
                "overall_grade": worst_grade,
                "overall_score": worst_score,
            }, indent=2))

    # Multi-file summary
    if len(files) > 1 and not args.json_output:
        print(f"{'─' * 60}")
        errors = sum(1 for f in all_findings if f.severity == Severity.ERROR)
        warnings = sum(1 for f in all_findings if f.severity == Severity.WARNING)
        infos = sum(1 for f in all_findings if f.severity == Severity.INFO)
        gc = GRADE_COLORS.get(worst_grade, "") if color else ""
        rc = RESET if color else ""
        bold = BOLD if color else ""
        print(f"Overall: {gc}{bold}{worst_grade}{rc} ({worst_score}/100) across {len(files)} files")
        print(f"Total: {errors} errors, {warnings} warnings, {infos} info")

    # CI check mode
    if args.check:
        threshold = args.check.upper()
        if threshold not in grade_order:
            print(f"Invalid grade threshold: {threshold}", file=sys.stderr)
            return 1

        if grade_order.index(worst_grade) > grade_order.index(threshold):
            if not args.json_output:
                print(f"\n❌ CI check failed: grade {worst_grade} is below threshold {threshold}")
            return 1
        else:
            if not args.json_output:
                print(f"\n✅ CI check passed: grade {worst_grade} meets threshold {threshold}")
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
