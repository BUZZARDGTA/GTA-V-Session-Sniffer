---
trigger: model_decision
description: Use when adding, modifying, debugging, reviewing, or validating code, including tests, linting, type checking, quality checks, builds, or release-sensitive validation.
---

# Testing and Quality Rules

Apply these rules when adding, modifying, debugging, reviewing, or validating code.

## Validation Strategy

Use the smallest relevant validation first.

Depending on the change, this may include:

* targeted tests,
* static analysis,
* linting,
* type checking,
* application startup,
* relevant integration checks,
* broader project quality checks.

Do not run unrelated expensive validation when it provides no useful signal.

For non-trivial changes, broaden validation when appropriate.

## Existing Tooling

Follow the project's existing tooling and configuration in `pyproject.toml`.

The project uses strict static-analysis and linting configurations including Ruff, MyPy, Pyrefly, Pyright, Flake8, Pylint, and Vulture.

Do not introduce competing validation tools.

Preserve existing intentional suppression lists and disabled diagnostics unless the task explicitly requires changing them.

## Tests

When behavior changes, consider:

* normal behavior,
* edge cases,
* error handling,
* relevant concurrency behavior,
* backward-incompatible replacements,
* interaction with existing callers.

Prefer focused tests that directly validate the changed behavior.

Do not add tests that merely duplicate implementation details without providing meaningful behavioral coverage.

## Existing Behavior

When fixing a bug, verify the actual failure path before changing code.

Do not weaken assertions, type checking, linting, or tests simply to make a change pass.

Fix the underlying problem whenever practical.

## Verification Claims

Only report checks that were actually performed.

If a check could not be run, state that clearly rather than implying it passed.

Do not claim that the application was launched, tests passed, or a build succeeded unless the corresponding operation was actually performed.

## Dependency Changes

If dependencies or `pyproject.toml` are changed, follow the project's dependency workflow and run the appropriate dependency installation and validation steps.

## Release-Sensitive Changes

If resources or PyInstaller configuration are changed, validate the relevant specification and resource inclusion.

The release build uses the project's one-file PyInstaller configuration, so runtime resources must remain correctly represented in the spec.

## Quality

Keep diffs focused.

Do not reformat unrelated code or modify unrelated configuration simply because a quality tool reports existing issues outside the scope of the change.