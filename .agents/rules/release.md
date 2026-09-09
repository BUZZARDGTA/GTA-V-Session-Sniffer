---
trigger: model_decision
description: Use when working on packaging, PyInstaller, release builds, runtime resources, executable generation, dependency releases, CI/release configuration, or release validation.
---

# Release and Build Rules

Apply these rules when working on packaging, PyInstaller, release builds, runtime resources, executable generation, dependency releases, or CI/release configuration.

## Python and Dependencies

* The project requires Python 3.14.
* Keep dependency versions consistent with the existing `pyproject.toml` configuration.
* New normal dependencies must be pinned exactly, matching the project's existing style.
* Security libraries may use `>=` when appropriate.
* Do not change dependency versions without understanding their impact on the supported Python version and existing tooling.

## PyInstaller

The release workflow builds a one-file executable using:

`.github/workflows/Session_Sniffer.spec`

When adding or moving runtime resources:

* ensure the resource exists in the repository,
* update the PyInstaller `datas` configuration when required,
* preserve the correct runtime-relative paths.

Do not assume that a file present in the source repository will automatically be included in the packaged executable.

## Release Validation

When release-sensitive files are changed:

* run the relevant quality checks,
* verify application startup when appropriate,
* verify affected runtime resources,
* dry-run the PyInstaller build locally when available and relevant.

Do not claim that a release build or PyInstaller build succeeded unless it was actually executed.

## CI and Workflows

Do not modify release or CI workflows merely to accommodate unrelated code changes.

When changing workflow behavior, inspect the existing workflow and understand its dependencies, build sequence, artifacts, and release assumptions before editing it.

## Scope

Keep release changes focused.

Do not combine packaging changes with unrelated refactoring, formatting, dependency upgrades, or repository cleanup unless explicitly requested.
