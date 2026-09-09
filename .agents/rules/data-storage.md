---
trigger: model_decision
description: Use when working on settings, configuration, persistence, AppData paths, logs, databases, user scripts, stored user data, or settings documentation.
---

# Data and Settings Rules

Apply these rules when working on settings, configuration, persistence,
AppData paths, logs, databases, user scripts, or other stored user data.

## Storage Location

Session Sniffer stores user read/write data under the user's AppData.

Do not write user data into the repository, current working directory, or
application/install directory.

Use the existing path constants from:

`src/session_sniffer/constants/local.py`

Follow the existing AppData scope selection:

* Local AppData is for machine-specific and/or potentially large data such
  as logs, databases, and caches.
* Roaming AppData is for user-owned and potentially syncable data such as
  configuration and user-managed content.

Do not create ad-hoc paths when an existing project constant or storage
location already exists.

## Settings

Use the existing `Settings` architecture.

Settings are loaded through `Settings.load_from_settings_file`.

After changing persistent in-memory settings, call
`Settings.reconstruct_settings()` once after the complete batch of changes.

Do not repeatedly reconstruct settings for individual changes when several
changes can be persisted together.

Follow existing setting names, structures, defaults, and persistence patterns.

Feature toggles and other persisted settings must continue to use the
established persistence flow. Do not rely only on transient in-memory state
when the feature is expected to survive application restarts.

## No Backward Compatibility

This project never maintains backward compatibility for settings or stored
data.

When a setting is renamed or replaced:

* remove the old setting,
* update every call site,
* use only the new setting,
* do not add migration code,
* do not add aliases,
* do not add fallback lookups,
* do not add transitional validators.

If stale keys exist in `Settings.ini`, they are intentionally treated as
unknown and discarded by the existing rewrite logic.

## Settings Documentation

When adding, removing, or changing a default setting, synchronize the
project's Wiki documentation.

The relevant Wiki repository is:

`d:\Git\Session-Sniffer.wiki`

Check the appropriate configuration documentation, particularly
`Configuration-Guide.md`, and update setting defaults or setting lists when
required.

Do not consider a settings change complete until the relevant documentation
has been checked.

## Logging

* Configure application logging through
  `session_sniffer.logging_setup.setup_logging` once during startup.
* Obtain module loggers with `get_logger(__name__)`.
* Preserve the existing log file behavior:

  * `warnings.log`: WARNING and above.
  * `errors.log`: ERROR and above.
* Do not create a separate logging configuration for individual features.

Application logs belong under the appropriate Local AppData location rather
than the repository or working directory.

## User Data and Privacy

Treat stored IP addresses, packet information, session information, logs, and
databases as potentially sensitive.

Do not unnecessarily:

* persist captured network information,
* expand logging of sensitive data,
* transmit stored user data externally,
* add telemetry,
* expose user data through diagnostics.

When adding persistence, explicitly understand what is stored, where it is
stored, and why it is required.

## Logging Data

Follow the existing logging locations and architecture.

Do not create a second logging or persistence mechanism for functionality
already handled by the project.
