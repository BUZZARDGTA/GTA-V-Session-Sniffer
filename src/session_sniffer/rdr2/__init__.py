"""RDR2-specific process detection and suspension control.

Groups modules dedicated to the Red Dead Redemption 2 process:

- `process`: detect the running RDR2 executable and snapshot its state (`RDR2Status`,
    `find_running_rdr2_path`).
- `suspend_manager`: reason-based suspend/resume of that process (`RDR2SuspendManager`).

Import symbols directly from their submodules
(e.g. `from session_sniffer.rdr2.process import RDR2Status`). This keeps `process` a
dependency-light leaf and avoids pulling the suspend manager's heavier
imports into call sites that only need detection.
"""
