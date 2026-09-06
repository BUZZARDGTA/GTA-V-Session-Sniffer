"""John Carpenter's Toxic Commando process detection and immutable state snapshot.

Detects the currently running John Carpenter's Toxic Commando process, verifies its
Authenticode signature to reject impostor executables that merely reuse the process name,
and exposes the result as an immutable `ToxicCommandoStatus` snapshot.
"""

from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import psutil

from session_sniffer.capture.process import get_process_udp_ports
from session_sniffer.ctypes_wintrust import has_valid_authenticode_signature
from session_sniffer.logging_setup import get_logger

logger = get_logger(__name__)

_TOXIC_COMMANDO_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        "john carpenter's toxic commando.exe",
        "john carpenter's toxic commando demo.exe",
        'toxiccommando.exe',
        'toxiccommando-win64-shipping.exe',
    },
)


@dataclass(frozen=True, slots=True)
class ToxicCommandoStatus:
    """Immutable snapshot of the running John Carpenter's Toxic Commando process state.

    Attributes:
        path: Resolved path to the running executable, or `None` if not running.
        pid: PID of the running process, or `None` if not running.
        is_suspended: `True` if the running process is currently suspended at the OS level.
        udp_ports: Set of local UDP socket ports currently bound by the process.
        is_running: `True` if a Toxic Commando process was detected.
    """

    path: Path | None
    pid: int | None = None
    is_suspended: bool = False
    udp_ports: frozenset[int] = frozenset()
    is_running: bool = field(init=False)

    def __post_init__(self) -> None:
        """Derive `is_running` from `path`."""
        object.__setattr__(self, 'is_running', self.path is not None)


def find_running_toxic_commando_path(
    cached_process: psutil.Process | None = None,
    cached_status: ToxicCommandoStatus | None = None,
) -> tuple[ToxicCommandoStatus, psutil.Process | None]:
    """Return a `ToxicCommandoStatus` snapshot for the currently running process plus its process handle.

    Scans running processes for Toxic Commando executables using a case-insensitive
    filename match, then verifies the binary carries a valid Authenticode signature.

    The fast path re-queries only the single cached PID when `cached_process`/`cached_status`
    describe an already validated process.

    Args:
        cached_process: The `psutil.Process` returned by the previous call, re-queried
            directly to avoid a full scan. Pass `None` to force a full scan.
        cached_status: The `ToxicCommandoStatus` returned by the previous call.

    Returns:
        A `(ToxicCommandoStatus, psutil.Process | None)` tuple.
    """
    # Fast path: re-query only the previously validated PID.
    if cached_process is not None and cached_status is not None and cached_status.path is not None:
        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            if cached_process.is_running():
                return (
                    ToxicCommandoStatus(
                        path=cached_status.path,
                        pid=cached_process.pid,
                        is_suspended=cached_process.status() == psutil.STATUS_STOPPED,
                        udp_ports=get_process_udp_ports(cached_process.pid),
                    ),
                    cached_process,
                )

    # Slow path: cheap scan by process name only.
    for process in psutil.process_iter(['name']):
        process_name = cast('str | None', process.info.get('name'))

        if not process_name or process_name.lower() not in _TOXIC_COMMANDO_PROCESS_NAMES:
            continue

        try:
            process_path = Path(process.exe())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if not has_valid_authenticode_signature(process_path):
            logger.debug('[ToxicCommandoMonitor] Authenticode signature invalid, ignoring impostor: "%s" (PID: %s)', process_path, process.pid)
            continue

        resolved_path = process_path.resolve()

        logger.debug('[ToxicCommandoMonitor] Authenticode signature verified: "%s" (PID: %s)', resolved_path, process.pid)

        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            return (
                ToxicCommandoStatus(
                    path=resolved_path,
                    pid=process.pid,
                    is_suspended=process.status() == psutil.STATUS_STOPPED,
                    udp_ports=get_process_udp_ports(process.pid),
                ),
                process,
            )

    return (
        ToxicCommandoStatus(path=None),
        None,
    )
