"""Target process inspection and UDP port resolution via Win32 IP Helper and Windows APIs."""

import ctypes
import socket
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from session_sniffer.logging_setup import get_logger
from session_sniffer.utils import ProcessEntry32W

logger = get_logger(__name__)

_PROCESS_TERMINATE = 0x0001
_PROCESS_SUSPEND_RESUME = 0x0800
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259
_TH32CS_SNAPPROCESS = 0x00000002
_SYSTEM_PROCESS_INFORMATION_CLASS = 5
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_THREAD_STATE_WAITING = 5
_WAIT_REASON_SUSPENDED = 5
_WINDOWS_EPOCH_DELTA_100NS = 116444736000000000
_BYTES_PER_MB = 1024**2
_CREATION_TIME_TOLERANCE_SECONDS = 0.05
_ERROR_ACCESS_DENIED = 5

_kernel32 = ctypes.windll.kernel32
_ntdll = ctypes.windll.ntdll
_psapi = ctypes.windll.psapi
_iphlpapi = ctypes.windll.iphlpapi


class _MibUdpRowOwnerPid(ctypes.Structure):
    """ctypes definition for MIB_UDPROW_OWNER_PID structure."""

    _fields_ = [
        ('dwLocalAddr', wintypes.DWORD),
        ('dwLocalPort', wintypes.DWORD),
        ('dwOwningPid', wintypes.DWORD),
    ]


class _IOCounters(ctypes.Structure):
    """ctypes definition for IO_COUNTERS structure."""

    _fields_ = [
        ('ReadOperationCount', ctypes.c_uint64),
        ('WriteOperationCount', ctypes.c_uint64),
        ('OtherOperationCount', ctypes.c_uint64),
        ('ReadTransferCount', ctypes.c_uint64),
        ('WriteTransferCount', ctypes.c_uint64),
        ('OtherTransferCount', ctypes.c_uint64),
    ]


class _ProcessMemoryCounters(ctypes.Structure):
    """ctypes definition for PROCESS_MEMORY_COUNTERS structure."""

    _fields_ = [
        ('cb', wintypes.DWORD),
        ('PageFaultCount', wintypes.DWORD),
        ('PeakWorkingSetSize', ctypes.c_size_t),
        ('WorkingSetSize', ctypes.c_size_t),
        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPagedPoolUsage', ctypes.c_size_t),
        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
        ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
        ('PagefileUsage', ctypes.c_size_t),
        ('PeakPagefileUsage', ctypes.c_size_t),
    ]

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.cb = ctypes.sizeof(self)


_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_kernel32.OpenProcess.restype = wintypes.HANDLE

_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL

_kernel32.GetCurrentProcess.argtypes = []
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE

_kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_kernel32.GetExitCodeProcess.restype = wintypes.BOOL

_kernel32.GetProcessTimes.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME),
]
_kernel32.GetProcessTimes.restype = wintypes.BOOL

_kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
_kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

_kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

_kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
_kernel32.Process32FirstW.restype = wintypes.BOOL

_kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
_kernel32.Process32NextW.restype = wintypes.BOOL

_kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
_kernel32.TerminateProcess.restype = wintypes.BOOL

_kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(_IOCounters)]
_kernel32.GetProcessIoCounters.restype = wintypes.BOOL

_psapi.GetProcessMemoryInfo.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_ProcessMemoryCounters),
    wintypes.DWORD,
]
_psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

_ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
_ntdll.NtSuspendProcess.restype = wintypes.LONG

_ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
_ntdll.NtResumeProcess.restype = wintypes.LONG

_ntdll.NtQuerySystemInformation.argtypes = [
    wintypes.ULONG,
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]
_ntdll.NtQuerySystemInformation.restype = wintypes.LONG

_AF_INET = 2
_UDP_TABLE_OWNER_PID = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_SUCCESS = 0

_GetExtendedUdpTable = _iphlpapi.GetExtendedUdpTable
_GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
    wintypes.ULONG,
    ctypes.c_int,
    wintypes.ULONG,
]
_GetExtendedUdpTable.restype = wintypes.DWORD


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """Snapshot of a process identity for tracking and cache validation."""

    pid: int
    creation_time: float


@dataclass(frozen=True, slots=True)
class TargetProcessStatus:
    """Immutable snapshot of the monitored target process state.

    Attributes:
        pid: PID of the monitored process, or `None` if not monitored or not running.
        name: Name of the process executable, or `None` if not running.
        path: Resolved path to the running executable, or `None` if not running.
        udp_ports: Set of local UDP socket ports currently bound by the process.
        is_running: `True` if the process was detected and is running.
    """

    pid: int | None = None
    name: str | None = None
    path: Path | None = None
    udp_ports: frozenset[int] = frozenset()
    is_running: bool = False


def _get_creation_time_from_handle(handle: wintypes.HANDLE) -> float | None:
    creation_time = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    if not _kernel32.GetProcessTimes(handle, ctypes.byref(creation_time), ctypes.byref(exit_time), ctypes.byref(kernel_time), ctypes.byref(user_time)):
        return None
    time_100ns = (creation_time.dwHighDateTime << 32) + creation_time.dwLowDateTime
    return (time_100ns - _WINDOWS_EPOCH_DELTA_100NS) / 10000000.0


def get_process_creation_time(pid: int) -> float | None:
    """Return the creation time of the process in seconds since Unix epoch, or None if unavailable."""
    if pid <= 0:
        return None
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)  # noqa: FBT003
    if not handle:
        return None
    try:
        return _get_creation_time_from_handle(handle)
    finally:
        _kernel32.CloseHandle(handle)


def is_process_running(target: int | ProcessInfo, creation_time: float | None = None) -> bool:
    """Return `True` if the process is currently active and matches creation time if specified."""
    if isinstance(target, ProcessInfo):
        pid = target.pid
        if creation_time is None:
            creation_time = target.creation_time
    else:
        pid = target

    if pid <= 0:
        return False
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)  # noqa: FBT003
    if not handle:
        return False
    try:
        exit_code = wintypes.DWORD()
        if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        if exit_code.value != _STILL_ACTIVE:
            return False
        if creation_time is not None:
            actual_creation_time = _get_creation_time_from_handle(handle)
            if actual_creation_time is None or abs(actual_creation_time - creation_time) > _CREATION_TIME_TOLERANCE_SECONDS:
                return False
        return True
    finally:
        _kernel32.CloseHandle(handle)


def get_process_image_path(pid: int) -> Path | None:
    """Return the resolved executable file path for the given PID, or `None` if inaccessible."""
    if pid <= 0:
        return None
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)  # noqa: FBT003
    if not handle:
        return None
    try:
        buffer_size = wintypes.DWORD(1024)
        image_path_buffer = ctypes.create_unicode_buffer(buffer_size.value)
        if not _kernel32.QueryFullProcessImageNameW(handle, 0, image_path_buffer, ctypes.byref(buffer_size)):
            return None
        return Path(image_path_buffer.value).resolve()
    finally:
        _kernel32.CloseHandle(handle)


def iter_running_processes() -> list[tuple[int, str]]:
    """Return a snapshot list of `(pid, name)` for all running processes."""
    snapshot_handle = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot_handle or snapshot_handle == wintypes.HANDLE(-1).value:
        return []
    try:
        entry = ProcessEntry32W()
        if not _kernel32.Process32FirstW(snapshot_handle, ctypes.byref(entry)):
            return []
        processes: list[tuple[int, str]] = []
        while True:
            processes.append((entry.th32ProcessID, entry.szExeFile))
            if not _kernel32.Process32NextW(snapshot_handle, ctypes.byref(entry)):
                break
        return processes
    finally:
        _kernel32.CloseHandle(snapshot_handle)


def suspend_process(pid: int) -> None:
    """Suspend execution of the process with the given PID via `NtSuspendProcess`."""
    if pid <= 0:
        error_message = f'Invalid process ID: {pid}'
        raise ProcessLookupError(error_message)
    handle = _kernel32.OpenProcess(_PROCESS_SUSPEND_RESUME | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)  # noqa: FBT003
    if not handle:
        last_error = _kernel32.GetLastError()
        if last_error in (2, 87, 1168):
            error_message = f'Process {pid} does not exist'
            raise ProcessLookupError(error_message)
        if last_error == _ERROR_ACCESS_DENIED:
            error_message = f'Access denied to suspend process {pid}'
            raise PermissionError(error_message)
        error_message = f'Failed to open process {pid}: Win32 error {last_error}'
        raise OSError(error_message)
    try:
        ntstatus = _ntdll.NtSuspendProcess(handle)
        if ntstatus:
            error_message = f'NtSuspendProcess failed for PID {pid} with NTSTATUS {ntstatus:#x}'
            raise OSError(error_message)
    finally:
        _kernel32.CloseHandle(handle)


def resume_process(pid: int) -> None:
    """Resume execution of the process with the given PID via `NtResumeProcess`."""
    if pid <= 0:
        error_message = f'Invalid process ID: {pid}'
        raise ProcessLookupError(error_message)
    handle = _kernel32.OpenProcess(_PROCESS_SUSPEND_RESUME | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)  # noqa: FBT003
    if not handle:
        last_error = _kernel32.GetLastError()
        if last_error in (2, 87, 1168):
            error_message = f'Process {pid} does not exist'
            raise ProcessLookupError(error_message)
        if last_error == _ERROR_ACCESS_DENIED:
            error_message = f'Access denied to resume process {pid}'
            raise PermissionError(error_message)
        error_message = f'Failed to open process {pid}: Win32 error {last_error}'
        raise OSError(error_message)
    try:
        ntstatus = _ntdll.NtResumeProcess(handle)
        if ntstatus:
            error_message = f'NtResumeProcess failed for PID {pid} with NTSTATUS {ntstatus:#x}'
            raise OSError(error_message)
    finally:
        _kernel32.CloseHandle(handle)


def is_process_suspended(pid: int) -> bool:
    """Check whether all threads in the target process are in the Waiting/Suspended state."""
    if pid <= 0:
        return False
    buffer_size = wintypes.ULONG(0x100000)
    while True:
        process_info_buffer = ctypes.create_string_buffer(buffer_size.value)
        return_length = wintypes.ULONG()
        status = _ntdll.NtQuerySystemInformation(
            _SYSTEM_PROCESS_INFORMATION_CLASS,
            process_info_buffer,
            buffer_size,
            ctypes.byref(return_length),
        ) & 0xFFFFFFFF
        if not status:
            break
        if status == _STATUS_INFO_LENGTH_MISMATCH:
            buffer_size = wintypes.ULONG(max(buffer_size.value * 2, return_length.value + 4096))
            continue
        return False

    current_address = ctypes.addressof(process_info_buffer)
    while True:
        next_entry_offset = wintypes.ULONG.from_address(current_address).value
        number_of_threads = wintypes.ULONG.from_address(current_address + 4).value
        process_id = ctypes.c_void_p.from_address(current_address + 80).value or 0

        if process_id == pid:
            if not number_of_threads:
                return False
            threads_base_address = current_address + 256
            for i in range(number_of_threads):
                thread_address = threads_base_address + i * 80
                thread_state = wintypes.ULONG.from_address(thread_address + 68).value
                wait_reason = wintypes.ULONG.from_address(thread_address + 72).value
                if thread_state != _THREAD_STATE_WAITING or wait_reason != _WAIT_REASON_SUSPENDED:
                    return False
            return True

        if not next_entry_offset:
            break
        current_address += next_entry_offset

    return False


def get_current_process_memory_mb() -> float:
    """Return the RSS memory usage of the current process in megabytes."""
    memory_counters = _ProcessMemoryCounters()
    if not _psapi.GetProcessMemoryInfo(_kernel32.GetCurrentProcess(), ctypes.byref(memory_counters), memory_counters.cb):
        return 0.0
    return float(memory_counters.WorkingSetSize) / _BYTES_PER_MB


def get_current_process_io_bytes() -> tuple[int, int]:
    """Return `(read_bytes, write_bytes)` for the current process."""
    io_counters = _IOCounters()
    if not _kernel32.GetProcessIoCounters(_kernel32.GetCurrentProcess(), ctypes.byref(io_counters)):
        return (0, 0)
    return (int(io_counters.ReadTransferCount), int(io_counters.WriteTransferCount))


def get_current_process_cpu_time() -> float:
    """Return total CPU time (kernel + user) in seconds for the current process."""
    creation_time = wintypes.FILETIME()
    exit_time = wintypes.FILETIME()
    kernel_time = wintypes.FILETIME()
    user_time = wintypes.FILETIME()
    if not _kernel32.GetProcessTimes(
        _kernel32.GetCurrentProcess(),
        ctypes.byref(creation_time),
        ctypes.byref(exit_time),
        ctypes.byref(kernel_time),
        ctypes.byref(user_time),
    ):
        return 0.0
    kernel_100ns = (kernel_time.dwHighDateTime << 32) + kernel_time.dwLowDateTime
    user_100ns = (user_time.dwHighDateTime << 32) + user_time.dwLowDateTime
    return (kernel_100ns + user_100ns) / 10000000.0


def get_process_udp_ports(target_pid: int) -> frozenset[int]:
    """Return the set of local UDP ports currently bound by the target PID via Win32 IP Helper API."""
    buffer_size = wintypes.DWORD(0)
    result = _GetExtendedUdpTable(None, ctypes.byref(buffer_size), 0, _AF_INET, _UDP_TABLE_OWNER_PID, 0)

    for _attempt in range(3):
        if result != _ERROR_INSUFFICIENT_BUFFER:
            break
        buffer = ctypes.create_string_buffer(buffer_size.value)
        result = _GetExtendedUdpTable(buffer, ctypes.byref(buffer_size), 0, _AF_INET, _UDP_TABLE_OWNER_PID, 0)
        if result == _ERROR_SUCCESS:
            number_of_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
            if not number_of_entries:
                return frozenset[int]()
            table_offset = ctypes.sizeof(wintypes.DWORD)
            row_array = (_MibUdpRowOwnerPid * number_of_entries).from_buffer(buffer, table_offset)
            return frozenset(
                socket.ntohs(row.dwLocalPort)
                for row in row_array
                if row.dwOwningPid == target_pid
            )

    return frozenset[int]()


def inspect_target_process(
    target_pid: int,
    cached_process: ProcessInfo | None = None,
) -> tuple[TargetProcessStatus, ProcessInfo | None]:
    """Return a `TargetProcessStatus` snapshot for the specified PID plus its process cache token.

    Args:
        target_pid: The Process ID (PID) to inspect.
        cached_process: The `ProcessInfo` returned by a previous call, re-queried directly
            to avoid resolving a new handle. Pass `None` to force a new handle resolution.

    Returns:
        A `(TargetProcessStatus, ProcessInfo | None)` tuple.
    """
    if target_pid <= 0:
        return (TargetProcessStatus(), None)

    # Fast path: re-query existing cached process handle if PID matches.
    if cached_process is not None and cached_process.pid == target_pid and is_process_running(cached_process):
        process_path = get_process_image_path(target_pid)
        process_name = process_path.name if process_path is not None else None
        return (
            TargetProcessStatus(
                pid=target_pid,
                name=process_name,
                path=process_path,
                udp_ports=get_process_udp_ports(target_pid),
                is_running=True,
            ),
            cached_process,
        )

    # Slow path: resolve process information for target_pid
    if is_process_running(target_pid):
        creation_time = get_process_creation_time(target_pid)
        process_path = get_process_image_path(target_pid)
        process_name = process_path.name if process_path is not None else None
        cached_info = ProcessInfo(pid=target_pid, creation_time=creation_time) if creation_time is not None else None
        return (
            TargetProcessStatus(
                pid=target_pid,
                name=process_name,
                path=process_path,
                udp_ports=get_process_udp_ports(target_pid),
                is_running=True,
            ),
            cached_info,
        )

    return (TargetProcessStatus(pid=target_pid, is_running=False), None)


_SYSTEM_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        'conhost.exe',
        'csrss.exe',
        'dwm.exe',
        'fontdrvhost.exe',
        'lsass.exe',
        'registry',
        'runtimebroker.exe',
        'services.exe',
        'sihost.exe',
        'smss.exe',
        'spoolsv.exe',
        'system',
        'taskhostw.exe',
        'wininit.exe',
        'winlogon.exe',
    },
)


def get_running_applications(*, user_apps_only: bool = True) -> list[tuple[int, str, str]]:
    """Return a sorted list of `(pid, name, exe_path)` for running processes."""
    processes: list[tuple[int, str, str]] = []

    for pid, name in iter_running_processes():
        if pid <= 0:
            continue
        if not name:
            continue

        if user_apps_only and name.lower() in _SYSTEM_PROCESS_NAMES:
            continue

        process_path = get_process_image_path(pid)
        exe_path = str(process_path) if process_path is not None else ''

        if user_apps_only and exe_path:
            normalized_exe_path = exe_path.lower()
            if '\\windows\\system32\\' in normalized_exe_path or '\\windows\\systemapps\\' in normalized_exe_path:
                continue

        processes.append((pid, name, exe_path))

    processes.sort(key=lambda item: item[1].lower())
    return processes
