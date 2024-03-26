import os
import subprocess
from pathlib import Path
from typing import List


class TSharkNotFoundException(Exception):
    pass

class TSharkCrashException(Exception):
    pass

class Frame:
    def __init__(self, time_epoch: str):
        self.time_epoch = time_epoch

class IP:
    def __init__(self, src: str, dst: str):
        self.src = src
        self.dst = dst

class UDP:
    def __init__(self, srcport: str, dstport: str):
        self.srcport = srcport
        self.dstport = dstport

class Packet:
    def __init__(self, fields: list):
        self.frame = Frame(fields[0])
        self.ip = IP(fields[1], fields[2])
        self.udp = UDP(fields[3], fields[4])

class PacketCapture:
    def __init__(
        self,
        interface: str,
        capture_filter: None | str = None,
        display_filter: None | str = None,
        tshark_path: Path = None
    ):
        self.tshark__path = get_tshark_path(tshark_path)
        self.tshark__process = None
        self.command = [
            self.tshark__path,
            '-l',
            '-n',
            '-Q',
            '--log-level', 'critical',
            '-B', '1',
            '-i', interface,
            *(("-f", capture_filter) if capture_filter else ()),
            *(("-Y", display_filter) if display_filter else ()),
            '-T', 'fields',
            '-E', 'separator=|',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
        ]

    def apply_on_packets(self, callback):
        for packet in self._capture_packets():
            callback(packet)

    def _capture_packets(self):
        def process_tshark_stdout(line: str):
            return line.rstrip().split('|', 4)

        self.tshark__process = subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        assert self.tshark__process.stdout

        yield from (Packet(fields) for fields in map(process_tshark_stdout, self.tshark__process.stdout))

def get_tshark_path(tshark_path: Path = None):
    """Finds the path of the tshark executable.

    If the user has provided a path it will be used
    Otherwise default locations will be searched.

    :param tshark_path: Path of the tshark binary
    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    possible_paths: List[Path] = []

    if tshark_path is not None:
        if tshark_path.is_file():
            if tshark_path.name.endswith("tshark.exe"):
                user_tshark_path = tshark_path
        elif tshark_path.is_dir():
            if (tshark_path / "tshark.exe").is_file():
                user_tshark_path = tshark_path / "tshark.exe"

        if user_tshark_path:
            possible_paths.insert(0, user_tshark_path)

    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        program_files = Path(os.getenv(env))
        if program_files is not None:
            possible_paths.append(program_files / "Wireshark" / "tshark.exe")

    for path in possible_paths:
        if path.exists():
            return path

    raise TSharkNotFoundException(
        "TShark not found. Try adding its location to the configuration file. "
        f"Searched these paths: {[path for path in possible_paths]}"
    )
