# Local Python Libraries (Included with Project)
from Modules.capture.utils import get_tshark_path

# Standard Python Libraries
import subprocess
from pathlib import Path
from typing import Callable
from datetime import datetime


class TSharkCrashException(Exception):
    pass

class Frame:
    def __init__(self, time_epoch: str):
        self.datetime = converts_tshark_packet_timestamp_to_datetime_object(time_epoch)

class IP:
    def __init__(self, src: str, dst: str):
        self.src = src
        self.dst = dst

class UDP:
    def __init__(self, srcport: str, dstport: str):
        self.srcport = int(srcport) if srcport else None
        self.dstport = int(dstport) if dstport else None

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
        self.interface = interface
        self.capture_filter = capture_filter
        self.display_filter = display_filter
        self.tshark_path = get_tshark_path(tshark_path)

        self._tshark_command  = [
            self.tshark_path,
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
        self._tshark__process = None

    def live_capture(self, callback: Callable[[Packet], None], timeout: int | float):
        import time
        import queue
        import threading

        packets_queue = queue.Queue()

        def read_packets():
            for packet in self._capture_packets():
                packets_queue.put(packet)

        stdout_thread = threading.Thread(target=read_packets, daemon=True)
        stdout_thread.start()

        start_time = time.time()

        while True:
            time_elapsed = time.time() - start_time
            if time_elapsed >= timeout:
                if packets_queue.empty():
                    callback("None")
                else:
                    while not packets_queue.empty():
                        packet = packets_queue.get()
                        callback(packet)

                start_time = time.time()

            time.sleep(0.1)

    def apply_on_packets(self, callback: Callable[[Packet], None]):
        for packet in self._capture_packets():
            callback(packet)

    def _capture_packets(self):
        def process_tshark_stdout(line: str):
            return line.rstrip().split('|', 4)

        with subprocess.Popen(
            self._tshark_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        ) as process:
            self._tshark__process = process

            yield from (Packet(fields) for fields in map(process_tshark_stdout, process.stdout))


def converts_tshark_packet_timestamp_to_datetime_object(packet_frame_time_epoch: str):
    return datetime.fromtimestamp(timestamp=float(packet_frame_time_epoch))