# Standard Python Libraries
import os
import subprocess
from pathlib import Path
from typing import Optional


class TSharkNotFoundException(Exception):
    pass


def get_tshark_path(tshark_path: Path = None):
    """Finds the path of the tshark executable.

    If the user has provided a path it will be used
    Otherwise default locations will be searched.

    :param tshark_path: Path of the tshark binary
    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    possible_paths: list[Path] = []

    if tshark_path is not None:
        user_tshark_path = None

        if tshark_path.is_file():
            if tshark_path.name == "tshark.exe":
                user_tshark_path = tshark_path
        elif tshark_path.is_dir():
            if (tshark_path / "tshark.exe").is_file():
                user_tshark_path = tshark_path / "tshark.exe"

        if user_tshark_path:
            possible_paths.insert(0, user_tshark_path)

    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        env_path = os.getenv(env)
        if env_path is not None:
            program_files = Path(env_path)
            possible_paths.append(program_files / "Wireshark" / "tshark.exe")

    for path in possible_paths:
        if path.exists():
            return path

    raise TSharkNotFoundException(
          "TShark not found. Try adding its location to the configuration file.\n"
        fR"Searched these paths: {', '.join(f'\"{path}\"' for path in possible_paths)}"
    )

def get_tshark_version(tshark_path: Optional[Path]):
    tshark_path = get_tshark_path(tshark_path)

    try:
        result = subprocess.check_output([tshark_path, '--version'], text=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    else:
        return result.splitlines()[0]

def is_npcap_or_winpcap_installed():
    service_names = ["npcap", "npf"]

    for service in service_names:
        try:
            subprocess.check_output(["sc", "query", service], stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            continue
        else:
            return True

    return False