# Standard Python Libraries
from pathlib import Path


class TSharkNotFoundException(Exception):
    pass

class InvalidTSharkVersionException(Exception):
    def __init__(self, version: str, tshark_path: Path):
        self.version = version
        self.path = tshark_path
        self.message = f"Invalid TShark version: {version}"
        super().__init__(self.message)


def get_tshark_path(tshark_path: Path = None):
    """Finds the path of the tshark executable.

    If the user has provided a path it will be used
    Otherwise default locations will be searched.

    Args:
        tshark_path (optional): If provided, the path of the tshark executable.
    Raises:
        TSharkNotFoundException: When TShark could not be found in any location.
    """

    import os
    import winreg

    def find_tshark_by_argument_path(possible_tshark_paths: list[Path]):
        if tshark_path is not None:
            user_tshark_path = None

            if tshark_path.is_file():
                if tshark_path.name == "tshark.exe":
                    user_tshark_path = tshark_path
            elif tshark_path.is_dir():
                user_tshark_path = tshark_path / "tshark.exe"

            if user_tshark_path:
                if user_tshark_path not in possible_tshark_paths:
                    possible_tshark_paths.insert(0, user_tshark_path)

        return possible_tshark_paths

    def find_tshark_by_wireshark_common_installation_path(possible_tshark_paths: list[Path]):
        """Adds common Wireshark installation paths to the provided list of possible paths.

        This function checks the `ProgramFiles` and `ProgramFiles(x86)` environment variables to locate the
        standard installation directories for Wireshark. If these directories exist, the path to `tshark.exe`
        inside the `Wireshark` folder is appended to the list of possible paths.

        Args:
            possible_tshark_paths: A list of existing possible paths to Wireshark.

        Returns:
            list: The updated list of possible paths including standard installation paths.
        """
        for env in ("ProgramFiles", "ProgramFiles(x86)"):
            env_path = os.getenv(env)
            if env_path is None:
                continue

            program_files = Path(env_path)
            possible_tshark_path = program_files / "Wireshark" / "tshark.exe"
            if possible_tshark_path not in possible_tshark_paths:
                possible_tshark_paths.append(possible_tshark_path)

        return possible_tshark_paths

    def find_tshark_by_wireshark_regedit_installation_paths(possible_tshark_paths: list[Path]):
        """Find all possible installation paths of Wireshark by querying the Windows registry and add them to the provided list of potential paths."""
        # Registry paths to check
        registry_paths = [
            R"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",  # 64-bit programs
            R"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"  # 32-bit programs
        ]

        for registry_path in registry_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path) as reg_key:
                    for i in range(winreg.QueryInfoKey(reg_key)[0]):  # Iterate through subkeys
                        subkey_name = winreg.EnumKey(reg_key, i)
                        with winreg.OpenKey(reg_key, subkey_name) as subkey:
                            try:
                                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                if not isinstance(display_name, str):
                                    continue
                                install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                                if not isinstance(install_location, str):
                                    continue

                                if not display_name.startswith("Wireshark"):
                                    continue

                                possible_tshark_path = Path(install_location) / "tshark.exe"
                                if possible_tshark_path not in possible_tshark_paths:
                                    possible_tshark_paths.append(possible_tshark_path)
                            except FileNotFoundError:
                                # Skip keys without the required values
                                continue
            except FileNotFoundError:
                # Skip if the registry path doesn't exist
                continue

        return possible_tshark_paths

    def validate_tshark_path(possible_tshark_path: Path):
        """Validates if a given path points to a valid `tshark.exe` executable and matches the required version."""

        import subprocess
        from Modules.consts import WIRESHARK_REQUIRED_VERSION

        def get_tshark_version(tshark_path: Path):
            try:
                result = subprocess.check_output([tshark_path, '--version'], text=True)
                return result.splitlines()[0]
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

            return None

        if not possible_tshark_path.exists() or not possible_tshark_path.is_file():
            return None

        if tshark_version := get_tshark_version(possible_tshark_path):
            if tshark_version is None:
                return None

            if tshark_version != WIRESHARK_REQUIRED_VERSION:
                raise InvalidTSharkVersionException(tshark_version, possible_tshark_path)

        return possible_tshark_path

    possible_tshark_paths: list[Path] = []
    possible_tshark_paths = find_tshark_by_argument_path(possible_tshark_paths)
    possible_tshark_paths = find_tshark_by_wireshark_regedit_installation_paths(possible_tshark_paths)
    possible_tshark_paths = find_tshark_by_wireshark_common_installation_path(possible_tshark_paths)

    invalid_tshark_version_exception = None

    for possible_tshark_path in possible_tshark_paths:
        try:
            if tshark_path := validate_tshark_path(possible_tshark_path):
                return tshark_path
        except InvalidTSharkVersionException as invalid_tshark_version:
            invalid_tshark_version_exception = invalid_tshark_version

    if invalid_tshark_version_exception:
        raise invalid_tshark_version_exception

    raise TSharkNotFoundException(
        "TShark not found. Try adding its location to the configuration file.\n"
        f"Searched these paths: {', '.join(f'\"{possible_tshark_path}\"' for possible_tshark_path in possible_tshark_paths)}"
    )

def is_npcap_or_winpcap_installed():
    import subprocess

    service_names = ["npcap", "npf"]

    for service in service_names:
        try:
            subprocess.check_output(["sc", "query", service], stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            continue
        else:
            return True

    return False
