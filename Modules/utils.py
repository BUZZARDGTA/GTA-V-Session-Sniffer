# Standard Python Libraries
import re
from pathlib import Path
from datetime import datetime


class Version:
    def __init__(self, version: str):
        self.major, self.minor, self.patch = map(int, version[1:6:2])
        self.date = datetime.strptime(version[9:19], "%d/%m/%Y").date().strftime("%d/%m/%Y")

        # Check if the version string contains the time component
        if (
            len(version) == 27
            and re.search(r" \((\d{2}:\d{2})\)$", version)
        ):
            self.time = datetime.strptime(version[21:26], "%H:%M").time().strftime("%H:%M")
            self.date_time = datetime.strptime(version[9:27], "%d/%m/%Y (%H:%M)")
        else:
            self.time = None
            self.date_time = datetime.strptime(version[9:19], "%d/%m/%Y")

    def __str__(self):
        return f"v{self.major}.{self.minor}.{self.patch} - {self.date}{f' ({self.time})' if self.time else ''}"


def get_documents_folder(use_alternative_method = False):
    """
    Retrieves the Path object to the current user's \"Documents\" folder by querying the Windows registry.

    Args:
        use_alternative_method: If set to `True`, the alternative method will be used to retrieve the "Documents" folder.\n
        If set to `False` (default), the registry-based method will be used.

    Returns:
        Path: A `Path` object pointing to the user's "Documents" folder.

    Raises:
        TypeError: If the retrieved path is not a string.
    """
    from pathlib import Path

    if use_alternative_method:
        # Alternative method using SHGetKnownFolderPath from WinAPI
        from win32com.shell import shell, shellcon # type:ignore # Seems like we can also use `win32comext.shell`

        # Get the Documents folder path
        documents_path = shell.SHGetKnownFolderPath(shellcon.FOLDERID_Documents, 0)
    else:
        # Default method using Windows registry
        import winreg
        from Modules.consts import USER_SHELL_FOLDERS_REG_KEY

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, USER_SHELL_FOLDERS_REG_KEY) as key:
            documents_path, _ = winreg.QueryValueEx(key, "Personal")

    if not isinstance(documents_path, str):
        raise TypeError(f'Expected "str", got "{type(documents_path)}"')

    return Path(documents_path)

def resource_path(relative_path: Path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    import sys

    base_path = getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent) # .parent twice because of modularizing bruh
    if not isinstance(base_path, Path):
        base_path = Path(base_path)
    return base_path / relative_path
