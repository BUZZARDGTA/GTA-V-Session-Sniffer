from pathlib import Path


def get_documents_folder():
    """Retrieves the Path object to the current user's \"Documents\" folder by querying the Windows registry."""
    import winreg

    reg_key = R"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key) as key:
        documents_path, _ = winreg.QueryValueEx(key, "Personal")

    if not isinstance(documents_path, str):
        raise TypeError(f'Expected "str", got "{type(documents_path)}"')

    return Path(documents_path)

    """ NOTE: Alternative code:
    import os
    import sys
    from pathlib import Path

    # Windows - Use SHGetKnownFolderPath for Documents
    from win32com.shell import shell, shellcon

    # Get the Documents folder path
    documents_path = Path(shell.SHGetKnownFolderPath(shellcon.FOLDERID_Documents, 0))

    # Append the desired file path
    log_path = documents_path / "Cherax" / "Lua" / "GTA_V_Session_Sniffer-plugin" / "log.txt"

    print(log_path)
    """

def resource_path(relative_path: Path):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    import sys

    base_path = getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent) # .parent twice because of modularizing bruh
    if not isinstance(base_path, Path):
        base_path = Path(base_path)
    return base_path / relative_path
