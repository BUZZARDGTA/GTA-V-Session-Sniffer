from pathlib import Path


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
        from win32com.shell import shell, shellcon

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
