from Modules.utils import get_documents_folder, resource_path

import re
from pathlib import Path
from colorama import Fore
from datetime import datetime
from PyQt6.QtGui import QColor

USERIP_INI_SETTINGS_LIST = ["ENABLED", "COLOR", "NOTIFICATIONS", "VOICE_NOTIFICATIONS", "LOG", "PROTECTION", "PROTECTION_PROCESS_PATH", "PROTECTION_RESTART_PROCESS_PATH", "PROTECTION_SUSPEND_PROCESS_MODE"]
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
RE_MAC_ADDRESS_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
USERIP_DATABASES_PATH = Path("UserIP Databases")
SESSIONS_LOGGING_PATH = Path("Sessions Logging") / datetime.now().strftime("%Y/%m/%d") / f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
USERIP_LOGGING_PATH = Path("UserIP_Logging.log")
TWO_TAKE_ONE__PLUGIN__LOG_PATH = Path.home() / "AppData/Roaming/PopstarDevs/2Take1Menu/scripts/GTA_V_Session_Sniffer-plugin/log.txt"
STAND__PLUGIN__LOG_PATH = Path.home() / "AppData/Roaming/Stand/Lua Scripts/GTA_V_Session_Sniffer-plugin/log.txt"
USER_SHELL_FOLDERS_REG_KEY = R"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
CHERAX__PLUGIN__LOG_PATH = get_documents_folder() / "Cherax/Lua/GTA_V_Session_Sniffer-plugin/log.txt"
TTS_PATH = resource_path(Path("TTS/"))
RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)")
RE_USERIP_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)")
RE_MODMENU_LOGS_USER_PATTERN = re.compile(r"^user:(?P<username>[\w._-]{1,16}), scid:\d{1,9}, ip:(?P<ip>[\d.]+), timestamp:\d{10}$")
WIRESHARK_REQUIRED_VERSION = "TShark (Wireshark) 4.2.9 (v4.2.9-0-g2acaabc9099c)."
WIRESHARK_REQUIRED_DL = "https://www.wireshark.org/download/win64/"
HEADER_TEXT_MAX_LENGTH = 99
HEADER_TEXT_SEPARATOR = "-" * HEADER_TEXT_MAX_LENGTH
HEADER_TEXT_MIDDLE_SEPARATOR = "-   " * 25
GITHUB_RELEASE_API__GEOLITE2 = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"
GITHUB_RELEASE_API__GEOLITE2__BACKUP = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"
# Mapping of `colorama.Fore` colors to `QColor` equivalents
COLORAMA_FORE_TO_QCOLOR = {
    Fore.RED: QColor(255, 0, 0),
    Fore.GREEN: QColor(0, 255, 0),
    Fore.BLUE: QColor(0, 0, 255),
    Fore.YELLOW: QColor(255, 255, 0),
    Fore.CYAN: QColor(0, 255, 255),
    Fore.MAGENTA: QColor(255, 0, 255),
    Fore.WHITE: QColor(255, 255, 255),
    Fore.BLACK: QColor(0, 0, 0),
    Fore.LIGHTRED_EX: QColor(255, 102, 102),
    Fore.LIGHTGREEN_EX: QColor(102, 255, 102),
    Fore.LIGHTBLUE_EX: QColor(102, 102, 255),
    Fore.LIGHTYELLOW_EX: QColor(255, 255, 153),
    Fore.LIGHTCYAN_EX: QColor(153, 255, 255),
    Fore.LIGHTMAGENTA_EX: QColor(255, 153, 255),
    Fore.RESET: None,  # Reset color
}