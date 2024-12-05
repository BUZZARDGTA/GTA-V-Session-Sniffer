from Modules.utils import get_documents_folder, resource_path

import re
from pathlib import Path
from datetime import datetime

USERIP_INI_SETTINGS_LIST = ["ENABLED", "COLOR", "NOTIFICATIONS", "VOICE_NOTIFICATIONS", "LOG", "PROTECTION", "PROTECTION_PROCESS_PATH", "PROTECTION_RESTART_PROCESS_PATH", "PROTECTION_SUSPEND_PROCESS_MODE"]
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
RE_MAC_ADDRESS_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
USERIP_DATABASES_PATH = Path("UserIP Databases")
SESSIONS_LOGGING_PATH = Path("Sessions Logging") / datetime.now().strftime("%Y/%m/%d") / f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
USERIP_LOGGING_PATH = Path("UserIP_Logging.log")
TWO_TAKE_ONE__PLUGIN__LOG_PATH = Path.home() / "AppData/Roaming/PopstarDevs/2Take1Menu/scripts/GTA_V_Session_Sniffer-plugin/log.txt"
STAND__PLUGIN__LOG_PATH = Path.home() / "AppData/Roaming/Stand/Lua Scripts/GTA_V_Session_Sniffer-plugin/log.txt"
CHERAX__PLUGIN__LOG_PATH = get_documents_folder() / "Cherax/Lua/GTA_V_Session_Sniffer-plugin/log.txt"
TTS_PATH = resource_path(Path("TTS/"))
RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)")
RE_USERIP_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)")
RE_MODMENU_LOGS_USER_PATTERN = re.compile(r"^user:(?P<username>[\w._-]{1,16}), scid:\d{1,9}, ip:(?P<ip>[\d.]+), timestamp:\d{10}$")
WIRESHARK_REQUIRED_VERSION = "TShark (Wireshark) 4.2.9 (v4.2.9-0-g2acaabc9099c)."
WIRESHARK_REQUIRED_DL = "https://www.wireshark.org/download/win64/"
