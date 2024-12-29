from Modules.utils import get_documents_folder, resource_path

import re
from pathlib import Path
from colorama import Fore
from datetime import datetime
from PyQt6.QtGui import QColor


class QColorPalette:
    RED = QColor(255, 0, 0)
    GREEN = QColor(0, 255, 0)
    #BLUE = QColor(0, 0, 255)
    YELLOW = QColor(255, 255, 0)
    #CYAN = QColor(0, 255, 255)
    #MAGENTA = QColor(255, 0, 255)
    WHITE = QColor(255, 255, 255)
    #BLACK = QColor(0, 0, 0)
    #LIGHTRED_EX = QColor(255, 102, 102)
    #LIGHTGREEN_EX = QColor(102, 255, 102)
    #LIGHTBLUE_EX = QColor(102, 102, 255)
    #LIGHTYELLOW_EX = QColor(255, 255, 153)
    #LIGHTCYAN_EX = QColor(153, 255, 255)
    #LIGHTMAGENTA_EX = QColor(255, 153, 255)


USERIP_INI_SETTINGS_LIST = ["ENABLED", "COLOR", "NOTIFICATIONS", "VOICE_NOTIFICATIONS", "LOG", "PROTECTION", "PROTECTION_PROCESS_PATH", "PROTECTION_RESTART_PROCESS_PATH", "PROTECTION_SUSPEND_PROCESS_MODE"]
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
RE_MAC_ADDRESS_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
USERIP_DATABASES_PATH = Path("UserIP Databases")
SESSIONS_LOGGING_PATH = Path("Sessions Logging") / datetime.now().strftime("%Y/%m/%d") / f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
USERIP_LOGGING_PATH = Path("UserIP_Logging.log")
GEOLITE2_DATABASES_FOLDER_PATH = Path("GeoLite2 Databases")
TWO_TAKE_ONE__PLUGIN__LOG_PATH = Path.home() / "AppData/Roaming/PopstarDevs/2Take1Menu/scripts/GTA_V_Session_Sniffer-plugin/log.txt"
STAND__PLUGIN__LOG_PATH = Path.home() / "AppData/Roaming/Stand/Lua Scripts/GTA_V_Session_Sniffer-plugin/log.txt"
USER_SHELL_FOLDERS_REG_KEY = R"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
CHERAX__PLUGIN__LOG_PATH = get_documents_folder() / "Cherax/Lua/GTA_V_Session_Sniffer-plugin/log.txt"
TTS_PATH = resource_path(Path("TTS/"))
RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)")
RE_USERIP_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)")
RE_MODMENU_LOGS_USER_PATTERN = re.compile(r"^user:(?P<username>[\w._-]{1,16}), scid:\d{1,9}, ip:(?P<ip>[\d.]+), timestamp:\d{10}$")
WIRESHARK_VERSION_PATTERN = re.compile(r"\b(?P<version>\d+\.\d+\.\d+)\b")
WIRESHARK_RECOMMENDED_FULL_VERSION = "TShark (Wireshark) 4.2.9 (v4.2.9-0-g2acaabc9099c)."
WIRESHARK_RECOMMENDED_VERSION_NUMBER = "4.2.9"
WIRESHARK_REQUIRED_DL = "https://www.wireshark.org/download/win64/"
GITHUB_RELEASE_API__GEOLITE2 = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"
GITHUB_RELEASE_API__GEOLITE2__BACKUP = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"
GUI_COLUMN_HEADERS_TOOLTIP_MAPPING = {
    "Usernames": "Display the usernames of the players.",
    "First Seen": "The first time the player was observed.",
    "Last Rejoin": "The most recent time the player rejoined.",
    "Last Seen": "The last time the player was active.",
    "Rejoins": "The number of times the player has left and rejoined later.",
    "T. Packets": "The total number of packets exchanged by the player across all sessions.",
    "Packets": "The number of packets exchanged by the player during the current session.",
    "PPS": "The number of Packets Per Second exchanged by the player.",
    "IP Address": "The IP address of the player.",
    "Last Port": "The port used by the player's last captured packet.",
    "Intermediate Ports": "The ports used by the player between the first and last captured packets.",
    "First Port": "The port used by the player's first captured packet.",
    "Continent": "The continent of the player's IP location.",
    "Country": "The country of the player's IP location.",
    "Region": "The region of the player's IP location.",
    "R. Code": "The region code of the player's IP location.",
    "City": "The city associated with the player's IP location (typically representing the ISP or an intermediate location, not the player's home address city).",
    "District": "The district of the player's IP location.",
    "ZIP Code": "The ZIP/postal code of the player's IP location.",
    "Lat": "The latitude of the player's IP location.",
    "Lon": "The longitude of the player's IP location.",
    "Time Zone": "The time zone of the player's IP location.",
    "Offset": "The time zone offset of the player's IP location.",
    "Currency": "The currency associated with the player's IP location.",
    "Organization": "The organization associated with the player's IP address.",
    "ISP": "The Internet Service Provider of the player's IP address.",
    "ASN / ISP": "The Autonomous System Number or Internet Service Provider of the player.",
    "AS": "The Autonomous System code of the player's IP.",
    "ASN": "The Autonomous System Number name associated with the player's IP.",
    "Mobile": "Indicates if the player is using a mobile network (e.g., through a cellular hotspot or mobile data).",
    "VPN": "Indicates if the player is using a VPN, Proxy, or Tor relay.",
    "Hosting": "Indicates if the player is using a hosting provider (similar to VPN).",
}