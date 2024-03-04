# --------------------------------------------
# 📦 External/Third-party Python Libraries 📦
# --------------------------------------------
import psutil
import pyshark
import colorama
import geoip2.errors
import geoip2.database
#import maxminddb.errors
from colorama import Fore
from prettytable import PrettyTable, SINGLE_BORDER
from pyshark.packet.packet import Packet
from pyshark.capture.capture import TSharkCrashException
from pyshark.tshark.tshark import TSharkNotFoundException

# ------------------------------------------------------
# 🐍 Standard Python Libraries (Included by Default) 🐍
# ------------------------------------------------------
import os
import sys
#import uuid
import time
import enum
import socket
import ctypes
import signal
import atexit
import logging
import textwrap
import threading
import ipaddress
import subprocess
import webbrowser
from pathlib import Path
from threading import Timer
from operator import itemgetter
from datetime import datetime, timedelta
from ipaddress import IPv4Network, IPv4Address

logging.basicConfig(filename='debug.log',
                    level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

if sys.version_info.major <= 3 and sys.version_info.minor < 9:
    print("To use this script, your Python version must be 3.9 or higher.")
    print("Please note that Python 3.9 is not compatible with Windows versions 7 or lower.")
    sys.exit(0)

class Version:
    def __init__(self, version: str):
        self.major = int(version[1])
        self.minor = int(version[3])
        self.patch = int(version[5])
        self.date = f"{version[9:19]}"
        self.version = f"v{version[1:6]}"
        self.version_date = f"{self.version} - {self.date}"

    def __str__(self):
        return self.version_date

class Updater:
    def __init__(self, current_version: str):
        self.current_version = current_version

    def check_for_update(self, latest_version: str):
        if latest_version.major > self.current_version.major:
            return True
        elif latest_version.major == self.current_version.major:
            if latest_version.minor > self.current_version.minor:
                return True
            elif latest_version.minor == self.current_version.minor:
                if latest_version.patch > self.current_version.patch:
                    return True
        return False

class Msgbox(enum.IntFlag):
    # https://stackoverflow.com/questions/50086178/python-how-to-keep-messageboxw-on-top-of-all-other-windows
    # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw
    # https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/msgbox-function
    OKOnly = 0  # Display OK button only.
    OKCancel = 1  # Display OK and Cancel buttons.
    AbortRetryIgnore = 2  # Display Abort, Retry, and Ignore buttons.
    YesNoCancel = 3  # Display Yes, No, and Cancel buttons.
    YesNo = 4  # Display Yes and No buttons.
    RetryCancel = 5  # Display Retry and Cancel buttons.
    Critical = 16  # Display Critical Message icon.
    Question = 32  # Display Warning Query icon.
    Exclamation = 48  # Display Warning Message icon.
    Information = 64  # Display Information Message icon.
    DefaultButton1 = 0  # First button is default.
    DefaultButton2 = 256  # Second button is default.
    DefaultButton3 = 512  # Third button is default.
    DefaultButton4 = 768  # Fourth button is default.
    ApplicationModal = 0  # Application modal; the user must respond to the message box before continuing work in the current application.
    SystemModal = 4096  # System modal; all applications are suspended until the user responds to the message box.
    MsgBoxHelpButton = 16384  # Adds Help button to the message box.
    MsgBoxSetForeground = 65536  # Specifies the message box window as the foreground window.
    MsgBoxRight = 524288  # Text is right-aligned.
    MsgBoxRtlReading = 1048576  # Specifies text should appear as right-to-left reading on Hebrew and Arabic systems.

class ThirdPartyServers(enum.Enum):
    PC_Discord = ["66.22.196.0/22", "66.22.244.0/24", "66.22.241.0/24"]
    PC_Valve = ["155.133.248.0/24"] # Valve = Steam
    GTAV_PC_and_PS3_TakeTwo = ["104.255.104.0/23", "104.255.106.0/24", "185.56.64.0/22", "192.81.241.0/24", "192.81.244.0/23"]
    GTAV_PC_Microsoft = ["52.139.128.0/18"]
    GTAV_PC_DoD_Network_Information_Center = ["26.0.0.0/8"]
    GTAV_XboxOne_Microsoft = ["52.159.128.0/17", "52.160.0.0/16"]
    PS5_Amazon = ["52.40.62.0/25"]
    MinecraftBedrockEdition_PC_and_PS3_Microsoft = ["20.202.0.0/24", "20.224.0.0/16", "168.61.142.128/25", "168.61.143.0/24", "168.61.144.0/20", "168.61.160.0/19"]

def create_unsafe_https_session():
    # Standard Python Libraries
    import ssl
    from ssl import SSLContext

    # Third-party library imports
    import requests
    import requests.adapters
    import urllib3
    from urllib3.poolmanager import PoolManager
    from urllib3.util import create_urllib3_context
    from urllib3.exceptions import InsecureRequestWarning


    # Workaround unsecure request warnings
    urllib3.disable_warnings(InsecureRequestWarning)


    # Allow custom ssl context for adapters
    class CustomSSLContextHTTPAdapter(requests.adapters.HTTPAdapter):
        def __init__(self, ssl_context: SSLContext | None = None, **kwargs):
            self.ssl_context = ssl_context
            super().__init__(**kwargs)

        def init_poolmanager(self, connections:int, maxsize:int, block=False):
            self.poolmanager = PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                ssl_context=self.ssl_context,
            )


    context = create_urllib3_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Work around unsecure ciphers being rejected
    context.set_ciphers("DEFAULT@SECLEVEL=0")
    # Work around legacy renegotiation being disabled
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT

    session = requests.session()
    session.mount('https://', CustomSSLContextHTTPAdapter(context))
    session.headers.update(HEADERS)
    session.verify = False

    return session

def signal_handler(sig, frame):
    if sig == 2: # means CTRL+C pressed
        cleanup_before_exit()

def cleanup_before_exit():
    if exit_signal.is_set():
        return
    exit_signal.set()

    print(f"\n{Fore.YELLOW}Ctrl+C pressed. Exiting script ...{Fore.RESET}")

    try:
        if (stdout_render_core__thread and stdout_render_core__thread.is_alive()):
            stdout_render_core__thread.join() # Wait for the thread to finish
    except Exception as e:
        logging.debug(f"EXCEPTION: cleanup_before_exit() > stdout_render_core__thread [{exit_signal.is_set()}], [{str(e)}], [{type(e).__name__}]")
        pass

    try:
        capture.clear()
    except Exception as e:
        logging.debug(f"EXCEPTION: cleanup_before_exit() > capture.clear() [{exit_signal.is_set()}], [{str(e)}], [{type(e).__name__}]")
        pass

    """ I don't know why, but those trows me an error so I'll leave them commented.
    capture.close_async()
    capture.close()
    """

    try:
        close_maxmind_reader()
    except Exception as e:
        logging.debug(f"EXCEPTION: cleanup_before_exit() > close_maxmind_reader() [{exit_signal.is_set()}], [{str(e)}], [{type(e).__name__}]")
        pass

    print(f"{Fore.YELLOW}If it doesn't exit correctly, you may want to press it again.{Fore.RESET}")

    sys.exit(0)

def is_pyinstaller_compiled():
    return getattr(sys, 'frozen', False) # Check if the running Python script is compiled using PyInstaller, cx_Freeze or similar

def converts_pyshark_packet_timestamp_to_datetime_object(sniff_timestamp: str):
    return datetime.fromtimestamp(timestamp=float(sniff_timestamp))

def title(title: str):
    print(f"\033]0;{title}\007", end="")

def cls():
    print("\033c", end="")

def plural(variable: int):
    return "s" if variable > 1 else ""

def is_script_an_executable():
    return Path(sys.argv[0]).suffix.lower() == ".exe" # Check if the running Python script, command-line argument has a file extension ending with .exe

def is_ipv4_address(ip_address: str):
    try:
        return ipaddress.IPv4Address(ip_address).version == 4
    except:
        return False

def align_ip_address_segments(ip_address: str):
    return ".".join(f"{segment:<3}" for segment in ip_address.split("."))

def get_country_info(packet: Packet, ip_address: str):
    country_name = "N/A"
    country_iso = "N/A"

    # Try to get country info from MaxMind reader
    if maxmind_reader:
        try:
            response = maxmind_reader.country(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            country_name = str(response.country.name)
            country_iso = str(response.country.iso_code)

    # Try to get country info from packet attributes
    elif hasattr(packet, 'ip') and hasattr(packet.ip, 'geosrc_country') and hasattr(packet.ip, 'geosrc_country_iso'):
        country_name = str(packet.ip.geosrc_country)
        country_iso = str(packet.ip.geosrc_country_iso)

    return country_name, country_iso

def show_message_box(title: str, message: str, style: Msgbox):
    return ctypes.windll.user32.MessageBoxW(0, message, title, style)

def npcap_or_winpcap_installed():
    service_names = ["npcap", "npf"]

    for service in service_names:
        try:
            subprocess.check_output(["sc", "query", service], stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            continue

    return False

def create_or_happen_to_variable(variable: str, operator: str, string_to_happen: str):
    if not string_to_happen:
        return variable

    if variable:
        return f"{variable}{operator}{string_to_happen}"
    else:
        return string_to_happen

def initialize_maxmind_reader():
    maxmind_reader = None

    if MAXMIND_DB_PATH is not None:
        maxmind_reader = geoip2.database.Reader(MAXMIND_DB_PATH)

    return maxmind_reader

def close_maxmind_reader():
    try:
        if MAXMIND_DB_PATH and maxmind_reader is not None:
            maxmind_reader.close()
    except NameError:
        pass

def reconstruct_settings():
    print("\nCorrect reconstruction of 'Settings.ini' ...")
    text = f"""
        ;;-----------------------------------------------------------------------------
        ;;Lines starting with ";;" symbols are commented lines.
        ;;
        ;;This is the settings file for 'GTA V Session Sniffer' configuration.
        ;;
        ;;If you don't know what value to choose for a specifc setting, set it's value to None.
        ;;The program will automatically analyzes this file and if needed will regenerate it if it contains errors.
        ;;
        ;;<STDOUT_SHOW_HEADER>
        ;;Determine if you want or not to show the developper's header in the script's screen.
        ;;
        ;;<STDOUT_SHOW_DATE>
        ;;Shows or not the date from which a player has been captured in "First Seen" and "Last Seen" fields.
        ;;
        ;;<STDOUT_REFRESHING_TIMER>
        ;;Time interval between which this will refresh the console display.
        ;;
        ;;<STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS>
        ;;The maximum number of players showing up in disconnected players list.
        ;;Valid values are any number greater than 0.
        ;;Setting it to 0 will make it unlimitted.
        ;;
        ;;<STDOUT_RESET_INFOS_ON_CONNECTED>
        ;;Resets and recalculates each fields for players who were previously disconnected.
        ;;
        ;;<MAXMIND_DB_PATH>
        ;;The Windows directory (full path) where you store the MaxMind DB *.mmdb files. (optional)
        ;;This is used to resolve countrys from the players.
        ;;
        ;;<INTERFACE_NAME>
        ;;Automatically select this network adapter where the packets are going to be captured from.
        ;;
        ;;<IP_ADDRESS>
        ;;Your PC local IP address. You can obtain it like that:
        ;;https://support.microsoft.com/en-us/windows/find-your-ip-address-in-windows-f21a9bbc-c582-55cd-35e0-73431160a1b9
        ;;Valid example value: 'x.x.x.x'
        ;;
        ;;<BLOCK_THIRD_PARTY_SERVERS>
        ;;Determine if you want or not to block the annoying IP ranges from servers that shouldn't be detected.
        ;;
        ;;<PROGRAM_PRESET>
        ;;A program preset that will help capturing the right packets for your program.
        ;;Supported program presets are only 'GTA5' and 'Minecraft'.
        ;;Note that Minecraft only supports Bedrock Edition.
        ;;Please also note that both of these have only been tested on PCs.
        ;;I do not have information regarding their functionality on consoles.
        ;;
        ;;<LOW_PERFORMANCE_MODE>
        ;;If the script is responding inappropriately, such as displaying all players as disconnected even when they are not,
        ;;consider setting this to True. This will reduce the resource usage on your computer.
        ;;Enabling this option will process fewer packets at a time, alleviating strain on your CPU.
        ;;-----------------------------------------------------------------------------
    """
    text = textwrap.dedent(text.removeprefix("\n"))
    for setting in SETTINGS_LIST:
        text += f"{setting}={globals().get(setting)}\n"
    with open(SETTINGS_PATH, "w", encoding="utf-8") as file:
        file.write(text)

def apply_settings():
    global STDOUT_SHOW_HEADER, STDOUT_SHOW_DATE, STDOUT_REFRESHING_TIMER, STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS, STDOUT_RESET_INFOS_ON_CONNECTED, MAXMIND_DB_PATH, INTERFACE_NAME, IP_ADDRESS, BLOCK_THIRD_PARTY_SERVERS, PROGRAM_PRESET, LOW_PERFORMANCE_MODE

    def return_setting(setting: str, need_rewrite_settings: bool):
        return_setting_value = None

        if not settings_file_not_found:
            for line in SETTINGS:
                line: str = line.rstrip("\n")
                corrected__line = line.strip()

                if corrected__line.startswith(";;"):
                    continue

                if not line == corrected__line:
                    need_rewrite_settings = True

                parts = corrected__line.split(sep="=", maxsplit=1)
                try:
                    setting_name = parts[0]
                    setting_value = parts[1]
                except IndexError:
                    need_rewrite_settings = True
                    continue

                if setting_name == setting:
                    corrected__setting_value = setting_value.strip()
                    if corrected__setting_value == "":
                        return_setting_value = None
                        need_rewrite_settings = True

                        continue
                    if not corrected__setting_value == setting_value:
                        need_rewrite_settings = True
                    return_setting_value = corrected__setting_value

                    break

        if return_setting_value is None:
            need_rewrite_settings = True

        return return_setting_value, need_rewrite_settings

    need_rewrite_settings = False

    try:
        SETTINGS = SETTINGS_PATH.read_text("utf-8").splitlines(keepends=False)
    except FileNotFoundError:
        settings_file_not_found = True
        need_rewrite_settings = True
    else:
        settings_file_not_found = False

    for setting in SETTINGS_LIST:
        if setting == "STDOUT_SHOW_HEADER":
            STDOUT_SHOW_HEADER, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if STDOUT_SHOW_HEADER == "True":
                STDOUT_SHOW_HEADER = True
            elif STDOUT_SHOW_HEADER == "False":
                STDOUT_SHOW_HEADER = False
            else:
                need_rewrite_settings = True
                STDOUT_SHOW_HEADER = True
        elif setting == "STDOUT_SHOW_DATE":
            STDOUT_SHOW_DATE, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if STDOUT_SHOW_DATE == "True":
                STDOUT_SHOW_DATE = True
            elif STDOUT_SHOW_DATE == "False":
                STDOUT_SHOW_DATE = False
            else:
                need_rewrite_settings = True
                STDOUT_SHOW_DATE = False
        elif setting == "STDOUT_REFRESHING_TIMER":
            reset_current_setting__flag = False
            try:
                STDOUT_REFRESHING_TIMER, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
                STDOUT_REFRESHING_TIMER = int(STDOUT_REFRESHING_TIMER)
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if STDOUT_REFRESHING_TIMER < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                STDOUT_REFRESHING_TIMER = 0
        elif setting == "STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS":
            reset_current_setting__flag = False
            try:
                STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
                STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS = int(STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS)
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS = 6
        elif setting == "STDOUT_RESET_INFOS_ON_CONNECTED":
            STDOUT_RESET_INFOS_ON_CONNECTED, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if STDOUT_RESET_INFOS_ON_CONNECTED == "True":
                STDOUT_RESET_INFOS_ON_CONNECTED = True
            elif STDOUT_RESET_INFOS_ON_CONNECTED == "False":
                STDOUT_RESET_INFOS_ON_CONNECTED = False
            else:
                need_rewrite_settings = True
                STDOUT_RESET_INFOS_ON_CONNECTED = True
        elif setting == "MAXMIND_DB_PATH":
            reset_current_setting__flag = False
            MAXMIND_DB_PATH, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if MAXMIND_DB_PATH is None:
                reset_current_setting__flag = True
            elif MAXMIND_DB_PATH == "None":
                MAXMIND_DB_PATH = None
            else:
                MAXMIND_DB_PATH = Path(MAXMIND_DB_PATH)
                if MAXMIND_DB_PATH.is_file():
                    pass
                elif MAXMIND_DB_PATH.is_dir():
                    MAXMIND_DB_PATH /= "GeoLite2-Country.mmdb"
                    if not MAXMIND_DB_PATH.is_file():
                        reset_current_setting__flag = True
                else:
                    reset_current_setting__flag = True
                try:
                    with geoip2.database.Reader(f"{MAXMIND_DB_PATH}") as reader:
                        reader.country("1.1.1.1")
                except Exception as e:
                    msgbox_title = TITLE
                    msgbox_text = f"""
                    Error: {e}

                    Now disabling the setting <MAXMIND_DB_PATH> [...]
                    """
                    msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
                    msgbox_style = Msgbox.OKOnly | Msgbox.Exclamation
                    show_message_box(msgbox_title, msgbox_text, msgbox_style)
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                MAXMIND_DB_PATH = None
        elif setting == "INTERFACE_NAME":
            INTERFACE_NAME, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if INTERFACE_NAME is None:
                need_rewrite_settings = True
            elif INTERFACE_NAME == "None":
                INTERFACE_NAME = None
        elif setting == "IP_ADDRESS":
            reset_current_setting__flag = False
            IP_ADDRESS, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if IP_ADDRESS is None:
                reset_current_setting__flag = True
            elif IP_ADDRESS == "None":
                IP_ADDRESS = None
            else:
                if not is_ipv4_address(IP_ADDRESS):
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                IP_ADDRESS = None
        elif setting == "BLOCK_THIRD_PARTY_SERVERS":
            BLOCK_THIRD_PARTY_SERVERS, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if BLOCK_THIRD_PARTY_SERVERS == "True":
                BLOCK_THIRD_PARTY_SERVERS = True
            elif BLOCK_THIRD_PARTY_SERVERS == "False":
                BLOCK_THIRD_PARTY_SERVERS = False
            else:
                need_rewrite_settings = True
                BLOCK_THIRD_PARTY_SERVERS = True
        elif setting == "PROGRAM_PRESET":
            reset_current_setting__flag = False
            PROGRAM_PRESET, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if PROGRAM_PRESET is None:
                reset_current_setting__flag = True
            elif PROGRAM_PRESET == "None":
                PROGRAM_PRESET = None
            else:
                if not PROGRAM_PRESET in ["GTA5", "Minecraft"]:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                PROGRAM_PRESET = None
        elif setting == "LOW_PERFORMANCE_MODE":
            LOW_PERFORMANCE_MODE, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if LOW_PERFORMANCE_MODE == "True":
                LOW_PERFORMANCE_MODE = True
            elif LOW_PERFORMANCE_MODE == "False":
                LOW_PERFORMANCE_MODE = False
            else:
                need_rewrite_settings = True
                LOW_PERFORMANCE_MODE = True

    if need_rewrite_settings:
        reconstruct_settings()

colorama.init(autoreset=True)
signal.signal(signal.SIGINT, signal_handler)
atexit.register(cleanup_before_exit)
exit_signal = threading.Event()

if is_pyinstaller_compiled():
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

TITLE = "GTA V Session Sniffer"
VERSION = "v1.0.7 - 04/03/2024 (22:26)"
TITLE_VERSION = f"{TITLE} {VERSION}"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:122.0) Gecko/20100101 Firefox/122.0"
}
SETTINGS_LIST = [
    "STDOUT_SHOW_HEADER",
    "STDOUT_SHOW_DATE",
    "STDOUT_REFRESHING_TIMER",
    "STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS",
    "STDOUT_RESET_INFOS_ON_CONNECTED",
    "MAXMIND_DB_PATH",
    "INTERFACE_NAME",
    "IP_ADDRESS",
    "BLOCK_THIRD_PARTY_SERVERS",
    "PROGRAM_PRESET",
    "LOW_PERFORMANCE_MODE"
]
s = create_unsafe_https_session()

cls()
title(f"Initializing the script for your Windows version - {TITLE}")
print("\nInitializing the script for your Windows version ...\n")
if sys.getwindowsversion().major >= 10:
    UNDERLINE = "\033[4m"
    UNDERLINE_RESET = "\033[24m"
else:
    UNDERLINE = ""
    UNDERLINE_RESET = ""

cls()
title(f"Searching for a new update - {TITLE}")
print("\nSearching for a new update ...\n")

error_updating__flag = False

try:
    response = s.get("https://raw.githubusercontent.com/Illegal-Services/GTA-V-Session-Sniffer/version/version.txt")
except:
    error_updating__flag = True
else:
    if response.status_code == 200:
        current_version = Version(VERSION)
        latest_version = Version(response.text)
        if Updater(current_version).check_for_update(latest_version):
            msgbox_title = TITLE
            msgbox_text = f"""
                New version found. Do you want to update ?

                Current version: {VERSION}
                Latest version : {latest_version}
            """
            msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
            msgbox_style = Msgbox.YesNo | Msgbox.Question
            errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
            if errorlevel == 6:
                if is_script_an_executable():
                    webbrowser.open("https://github.com/Illegal-Services/GTA-V-Session-Sniffer")
                    sys.exit(0)
                try:
                    response = s.get("https://raw.githubusercontent.com/Illegal-Services/GTA-V-Session-Sniffer/main/GTA_V_Session_Sniffer.py")
                except:
                    error_updating__flag = True
                else:
                    if response.status_code == 200:
                        Path(f"{Path(__file__).name}").write_bytes(response.content)
                        subprocess.Popen(["start", "python", f"{Path(__file__).name}"], shell=True)
                        sys.exit(0)
                    else:
                        error_updating__flag = True
    else:
        error_updating__flag = True

if error_updating__flag:
    msgbox_title = TITLE
    msgbox_text = f"""
        ERROR: {TITLE} Failed updating itself.

        Do you want to open the '{TITLE}' project download page ?
        You can then download and run the latest version from there.
    """
    msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
    msgbox_style = Msgbox.YesNo | Msgbox.Exclamation
    errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
    if errorlevel == 6:
        webbrowser.open("https://github.com/Illegal-Services/GTA-V-Session-Sniffer")
        sys.exit(0)

cls()
title(f"Checking that 'Npcap' or 'WinpCap' driver is installed on your system - {TITLE}")
print("\nChecking that 'Npcap' or 'WinpCap' driver is installed on your system ...\n")

while True:
    if npcap_or_winpcap_installed():
        break
    else:
        webbrowser.open("https://nmap.org/npcap/")
        msgbox_title = TITLE
        msgbox_text = f"""
            ERROR: {TITLE} could not detect the 'Npcap' or 'WinpCap' driver installed on your system.

            Opening the 'Npcap' project download page for you.
            You can then download and install it from there and press "Retry".
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
        if errorlevel == 2:
            sys.exit(0)

cls()
title(f"Applying your custom settings from 'Settings.ini' - {TITLE}")
print("\nApplying your custom settings from 'Settings.ini' ...\n")

SETTINGS_PATH = Path("Settings.ini")

apply_settings()

cls()
title(f"Capture network interface selection - {TITLE}")
print(f"\nCapture network interface selection ...\n")

table = PrettyTable()
table.field_names = ["#", "Interface", "IP Address", "Packets Sent", "Packets Received"]
table.align["#"] = "c"
table.align["Interface"] = "l"
table.align["IP Address"] = "c"
table.align["Packets Sent"] = "c"
table.align["Packets Received"] = "c"

counter = 0
interfaces_info = []
user_network_interface_name = None
user_network_interface_ip_address = None

net_io_stats = psutil.net_io_counters(pernic=True)
net_if_addrs = psutil.net_if_addrs()

for interface, stats in net_io_stats.items():
    if interface in net_if_addrs:
        counter += 1

        for addr in net_if_addrs[interface]:
            if addr.family == socket.AF_INET:
                ip_address = addr.address
                break
        else:
            ip_address = None

        interface_info = {
            "Interface": interface,
            "IP Address": ip_address,
            "Packets Sent": stats.packets_sent,
            "Packets Received": stats.packets_recv
        }
        interfaces_info.append(interface_info)

        table.add_row([f"{Fore.YELLOW}{counter}{Fore.RESET}", interface, align_ip_address_segments(ip_address), stats.packets_sent, stats.packets_recv])

if INTERFACE_NAME is not None:
    for interface in interfaces_info:
        if interface["Interface"].lower() == INTERFACE_NAME.lower():
            if not interface["Interface"] == INTERFACE_NAME:
                INTERFACE_NAME = interface["Interface"]
                reconstruct_settings()

            user_network_interface_name: str = interface["Interface"]
            user_network_interface_ip_address: str = interface["IP Address"]
            break
    else:
        INTERFACE_NAME = None

if INTERFACE_NAME is None:
    print(table)

    while True:
        try:
            selection = int(input(f"\nSelect your desired capture network interface ({Fore.YELLOW}1{Fore.RESET}-{Fore.YELLOW}{len(interfaces_info)}{Fore.RESET}): {Fore.YELLOW}"))
        except ValueError:
            print(f"{Fore.RED}ERROR{Fore.RESET}: You didn't provide a number.")
        else:
            if (
                selection >= 1
                and selection <= len(interfaces_info)
            ):
                print(end=Fore.RESET)
                break
            print(f"{Fore.RED}ERROR{Fore.RESET}: The number you provided is not matching with the available network interfaces.")
    user_network_interface_name: str = interfaces_info[selection-1]["Interface"]
    user_network_interface_ip_address: str = interfaces_info[selection-1]["IP Address"]

cls()
title(f"Initializing addresses and establishing connection to your PC / Console - {TITLE}")
print(f"\nInitializing addresses and establishing connection to your PC / Console ...\n")

need_rewrite_settings = False

if not user_network_interface_name == INTERFACE_NAME:
    INTERFACE_NAME = user_network_interface_name
    need_rewrite_settings = True

if not IP_ADDRESS:
    IP_ADDRESS = user_network_interface_ip_address
    need_rewrite_settings = True

if need_rewrite_settings:
    reconstruct_settings()

while True:
    if not IP_ADDRESS:
        msgbox_title = TITLE
        msgbox_text = """
        ERROR: Unable to establish connection to your computer or console local IP Address.

        Open the file "Settings.ini" and enter your computer or console local IP Address in <IP_ADDRESS> setting.
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        show_message_box(msgbox_title, msgbox_text, msgbox_style)
        IP_ADDRESS = apply_settings(["IP_ADDRESS"])
    else:
        break

BPF_FILTER = f"dst or src host {IP_ADDRESS} and ip and udp and not port 53 and not port 80 and not port 443 and not port 5353"
DISPLAY_FILTER = None

if PROGRAM_PRESET:
    if PROGRAM_PRESET == "GTA5":
        DISPLAY_FILTER = create_or_happen_to_variable(DISPLAY_FILTER, " and ", "frame.len>=71 and frame.len<=999")
    elif PROGRAM_PRESET == "Minecraft":
        DISPLAY_FILTER = create_or_happen_to_variable(DISPLAY_FILTER, " and ", "frame.len>=49 and frame.len<=1498")

    # If the 'PROGRAM_PRESET' setting is set, automatically block RTCP connections.
    # In case RTCP can be useful to get someone IP, I decided not to block them without using a 'PROGRAM_PRESET'.
    # RTCP is known to be for example the Discord's server IP while you are in a call there.
    # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
    # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
    # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
    # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
    DISPLAY_FILTER = create_or_happen_to_variable(DISPLAY_FILTER, " and ", "not rtcp")

if BLOCK_THIRD_PARTY_SERVERS:
    # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
    # But there can be a lot more, those are just a couples I could find on my own usage.
    DISPLAY_FILTER = create_or_happen_to_variable(DISPLAY_FILTER, " and ", "not ssdp and not raknet and not dtls and not nbns and not pcp and not bt-dht and not uaudp and not classicstun and not dhcp and not mdns")

    for server in ThirdPartyServers:
        for ip_range in server.value:
            BPF_FILTER += f" and not net {ip_range}"

while True:
    try:
        capture = pyshark.LiveCapture(
            interface = INTERFACE_NAME,
            bpf_filter = BPF_FILTER,
            display_filter = DISPLAY_FILTER
        )
    except TSharkNotFoundException:
        webbrowser.open("https://www.wireshark.org/download.html")
        msgbox_title = TITLE
        msgbox_text = f"""
            ERROR: 'pyshark' Python module could not detect 'Tshark' installed on your system.

            Opening the 'Tshark' project download page for you.
            You can then download and install it from there and press "Retry".
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
        if errorlevel == 2:
            sys.exit(0)
    else:
        break

session_db = []

def stdout_render_core():
    class PrintCacher:
        def __init__(self):
            self.cache = []

        def cache_print(self, statement: str):
            self.cache.append(statement)

        def flush_cache(self):
            print("\n".join(self.cache))
            self.cache = []

    def get_minimum_padding(var: str | int, max_padding: int, padding: int):

        current_padding = len(str(var))
        if current_padding <= padding:
            if current_padding > max_padding:
                max_padding = current_padding

        return max_padding

    def port_list_creation(color: str):
        stdout_port_list = ""

        for port in player["ports"]:
            to_add_in_portlist = None

            if port == player["first_port"] == player["last_port"]:
                to_add_in_portlist = f"[{UNDERLINE}{port}{UNDERLINE_RESET}]"
            elif port == player["first_port"]:
                to_add_in_portlist = f"[{port}]"
            elif port == player["last_port"]:
                to_add_in_portlist = f"{UNDERLINE}{port}{UNDERLINE_RESET}"
            else:
                to_add_in_portlist = f"{port}"

            if to_add_in_portlist:
                stdout_port_list = create_or_happen_to_variable(stdout_port_list, ", ", f"{color}{to_add_in_portlist}{Fore.RESET}")

        return stdout_port_list

    def extract_datetime_from_timestamp(datetime_object: datetime):
        if STDOUT_SHOW_DATE:
            formatted_datetime = datetime_object.strftime("%m/%d/%Y %H:%M:%S")
        else:
            formatted_datetime = datetime_object.strftime("%H:%M:%S")

        return formatted_datetime

    printer = PrintCacher()
    refreshing_rate_t1 = time.perf_counter()

    while not exit_signal.is_set():
        session_connected__padding_country_name = 0
        session_disconnected__padding_country_name = 0
        session_connected = []
        session_disconnected = []

        for player in session_db:
            if not player["datetime_left"]:
                if (datetime.now() - player["t1"]) > timedelta(seconds=10):
                    player["datetime_left"] = player["t1"]

            if player["datetime_left"]:
                session_disconnected.append({
                    'datetime_left': player['datetime_left'],
                    'datetime_joined': player['datetime_joined'],
                    'packets': f"{player['packets']}",
                    'country_name': f"{player['country_name']}",
                    'country_iso': f"{player['country_iso']}",
                    'ip': f"{player['ip']}",
                    'stdout_port_list': port_list_creation(Fore.RED)
                })
            else:
                session_connected__padding_country_name = get_minimum_padding(player["country_name"], session_connected__padding_country_name, 27)

                session_connected.append({
                    'datetime_joined': player['datetime_joined'],
                    'packets': f"{player['packets']}",
                    'country_name': f"{player['country_name']}",
                    'country_iso': f"{player['country_iso']}",
                    'ip': f"{player['ip']}",
                    'stdout_port_list': port_list_creation(Fore.GREEN)
                })

        session_connected = sorted(session_connected, key=itemgetter('datetime_joined'))
        session_disconnected = sorted(session_disconnected, key=itemgetter('datetime_left'))

        session_disconnected__stdout_counter = session_disconnected[-STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS:]

        for player in session_disconnected__stdout_counter:
            session_disconnected__padding_country_name = get_minimum_padding(player["country_name"], session_disconnected__padding_country_name, 27)

        if (
            STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS == 0
            or STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS >= len(session_disconnected)
        ):
            len_session_disconnected_message = str(len(session_disconnected))
        else:
            len_session_disconnected_message = f"showing {STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS}/{len(session_disconnected)}"

        printer.cache_print("\n")

        if STDOUT_SHOW_HEADER:
            printer.cache_print(f"-" * 110)
            printer.cache_print(f"{UNDERLINE}Advertising{UNDERLINE_RESET}:")
            printer.cache_print(f"  * https://illegal-services.com/")
            printer.cache_print(f"  * https://github.com/Illegal-Services/PC-Blacklist-Sniffer")
            printer.cache_print(f"  * https://github.com/Illegal-Services/PS3-Blacklist-Sniffer")
            printer.cache_print("")
            printer.cache_print(f"{UNDERLINE}Contact Details{UNDERLINE_RESET}:")
            printer.cache_print(f"    You can contact me from Email: BUZZARDGTA@protonmail.com, Discord: waitingforharukatoaddme or Telegram: https://t.me/mathieudummy")
            printer.cache_print("")

        printer.cache_print(f"-" * 110)
        printer.cache_print(f"                             Welcome in {TITLE_VERSION}")
        printer.cache_print(f"                   This script aims in getting people's address IP from GTA V, WITHOUT MODS.")
        printer.cache_print(f"-" * 110)

        connected_players_table = PrettyTable()
        connected_players_table.set_style(SINGLE_BORDER)
        connected_players_table.title = f"Player{plural(len(session_connected))} connected in your session ({len(session_connected)}):"
        connected_players_table.field_names = ["First Seen", "Packets", "Country", "IP Address", "Ports"]
        connected_players_table.align = "l"
        connected_players_table.add_rows(
            [
                f"{Fore.GREEN}{extract_datetime_from_timestamp(player['datetime_joined'])}{Fore.RESET}",
                f"{Fore.GREEN}{player['packets']}{Fore.RESET}",
                f"{Fore.GREEN}{player['country_name']:<{session_connected__padding_country_name}} ({player['country_iso']}){Fore.RESET}",
                f"{Fore.GREEN}{player['ip']}{Fore.RESET}",
                f"{Fore.GREEN}{player['stdout_port_list']}{Fore.RESET}"
            ]
            for player in session_connected
        )

        disconnected_players_table = PrettyTable()
        disconnected_players_table.set_style(SINGLE_BORDER)
        disconnected_players_table.title = f"Player{plural(len(session_disconnected))} who've left your session ({len_session_disconnected_message}):"
        disconnected_players_table.field_names = ["Last Seen", "First Seen", "Packets", "Country", "IP Address", "Ports"]
        disconnected_players_table.align = "l"
        disconnected_players_table.add_rows(
            [
                f"{Fore.RED}{extract_datetime_from_timestamp(player['datetime_left'])}{Fore.RESET}",
                f"{Fore.RED}{extract_datetime_from_timestamp(player['datetime_joined'])}{Fore.RESET}",
                f"{Fore.RED}{player['packets']}{Fore.RESET}",
                f"{Fore.RED}{player['country_name']:<{session_disconnected__padding_country_name}} ({player['country_iso']}){Fore.RESET}",
                f"{Fore.RED}{player['ip']}{Fore.RESET}",
                f"{Fore.RED}{player['stdout_port_list']}{Fore.RESET}"
            ]
            for player in session_disconnected__stdout_counter
        )

        printer.cache_print(f"\n\n{connected_players_table}\n{disconnected_players_table}\n\n")

        cls()
        printer.flush_cache()

        while not exit_signal.is_set():
            refreshing_rate_t2 = time.perf_counter()

            seconds_elapsed = round(refreshing_rate_t2 - refreshing_rate_t1)
            if seconds_elapsed <= STDOUT_REFRESHING_TIMER:
                seconds_left = max(STDOUT_REFRESHING_TIMER - seconds_elapsed, 0)
                print("\033[K" + f"Scanning IPs, refreshing display in {seconds_left} second{plural(seconds_left)} ...", end="\r")
                time.sleep(1)
                continue

            refreshing_rate_t1 = refreshing_rate_t2
            break

def clear_recently_resolved_ips():
    recently_resolved_ips.clear()

    if not exit_signal.is_set():
        try:
            Timer(1, clear_recently_resolved_ips).start()
        except Exception as e:
            if not exit_signal.is_set():
                logging.debug(f"EXCEPTION: clear_recently_resolved_ips() [{exit_signal.is_set()}], [{type(str(e))}], [{type(e).__name__}]")
                raise

def packet_callback(packet: Packet):
    if exit_signal.is_set():
        raise ValueError(EXIT_SIGNAL_MESSAGE)

    packet_timestamp = converts_pyshark_packet_timestamp_to_datetime_object(packet.sniff_timestamp)

    if (datetime.now() - packet_timestamp) >= timedelta(seconds=3):
        raise ValueError(PACKET_CAPTURE_OVERFLOW)

    # Believe it or not, this happened one time during my testings ...
    # So instead of respawning "tshark.exe" due to a single weird packet, just ignore it.
    if not hasattr(packet, 'ip'):
        return

    source_address: str = packet.ip.src
    destination_address: str = packet.ip.dst
    transport_layer = packet.transport_layer

    if source_address == IP_ADDRESS:
        target__ip = destination_address
        target__port: int = packet[transport_layer].dstport
    elif destination_address == IP_ADDRESS:
        target__ip = source_address
        target__port: int = packet[transport_layer].srcport
    else:
        return

    if LOW_PERFORMANCE_MODE:
        if target__ip in recently_resolved_ips:
            return
        recently_resolved_ips.add(target__ip)

    # Skip local and private IP Ranges.
    #https://stackoverflow.com/questions/45365482/python-ip-range-to-ip-range-match
    if any(IPv4Address(target__ip) in ip_range for ip_range in private_ip_ranges):
        return

    for player in session_db:
        if player["ip"] == target__ip:
            if player["datetime_left"]:
                if STDOUT_RESET_INFOS_ON_CONNECTED:
                    session_db.remove(player)
                    break
                player["datetime_left"] = None
            player["t1"] = packet_timestamp
            player["packets"] += 1
            if target__port not in player["ports"]:
                player["ports"].append(target__port)
            if player["last_port"] != target__port:
                player["last_port"] = target__port

            return

    target__country_name, target__country_iso = get_country_info(packet, target__ip)

    target = dict(
        t1 = packet_timestamp,
        packets = 1,
        ip = target__ip,
        ports = [target__port],
        first_port = target__port,
        last_port = target__port,
        country_name = target__country_name,
        country_iso = target__country_iso,
        datetime_joined = packet_timestamp,
        datetime_left = None
    )

    session_db.append(target)

cls()
title(TITLE)

stdout_render_core__thread = threading.Thread(target=stdout_render_core)
stdout_render_core__thread.start()

maxmind_reader = initialize_maxmind_reader()

private_ip_ranges = [IPv4Network(ip_range) for ip_range in ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"]]

PACKET_CAPTURE_OVERFLOW = "Packet capture time exceeded 3 seconds."
EXIT_SIGNAL_MESSAGE = "Script aborted by user interruption."

while True:
    if LOW_PERFORMANCE_MODE:
        recently_resolved_ips = set()
        clear_recently_resolved_ips()

    try:
        capture.apply_on_packets(callback=packet_callback)
    except TSharkCrashException:
        if exit_signal.is_set():
            pass
        raise
    except Exception as e:
        if not (
            str(e) == PACKET_CAPTURE_OVERFLOW
            or str(e) == EXIT_SIGNAL_MESSAGE
            or exit_signal.is_set()
        ):
            logging.debug(f"EXCEPTION: capture.apply_on_packets() [{exit_signal.is_set()}], [{str(e)}], [{type(e).__name__}]")
            print("An unexcepted error raised:")
            raise

    time.sleep(0.1)