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
from scapy.sendrecv import srp1
from scapy.layers.l2 import ARP
from scapy.layers.inet import Ether
from pyshark.packet.packet import Packet

# ------------------------------------------------------
# 🐍 Standard Python Libraries (Included by Default) 🐍
# ------------------------------------------------------
import os
import re
import sys
#import uuid
import time
import enum
import socket
import ctypes
import signal
import atexit
#import logging
import textwrap
import threading
import ipaddress
import subprocess
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta
from operator import itemgetter
from ipaddress import IPv4Address, IPv4Network

#logging.basicConfig(filename='debug.log',
#                    level=logging.DEBUG,
#                    format='%(asctime)s - %(levelname)s - %(message)s',
#                    datefmt='%Y-%m-%d %H:%M:%S')

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
    Discord_PC = ["66.22.196.0/22", "66.22.244.0/24", "66.22.241.0/24"]
    GTAV_PC_and_PS3_TakeTwo = ["104.255.104.0/23", "104.255.106.0/24", "185.56.64.0/22", "192.81.241.0/24", "192.81.244.0/23"]
    GTAV_PC_Microsoft = ["52.139.128.0/18"]
    GTAV_PC_DoD_Network_Information_Center = ["26.0.0.0/8"]
    GTAV_XboxOne_Microsoft = ["52.159.128.0/17", "52.160.0.0/16"]
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
    global exit_signal

    if exit_signal.is_set():
        return

    print(f"\n{Fore.YELLOW}Ctrl+C pressed. Exiting script ...{Fore.RESET}")

    exit_signal.set()

    try:
        if (stdout_render_core__thread and stdout_render_core__thread.is_alive()):
            stdout_render_core__thread.join()  # Wait for the thread to finish
    except NameError:
        pass

    atexit.register(close_maxmind_reader)

    sys.exit(0)

def is_pyinstaller_compiled():
    return getattr(sys, 'frozen', False) # Check if the running Python script is compiled using PyInstaller, cx_Freeze or similar

def get_formatted_datetime(base_datetime: datetime | str = None):
    if base_datetime is None:
        base_datetime = datetime.now()

    # Format the datetime object as a string
    formatted_datetime = base_datetime.strftime("%Y/%m/%d %H:%M:%S")

    return str(formatted_datetime)

def title(title: str):
    print(f"\033]0;{title}\007", end="")

def cls():
    print("\033c", end="")

def plural(variable: int):
    return "s" if variable > 1 else ""

def is_script_an_executable():
    return Path(sys.argv[0]).suffix.lower() == ".exe" # Check if the running Python script, command-line argument has a file extension ending with .exe

def is_ip_address(string: str):
  try:
    ipaddress.ip_address(string)
    return True
  except ValueError:
    return False

def is_mac_address(string: str):
    pattern = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    return pattern.match(string) is not None

def get_local_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_mac_by_ip_address(ip_address: str):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=ip_address)
    packet = ether / arp
    answer = srp1(packet, timeout=1, verbose=0)
    if answer:
        print(answer[Ether])
        return str(answer[Ether].src).upper()
    else:
        return None

def get_country_info(packet: Packet, ip_address: str):
    country_name = "N/A"
    country_iso = "N/A"

    if maxmind_reader:
        try:
            response = maxmind_reader.country(ip_address)
            country_name = str(response.country.name)
            country_iso = str(response.country.iso_code)
        except geoip2.errors.AddressNotFoundError:
            pass

    try:
        country_name = str(packet.ip.geosrc_country)
        country_iso =  str(packet.ip.geosrc_country_iso)
    except AttributeError:
        pass

    return country_name, country_iso

def show_message_box(title: str, message: str, style: Msgbox):
    return ctypes.windll.user32.MessageBoxW(0, message, title, style)

def npcap_or_winpcap_installed():
    try:
        subprocess.check_output(["sc", "query", "npcap"], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        try:
            subprocess.check_output(["sc", "query", "npf"], stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
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
    if MAXMIND_DB_PATH and maxmind_reader is not None:
        maxmind_reader.close()

def reconstruct_settings():
    print("\nCorrect reconstruction of 'Settings.ini' ...")
    with open(SETTINGS_PATH, "w", encoding="utf-8") as file:
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
            ;;<STDOUT_REFRESHING_TIMER>
            ;;Time interval between which this will refresh the console display.
            ;;
            ;;<STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS>
            ;;The maximum number of players showing up in disconnected players list.
            ;;Valid values are any number greater than 0.
            ;;Setting it to 0 will make it unlimitted.
            ;;
            ;;<MAXMIND_DB_PATH>
            ;;The Windows directory (full path) where you store the MaxMind DB *.mmdb files. (optional)
            ;;This is used to resolve countrys from the players.
            ;;
            ;;<INTERFACE_NAME>
            ;;Automatically select this network adapter where the packets are going to be captured from.
            ;;
            ;;<IP_AND_MAC_ADDRESS_AUTOMATIC>
            ;;Determine if you want or not to automaticly detect your <IP_ADDRESS> and <MAC_ADDRESS> addresses.
            ;;
            ;;<IP_ADDRESS>
            ;;Your PC local IP address. You can obtain it like that:
            ;;https://support.microsoft.com/en-us/windows/find-your-ip-address-in-windows-f21a9bbc-c582-55cd-35e0-73431160a1b9
            ;;Valid example value: 'x.x.x.x'
            ;;
            ;;<MAC_ADDRESS>
            ;;Your PC MAC address. You can obtain it from your PC:
            ;;https://support.microsoft.com/en-us/windows/find-your-ip-address-in-windows-f21a9bbc-c582-55cd-35e0-73431160a1b9
            ;;Valid example value:'xx:xx:xx:xx:xx:xx'
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
            ;;-----------------------------------------------------------------------------
            STDOUT_SHOW_HEADER={STDOUT_SHOW_HEADER}
            STDOUT_REFRESHING_TIMER={STDOUT_REFRESHING_TIMER}
            STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS={STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS}
            MAXMIND_DB_PATH={MAXMIND_DB_PATH}
            INTERFACE_NAME={INTERFACE_NAME}
            IP_AND_MAC_ADDRESS_AUTOMATIC={IP_AND_MAC_ADDRESS_AUTOMATIC}
            IP_ADDRESS={IP_ADDRESS}
            MAC_ADDRESS={MAC_ADDRESS}
            BLOCK_THIRD_PARTY_SERVERS={BLOCK_THIRD_PARTY_SERVERS}
            PROGRAM_PRESET={PROGRAM_PRESET}
        """
        text = textwrap.dedent(text).removeprefix("\n")
        file.write(text)

def apply_settings(settings_list: list):
    global need_rewrite_settings, settings_file_not_found

    settings_file_not_found = False
    need_rewrite_settings = False

    try:
        SETTINGS = SETTINGS_PATH.read_text("utf-8").splitlines(keepends=False)
    except FileNotFoundError:
        settings_file_not_found = True
        need_rewrite_settings = True

    for setting in (settings_list):
        def rewrite_settings():
            global need_rewrite_settings

            if need_rewrite_settings is False:
                need_rewrite_settings = True

        def return_setting(setting: str):
            if settings_file_not_found:
                return None

            for line in SETTINGS:
                line: str
                line = line.rstrip("\n")
                corrected_line = line.strip()

                if corrected_line.startswith(";;"):
                    continue

                parts = corrected_line.split("=")
                try:
                    setting_name = parts[0]
                    setting_value = parts[1]
                except IndexError:
                    rewrite_settings()
                    continue

                if not line == corrected_line:
                    rewrite_settings()

                if setting_name == setting:
                    return setting_value

            return None

        global STDOUT_SHOW_HEADER, STDOUT_REFRESHING_TIMER, STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS, MAXMIND_DB_PATH, INTERFACE_NAME, IP_AND_MAC_ADDRESS_AUTOMATIC, IP_ADDRESS, MAC_ADDRESS, BLOCK_THIRD_PARTY_SERVERS, PROGRAM_PRESET

        if setting == "STDOUT_SHOW_HEADER":
            STDOUT_SHOW_HEADER = return_setting(setting)
            if STDOUT_SHOW_HEADER == "True":
                STDOUT_SHOW_HEADER = True
            elif STDOUT_SHOW_HEADER == "False":
                STDOUT_SHOW_HEADER = False
            else:
                rewrite_settings()
                STDOUT_SHOW_HEADER = True
        elif setting == "STDOUT_REFRESHING_TIMER":
            reset_current_setting__flag = False
            try:
                STDOUT_REFRESHING_TIMER = int(return_setting(setting))
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if STDOUT_REFRESHING_TIMER < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                STDOUT_REFRESHING_TIMER = 0
        elif setting == "STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS":
            reset_current_setting__flag = False
            try:
                STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS = int(return_setting(setting))
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS = 6
        elif setting == "MAXMIND_DB_PATH":
            reset_current_setting__flag = False
            MAXMIND_DB_PATH = return_setting(setting)
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
                rewrite_settings()
                MAXMIND_DB_PATH = None
        elif setting == "INTERFACE_NAME":
            INTERFACE_NAME = return_setting(setting)
            if INTERFACE_NAME is None:
                rewrite_settings()
            elif INTERFACE_NAME == "None":
                INTERFACE_NAME = None
        elif setting == "IP_AND_MAC_ADDRESS_AUTOMATIC":
            IP_AND_MAC_ADDRESS_AUTOMATIC = return_setting(setting)
            if IP_AND_MAC_ADDRESS_AUTOMATIC == "True":
                IP_AND_MAC_ADDRESS_AUTOMATIC = True
            elif IP_AND_MAC_ADDRESS_AUTOMATIC == "False":
                IP_AND_MAC_ADDRESS_AUTOMATIC = False
            else:
                rewrite_settings()
                IP_AND_MAC_ADDRESS_AUTOMATIC = True
        elif setting == "IP_ADDRESS":
            reset_current_setting__flag = False
            IP_ADDRESS = return_setting(setting)
            if IP_ADDRESS is None:
                reset_current_setting__flag = True
            elif IP_ADDRESS == "None":
                IP_ADDRESS = None
            else:
                if not is_ip_address(IP_ADDRESS):
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                IP_ADDRESS = None
        elif setting == "MAC_ADDRESS":
            reset_current_setting__flag = False
            MAC_ADDRESS = return_setting(setting)
            if MAC_ADDRESS is None:
                reset_current_setting__flag = True
            elif MAC_ADDRESS == "None":
                MAC_ADDRESS = None
            else:
                if not is_mac_address(MAC_ADDRESS):
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                MAC_ADDRESS = None
        elif setting == "BLOCK_THIRD_PARTY_SERVERS":
            BLOCK_THIRD_PARTY_SERVERS = return_setting(setting)
            if BLOCK_THIRD_PARTY_SERVERS == "True":
                BLOCK_THIRD_PARTY_SERVERS = True
            elif BLOCK_THIRD_PARTY_SERVERS == "False":
                BLOCK_THIRD_PARTY_SERVERS = False
            else:
                rewrite_settings()
                BLOCK_THIRD_PARTY_SERVERS = True
        elif setting == "PROGRAM_PRESET":
            reset_current_setting__flag = False
            PROGRAM_PRESET = return_setting(setting)
            if PROGRAM_PRESET is None:
                reset_current_setting__flag = True
            elif PROGRAM_PRESET == "None":
                PROGRAM_PRESET = None
            else:
                if not PROGRAM_PRESET in ["GTA5", "Minecraft"]:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                PROGRAM_PRESET = None

    if need_rewrite_settings:
        reconstruct_settings()

colorama.init(autoreset=True)
signal.signal(signal.SIGINT, signal_handler)
exit_signal = threading.Event()

if is_pyinstaller_compiled():
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

TITLE = "GTA V Session Sniffer"
VERSION = "v1.0.7 - 24/02/2024"
TITLE_VERSION = f"{TITLE} {VERSION}"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:122.0) Gecko/20100101 Firefox/122.0"
}
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

while not exit_signal.is_set():
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

apply_settings(["STDOUT_SHOW_HEADER", "STDOUT_REFRESHING_TIMER", "STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS", "MAXMIND_DB_PATH", "INTERFACE_NAME", "IP_AND_MAC_ADDRESS_AUTOMATIC", "IP_ADDRESS", "MAC_ADDRESS", "BLOCK_THIRD_PARTY_SERVERS", "PROGRAM_PRESET"])

cls()
title(f"Capture network interface selection - {TITLE}")
print(f"\nCapture network interface selection ...\n")
interfaces = psutil.net_io_counters(pernic=True)

if INTERFACE_NAME in interfaces:
    iface_name = INTERFACE_NAME
else:
    cls()
    print()
    for i, interface_name in enumerate(interfaces):
        print(f"{Fore.YELLOW}{i+1}{Fore.RESET}: {interface_name}")
    print()
    while not exit_signal.is_set():
        try:
            selection = int(input(f"Select your desired capture network interface ({Fore.YELLOW}1{Fore.RESET}-{Fore.YELLOW}{len(interfaces)}{Fore.RESET}): {Fore.YELLOW}"))
        except ValueError:
            print(f"{Fore.RED}ERROR{Fore.RESET}: You didn't provide a number.")
            continue
        if (
            selection >= 1
            and selection <= len(interfaces)
        ):
            break
        print(f"{Fore.RED}ERROR{Fore.RESET}: The number you provided is not matching with the available network interfaces.")
        continue
    iface_name = list(interfaces.keys())[selection-1]

cls()
title(f"Initializing addresses and establishing connection to your PC - {TITLE}")
print(f"\nInitializing addresses and establishing connection to your PC ...\n")

if IP_AND_MAC_ADDRESS_AUTOMATIC:
    old_ip_address = IP_ADDRESS
    old_mac_address = MAC_ADDRESS

    try:
        IP_ADDRESS = get_local_ip_address()
        if IP_ADDRESS == "127.0.0.1":
            raise ValueError("IP address is a loopback address")
        MAC_ADDRESS = get_mac_by_ip_address(IP_ADDRESS)
        if not MAC_ADDRESS:
            raise ValueError("MAC address not found")
    except ValueError:
        IP_ADDRESS = None
        MAC_ADDRESS = None

    if (
        not old_ip_address == IP_ADDRESS
        or not old_mac_address == MAC_ADDRESS
    ):
        reconstruct_settings()

while not exit_signal.is_set():
    if not IP_ADDRESS:
        msgbox_title = TITLE
        msgbox_text = """
        ERROR: Unable to establish connection to your computer's local IP Address.

        Open the file "Settings.ini" and enter your computer's local IP Address in <IP_ADDRESS> setting.
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        show_message_box(msgbox_title, msgbox_text, msgbox_style)
        apply_settings(["IP_ADDRESS", "MAC_ADDRESS"])
    else:
        break

while not exit_signal.is_set():
    if not MAC_ADDRESS:
        msgbox_title = TITLE
        msgbox_text = """
        ERROR: Unable to establish connection to your computer's MAC Address.

        Open the file "Settings.ini" and enter your computer's MAC Address in <MAC_ADDRESS> setting.
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        show_message_box(msgbox_title, msgbox_text, msgbox_style)
        apply_settings(["IP_ADDRESS", "MAC_ADDRESS"])
    else:
        break

BPF_FILTER = f"dst or src host {IP_ADDRESS} and ether dst or src {MAC_ADDRESS} and ip and udp and not broadcast and not multicast and not port 53 and not port 80 and not port 443"
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
    DISPLAY_FILTER = create_or_happen_to_variable(DISPLAY_FILTER, " and ", "not ssdp and not raknet and not dtls and not nbns and not pcp and not bt-dht and not uaudp")

    for server in ThirdPartyServers:
        for ip_range in server.value:
            BPF_FILTER += f" and not net {ip_range}"

while not exit_signal.is_set():
    try:
        capture = pyshark.LiveCapture(
            interface = iface_name,
            bpf_filter = BPF_FILTER,
            display_filter = DISPLAY_FILTER
        )
    except pyshark.tshark.tshark.TSharkNotFoundException:
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

    refreshing_rate_t1 = time.perf_counter()

    while not exit_signal.is_set():
        datetime_now = datetime.now()

        session_connected__padding_counter = session_connected__padding_country = session_connected__padding_ip = 0
        session_disconnected__padding_counter = session_disconnected__padding_country = session_disconnected__padding_ip = 0
        session_connected = []
        session_disconnected = []

        for player in session_db:
            if not player["datetime_left"]:
                if (datetime_now - player["t1"]) > timedelta(seconds=10):
                    player["datetime_left"] = get_formatted_datetime(datetime_now)

            if player["datetime_left"]:
                session_disconnected.append({
                    'datetime_left': player['datetime_left'],
                    'datetime_joined': player['datetime_joined'],
                    'counter': f"{player['counter']}",
                    'country': f"{player['country']}",
                    'ip': f"{player['ip']}",
                    'stdout_port_list': port_list_creation(Fore.RED)
                })
            else:
                session_connected__padding_counter = get_minimum_padding(player["counter"], session_connected__padding_counter, 6)
                session_connected__padding_country = get_minimum_padding(player["country"], session_connected__padding_country, 27)
                session_connected__padding_ip = get_minimum_padding(player["ip"], session_connected__padding_ip, 16)

                session_connected.append({
                    'datetime_joined': player['datetime_joined'],
                    'counter': f"{player['counter']}",
                    'country': f"{player['country']}",
                    'ip': f"{player['ip']}",
                    'stdout_port_list': port_list_creation(Fore.GREEN)
                })

        session_connected = sorted(session_connected, key=itemgetter('datetime_joined'))
        session_disconnected = sorted(session_disconnected, key=itemgetter('datetime_left'))

        session_disconnected__stdout_counter = session_disconnected[-STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS:]

        for player in session_disconnected__stdout_counter:
            session_disconnected__padding_counter = get_minimum_padding(player["counter"], session_disconnected__padding_counter, 6)
            session_disconnected__padding_country = get_minimum_padding(player["country"], session_disconnected__padding_country, 27)
            session_disconnected__padding_ip = get_minimum_padding(player["ip"], session_disconnected__padding_ip, 16)

        if (
            STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS == 0
            or STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS >= len(session_disconnected)
        ):
            len_session_disconnected_message = str(len(session_disconnected))
        else:
            len_session_disconnected_message = f"showing {STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS}/{len(session_disconnected)}"

        cls()
        print("")

        if STDOUT_SHOW_HEADER:
            print(f"-" * 110)
            print(f"{UNDERLINE}Advertising{UNDERLINE_RESET}:")
            print(f"  * https://illegal-services.com/")
            print(f"  * https://github.com/Illegal-Services/PC-Blacklist-Sniffer")
            print(f"  * https://github.com/Illegal-Services/PS3-Blacklist-Sniffer")
            print("")
            print(f"{UNDERLINE}Contact Details{UNDERLINE_RESET}:")
            print(f"    You can contact me from Email: BUZZARDGTA@protonmail.com, Discord: waitingforharukatoaddme or Telegram: https://t.me/mathieudummy")
            print("")

        print(f"-" * 110)
        print(f"                             Welcome in {TITLE_VERSION}")
        print(f"                   This script aims in getting people's address IP from GTA V, WITHOUT MODS.")
        print(f"-" * 110)
        print("")
        print(f"> Player{plural(len(session_connected))} connected in your session ({len(session_connected)}):")
        if len(session_connected) < 1:
            print("None")
        else:
            for player in session_connected:
                print(f"first seen:{Fore.GREEN}{player['datetime_joined']}{Fore.RESET} | counter:{Fore.GREEN}{player['counter']:<{session_connected__padding_counter}}{Fore.RESET} | country:{Fore.GREEN}{player['country']:<{session_connected__padding_country}}{Fore.RESET} | IP:{Fore.GREEN}{player['ip']:<{session_connected__padding_ip}}{Fore.RESET} | Port(s):{Fore.GREEN}{player['stdout_port_list']}{Fore.RESET}")
        print("")
        print(f"> Player{plural(len(session_disconnected))} who've left your session ({len_session_disconnected_message}):")
        if len(session_disconnected) < 1:
            print("None")
        else:
            for player in session_disconnected__stdout_counter:
                print(f"last seen:{Fore.RED}{player['datetime_left']}{Fore.RESET} | first seen:{Fore.RED}{player['datetime_joined']}{Fore.RESET} | counter:{Fore.RED}{player['counter']:<{session_disconnected__padding_counter}}{Fore.RESET} | country:{Fore.RED}{player['country']:<{session_disconnected__padding_country}}{Fore.RESET} | IP:{Fore.RED}{player['ip']:<{session_disconnected__padding_ip}}{Fore.RESET} | Port(s):{Fore.RED}{player['stdout_port_list']}{Fore.RESET}")
        print("")

        while not exit_signal.is_set():
            time.sleep(0.1)

            refreshing_rate_t2 = time.perf_counter()

            seconds_elapsed = round(refreshing_rate_t2 - refreshing_rate_t1)
            if seconds_elapsed <= STDOUT_REFRESHING_TIMER:
                print(f"Scanning IPs, refreshing display in {max(STDOUT_REFRESHING_TIMER - seconds_elapsed, 0)} seconds ...\r", end="")
                time.sleep(1)
                continue

            refreshing_rate_t1 = refreshing_rate_t2
            break

def packet_callback(packet: Packet):
    packet_timestamp = datetime.fromtimestamp(timestamp=float(packet.sniff_timestamp))
    datetime_now = datetime.now()
    if (datetime_now - packet_timestamp) > timedelta(seconds=3):
        raise ValueError(PACKET_CAPTURE_OVERFLOW)

    source_address: str = packet.ip.src
    destination_address: str = packet.ip.dst

    if source_address == IP_ADDRESS:
        target__ip = destination_address
        target__port: int = packet[packet.transport_layer].dstport
        target__country, target__country_iso = get_country_info(packet, destination_address)
    elif destination_address == IP_ADDRESS:
        target__ip = source_address
        target__port: int =  packet[packet.transport_layer].srcport
        target__country, target__country_iso = get_country_info(packet, source_address)
    else:
        return

    # Skip local and private IP Ranges.
    #https://stackoverflow.com/questions/45365482/python-ip-range-to-ip-range-match
    if any(IPv4Address(target__ip) in IPv4Network(ip) for ip in ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"]):
        return

    for player in session_db:
        if player["ip"] == target__ip:
            player["t1"] = packet_timestamp
            player["counter"] += 1
            if player["datetime_left"]:
                player["datetime_left"] = None
            if target__port not in player["ports"]:
                player["ports"].append(target__port)
            if player["last_port"] != target__port:
                player["last_port"] = target__port

            break
    else:
        target = dict(
            t1 = packet_timestamp,
            counter = 1,
            ip = target__ip,
            ports = [target__port],
            country = f"{target__country} ({target__country_iso})",
            datetime_joined = get_formatted_datetime(datetime_now),
            datetime_left = None,
            first_port = target__port,
            last_port = target__port
        )

        session_db.append(target)

cls()
title(TITLE)

stdout_render_core__thread = threading.Thread(target=stdout_render_core)
stdout_render_core__thread.start()

maxmind_reader = initialize_maxmind_reader()

PACKET_CAPTURE_OVERFLOW = "Packet capture time exceeded 3 seconds."

while not exit_signal.is_set():
    try:
        capture.apply_on_packets(callback=packet_callback)
    except Exception as e:
        if not str(e) == PACKET_CAPTURE_OVERFLOW:
            raise
