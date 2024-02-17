#!/usr/bin/env python3

#GTA_V_Session_Sniffer.py

#TODO:
# - create an algo before and new session to find duplicated ip players
# - Add a timer limit for disconnected IPs
#Features I can add later but won't be very useful:
# - Player port counter
# - when someone leaves and come back, trace it with a newline (list)
# explain counter and add packets
# tell it's for 1080/1920 display
# make an online service for username lookup for each platforms

# Standard library imports
import os
import re
import sys
#import uuid
import time
import enum
import socket
import ctypes
#import logging
import textwrap
import ipaddress
import subprocess
import webbrowser
import geoip2.errors
import geoip2.database
#import maxminddb.errors
from pathlib import Path
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

# Third-party library imports
import psutil
import pyshark
import urllib3
import requests
import colorama
from colorama import Fore
from scapy.sendrecv import srp1
from scapy.layers.l2 import ARP
from scapy.layers.inet import Ether

if sys.version_info.major <= 3 and sys.version_info.minor < 9:
    print("To use this script, your Python version must be 3.9 or higher.")
    print("Please note that Python 3.9 is not compatible with Windows versions 7 or lower.")
    sys.exit(0)

def is_pyinstaller_compiled():
    return getattr(sys, 'frozen', False) # Check if the running Python script is compiled using PyInstaller, cx_Freeze or similar

if is_pyinstaller_compiled():
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

colorama.init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.util.ssl_.DEFAULT_CIPHERS += "HIGH:!DH:!aNULL"
s = requests.Session()

#logging.basicConfig(filename='debug.log',
#                    level=logging.DEBUG,
#                    format='%(asctime)s - %(levelname)s - %(message)s',
#                    datefmt='%Y-%m-%d %H:%M:%S')

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

#def get_internet_connected_mac_addresses():
#    mac_addresses = []
#    for interface, addrs in psutil.net_if_addrs().items():
#        stats = psutil.net_io_counters(pernic=True)[interface]
#        if stats.bytes_sent > 0 or stats.bytes_recv > 0:
#            if socket.gethostname() != 'localhost':
#                for addr in addrs:
#                    if addr.family == psutil.AF_LINK:
#                        mac_addresses.append(addr.address)
#    return mac_addresses

#def get_mac_address():
#    mac_address = hex(uuid.getnode()).replace("0x", "").upper()
#    if len(mac_address) % 2:
#        mac_address = "0{}".format(mac_address)
#    return ":".join(mac_address[i:i+2] for i in range(0, len(mac_address), 2))

def get_country_info_from_ip(ip_address: str):
    if MAXMIND_DB_PATH is None:
        return "N/A", "N/A"

    with geoip2.database.Reader(f"{MAXMIND_DB_PATH}") as reader:
        try:
            response = reader.country(ip_address)
            country_name = response.country.name
            country_iso = response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            country_name = "N/A"
            country_iso = "N/A"

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

def happen_to_display_filter(string_to_happen: str):
    if DISPLAY_FILTER:
        return f"{DISPLAY_FILTER} and {string_to_happen}"
    else:
        return string_to_happen


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
            ;;
            ;;<REFRESHING_TIMER>
            ;;Time interval between which this will refresh the console display.
            ;;
            ;;<COUNTER_SESSION_DISCONNECTED_PLAYERS>
            ;;The maximum number of players showing up in disconnected players.
            ;;
            ;;<PYSHARK_PACKET_COUNT>
            ;;The chosen number of packet counted in the Python pyshark module.
            ;;Valid values are any number greater than 0.
            ;;Setting it to '0' will make it unlimitted.
            ;;Be aware that this is not recommended because when you are looking for many IPs at the same time,
            ;;the script will take longer to scan the IPs as the IPs will keep coming in at the same time,
            ;;which will cause the information provided by the script to be updated later than they should.
            ;;-----------------------------------------------------------------------------
            STDOUT_SHOW_HEADER={STDOUT_SHOW_HEADER}
            MAXMIND_DB_PATH={MAXMIND_DB_PATH}
            INTERFACE_NAME={INTERFACE_NAME}
            IP_AND_MAC_ADDRESS_AUTOMATIC={IP_AND_MAC_ADDRESS_AUTOMATIC}
            IP_ADDRESS={IP_ADDRESS}
            MAC_ADDRESS={MAC_ADDRESS}
            REFRESHING_TIMER={REFRESHING_TIMER}
            COUNTER_SESSION_DISCONNECTED_PLAYERS={COUNTER_SESSION_DISCONNECTED_PLAYERS}
            BLOCK_THIRD_PARTY_SERVERS={BLOCK_THIRD_PARTY_SERVERS}
            PROGRAM_PRESET={PROGRAM_PRESET}
            PYSHARK_PACKET_COUNT={PYSHARK_PACKET_COUNT}
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

        global STDOUT_SHOW_HEADER, MAXMIND_DB_PATH, INTERFACE_NAME, IP_AND_MAC_ADDRESS_AUTOMATIC, IP_ADDRESS, MAC_ADDRESS, BLOCK_THIRD_PARTY_SERVERS, PROGRAM_PRESET, REFRESHING_TIMER, COUNTER_SESSION_DISCONNECTED_PLAYERS, PYSHARK_PACKET_COUNT

        if setting == "STDOUT_SHOW_HEADER":
            STDOUT_SHOW_HEADER = return_setting(setting)
            if STDOUT_SHOW_HEADER == "True":
                STDOUT_SHOW_HEADER = True
            elif STDOUT_SHOW_HEADER == "False":
                STDOUT_SHOW_HEADER = False
            else:
                rewrite_settings()
                STDOUT_SHOW_HEADER = True
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
        elif setting == "REFRESHING_TIMER":
            reset_current_setting__flag = False
            try:
                REFRESHING_TIMER = int(return_setting(setting))
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if REFRESHING_TIMER < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                REFRESHING_TIMER = 0
        elif setting == "COUNTER_SESSION_DISCONNECTED_PLAYERS":
            reset_current_setting__flag = False
            try:
                COUNTER_SESSION_DISCONNECTED_PLAYERS = int(return_setting(setting))
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if COUNTER_SESSION_DISCONNECTED_PLAYERS < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                COUNTER_SESSION_DISCONNECTED_PLAYERS = 0
        elif setting == "PYSHARK_PACKET_COUNT":
            reset_current_setting__flag = False
            try:
                PYSHARK_PACKET_COUNT = int(return_setting(setting))
            except (ValueError, TypeError):
                reset_current_setting__flag = True
            else:
                if PYSHARK_PACKET_COUNT < 0:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                rewrite_settings()
                PYSHARK_PACKET_COUNT = 30

    if need_rewrite_settings:
        reconstruct_settings()

def datetime_now():
    return datetime.now().strftime("%Y/%m/%d %H:%M:%S")

def stdout_header():
    if STDOUT_SHOW_HEADER:
        print(f"")
        print(f"-" * 131)
        print(f"{UNDERLINE}Tips and Tricks{UNDERLINE_RESET}:")
        print(f"  * When using {TITLE}:")
        print(f"    - By entering story mode (optional) and then joining your friend's session, you can easily get their host IP address.")
        print(f"    - If somebody leaves the session, you can get their IP from players who've left your session")
        print(f"    - One way to get someone's IP address is to save all IP addresses for the current session while they're in your session.")
        print(f"      When you find that person in another session, do the same thing and compare the registered IP addresses, if an IP address matches, it means you have their IP address.")
        print(f"    - The port in [brackets] is the first detected, while the {UNDERLINE}underlined{UNDERLINE_RESET} is the last detected.")
        print(f"  * If the Host of a session suddenly loose it's internet access, it will cause a \"session split\"* which, most of the time result in a mess of the lobby.")
        print(f"  * The game port is \"6672\", unfortunately I don't have any clue what the other ports mean.")
        print(f"  * If you want to know more informations about a specific IP or Port, I'd recommend you to checkout the Illegal Services application IP Lookup / Port Scanning.")
        print(f"    It has a very good IP Lookup that can also find out VPN, Mobile connections etc.")
        print(f"    You can find Illegal Services website in my advertisements bellow.")
        print(f"  * Using 'PC Blacklist Sniffer' allows you to detect people you blacklisted from your sessions (link in my advertisements bellow).")
        print(f"")
        print(f"{UNDERLINE}Lexicon{UNDERLINE_RESET}:")
        print(f"  * \"Session Split\":")
        print(f"      The person hosting the session suddenly loses internet access (Example: DDoS)")
        print(f"      A new host will be automatically selected from the players who are already in the session.")
        print(f"      During this new host selection process, some players may be kicked out of the lobby, leaving them alone in their new session.")
        print(f"")
        print(f"{UNDERLINE}Common Problems{UNDERLINE_RESET}:")
        print(f"  * If the scanner is stuck, that either means:")
        print(f"    - You are not in an online session with at least 2 players.")
        print(f"    - You didn't set up {TITLE} correctly.")
        print(f"      Make sure this values are right: [Local IP:{IP_ADDRESS}], [MAC IP:{MAC_ADDRESS}]")
        print(f"  * {TITLE} does not scan for usernames because I believe it's impossible, let me know if I'm wrong. Contact details below.")
        print(f"  * It is possible that IPs not related to \"GTAV.exe\" executable be displayed.") # https://stackoverflow.com/questions/1339691/filter-by-process-pid-in-wireshark
        print(f"    I tried my possible with \"BPF_FILTER\" and \"DISPLAY_FILTER\" to make this scenario rare.")
        print(f"  * Refreshing (clear screen) the display from \"cmd.exe\" positions your command prompt cursor at the very bottom of the script.")
        print(f"    This problem is kind of resolved if you are using Windows Terminal from Windows 10 or 11")
        print(f"")
        print(f"{UNDERLINE}Advertising{UNDERLINE_RESET}:")
        print(f"  * https://illegal-services.com/")
        print(f"  * https://github.com/Illegal-Services/PS3-Blacklist-Sniffer")
        print(f"  * https://github.com/Illegal-Services/PC-Blacklist-Sniffer")
        print(f"")
        print(f"{UNDERLINE}Contact Details{UNDERLINE_RESET}:")
        print(f"    You can contact me from Email: BUZZARDGTA@protonmail.com, Discord: waitingforharukatoaddme or Telegram: https://t.me/mathieudummy")

    print(f"-" * 131)
    print(f"                                       Welcome in {TITLE_VERSION}")
    print(f"                            This script aims in getting people's address IP from GTA V, WITHOUT MODS.")
    print(f"-" * 131)

def stdout_scanning_ips_from_your_session(t1: float):
    t2 = time.perf_counter()
    seconds_elapsed = round(t2 - t1)
    if seconds_elapsed < 5:
        print(f"Scanning IPs, refreshing display in {REFRESHING_TIMER - seconds_elapsed} seconds ...\r", end="")

TITLE = "GTA V Session Sniffer"
VERSION = "v1.0.4 - 18/02/2024"
TITLE_VERSION = f"{TITLE} {VERSION}"

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

apply_settings(["STDOUT_SHOW_HEADER", "MAXMIND_DB_PATH", "INTERFACE_NAME", "IP_AND_MAC_ADDRESS_AUTOMATIC", "IP_ADDRESS", "MAC_ADDRESS", "BLOCK_THIRD_PARTY_SERVERS", "PROGRAM_PRESET", "REFRESHING_TIMER", "COUNTER_SESSION_DISCONNECTED_PLAYERS", "PYSHARK_PACKET_COUNT"])

cls()
title(f"Capture network interface selection - {TITLE}")
print(f"\nCapture network interface selection ...\n")
interfaces = psutil.net_io_counters(pernic=True)

if INTERFACE_NAME in interfaces:
    iface_name = INTERFACE_NAME
else:
    cls()
    print()
    for i, item in enumerate(interfaces):
        print(f"{Fore.YELLOW}{i+1}{Fore.RESET}: {item}")
    print()
    while True:
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

while True:
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

while True:
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
        DISPLAY_FILTER = happen_to_display_filter("frame.len>=71 and frame.len<=999")
    elif PROGRAM_PRESET == "Minecraft":
        DISPLAY_FILTER = happen_to_display_filter("frame.len>=49 and frame.len<=1498")

    # If the 'PROGRAM_PRESET' setting is set, automatically block RTCP connections.
    # In case RTCP can be useful to get someone IP, I decided not to block them without using a 'PROGRAM_PRESET'.
    # RTCP is known to be for example the Discord's server IP while you are in a call there.
    # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
    # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
    # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
    # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
    DISPLAY_FILTER = happen_to_display_filter("not rtcp")

if BLOCK_THIRD_PARTY_SERVERS:
    # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
    # But there can be a lot more, those are just a couples I could find on my own usage.
    DISPLAY_FILTER = happen_to_display_filter("not ssdp and not raknet and not dtls and not nbns and not pcp and not bt-dht and not uaudp")

    ip_ranges_blocking_list = []

    for server in ThirdPartyServers:
        for ip_range in server.value:
            if ip_range not in ip_ranges_blocking_list:
                ip_ranges_blocking_list.append(ip_range)

    if ip_ranges_blocking_list:
        BPF_FILTER += f" and not net {' and not net '.join(ip_ranges_blocking_list)}"

while True:
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

cls()
title(TITLE)
stdout_header()
print("\n> Players connected in your session (0):")
print("None")
print("\n> Player who've left your session (0):")
print("None")
print("")
refreshing_rate_t1 = time.perf_counter()
stdout_scanning_ips_from_your_session(refreshing_rate_t1)

while True:
    time.sleep(0.1)
    for packet in capture.sniff_continuously():
        def padding(connection_type: str):
            def get_minimum_padding(var: str, max_padding: int, padding: int):

                current_padding = len(str(var))
                if current_padding <= padding:
                    if current_padding > max_padding:
                        max_padding = current_padding

                return max_padding

            def port_list_creation(color: str):
                global stdout_port_list

                stdout_port_list = ""
                for port in player["port"]:
                    to_add_in_portlist = ""
                    if port == player["first_port"]:
                        if port == player["last_port"]:
                            to_add_in_portlist = f"[{UNDERLINE}{port}{UNDERLINE_RESET}]"
                        else:
                            to_add_in_portlist = f"[{port}]"
                    elif port == player["last_port"]:
                        to_add_in_portlist = f"{UNDERLINE}{port}{UNDERLINE_RESET}"
                    else:
                        to_add_in_portlist = f"{port}"

                    if stdout_port_list:
                        stdout_port_list += f", {color}{to_add_in_portlist}{Fore.RESET}"
                    else:
                        stdout_port_list += f"{color}{to_add_in_portlist}{Fore.RESET}"

            padding_counter = padding_country = padding_ip = 0

            if connection_type == "connected":
                for player in session_db:
                    if not player["datetime_left"]:
                        padding_counter = get_minimum_padding(player["counter"], padding_counter, 6)
                        padding_country = get_minimum_padding(player["country"], padding_country, 27)
                        padding_ip = get_minimum_padding(player["ip"], padding_ip, 16)
            else:
                for player in session_db:
                    if player["datetime_left"]:
                        padding_counter = get_minimum_padding(player["counter"], padding_counter, 6)
                        padding_country = get_minimum_padding(player["country"], padding_country, 27)
                        padding_ip = get_minimum_padding(player["ip"], padding_ip, 16)

            for player in session_db:
                if connection_type == "connected":
                    if not player["datetime_left"]:
                        port_list_creation(Fore.GREEN)
                        session_connected.append((player['datetime_joined'], f"{player['counter']:<{padding_counter}}", f"{player['country']:<{padding_country}}", f"{player['ip']:<{padding_ip}}", stdout_port_list))
                else:
                    if player["datetime_left"]:
                        port_list_creation(Fore.RED)
                        session_disconnected.append((player['datetime_left'], player['datetime_joined'], f"{player['counter']:<{padding_counter}}", f"{player['country']:<{padding_country}}", f"{player['ip']:<{padding_ip}}", stdout_port_list))

        stdout_scanning_ips_from_your_session(refreshing_rate_t1)

        #TODO: ADD packet len
        #print(packet[packet.transport_layer].field_names)
        #print(packet[packet.transport_layer].length)
        #print(packet[packet.transport_layer].checksum)
        #print(packet[packet.transport_layer].checksum_status)
        #print(packet[packet.transport_layer].stream)
        #-----------------------------------------------------
        #print(packet.ip.field_names)
        #print(packet.ip.version)
        #print(packet.ip.hdr_len)
        #print(packet.ip.dsfield)
        #print(packet.ip.dsfield_dscp)
        #print(packet.ip.dsfield_ecn)
        #print(packet.ip.len)
        #print(packet.ip.id)
        #print(packet.ip.flags)
        #print(packet.ip.flags_rb)
        #print(packet.ip.flags_df)
        #print(packet.ip.flags_mf)
        #print(packet.ip.frag_offset)
        #print(packet.ip.ttl)
        #print(packet.ip.proto)
        #print(packet.ip.checksum)
        #print(packet.ip.checksum_status)
        #-----------------------------------------------------
        #input()

        # This piece of code should be useless because the "not rtcp" Display Filter already filter those, and faster.
        # (I did a test that confirms it is indeed useless to filter them again after the "not rtcp" Display Filter.)
        # Also, if the 'PROGRAM_PRESET' is set to None, we do NOT want to filter RTCP.
        ## Skip Real-time Control Protocol (RTCP)
        ## RTCP is used together with RTP e.g. for VoIP (see also VOIPProtocolFamily).
        ## Block for example Discord IPs while you're in a voice call.
        #if getattr(packet, "rtcp", False):
        #    continue

        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        try:
            source_country = packet.ip.geosrc_country
            source_country_iso = packet.ip.geosrc_country_iso
        except AttributeError:
            source_country, source_country_iso = get_country_info_from_ip(source_address)
        try:
            destination_country = packet.ip.geodst_country
            destination_country_iso = packet.ip.geodst_country_iso
        except AttributeError:
            destination_country, destination_country_iso = get_country_info_from_ip(destination_address)

        if source_address == IP_ADDRESS:
            target = dict(
                direction = "dst",
                ip = destination_address,
                port = [destination_port],
                country = f"{destination_country} ({destination_country_iso})"
            )
        else:
            target = dict(
                direction = "src",
                ip = source_address,
                port = [source_port],
                country = f"{source_country} ({source_country_iso})"
            )

        # Skip local and private IP Ranges.
        #https://stackoverflow.com/questions/45365482/python-ip-range-to-ip-range-match
        if any(IPv4Address(target["ip"]) in IPv4Network(ip) for ip in ["10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"]):
            continue

        t2 = time.perf_counter()
        if any(target["ip"] == player["ip"] for player in session_db):
            for player in session_db:
                if target["ip"] == player["ip"]:
                    player["counter"] += 1
                    player["t1"] = time.perf_counter()
                    if not target["port"][0] in player["port"]:
                        player["port"].append(target["port"][0])
                    if not player["last_port"] == target["port"][0]:
                        player["last_port"] = target["port"][0]
                    if player["datetime_left"]:
                        player["datetime_left"] = None
                    break
        else:
            target["counter"] = 1
            target["datetime_joined"] = datetime_now()
            target["datetime_left"] =  None
            target["first_port"] = target["port"][0]
            target["last_port"] = target["port"][0]
            target["t1"] = time.perf_counter()
            session_db.append(target)

        seconds_elapsed = round(t2 - refreshing_rate_t1)
        if seconds_elapsed <= REFRESHING_TIMER:
            continue
        refreshing_rate_t1 = time.perf_counter()

        session_connected = []
        session_disconnected = []

        for player in session_db:
            if not player["datetime_left"]:
                seconds_elapsed = round(t2 - player["t1"])
                if seconds_elapsed >= 10:
                    player["datetime_left"] = datetime_now()

        padding("connected")
        padding("disconnected")

        cls()
        stdout_header()
        print("")
        print(f"> Player{plural(len(session_connected))} connected in your session ({len(session_connected)}):")
        if len(session_connected) < 1:
            print("None")
        else:
            #https://stackoverflow.com/questions/57873530/how-to-sort-a-list-by-datetime-in-python#57873719
            for item in sorted(session_connected, key=lambda t: datetime.strptime(t[0], "%Y/%m/%d %H:%M:%S")):
                print(f"first seen:{Fore.GREEN}{item[0]}{Fore.RESET} | counter:{Fore.GREEN}{item[1]}{Fore.RESET} | country:{Fore.GREEN}{item[2]}{Fore.RESET} | IP:{Fore.GREEN}{item[3]}{Fore.RESET} | Port(s):{Fore.GREEN}{item[4]}{Fore.RESET}")
        if COUNTER_SESSION_DISCONNECTED_PLAYERS:
            if COUNTER_SESSION_DISCONNECTED_PLAYERS > len(session_disconnected):
                len_session_disconnected = len(session_disconnected)
            else:
                len_session_disconnected = f"showing {COUNTER_SESSION_DISCONNECTED_PLAYERS}/{len(session_disconnected)}"
        else:
            len_session_disconnected = len(session_disconnected)
        print("")
        print(f"> Player{plural(len(session_disconnected))} who've left your session ({len_session_disconnected}):")
        if len(session_disconnected) < 1:
            print("None")
            print("")
        else:
            if COUNTER_SESSION_DISCONNECTED_PLAYERS:
                session_disconnected_players = session_disconnected[-COUNTER_SESSION_DISCONNECTED_PLAYERS:]
            else:
                session_disconnected_players = session_disconnected
            #https://stackoverflow.com/questions/57873530/how-to-sort-a-list-by-datetime-in-python#57873719
            for item in sorted(session_disconnected_players, key=lambda t: datetime.strptime(t[0], "%Y/%m/%d %H:%M:%S")):
                print(f"last seen:{Fore.RED}{item[0]}{Fore.RESET} | first seen:{Fore.RED}{item[1]}{Fore.RESET} | counter:{Fore.RED}{item[2]}{Fore.RESET} | country:{Fore.RED}{item[3]}{Fore.RESET} | IP:{Fore.RED}{item[4]}{Fore.RESET} | Port(s):{Fore.RED}{item[5]}{Fore.RESET}")
            print("")

        stdout_scanning_ips_from_your_session(refreshing_rate_t1)
