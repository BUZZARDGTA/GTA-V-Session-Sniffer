# --------------------------------------------
# 📦 External/Third-party Python Libraries 📦
# --------------------------------------------
import wmi
import psutil
import colorama
import geoip2.errors
import geoip2.database
from colorama import Fore
from wmi import _wmi_namespace, _wmi_object
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from prettytable import PrettyTable, SINGLE_BORDER
from capture.sync_capture import PacketCapture, Packet, TSharkNotFoundException

# ------------------------------------------------------
# 🐍 Standard Python Libraries (Included by Default) 🐍
# ------------------------------------------------------
import os
import re
import sys
import json
import time
import enum
import socket
import ctypes
import signal
import logging
import textwrap
import threading
import subprocess
import webbrowser
from pathlib import Path
from types import FrameType
from operator import attrgetter
from ipaddress import IPv4Address
from typing import Optional
from datetime import datetime, timedelta
from json.decoder import JSONDecodeError


if sys.version_info.major <= 3 and sys.version_info.minor < 9:
    print("To use this script, your Python version must be 3.9 or higher.")
    print("Please note that Python 3.9 is not compatible with Windows versions 7 or lower.")
    sys.exit(0)

logging.basicConfig(filename="debug.log",
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class InvalidBooleanValueError(Exception):
    pass

class InvalidNoneTypeValueError(Exception):
    pass

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
            self._date_time = datetime.strptime(version[9:27], "%d/%m/%Y (%H:%M)")
        else:
            self.time = None
            self._date_time = datetime.strptime(version[9:19], "%d/%m/%Y")

    def __str__(self):
        return f"v{self.major}.{self.minor}.{self.patch} - {self.date}{f' ({self.time})' if self.time else ''}"

class Updater:
    def __init__(self, current_version: Version):
        self.current_version = current_version

    def check_for_update(self, latest_version: Version):
        # Check if the latest version is newer than the current version
        if (latest_version.major, latest_version.minor, latest_version.patch) > (self.current_version.major, self.current_version.minor, self.current_version.patch):
            return True
        elif (latest_version.major, latest_version.minor, latest_version.patch) == (self.current_version.major, self.current_version.minor, self.current_version.patch):
            # Compare date and time if versioning is equal
            if latest_version._date_time > self.current_version._date_time:
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

class Settings:
    TSHARK_PATH = None
    STDOUT_SHOW_ADVERTISING = True
    STDOUT_FIELD_SHOW_SEEN_DATE = False
    STDOUT_FIELD_SESSION_CONNECTED_PLAYERS_SORTED_BY = "First Seen"
    STDOUT_FIELD_SESSION_DISCONNECTED_PLAYERS_SORTED_BY = "Last Seen"
    STDOUT_FIELD_PPS_TIMER = 1.0
    STDOUT_GLOBAL_PPS_TIMER = 1.0
    STDOUT_RESET_INFOS_ON_CONNECTED = True
    STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS = 6
    STDOUT_REFRESHING_TIMER = 3
    PLAYER_DISCONNECTED_TIMER = 6.0
    PACKET_CAPTURE_OVERFLOW_TIMER = 3.0
    NETWORK_INTERFACE_CONNECTION_PROMPT = True
    INTERFACE_NAME = None
    IP_ADDRESS = None
    MAC_ADDRESS = None
    ARP = True
    BLOCK_THIRD_PARTY_SERVERS = True
    PROGRAM_PRESET = None
    VPN_MODE = False

    _allowed_settings_types = (Path, str, int, bool, float, type(None))

    _stdout_fields_mapping = {
        "First Seen": "datetime_first_seen",
        "Last Seen": "datetime_last_seen",
        "Packets": "packets",
        "PPS": "packets_per_second",
        "IP Address": "ip",
        "Ports": "ports",
        "Country": "country_name",
        "City": "city",
        "Asn": "asn"
    }

    @classmethod
    def iterate_over_settings(cls):
        for attr_name in vars(cls):
            attr_value = getattr(cls, attr_name)

            if (
                attr_name.startswith("_")
                or callable(attr_value)
                or not isinstance(attr_value, Settings._allowed_settings_types)
            ):
                continue

            yield attr_name, attr_value

    @classmethod
    def get_settings_length(cls):
        return sum(1 for _ in cls.iterate_over_settings())

    @classmethod
    def has_setting(cls, setting_name):
        return hasattr(cls, setting_name)

    def reconstruct_settings():
        print("\nCorrect reconstruction of \"Settings.ini\" ...")
        text = f"""
            ;;-----------------------------------------------------------------------------
            ;;Lines starting with \";;\" symbols are commented lines.
            ;;
            ;;This is the settings file for \"GTA V Session Sniffer\" configuration.
            ;;
            ;;If you don't know what value to choose for a specifc setting, set it's value to None.
            ;;The program will automatically analyzes this file and if needed will regenerate it if it contains errors.
            ;;
            ;;<TSHARK_PATH>
            ;;The full path to your "tshark.exe" executable.
            ;;If not set, it will attempt to detect tshark from your Wireshark installation.
            ;;
            ;;<STDOUT_SHOW_ADVERTISING>
            ;;Determine if you want or not to show the developer's advertisements in the script's display.
            ;;
            ;;<STDOUT_FIELD_SHOW_SEEN_DATE>
            ;;Shows or not the date from which a player has been captured in \"First Seen\" and \"Last Seen\" fields.
            ;;
            ;;<STDOUT_FIELD_SESSION_CONNECTED_PLAYERS_SORTED_BY>
            ;;Specifies the fields from the connected players by which you want the output data to be sorted.
            ;;Valid values include any field names. For example: First Seen
            ;;
            ;;<STDOUT_FIELD_SESSION_DISCONNECTED_PLAYERS_SORTED_BY>
            ;;Specifies the fields from the disconnected players by which you want the output data to be sorted.
            ;;Valid values include any field names. For example: First Seen
            ;;
            ;;<STDOUT_FIELD_PPS_TIMER>
            ;;The Packets Per Second (PPS) time interval calculated for each player.
            ;;
            ;;<STDOUT_GLOBAL_PPS_TIMER>
            ;;The global Packets Per Second (PPS) time interval calculated for all players combined.
            ;;
            ;;<STDOUT_RESET_INFOS_ON_CONNECTED>
            ;;Resets and recalculates each fields for players who were previously disconnected.
            ;;
            ;;<STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS>
            ;;The maximum number of players showing up in disconnected players list.
            ;;Valid values include any number greater than or equal to 0.
            ;;Setting it to 0 will make it unlimitted.
            ;;
            ;;<STDOUT_REFRESHING_TIMER>
            ;;Time interval between which this will refresh the console display.
            ;;
            ;;<PLAYER_DISCONNECTED_TIMER>
            ;;The duration after which a player will be moved as disconnected on the console if no packets are received within this time.
            ;;Valid values include any number greater than or equal to 3.
            ;;
            ;;<PACKET_CAPTURE_OVERFLOW_TIMER>
            ;;This timer represents the duration between the timestamp of a captured packet and the current time.
            ;;When this timer is reached, the tshark process will be restarted.
            ;;Valid values include any number greater than or equal to 3.
            ;;
            ;;<NETWORK_INTERFACE_CONNECTION_PROMPT>
            ;;Allows you to skip the network interface selection by automatically
            ;;using the <INTERFACE_NAME>, <MAC_ADDRESS> and <IP_ADDRESS> settings.
            ;;
            ;;<INTERFACE_NAME>
            ;;The network interface from which packets will be captured.
            ;;
            ;;<IP_ADDRESS>
            ;;The IP address of a network interface on your computer from which packets will be captured.
            ;;If the <ARP> setting is enabled, it can be from any device on your home network.
            ;;Valid example value: \"x.x.x.x\"
            ;;
            ;;<MAC_ADDRESS>
            ;;The MAC address of a network interface on your computer from which packets will be captured.
            ;;If the <ARP> setting is enabled, it can be from any device on your home network.
            ;;Valid example value: \"xx:xx:xx:xx:xx:xx\" or \"xx-xx-xx-xx-xx-xx\"
            ;;
            ;;<ARP>
            ;;Allows you to capture from devices located outside your computer but within your home network, such as gaming consoles.
            ;;
            ;;<BLOCK_THIRD_PARTY_SERVERS>
            ;;Determine if you want or not to block the annoying IP ranges from servers that shouldn't be detected.
            ;;
            ;;<PROGRAM_PRESET>
            ;;A program preset that will help capturing the right packets for your program.
            ;;Supported program presets are only \"GTA5\" and \"Minecraft\".
            ;;Note that Minecraft only supports Bedrock Edition.
            ;;Please also note that both of these have only been tested on PCs.
            ;;I do not have information regarding their functionality on consoles.
            ;;
            ;;<VPN_MODE>
            ;;Setting this to False will add filters to exclude unrelated IPs from the output.
            ;;However, if you are scanning trough a VPN <INTERFACE_NAME>, you have to set it to True.
            ;;-----------------------------------------------------------------------------
        """
        text = textwrap.dedent(text.removeprefix("\n"))
        for setting_name, setting_value in Settings.iterate_over_settings():
            text += f"{setting_name}={setting_value}\n"
        SETTINGS_PATH.write_text(text, encoding="utf-8")

    def load_from_file(settings_path: Path):
        def iterate_and_parse_settings_file_data(settings_data: str):
            def process_setting_line_output(line: str):
                return line.rstrip("\n")

            for line in map(process_setting_line_output, settings_data):
                need_rewrite_current_setting = False

                corrected__line = line.strip()

                if corrected__line.startswith(";;"):
                    continue
                elif not corrected__line == line:
                    need_rewrite_current_setting = True

                parts = corrected__line.split("=", 1)
                try:
                    setting_name = parts[0]
                    setting_value = parts[1]
                except IndexError:
                    continue

                corrected__setting_name = setting_name.strip()
                if corrected__setting_name == "":
                    continue
                elif not corrected__setting_name == setting_name:
                    need_rewrite_current_setting = True

                if Settings.has_setting(corrected__setting_name):
                    corrected__setting_value = setting_value.strip()

                    if corrected__setting_value == "":
                        continue
                    elif not corrected__setting_value == setting_value:
                        need_rewrite_current_setting = True

                    yield corrected__setting_name, corrected__setting_value, need_rewrite_current_setting

        def custom_str_to_bool(string: str):
            """
            This function returns the boolean value represented by the string for lowercase or any case variation;\n
            otherwise, it raises an \"InvalidBooleanValueError\".

            Args:
                string (str): The boolean string to be checked.
            """
            string_lower = string.lower()
            need_rewrite_current_setting = False

            if string_lower == "true":
                if not string == "True":
                    need_rewrite_current_setting = True
                value = True
            elif string_lower == "false":
                if not string == "False":
                    need_rewrite_current_setting = True
                value = False
            else:
                raise InvalidBooleanValueError("Input is not a valid boolean value")

            return value, need_rewrite_current_setting

        def custom_str_to_nonetype(string: str):
            """
            This function returns the NoneType value represented by the string for lowercase or any case variation;\n
            otherwise, it raises an \"InvalidNoneTypeValueError\".

            Args:
                string (str): The NoneType string to be checked.
            """
            string_lower = string.lower()
            need_rewrite_current_setting = False

            if string_lower == "none":
                if not string == "None":
                    need_rewrite_current_setting = True
                value = None
            else:
                raise InvalidNoneTypeValueError("Input is not a valid NoneType value")

            return value, need_rewrite_current_setting

        try:
            settings_data = settings_path.read_text("utf-8").splitlines(keepends=False)
        except FileNotFoundError:
            need_rewrite_settings = True
        else:
            need_rewrite_settings = False
            matched_settings_count = 0

            for setting_name, setting_value, need_rewrite_current_setting in iterate_and_parse_settings_file_data(settings_data):
                matched_settings_count += 1

                if need_rewrite_current_setting:
                    need_rewrite_settings = True

                if setting_name == "TSHARK_PATH":
                    try:
                        Settings.TSHARK_PATH, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.TSHARK_PATH = Path(setting_value)
                elif setting_name == "STDOUT_SHOW_ADVERTISING":
                    try:
                        Settings.STDOUT_SHOW_ADVERTISING, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_SHOW_SEEN_DATE":
                    try:
                        Settings.STDOUT_FIELD_SHOW_SEEN_DATE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_SESSION_CONNECTED_PLAYERS_SORTED_BY":
                    if setting_value in Settings._stdout_fields_mapping.keys():
                        Settings.STDOUT_FIELD_SESSION_CONNECTED_PLAYERS_SORTED_BY = setting_value
                    else:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_SESSION_DISCONNECTED_PLAYERS_SORTED_BY":
                    if setting_value in Settings._stdout_fields_mapping.keys():
                        Settings.STDOUT_FIELD_SESSION_DISCONNECTED_PLAYERS_SORTED_BY = setting_value
                    else:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_PPS_TIMER":
                    try:
                        stdout_field_pps_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if stdout_field_pps_timer >= 1.0:
                            Settings.STDOUT_FIELD_PPS_TIMER = stdout_field_pps_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_GLOBAL_PPS_TIMER":
                    try:
                        stdout_global_pps_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if stdout_global_pps_timer >= 1.0:
                            Settings.STDOUT_GLOBAL_PPS_TIMER = stdout_global_pps_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_RESET_INFOS_ON_CONNECTED":
                    try:
                        Settings.STDOUT_RESET_INFOS_ON_CONNECTED, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS":
                    try:
                        stdout_counter_session_disconnected_players = int(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if stdout_counter_session_disconnected_players >= 0:
                            Settings.STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS = stdout_counter_session_disconnected_players
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_REFRESHING_TIMER":
                    try:
                        if "." in setting_value:
                            stdout_refreshing_timer = float(setting_value)
                        else:
                            stdout_refreshing_timer = int(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if stdout_refreshing_timer >= 0:
                            Settings.STDOUT_REFRESHING_TIMER = stdout_refreshing_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == "PLAYER_DISCONNECTED_TIMER":
                    try:
                        player_disconnected_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if player_disconnected_timer >= 3.0:
                            Settings.PLAYER_DISCONNECTED_TIMER = player_disconnected_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == "PACKET_CAPTURE_OVERFLOW_TIMER":
                    try:
                        packet_capture_overflow_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if packet_capture_overflow_timer >= 1:
                            Settings.PACKET_CAPTURE_OVERFLOW_TIMER = packet_capture_overflow_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == "NETWORK_INTERFACE_CONNECTION_PROMPT":
                    try:
                        Settings.NETWORK_INTERFACE_CONNECTION_PROMPT, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "INTERFACE_NAME":
                    if setting_value == "None":
                        Settings.INTERFACE_NAME = None
                    else:
                        Settings.INTERFACE_NAME = setting_value
                elif setting_name == "IP_ADDRESS":
                    if setting_value == "None":
                        Settings.IP_ADDRESS = None
                    elif is_ipv4_address(setting_value):
                        Settings.IP_ADDRESS = setting_value
                    else:
                        need_rewrite_settings = True
                elif setting_name == "MAC_ADDRESS":
                    if setting_value == "None":
                        Settings.MAC_ADDRESS = None
                    elif is_mac_address(setting_value):
                        formatted_mac_address = format_mac_address(setting_value)
                        if not formatted_mac_address == setting_value:
                            need_rewrite_settings = True
                        Settings.MAC_ADDRESS = formatted_mac_address
                    else:
                        need_rewrite_settings = True
                elif setting_name == "ARP":
                    try:
                        Settings.ARP, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "BLOCK_THIRD_PARTY_SERVERS":
                    try:
                        Settings.BLOCK_THIRD_PARTY_SERVERS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "PROGRAM_PRESET":
                    try:
                        Settings.PROGRAM_PRESET, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        if setting_value in ["GTA5", "Minecraft"]:
                            Settings.PROGRAM_PRESET = setting_value
                        else:
                            need_rewrite_settings = True
                elif setting_name == "VPN_MODE":
                    try:
                        Settings.VPN_MODE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True

            if not matched_settings_count == Settings.get_settings_length():
                need_rewrite_settings = True

        if need_rewrite_settings:
            Settings.reconstruct_settings()

class Interface:
    all_interfaces: list["Interface"] = []

    def __init__(
        self, name: str,
        ip_addresses: list[str] = None,
        mac_address: str = None,
        vendor_name: str = None,
        packets_sent: int = None,
        packets_recv: int = None
    ):
        self.name = name
        self.ip_addresses = ip_addresses
        self.mac_address = mac_address
        self.vendor_name = vendor_name
        self.packets_sent = packets_sent
        self.packets_recv = packets_recv
        self.arp_infos: dict[str, dict] = {}
        Interface.all_interfaces.append(self)

    def add_arp_info(self, ip_address: str, mac_address: str, details: Optional[dict[str, str]] = None):
        """
        Add ARP information for the given IP and MAC addresses.

        Args:
            ip_address (str): IP address.
            mac_address (str): MAC address.
            details (Optional[Dict[str, str]]): Additional details related to ARP.
        """
        if ip_address and mac_address:
            arp_info = {"mac_address": mac_address, "details": details or {}}
            self.arp_infos[ip_address] = arp_info

    def update_arp_info(self, ip_address: str, details: Optional[dict[str, str]] = None):
        """
        Update ARP information for the given IP address.

        Args:
            ip_address (str): IP address.
            details (Optional[Dict[str, str]]): Updated details related to ARP.
        """
        if ip_address in self.arp_infos:
            self.arp_infos[ip_address]["details"].update(details or {})

    def get_infos(self):
        """
        Get information about all attributes of the Interface class for the given instance.
        """
        info_dict = self.__dict__.copy()
        # Remove any internal attributes or methods
        info_dict.pop("arp_infos", None)
        return info_dict

    def get_arp_info_by_ip(self, ip_address: str):
        """
        Get ARP information for the given IP address.

        Args:
            ip_address (str): IP address.
        """
        return self.arp_infos.get(ip_address)

    def get_all_arp_infos(self):
        """
        Get all ARP information for the given interface.
        """
        return self.arp_infos

    @classmethod
    def get_all_interfaces(cls):
        return cls.all_interfaces

    @classmethod
    def get_interface_by_name(cls, interface_name: str):
        for interface in cls.all_interfaces:
            if interface.name == interface_name:
                return interface
        return None

class ThirdPartyServers(enum.Enum):
    PC_Discord = ["66.22.196.0/22", "66.22.238.0/24", "66.22.241.0/24", "66.22.244.0/24"]
    PC_Valve = ["155.133.248.0/24", "162.254.197.0/24", "185.25.180.0/23", "185.25.182.0/24"] # Valve = Steam
    PC_multicast = ["224.0.0.0/4"]
    GTAV_PC_and_PS3_TakeTwo = ["104.255.104.0/23", "104.255.106.0/24", "185.56.64.0/22", "192.81.241.0/24", "192.81.244.0/23"]
    GTAV_PC_Microsoft = ["52.139.128.0/18"]
    GTAV_PC_DoD_Network_Information_Center = ["26.0.0.0/8"]
    GTAV_XboxOne_Microsoft = ["52.159.128.0/17", "52.160.0.0/16"]
    PS5_Amazon = ["52.40.62.0/25"]
    MinecraftBedrockEdition_PC_and_PS3_Microsoft = ["20.202.0.0/24", "20.224.0.0/16", "168.61.142.128/25", "168.61.143.0/24", "168.61.144.0/20", "168.61.160.0/19"]

class PrintCacher:
    def __init__(self):
        self.cache = []

    def cache_print(self, string: str):
        self.cache.append(string)

    def flush_cache(self):
        print("\n".join(self.cache))
        self.cache = []

class Player:
    def __init__(self, packet_timestamp: datetime, ip: str, port: int):
        self.packets = 1
        self.pps_t1 = packet_timestamp
        self.pps_counter = 0
        self.packets_per_second = 0
        self.is_pps_first_calculation = True

        self.ip = ip

        self.ports = [port]
        self.first_port = port
        self.last_port = port

        self.datetime_first_seen = packet_timestamp
        self.datetime_last_seen = packet_timestamp
        self.datetime_left = None

        self.country_iso = None
        self.country_name = None
        self.city = None
        self.asn = None

        self.just_joined = True
        self.rejoined = None

class PlayersRegistry:
    players_registry: dict[str, Player] = {}

    @classmethod
    def add_player(cls, player: Player):
        if player.ip in cls.players_registry:
            raise ValueError(f"Player with IP \"{player.ip}\" already exists.")
        cls.players_registry[player.ip] = player

    @classmethod
    def get_player(cls, ip: str):
        return cls.players_registry.get(ip)

    @classmethod
    def iterate_players_from_registry(cls):
        # Using list() ensures a static snapshot of the dictionary's values is used, avoiding the 'RuntimeError: dictionary changed size during iteration'.
        for player in list(cls.players_registry.values()):
            yield player

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
    session.mount("https://", CustomSSLContextHTTPAdapter(context))
    session.headers.update(HEADERS)
    session.verify = False

    return session

def signal_handler(sig: int, frame: FrameType):
    if sig == 2: # means CTRL+C pressed
        cleanup_before_exit()

def cleanup_before_exit():
    if exit_signal.is_set():
        return
    exit_signal.set()

    if (
        "stdout_render_core__thread" in globals()
        and stdout_render_core__thread.is_alive()
    ):
        stdout_render_core__thread.join()

    print(f"\n{Fore.YELLOW}Ctrl+C pressed. Exiting script ...{Fore.RESET}")

    sys.exit(0)

def is_pyinstaller_compiled():
    return getattr(sys, "frozen", False) # Check if the running Python script is compiled using PyInstaller, cx_Freeze or similar

def title(title: str):
    print(f"\033]0;{title}\007", end="")

def cls():
    print("\033c", end="")

def plural(variable: int):
    return "s" if variable > 1 else ""

def hex_to_int(hex_string: str):
    return int(hex_string, 16)

def is_hex(string: str):
    try:
        int(string, 16)
        return True
    except (ValueError, TypeError):
        return False

def is_ipv4_address(ip_address: str):
    try:
        return IPv4Address(ip_address).version == 4
    except:
        return False

def is_mac_address(mac_address: str):
    return bool(RE_MAC_ADDRESS_PATTERN.match(mac_address))

def is_private_device_ipv4(ip_address: str):
    try:
        ipv4_obj = IPv4Address(ip_address)
    except ValueError:
        return False

    if (
        not ipv4_obj.version == 4
        or ipv4_obj.packed[-1] == 255
        or ipv4_obj.is_link_local # might wants to disable this
        or ipv4_obj.is_loopback
        or ipv4_obj.is_reserved
        or ipv4_obj.is_unspecified
        or ipv4_obj.is_global
        or ipv4_obj.is_multicast
    ):
        return False

    return True

def get_minimum_padding(var: str | int, max_padding: int, padding: int):
    current_padding = len(str(var))

    if current_padding <= padding:
        if current_padding > max_padding:
            max_padding = current_padding

    return max_padding

def get_interface_info(interface_index: str):
    c: _wmi_namespace = wmi.WMI()
    if not isinstance(c, _wmi_namespace):
        raise TypeError(f"Expected '_wmi_namespace' object, got '{type(c)}'")

    interfaces: list[_wmi_object] = c.Win32_NetworkAdapter(InterfaceIndex=interface_index)
    if not isinstance(interfaces, list):
        raise TypeError(f"Expected 'list', got '{type(interfaces)}'")
    for interface in interfaces:
        if not isinstance(interface, _wmi_object):
            raise TypeError(f"Expected '_wmi_object' object, got '{type(interface)}'")

    if len(interfaces) != 1:
        raise ValueError(
            "\nERROR:\n"
            "         Developer didn't expect this scenario to be possible.\n"
            "\nINFOS:\n"
            "         \"WMI\" Python's module did not return a single interface for a given interface Index.\n"
            "\nDEBUG:\n"
            f"         interface_index: {interface_index}\n"
            f"         interfaces: {interfaces}\n"
            f"         len(interfaces): {len(interfaces)}"
        )

    return interfaces[0]

def get_vendor_name(mac_address: str):
    if mac_address is None:
        return None

    try:
        vendor_name = mac_lookup.lookup(mac_address)
    except VendorNotFoundError:
        return None

    if not isinstance(vendor_name, str):
        raise TypeError(
            "\nERROR:\n"
            "         Developer didn't expect this scenario to be possible.\n"
            "\nINFOS:\n"
            "         Vendor name is not a string\n"
            "\nDEBUG:\n"
            f"         vendor_name: {vendor_name}\n"
            f"         type(vendor_name): {type(vendor_name)}"
        )

    if vendor_name == "":
        return None

    return vendor_name

def get_and_parse_arp_cache():
    def process_arp_output(arp_output: str):
        return arp_output.split(maxsplit=5)

    ## Changes the code page to 65001
    #arp_output = subprocess.check_output([
    #    "chcp", "65001",
    #    "&",
    #    "arp", "-a"
    #], shell=True, text=True)

    # deepcode ignore HandleUnicode: Strings in Python 3 are already Unicode by default.
    arp_output = subprocess.check_output([
        "arp", "-a"
    ], text=True)

    cached_arp_dict: dict[int, dict[str, str | list[Optional[dict[str, str]]]]] = {}

    for parts in map(process_arp_output, arp_output.splitlines()):
        if (
            len(parts) >= 4
            and is_ipv4_address(parts[1])
            and parts[2] == "---"
            and is_hex(parts[3])
        ):
            interface_index = hex_to_int(parts[3])
            interface_info = get_interface_info(interface_index)

            interface_name: str | None = interface_info.NetConnectionID
            if not isinstance(interface_name, str):
                if interface_name is None:
                    raise TypeError(
                        "\nERROR:\n"
                        "         Developer didn't expect this scenario to be possible.\n"
                        "\nINFOS:\n"
                        "         \"WMI\" Python module returned \"None\" for the interface name when a string was expected.\n"
                        "\nDEBUG:\n"
                        f"         interface_index: {interface_index}\n"
                        f"         interface_name: {interface_name}"
                    )
                raise TypeError(f"Expected 'str', got '{type(interface_name)}'")

            interface_ip_address = parts[1]

            cached_arp_dict[interface_index] = dict(
                interface_name = interface_name,
                interface_ip_address = interface_ip_address,
                interface_arp_output = []
            )

            continue

        if (
            len(parts) >= 3
            and is_ipv4_address(parts[0])
            and is_mac_address(parts[1])
        ):
            ip_address = parts[0]
            mac_address = format_mac_address(parts[1])

            cached_arp_dict[interface_index]["interface_arp_output"].append(
                dict(
                    ip_address = ip_address,
                    mac_address = mac_address
                )
            )

    return cached_arp_dict

def format_mac_address(mac_address: str):
    if not is_mac_address(mac_address):
        raise ValueError(
            "\nERROR:\n"
            "         Developer didn't expect this scenario to be possible.\n"
            "\nINFOS:\n"
            "         It seems like a MAC address does not follow \"xx:xx:xx:xx:xx:xx\" or \"xx-xx-xx-xx-xx-xx\" format."
            "\nDEBUG:\n"
            f"         mac_address: {mac_address}"
        )

    # deepcode ignore AttributeLoadOnNone: It's impossible for 'mac_address' to be 'None' at this point. If it were 'None', a TypeError would have been raised earlier in the code, most likely from the 'is_mac_address()' function.
    return mac_address.replace("-", ":").upper()

def get_country_info(ip_address: str):
    country_name = "N/A"
    country_iso = "N/A"

    if geoip2_enabled:
        try:
            response = geolite2_country_reader.country(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            country_name = str(response.country.name)
            country_iso = str(response.country.iso_code)

    return country_name, country_iso

def get_city_info(ip_address: str):
    city = "N/A"

    if geoip2_enabled:
        try:
            response = geolite2_city_reader.city(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            city = str(response.city.name)

    return city

def get_asn_info(ip_address: str):
    asn = "N/A"

    if geoip2_enabled:
        try:
            response = geolite2_asn_reader.asn(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            asn = str(response.autonomous_system_organization)

    return asn

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

def update_and_initialize_geolite2_readers():
    def update_geolite2_databases():
        geolite2_version_file_path = geolite2_databases_folder_path / "version.json"
        geolite2_databases: dict[str, dict[str, None | str]] = {
            f"GeoLite2-{db}.mmdb": {
                "current_version": None,
                "last_version": None,
                "download_url": None
            }
            for db in ["ASN", "City", "Country"]
        }

        try:
            with geolite2_version_file_path.open("r") as f:
                loaded_data = json.load(f)
        except (FileNotFoundError, JSONDecodeError):
            pass
        else:
            if isinstance(loaded_data, dict):
                for database_name, database_info in loaded_data.items():
                    if not isinstance(database_info, dict):
                        continue

                    if database_name in geolite2_databases:
                        geolite2_databases[database_name]["current_version"] = database_info.get("version", None)

        github_release_api__geolite2 = "https://api.github.com/repos/PrxyHunter/GeoLite2/releases/latest"
        try:
            response = s.get(github_release_api__geolite2)
        except Exception as e:
            return {
                "exception": e,
                "url": github_release_api__geolite2,
                "http_code": None
            }
        if response.status_code != 200:
            return {
                "exception": None,
                "url": github_release_api__geolite2,
                "http_code": response.status_code
            }

        release_data = response.json()
        for asset in release_data["assets"]:
            asset_name = asset["name"]
            if asset_name in geolite2_databases:
                geolite2_databases[asset_name].update(
                    {
                        "last_version": asset["updated_at"],
                        "download_url": asset["browser_download_url"]
                    }
                )

        for database_name, database_info in geolite2_databases.items():
            if not database_info["current_version"] == database_info["last_version"]:
                try:
                    response = s.get(database_info["download_url"])
                except Exception as e:
                    return {
                        "exception": e,
                        "url": database_info["download_url"],
                        "http_code": None
                    }
                if response.status_code != 200:
                    return {
                        "exception": None,
                        "url": database_info["download_url"],
                        "http_code": response.status_code
                    }

                geolite2_databases_folder_path.mkdir(parents=True, exist_ok=True)  # Create directory if it doesn't exist
                file_path = geolite2_databases_folder_path / database_name
                file_path.write_bytes(response.content)

                geolite2_databases[database_name]["current_version"] = database_info["last_version"]

        with geolite2_version_file_path.open("w") as f:
            json.dump(
                {
                    name: {"version": info["current_version"]}
                    for name, info in geolite2_databases.items()
                }, f, indent=4
            )

        return {
            "exception": None,
            "url": None,
            "http_code": None
        }

    def initialize_geolite2_readers():
        try:
            geolite2_asn_reader = geoip2.database.Reader(geolite2_databases_folder_path / R"GeoLite2-ASN.mmdb")
            geolite2_city_reader = geoip2.database.Reader(geolite2_databases_folder_path / R"GeoLite2-City.mmdb")
            geolite2_country_reader = geoip2.database.Reader(geolite2_databases_folder_path / R"GeoLite2-Country.mmdb")

            geolite2_asn_reader.asn("1.1.1.1")
            geolite2_city_reader.city("1.1.1.1")
            geolite2_country_reader.country("1.1.1.1")
        except Exception as e:
            geolite2_asn_reader = None
            geolite2_city_reader = None
            geolite2_country_reader = None

            exception = e
        else:
            exception = None

        return exception, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader

    geolite2_databases_folder_path = Path("GeoLite2 Databases")

    update_geolite2_databases__dict = update_geolite2_databases()
    exception__initialize_geolite2_readers, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = initialize_geolite2_readers()

    show_error = False
    msgbox_text = ""

    if update_geolite2_databases__dict["exception"]:
        msgbox_text += f"Exception Error: {update_geolite2_databases__dict['exception']}\n\n"
        show_error = True
    if update_geolite2_databases__dict["url"]:
        msgbox_text += f"Error: Failed fetching url: \"{update_geolite2_databases__dict['url']}\"."
        if update_geolite2_databases__dict["http_code"]:
            msgbox_text += f" (http_code: {update_geolite2_databases__dict['http_code']})"
        msgbox_text += "\nImpossible to keep Maxmind's GeoLite2 IP to Country, City and ASN resolutions feature up-to-date.\n\n"
        show_error = True

    if exception__initialize_geolite2_readers:
        msgbox_text += f"Exception Error: {exception__initialize_geolite2_readers}\n\n"
        msgbox_text += "Now disabling MaxMind's GeoLite2 IP to Country, City and ASN resolutions feature.\n"
        msgbox_text += "Countrys, Citys and ASN from players won't shows up from the players fields."
        geoip2_enabled = False
        show_error = True
    else:
        geoip2_enabled = True

    if show_error:
        msgbox_title = TITLE
        msgbox_text = msgbox_text.rstrip("\n")
        msgbox_style = Msgbox.OKOnly | Msgbox.Exclamation
        show_message_box(msgbox_title, msgbox_text, msgbox_style)

    return geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader

colorama.init(autoreset=True)
signal.signal(signal.SIGINT, signal_handler)
exit_signal = threading.Event()

if is_pyinstaller_compiled():
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

TITLE = "GTA V Session Sniffer"
VERSION = "v1.1.0 - 31/03/2024 (19:01)"
TITLE_VERSION = f"{TITLE} {VERSION}"
SETTINGS_PATH = Path("Settings.ini")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:123.0) Gecko/20100101 Firefox/123.0"
}
RE_MAC_ADDRESS_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
s = create_unsafe_https_session()

cls()
if not is_pyinstaller_compiled():
    import importlib.metadata

    title(f"Checking that your Python packages versions matches with file \"requirements.txt\" - {TITLE}")
    print(f"\nChecking that your Python packages versions matches with file \"requirements.txt\" ...\n")

    def check_packages_version(third_party_packages: dict[str, str]):
        outdated_packages = []

        for package_name, required_version in third_party_packages.items():
            installed_version = importlib.metadata.version(package_name)
            if not installed_version == required_version:
                outdated_packages.append((package_name, installed_version, required_version))

        return outdated_packages

    third_party_packages = {
        "psutil": "5.9.8",
        "requests": "2.31.0",
        "urllib3": "2.2.1",
        "WMI": "1.5.1"
    }

    outdated_packages: list[tuple[str, str, str]] = check_packages_version(third_party_packages)
    if outdated_packages:
        msgbox_text = "Your following packages are not up to date:\n\n"
        msgbox_text += f"Package Name: Installed version --> Required version\n"

        # Iterate over outdated packages and add each package's information to the message box text
        for package_name, installed_version, required_version in outdated_packages:
            msgbox_text += f"{package_name}: {installed_version} --> {required_version}\n"

        # Add additional message box text
        msgbox_text += f"\nKeeping your packages synced with \"{TITLE}\" ensures smooth script execution and prevents compatibility issues."
        msgbox_text += "\n\nDo you want to ignore this warning and continue with script execution?"

        # Show message box
        msgbox_style = Msgbox.YesNo | Msgbox.Exclamation
        msgbox_title = TITLE
        errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
        if errorlevel != 6:
            sys.exit(0)

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

try:
    response = s.get("https://raw.githubusercontent.com/Illegal-Services/GTA-V-Session-Sniffer/version/version.txt")
except:
    error_updating__flag = True
else:
    if response.status_code == 200:
        error_updating__flag = False
        current_version = Version(VERSION)
        latest_version = Version(response.text)
        if Updater(current_version).check_for_update(latest_version):
            msgbox_title = TITLE
            msgbox_text = f"""
                New version found. Do you want to update ?

                Current version: {current_version}
                Latest version : {latest_version}
            """
            msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
            msgbox_style = Msgbox.YesNo | Msgbox.Question
            errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
            if errorlevel == 6:
                webbrowser.open("https://github.com/Illegal-Services/GTA-V-Session-Sniffer")
                sys.exit(0)
    else:
        error_updating__flag = True

if error_updating__flag:
    msgbox_title = TITLE
    msgbox_text = f"""
        ERROR: {TITLE} Failed updating itself.

        Do you want to open the \"{TITLE}\" project download page ?
        You can then download and run the latest version from there.
    """
    msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
    msgbox_style = Msgbox.YesNo | Msgbox.Exclamation
    errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
    if errorlevel == 6:
        webbrowser.open("https://github.com/Illegal-Services/GTA-V-Session-Sniffer")
        sys.exit(0)

cls()
title(f"Checking that \"Npcap\" or \"WinpCap\" driver is installed on your system - {TITLE}")
print("\nChecking that \"Npcap\" or \"WinpCap\" driver is installed on your system ...\n")

while True:
    if npcap_or_winpcap_installed():
        break
    else:
        webbrowser.open("https://nmap.org/npcap/")
        msgbox_title = TITLE
        msgbox_text = f"""
            ERROR: {TITLE} could not detect the \"Npcap\" or \"WinpCap\" driver installed on your system.

            Opening the \"Npcap\" project download page for you.
            You can then download and install it from there and press \"Retry\".
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
        if errorlevel == 2:
            sys.exit(0)

cls()
title(f"Applying your custom settings from \"Settings.ini\" - {TITLE}")
print("\nApplying your custom settings from \"Settings.ini\" ...\n")
Settings.load_from_file(SETTINGS_PATH)

cls()
title(f"Initializing and updating MaxMind's GeoLite2 Country, City and ASN databases - {TITLE}")
print("\nInitializing and updating MaxMind's GeoLite2 Country, City and ASN databases ...\n")

geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = update_and_initialize_geolite2_readers()

cls()
title(f"Capture network interface selection - {TITLE}")
print(f"\nCapture network interface selection ...\n")

#mac_lookup.update_vendors()
mac_lookup = MacLookup()

if Settings.ARP:
    cached_arp_dict = get_and_parse_arp_cache()

net_io_stats = psutil.net_io_counters(pernic=True)
net_if_addrs = psutil.net_if_addrs()

for interface, stats in net_io_stats.items():
    if not interface in net_if_addrs:
        continue

    ip_addresses: list[str] = []
    mac_addresses: list[str] = []

    for addr in net_if_addrs[interface]:
        if addr.family == socket.AF_INET:
            ip_addresses.append(addr.address)
        elif addr.family == psutil.AF_LINK:
            mac_addresses.append(addr.address)

    if not ip_addresses:
        continue

    if len(mac_addresses) > 1:
        raise ValueError(
            "\nERROR:\n"
            "         Developer didn't expect this scenario to be possible.\n"
            "\nINFOS:\n"
            "         It seems like an IP address has not been found within a network interface,\n"
            "         or multiple MAC addresses have been found for this one.\n"
            "\nDEBUG:\n"
            f"         interface: {interface}\n"
            f"         ip_addresses: {ip_addresses}\n"
            f"         mac_addresses: {mac_addresses}"
        )

    ip_addresses = [ip for ip in ip_addresses if is_private_device_ipv4(ip)]
    if not ip_addresses:
        continue

    mac_address = format_mac_address(mac_addresses[0]) if mac_addresses else None

    vendor_name = (
        get_vendor_name(mac_address)
        or "N/A"
    )

    Interface(interface, ip_addresses, mac_address, vendor_name, stats.packets_sent, stats.packets_recv)

    if not Settings.ARP:
        continue

    for ip_address in ip_addresses:
        for interface_info in cached_arp_dict.values():
            if (
                not interface_info["interface_name"] == interface
                or not interface_info["interface_ip_address"] == ip_address
                or not interface_info["interface_arp_output"]
            ):
                continue

            arp_info: dict[str, str] = [
                {
                    "ip_address": entry["ip_address"],
                    "mac_address": entry["mac_address"],
                    "vendor_name": (
                        get_vendor_name(entry["mac_address"])
                        or "N/A"
                    )
                }
                for entry in interface_info["interface_arp_output"]
                if is_private_device_ipv4(entry["ip_address"])
            ]

            Interface.get_interface_by_name(interface).add_arp_info(ip_address, mac_address, arp_info)

table = PrettyTable()
table.field_names = ["#", "Interface", "Packets Sent", "Packets Received", "IP Address", "MAC Address", "Organization or Vendor Name"]
table.align["#"] = "c"
table.align["Interface"] = "l"
table.align["Packets Sent"] = "c"
table.align["Packets Received"] = "c"
table.align["IP Address"] = "l"
table.align["MAC Address"] = "c"
table.align["Organization or Vendor Name"] = "c"

interfaces_options: dict[int, dict[str, str | None]] = {}
counter = 0

for interface in Interface.get_all_interfaces():
    if (
        Settings.INTERFACE_NAME is not None
        and Settings.INTERFACE_NAME.lower() == interface.name.lower()
        and not Settings.INTERFACE_NAME == interface.name
    ):
        Settings.INTERFACE_NAME = interface.name
        Settings.reconstruct_settings()

    for ip_address in interface.ip_addresses:
        counter += 1

        interfaces_options[counter] = {
            "is_arp": False,
            "Interface": interface.name,
            "IP Address": ip_address,
            "MAC Address": interface.mac_address
        }

        table.add_row([f"{Fore.YELLOW}{counter}{Fore.RESET}", interface.name, interface.packets_sent, interface.packets_recv, ip_address, interface.mac_address, interface.vendor_name])

    if not Settings.ARP:
        continue

    for ip_address, info in interface.get_all_arp_infos().items():
        for detail in info["details"]:
            counter += 1

            interfaces_options[counter] = {
                "is_arp": True,
                "Interface": interface.name,
                "IP Address": detail["ip_address"],
                "MAC Address": detail["mac_address"]
            }

            table.add_row([f"{Fore.YELLOW}{counter}{Fore.RESET}", f"{interface.name} (ARP)", "N/A", "N/A", detail["ip_address"], detail["mac_address"], detail["vendor_name"]])

user_interface_selection = None

if (
    not Settings.NETWORK_INTERFACE_CONNECTION_PROMPT
    and any(setting is not None for setting in [Settings.INTERFACE_NAME, Settings.MAC_ADDRESS, Settings.IP_ADDRESS])
):
    max_priority = 0

    for interface_counter, interface_options in interfaces_options.items():
        priority = 0

        if Settings.INTERFACE_NAME == interface_options["Interface"]:
            priority += 1
        if Settings.MAC_ADDRESS == interface_options["MAC Address"]:
            priority += 1
        if Settings.IP_ADDRESS == interface_options["IP Address"]:
            priority += 1

        if priority == max_priority: # If multiple matches on the same priority are found we search for the next bigger priority else we prompt the user.
            user_interface_selection = None
        elif priority > max_priority:
            max_priority = priority
            user_interface_selection = interface_counter

if not user_interface_selection:
    print(table)

    while True:
        try:
            user_interface_selection = int(input(f"\nSelect your desired capture network interface ({Fore.YELLOW}1{Fore.RESET}-{Fore.YELLOW}{len(interfaces_options)}{Fore.RESET}): {Fore.YELLOW}"))
        except ValueError:
            print(f"{Fore.RED}ERROR{Fore.RESET}: You didn't provide a number.")
        else:
            if (
                user_interface_selection >= 1
                and user_interface_selection <= len(interfaces_options)
            ):
                print(end=Fore.RESET)
                break
            print(f"{Fore.RED}ERROR{Fore.RESET}: The number you provided is not matching with the available network interfaces.")

cls()
title(f"Initializing addresses and establishing connection to your PC / Console - {TITLE}")
print(f"\nInitializing addresses and establishing connection to your PC / Console ...\n")

need_rewrite_settings = False

if not Settings.INTERFACE_NAME == interfaces_options[user_interface_selection]["Interface"]:
    Settings.INTERFACE_NAME = interfaces_options[user_interface_selection]["Interface"]
    need_rewrite_settings = True

if not Settings.MAC_ADDRESS == interfaces_options[user_interface_selection]["MAC Address"]:
    Settings.MAC_ADDRESS = interfaces_options[user_interface_selection]["MAC Address"]
    need_rewrite_settings = True

if not Settings.IP_ADDRESS == interfaces_options[user_interface_selection]["IP Address"]:
    Settings.IP_ADDRESS = interfaces_options[user_interface_selection]["IP Address"]
    need_rewrite_settings = True

if need_rewrite_settings:
    Settings.reconstruct_settings()

bpf_filter = None
display_filter = None
display_filter_protocols_to_exclude = []

bpf_filter = create_or_happen_to_variable(bpf_filter, " and ", f"((src host {Settings.IP_ADDRESS} and (not (dst net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))) or (dst host {Settings.IP_ADDRESS} and (not (src net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))))")
bpf_filter = create_or_happen_to_variable(bpf_filter, " and ", "udp")
if not Settings.VPN_MODE:
    bpf_filter = create_or_happen_to_variable(bpf_filter, " and ", f"not (broadcast or multicast)")
bpf_filter = create_or_happen_to_variable(bpf_filter, " and ", "not (portrange 0-1023 or port 5353)")

if Settings.PROGRAM_PRESET:
    if Settings.PROGRAM_PRESET == "GTA5":
        display_filter = create_or_happen_to_variable(display_filter, " and ", "(frame.len>=71 and frame.len<=999)")
    elif Settings.PROGRAM_PRESET == "Minecraft":
        display_filter = create_or_happen_to_variable(display_filter, " and ", "(frame.len>=49 and frame.len<=1498)")

    # If the <PROGRAM_PRESET> setting is set, automatically blocks RTCP connections.
    # In case RTCP can be useful to get someone IP, I decided not to block them without using a <PROGRAM_PRESET>.
    # RTCP is known to be for example the Discord's server IP while you are in a call there.
    # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
    # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
    # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
    # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
    display_filter_protocols_to_exclude.append("rtcp")

if Settings.BLOCK_THIRD_PARTY_SERVERS:
    # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
    # But there can be a lot more, those are just a couples I could find on my own usage.
    display_filter_protocols_to_exclude.extend(["ssdp", "raknet", "dtls", "nbns", "pcp", "bt-dht", "uaudp", "classicstun", "dhcp", "mdns", "llmnr"])

    ip_ranges = [ip_range for server in ThirdPartyServers for ip_range in server.value]
    bpf_filter = create_or_happen_to_variable(bpf_filter, " and ", f"not (net {' or '.join(ip_ranges)})")

if display_filter_protocols_to_exclude:
    display_filter = create_or_happen_to_variable(display_filter, " and ", f"not ({' or '.join(display_filter_protocols_to_exclude)})")

while True:
    try:
        capture = PacketCapture(
            interface = Settings.INTERFACE_NAME,
            capture_filter = bpf_filter,
            display_filter = display_filter,
            tshark_path = Settings.TSHARK_PATH
        )
    except TSharkNotFoundException:
        webbrowser.open("https://www.wireshark.org/download.html")
        msgbox_title = TITLE
        msgbox_text = f"""
            ERROR: Could not detect \"Tshark\" installed on your system.

            Opening the \"Tshark\" project download page for you.
            You can then download and install it from there and press \"Retry\".
        """
        msgbox_text = textwrap.dedent(msgbox_text).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        errorlevel = show_message_box(msgbox_title, msgbox_text, msgbox_style)
        if errorlevel == 2:
            sys.exit(0)
    else:
        break

if not capture.tshark_path == Settings.TSHARK_PATH:
    Settings.TSHARK_PATH = capture.tshark_path
    Settings.reconstruct_settings()

tshark_latency = []

def stdout_render_core():
    def port_list_creation(player: Player):
        stdout_port_list = ""

        for port in player.ports:
            to_add_in_portlist = None

            if port == player.first_port == player.last_port:
                to_add_in_portlist = f"[{UNDERLINE}{port}{UNDERLINE_RESET}]"
            elif port == player.first_port:
                to_add_in_portlist = f"[{port}]"
            elif port == player.last_port:
                to_add_in_portlist = f"{UNDERLINE}{port}{UNDERLINE_RESET}"
            else:
                to_add_in_portlist = f"{port}"

            if to_add_in_portlist:
                stdout_port_list = create_or_happen_to_variable(stdout_port_list, ", ", to_add_in_portlist)

        return stdout_port_list

    def calculate_padding_width(total_width: int, *lengths: int):
        """
        Calculate the padding width based on the total width and the lengths of provided strings.

        Args:
        - total_width (int): Total width available for padding
        - *args (int): Integrers for which lengths are used to calculate padding width

        Returns:
        - padding_width (int): Calculated padding width
        """
        # Calculate the total length of all strings
        total_length = sum(length for length in lengths)

        # Calculate the padding width
        padding_width = max(0, (total_width - total_length) // 2)

        return padding_width

    def extract_datetime_from_timestamp(datetime_object: datetime):
        if Settings.STDOUT_FIELD_SHOW_SEEN_DATE:
            formatted_datetime = datetime_object.strftime("%m/%d/%Y %H:%M:%S.%f")[:-3]
        else:
            formatted_datetime = datetime_object.strftime("%H:%M:%S.%f")[:-3]

        return formatted_datetime

    def format_player_pps(is_pps_first_calculation: bool, packets_per_second: int):
        if packets_per_second == 0:
            if is_pps_first_calculation:
                pps_color = Fore.GREEN
            else:
                pps_color = Fore.RED
        elif packets_per_second == 1:
            pps_color = Fore.YELLOW
        else:
            pps_color = Fore.GREEN

        return f"{pps_color}{packets_per_second}{Fore.RESET}"

    def add_down_arrow_to_field(field_names: list[str], target_field: str):
        for i, field in enumerate(field_names):
            if field == target_field:
                field_names[i] += " \u2193"
                break

    global global_pps_counter, tshark_latency

    session_connected_sorted_key = Settings._stdout_fields_mapping[Settings.STDOUT_FIELD_SESSION_CONNECTED_PLAYERS_SORTED_BY]
    session_disconnected_sorted_key = Settings._stdout_fields_mapping[Settings.STDOUT_FIELD_SESSION_DISCONNECTED_PLAYERS_SORTED_BY]

    connected_players_table__field_names = ["First Seen", "Packets", "PPS", "IP Address", "Ports", "Country", "City", "Asn"]
    add_down_arrow_to_field(connected_players_table__field_names, Settings.STDOUT_FIELD_SESSION_CONNECTED_PLAYERS_SORTED_BY)
    disconnected_players_table__field_names = ["Last Seen", "First Seen", "Packets", "IP Address", "Ports", "Country", "City", "Asn"]
    add_down_arrow_to_field(disconnected_players_table__field_names, Settings.STDOUT_FIELD_SESSION_DISCONNECTED_PLAYERS_SORTED_BY)

    printer = PrintCacher()

    global_pps_t1 = time.perf_counter()
    global_packets_per_second = 0

    while not exit_signal.is_set():
        session_connected__padding_country_name = 0
        session_disconnected__padding_country_name = 0
        session_connected: list[Player] = []
        session_disconnected: list[Player] = []

        date_time_now = datetime.now()
        time_perf_counter = time.perf_counter()

        for player in PlayersRegistry.iterate_players_from_registry():
            if (
                not player.datetime_left
                and (date_time_now - player.datetime_last_seen) >= timedelta(seconds=Settings.PLAYER_DISCONNECTED_TIMER)
            ):
               player.datetime_left = player.datetime_last_seen

            if player.asn is None:
                player.asn = get_asn_info(player.ip)

            if player.country_name is None:
                player.country_name, player.country_iso = get_country_info(player.ip)

            if player.city is None:
                player.city = get_city_info(player.ip)

            if player.datetime_left:
                session_disconnected.append(player)
            else:
                session_connected__padding_country_name = get_minimum_padding(player.country_name, session_connected__padding_country_name, 27)

                player_time_delta: timedelta = (date_time_now - player.pps_t1)
                if player_time_delta >= timedelta(seconds=Settings.STDOUT_FIELD_PPS_TIMER):
                    player.packets_per_second = round(player.pps_counter / player_time_delta.total_seconds())
                    player.pps_counter = 0
                    player.pps_t1 = date_time_now
                    player.is_pps_first_calculation = False

                session_connected.append(player)

        session_connected = sorted(session_connected, key=attrgetter(session_connected_sorted_key))
        session_disconnected = sorted(session_disconnected, key=attrgetter(session_disconnected_sorted_key))

        if Settings.STDOUT_FIELD_SESSION_DISCONNECTED_PLAYERS_SORTED_BY == "First Seen":
            session_disconnected__stdout_counter = session_disconnected[:Settings.STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS]
        else:
            session_disconnected__stdout_counter = session_disconnected[-Settings.STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS:]

        for player in session_disconnected__stdout_counter:
            session_disconnected__padding_country_name = get_minimum_padding(player.country_name, session_disconnected__padding_country_name, 27)

        if (
            Settings.STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS == 0
            or Settings.STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS >= len(session_disconnected)
        ):
            len_session_disconnected_message = str(len(session_disconnected))
        else:
            len_session_disconnected_message = f"showing {Settings.STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS}/{len(session_disconnected)}"

        printer.cache_print("")

        if Settings.STDOUT_SHOW_ADVERTISING:
            printer.cache_print("-" * 109)
            printer.cache_print(f"{UNDERLINE}Advertising{UNDERLINE_RESET}:")
            printer.cache_print("  * https://illegal-services.com/")
            printer.cache_print("  * https://github.com/Illegal-Services/PC-Blacklist-Sniffer")
            printer.cache_print("  * https://github.com/Illegal-Services/PS3-Blacklist-Sniffer")
            printer.cache_print("")
            printer.cache_print(f"{UNDERLINE}Contact Details{UNDERLINE_RESET}:")
            printer.cache_print("    You can contact me from Email: BUZZARDGTA@protonmail.com, Discord: waitingforharukatoaddme or Telegram: https://t.me/mathieudummy")
            printer.cache_print("")

        printer.cache_print(f"-" * 109)
        printer.cache_print(f"                             Welcome in {TITLE_VERSION}")
        printer.cache_print(f"                   This script aims in getting people's address IP from GTA V, WITHOUT MODS.")
        printer.cache_print(f"-   " * 28)
        is_arp_enabled = "Enabled" if interfaces_options[user_interface_selection]["is_arp"] else "Disabled"
        padding_width = calculate_padding_width(109, 44, len(str(Settings.IP_ADDRESS)), len(str(Settings.INTERFACE_NAME)), len(str(is_arp_enabled)))
        printer.cache_print(f"{' ' * padding_width}Scanning on network interface:{Fore.YELLOW}{Settings.INTERFACE_NAME}{Fore.RESET} at IP:{Fore.YELLOW}{Settings.IP_ADDRESS}{Fore.RESET} (ARP:{Fore.YELLOW}{is_arp_enabled}{Fore.RESET})")
        tshark_average_latency = sum(tshark_latency, timedelta(0)) / len(tshark_latency) if tshark_latency else timedelta(0)
        tshark_latency = []

        # Convert the average latency to seconds and round it to 1 decimal place
        average_latency_seconds = tshark_average_latency.total_seconds()
        average_latency_rounded = round(average_latency_seconds, 1)

        if tshark_average_latency >= timedelta(seconds=0.90 * Settings.PACKET_CAPTURE_OVERFLOW_TIMER):  # Check if average latency exceeds 90% threshold
            latency_color = Fore.RED
        elif tshark_average_latency >= timedelta(seconds=0.75 * Settings.PACKET_CAPTURE_OVERFLOW_TIMER):  # Check if average latency exceeds 75% threshold
            latency_color = Fore.YELLOW
        else:
            latency_color = Fore.GREEN

        global_pps_t2 = time_perf_counter
        seconds_elapsed = global_pps_t2 - global_pps_t1
        if seconds_elapsed >= Settings.STDOUT_GLOBAL_PPS_TIMER:
            global_packets_per_second = round(global_pps_counter / seconds_elapsed)
            global_pps_counter = 0
            global_pps_t1 = global_pps_t2

        # For reference, in a GTA Online session, the packets per second (PPS) typically range from 0 (solo session) to 1500 (public session, 32 players).
        # If the packet rate exceeds these ranges, we flag them with yellow or red color to indicate potential issues (such as scanning unwanted packets outside of the GTA game).
        if global_packets_per_second >= 3000: # Check if PPS exceeds 3000
            pps_color = Fore.RED
        elif global_packets_per_second >= 1500: # Check if PPS exceeds 1500
            pps_color = Fore.YELLOW
        else:
            pps_color = Fore.GREEN

        color_restarted_time = Fore.GREEN if tshark_restarted_times == 0 else Fore.RED
        padding_width = calculate_padding_width(109, 71, len(str(plural(average_latency_seconds))), len(str(average_latency_rounded)), len(str(Settings.PACKET_CAPTURE_OVERFLOW_TIMER)), len(str(plural(tshark_restarted_times))), len(str(tshark_restarted_times)), len(str(global_packets_per_second)))
        printer.cache_print(f"{' ' * padding_width}Captured packets average second{plural(average_latency_seconds)} latency:{latency_color}{average_latency_rounded}{Fore.RESET}/{latency_color}{Settings.PACKET_CAPTURE_OVERFLOW_TIMER}{Fore.RESET} (tshark restarted time{plural(tshark_restarted_times)}:{color_restarted_time}{tshark_restarted_times}{Fore.RESET}) PPS:{pps_color}{global_packets_per_second}{Fore.RESET}")
        printer.cache_print(f"-" * 109)
        connected_players_table = PrettyTable()
        connected_players_table.set_style(SINGLE_BORDER)
        connected_players_table.title = f"Player{plural(len(session_connected))} connected in your session ({len(session_connected)}):"
        connected_players_table.field_names = connected_players_table__field_names
        connected_players_table.align = "l"
        connected_players_table.add_rows([
            f"{Fore.GREEN}{extract_datetime_from_timestamp(player.datetime_first_seen)}{Fore.RESET}",
            f"{Fore.GREEN}{player.packets}{Fore.RESET}",
            f"{Fore.GREEN}{format_player_pps(player.is_pps_first_calculation, player.packets_per_second)}{Fore.RESET}",
            f"{Fore.GREEN}{player.ip}{Fore.RESET}",
            f"{Fore.GREEN}{port_list_creation(player)}{Fore.RESET}",
            f"{Fore.GREEN}{player.country_name:<{session_connected__padding_country_name}} ({player.country_iso}){Fore.RESET}",
            f"{Fore.GREEN}{player.city}{Fore.RESET}",
            f"{Fore.GREEN}{player.asn}{Fore.RESET}"
        ] for player in session_connected)

        disconnected_players_table = PrettyTable()
        disconnected_players_table.set_style(SINGLE_BORDER)
        disconnected_players_table.title = f"Player{plural(len(session_disconnected))} who've left your session ({len_session_disconnected_message}):"
        disconnected_players_table.field_names = disconnected_players_table__field_names
        disconnected_players_table.align = "l"
        disconnected_players_table.add_rows([
            f"{Fore.RED}{extract_datetime_from_timestamp(player.datetime_last_seen)}{Fore.RESET}",
            f"{Fore.RED}{extract_datetime_from_timestamp(player.datetime_first_seen)}{Fore.RESET}",
            f"{Fore.RED}{player.packets}{Fore.RESET}",
            f"{Fore.RED}{player.ip}{Fore.RESET}",
            f"{Fore.RED}{port_list_creation(player)}{Fore.RESET}",
            f"{Fore.RED}{player.country_name:<{session_disconnected__padding_country_name}} ({player.country_iso}){Fore.RESET}",
            f"{Fore.RED}{player.city}{Fore.RESET}",
            f"{Fore.RED}{player.asn}{Fore.RESET}"
        ] for player in session_disconnected__stdout_counter)

        printer.cache_print("")
        printer.cache_print(connected_players_table.get_string())
        printer.cache_print(disconnected_players_table.get_string())
        printer.cache_print("")

        cls()
        printer.flush_cache()

        refreshing_rate_t1 = time_perf_counter
        printed_text__flag = False
        while not exit_signal.is_set():
            refreshing_rate_t2 = time.perf_counter()

            seconds_elapsed = refreshing_rate_t2 - refreshing_rate_t1
            if seconds_elapsed <= Settings.STDOUT_REFRESHING_TIMER:
                seconds_left = max(Settings.STDOUT_REFRESHING_TIMER - seconds_elapsed, 0)
                if isinstance(Settings.STDOUT_REFRESHING_TIMER, float):
                    seconds_left = round(seconds_left, 1)
                    sleep = 0.1
                else:
                    seconds_left = round(seconds_left)
                    sleep = 1
                print("\033[K" + f"Scanning IPs, refreshing display in {seconds_left} second{plural(seconds_left)} ...", end="\r")
                printed_text__flag = True

                if exit_signal.is_set():
                    break
                time.sleep(sleep)
                if exit_signal.is_set():
                    break
                continue

            refreshing_rate_t1 = refreshing_rate_t2
            break
        if (
            exit_signal.is_set()
            and printed_text__flag
        ):
            print("\033[K" + "\033[F", end="\r")

def packet_callback(packet: Packet):
    global tshark_restarted_times, global_pps_counter

    packet_timestamp = packet.frame.time_epoch

    packet_latency = datetime.now() - packet_timestamp
    tshark_latency.append(packet_latency)
    if packet_latency >= timedelta(seconds=Settings.PACKET_CAPTURE_OVERFLOW_TIMER):
        tshark_restarted_times += 1
        raise ValueError(PACKET_CAPTURE_OVERFLOW)

    source_address = packet.ip.src
    destination_address = packet.ip.dst

    if source_address == Settings.IP_ADDRESS:
        target__ip = destination_address
        target__port = packet.udp.dstport
    elif destination_address == Settings.IP_ADDRESS:
        target__ip = source_address
        target__port = packet.udp.srcport
    else:
        raise ValueError("Neither the source nor destination address matches the specified IP_ADDRESS.")

    global_pps_counter += 1

    player = PlayersRegistry.get_player(target__ip)
    if player is None:
        PlayersRegistry.add_player(
            Player(packet_timestamp, target__ip, target__port)
        )
        return

    player.just_joined = False

    if not player.datetime_left:
        player.rejoined = False

        player.datetime_last_seen = packet_timestamp

        player.packets += 1
        player.pps_counter += 1

        if target__port not in player.ports:
            player.ports.append(target__port)
        player.last_port = target__port

        return

    player.datetime_left = None
    player.rejoined = True

    player.pps_t1 = packet_timestamp
    player.pps_counter = 0
    player.packets_per_second = 0
    player.is_pps_first_calculation = True

    if Settings.STDOUT_RESET_INFOS_ON_CONNECTED:
        player.packets = 1

        player.ports = [target__port]
        player.first_port = target__port
        player.last_port = target__port

    return

cls()
title(TITLE)

PACKET_CAPTURE_OVERFLOW = "Packet capture time exceeded 3 seconds."
tshark_restarted_times = 0
global_pps_counter = 0

# deepcode ignore MissingAPI: The .join() method is indeed in cleanup_before_exit()
stdout_render_core__thread = threading.Thread(target=stdout_render_core)
stdout_render_core__thread.start()

while True:
    try:
        capture.apply_on_packets(callback=packet_callback)
    except ValueError as e:
        if str(e) == PACKET_CAPTURE_OVERFLOW:
            continue
    except Exception as e:
        if not exit_signal.is_set():
            logger.debug(f"EXCEPTION: capture.apply_on_packets() [{exit_signal}], [{str(e)}], [{type(e).__name__}]")
            raise
