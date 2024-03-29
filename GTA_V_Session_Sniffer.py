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
import importlib.metadata
from pathlib import Path
from types import FrameType
from operator import itemgetter
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
    def __init__(self, current_version: Version):
        self.current_version = current_version

    def check_for_update(self, latest_version: Version):
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
    def cache_print(self, statement: str):
        self.cache.append(statement)
    def flush_cache(self):
        print("\n".join(self.cache))
        self.cache = []

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

def is_script_an_executable():
    return Path(sys.argv[0]).suffix.lower() == ".exe" # Check if the running Python script, command-line argument has a file extension ending with .exe

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

    cached_arp_dict = {}

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

def converts_tshark_packet_timestamp_to_datetime_object(packet_frame_time_epoch: str):
    return datetime.fromtimestamp(timestamp=float(packet_frame_time_epoch))

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
            for db in ["ASN", "Country"]
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
        if not response.status_code == 200:
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
                if not response.status_code == 200:
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
            geolite2_country_reader = geoip2.database.Reader(geolite2_databases_folder_path / R"GeoLite2-Country.mmdb")

            geolite2_asn_reader.asn("1.1.1.1")
            geolite2_country_reader.country("1.1.1.1")

            exception = None
        except Exception as e:
            geolite2_asn_reader = None
            geolite2_country_reader = None

            exception = e

        return exception, geolite2_asn_reader, geolite2_country_reader

    geolite2_databases_folder_path = Path("GeoLite2 Databases")

    update_geolite2_databases__dict = update_geolite2_databases()
    exception__initialize_geolite2_readers, geolite2_asn_reader, geolite2_country_reader = initialize_geolite2_readers()

    show_error = False
    msgbox_text = ""

    if update_geolite2_databases__dict["exception"]:
        msgbox_text += f"Exception Error: {update_geolite2_databases__dict['exception']}\n\n"
        show_error = True
    if update_geolite2_databases__dict["url"]:
        msgbox_text += f"Error: Failed fetching url: \"{update_geolite2_databases__dict['url']}\"."
        if update_geolite2_databases__dict["http_code"]:
            msgbox_text += f" (http_code: {update_geolite2_databases__dict['http_code']})"
        msgbox_text += "\nImpossible to keep Maxmind's GeoLite2 IP-to-Country and ASN resolutions feature up-to-date.\n\n"
        show_error = True

    if exception__initialize_geolite2_readers:
        msgbox_text += f"Exception Error: {exception__initialize_geolite2_readers}\n\n"
        msgbox_text += "Now disabling MaxMind's GeoLite2 IP-to-Country and ASN resolutions feature.\n"
        msgbox_text += "Countrys and ASN from players won't shows up from the players fields."
        geoip2_enabled = False
        show_error = True
    else:
        geoip2_enabled = True

    if show_error:
        msgbox_title = TITLE
        msgbox_text = msgbox_text.rstrip("\n")
        msgbox_style = Msgbox.OKOnly | Msgbox.Exclamation
        show_message_box(msgbox_title, msgbox_text, msgbox_style)

    return geoip2_enabled, geolite2_asn_reader, geolite2_country_reader

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
        ;;<STDOUT_SHOW_DATE>
        ;;Shows or not the date from which a player has been captured in \"First Seen\" and \"Last Seen\" fields.
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
    SETTINGS_PATH.write_text(text, encoding="utf-8")

def apply_settings():
    global TSHARK_PATH, STDOUT_SHOW_ADVERTISING, STDOUT_SHOW_DATE, STDOUT_RESET_INFOS_ON_CONNECTED, STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS, STDOUT_REFRESHING_TIMER, PLAYER_DISCONNECTED_TIMER, PACKET_CAPTURE_OVERFLOW_TIMER, NETWORK_INTERFACE_CONNECTION_PROMPT, INTERFACE_NAME, IP_ADDRESS, MAC_ADDRESS, ARP, BLOCK_THIRD_PARTY_SERVERS, PROGRAM_PRESET, VPN_MODE, LOW_PERFORMANCE_MODE

    def return_setting(setting: str, need_rewrite_settings: bool):
        return_setting_value = None

        if not settings_file_not_found:
            for line in SETTINGS:
                line = line.rstrip("\n")
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
        if setting == "TSHARK_PATH":
            TSHARK_PATH, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if TSHARK_PATH is not None:
                TSHARK_PATH = Path(TSHARK_PATH)
        if setting == "STDOUT_SHOW_ADVERTISING":
            STDOUT_SHOW_ADVERTISING, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if STDOUT_SHOW_ADVERTISING == "True":
                STDOUT_SHOW_ADVERTISING = True
            elif STDOUT_SHOW_ADVERTISING == "False":
                STDOUT_SHOW_ADVERTISING = False
            else:
                need_rewrite_settings = True
                STDOUT_SHOW_ADVERTISING = True
        elif setting == "STDOUT_SHOW_DATE":
            STDOUT_SHOW_DATE, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if STDOUT_SHOW_DATE == "True":
                STDOUT_SHOW_DATE = True
            elif STDOUT_SHOW_DATE == "False":
                STDOUT_SHOW_DATE = False
            else:
                need_rewrite_settings = True
                STDOUT_SHOW_DATE = False
        elif setting == "STDOUT_RESET_INFOS_ON_CONNECTED":
            STDOUT_RESET_INFOS_ON_CONNECTED, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if STDOUT_RESET_INFOS_ON_CONNECTED == "True":
                STDOUT_RESET_INFOS_ON_CONNECTED = True
            elif STDOUT_RESET_INFOS_ON_CONNECTED == "False":
                STDOUT_RESET_INFOS_ON_CONNECTED = False
            else:
                need_rewrite_settings = True
                STDOUT_RESET_INFOS_ON_CONNECTED = True
        elif setting == "STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS":
            reset_current_setting__flag = False
            STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS is None:
                reset_current_setting__flag = True
            else:
                try:
                    STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS = int(STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS)
                except (ValueError, TypeError):
                    reset_current_setting__flag = True
                else:
                    if STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS < 0:
                        reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS = 6
        elif setting == "STDOUT_REFRESHING_TIMER":
            reset_current_setting__flag = False
            STDOUT_REFRESHING_TIMER, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if STDOUT_REFRESHING_TIMER is None:
                reset_current_setting__flag = True
            else:
                try:
                    if "." in STDOUT_REFRESHING_TIMER:
                        STDOUT_REFRESHING_TIMER = float(STDOUT_REFRESHING_TIMER)
                    else:
                        STDOUT_REFRESHING_TIMER = int(STDOUT_REFRESHING_TIMER)
                except (ValueError, TypeError):
                    reset_current_setting__flag = True
                else:
                    if STDOUT_REFRESHING_TIMER < 0:
                        reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                STDOUT_REFRESHING_TIMER = 3
        elif setting == "PLAYER_DISCONNECTED_TIMER":
            reset_current_setting__flag = False
            PLAYER_DISCONNECTED_TIMER, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if PLAYER_DISCONNECTED_TIMER is None:
                reset_current_setting__flag = True
            else:
                try:
                    PLAYER_DISCONNECTED_TIMER = float(PLAYER_DISCONNECTED_TIMER)
                except (ValueError, TypeError):
                    reset_current_setting__flag = True
                else:
                    if PLAYER_DISCONNECTED_TIMER < 3.0:
                        reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                PLAYER_DISCONNECTED_TIMER = 6
        elif setting == "PACKET_CAPTURE_OVERFLOW_TIMER":
            reset_current_setting__flag = False
            PACKET_CAPTURE_OVERFLOW_TIMER, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if PACKET_CAPTURE_OVERFLOW_TIMER is None:
                reset_current_setting__flag = True
            else:
                try:
                    PACKET_CAPTURE_OVERFLOW_TIMER = float(PACKET_CAPTURE_OVERFLOW_TIMER)
                except (ValueError, TypeError):
                    reset_current_setting__flag = True
                else:
                    if PACKET_CAPTURE_OVERFLOW_TIMER < 1:
                        reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                PACKET_CAPTURE_OVERFLOW_TIMER = 3
        elif setting == "NETWORK_INTERFACE_CONNECTION_PROMPT":
            NETWORK_INTERFACE_CONNECTION_PROMPT, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if NETWORK_INTERFACE_CONNECTION_PROMPT == "True":
                NETWORK_INTERFACE_CONNECTION_PROMPT = True
            elif NETWORK_INTERFACE_CONNECTION_PROMPT == "False":
                NETWORK_INTERFACE_CONNECTION_PROMPT = False
            else:
                need_rewrite_settings = True
                NETWORK_INTERFACE_CONNECTION_PROMPT = True
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
        elif setting == "MAC_ADDRESS":
            reset_current_setting__flag = False
            MAC_ADDRESS, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if MAC_ADDRESS is None:
                reset_current_setting__flag = True
            elif MAC_ADDRESS == "None":
                MAC_ADDRESS = None
            else:
                if is_mac_address(MAC_ADDRESS):
                    formatted_mac_address = format_mac_address(MAC_ADDRESS)
                    if not formatted_mac_address == MAC_ADDRESS:
                        MAC_ADDRESS = formatted_mac_address
                        need_rewrite_settings = True
                else:
                    reset_current_setting__flag = True
            if reset_current_setting__flag:
                need_rewrite_settings = True
                MAC_ADDRESS = None
        elif setting == "ARP":
            ARP, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if ARP == "True":
                ARP = True
            elif ARP == "False":
                ARP = False
            else:
                need_rewrite_settings = True
                ARP = False
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
        elif setting == "VPN_MODE":
            VPN_MODE, need_rewrite_settings = return_setting(setting, need_rewrite_settings)
            if VPN_MODE == "True":
                VPN_MODE = True
            elif VPN_MODE == "False":
                VPN_MODE = False
            else:
                need_rewrite_settings = True
                VPN_MODE = False
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
exit_signal = threading.Event()

if is_pyinstaller_compiled():
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

TITLE = "GTA V Session Sniffer"
VERSION = "v1.0.7 - 28/03/2024 (10:46)"
TITLE_VERSION = f"{TITLE} {VERSION}"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:123.0) Gecko/20100101 Firefox/123.0"
}
SETTINGS_LIST = [
    "TSHARK_PATH",
    "STDOUT_SHOW_ADVERTISING",
    "STDOUT_SHOW_DATE",
    "STDOUT_RESET_INFOS_ON_CONNECTED",
    "STDOUT_COUNTER_SESSION_DISCONNECTED_PLAYERS",
    "STDOUT_REFRESHING_TIMER",
    "PLAYER_DISCONNECTED_TIMER",
    "PACKET_CAPTURE_OVERFLOW_TIMER",
    "NETWORK_INTERFACE_CONNECTION_PROMPT",
    "INTERFACE_NAME",
    "IP_ADDRESS",
    "MAC_ADDRESS",
    "ARP",
    "BLOCK_THIRD_PARTY_SERVERS",
    "PROGRAM_PRESET",
    "VPN_MODE",
    "LOW_PERFORMANCE_MODE"
]
RE_MAC_ADDRESS_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
s = create_unsafe_https_session()

cls()
title(f"Checking that your Python packages versions matches with file \"requirements.txt\" - {TITLE}")
print(f"\nChecking that your Python packages versions matches with file \"requirements.txt\" ...\n")

def check_packages_version(third_party_packages: dict[str, str]):
    outdated_packages = []

    for package_name, required_version in third_party_packages.items():
        installed_version = importlib.metadata.version(package_name)
        if installed_version != required_version:
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
    msgbox_text += "Package Name\tInstalled version\tRequired version\n"

    name_padding = len("Package Name") + 2
    installed_padding = len("Installed version") + 2
    required_padding = len("Required version") + 2


    for package_info in outdated_packages:
        package_name, installed_version, required_version = package_info

        msgbox_text += f"{package_name.ljust(name_padding)}\t{installed_version.ljust(installed_padding)}\t{required_version}\n"

    msgbox_text += f"\n\nKeeping your packages synced with \"{TITLE}\" ensures smooth script execution and prevents compatibility issues."
    msgbox_text += "\n\nDo you want to ignore this warning and continue with script execution?"

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
    error_updating__flag = False
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

SETTINGS_PATH = Path("Settings.ini")

apply_settings()

cls()
title(f"Initializing and updating MaxMind's GeoLite2 Country, and ASN databases - {TITLE}")
print("\nInitializing and updating MaxMind's GeoLite2 Country, and ASN databases ...\n")

geoip2_enabled, geolite2_asn_reader, geolite2_country_reader = update_and_initialize_geolite2_readers()

cls()
title(f"Capture network interface selection - {TITLE}")
print(f"\nCapture network interface selection ...\n")

#mac_lookup.update_vendors()
mac_lookup = MacLookup()

if ARP:
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

    if (
        not ip_addresses
        or len(mac_addresses) > 1
    ):
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

    if not ARP:
        continue

    for ip_address in ip_addresses:
        for interface_index, interface_info in cached_arp_dict.items():
            if (
                not interface_info["interface_name"] == interface
                or not interface_info["interface_ip_address"] == ip_address
                or not interface_info["interface_arp_output"]
            ):
                continue

            arp_info = [
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
        INTERFACE_NAME is not None
        and INTERFACE_NAME.lower() == interface.name.lower()
        and not INTERFACE_NAME == interface.name
    ):
        INTERFACE_NAME = interface.name
        reconstruct_settings()

    for ip_address in interface.ip_addresses:
        counter += 1

        interfaces_options[counter] = {
            "is_arp": False,
            "Interface": interface.name,
            "IP Address": ip_address,
            "MAC Address": interface.mac_address
        }

        table.add_row([f"{Fore.YELLOW}{counter}{Fore.RESET}", interface.name, interface.packets_sent, interface.packets_recv, ip_address, interface.mac_address, interface.vendor_name])

    if not ARP:
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
    not NETWORK_INTERFACE_CONNECTION_PROMPT
    and any(setting is not None for setting in [INTERFACE_NAME, MAC_ADDRESS, IP_ADDRESS])
):
    max_priority = 0

    for interface_counter, interface_options in interfaces_options.items():
        priority = 0

        if INTERFACE_NAME == interface_options["Interface"]:
            priority += 1
        if MAC_ADDRESS == interface_options["MAC Address"]:
            priority += 1
        if IP_ADDRESS == interface_options["IP Address"]:
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

if not INTERFACE_NAME == interfaces_options[user_interface_selection]["Interface"]:
    INTERFACE_NAME = interfaces_options[user_interface_selection]["Interface"]
    need_rewrite_settings = True

if not MAC_ADDRESS == interfaces_options[user_interface_selection]["MAC Address"]:
    MAC_ADDRESS = interfaces_options[user_interface_selection]["MAC Address"]
    need_rewrite_settings = True

if not IP_ADDRESS == interfaces_options[user_interface_selection]["IP Address"]:
    IP_ADDRESS = interfaces_options[user_interface_selection]["IP Address"]
    need_rewrite_settings = True

if need_rewrite_settings:
    reconstruct_settings()

BPF_FILTER = None
DISPLAY_FILTER = None
display_filter_protocols_to_exclude = []

BPF_FILTER = create_or_happen_to_variable(BPF_FILTER, " and ", f"((src host {IP_ADDRESS} and (not (dst net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))) or (dst host {IP_ADDRESS} and (not (src net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))))")
BPF_FILTER = create_or_happen_to_variable(BPF_FILTER, " and ", "udp")
if not VPN_MODE:
    BPF_FILTER = create_or_happen_to_variable(BPF_FILTER, " and ", f"not (broadcast or multicast)")
BPF_FILTER = create_or_happen_to_variable(BPF_FILTER, " and ", "not (portrange 0-1023 or port 5353)")

if PROGRAM_PRESET:
    if PROGRAM_PRESET == "GTA5":
        DISPLAY_FILTER = create_or_happen_to_variable(DISPLAY_FILTER, " and ", "(frame.len>=71 and frame.len<=999)")
    elif PROGRAM_PRESET == "Minecraft":
        DISPLAY_FILTER = create_or_happen_to_variable(DISPLAY_FILTER, " and ", "(frame.len>=49 and frame.len<=1498)")

    # If the <PROGRAM_PRESET> setting is set, automatically blocks RTCP connections.
    # In case RTCP can be useful to get someone IP, I decided not to block them without using a <PROGRAM_PRESET>.
    # RTCP is known to be for example the Discord's server IP while you are in a call there.
    # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
    # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
    # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
    # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
    display_filter_protocols_to_exclude.append("rtcp")

if BLOCK_THIRD_PARTY_SERVERS:
    # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
    # But there can be a lot more, those are just a couples I could find on my own usage.
    display_filter_protocols_to_exclude.extend(["ssdp", "raknet", "dtls", "nbns", "pcp", "bt-dht", "uaudp", "classicstun", "dhcp", "mdns", "llmnr"])

    ip_ranges = [ip_range for server in ThirdPartyServers for ip_range in server.value]
    BPF_FILTER = create_or_happen_to_variable(BPF_FILTER, " and ", f"not (net {' or '.join(ip_ranges)})")

if display_filter_protocols_to_exclude:
    DISPLAY_FILTER = create_or_happen_to_variable(DISPLAY_FILTER, " and ", f"not ({' or '.join(display_filter_protocols_to_exclude)})")

while True:
    try:
        capture = PacketCapture(
            interface = INTERFACE_NAME,
            capture_filter = BPF_FILTER,
            display_filter = DISPLAY_FILTER,
            tshark_path = TSHARK_PATH
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

if not capture.tshark_path == TSHARK_PATH:
    TSHARK_PATH = capture.tshark_path
    reconstruct_settings()

session_db = []
tshark_latency = []

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
        if STDOUT_SHOW_DATE:
            formatted_datetime = datetime_object.strftime("%m/%d/%Y %H:%M:%S")
        else:
            formatted_datetime = datetime_object.strftime("%H:%M:%S")

        return formatted_datetime

    def format_player_pps(packets_per_second: int):
        # TODO: Add that it's not red when new people are showd
        if packets_per_second == 0:
            pps_color = Fore.RED
        elif packets_per_second == 1:
            pps_color = Fore.YELLOW
        else:
            pps_color = Fore.GREEN

        return f"{pps_color}{packets_per_second}{Fore.RESET}"

    global pps_counter, tshark_latency

    printer = PrintCacher()
    pps_t1 = time.perf_counter()
    packets_per_second = 0

    while not exit_signal.is_set():
        session_connected__padding_country_name = 0
        session_disconnected__padding_country_name = 0
        session_connected = []
        session_disconnected = []

        date_time_now = datetime.now()
        time_perf_counter = time.perf_counter()

        for player in session_db:
            if (
                not player["datetime_left"]
                and (date_time_now - player["datetime_last_seen"]) >= timedelta(seconds=PLAYER_DISCONNECTED_TIMER)
            ):
               player["datetime_left"] = player["datetime_last_seen"]

            if not "asn" in player:
                player["asn"] = get_asn_info(player["ip"])

            if not "country_name" in player:
                player["country_name"], player["country_iso"] = get_country_info(player["ip"])

            if player["datetime_left"]:
                session_disconnected.append({
                    "datetime_last_seen": player["datetime_last_seen"],
                    "datetime_first_seen": player["datetime_first_seen"],
                    "packets": player["packets"],
                    "ip": player["ip"],
                    "stdout_port_list": port_list_creation(Fore.RED),
                    "country_name": player["country_name"],
                    "country_iso": player["country_iso"],
                    "asn": player["asn"]
                })
            else:
                session_connected__padding_country_name = get_minimum_padding(player["country_name"], session_connected__padding_country_name, 27)

                player_time_delta: timedelta = (date_time_now - player["pps_t1"])
                if player_time_delta >= timedelta(seconds=1):
                    player["packets_per_second"] = round(player["pps_counter"] / player_time_delta.total_seconds())
                    player["pps_counter"] = 0
                    player["pps_t1"] = date_time_now

                session_connected.append({
                    "datetime_first_seen": player["datetime_first_seen"],
                    "packets": player["packets"],
                    "packets_per_second": player["packets_per_second"],
                    "ip": player["ip"],
                    "stdout_port_list": port_list_creation(Fore.GREEN),
                    "country_name": player["country_name"],
                    "country_iso": player["country_iso"],
                    "asn": player["asn"]
                })

        session_connected = sorted(session_connected, key=itemgetter("datetime_first_seen"))
        session_disconnected = sorted(session_disconnected, key=itemgetter("datetime_last_seen"))

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

        printer.cache_print("")

        if STDOUT_SHOW_ADVERTISING:
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
        padding_width = calculate_padding_width(109, 44, len(str(IP_ADDRESS)), len(str(INTERFACE_NAME)), len(str(is_arp_enabled)))
        printer.cache_print(f"{' ' * padding_width}Scanning on network interface:{Fore.YELLOW}{INTERFACE_NAME}{Fore.RESET} at IP:{Fore.YELLOW}{IP_ADDRESS}{Fore.RESET} (ARP:{Fore.YELLOW}{is_arp_enabled}{Fore.RESET})")
        tshark_average_latency = sum(tshark_latency, timedelta(0)) / len(tshark_latency) if tshark_latency else timedelta(0)
        tshark_latency = []

        # Convert the average latency to seconds and round it to 1 decimal place
        average_latency_seconds = tshark_average_latency.total_seconds()
        average_latency_rounded = round(average_latency_seconds, 1)

        if tshark_average_latency >= timedelta(seconds=0.90 * PACKET_CAPTURE_OVERFLOW_TIMER):  # Check if average latency exceeds 90% threshold
            latency_color = Fore.RED
        elif tshark_average_latency >= timedelta(seconds=0.75 * PACKET_CAPTURE_OVERFLOW_TIMER):  # Check if average latency exceeds 75% threshold
            latency_color = Fore.YELLOW
        else:
            latency_color = Fore.GREEN

        pps_t2 = time_perf_counter
        seconds_elapsed = pps_t2 - pps_t1
        if seconds_elapsed >= 1:
            packets_per_second = round(pps_counter / seconds_elapsed)
            pps_counter = 0
            pps_t1 = pps_t2

        # For reference, in a GTA Online session, the packets per second (PPS) typically range from 0 (solo session) to 1500 (public session, 32 players).
        # If the packet rate exceeds these ranges, we flag them with yellow or red color to indicate potential issues (such as scanning unwanted packets outside of the GTA game).
        if packets_per_second >= 3000: # Check if PPS exceeds 3000
            pps_color = Fore.RED
        elif packets_per_second >= 1500: # Check if PPS exceeds 1500
            pps_color = Fore.YELLOW
        else:
            pps_color = Fore.GREEN

        color_restarted_time = Fore.GREEN if tshark_restarted_times == 0 else Fore.RED
        padding_width = calculate_padding_width(109, 71, len(str(plural(average_latency_seconds))), len(str(average_latency_rounded)), len(str(PACKET_CAPTURE_OVERFLOW_TIMER)), len(str(plural(tshark_restarted_times))), len(str(tshark_restarted_times)), len(str(packets_per_second)))
        printer.cache_print(f"{' ' * padding_width}Captured packets average second{plural(average_latency_seconds)} latency:{latency_color}{average_latency_rounded}{Fore.RESET}/{latency_color}{PACKET_CAPTURE_OVERFLOW_TIMER}{Fore.RESET} (tshark restarted time{plural(tshark_restarted_times)}:{color_restarted_time}{tshark_restarted_times}{Fore.RESET}) PPS:{pps_color}{packets_per_second}{Fore.RESET}")
        printer.cache_print(f"-" * 109)
        connected_players_table = PrettyTable()
        connected_players_table.set_style(SINGLE_BORDER)
        connected_players_table.title = f"Player{plural(len(session_connected))} connected in your session ({len(session_connected)}):"
        connected_players_table.field_names = ["First Seen", "Packets", "PPS", "IP Address", "Ports", "Country", "Asn"]
        connected_players_table.align = "l"
        connected_players_table.add_rows([
            f"{Fore.GREEN}{extract_datetime_from_timestamp(player['datetime_first_seen'])}{Fore.RESET}",
            f"{Fore.GREEN}{player['packets']}{Fore.RESET}",
            f"{Fore.GREEN}{format_player_pps(player['packets_per_second'])}{Fore.RESET}",
            f"{Fore.GREEN}{player['ip']}{Fore.RESET}",
            f"{Fore.GREEN}{player['stdout_port_list']}{Fore.RESET}",
            f"{Fore.GREEN}{player['country_name']:<{session_connected__padding_country_name}} ({player['country_iso']}){Fore.RESET}",
            f"{Fore.GREEN}{player['asn']}{Fore.RESET}"
        ] for player in session_connected)

        disconnected_players_table = PrettyTable()
        disconnected_players_table.set_style(SINGLE_BORDER)
        disconnected_players_table.title = f"Player{plural(len(session_disconnected))} who've left your session ({len_session_disconnected_message}):"
        disconnected_players_table.field_names = ["Last Seen", "First Seen", "Packets", "IP Address", "Ports", "Country", "Asn"]
        disconnected_players_table.align = "l"
        disconnected_players_table.add_rows([
            f"{Fore.RED}{extract_datetime_from_timestamp(player['datetime_last_seen'])}{Fore.RESET}",
            f"{Fore.RED}{extract_datetime_from_timestamp(player['datetime_first_seen'])}{Fore.RESET}",
            f"{Fore.RED}{player['packets']}{Fore.RESET}",
            f"{Fore.RED}{player['ip']}{Fore.RESET}",
            f"{Fore.RED}{player['stdout_port_list']}{Fore.RESET}",
            f"{Fore.RED}{player['country_name']:<{session_disconnected__padding_country_name}} ({player['country_iso']}){Fore.RESET}",
            f"{Fore.RED}{player['asn']}{Fore.RESET}"
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
            if seconds_elapsed <= STDOUT_REFRESHING_TIMER:
                seconds_left = max(STDOUT_REFRESHING_TIMER - seconds_elapsed, 0)
                if isinstance(STDOUT_REFRESHING_TIMER, float):
                    seconds_left = round(seconds_left, 1)
                    sleep = 0.1
                else:
                    seconds_left = round(seconds_left)
                    sleep = 1
                print("\033[K" + f"Scanning IPs, refreshing display in {seconds_left} second{plural(seconds_left)} ...", end="\r")
                printed_text__flag = True

                time.sleep(sleep)
                continue

            refreshing_rate_t1 = refreshing_rate_t2
            break
        if (
            exit_signal.is_set()
            and printed_text__flag
        ):
            print("\033[K" + "\033[F", end="\r")

def clear_recently_resolved_ips():
    if not exit_signal.is_set():
        recently_resolved_ips.clear()

        threading.Timer(1, clear_recently_resolved_ips).start()

def packet_callback(packet: Packet):
    global pps_counter, tshark_restarted_times

    pps_counter += 1

    packet_timestamp = converts_tshark_packet_timestamp_to_datetime_object(packet.frame.time_epoch)
    packet_latency = datetime.now() - packet_timestamp
    tshark_latency.append(packet_latency)
    if packet_latency >= timedelta(seconds=PACKET_CAPTURE_OVERFLOW_TIMER):
        tshark_restarted_times += 1
        raise ValueError(PACKET_CAPTURE_OVERFLOW)

    source_address = packet.ip.src
    destination_address = packet.ip.dst

    if source_address == IP_ADDRESS:
        target__ip = destination_address
        target__port = packet.udp.dstport
    elif destination_address == IP_ADDRESS:
        target__ip = source_address
        target__port = packet.udp.srcport
    else:
        return

    if LOW_PERFORMANCE_MODE:
        if target__ip in recently_resolved_ips:
            return
        recently_resolved_ips.add(target__ip)

    for player in session_db:
        if player["ip"] == target__ip:
            if player["datetime_left"]:
                if STDOUT_RESET_INFOS_ON_CONNECTED:
                    session_db.remove(player)
                    break
                player["pps_t1"] = packet_timestamp
                player["pps_counter"] = 0
                player["datetime_left"] = None
            else:
                player["pps_counter"] += 1
            player["packets"] += 1
            if target__port not in player["ports"]:
                player["ports"].append(target__port)
            player["last_port"] = target__port
            player["datetime_last_seen"] = packet_timestamp

            return

    session_db.append(
        dict(
            packets = 1,
            pps_t1 = packet_timestamp,
            pps_counter = 0,
            packets_per_second = 0,
            ip = target__ip,
            ports = [target__port],
            first_port = target__port,
            last_port = target__port,
            datetime_first_seen = packet_timestamp,
            datetime_last_seen = packet_timestamp,
            datetime_left = None
        )
    )

cls()
title(TITLE)

PACKET_CAPTURE_OVERFLOW = "Packet capture time exceeded 3 seconds."
pps_counter = 0
tshark_restarted_times = 0

# deepcode ignore MissingAPI: <please specify a reason of ignoring this>
stdout_render_core__thread = threading.Thread(target=stdout_render_core)
stdout_render_core__thread.start()

if LOW_PERFORMANCE_MODE:
    recently_resolved_ips = set()
    clear_recently_resolved_ips()

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
