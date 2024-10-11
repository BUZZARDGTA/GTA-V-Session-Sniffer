# -----------------------------------------------------
# 📚 Local Python Libraries (Included with Project) 📚
# -----------------------------------------------------
from Modules.capture.sync_capture import PacketCapture, Packet, TSharkNotFoundException
from Modules.oui_lookup.oui_lookup import MacLookup
from Modules.https_utils.unsafe_https import create_unsafe_https_session

# --------------------------------------------
# 📦 External/Third-party Python Libraries 📦
# --------------------------------------------
import wmi
import psutil
import colorama
import requests
import geoip2.errors
import geoip2.database
from colorama import Fore, Back, Style
from wmi import _wmi_namespace, _wmi_object
from prettytable import PrettyTable, SINGLE_BORDER
from rich.console import Console
from rich.traceback import Traceback
from rich.text import Text

# ------------------------------------------------------
# 🐍 Standard Python Libraries (Included by Default) 🐍
# ------------------------------------------------------
import os
import re
import sys
import ast
import json
import time
import enum
import errno
import socket
import ctypes
import signal
import logging
import textwrap
import winsound
import threading
import subprocess
import webbrowser
from pathlib import Path
from types import FrameType, TracebackType
from typing import Optional, Literal
from operator import attrgetter
from ipaddress import IPv4Address, AddressValueError
from datetime import datetime, timedelta
from json.decoder import JSONDecodeError


if sys.version_info.major <= 3 and sys.version_info.minor < 9:
    print("To use this script, your Python version must be 3.9 or higher.")
    print("Please note that Python 3.9 is not compatible with Windows versions 7 or lower.")
    sys.exit(0)

logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M",
    handlers=[
        logging.FileHandler("error.log")
        # rich.traceback does it nicer ---> logging.StreamHandler(sys.stdout)
    ]
)

def log_and_display_exception(exc_type, exc_value, exc_traceback):
    """Log and display the exception with rich formatting."""
    logging.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

    console = Console()

    traceback_message = Traceback.from_exception(exc_type, exc_value, exc_traceback)

    error_message = Text.from_markup(
        "\n\n\nAn error occurred. [bold]Please kindly report it to [link=https://github.com/Illegal-Services/GTA-V-Session-Sniffer/issues]https://github.com/Illegal-Services/GTA-V-Session-Sniffer/issues[/link][/bold]."
        "\n\n\nPress [yellow]{ANY KEY}[/yellow] to exit ...",
        style="white"
    )

    console.print(traceback_message)
    console.print(error_message)
    input()

def handle_exception(exc_type, exc_value, exc_traceback):
    """Handles exceptions for the main script. (not threads)"""
    if issubclass(exc_type, KeyboardInterrupt):
        return

    log_and_display_exception(exc_type, exc_value, exc_traceback)
    sys.exit(1)

sys.excepthook = handle_exception


class InvalidBooleanValueError(Exception):
    pass

class InvalidNoneTypeValueError(Exception):
    pass

class InvalidFileError(Exception):
    def __init__(self, path: str):
        super().__init__(f"The path does not point to a regular file: '{path}'")

class PacketCaptureOverflow(Exception):
    pass

class ScriptCrashedUnderControl(Exception):
    pass

class ScriptControl:
    _lock = threading.Lock()
    _crashed = False
    _message = ""

    @classmethod
    def set_crashed(cls, message=""):
        with cls._lock:
            cls._crashed = True
            cls._message = message

    @classmethod
    def reset_crashed(cls):
        with cls._lock:
            cls._crashed = False
            cls._message = ""

    @classmethod
    def has_crashed(cls):
        with cls._lock:
            return cls._crashed

    @classmethod
    def get_message(cls):
        with cls._lock:
            return cls._message

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

class Threads_ExceptionHandler:
    """In Python, threads cannot be raised within the main source code. When raised, they operate independently,
    and the main process continues execution without halting for the thread's completion. To overcome this limitation,
    this class is designed to enhance thread management and provide additional functionality.

    Attributes:
        raising_function (str): The name of the function where the exception was raised.
        raising_e_type (type): The type of the exception raised.
        raising_e_value (Exception): The value of the exception raised.
        raising_e_traceback (TracebackType): The traceback information of the exception raised.
    """
    raising_function = None
    raising_e_type = None
    raising_e_value = None
    raising_e_traceback = None

    def __init__(self):
        pass

    def __enter__(self):
        pass

    def __exit__(self, e_type: type, e_value: Exception, e_traceback: TracebackType):
        """Exit method called upon exiting the 'with' block.

        Args:
            e_type (type): The type of the exception raised.
            e_value (Exception): The value of the exception raised.
            e_traceback (TracebackType): The traceback information of the exception raised.

        Returns:
            bool: True to suppress the exception from propagating further.
        """
        if e_type:
            Threads_ExceptionHandler.raising_e_type = e_type
            Threads_ExceptionHandler.raising_e_value = e_value
            Threads_ExceptionHandler.raising_e_traceback = e_traceback

            tb = e_traceback
            while tb.tb_next:
                tb = tb.tb_next
            # Set the failed function name
            Threads_ExceptionHandler.raising_function = tb.tb_frame.f_code.co_name

            terminate_current_script_process("THREAD_RAISED")

            return True  # Prevent exceptions from propagating

class Settings:
    CAPTURE_TSHARK_PATH = None
    CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT = True
    CAPTURE_INTERFACE_NAME = None
    CAPTURE_IP_ADDRESS = None
    CAPTURE_MAC_ADDRESS = None
    CAPTURE_ARP = True
    CAPTURE_BLOCK_THIRD_PARTY_SERVERS = True
    CAPTURE_PROGRAM_PRESET = None
    CAPTURE_VPN_MODE = False
    CAPTURE_OVERFLOW_TIMER = 3.0
    STDOUT_SHOW_ADVERTISING_HEADER = True
    STDOUT_RESET_INFOS_ON_CONNECTED = True
    STDOUT_FIELDS_TO_HIDE = []
    STDOUT_FIELD_SHOW_SEEN_DATE = False
    STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY = "First Seen"
    STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY = "Last Seen"
    STDOUT_DISCONNECTED_PLAYERS_TIMER = 6.0
    STDOUT_DISCONNECTED_PLAYERS_COUNTER = 6
    STDOUT_REFRESHING_TIMER = 3
    BLACKLIST_ENABLED = True
    BLACKLIST_NOTIFICATIONS = True
    BLACKLIST_VOICE_NOTIFICATIONS: Literal["Male", "Female", False] = "Male"
    BLACKLIST_PROTECTION: Literal["Exit_Process", "Restart_Process", "Shutdown_PC", "Restart_PC", False] = False
    BLACKLIST_PROTECTION_EXIT_PROCESS_PATH = None
    BLACKLIST_PROTECTION_RESTART_PROCESS_PATH = None

    _allowed_settings_types = (type(None), Path, bool, list, str, float, int)

    _valid_stdout_hidden_fields = ["Ports", "Country", "City", "ASN", "Mobile", "Proxy/VPN/Tor", "Hosting/Data Center"]

    _stdout_fields_mapping = {
        "First Seen": "datetime.first_seen",
        "Last Seen": "datetime.last_seen",
        "Usernames": "blacklist.usernames",
        "Packets": "packets",
        "PPS": "pps.rate",
        "Rejoins": "rejoins",
        "IP Address": "ip",
        "Ports": "ports",
        "Country": "iplookup.country",
        "City": "iplookup.city",
        "ASN": "iplookup.asn",
        "Mobile": "iplookup.mobile",
        "Proxy/VPN/Tor": "iplookup.proxy",
        "Hosting/Data Center": "iplookup.hosting"
    }

    @classmethod
    def iterate_over_settings(cls):
        for attr_name, attr_value in vars(cls).items():
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
        text = textwrap.dedent(f"""
            ;;-----------------------------------------------------------------------------
            ;;Lines starting with \";\" or \"#\" symbols are commented lines.
            ;;
            ;;This is the settings file for \"GTA V Session Sniffer\" configuration.
            ;;
            ;;If you don't know what value to choose for a specifc setting, set it's value to None.
            ;;The program will automatically analyzes this file and if needed will regenerate it if it contains errors.
            ;;
            ;;<CAPTURE_TSHARK_PATH>
            ;;The full path to your \"tshark.exe\" executable.
            ;;If not set, it will attempt to detect tshark from your Wireshark installation.
            ;;
            ;;<CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT>
            ;;Allows you to skip the network interface selection by automatically
            ;;using the <CAPTURE_INTERFACE_NAME>, <CAPTURE_IP_ADDRESS> and <CAPTURE_MAC_ADDRESS> settings.
            ;;
            ;;<CAPTURE_INTERFACE_NAME>
            ;;The network interface from which packets will be captured.
            ;;
            ;;<CAPTURE_IP_ADDRESS>
            ;;The IP address of a network interface on your computer from which packets will be captured.
            ;;If the <CAPTURE_ARP> setting is enabled, it can be from any device on your home network.
            ;;Valid example value: \"x.x.x.x\"
            ;;
            ;;<CAPTURE_MAC_ADDRESS>
            ;;The MAC address of a network interface on your computer from which packets will be captured.
            ;;If the <CAPTURE_ARP> setting is enabled, it can be from any device on your home network.
            ;;Valid example value: \"xx:xx:xx:xx:xx:xx\" or \"xx-xx-xx-xx-xx-xx\"
            ;;
            ;;<CAPTURE_ARP>
            ;;Allows you to capture from devices located outside your computer but within your home network, such as gaming consoles.
            ;;
            ;;<CAPTURE_BLOCK_THIRD_PARTY_SERVERS>
            ;;Determine if you want or not to block the annoying IP ranges from servers that shouldn't be detected.
            ;;
            ;;<CAPTURE_PROGRAM_PRESET>
            ;;A program preset that will help capturing the right packets for your program.
            ;;Supported program presets are only \"GTA5\" and \"Minecraft\".
            ;;Note that Minecraft only supports Bedrock Edition.
            ;;Please also note that Minecraft have only been tested on PCs.
            ;;I do not have information regarding it's functionality on consoles.
            ;;
            ;;<CAPTURE_VPN_MODE>
            ;;Setting this to False will add filters to exclude unrelated IPs from the output.
            ;;However, if you are scanning trough a VPN <CAPTURE_INTERFACE_NAME>, you have to set it to True.
            ;;
            ;;<CAPTURE_OVERFLOW_TIMER>
            ;;This timer represents the duration between the timestamp of a captured packet and the current time.
            ;;When this timer is reached, the tshark process will be restarted.
            ;;Valid values include any number greater than or equal to 3.
            ;;
            ;;<STDOUT_SHOW_ADVERTISING_HEADER>
            ;;Determine if you want or not to show the developer's advertisements in the script's display.
            ;;
            ;;<STDOUT_RESET_INFOS_ON_CONNECTED>
            ;;Resets and recalculates each fields for players who were previously disconnected.
            ;;
            ;;<STDOUT_FIELDS_TO_HIDE>
            ;;Specifies a list of fields you wish to hide from the output.
            ;;It can only hides field names that are not essential to the script's functionality.
            ;;Valid values include any of the following field names:
            ;;{Settings._valid_stdout_hidden_fields}
            ;;
            ;;<STDOUT_FIELD_SHOW_SEEN_DATE>
            ;;Shows or not the date from which a player has been captured in \"First Seen\" and \"Last Seen\" fields.
            ;;
            ;;<STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY>
            ;;Specifies the fields from the connected players by which you want the output data to be sorted.
            ;;Valid values include any field names. For example: First Seen
            ;;
            ;;<STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY>
            ;;Specifies the fields from the disconnected players by which you want the output data to be sorted.
            ;;Valid values include any field names. For example: Last Seen
            ;;
            ;;<STDOUT_DISCONNECTED_PLAYERS_TIMER>
            ;;The duration after which a player will be moved as disconnected on the console if no packets are received within this time.
            ;;Valid values include any number greater than or equal to 3.
            ;;
            ;;<STDOUT_DISCONNECTED_PLAYERS_COUNTER>
            ;;The maximum number of players showing up in disconnected players list.
            ;;Valid values include any number greater than or equal to 0.
            ;;Setting it to 0 will make it unlimitted.
            ;;
            ;;<STDOUT_REFRESHING_TIMER>
            ;;Time interval between which this will refresh the console display.
            ;;
            ;;<BLACKLIST_ENABLED>
            ;;Determine if you want or not to enable the blacklisted users feature.
            ;;
            ;;<BLACKLIST_NOTIFICATIONS>
            ;;Determine if you want or not to display a notification when a blacklisted user is detected.
            ;;
            ;;<BLACKLIST_VOICE_NOTIFICATIONS>
            ;;This setting determines the voice that will play when a blacklisted player is detected or when they disconnect.
            ;;Valid values are either \"Male\" or \"Female\".
            ;;Set it to \"False\" to disable this setting.
            ;;
            ;;<BLACKLIST_PROTECTION>
            ;;Determine if you want or not a protection when a blacklisted user is found.
            ;;Valid values include any of the following protections:
            ;;\"Exit_Process\", \"Restart_Process\", \"Shutdown_PC\", \"Restart_PC\"
            ;;Set it to \"False\" value to disable this setting.
            ;;
            ;;<BLACKLIST_PROTECTION_EXIT_PROCESS_PATH>
            ;;The file path of the process that will be terminated when
            ;;the <BLACKLIST_PROTECTION> setting is set to either \"Exit_Process\" or \"Restart_Process\" value.
            ;;Please note that UWP apps are not supported.
            ;;
            ;;<BLACKLIST_PROTECTION_RESTART_PROCESS_PATH>
            ;;The file path of the process that will be started when
            ;;the <BLACKLIST_PROTECTION> setting is set to the \"Restart_Process\" value.
            ;;Please note that UWP apps are not supported.
            ;;-----------------------------------------------------------------------------
        """.removeprefix("\n"))
        for setting_name, setting_value in Settings.iterate_over_settings():
            text += f"{setting_name}={setting_value}\n"
        SETTINGS_PATH.write_text(text, encoding="utf-8")

    def load_from_settings_file(settings_path: Path):
        def custom_str_to_bool(string: str, only_match_against: bool | None = None):
            """
            This function returns the boolean value represented by the string for lowercase or any case variation;\n
            otherwise, it raises an \"InvalidBooleanValueError\".

            Args:
                string (str): The boolean string to be checked.
                (optional) only_match_against (bool | None): If provided, the only boolean value to match against.
            """
            need_rewrite_current_setting = False
            resolved_value = None

            string_lower = string.lower()

            if string_lower == "true":
                resolved_value = True
            elif string_lower == "false":
                resolved_value = False

            if resolved_value is None:
                raise InvalidBooleanValueError("Input is not a valid boolean value")

            if (
                only_match_against is not None
                and only_match_against is not resolved_value
            ):
                raise InvalidBooleanValueError("Input does not match the specified boolean value")

            if not string == str(resolved_value):
                need_rewrite_current_setting = True

            return resolved_value, need_rewrite_current_setting

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


        matched_settings_count = 0

        try:
            settings, need_rewrite_settings = parse_ini_file(settings_path, values_handling="first")
            settings: dict[str, str]
        except FileNotFoundError:
            need_rewrite_settings = True
        else:
            for setting_name, setting_value in settings.items():
                if not Settings.has_setting(setting_name):
                    need_rewrite_settings = True
                    continue

                matched_settings_count += 1
                need_rewrite_current_setting = False

                if setting_name == "CAPTURE_TSHARK_PATH":
                    try:
                        Settings.CAPTURE_TSHARK_PATH, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        Settings.CAPTURE_TSHARK_PATH = Path(setting_value)
                elif setting_name == "CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT":
                    try:
                        Settings.CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_INTERFACE_NAME":
                    if setting_value == "None":
                        Settings.CAPTURE_INTERFACE_NAME = None
                    else:
                        Settings.CAPTURE_INTERFACE_NAME = setting_value
                elif setting_name == "CAPTURE_IP_ADDRESS":
                    if setting_value == "None":
                        Settings.CAPTURE_IP_ADDRESS = None
                    elif is_ipv4_address(setting_value):
                        Settings.CAPTURE_IP_ADDRESS = setting_value
                    else:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_MAC_ADDRESS":
                    if setting_value == "None":
                        Settings.CAPTURE_MAC_ADDRESS = None
                    elif is_mac_address(setting_value):
                        formatted_mac_address = format_mac_address(setting_value)
                        if not formatted_mac_address == setting_value:
                            need_rewrite_settings = True
                        Settings.CAPTURE_MAC_ADDRESS = formatted_mac_address
                    else:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_ARP":
                    try:
                        Settings.CAPTURE_ARP, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_BLOCK_THIRD_PARTY_SERVERS":
                    try:
                        Settings.CAPTURE_BLOCK_THIRD_PARTY_SERVERS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_PROGRAM_PRESET":
                    try:
                        Settings.CAPTURE_PROGRAM_PRESET, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        if setting_value in ["GTA5", "Minecraft"]:
                            Settings.CAPTURE_PROGRAM_PRESET = setting_value
                        else:
                            need_rewrite_settings = True
                elif setting_name == "CAPTURE_VPN_MODE":
                    try:
                        Settings.CAPTURE_VPN_MODE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "CAPTURE_OVERFLOW_TIMER":
                    try:
                        CAPTURE_OVERFLOW_TIMER = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if CAPTURE_OVERFLOW_TIMER >= 1:
                            Settings.CAPTURE_OVERFLOW_TIMER = CAPTURE_OVERFLOW_TIMER
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_SHOW_ADVERTISING_HEADER":
                    try:
                        Settings.STDOUT_SHOW_ADVERTISING_HEADER, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_RESET_INFOS_ON_CONNECTED":
                    try:
                        Settings.STDOUT_RESET_INFOS_ON_CONNECTED, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELDS_TO_HIDE":
                    try:
                        stdout_fields_to_hide = ast.literal_eval(setting_value)
                    except ValueError:
                        need_rewrite_settings = True
                    else:
                        if isinstance(stdout_fields_to_hide, list):
                            # Filter out invalid field names from stdout_fields_to_hide
                            filtered_stdout_fields_to_hide = [field_name for field_name in stdout_fields_to_hide if field_name in Settings._valid_stdout_hidden_fields]

                            # Check if any invalid field names were removed
                            if set(stdout_fields_to_hide) != set(filtered_stdout_fields_to_hide):
                                need_rewrite_settings = True

                            # Update STDOUT_FIELDS_TO_HIDE with the corrected list
                            Settings.STDOUT_FIELDS_TO_HIDE = filtered_stdout_fields_to_hide
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_SHOW_SEEN_DATE":
                    try:
                        Settings.STDOUT_FIELD_SHOW_SEEN_DATE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY":
                    if setting_value in Settings._stdout_fields_mapping.keys():
                        Settings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY = setting_value
                    else:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY":
                    if setting_value in Settings._stdout_fields_mapping.keys():
                        Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY = setting_value
                    else:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_DISCONNECTED_PLAYERS_TIMER":
                    try:
                        player_disconnected_timer = float(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if player_disconnected_timer >= 3.0:
                            Settings.STDOUT_DISCONNECTED_PLAYERS_TIMER = player_disconnected_timer
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_DISCONNECTED_PLAYERS_COUNTER":
                    try:
                        stdout_counter_session_disconnected_players = int(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if stdout_counter_session_disconnected_players >= 0:
                            Settings.STDOUT_DISCONNECTED_PLAYERS_COUNTER = stdout_counter_session_disconnected_players
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
                elif setting_name == "BLACKLIST_ENABLED":
                    try:
                        Settings.BLACKLIST_ENABLED, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "BLACKLIST_NOTIFICATIONS":
                    try:
                        Settings.BLACKLIST_NOTIFICATIONS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "BLACKLIST_VOICE_NOTIFICATIONS":
                    try:
                        Settings.BLACKLIST_VOICE_NOTIFICATIONS, need_rewrite_current_setting = custom_str_to_bool(setting_value, only_match_against=False)
                    except InvalidBooleanValueError:
                        if setting_value in ["Male", "Female"]:
                            Settings.BLACKLIST_VOICE_NOTIFICATIONS = setting_value
                        else:
                            need_rewrite_settings = True
                elif setting_name == "BLACKLIST_PROTECTION":
                    try:
                        Settings.BLACKLIST_PROTECTION, need_rewrite_current_setting = custom_str_to_bool(setting_value, only_match_against=False)
                    except InvalidBooleanValueError:
                        if setting_value in [
                            "Exit_Process", "Restart_Process", "Shutdown_PC", "Restart_PC"
                        ]:
                            Settings.BLACKLIST_PROTECTION = setting_value
                        else:
                            need_rewrite_settings = True
                elif setting_name == "BLACKLIST_PROTECTION_EXIT_PROCESS_PATH":
                    try:
                        Settings.BLACKLIST_PROTECTION_EXIT_PROCESS_PATH, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        blacklist_protection_exit_process_path = Path(setting_value)
                        if blacklist_protection_exit_process_path.is_file():
                            Settings.BLACKLIST_PROTECTION_EXIT_PROCESS_PATH = blacklist_protection_exit_process_path
                        else:
                            need_rewrite_settings = True
                elif setting_name == "BLACKLIST_PROTECTION_RESTART_PROCESS_PATH":
                    try:
                        Settings.BLACKLIST_PROTECTION_RESTART_PROCESS_PATH, need_rewrite_current_setting = custom_str_to_nonetype(setting_value)
                    except InvalidNoneTypeValueError:
                        blacklist_protection_restart_process_path = Path(setting_value)
                        if (
                            blacklist_protection_restart_process_path.is_file()
                            or blacklist_protection_restart_process_path.is_symlink()
                        ):
                            Settings.BLACKLIST_PROTECTION_RESTART_PROCESS_PATH = blacklist_protection_restart_process_path
                        else:
                            need_rewrite_settings = True

                if need_rewrite_current_setting:
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
        organization_name: str = None,
        packets_sent: int = None,
        packets_recv: int = None
    ):
        self.name = name
        self.ip_addresses = ip_addresses
        self.mac_address = mac_address
        self.organization_name = organization_name
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
    PC_Discord = ["66.22.196.0/22", "66.22.237.0/24", "66.22.238.0/24", "66.22.241.0/24", "66.22.243.0/24", "66.22.244.0/24"]
    PC_Valve = ["155.133.248.0/24", "162.254.197.0/24", "185.25.180.0/23", "185.25.182.0/24"] # Valve = Steam
    PC_Google = ["34.0.192.0/19", "34.0.240.0/20", "35.214.128.0/17"]
    PC_multicast = ["224.0.0.0/4"]
    GTAV_PC_and_PS3_TakeTwo = ["104.255.104.0/23", "104.255.106.0/24", "185.56.64.0/22", "192.81.241.0/24", "192.81.244.0/23"]
    GTAV_PC_Microsoft = ["52.139.128.0/18"]
    GTAV_PC_DoD_Network_Information_Center = ["26.0.0.0/8"]
    GTAV_PC_BattleEye = ["51.89.99.255/32"]
    PC_IDK = ["113.117.15.193/32"]
    GTAV_XboxOne_Microsoft = ["52.159.128.0/17", "52.160.0.0/16", "40.74.0.0/18"]
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

class Player_PPS:
    def __init__(self, packet_datetime: datetime):
        self.t1 = packet_datetime
        self.counter = 0
        self.rate = 0
        self.is_first_calculation = True

class Player_Ports:
    def __init__(self, port: int):
        self.list = [port]
        self.first = port
        self.last = port

class Player_DateTime:
    def __init__(self, packet_datetime: datetime):
        self.first_seen = packet_datetime
        self.last_seen = packet_datetime
        self.left = None

class MaxMind_GeoLite2:
    def __init__(self):
        self.is_initialized = False

        self.country = None
        self.country_iso = None
        self.city = None
        self.asn = None

class IPAPI:
    def __init__(self):
        self.is_initialized = False

        self.continent = None
        self.continentCode = None
        self.country = None
        self.countryCode = None
        self.region = None
        self.regionName = None
        self.city = None
        self.district = None
        self.zipcode = None
        self.lat = None
        self.lon = None
        self.timezone = None
        self.offset = None
        self.currency = None
        self.isp = None
        self.org = None
        self.asnumber = None
        self.asname = None
        self.mobile = None
        self.proxy = None
        self.hosting = None

class Player_IPLookup:
    def __init__(self):
        self.maxmind = MaxMind_GeoLite2()
        self.ipapi = IPAPI()

class Player_Blacklist:
    def __init__(self):
        self.detection_type = None
        self.usernames: list[str] = []
        self.notification_t1 = None
        self.time =  None
        self.date_time = None
        self.processed_logging = False
        self.processed_protection = False

class Player:
    def __init__(self, packet_datetime: datetime, ip: str, port: int):
        self.ip = ip
        self.two_take_one__usernames = []

        self.rejoins = 0
        self.packets = 1

        self.pps = Player_PPS(packet_datetime)
        self.ports = Player_Ports(port)
        self.datetime = Player_DateTime(packet_datetime)
        self.iplookup = Player_IPLookup()
        self.blacklist = Player_Blacklist()

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

class IPLookup:
    lock =  threading.Lock()
    _lock_pending_ips = threading.Lock()
    _lock_results_ips = threading.Lock()

    _pending_ips_for_lookup: list[str] = []
    _results_ips_for_lookup: dict[str, IPAPI] = {}

    @classmethod
    def add_pending_ip(cls, ip: str):
        with cls._lock_pending_ips:
            if ip in cls._pending_ips_for_lookup:
                raise ValueError(f"IP address '{ip}' is already in the pending IP lookup list.")
            cls._pending_ips_for_lookup.append(ip)

    @classmethod
    def remove_pending_ip(cls, ip: str):
        with cls._lock_pending_ips:
            if ip in cls._pending_ips_for_lookup:
                cls._pending_ips_for_lookup.remove(ip)

    @classmethod
    def get_pending_ips(cls):
        with cls._lock_pending_ips:
            return cls._pending_ips_for_lookup

    @classmethod
    def get_pending_ips_slice(cls, start: int, end: int):
        with cls._lock_pending_ips:
            return cls._pending_ips_for_lookup[start:end]

    @classmethod
    def update_results(cls, ip: str, result: IPAPI):
        with cls._lock_results_ips:
            cls._results_ips_for_lookup[ip] = result

    @classmethod
    def get_results(cls, ip: str):
        with cls._lock_results_ips:
            return cls._results_ips_for_lookup.get(ip)

    @classmethod
    def ip_in_pending(cls, ip: str):
        with cls._lock_pending_ips:
            return ip in cls._pending_ips_for_lookup

    @classmethod
    def ip_in_results(cls, ip: str):
        with cls._lock_results_ips:
            return ip in cls._results_ips_for_lookup

    @classmethod
    def ip_exists(cls, ip: str):
        with cls._lock_pending_ips:
            if ip in cls._pending_ips_for_lookup:
                return "pending"
        with cls._lock_results_ips:
            if  ip in cls._results_ips_for_lookup:
                return "results"
        return "not found"

class SessionHost:
    player = None
    search_player = False
    players_pending_for_disconnection = []

    def get_host_player(session_connected: list[Player]):
        connected_players: list[Player] = take(2, sorted(session_connected, key=attrgetter("datetime.first_seen")))

        potential_session_host_player = None

        if len(connected_players) == 1:
            potential_session_host_player = connected_players[0]
        elif len(connected_players) == 2:
            time_difference = connected_players[1].datetime.first_seen - connected_players[0].datetime.first_seen
            if time_difference >= timedelta(milliseconds=200):
                potential_session_host_player = connected_players[0]
        else:
            raise ValueError(f"Unexpected number of connected players: {len(connected_players)}")

        if potential_session_host_player and (
            # Skip players remaining to be disconnected from the previous session.
            potential_session_host_player not in SessionHost.players_pending_for_disconnection
            # Ensures that we only check for the newly joined session's players.
            # The lower this value, the riskier it becomes, as it could potentially flag a player who ultimately isn't part of the newly discovered session.
            # In such scenarios, a better approach might involve checking around 25-100 packets.
            # However, increasing this value also increases the risk, as the host may have already disconnected.
            and potential_session_host_player.packets >= 50
        ):
            SessionHost.player = potential_session_host_player
            SessionHost.search_player = False

def is_pyinstaller_compiled():
    return getattr(sys, "frozen", False) # Check if the running Python script is compiled using PyInstaller, cx_Freeze or similar

def resource_path(relative_path: Path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)
    if not isinstance(base_path, Path):
        base_path = Path(base_path)
    return base_path / relative_path

def title(title: str):
    print(f"\033]0;{title}\007", end="")

def cls():
    print("\033c", end="")

def take(n: int, iterable: list):
    """Return first n items of the iterable as a list."""
    return iterable[:n]

def tail(n: int, iterable: list):
    """Return last n items of the iterable as a list."""
    return iterable[-n:]

def concat_lists_no_duplicates(list1: list, list2: list):
    combined_list = list1 + list2

    # Remove duplicates while preserving order
    unique_list = []
    seen = set()
    for item in combined_list:
        if item not in seen:
            unique_list.append(item)
            seen.add(item)

    return unique_list

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
    except AddressValueError:
        return False

def is_mac_address(mac_address: str):
    return bool(RE_MAC_ADDRESS_PATTERN.match(mac_address))

def is_private_device_ipv4(ip_address: str):
    try:
        ipv4_obj = IPv4Address(ip_address)
    except AddressValueError:
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

def get_pid_by_path(filepath: Path):
    for process in psutil.process_iter(['pid', 'exe']):
        if process.info['exe'] == str(filepath.absolute()):
            return process.pid
    return None

def get_interface_info(interface_index: str):
    c: _wmi_namespace = wmi.WMI()
    if not isinstance(c, _wmi_namespace):
        raise TypeError(f"Expected '_wmi_namespace' object, got '{type(c)}'")

    interfaces: list[_wmi_object] = c.Win32_NetworkAdapter(InterfaceIndex=interface_index)
    if not isinstance(interfaces, list):
        raise TypeError(f"Expected 'list', got '{type(interfaces)}'")
    if not interfaces:
        return None
    if len(interfaces) > 1:
        crash_text = textwrap.dedent(f"""
            ERROR:
                   Developer didn't expect this scenario to be possible.

            INFOS:
                   \"WMI\" Python's module returned more then one
                   interface for a given interface Index.

            DEBUG:
                   interface_index: {interface_index}
                   interfaces: {interfaces}
                   len(interfaces): {len(interfaces)}
        """.removeprefix("\n").removesuffix("\n"))
        init_script_crash_under_control(crash_text)
        raise ScriptCrashedUnderControl

    interface = interfaces[0]
    if not isinstance(interface, _wmi_object):
        raise TypeError(f"Expected '_wmi_object' object, got '{type(interface)}'")

    return interface

def get_organization_name(mac_address: str | None):
    if mac_address is None:
        return None

    oui_or_mal_infos: list[dict[str, str]] = mac_lookup.lookup(mac_address)
    if not oui_or_mal_infos:
        return None

    for oui_or_mal in oui_or_mal_infos:
        organization_name = oui_or_mal["organization_name"]
        if not organization_name == "":
            return organization_name

    return None

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
            if not interface_info:
                continue

            interface_name: str | None = interface_info.NetConnectionID
            if not isinstance(interface_name, str):
                crash_text = textwrap.dedent(f"""
                    ERROR:
                           Developer didn't expect this scenario to be possible.

                    INFOS:
                           The "WMI" Python module returned an unexpected
                           type for the interface name; expected 'str'.

                    DEBUG:
                           type(interface_name).__name__: {type(interface_name).__name__}
                           interface_index: {interface_index}
                           interface_name: {interface_name}
                """.removeprefix("\n").removesuffix("\n"))
                init_script_crash_under_control(crash_text)
                raise ScriptCrashedUnderControl

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
        crash_text = textwrap.dedent(f"""
            ERROR:
                   Developer didn't expect this scenario to be possible.

            INFOS:
                   It seems like a MAC address does not follow
                   \"xx:xx:xx:xx:xx:xx\" or \"xx-xx-xx-xx-xx-xx\"
                   format.

            DEBUG:
                   mac_address: {mac_address}
        """.removeprefix("\n").removesuffix("\n"))
        init_script_crash_under_control(crash_text)
        raise ScriptCrashedUnderControl

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
            with geolite2_version_file_path.open("r", encoding="utf-8") as f:
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

        with geolite2_version_file_path.open("w", encoding="utf-8") as f:
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
            geolite2_asn_reader = geoip2.database.Reader(geolite2_databases_folder_path / "GeoLite2-ASN.mmdb")
            geolite2_city_reader = geoip2.database.Reader(geolite2_databases_folder_path / "GeoLite2-City.mmdb")
            geolite2_country_reader = geoip2.database.Reader(geolite2_databases_folder_path / "GeoLite2-Country.mmdb")

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
    msgbox_message = ""

    if update_geolite2_databases__dict["exception"]:
        msgbox_message += f"Exception Error: {update_geolite2_databases__dict['exception']}\n\n"
        show_error = True
    if update_geolite2_databases__dict["url"]:
        msgbox_message += f"Error: Failed fetching url: \"{update_geolite2_databases__dict['url']}\"."
        if update_geolite2_databases__dict["http_code"]:
            msgbox_message += f" (http_code: {update_geolite2_databases__dict['http_code']})"
        msgbox_message += "\nImpossible to keep Maxmind's GeoLite2 IP to Country, City and ASN resolutions feature up-to-date.\n\n"
        show_error = True

    if exception__initialize_geolite2_readers:
        msgbox_message += f"Exception Error: {exception__initialize_geolite2_readers}\n\n"
        msgbox_message += "Now disabling MaxMind's GeoLite2 IP to Country, City and ASN resolutions feature.\n"
        msgbox_message += "Countrys, Citys and ASN from players won't shows up from the players fields."
        geoip2_enabled = False
        show_error = True
    else:
        geoip2_enabled = True

    if show_error:
        msgbox_title = TITLE
        msgbox_message = msgbox_message.rstrip("\n")
        msgbox_style = Msgbox.OKOnly | Msgbox.Exclamation
        show_message_box(msgbox_title, msgbox_message, msgbox_style)

    return geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader

def parse_ini_file(ini_path: Path, values_handling: Literal["first", "last", "all"]):
    def process_ini_line_output(line: str):
        return line.rstrip("\n")

    if not ini_path.exists():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                                str(ini_path.absolute()))
    if not ini_path.is_file():
        raise InvalidFileError(str(ini_path.absolute()))

    ini_data = ini_path.read_text("utf-8")

    need_rewrite_ini = False
    ini_db = {}

    for line in map(process_ini_line_output, ini_data.splitlines(keepends=False)):
        corrected_line = line.strip()
        if not corrected_line == line:
            need_rewrite_ini = True

        match = RE_INI_PARSER_PATTERN.search(corrected_line)
        if not match:
            continue
        key_name = match.group("key")
        key_value = match.group("value")

        corrected_key_name = key_name.strip()
        if corrected_key_name == "":
            continue
        elif not corrected_key_name == key_name:
            need_rewrite_ini = True

        corrected_key_value = key_value.strip()
        if corrected_key_value == "":
            continue
        elif not corrected_key_value == key_value:
            need_rewrite_ini = True

        if values_handling == "first":
            if corrected_key_name not in ini_db:
                ini_db[corrected_key_name] = corrected_key_value
        elif values_handling == "last":
            ini_db[corrected_key_name] = corrected_key_value
        elif values_handling == "all":
            if corrected_key_name in ini_db:
                ini_db[corrected_key_name].append(corrected_key_value)
            else:
                ini_db[corrected_key_name] = [corrected_key_value]

    return ini_db, need_rewrite_ini

def is_file_need_newline_ending(file):
    file = Path(file)
    if file.stat().st_size == 0:
        return False

    return not file.read_bytes().endswith(b"\n")

def kill_process_tree(pid: int):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.terminate()
        psutil.wait_procs(children, timeout=5)
        parent.terminate()
        parent.wait(5)
    except psutil.NoSuchProcess:
        pass

def terminate_current_script_process(terminate_method: Literal["EXIT", "SIGINT", "THREAD_RAISED"]):
    if terminate_method == "EXIT":
        if exit__signal.is_set():
            return
        exit__signal.set()

    elif terminate_method == "SIGINT":
        if keyboard_interrupt__signal.is_set():
            return
        keyboard_interrupt__signal.set()

        print(f"\n{Fore.YELLOW}Ctrl+C pressed. Exiting script ...{Fore.RESET}")

    elif terminate_method == "THREAD_RAISED":
        if threads_raised__signal.is_set():
            return
        threads_raised__signal.set()

        log_and_display_exception(Threads_ExceptionHandler.raising_e_type, Threads_ExceptionHandler.raising_e_value, Threads_ExceptionHandler.raising_e_traceback)

    exit_gracefully = True

    for thread_name in ["stdout_render_core__thread", "iplookup_core__thread", "blacklist_sniffer_core__thread"]:
        if thread_name in globals():
            thread = globals()[thread_name]
            if isinstance(thread, threading.Thread):
                if thread.is_alive():
                    exit_gracefully = False

    if exit_gracefully:
        sys.exit(1) if terminate_method == "THREAD_RAISED" else sys.exit(0)
    else:
        pid = os.getpid() # Get the process ID (PID) of the current script
        process = psutil.Process(pid)
        process.terminate()

def init_script_crash_under_control(crash_text: str):
    ScriptControl.set_crashed(f"\n\n{crash_text}\n")

    msgbox_title = TITLE
    msgbox_message = crash_text
    msgbox_style = Msgbox.OKOnly | Msgbox.Critical

    crash_alert__thread = threading.Thread(target=show_message_box, args=(msgbox_title, msgbox_message, msgbox_style))
    crash_alert__thread.start()

    time.sleep(1)

    print(ScriptControl.get_message())

    crash_alert__thread.join()

def signal_handler(sig: int, frame: FrameType):
    if sig == 2: # means CTRL+C pressed
        if not ScriptControl.has_crashed(): # Block CTRL+C if script is already crashing under control
            terminate_current_script_process("SIGINT")

colorama.init(autoreset=True)
signal.signal(signal.SIGINT, signal_handler)
exit__signal = threading.Event()
keyboard_interrupt__signal = threading.Event()
threads_raised__signal = threading.Event()

if is_pyinstaller_compiled():
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

TITLE = "GTA V Session Sniffer"
VERSION = "v1.1.5 - 16/09/2024 (20:02)"
TITLE_VERSION = f"{TITLE} {VERSION}"
SETTINGS_PATH = Path("Settings.ini")
BLACKLIST_PATH = Path("Blacklist.ini")
BLACKLIST_LOGGING_PATH = Path("blacklist.log")
TWO_TAKE_ONE__PLUGIN__LOG_PATH = Path.home() / "AppData/Roaming/PopstarDevs/2Take1Menu/scripts/GTA_V_Session_Sniffer-plugin/log.txt"
TTS_PATH = resource_path(Path("TTS/"))
RE_MAC_ADDRESS_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
RE_INI_PARSER_PATTERN = re.compile(r"^(?P<key>[^=]+)=(?P<value>[^;#]+)")
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
        "colorama": "0.4.6",
        "geoip2": "4.8.0",
        "prettytable": "3.10.2",
        "psutil": "6.0.0",
        "requests": "2.32.3",
        "urllib3": "2.2.2",
        "WMI": "1.5.1"
    }

    outdated_packages: list[tuple[str, str, str]] = check_packages_version(third_party_packages)
    if outdated_packages:
        msgbox_message = "Your following packages are not up to date:\n\n"
        msgbox_message += f"Package Name: Installed version --> Required version\n"

        # Iterate over outdated packages and add each package's information to the message box text
        for package_name, installed_version, required_version in outdated_packages:
            msgbox_message += f"{package_name}: {installed_version} --> {required_version}\n"

        # Add additional message box text
        msgbox_message += f"\nKeeping your packages synced with \"{TITLE}\" ensures smooth script execution and prevents compatibility issues."
        msgbox_message += "\n\nDo you want to ignore this warning and continue with script execution?"

        # Show message box
        msgbox_style = Msgbox.YesNo | Msgbox.Exclamation
        msgbox_title = TITLE
        errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
        if errorlevel != 6:
            terminate_current_script_process("EXIT")

cls()
title(f"Initializing the script for your Windows version - {TITLE}")
print("\nInitializing the script for your Windows version ...\n")
if sys.getwindowsversion().major >= 10:
    UNDERLINE = "\033[4m"
    UNDERLINE_RESET = "\033[24m"
else:
    UNDERLINE = "_"
    UNDERLINE_RESET = "_"

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
        latest_version = Version(response.text.strip().rstrip())
        if Updater(current_version).check_for_update(latest_version):
            msgbox_title = TITLE
            msgbox_message = textwrap.dedent(f"""
                New version found. Do you want to update ?

                Current version: {current_version}
                Latest version: {latest_version}
            """.removeprefix("\n").removesuffix("\n"))
            msgbox_style = Msgbox.YesNo | Msgbox.Question
            errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
            if errorlevel == 6:
                webbrowser.open("https://github.com/Illegal-Services/GTA-V-Session-Sniffer")
                terminate_current_script_process("EXIT")
    else:
        error_updating__flag = True

if error_updating__flag:
    msgbox_title = TITLE
    msgbox_message = f"""
        ERROR: {TITLE} Failed updating itself.

        Do you want to open the \"{TITLE}\" project download page ?
        You can then download and run the latest version from there.
    """
    msgbox_message = textwrap.dedent(msgbox_message).removeprefix("\n").removesuffix("\n")
    msgbox_style = Msgbox.YesNo | Msgbox.Exclamation
    errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
    if errorlevel == 6:
        webbrowser.open("https://github.com/Illegal-Services/GTA-V-Session-Sniffer")
        terminate_current_script_process("EXIT")

cls()
title(f"Checking that \"Npcap\" or \"WinpCap\" driver is installed on your system - {TITLE}")
print("\nChecking that \"Npcap\" or \"WinpCap\" driver is installed on your system ...\n")
while True:
    if npcap_or_winpcap_installed():
        break
    else:
        webbrowser.open("https://nmap.org/npcap/")
        msgbox_title = TITLE
        msgbox_message = f"""
            ERROR: {TITLE} could not detect the \"Npcap\" or \"WinpCap\" driver installed on your system.

            Opening the \"Npcap\" project download page for you.
            You can then download and install it from there and press \"Retry\".
        """
        msgbox_message = textwrap.dedent(msgbox_message).removeprefix("\n").removesuffix("\n")
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
        if errorlevel == 2:
            terminate_current_script_process("EXIT")

cls()
title(f"Applying your custom settings from \"Settings.ini\" - {TITLE}")
print("\nApplying your custom settings from \"Settings.ini\" ...\n")
Settings.load_from_settings_file(SETTINGS_PATH)
if Settings.BLACKLIST_VOICE_NOTIFICATIONS:
    if Settings.BLACKLIST_VOICE_NOTIFICATIONS == "Male":
        VOICE_NAME = "Liam"
    elif Settings.BLACKLIST_VOICE_NOTIFICATIONS == "Female":
        VOICE_NAME = "Jane"

cls()
title(f"Initializing and updating MaxMind's GeoLite2 Country, City and ASN databases - {TITLE}")
print("\nInitializing and updating MaxMind's GeoLite2 Country, City and ASN databases ...\n")
geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader = update_and_initialize_geolite2_readers()

cls()
title(f"Initializing MacLookup module - {TITLE}")
print(f"\nInitializing MacLookup module ...\n")
mac_lookup = MacLookup(bypass_fetch_error=True)

cls()
title(f"Capture network interface selection - {TITLE}")
print(f"\nCapture network interface selection ...\n")
if Settings.CAPTURE_ARP:
    cached_arp_dict = get_and_parse_arp_cache()

net_io_stats = psutil.net_io_counters(pernic=True)
net_if_addrs = psutil.net_if_addrs()

for interface, stats in net_io_stats.items():
    if interface not in net_if_addrs:
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
        crash_text = textwrap.dedent(f"""
            ERROR:
                   Developer didn't expect this scenario to be possible.

            INFOS:
                   The IP address has multiple MAC addresses.

            DEBUG:
                   interface: {interface}
                   ip_addresses: {ip_addresses}
                   mac_addresses: {mac_addresses}
        """.removeprefix("\n").removesuffix("\n"))
        init_script_crash_under_control(crash_text)
        raise ScriptCrashedUnderControl

    ip_addresses = [ip for ip in ip_addresses if is_private_device_ipv4(ip)]
    if not ip_addresses:
        continue

    mac_address = format_mac_address(mac_addresses[0]) if mac_addresses else None

    organization_name = (
        get_organization_name(mac_address)
        or "N/A"
    )

    Interface(interface, ip_addresses, mac_address, organization_name, stats.packets_sent, stats.packets_recv)

    if not Settings.CAPTURE_ARP:
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
                    "organization_name": (
                        get_organization_name(entry["mac_address"])
                        or "N/A"
                    )
                }
                for entry in interface_info["interface_arp_output"]
                if is_private_device_ipv4(entry["ip_address"])
            ]

            Interface.get_interface_by_name(interface).add_arp_info(ip_address, mac_address, arp_info)

table = PrettyTable()
table.field_names = ["#", "Interface", "Packets Sent", "Packets Received", "IP Address", "MAC Address", "Organization Name"]
table.align["#"] = "c"
table.align["Interface"] = "l"
table.align["Packets Sent"] = "c"
table.align["Packets Received"] = "c"
table.align["IP Address"] = "l"
table.align["MAC Address"] = "c"
table.align["Organization Name"] = "c"

interfaces_options: dict[int, dict[str, str | None]] = {}
counter = 0

for interface in Interface.get_all_interfaces():
    if (
        Settings.CAPTURE_INTERFACE_NAME is not None
        and Settings.CAPTURE_INTERFACE_NAME.lower() == interface.name.lower()
        and not Settings.CAPTURE_INTERFACE_NAME == interface.name
    ):
        Settings.CAPTURE_INTERFACE_NAME = interface.name
        Settings.reconstruct_settings()

    for ip_address in interface.ip_addresses:
        counter += 1

        interfaces_options[counter] = {
            "is_arp": False,
            "Interface": interface.name,
            "IP Address": ip_address,
            "MAC Address": interface.mac_address
        }

        table.add_row([f"{Fore.YELLOW}{counter}{Fore.RESET}", interface.name, interface.packets_sent, interface.packets_recv, ip_address, interface.mac_address, interface.organization_name])

    if not Settings.CAPTURE_ARP:
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

            table.add_row([f"{Fore.YELLOW}{counter}{Fore.RESET}", f"{interface.name} (ARP)", "N/A", "N/A", detail["ip_address"], detail["mac_address"], detail["organization_name"]])

user_interface_selection = None

if (
    not Settings.CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT
    and any(setting is not None for setting in [Settings.CAPTURE_INTERFACE_NAME, Settings.CAPTURE_MAC_ADDRESS, Settings.CAPTURE_IP_ADDRESS])
):
    max_priority = 0

    for interface_counter, interface_options in interfaces_options.items():
        priority = 0

        if Settings.CAPTURE_INTERFACE_NAME == interface_options["Interface"]:
            priority += 1
        if Settings.CAPTURE_MAC_ADDRESS == interface_options["MAC Address"]:
            priority += 1
        if Settings.CAPTURE_IP_ADDRESS == interface_options["IP Address"]:
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

if not Settings.CAPTURE_INTERFACE_NAME == interfaces_options[user_interface_selection]["Interface"]:
    Settings.CAPTURE_INTERFACE_NAME = interfaces_options[user_interface_selection]["Interface"]
    need_rewrite_settings = True

if not Settings.CAPTURE_MAC_ADDRESS == interfaces_options[user_interface_selection]["MAC Address"]:
    Settings.CAPTURE_MAC_ADDRESS = interfaces_options[user_interface_selection]["MAC Address"]
    need_rewrite_settings = True

if not Settings.CAPTURE_IP_ADDRESS == interfaces_options[user_interface_selection]["IP Address"]:
    Settings.CAPTURE_IP_ADDRESS = interfaces_options[user_interface_selection]["IP Address"]
    need_rewrite_settings = True

if need_rewrite_settings:
    Settings.reconstruct_settings()

capture_filter: list[str]  = [
    f"((src host {Settings.CAPTURE_IP_ADDRESS} and (not (dst net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))) or (dst host {Settings.CAPTURE_IP_ADDRESS} and (not (src net 10.0.0.0/8 or 100.64.0.0/10 or 172.16.0.0/12 or 192.168.0.0/16 or 224.0.0.0/4))))",
    "udp"
]
display_filter: list[str] = []
excluded_protocols = []

if not Settings.CAPTURE_VPN_MODE:
    capture_filter.append(f"not (broadcast or multicast)")
capture_filter.append("not (portrange 0-1023 or port 5353)")

if Settings.CAPTURE_PROGRAM_PRESET:
    if Settings.CAPTURE_PROGRAM_PRESET == "GTA5":
        display_filter.append("(frame.len>=71 and frame.len<=999)")
    elif Settings.CAPTURE_PROGRAM_PRESET == "Minecraft":
        display_filter.append("(frame.len>=49 and frame.len<=1498)")

    # If the <CAPTURE_PROGRAM_PRESET> setting is set, automatically blocks RTCP connections.
    # In case RTCP can be useful to get someone IP, I decided not to block them without using a <CAPTURE_PROGRAM_PRESET>.
    # RTCP is known to be for example the Discord's server IP while you are in a call there.
    # The "not rtcp" Display Filter have been heavily tested and I can confirm that it's indeed working correctly.
    # I know that eventually you will see their corresponding IPs time to time but I can guarantee that it does the job it is supposed to do.
    # It filters RTCP but some connections are STILL made out of it, but those are not RTCP ¯\_(ツ)_/¯.
    # And that's exactly why the "Discord" (`class ThirdPartyServers`) IP ranges Capture Filters are useful for.
    excluded_protocols.append("rtcp")

if Settings.CAPTURE_BLOCK_THIRD_PARTY_SERVERS:
    ip_ranges = [ip_range for server in ThirdPartyServers for ip_range in server.value]
    capture_filter.append(f"not (net {' or '.join(ip_ranges)})")

    # Here I'm trying to exclude various UDP protocols that are usefless for the srcipt.
    # But there can be a lot more, those are just a couples I could find on my own usage.
    excluded_protocols.extend(["ssdp", "raknet", "dtls", "nbns", "pcp", "bt-dht", "uaudp", "classicstun", "dhcp", "mdns", "llmnr"])

if excluded_protocols:
    display_filter.append(
        f"not ({' or '.join(excluded_protocols)})"
    )

CAPTURE_FILTER = " and ".join(capture_filter) if capture_filter else None
DISPLAY_FILTER = " and ".join(display_filter) if display_filter else None

while True:
    try:
        capture = PacketCapture(
            interface = Settings.CAPTURE_INTERFACE_NAME,
            capture_filter = CAPTURE_FILTER,
            display_filter = DISPLAY_FILTER,
            tshark_path = Settings.CAPTURE_TSHARK_PATH
        )
    except TSharkNotFoundException:
        webbrowser.open("https://www.wireshark.org/download.html")
        msgbox_title = TITLE
        msgbox_message = textwrap.dedent(f"""
            ERROR: Could not detect \"Tshark\" installed on your system.

            Opening the \"Tshark\" project download page for you.
            You can then download and install it from there and press \"Retry\".
        """.removeprefix("\n").removesuffix("\n"))
        msgbox_style = Msgbox.RetryCancel | Msgbox.Exclamation
        errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
        if errorlevel == 2:
            terminate_current_script_process("EXIT")
    else:
        break

if not capture.tshark_path == Settings.CAPTURE_TSHARK_PATH:
    Settings.CAPTURE_TSHARK_PATH = capture.tshark_path
    Settings.reconstruct_settings()

def blacklist_sniffer_core():
    def create_blacklist_file():
        text = textwrap.dedent(f"""
            ;;-----------------------------------------------------------------------
            ;;Lines starting with \";\" or \"#\" symbols are commented lines.
            ;;
            ;;This is the blacklist file for \"GTA V Session Sniffer\" configuration.
            ;;
            ;;Your blacklist MUST be formatted in the following way in order to work:
            ;;<USERNAME>=<IP ADDRESS>
            ;;-----------------------------------------------------------------------
        """.removeprefix("\n"))
        BLACKLIST_PATH.write_text(text, encoding="utf-8")

    def blacklist_show_messagebox(player: Player):
        msgbox_title = TITLE
        msgbox_message = textwrap.indent(textwrap.dedent(f"""
            #### Blacklisted user detected at {player.blacklist.time} ####
            User{plural(len(player.blacklist.usernames))}: {', '.join(player.blacklist.usernames)}
            IP: {player.ip}
            Port{plural(len(player.ports.list))}: {', '.join(map(str, player.ports.list))}
            Country Code: {player.iplookup.maxmind.country_iso}
            Detection Type: {player.blacklist.detection_type}
            ############# IP Lookup ##############
            Continent: {player.iplookup.ipapi.continent}
            Country: {player.iplookup.maxmind.country}
            City: {player.iplookup.maxmind.city}
            Organization: {player.iplookup.ipapi.org}
            ISP: {player.iplookup.ipapi.isp}
            AS: {player.iplookup.ipapi.asnumber}
            AS Name: {player.iplookup.maxmind.asn}
            Mobile (cellular) connection: {player.iplookup.ipapi.mobile}
            Proxy, VPN or Tor exit address: {player.iplookup.ipapi.proxy}
            Hosting, colocated or data center: {player.iplookup.ipapi.hosting}
        """.removeprefix("\n").removesuffix("\n")), "    ")
        msgbox_style = Msgbox.OKOnly | Msgbox.Exclamation | Msgbox.SystemModal | Msgbox.MsgBoxSetForeground
        # deepcode ignore MissingAPI: If the thread was started and the program exits, it will be `join()` in the `terminate_current_script_process()` function.
        threading.Thread(target=show_message_box, args=(msgbox_title, msgbox_message, msgbox_style)).start()

    def text_to_speech(connection_type: Literal["connected", "disconnected"]):
        file_path = Path(f"{TTS_PATH}/{VOICE_NAME} ({connection_type}).wav")

        if not file_path.exists():
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                str(file_path.absolute()))
        if not file_path.is_file():
            raise InvalidFileError(str(file_path.absolute()))

        winsound.PlaySound(file_path, winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)

    with Threads_ExceptionHandler():
        while True:
            if ScriptControl.has_crashed():
                return

            start_time = datetime.now()

            try:
                blacklist, need_rewrite_blacklist = parse_ini_file(BLACKLIST_PATH, values_handling="all")
                blacklist: dict[str, list[str]]
            except FileNotFoundError:
                create_blacklist_file()
                continue

            for player in PlayersRegistry.iterate_players_from_registry():
                if not player.iplookup.maxmind.is_initialized:
                    continue

                player.blacklist.detection_type = Player_Blacklist().detection_type
                player.blacklist.usernames = Player_Blacklist().usernames

                for username, ips in blacklist.items():
                    for ip in ips:
                        if not is_ipv4_address(ip):
                            continue

                        if ip == player.ip:
                            player.blacklist.detection_type = "Static IP"

                            if username not in player.blacklist.usernames:
                                player.blacklist.usernames.append(username)

                if player.blacklist.detection_type is None:
                    player.blacklist = Player_Blacklist()
                    continue

                if player.datetime.left:
                    if (
                        Settings.BLACKLIST_VOICE_NOTIFICATIONS
                        and player.blacklist.notification_t1
                    ):
                        text_to_speech("disconnected")

                    player.blacklist.notification_t1 = Player_Blacklist().notification_t1
                    player.blacklist.processed_logging = Player_Blacklist().processed_logging
                    player.blacklist.processed_protection = Player_Blacklist().processed_protection
                    continue

                player.blacklist.time = player.datetime.last_seen.strftime("%H:%M:%S")
                player.blacklist.date_time = player.datetime.last_seen.strftime("%Y-%m-%d_%H:%M:%S")

                if (
                    Settings.BLACKLIST_VOICE_NOTIFICATIONS
                    and player.blacklist.notification_t1 is None
                ):
                    text_to_speech("connected")

                if not player.blacklist.processed_logging:
                    player.blacklist.processed_logging = True
                    with BLACKLIST_LOGGING_PATH.open("a", encoding="utf-8") as f:
                        newline = "\n" if is_file_need_newline_ending(BLACKLIST_LOGGING_PATH) else ""
                        # TODO
                        f.write(f"{newline}User{plural(len(player.blacklist.usernames))}:{', '.join(player.blacklist.usernames)} | IP:{player.ip} | Ports:{', '.join(map(str, player.ports.list))} | Time:{player.blacklist.date_time} | Country:{player.iplookup.maxmind.country} | Detection Type: {player.blacklist.detection_type}\n")

                if Settings.BLACKLIST_NOTIFICATIONS:
                    if not player.iplookup.ipapi.is_initialized:
                        continue

                    blacklist_notifaction_t2 = datetime.now()
                    if player.blacklist.notification_t1 is None:
                        player.blacklist.notification_t1 = blacklist_notifaction_t2
                        blacklist_show_messagebox(player)

                if Settings.BLACKLIST_PROTECTION:
                    if not player.blacklist.processed_protection:
                        player.blacklist.processed_protection = True
                        if Settings.BLACKLIST_PROTECTION in ["Exit_Process", "Restart_Process"]:
                            if isinstance(Settings.BLACKLIST_PROTECTION_EXIT_PROCESS_PATH, Path):
                                process_pid = get_pid_by_path(Settings.BLACKLIST_PROTECTION_EXIT_PROCESS_PATH)
                                if process_pid:
                                    kill_process_tree(process_pid)

                                    if (
                                        Settings.BLACKLIST_PROTECTION == "Restart_Process"
                                        and isinstance(Settings.BLACKLIST_PROTECTION_RESTART_PROCESS_PATH, Path)
                                    ):
                                        os.startfile(str(Settings.BLACKLIST_PROTECTION_RESTART_PROCESS_PATH.absolute()))
                        elif Settings.BLACKLIST_PROTECTION == "Shutdown_PC":
                            subprocess.Popen(["shutdown", "/s"])
                        elif Settings.BLACKLIST_PROTECTION == "Restart_PC":
                            subprocess.Popen(["shutdown", "/r"])

            execution_time = datetime.now() - start_time
            remaining_sleep_time = max(0, 3 - execution_time.total_seconds())
            if remaining_sleep_time > 0:
                time.sleep(remaining_sleep_time)

def iplookup_core():
    def throttle_until():
        requests_remaining = int(response.headers["X-Rl"])
        throttle_until = int(response.headers["X-Ttl"])

        if requests_remaining <= 1:
            time.sleep(throttle_until)
        else:
            time.sleep(throttle_until / requests_remaining)  # We sleep x seconds (just in case) to avoid triggering a "429" status code.

    with Threads_ExceptionHandler():
        # Following values taken from https://ip-api.com/docs/api:batch the 03/04/2024.
        MAX_REQUESTS = 15
        MAX_THROTTLE_TIME = 60
        MAX_BATCH_IP_API_IPS = 100
        FIELDS_TO_LOOKUP = "continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query"

        first_exec = True
        while True:
            if ScriptControl.has_crashed():
                return

            if not first_exec:
                time.sleep(1)
            else:
                first_exec = False

            players_connected_to_lookup: list[str] = []
            players_disconnected_to_lookup: list[str] = []
            removed_disconnected_ip = None

            for player in PlayersRegistry.iterate_players_from_registry():
                if player.iplookup.ipapi.is_initialized:
                    continue

                if player.datetime.left:
                    players_disconnected_to_lookup.append(player.ip)
                else:
                    players_connected_to_lookup.append(player.ip)

                if (len(players_connected_to_lookup) + len(players_disconnected_to_lookup)) == MAX_BATCH_IP_API_IPS:
                    if players_disconnected_to_lookup:
                        removed_disconnected_ip = players_disconnected_to_lookup.pop(-1)
                    else:
                        break

            ips_to_lookup = players_connected_to_lookup + players_disconnected_to_lookup
            if len(ips_to_lookup) < MAX_BATCH_IP_API_IPS:
                if (
                    len(ips_to_lookup) == (MAX_BATCH_IP_API_IPS - 1)
                    and removed_disconnected_ip
                ):
                    ips_to_lookup.append(removed_disconnected_ip)
                else:
                    remaining_space = MAX_BATCH_IP_API_IPS - len(ips_to_lookup)
                    items_to_add = IPLookup.get_pending_ips_slice(0, remaining_space)
                    ips_to_lookup.extend(items_to_add)

            # Ensure the final list is no longer than 100 elements
            ips_to_lookup = ips_to_lookup[:MAX_BATCH_IP_API_IPS]
            if len(ips_to_lookup) == 0:
                time.sleep(1) # If there are no new players to lookup, sleep for 1 second to reduce CPU usage.
                continue

            try:
                response = s.post(
                    f"http://ip-api.com/batch?fields={FIELDS_TO_LOOKUP}",
                    headers={"Content-Type": "application/json"},
                    json=ips_to_lookup,
                    timeout=3
                )
            except requests.exceptions.ConnectionError:
                continue

            if response.status_code != 200:
                throttle_until()
                continue

            iplookup_results = response.json()

            if not isinstance(iplookup_results, list):
                raise TypeError(f"Expected 'list' object, got '{type(iplookup_results)}'")

            for iplookup in iplookup_results:
                if not isinstance(iplookup, dict):
                    raise TypeError(f"Expected 'dict' object, got '{type(iplookup)}'")

                player_ip_looked_up: str = iplookup.get("query", None)
                if not isinstance(player_ip_looked_up, str):
                    raise TypeError(f"Expected 'str' object, got '{type(player_ip_looked_up)}'")

                ip_api_instance = IPAPI()
                ip_api_instance.is_initialized = True
                ip_api_instance.continent = iplookup.get("continent", "N/A")
                ip_api_instance.continentCode = iplookup.get("continentCode", "N/A")
                ip_api_instance.country = iplookup.get("country", "N/A")
                ip_api_instance.countryCode = iplookup.get("countryCode", "N/A")
                ip_api_instance.region = iplookup.get("region", "N/A")
                ip_api_instance.regionName = iplookup.get("regionName", "N/A")
                ip_api_instance.city = iplookup.get("city", "N/A")
                ip_api_instance.district = iplookup.get("district", "N/A")
                ip_api_instance.zipcode = iplookup.get("zip", "N/A")
                ip_api_instance.lat = iplookup.get("lat", "N/A")
                ip_api_instance.lon = iplookup.get("lon", "N/A")
                ip_api_instance.timezone = iplookup.get("timezone", "N/A")
                ip_api_instance.offset = iplookup.get("offset", "N/A")
                ip_api_instance.currency = iplookup.get("currency", "N/A")
                ip_api_instance.isp = iplookup.get("isp", "N/A")
                ip_api_instance.org = iplookup.get("org", "N/A")
                ip_api_instance.asnumber = iplookup.get("as", "N/A")
                ip_api_instance.asname = iplookup.get("asname", "N/A")
                ip_api_instance.mobile = iplookup.get("mobile", "N/A")
                ip_api_instance.proxy = iplookup.get("proxy", "N/A")
                ip_api_instance.hosting = iplookup.get("hosting", "N/A")

                with IPLookup.lock:
                    IPLookup.remove_pending_ip(player_ip_looked_up)
                    IPLookup.update_results(player_ip_looked_up, ip_api_instance)

                player_to_update = PlayersRegistry.get_player(player_ip_looked_up)
                if isinstance(player_to_update, Player):
                    player_to_update.iplookup.ipapi = ip_api_instance

            throttle_until()

tshark_latency = []

def stdout_render_core():
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

    def format_player_datetime(datetime_object: datetime):
        if Settings.STDOUT_FIELD_SHOW_SEEN_DATE:
            formatted_datetime = datetime_object.strftime("%m/%d/%Y %H:%M:%S.%f")[:-3]
        else:
            formatted_datetime = datetime_object.strftime("%H:%M:%S.%f")[:-3]

        return formatted_datetime

    def format_player_usernames(player_usernames: list[str]):
        if player_usernames:
            if len(player_usernames) > 1:
                player_usernames = f"{', '.join(player_usernames)}"
            else:
                player_usernames = player_usernames[0]
        else:
            player_usernames = "N/A"

        return f"{player_color}{player_usernames}{player_reset}"

    def format_player_pps(player_color: str, is_pps_first_calculation: bool, pps_rate: int):
        if pps_rate == 0:
            if is_pps_first_calculation:
                pps_color = player_color
            else:
                pps_color = Fore.RED
        elif pps_rate == 1:
            pps_color = Fore.YELLOW
        else:
            pps_color = player_color

        return f"{pps_color}{pps_rate}{Fore.RESET}"

    def format_player_ip(player_ip: str):
        if (
            SessionHost.player
            and SessionHost.player.ip == player_ip
        ):
            return f"{player_ip} 👑"
        else:
            return player_ip

    def format_player_ports_list(ports_list: list[int], last_port: int, first_port: int):
        formatted_ports = []

        if len(ports_list) == 1:
            return str(last_port)

        for port in reversed(ports_list):
            if not (
                port == last_port
                or port == first_port
            ):
                formatted_ports.append(str(port))

        if last_port == first_port:
            formatted_ports.insert(0, f"[{UNDERLINE}{last_port}{UNDERLINE_RESET}]")  # Insert last port at the beginning
        else:
            formatted_ports.insert(0, f"{UNDERLINE}{last_port}{UNDERLINE_RESET}")  # Insert last port at the beginning
            formatted_ports.append(f"[{first_port}]")  # Append first port at the end

        return ", ".join(formatted_ports)

    def add_down_arrow_char_to_sorted_table_field(field_names: list[str], target_field: str):
        for i, field in enumerate(field_names):
            if field == target_field:
                field_names[i] += " \u2193"
                break

    with Threads_ExceptionHandler():
        global iplookup_core__thread, global_pps_counter, tshark_latency

        session_connected_sorted_key = Settings._stdout_fields_mapping[Settings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY]
        session_disconnected_sorted_key = Settings._stdout_fields_mapping[Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY]

        connected_players_table__field_names = [
            field_name
            for field_name in [
                field_name
                for field_name in Settings._stdout_fields_mapping.keys()
                if not field_name == "Last Seen"
            ]
            if field_name not in Settings.STDOUT_FIELDS_TO_HIDE and (Settings.BLACKLIST_ENABLED or field_name != "Usernames")
        ]
        add_down_arrow_char_to_sorted_table_field(connected_players_table__field_names, Settings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY)

        disconnected_players_table__field_names = [
            field_name
            for field_name in [
                field_name
                for field_name in Settings._stdout_fields_mapping.keys()
                if not field_name == "PPS"
            ]
            if field_name not in Settings.STDOUT_FIELDS_TO_HIDE and (Settings.BLACKLIST_ENABLED or field_name != "Usernames")
        ]
        add_down_arrow_char_to_sorted_table_field(disconnected_players_table__field_names, Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY)

        printer = PrintCacher()
        global_pps_t1 = time.perf_counter()
        global_pps_rate = 0
        is_arp_enabled = "Enabled" if interfaces_options[user_interface_selection]["is_arp"] else "Disabled"
        padding_width = calculate_padding_width(109, 44, len(str(Settings.CAPTURE_IP_ADDRESS)), len(str(Settings.CAPTURE_INTERFACE_NAME)), len(str(is_arp_enabled)))
        stdout__scanning_on_network_interface = f"{' ' * padding_width}Scanning on network interface:{Fore.YELLOW}{Settings.CAPTURE_INTERFACE_NAME}{Fore.RESET} at IP:{Fore.YELLOW}{Settings.CAPTURE_IP_ADDRESS}{Fore.RESET} (ARP:{Fore.YELLOW}{is_arp_enabled}{Fore.RESET})"

        while True:
            if ScriptControl.has_crashed():
                return

            session_connected__padding_country_name = 0
            session_disconnected__padding_country_name = 0
            session_connected: list[Player] = []
            session_disconnected: list[Player] = []

            date_time_now = datetime.now()
            time_perf_counter = time.perf_counter()

            for player in PlayersRegistry.iterate_players_from_registry():
                if TWO_TAKE_ONE__PLUGIN__LOG_PATH.exists() and TWO_TAKE_ONE__PLUGIN__LOG_PATH.is_file():
                    for username in re.findall(
                        r"^user:(?P<username>[\w._-]{1,16}), scid:\d{1,9}, ip:%s, timestamp:\d{10}$" % re.escape(player.ip),
                        Path(TWO_TAKE_ONE__PLUGIN__LOG_PATH).read_text(encoding="utf-8"),
                        re.MULTILINE
                    ):
                        if username not in player.two_take_one__usernames:
                            player.two_take_one__usernames.append(username)

                if (
                    not player.datetime.left
                    and (date_time_now - player.datetime.last_seen) >= timedelta(seconds=Settings.STDOUT_DISCONNECTED_PLAYERS_TIMER)
                ):
                    player.datetime.left = player.datetime.last_seen

                if not player.iplookup.maxmind.is_initialized:
                    if "ASN" not in Settings.STDOUT_FIELDS_TO_HIDE:
                        player.iplookup.maxmind.asn = get_asn_info(player.ip)
                    if "Country" not in Settings.STDOUT_FIELDS_TO_HIDE:
                        player.iplookup.maxmind.country, player.iplookup.maxmind.country_iso = get_country_info(player.ip)
                    if "City" not in Settings.STDOUT_FIELDS_TO_HIDE:
                        player.iplookup.maxmind.city = get_city_info(player.ip)

                    player.iplookup.maxmind.is_initialized = True

                if player.datetime.left:
                    session_disconnected.append(player)
                else:
                    session_connected__padding_country_name = get_minimum_padding(player.iplookup.maxmind.country, session_connected__padding_country_name, 27)

                    player_time_delta = (date_time_now - player.pps.t1)
                    if player_time_delta >= timedelta(seconds=1):
                        player.pps.rate = round(player.pps.counter / player_time_delta.total_seconds())
                        player.pps.counter = 0
                        player.pps.t1 = date_time_now
                        player.pps.is_first_calculation = False

                    session_connected.append(player)

            session_connected.sort(key=attrgetter(session_connected_sorted_key))
            session_disconnected.sort(key=attrgetter(session_disconnected_sorted_key))

            if Settings.CAPTURE_PROGRAM_PRESET == "GTA5":
                if SessionHost.player:
                    if SessionHost.player.datetime.left:
                        SessionHost.player = None
                # we should also potentially needs to check that not more then 1s passed before each disconnected
                if SessionHost.players_pending_for_disconnection and all(player.datetime.left for player in SessionHost.players_pending_for_disconnection):
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection = []

                if len(session_connected) == 0:
                    SessionHost.player = None
                    SessionHost.search_player = True
                    SessionHost.players_pending_for_disconnection = []
                elif len(session_connected) >= 1 and all(not player.pps.is_first_calculation and player.pps.rate == 0 for player in session_connected):
                    SessionHost.players_pending_for_disconnection = session_connected
                else:
                    if SessionHost.search_player:
                        SessionHost.get_host_player(session_connected)

            session_disconnected_all = session_disconnected

            if Settings.STDOUT_DISCONNECTED_PLAYERS_COUNTER > 0:
                if Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY == "First Seen":
                    session_disconnected = take(Settings.STDOUT_DISCONNECTED_PLAYERS_COUNTER, session_disconnected)
                else:
                    session_disconnected = tail(Settings.STDOUT_DISCONNECTED_PLAYERS_COUNTER, session_disconnected)

            for player in session_disconnected:
                session_disconnected__padding_country_name = get_minimum_padding(player.iplookup.maxmind.country, session_disconnected__padding_country_name, 27)

            if (
                Settings.STDOUT_DISCONNECTED_PLAYERS_COUNTER == 0
                or Settings.STDOUT_DISCONNECTED_PLAYERS_COUNTER >= len(session_disconnected_all)
            ):
                len_session_disconnected_message = str(len(session_disconnected))
            else:
                len_session_disconnected_message = f"showing {len(session_disconnected)}/{len(session_disconnected_all)}"

            printer.cache_print("")

            if Settings.STDOUT_SHOW_ADVERTISING_HEADER:
                printer.cache_print("-" * 109)
                printer.cache_print(f"{UNDERLINE}Advertising{UNDERLINE_RESET}:")
                printer.cache_print("  * https://illegal-services.com/")
                printer.cache_print("")
                printer.cache_print(f"{UNDERLINE}Contact Details{UNDERLINE_RESET}:")
                printer.cache_print("    You can contact me from Email: BUZZARDGTA@protonmail.com, Discord: waitingforharukatoaddme or Telegram: https://t.me/waitingforharukatoaddme")
                printer.cache_print("")

            printer.cache_print(f"-" * 109)
            printer.cache_print(f"                         Welcome in {TITLE_VERSION}")
            printer.cache_print(f"                   This script aims in getting people's address IP from GTA V, WITHOUT MODS.")
            printer.cache_print(f"-   " * 28)
            printer.cache_print(stdout__scanning_on_network_interface)
            tshark_average_latency = sum(tshark_latency, timedelta(0)) / len(tshark_latency) if tshark_latency else timedelta(0)
            tshark_latency = []

            # Convert the average latency to seconds and round it to 1 decimal place
            average_latency_seconds = tshark_average_latency.total_seconds()
            average_latency_rounded = round(average_latency_seconds, 1)

            if tshark_average_latency >= timedelta(seconds=0.90 * Settings.CAPTURE_OVERFLOW_TIMER):  # Check if average latency exceeds 90% threshold
                latency_color = Fore.RED
            elif tshark_average_latency >= timedelta(seconds=0.75 * Settings.CAPTURE_OVERFLOW_TIMER):  # Check if average latency exceeds 75% threshold
                latency_color = Fore.YELLOW
            else:
                latency_color = Fore.GREEN

            global_pps_t2 = time_perf_counter
            seconds_elapsed = global_pps_t2 - global_pps_t1
            if seconds_elapsed >= 1:
                global_pps_rate = round(global_pps_counter / seconds_elapsed)
                global_pps_counter = 0
                global_pps_t1 = global_pps_t2

            # For reference, in a GTA Online session, the packets per second (PPS) typically range from 0 (solo session) to 1500 (public session, 32 players).
            # If the packet rate exceeds these ranges, we flag them with yellow or red color to indicate potential issues (such as scanning unwanted packets outside of the GTA game).
            # Also these values averagely indicates the max performances my script can run at during my testings. Luckely it's just enough to process GTA V game.
            if global_pps_rate >= 3000: # Check if PPS exceeds 3000
                pps_color = Fore.RED
            elif global_pps_rate >= 1500: # Check if PPS exceeds 1500
                pps_color = Fore.YELLOW
            else:
                pps_color = Fore.GREEN

            color_restarted_time = Fore.GREEN if tshark_restarted_times == 0 else Fore.RED
            padding_width = calculate_padding_width(109, 71, len(str(plural(average_latency_seconds))), len(str(average_latency_rounded)), len(str(Settings.CAPTURE_OVERFLOW_TIMER)), len(str(plural(tshark_restarted_times))), len(str(tshark_restarted_times)), len(str(global_pps_rate)))
            printer.cache_print(f"{' ' * padding_width}Captured packets average second{plural(average_latency_seconds)} latency:{latency_color}{average_latency_rounded}{Fore.RESET}/{latency_color}{Settings.CAPTURE_OVERFLOW_TIMER}{Fore.RESET} (tshark restarted time{plural(tshark_restarted_times)}:{color_restarted_time}{tshark_restarted_times}{Fore.RESET}) PPS:{pps_color}{global_pps_rate}{Fore.RESET}")
            printer.cache_print(f"-" * 109)
            connected_players_table = PrettyTable()
            connected_players_table.set_style(SINGLE_BORDER)
            connected_players_table.title = f"Player{plural(len(session_connected))} connected in your session ({len(session_connected)}):"
            connected_players_table.field_names = connected_players_table__field_names
            connected_players_table.align = "l"
            for player in session_connected:
                if (
                    Settings.BLACKLIST_ENABLED
                    and player.blacklist.usernames
                ):
                    player_color = Fore.WHITE + Back.RED + Style.BRIGHT
                    player_reset = Fore.RESET + Back.RESET + Style.RESET_ALL
                else:
                    player_color = Fore.GREEN
                    player_reset = Fore.RESET

                row = []
                row.append(f"{player_color}{format_player_datetime(player.datetime.first_seen)}{player_reset}")
                if Settings.BLACKLIST_ENABLED:
                    row.append(f"{player_color}{format_player_usernames(concat_lists_no_duplicates(player.two_take_one__usernames, player.blacklist.usernames))}{player_reset}")
                row.append(f"{player_color}{player.packets}{player_reset}")
                row.append(f"{format_player_pps(player_color, player.pps.is_first_calculation, player.pps.rate)}{player_reset}")
                row.append(f"{player_color}{player.rejoins}{player_reset}")
                row.append(f"{player_color}{format_player_ip(player.ip)}{player_reset}")
                if "Ports" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{format_player_ports_list(player.ports.list, player.ports.first, player.ports.last)}{player_reset}")
                if "Country" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.country:<{session_connected__padding_country_name}} ({player.iplookup.maxmind.country_iso}){player_reset}")
                if "City" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.city}{player_reset}")
                if "ASN" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.asn}{player_reset}")
                if "Mobile" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.mobile}{player_reset}")
                if "Proxy/VPN/Tor" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.proxy}{player_reset}")
                if "Hosting/Data Center" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.hosting}{player_reset}")

                connected_players_table.add_row(row)
            disconnected_players_table = PrettyTable()
            disconnected_players_table.set_style(SINGLE_BORDER)
            disconnected_players_table.title = f"Player{plural(len(session_disconnected))} who've left your session ({len_session_disconnected_message}):"
            disconnected_players_table.field_names = disconnected_players_table__field_names
            disconnected_players_table.align = "l"
            for player in session_disconnected:
                if (
                    Settings.BLACKLIST_ENABLED
                    and player.blacklist.usernames
                ):
                    player_color = Fore.WHITE + Back.RED + Style.BRIGHT
                    player_reset = Fore.RESET + Back.RESET + Style.RESET_ALL
                else:
                    player_color = Fore.RED
                    player_reset = Fore.RESET

                row = []
                row.append(f"{player_color}{format_player_datetime(player.datetime.first_seen)}{player_reset}")
                row.append(f"{player_color}{format_player_datetime(player.datetime.last_seen)}{player_reset}")
                if Settings.BLACKLIST_ENABLED:
                    row.append(f"{player_color}{format_player_usernames(concat_lists_no_duplicates(player.two_take_one__usernames, player.blacklist.usernames))}{player_reset}")
                row.append(f"{player_color}{player.packets}{player_reset}")
                row.append(f"{player_color}{player.rejoins}{player_reset}")
                row.append(f"{player_color}{player.ip}{player_reset}")
                if "Ports" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{format_player_ports_list(player.ports.list, player.ports.first, player.ports.last)}{player_reset}")
                if "Country" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.country:<{session_connected__padding_country_name}} ({player.iplookup.maxmind.country_iso}){player_reset}")
                if "City" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.city}{player_reset}")
                if "ASN" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.asn}{player_reset}")
                if "Mobile" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.mobile}{player_reset}")
                if "Proxy/VPN/Tor" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.proxy}{player_reset}")
                if "Hosting/Data Center" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.hosting}{player_reset}")

                disconnected_players_table.add_row(row)

            printer.cache_print("")
            printer.cache_print(connected_players_table.get_string())
            printer.cache_print(disconnected_players_table.get_string())
            printer.cache_print("")

            cls()
            printer.flush_cache()

            refreshing_rate_t1 = time_perf_counter
            while True:
                refreshing_rate_t2 = time.perf_counter()
                seconds_elapsed = refreshing_rate_t2 - refreshing_rate_t1

                if seconds_elapsed <= Settings.STDOUT_REFRESHING_TIMER:
                    seconds_left = max(Settings.STDOUT_REFRESHING_TIMER - seconds_elapsed, 0)

                    if isinstance(Settings.STDOUT_REFRESHING_TIMER, float):
                        seconds_left = round(seconds_left, 1)
                        sleep_seconds = 0.1
                    else:
                        seconds_left = round(seconds_left)
                        sleep_seconds = 1

                    print("\033[K" + f"Scanning IPs, refreshing display in {seconds_left} second{plural(seconds_left)} ...", end="\r")

                    time.sleep(sleep_seconds)
                    continue

                break

def packet_callback(packet: Packet):
    global tshark_restarted_times, global_pps_counter

    packet_datetime = packet.frame.datetime

    packet_latency = datetime.now() - packet_datetime
    tshark_latency.append(packet_latency)
    if packet_latency >= timedelta(seconds=Settings.CAPTURE_OVERFLOW_TIMER):
        tshark_restarted_times += 1
        raise PacketCaptureOverflow("Packet capture time exceeded 3 seconds.")

    if packet.ip.src == Settings.CAPTURE_IP_ADDRESS:
        target__ip = packet.ip.dst
        target__port = packet.udp.dstport
    elif packet.ip.dst == Settings.CAPTURE_IP_ADDRESS:
        target__ip = packet.ip.src
        target__port = packet.udp.srcport
    else:
        raise ValueError("Neither the source nor destination address matches the specified <CAPTURE_IP_ADDRESS>.")

    if not target__port:
        crash_text = textwrap.dedent(f"""
            ERROR:
                   Developer didn't expect this scenario to be possible.

            INFOS:
                   A player port was not found.
                   This situation already happened to me,
                   but at this time I had not the `target__ip` info
                   from the packet, so it was useless.

                   Note for the future:
                   If `target__ip` is a false positive (not a player),
                   always `continue` on a packet with no port.

            DEBUG:
                   target__ip: {target__ip}
                   target__port: {target__port}
        """.removeprefix("\n").removesuffix("\n"))
        init_script_crash_under_control(crash_text)
        raise ScriptCrashedUnderControl

    global_pps_counter += 1

    player = PlayersRegistry.get_player(target__ip)
    if player is None:
        PlayersRegistry.add_player(
            Player(packet_datetime, target__ip, target__port)
        )
        return

    if not player.datetime.left:
        player.datetime.last_seen = packet_datetime

        player.packets += 1
        player.pps.counter += 1

        if target__port not in player.ports.list:
            player.ports.list.append(target__port)
        player.ports.last = target__port

        return

    player.datetime.left = None
    player.rejoins += 1

    player.pps.t1 = packet_datetime
    player.pps.counter = 0
    player.pps.rate = 0
    player.pps.is_first_calculation = True

    if Settings.STDOUT_RESET_INFOS_ON_CONNECTED:
        player.packets = 1

        player.ports.list = [target__port]
        player.ports.first = target__port
        player.ports.last = target__port
    else:
        player.packets += 1

    return

cls()
title(TITLE)

tshark_restarted_times = 0
global_pps_counter = 0

# deepcode ignore MissingAPI: If the thread was started and the program exits, it will be `join()` in the `terminate_current_script_process()` function.
stdout_render_core__thread = threading.Thread(target=stdout_render_core)
stdout_render_core__thread.start()

if Settings.BLACKLIST_ENABLED:
    # deepcode ignore MissingAPI: If the thread was started and the program exits, it will be `join()` in the `terminate_current_script_process()` function.
    blacklist_sniffer_core__thread = threading.Thread(target=blacklist_sniffer_core)
    blacklist_sniffer_core__thread.start()

if not all(field_name in Settings.STDOUT_FIELDS_TO_HIDE for field_name in ["Mobile", "Proxy/VPN/Tor", "Hosting/Data Center"]):
    # deepcode ignore MissingAPI: If the thread was started and the program exits, it will be `join()` in the `terminate_current_script_process()` function.
    iplookup_core__thread = threading.Thread(target=iplookup_core)
    iplookup_core__thread.start()

with Threads_ExceptionHandler():
    while True:
        try:
            capture.apply_on_packets(callback=packet_callback)
        except PacketCaptureOverflow:
            continue