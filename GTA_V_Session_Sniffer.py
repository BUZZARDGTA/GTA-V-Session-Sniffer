# -----------------------------------------------------
# 📚 Local Python Libraries (Included with Project) 📚
# -----------------------------------------------------
from Modules.capture.capture import PacketCapture, Packet
from Modules.capture.utils import TSharkNotFoundException, get_tshark_path, get_tshark_version, is_npcap_or_winpcap_installed
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
from prettytable import PrettyTable, TableStyle
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
from operator import attrgetter
from datetime import datetime, timedelta
from traceback import TracebackException
from json.decoder import JSONDecodeError
from types import FrameType, TracebackType
from typing import Optional, Literal, Union, Type
from ipaddress import IPv4Address, AddressValueError
from dataclasses import dataclass


if sys.version_info.major <= 3 and sys.version_info.minor < 9:
    print("To use this script, your Python version must be 3.9 or higher.")
    print("Please note that Python 3.9 is not compatible with Windows versions 7 or lower.")
    sys.exit(0)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M",
    handlers=[
        logging.FileHandler("error.log")
        # rich.traceback does it nicer ---> logging.StreamHandler(sys.stdout)
    ]
)
logging.captureWarnings(True)


@dataclass
class ExceptionInfo:
    exc_type: Type[BaseException]
    exc_value: BaseException
    exc_traceback: Optional[TracebackType]

def terminate_script(
        terminate_method: Literal["EXIT", "SIGINT", "THREAD_RAISED"],
        msgbox_crash_text: Optional[str] = None,
        stdout_crash_text: Optional[str] = None,
        exception_info: Optional[ExceptionInfo] = None,
        terminate_gracefully = True,
        force_terminate_errorlevel: Union[int, Literal[False]] = False
    ):

    def should_terminate_gracefully():
        if terminate_gracefully is False:
            return False

        for thread_name in ["stdout_render_core__thread", "iplookup_core__thread"]:
            if thread_name in globals():
                thread = globals()[thread_name]
                if isinstance(thread, threading.Thread):
                    if thread.is_alive():
                        return False

        # TODO: Gracefully exit the script even when the `cature` module is running.
        if "capture" in globals():
            if capture is not None and isinstance(capture, PacketCapture):
                return False

        return True

    ScriptControl.set_crashed(None if stdout_crash_text is None else f"\n\n{stdout_crash_text}\n")

    if exception_info:
        logging.error("Uncaught exception", exc_info=(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback))

        console = Console()

        traceback_message = Traceback.from_exception(exception_info.exc_type, exception_info.exc_value, exception_info.exc_traceback)
        console.print(traceback_message)

        error_message = Text.from_markup(
            "\n\n\nAn unexpected (uncaught) error occurred. [bold]Please kindly report it to: [link=https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/issues]https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/issues[/link][/bold].",
            style="white"
        )
        console.print(error_message)

    if stdout_crash_text is not None:
        print(ScriptControl.get_message())

    if msgbox_crash_text is not None:
        msgbox_title = TITLE
        msgbox_message = msgbox_crash_text
        msgbox_style = Msgbox.Style.OKOnly | Msgbox.Style.Critical | Msgbox.Style.SystemModal | Msgbox.Style.MsgBoxSetForeground

        show_message_box(msgbox_title, msgbox_message, msgbox_style)
        time.sleep(1)

    time.sleep(3)

    if should_terminate_gracefully():
        if force_terminate_errorlevel is False:
            errorlevel = 1 if terminate_method == "THREAD_RAISED" else 0
        else:
            errorlevel = force_terminate_errorlevel
        sys.exit(errorlevel)

    terminate_process_tree()

def handle_exception(exc_type: Type[BaseException], exc_value: BaseException, exc_traceback: Optional[TracebackException]):
    """Handles exceptions for the main script. (not threads)"""
    if issubclass(exc_type, KeyboardInterrupt):
        return

    exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
    terminate_script("EXIT", "An unexpected (uncaught) error occurred.\n\nPlease kindly report it to: https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/issues", exception_info = exception_info)

def signal_handler(sig: int, frame: FrameType):
    if sig == 2: # means CTRL+C pressed
        if not ScriptControl.has_crashed(): # Block CTRL+C if script is already crashing under control
            print(f"\n{Fore.YELLOW}Ctrl+C pressed. Exiting script ...{Fore.RESET}")
            terminate_script("SIGINT")

sys.excepthook = handle_exception
signal.signal(signal.SIGINT, signal_handler)


class InvalidBooleanValueError(Exception):
    pass

class InvalidNoneTypeValueError(Exception):
    pass

class InvalidFileError(Exception):
    def __init__(self, path: str):
        super().__init__(f'The path does not point to a regular file: "{path}"')

class PacketCaptureOverflow(Exception):
    pass

class ScriptControl:
    _lock = threading.Lock()
    _crashed = False
    _message = None

    @classmethod
    def set_crashed(cls, message: Optional[str] = None):
        with cls._lock:
            cls._crashed = True
            cls._message = message

    @classmethod
    def reset_crashed(cls):
        with cls._lock:
            cls._crashed = False
            cls._message = None

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
        return f"v{self.major}.{self.minor}.{self.patch} - {self.date}{f" ({self.time})" if self.time else ""}"

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

class Msgbox:
    # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxw#return-value
    class ReturnValues(enum.IntEnum):
        IDABORT = 3 # The Abort button was selected.
        IDCANCEL = 2 # The Cancel button was selected.
        IDCONTINUE = 11 # The Continue button was selected.
        IDIGNORE = 5 # The Ignore button was selected.
        IDNO = 7 # The No button was selected.
        IDOK = 1 # The OK button was selected.
        IDRETRY = 4 # The Retry button was selected.
        IDTRYAGAIN = 10 # The Try Again button was selected.
        IDYES = 6 # The Yes button was selected.

    class Style(enum.IntFlag):
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
        raising_exc_type (type): The type of the exception raised.
        raising_exc_value (Exception): The value of the exception raised.
        raising_exc_traceback (TracebackType): The traceback information of the exception raised.
    """
    raising_function = None
    raising_exc_type = None
    raising_exc_value = None
    raising_exc_traceback = None

    def __init__(self):
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type: type, exc_value: Exception, exc_traceback: TracebackType):
        """Exit method called upon exiting the 'with' block.

        Args:
            exc_type (type): The type of the exception raised.
            exc_value (Exception): The value of the exception raised.
            exc_traceback (TracebackType): The traceback information of the exception raised.

        Returns:
            bool: True to suppress the exception from propagating further.
        """
        if exc_type:
            Threads_ExceptionHandler.raising_exc_type = exc_type
            Threads_ExceptionHandler.raising_exc_value = exc_value
            Threads_ExceptionHandler.raising_exc_traceback = exc_traceback

            tb = exc_traceback
            while tb.tb_next:
                tb = tb.tb_next
            # Set the failed function name
            Threads_ExceptionHandler.raising_function = tb.tb_frame.f_code.co_name

            exception_info = ExceptionInfo(exc_type, exc_value, exc_traceback)
            terminate_script("THREAD_RAISED", "An unexpected (uncaught) error occurred.\n\nPlease kindly report it to: https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/issues", exception_info = exception_info)

            return True  # Prevent exceptions from propagating

class DefaultSettings:
    """Class containing default setting values."""
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
    STDOUT_SESSIONS_LOGGING = True
    STDOUT_RESET_PORTS_ON_REJOINS = True
    STDOUT_FIELDS_TO_HIDE = ["Intermediate Ports", "First Port", "City"]
    STDOUT_DATE_FIELDS_SHOW_ELAPSED_TIME = True
    STDOUT_DATE_FIELDS_SHOW_DATE = False
    STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY = "Last Rejoin"
    STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY = "Last Seen"
    STDOUT_FIELD_COUNTRY_MAX_LEN = 20
    STDOUT_FIELD_CITY_MAX_LEN = 20
    STDOUT_FIELD_ASN_MAX_LEN = 20
    STDOUT_DISCONNECTED_PLAYERS_TIMER = 10.0
    STDOUT_DISCONNECTED_PLAYERS_COUNTER = 6
    STDOUT_REFRESHING_TIMER = 3
    USERIP_ENABLED = True

class Settings(DefaultSettings):
    stdout_hideable_fields = ["Last Port", "Intermediate Ports", "First Port", "Country", "City", "ASN", "Mobile", "VPN", "Hosting"]

    stdout_fields_mapping = {
        "First Seen": "datetime.first_seen",
        "Last Rejoin": "datetime.last_rejoin",
        "Last Seen": "datetime.last_seen",
        "Usernames": "userip.usernames",
        "Rejoins": "rejoins",
        "T. Packets": "total_packets",
        "Packets": "packets",
        "PPS": "pps.rate",
        "IP Address": "ip",
        "Last Port": "ports.last",
        "Intermediate Ports": "ports.intermediate",
        "First Port": "ports.first",
        "Country": "iplookup.country",
        "City": "iplookup.city",
        "ASN": "iplookup.asn",
        "Mobile": "iplookup.mobile",
        "VPN": "iplookup.proxy",
        "Hosting": "iplookup.hosting"
    }

    @classmethod
    def iterate_over_settings(cls):
        _allowed_settings_types = (type(None), Path, bool, list, str, float, int)

        for attr_name, attr_value in vars(DefaultSettings).items():
            if (
                callable(attr_value)
                or attr_name.startswith("_")
                or attr_name in ["stdout_hideable_fields", "stdout_fields_mapping"]
                or not attr_name.isupper()
                or not isinstance(attr_value, _allowed_settings_types)
            ):
                continue

            # Get the value from Settings if it exists, otherwise from DefaultSettings
            current_value = getattr(cls, attr_name, attr_value)
            yield attr_name, current_value

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
            ;; Lines starting with \";\" or \"#\" symbols are commented lines.
            ;;-----------------------------------------------------------------------------

            ;;-----------------------------------------------------------------------------
            ;; This is the settings file for \"GTA V Session Sniffer\" configuration.
            ;;
            ;; If you don't know what value to choose for a specifc setting, set it's value to None.
            ;; The program will automatically analyzes this file and if needed will regenerate it if it contains errors.
            ;;
            ;;<CAPTURE_TSHARK_PATH>
            ;;  The full path to your \"tshark.exe\" executable.
            ;;  If not set, it will attempt to detect tshark from your Wireshark installation.
            ;;
            ;;<CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT>
            ;;  Allows you to skip the network interface selection by automatically
            ;;  using the <CAPTURE_INTERFACE_NAME>, <CAPTURE_IP_ADDRESS> and <CAPTURE_MAC_ADDRESS> settings.
            ;;
            ;;<CAPTURE_INTERFACE_NAME>
            ;;  The network interface from which packets will be captured.
            ;;
            ;;<CAPTURE_IP_ADDRESS>
            ;;  The IP address of a network interface on your computer from which packets will be captured.
            ;;  If the <CAPTURE_ARP> setting is enabled, it can be from any device on your home network.
            ;;  Valid example value: \"x.x.x.x\"
            ;;
            ;;<CAPTURE_MAC_ADDRESS>
            ;;  The MAC address of a network interface on your computer from which packets will be captured.
            ;;  If the <CAPTURE_ARP> setting is enabled, it can be from any device on your home network.
            ;;  Valid example value: \"xx:xx:xx:xx:xx:xx\" or \"xx-xx-xx-xx-xx-xx\"
            ;;
            ;;<CAPTURE_ARP>
            ;;  Allows you to capture from devices located outside your computer but within your home network, such as gaming consoles.
            ;;
            ;;<CAPTURE_BLOCK_THIRD_PARTY_SERVERS>
            ;;  Determine if you want or not to block the annoying IP ranges from servers that shouldn't be detected.
            ;;
            ;;<CAPTURE_PROGRAM_PRESET>
            ;;  A program preset that will help capturing the right packets for your program.
            ;;  Supported program presets are only \"GTA5\" and \"Minecraft\".
            ;;  Note that Minecraft only supports Bedrock Edition.
            ;;  Please also note that Minecraft have only been tested on PCs.
            ;;  I do not have information regarding it's functionality on consoles.
            ;;
            ;;<CAPTURE_VPN_MODE>
            ;;  Setting this to False will add filters to exclude unrelated IPs from the output.
            ;;  However, if you are scanning trough a VPN <CAPTURE_INTERFACE_NAME>, you have to set it to True.
            ;;
            ;;<CAPTURE_OVERFLOW_TIMER>
            ;;  This timer represents the duration between the timestamp of a captured packet and the current time.
            ;;  When this timer is reached, the tshark process will be restarted.
            ;;  Valid values include any number greater than or equal to 3.
            ;;
            ;;<STDOUT_SHOW_ADVERTISING_HEADER>
            ;;  Determine if you want or not to show the developer's advertisements in the script's display.
            ;;
            ;;<STDOUT_SESSIONS_LOGGING>
            ;;  Determine if you want to log console's output to \"SessionsLogging\" folder.
            ;;  It is synced with the console output and contains all fields.
            ;;
            ;;<STDOUT_RESET_PORTS_ON_REJOINS>
            ;;  When a player rejoins, clear their previously detected ports list.
            ;;
            ;;<STDOUT_FIELDS_TO_HIDE>
            ;;  Specifies a list of fields you wish to hide from the output.
            ;;  It can only hides field names that are not essential to the script's functionality.
            ;;  Valid values include any of the following field names:
            ;;  {Settings.stdout_hideable_fields}
            ;;
            ;;<STDOUT_DATE_FIELDS_SHOW_ELAPSED_TIME>
            ;;  Shows or not the elapsed time from which a player has been captured in \"First Seen\", \"Last Rejoin\" and \"Last Seen\" fields.
            ;;
            ;;<STDOUT_DATE_FIELDS_SHOW_DATE>
            ;;  Shows or not the date from which a player has been captured in \"First Seen\", \"Last Rejoin\" and \"Last Seen\" fields.
            ;;
            ;;<STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY>
            ;;  Specifies the fields from the connected players by which you want the output data to be sorted.
            ;;  Valid values include any field names. For example: Last Rejoin
            ;;
            ;;<STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY>
            ;;  Specifies the fields from the disconnected players by which you want the output data to be sorted.
            ;;  Valid values include any field names. For example: Last Seen
            ;;
            ;;<STDOUT_FIELD_COUNTRY_MAX_LEN>
            ;;  Maximum allowed length for the "Country" field.
            ;;
            ;;<STDOUT_FIELD_CITY_MAX_LEN>
            ;;  Maximum allowed length for the "City" field.
            ;;
            ;;<STDOUT_FIELD_ASN_MAX_LEN>
            ;;  Maximum allowed length for the "ASN" field.
            ;;
            ;;<STDOUT_DISCONNECTED_PLAYERS_TIMER>
            ;;  The duration after which a player will be moved as disconnected on the console if no packets are received within this time.
            ;;  Valid values include any number greater than or equal to 3.
            ;;
            ;;<STDOUT_DISCONNECTED_PLAYERS_COUNTER>
            ;;  The maximum number of players showing up in disconnected players list.
            ;;  Valid values include any number greater than or equal to 0.
            ;;  Setting it to 0 will make it unlimitted.
            ;;
            ;;<STDOUT_REFRESHING_TIMER>
            ;;  Minimum time interval between which this will refresh the console display.
            ;;
            ;;<USERIP_ENABLED>
            ;; Determine if you want or not to enable detections from the UserIP databases.
            ;;-----------------------------------------------------------------------------
        """.removeprefix("\n"))
        for setting_name, setting_value in Settings.iterate_over_settings():
            text += f"{setting_name}={setting_value}\n"
        SETTINGS_PATH.write_text(text, encoding="utf-8")

    def load_from_settings_file(settings_path: Path):
        matched_settings_count = 0

        try:
            settings, need_rewrite_settings = parse_settings_ini_file(settings_path, values_handling="first")
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
                        stripped__setting_value = setting_value.strip("\"'")
                        if not setting_value == stripped__setting_value:
                            need_rewrite_settings = True
                        Settings.CAPTURE_TSHARK_PATH = Path(stripped__setting_value.replace("\\", "/"))
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
                        case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, ["GTA5", "Minecraft"])
                        if case_insensitive_match:
                            Settings.CAPTURE_PROGRAM_PRESET = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
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
                elif setting_name == "STDOUT_SESSIONS_LOGGING":
                    try:
                        Settings.STDOUT_SESSIONS_LOGGING, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_RESET_PORTS_ON_REJOINS":
                    try:
                        Settings.STDOUT_RESET_PORTS_ON_REJOINS, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELDS_TO_HIDE":
                    try:
                        stdout_fields_to_hide = ast.literal_eval(setting_value)
                    except ValueError:
                        need_rewrite_settings = True
                    else:
                        if isinstance(stdout_fields_to_hide, list) and all(isinstance(item, str) for item in stdout_fields_to_hide):
                            filtered_stdout_fields_to_hide: list[Optional[str]] = []

                            for value in stdout_fields_to_hide:
                                case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, Settings.stdout_hideable_fields)
                                if case_insensitive_match:
                                    filtered_stdout_fields_to_hide.append(normalized_match)
                                    if not case_sensitive_match:
                                        need_rewrite_current_setting = True
                                else:
                                    need_rewrite_settings = True

                            Settings.STDOUT_FIELDS_TO_HIDE = filtered_stdout_fields_to_hide
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_DATE_FIELDS_SHOW_ELAPSED_TIME":
                    try:
                        Settings.STDOUT_DATE_FIELDS_SHOW_ELAPSED_TIME, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_DATE_FIELDS_SHOW_DATE":
                    try:
                        Settings.STDOUT_DATE_FIELDS_SHOW_DATE, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY":
                    case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, Settings.stdout_fields_mapping.keys())
                    if case_insensitive_match:
                        Settings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY = normalized_match
                        if not case_sensitive_match:
                            need_rewrite_current_setting = True
                    else:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY":
                    case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(setting_value, Settings.stdout_fields_mapping.keys())
                    if case_insensitive_match:
                        Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY = normalized_match
                        if not case_sensitive_match:
                            need_rewrite_current_setting = True
                    else:
                        need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_COUNTRY_MAX_LEN":
                    try:
                        stdout_field_country_max_len = int(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if stdout_field_country_max_len >= 1:
                            Settings.STDOUT_FIELD_COUNTRY_MAX_LEN = stdout_field_country_max_len
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_CITY_MAX_LEN":
                    try:
                        stdout_field_city_max_len = int(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if stdout_field_city_max_len >= 1:
                            Settings.STDOUT_FIELD_CITY_MAX_LEN = stdout_field_city_max_len
                        else:
                            need_rewrite_settings = True
                elif setting_name == "STDOUT_FIELD_ASN_MAX_LEN":
                    try:
                        stdout_field_asn_max_len = int(setting_value)
                    except (ValueError, TypeError):
                        need_rewrite_settings = True
                    else:
                        if stdout_field_asn_max_len >= 1:
                            Settings.STDOUT_FIELD_ASN_MAX_LEN = stdout_field_asn_max_len
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
                elif setting_name == "USERIP_ENABLED":
                    try:
                        Settings.USERIP_ENABLED, need_rewrite_current_setting = custom_str_to_bool(setting_value)
                    except InvalidBooleanValueError:
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
    PC_Valve = ["103.10.124.0/23", "103.28.54.0/23", "146.66.152.0/21", "155.133.224.0/19", "162.254.192.0/21", "185.25.180.0/22", "205.196.6.0/24"] # Valve = Steam
    PC_Google = ["34.0.0.0/9", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/11", "35.224.0.0/12", "35.240.0.0/13"]
    PC_multicast = ["224.0.0.0/4"]
    PC_UK_Ministry_of_Defence = ["25.0.0.0/8"]
    PC_Servers_Com = ["173.237.26.0/24"]
    PC_Others = ["113.117.15.193/32"]
    GTAV_PC_and_PS3_TakeTwo = ["104.255.104.0/23", "104.255.106.0/24", "185.56.64.0/22", "192.81.241.0/24", "192.81.244.0/23"]
    GTAV_PC_Microsoft = ["52.139.128.0/18"]
    GTAV_PC_DoD_Network_Information_Center = ["26.0.0.0/8"]
    GTAV_PC_BattlEye = ["51.89.97.102/32", "51.89.99.255/32"]
    GTAV_XboxOne_Microsoft = ["52.159.128.0/17", "52.160.0.0/16", "40.74.0.0/18"]
    PS5_Amazon = ["52.40.62.0/25"]
    MinecraftBedrockEdition_PC_and_PS3_Microsoft = ["20.202.0.0/24", "20.224.0.0/16", "168.61.142.128/25", "168.61.143.0/24", "168.61.144.0/20", "168.61.160.0/19"]

class PrintCacher:
    def __init__(self):
        self.cache: list[str] = []

    def cache_print(self, string: str):
        self.cache.append(string)

    def flush_cache(self):
        print("\n".join(self.cache))
        self.cache: list[str] = []

class Player_PPS:
    def __init__(self, packet_datetime: datetime):
        self._initialize(packet_datetime)

    def _initialize(self, packet_datetime: datetime):
        self.t1 = packet_datetime
        self.counter = 0
        self.rate = 0
        self.is_first_calculation = True

    def reset(self, packet_datetime: datetime):
        self._initialize(packet_datetime)

class Player_Ports:
    def __init__(self, port: int):
        self._initialize(port)

    def _initialize(self, port: int):
        self.list = [port]
        self.first = port
        self.intermediate: list[Optional[int]] = []
        self.last = port

    def reset(self, port: int):
        self._initialize(port)

class Player_DateTime:
    def __init__(self, packet_datetime: datetime):
        self._initialize(packet_datetime)

    def _initialize(self, packet_datetime: datetime):
        self.first_seen = packet_datetime
        self.last_rejoin = packet_datetime
        self.last_seen = packet_datetime
        self.left: Optional[datetime] = None

    def reset(self, packet_datetime: datetime):
        self._initialize(packet_datetime)

class MaxMind_GeoLite2:
    def __init__(self):
        self.is_initialized = False

        self.country: Optional[str] = None
        self.country_short: Optional[str] = None
        self.country_iso: Optional[str] = None
        self.city: Optional[str] = None
        self.city_short: Optional[str] = None
        self.asn: Optional[str] = None
        self.asn_short: Optional[str] = None

class IPAPI:
    def __init__(self):
        self.is_initialized = False

        self.continent: Optional[str] = None
        self.continentCode: Optional[str] = None
        self.country: Optional[str] = None
        self.countryCode: Optional[str] = None
        self.region: Optional[str] = None
        self.regionName: Optional[str] = None
        self.city: Optional[str] = None
        self.district: Optional[str] = None
        self.zipcode: Optional[str] = None
        self.lat: Optional[str] = None
        self.lon: Optional[str] = None
        self.timezone: Optional[str] = None
        self.offset: Optional[str] = None
        self.currency: Optional[str] = None
        self.isp: Optional[str] = None
        self.org: Optional[str] = None
        self.asnumber: Optional[str] = None
        self.asname: Optional[str] = None
        self.mobile: Optional[str] = None
        self.proxy: Optional[str] = None
        self.hosting: Optional[str] = None

class Player_IPLookup:
    def __init__(self):
        self.maxmind = MaxMind_GeoLite2()
        self.ipapi = IPAPI()

class Player_Detection:
    def __init__(self):
        self.type: Optional[Literal["Static IP"]] = None
        self.time: Optional[str] = None
        self.date_time: Optional[str] = None
        self.as_processed_userip_task = False

class Player_UserIp:
    def __init__(self):
        self._initialize()

    def _initialize(self):
        self.is_listed = False
        self.database_name: Optional[str] = None
        self.settings: Optional[UserIP_Settings] = None
        self.usernames: list[Optional[str]] = []
        self.detection = Player_Detection()

    def reset(self):
        self._initialize()

class Player_TwoTakeOne:
    def __init__(self):
        self.usernames: list[Optional[str]] = []

class Player:
    def __init__(self, ip: str, port: int, packet_datetime: datetime):
        self._initialize(ip, port, packet_datetime)

    def _initialize(self, ip: str, port: int, packet_datetime: datetime):
        self.ip = ip
        self.rejoins = 0
        self.packets = 1
        self.total_packets = 1
        self.usernames: list[str] = []

        self.pps = Player_PPS(packet_datetime)
        self.ports = Player_Ports(port)
        self.datetime = Player_DateTime(packet_datetime)
        self.iplookup = Player_IPLookup()
        self.userip = Player_UserIp()
        self.two_take_one = Player_TwoTakeOne()

    def reset(self, port: int, packet_datetime: datetime):
        self.packets = 1
        self.pps.reset(packet_datetime)
        self.ports.reset(port)
        self.datetime.reset(packet_datetime)

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
        connected_players: list[Player] = take(2, sorted(session_connected, key=attrgetter("datetime.last_rejoin")))

        potential_session_host_player = None

        if len(connected_players) == 1:
            potential_session_host_player = connected_players[0]
        elif len(connected_players) == 2:
            time_difference = connected_players[1].datetime.last_rejoin - connected_players[0].datetime.last_rejoin
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

class UserIP_Settings:
    """
    Class to represent settings with attributes for each setting key.
    """
    def __init__(self,
        ENABLED: bool,
        COLOR: Literal["BLACK", "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE"],
        LOG: bool,
        NOTIFICATIONS: bool,
        VOICE_NOTIFICATIONS: Union[str | Literal[False]],
        PROTECTION: Literal["Suspend_Process", "Exit_Process", "Restart_Process", "Shutdown_PC", "Restart_PC", False],
        PROTECTION_PROCESS_PATH: Optional[Path],
        PROTECTION_RESTART_PROCESS_PATH: Optional[Path]
    ):
        self.ENABLED = ENABLED
        self.COLOR = COLOR
        self.NOTIFICATIONS = NOTIFICATIONS
        self.VOICE_NOTIFICATIONS = VOICE_NOTIFICATIONS
        self.LOG = LOG
        self.PROTECTION = PROTECTION
        self.PROTECTION_PROCESS_PATH = PROTECTION_PROCESS_PATH
        self.PROTECTION_RESTART_PROCESS_PATH = PROTECTION_RESTART_PROCESS_PATH

class UserIP:
    """
    Class representing information associated with a specific IP, including settings and usernames.
    """
    def __init__(self,
        ip: str,
        database_name: str,
        settings: UserIP_Settings,
        usernames: list[str]
    ):
        self.ip = ip
        self.database_name = database_name
        self.settings = settings
        self.usernames = usernames

class UserIP_Databases:
    userip_databases: list[tuple[str, UserIP_Settings, dict[str, list[str]]]] = []
    userip_infos_by_ip: dict[str, UserIP] = {}
    ips_set: set[str] = set()
    notified_conflicts: set[str] = set()

    @classmethod
    def add(cls, database_name: str, settings: UserIP_Settings, user_ips: dict[str, list[str]]):
        """
        Add a settings dictionary and user_ips dictionary pair to the databases.

        :param database_name: The name of the database.
        :param settings: The settings class for the database.
        :param user_ips: A dictionary mapping usernames to lists of IPs.
        """
        cls.userip_databases.append((database_name, settings, user_ips))

    @classmethod
    def reset(cls):
        """
        Reset the userip_databases by clearing all entries.
        """
        cls.userip_databases.clear()

    @classmethod
    def build(cls):
        """
        Build the userip_infos_by_ip dictionaries from the current databases.
        This method updates the dictionaries without clearing their content entirely, and avoids duplicates.
        """
        userip_infos_by_ip: dict[str, UserIP] = {}
        ips_set: set[str] = set()

        for database_name, settings, user_ips in cls.userip_databases:
            for username, ips in user_ips.items():
                for ip in ips:
                    conflict_key = f"{ip}:{database_name}"

                    if ip in userip_infos_by_ip and not userip_infos_by_ip[ip].database_name == database_name:
                        if conflict_key not in cls.notified_conflicts:
                            msgbox_title = TITLE
                            msgbox_message = textwrap.dedent(f"""
                                ERROR:
                                    UserIP databases IP conflict

                                INFOS:
                                    The same IP cannot be assigned to multiple databases.
                                    Users assigned to this IP will be ignored until the conflict is resolved.

                                DEBUG:
                                    \"{USERIP_DATABASES_PATH}\\{database_name}.ini\":
                                    {username}={ip}

                                    \"{USERIP_DATABASES_PATH}\\{userip_infos_by_ip[ip].database_name}.ini\":
                                    {', '.join(userip_infos_by_ip[ip].usernames)}={ip}
                            """.removeprefix("\n").removesuffix("\n"))
                            msgbox_style = Msgbox.Style.OKOnly | Msgbox.Style.Exclamation | Msgbox.Style.SystemModal | Msgbox.Style.MsgBoxSetForeground
                            threading.Thread(target=show_message_box, args=(msgbox_title, msgbox_message, msgbox_style), daemon=True).start()

                            cls.notified_conflicts.add(conflict_key)
                        continue

                    if conflict_key in cls.notified_conflicts:
                        cls.notified_conflicts.remove(conflict_key)

                    ips_set.add(ip)

                    if ip not in userip_infos_by_ip:
                        userip_infos_by_ip[ip] = UserIP(
                            ip = ip,
                            database_name = database_name,
                            settings = settings,
                            usernames = [username]
                        )

                    if username not in userip_infos_by_ip[ip].usernames:
                        userip_infos_by_ip[ip].usernames.append(username)

        cls.userip_infos_by_ip = userip_infos_by_ip
        cls.ips_set = ips_set

    @classmethod
    def get_userip_info(cls, ip: str):
        """
        Returns an UserIP object for the specified IP, containing its associated name, settings and usernames.
        """
        return cls.userip_infos_by_ip.get(ip)

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
        stdout_crash_text = textwrap.dedent(f"""
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
        terminate_script("EXIT", stdout_crash_text, stdout_crash_text)

    interface = interfaces[0]
    if not isinstance(interface, _wmi_object):
        raise TypeError(f"Expected '_wmi_object' object, got '{type(interface)}'")

    return interface

def get_organization_name(mac_address: Optional[str]):
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

            interface_name: Optional[str] = interface_info.NetConnectionID
            if not isinstance(interface_name, str):
                stdout_crash_text = textwrap.dedent(f"""
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
                terminate_script("EXIT", stdout_crash_text, stdout_crash_text)

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
        stdout_crash_text = textwrap.dedent(f"""
            ERROR:
                Developer didn't expect this scenario to be possible.

            INFOS:
                It seems like a MAC address does not follow
                \"xx:xx:xx:xx:xx:xx\" or \"xx-xx-xx-xx-xx-xx\"
                format.

            DEBUG:
                mac_address: {mac_address}
        """.removeprefix("\n").removesuffix("\n"))
        terminate_script("EXIT", stdout_crash_text, stdout_crash_text)

    return mac_address.replace("-", ":").upper()

def truncate_with_ellipsis(string: str, max_length: int):
    """
    Format a string by truncating it to a specified maximum length,
    and appending "..." if truncated.

    Args:
        string (str): The string to format.
        max_length (int): The maximum length of the formatted string.

    Returns:
        str: The formatted string, truncated with "..." if it exceeds
            the specified `max_length`. Otherwise, returns the original `string`.
    """
    if len(string) > max_length:
        return f"{string[:max_length]}..."
    return string

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

    country_short = truncate_with_ellipsis(country_name, Settings.STDOUT_FIELD_COUNTRY_MAX_LEN)

    return country_name, country_short, country_iso

def get_city_info(ip_address: str):
    city = "N/A"

    if geoip2_enabled:
        try:
            response = geolite2_city_reader.city(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            city = str(response.city.name)

    city_short = truncate_with_ellipsis(city, Settings.STDOUT_FIELD_CITY_MAX_LEN)

    return city, city_short

def get_asn_info(ip_address: str):
    asn = "N/A"

    if geoip2_enabled:
        try:
            response = geolite2_asn_reader.asn(ip_address)
        except geoip2.errors.AddressNotFoundError:
            pass
        else:
            asn = str(response.autonomous_system_organization)

    asn_short = truncate_with_ellipsis(asn, Settings.STDOUT_FIELD_ASN_MAX_LEN)

    return asn, asn_short

def show_message_box(title: str, message: str, style: Msgbox.Style) -> int:
    # https://stackoverflow.com/questions/50086178/python-how-to-keep-messageboxw-on-top-of-all-other-windows
    return ctypes.windll.user32.MessageBoxW(0, message, title, style)

def show_error__tshark_not_detected():
    webbrowser.open(WIRESHARK_REQUIERED_DL)

    msgbox_title = TITLE
    msgbox_message = textwrap.dedent(f"""
        ERROR: Could not detect \"TShark (Wireshark) v4.2.8\" installed on your system.

        Opening the \"Wireshark\" project download page for you.
        You can then download and install it from there and press \"Retry\".
    """.removeprefix("\n").removesuffix("\n"))
    msgbox_style = Msgbox.Style.RetryCancel | Msgbox.Style.Exclamation | Msgbox.Style.MsgBoxSetForeground

    return show_message_box(msgbox_title, msgbox_message, msgbox_style)

def safe_print(*args, **kwargs):
    """
    Print the provided arguments if the script has not crashed.

    :param args: The values to be printed.
    :param kwargs: Additional keyword arguments to pass to the built-in print function.
    """
    if ScriptControl.has_crashed():
        return

    print(*args, **kwargs)

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
        msgbox_style = Msgbox.Style.OKOnly | Msgbox.Style.Exclamation | Msgbox.Style.MsgBoxSetForeground
        show_message_box(msgbox_title, msgbox_message, msgbox_style)

    return geoip2_enabled, geolite2_asn_reader, geolite2_city_reader, geolite2_country_reader

def parse_settings_ini_file(ini_path: Path, values_handling: Literal["first", "last", "all"]):
    def process_ini_line_output(line: str):
        return line.rstrip("\n")

    if not ini_path.exists():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                                str(ini_path.absolute()))
    if not ini_path.is_file():
        raise InvalidFileError(str(ini_path.absolute()))

    ini_data = ini_path.read_text("utf-8")

    need_rewrite_ini = False
    ini_db: dict[str, str | list[str]] = {}

    for line in map(process_ini_line_output, ini_data.splitlines(keepends=False)):
        corrected_line = line.strip()
        if not corrected_line == line:
            need_rewrite_ini = True

        match = RE_SETTINGS_INI_PARSER_PATTERN.search(corrected_line)
        if not match:
            continue
        setting_name = match.group("key")
        if not isinstance(setting_name, str):
            raise TypeError(f"Expected 'str' object, got '{type(setting_name)}'")
        setting_value = match.group("value")
        if not isinstance(setting_value, str):
            raise TypeError(f"Expected 'str' object, got '{type(setting_value)}'")

        corrected_setting_name = setting_name.strip()
        if corrected_setting_name == "":
            continue
        elif not corrected_setting_name == setting_name:
            need_rewrite_ini = True

        corrected_setting_value = setting_value.strip()
        if corrected_setting_value == "":
            continue
        elif not corrected_setting_value == setting_value:
            need_rewrite_ini = True

        if values_handling == "first":
            if corrected_setting_name not in ini_db:
                ini_db[corrected_setting_name] = corrected_setting_value
        elif values_handling == "last":
            ini_db[corrected_setting_name] = corrected_setting_value
        elif values_handling == "all":
            if corrected_setting_name in ini_db:
                ini_db[corrected_setting_name].append(corrected_setting_value)
            else:
                ini_db[corrected_setting_name] = [corrected_setting_value]

    return ini_db, need_rewrite_ini

def parse_userip_ini_file(ini_path: Path):
    def process_ini_line_output(line: str):
        return line.strip()

    if not ini_path.exists():
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                                str(ini_path.absolute()))
    if not ini_path.is_file():
        raise InvalidFileError(str(ini_path.absolute()))

    settings: dict[str, Union[bool, str, int, float]] = {}
    userip: dict[str, list[str]] = {}
    current_section = None
    matched_settings = []
    ini_data = ini_path.read_text("utf-8")
    corrected_ini_data_lines = []

    for line in map(process_ini_line_output, ini_data.splitlines(keepends=True)):
        corrected_ini_data_lines.append(line)

        if line.startswith("[") and line.endswith("]"):
            # we basically adding a newline if the previous line is not a newline for eyes visiblitly or idk how we say that
            if corrected_ini_data_lines and len(corrected_ini_data_lines) > 1:
                if not corrected_ini_data_lines[-2] == "":
                    corrected_ini_data_lines.insert(-1, "")  # Insert an empty string before the last line
            current_section = line[1:-1]
            continue

        if current_section is None:
            continue

        elif current_section == "Settings":
            match = RE_SETTINGS_INI_PARSER_PATTERN.search(line)
            if not match:
                # If it's a newline or a comment we don't really care about rewritting at this point.
                if not line.startswith((";", "#")) or line == "":
                    corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                continue

            setting = match.group("key")
            if setting is None:
                if corrected_ini_data_lines:
                    corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                continue
            if not isinstance(setting, str):
                raise TypeError(f"Expected 'str' object, got '{type(setting)}'")
            value = match.group("value")
            if value is None:
                if corrected_ini_data_lines:
                    corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                continue
            if not isinstance(value, str):
                raise TypeError(f"Expected 'str' object, got '{type(value)}'")

            setting = setting.strip()
            if not setting:
                if corrected_ini_data_lines:
                    corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                continue
            value = value.strip()
            if not value:
                if corrected_ini_data_lines:
                    corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                continue

            if not setting in USERIP_INI_SETTINGS_LIST:
                if corrected_ini_data_lines:
                    corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                continue

            if setting in settings:
                if corrected_ini_data_lines:
                    corrected_ini_data_lines = corrected_ini_data_lines[:-1]
                continue
            else:
                matched_settings.append(setting)
                need_rewrite_current_setting = False
                is_setting_corrupted = False

                if setting == "ENABLED":
                    try:
                        settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                    except InvalidBooleanValueError:
                        is_setting_corrupted = True
                elif setting == "COLOR":
                    try:
                        settings[setting], need_rewrite_current_setting = custom_str_to_nonetype(value)
                    except InvalidNoneTypeValueError:
                        case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ["BLACK", "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE"])
                        if case_insensitive_match:
                            settings[setting] = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        else:
                            is_setting_corrupted = True
                elif setting == "LOG":
                    try:
                        settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                    except InvalidBooleanValueError:
                        is_setting_corrupted = True
                elif setting == "NOTIFICATIONS":
                    try:
                        settings[setting], need_rewrite_current_setting = custom_str_to_bool(value)
                    except InvalidBooleanValueError:
                        is_setting_corrupted = True
                elif setting == "VOICE_NOTIFICATIONS":
                    try:
                        settings[setting], need_rewrite_current_setting = custom_str_to_bool(value, only_match_against=False)
                    except InvalidBooleanValueError:
                        case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ["Male", "Female"])
                        if case_insensitive_match:
                            settings[setting] = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        else:
                            is_setting_corrupted = True
                elif setting == "PROTECTION":
                    try:
                        settings[setting], need_rewrite_current_setting = custom_str_to_bool(value, only_match_against=False)
                    except InvalidBooleanValueError:
                        case_insensitive_match, case_sensitive_match, normalized_match = check_case_insensitive_and_exact_match(value, ["Suspend_Process", "Exit_Process", "Restart_Process", "Shutdown_PC", "Restart_PC"])
                        if case_insensitive_match:
                            settings[setting] = normalized_match
                            if not case_sensitive_match:
                                need_rewrite_current_setting = True
                        else:
                            is_setting_corrupted = True
                elif setting == "PROTECTION_PROCESS_PATH":
                    try:
                        settings[setting], need_rewrite_current_setting = custom_str_to_nonetype(value)
                    except InvalidNoneTypeValueError:
                        stripped_value = value.strip("\"'")
                        if not value == stripped_value:
                            is_setting_corrupted = True
                        settings[setting] = Path(stripped_value.replace("\\", "/"))
                elif setting == "PROTECTION_RESTART_PROCESS_PATH":
                    try:
                        settings[setting], need_rewrite_current_setting = custom_str_to_nonetype(value)
                    except InvalidNoneTypeValueError:
                        stripped_value = value.strip("\"'")
                        if not value == stripped_value:
                            is_setting_corrupted = True
                        settings[setting] = Path(stripped_value.replace("\\", "/"))

                if is_setting_corrupted:
                    stdout_crash_text = textwrap.dedent(f"""
                        ERROR:
                            Corrupted UserIP Database File

                        INFOS:
                            The UserIP database file \"{ini_path}\" has an invalid value:
                            {setting}={value}

                            For more information on formatting, please refer to the documentation:
                                https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer?tab=readme-ov-file#userip_ini_databases_tutorial
                    """.removeprefix("\n").removesuffix("\n"))
                    terminate_script("EXIT", stdout_crash_text, stdout_crash_text)

                if need_rewrite_current_setting:
                    corrected_ini_data_lines[-1] = f"{setting}={settings[setting]}"

        elif current_section == "UserIP":
            match = RE_USERIP_INI_PARSER_PATTERN.search(line)
            if not match:
                continue
            username = match.group("username")
            if username is None:
                continue
            if not isinstance(username, str):
                raise TypeError(f"Expected 'str' object, got '{type(username)}'")
            ip = match.group("ip")
            if ip is None:
                continue
            if not isinstance(ip, str):
                raise TypeError(f"Expected 'str' object, got '{type(ip)}'")

            username = username.strip()
            if not username:
                continue
            ip = ip.strip()
            if not ip:
                continue

            if not is_ipv4_address(ip):
                continue

            if username in userip:
                if ip not in userip[username]:
                    userip[username].append(ip)
            else:
                userip[username] = [ip]

    # Basically always have a newline ending
    if len(corrected_ini_data_lines) > 1:
        if not corrected_ini_data_lines[-1] == "":
            corrected_ini_data_lines.append("")

    fixed_ini_data = "\n".join(corrected_ini_data_lines)

    if not ini_data == fixed_ini_data:
        print("rewritted, ini file")
        ini_path.write_text(fixed_ini_data)

    list_of_missing_settings = [setting for setting in USERIP_INI_SETTINGS_LIST if setting not in matched_settings]
    number_of_settings_missing = len(list_of_missing_settings)
    if number_of_settings_missing == 1:
        missing_settings_str = f"<{list_of_missing_settings[0].upper()}>"
    else:
        missing_settings_str = ", ".join(f"<{setting.upper()}>" for setting in list_of_missing_settings)

    if number_of_settings_missing > 0:
        stdout_crash_text = textwrap.dedent(f"""
            ERROR:
                Missing setting{plural(number_of_settings_missing)} in UserIP Database File

            INFOS:
                The UserIP database file \"{ini_path}\" as {number_of_settings_missing} missing setting{plural(number_of_settings_missing)}:
                {missing_settings_str}

                For more information on formatting, please refer to the documentation:
                    https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer?tab=readme-ov-file#userip_ini_databases_tutorial
        """.removeprefix("\n").removesuffix("\n"))
        terminate_script("EXIT", stdout_crash_text, stdout_crash_text)

    return UserIP_Settings(
        settings["ENABLED"],
        settings["COLOR"],
        settings["LOG"],
        settings["NOTIFICATIONS"],
        settings["VOICE_NOTIFICATIONS"],
        settings["PROTECTION"],
        settings["PROTECTION_PROCESS_PATH"],
        settings["PROTECTION_RESTART_PROCESS_PATH"],
    ), userip

def is_file_need_newline_ending(file):
    file = Path(file)
    if file.stat().st_size == 0:
        return False

    return not file.read_bytes().endswith(b"\n")

def terminate_process_tree(pid: int = None):
    """Terminates the process with the given PID and all its child processes.
       Defaults to the current process if no PID is specified."""
    pid = pid or os.getpid()

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

def check_case_insensitive_and_exact_match(input_value: str, custom_values_list: list[str]):
    """
    Checks if the input value matches any string in the list case-insensitively,
    and whether it also matches exactly (case-sensitive).

    It also returns the correctly capitalized version of the matched value from the list
    if a case-insensitive match is found.

    Returns a tuple of three values:
    - The first boolean is True if a case-insensitive match is found.
    - The second boolean is True if the exact case-sensitive match is found.
    - The third value is the correctly capitalized version of the matched string if found, otherwise None.
    """
    case_insensitive_match = False
    case_sensitive_match = False
    normalized_match = None

    lowered_input_value = input_value.lower()
    for value in custom_values_list:
        if value.lower() == lowered_input_value:
            case_insensitive_match = True
            normalized_match = value
            if value == input_value:
                case_sensitive_match = True
                break

    return case_insensitive_match, case_sensitive_match, normalized_match

def custom_str_to_bool(string: str, only_match_against: Optional[bool] = None):
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

colorama.init(autoreset=True)

if is_pyinstaller_compiled():
    SCRIPT_DIR = Path(sys.executable).parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

TITLE = "GTA V Session Sniffer"
VERSION = "v1.1.8 - 06/11/2024 (21:23)"
TITLE_VERSION = f"{TITLE} {VERSION}"
SETTINGS_PATH = Path("Settings.ini")
USERIP_DATABASES_PATH = Path("UserIP Databases")
SESSIONS_LOGGING_PATH = Path("Sessions Logging") / datetime.now().strftime("%Y/%m/%d") / f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
USERIP_LOGGING_PATH = Path("UserIP_Logging.log")
TWO_TAKE_ONE__PLUGIN__LOG_PATH = Path.home() / "AppData/Roaming/PopstarDevs/2Take1Menu/scripts/GTA_V_Session_Sniffer-plugin/log.txt"
TTS_PATH = resource_path(Path("TTS/"))
RE_MAC_ADDRESS_PATTERN = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")
RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<key>[^=]+)=(?P<value>[^;#]+)")
RE_USERIP_INI_PARSER_PATTERN = re.compile(r"^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)")
RE_TWO_TAKE_ONE_USER_PATTERN = re.compile(r"^user:(?P<username>[\w._-]{1,16}), scid:\d{1,9}, ip:(?P<ip>[\d.]+), timestamp:\d{10}$")
USERIP_INI_SETTINGS_LIST = ["ENABLED", "COLOR", "NOTIFICATIONS", "VOICE_NOTIFICATIONS", "LOG", "PROTECTION", "PROTECTION_PROCESS_PATH", "PROTECTION_RESTART_PROCESS_PATH"]
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
WIRESHARK_REQUIERED_VERSION = "TShark (Wireshark) 4.2.8 (v4.2.8-0-g91fdcf8e29f8)."
WIRESHARK_REQUIERED_DL = "https://www.wireshark.org/download.html"

s = create_unsafe_https_session()

cls()
title(f"Searching for a new update - {TITLE}")
print("\nSearching for a new update ...\n")
error_updating__flag = False
try:
    response = s.get("https://raw.githubusercontent.com/BUZZARDGTA/GTA-V-Session-Sniffer/version/version.txt")
except:
    error_updating__flag = True
else:
    if response.status_code == 200:
        current_version = Version(VERSION)
        latest_version = Version(response.text.strip().rstrip())
        if Updater(current_version).check_for_update(latest_version):
            msgbox_title = TITLE
            msgbox_message = textwrap.dedent(f"""
                New version found. Do you want to update ?

                Current version: {current_version}
                Latest version: {latest_version}
            """.removeprefix("\n").removesuffix("\n"))
            msgbox_style = Msgbox.Style.YesNo | Msgbox.Style.Question | Msgbox.Style.MsgBoxSetForeground
            errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
            if errorlevel == Msgbox.ReturnValues.IDYES:
                webbrowser.open("https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer")
                terminate_script("EXIT")
    else:
        error_updating__flag = True

if error_updating__flag:
    msgbox_title = TITLE
    msgbox_message = textwrap.dedent(f"""
        ERROR: Failed to check for updates.

        Do you want to open the \"{TITLE}\" project download page ?
        You can then download and run the latest version from there.
    """.removeprefix("\n").removesuffix("\n"))
    msgbox_style = Msgbox.Style.YesNo | Msgbox.Style.Exclamation | Msgbox.Style.MsgBoxSetForeground
    errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
    if errorlevel == Msgbox.ReturnValues.IDYES:
        webbrowser.open("https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer")
        terminate_script("EXIT")

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
        "prettytable": "3.12.0",
        "psutil": "6.1.0",
        "requests": "2.32.3",
        "urllib3": "2.2.3",
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
        msgbox_style = Msgbox.Style.YesNo | Msgbox.Style.Exclamation | Msgbox.Style.MsgBoxSetForeground
        msgbox_title = TITLE
        errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
        if errorlevel != Msgbox.ReturnValues.IDYES:
            terminate_script("EXIT")

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
title(f"Checking that \"Npcap\" or \"WinpCap\" driver is installed on your system - {TITLE}")
print("\nChecking that \"Npcap\" or \"WinpCap\" driver is installed on your system ...\n")
while not is_npcap_or_winpcap_installed():
    webbrowser.open("https://nmap.org/npcap/")
    msgbox_title = TITLE
    msgbox_message = textwrap.dedent(f"""
        ERROR: Could not detect the \"Npcap\" or \"WinpCap\" driver installed on your system.

        Opening the \"Npcap\" project download page for you.
        You can then download and install it from there and press \"Retry\".
    """.removeprefix("\n").removesuffix("\n"))
    msgbox_style = Msgbox.Style.RetryCancel | Msgbox.Style.Exclamation | Msgbox.Style.MsgBoxSetForeground
    errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
    if errorlevel == Msgbox.ReturnValues.IDCANCEL:
        terminate_script("EXIT")

cls()
title(f"Applying your custom settings from \"Settings.ini\" - {TITLE}")
print("\nApplying your custom settings from \"Settings.ini\" ...\n")
Settings.load_from_settings_file(SETTINGS_PATH)

cls()
title(f"Checking your custom settings from \"Settings.ini\" - {TITLE}")
print("\nChecking your custom settings from \"Settings.ini\" ...\n")
if Settings.STDOUT_FIELDS_TO_HIDE:
    for field_name in Settings.STDOUT_FIELDS_TO_HIDE:
        # Check for both connected and disconnected player sort fields
        for sort_field_name, sort_field_value, default_sort_value in [
            ("STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY", Settings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY, DefaultSettings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY),
            ("STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY", Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY, DefaultSettings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY)
        ]:
            if field_name in sort_field_value:
                msgbox_title = TITLE
                msgbox_message = textwrap.dedent(f"""
                    ERROR in your custom \"Settings.ini\" file:

                    You cannot sort players in the output from a hidden stdout field (STDOUT_FIELDS_TO_HIDE).

                    Do you want to replace:
                    {sort_field_name}={sort_field_value}
                    with its default value:
                    {sort_field_name}={default_sort_value}
                """.removeprefix("\n").removesuffix("\n"))
                msgbox_style = Msgbox.Style.YesNo | Msgbox.Style.Exclamation | Msgbox.Style.MsgBoxSetForeground
                errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)

                if errorlevel != Msgbox.ReturnValues.IDYES:
                    terminate_script("EXIT")

                # Replace the incorrect field with its default value
                setattr(Settings, sort_field_name, getattr(DefaultSettings, sort_field_name))

                # Reconstruct the settings after applying changes
                Settings.reconstruct_settings()

cls()
title(f"Checking that \"Tshark (Wireshark) v4.2.8\" is installed on your system - {TITLE}")
print("\nChecking that \"Tshark (Wireshark) v4.2.8\" is installed on your system ...\n")
while True:
    try:
        TSHARK_PATH = get_tshark_path(Settings.CAPTURE_TSHARK_PATH)
    except TSharkNotFoundException:
        errorlevel = show_error__tshark_not_detected()
        if errorlevel == Msgbox.ReturnValues.IDCANCEL:
            terminate_script("EXIT")
    else:
        TSHARK_VERSION = get_tshark_version(TSHARK_PATH)

        if TSHARK_VERSION == WIRESHARK_REQUIERED_VERSION:
            break

        webbrowser.open(WIRESHARK_REQUIERED_DL)
        msgbox_title = TITLE

        if TSHARK_VERSION is None:
            errorlevel = show_error__tshark_not_detected()
            if errorlevel == Msgbox.ReturnValues.IDCANCEL:
                terminate_script("EXIT")
        else:
            msgbox_message = textwrap.dedent(f"""
                ERROR: Detected an unsupported \"Tshark (Wireshark)\" version installed on your system.

                Installed version: {TSHARK_VERSION}
                Requiered version: {WIRESHARK_REQUIERED_VERSION}

                Opening the \"Wireshark\" project download page for you.
                You can then download and install it from there and press \"Retry\".
            """.removeprefix("\n").removesuffix("\n"))
            msgbox_style = Msgbox.Style.AbortRetryIgnore | Msgbox.Style.Exclamation | Msgbox.Style.MsgBoxSetForeground
            errorlevel = show_message_box(msgbox_title, msgbox_message, msgbox_style)
            if errorlevel == Msgbox.ReturnValues.IDABORT:
                terminate_script("EXIT")
            elif errorlevel == Msgbox.ReturnValues.IDIGNORE:
                break

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
        stdout_crash_text = textwrap.dedent(f"""
            ERROR:
                Developer didn't expect this scenario to be possible.

            INFOS:
                The IP address has multiple MAC addresses.

            DEBUG:
                interface: {interface}
                ip_addresses: {ip_addresses}
                mac_addresses: {mac_addresses}
        """.removeprefix("\n").removesuffix("\n"))
        terminate_script("EXIT", stdout_crash_text, stdout_crash_text)

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

interfaces_options: dict[int, dict[str, Optional[str]]] = {}
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
        display_filter.append("(frame.len>=71 and frame.len<=1032)")
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
            tshark_path = TSHARK_PATH
        )
    except TSharkNotFoundException:
        errorlevel = show_error__tshark_not_detected()
        if errorlevel == 2:
            terminate_script("EXIT")
    else:
        break

if not capture.tshark_path == Settings.CAPTURE_TSHARK_PATH:
    Settings.CAPTURE_TSHARK_PATH = capture.tshark_path
    Settings.reconstruct_settings()

userip_logging_file_write_lock = threading.Lock()

def process_userip_task(player: Player, connection_type: Literal["connected", "disconnected"]):
    with Threads_ExceptionHandler():
        def suspend_process_for_duration(process_pid: int, duration: int):
            """Suspend the specified process for a given duration, then resume it."""
            process = psutil.Process(process_pid)
            process.suspend()
            time.sleep(duration)
            process.resume()


        # We wants to run this as fast as possible so it's on top of the function.
        if connection_type == "connected":
            if player.userip.settings.PROTECTION:
                if player.userip.settings.PROTECTION == "Suspend_Process":
                    if process_pid := get_pid_by_path(player.userip.settings.PROTECTION_PROCESS_PATH):
                        threading.Thread(target=suspend_process_for_duration, args=(process_pid, 8), daemon=True).start()
                elif player.userip.settings.PROTECTION in ["Exit_Process", "Restart_Process"]:
                    if isinstance(player.userip.settings.PROTECTION_PROCESS_PATH, Path):
                        if process_pid := get_pid_by_path(player.userip.settings.PROTECTION_PROCESS_PATH):
                            terminate_process_tree(process_pid)

                            if player.userip.settings.PROTECTION == "Restart_Process" and isinstance(player.userip.settings.PROTECTION_RESTART_PROCESS_PATH, Path):
                                os.startfile(str(player.userip.settings.PROTECTION_RESTART_PROCESS_PATH.absolute()))
                elif player.userip.settings.PROTECTION == "Shutdown_PC":
                    subprocess.Popen(["shutdown", "/s"])
                elif player.userip.settings.PROTECTION == "Restart_PC":
                    subprocess.Popen(["shutdown", "/r"])

        if player.userip.settings.VOICE_NOTIFICATIONS:
            if player.userip.settings.VOICE_NOTIFICATIONS == "Male":
                voice_name = "Liam"
            elif player.userip.settings.VOICE_NOTIFICATIONS == "Female":
                voice_name = "Jane"
            file_path = Path(f"{TTS_PATH}/{voice_name} ({connection_type}).wav")

            if not file_path.exists():
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(file_path.absolute()))
            if not file_path.is_file():
                raise InvalidFileError(str(file_path.absolute()))

            winsound.PlaySound(file_path, winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)

        if connection_type == "connected":
            player.userip.detection.time = player.datetime.last_seen.strftime("%H:%M:%S")
            player.userip.detection.date_time = player.datetime.last_seen.strftime("%Y-%m-%d_%H:%M:%S")

            while not player.datetime.left and (datetime.now() - player.datetime.last_seen) < timedelta(seconds=10):
                if player.userip.usernames and player.iplookup.maxmind.is_initialized:
                    break
                time.sleep(0.1)
            else:
                return

            with userip_logging_file_write_lock:
                with USERIP_LOGGING_PATH.open("a", encoding="utf-8") as f:
                    newline = "\n" if is_file_need_newline_ending(USERIP_LOGGING_PATH) else ""
                    f.write(
                        f"{newline}"
                        f"User{plural(len(player.userip.usernames))}:{', '.join(player.userip.usernames)} | "
                        f"IP:{player.ip} | Ports:{', '.join(map(str, reversed(player.ports.list)))} | "
                        f"Time:{player.userip.detection.date_time} | Country:{player.iplookup.maxmind.country} | "
                        f"Detection Type: {player.userip.detection.type} | "
                        f"Database:{player.userip.database_name}\n"
                    )

            if player.userip.settings.NOTIFICATIONS:
                while not player.datetime.left and (datetime.now() - player.datetime.last_seen) < timedelta(seconds=10):
                    if player.iplookup.ipapi.is_initialized:
                        break
                    time.sleep(0.1)
                else:
                    return

                msgbox_title = TITLE
                msgbox_message = textwrap.indent(textwrap.dedent(f"""
                    #### UserIP detected at {player.userip.detection.time} ####
                    User{plural(len(player.userip.usernames))}: {', '.join(player.userip.usernames)}
                    IP: {player.ip}
                    Port{plural(len(player.ports.list))}: {', '.join(map(str, reversed(player.ports.list)))}
                    Country Code: {player.iplookup.maxmind.country_iso}
                    Detection Type: {player.userip.detection.type}
                    Database: {player.userip.database_name}
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
                msgbox_style = Msgbox.Style.OKOnly | Msgbox.Style.Exclamation | Msgbox.Style.SystemModal | Msgbox.Style.MsgBoxSetForeground
                threading.Thread(target=show_message_box, args=(msgbox_title, msgbox_message, msgbox_style), daemon=True).start()

def iplookup_core():
    with Threads_ExceptionHandler():
        def throttle_until():
            requests_remaining = int(response.headers["X-Rl"])
            throttle_until = int(response.headers["X-Ttl"])

            if requests_remaining <= 1:
                time.sleep(throttle_until)
            else:
                time.sleep(throttle_until / requests_remaining)  # We sleep x seconds (just in case) to avoid triggering a "429" status code.


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
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
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
    with Threads_ExceptionHandler():
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

        def format_player_datetime(datetime_object: datetime, is_stdout_processing = True):
            if is_stdout_processing and Settings.STDOUT_DATE_FIELDS_SHOW_ELAPSED_TIME:
                elapsed = datetime.now() - datetime_object

                hours, remainder = divmod(elapsed.total_seconds(), 3600)
                minutes, remainder = divmod(remainder, 60)
                seconds, milliseconds = divmod(remainder * 1000, 1000)

                elapsed_str = []
                if hours >= 1:
                    elapsed_str.append(f"{int(hours):02}h")
                if elapsed_str or minutes >= 1:
                    elapsed_str.append(f"{int(minutes):02}m")
                if elapsed_str or seconds >= 1:
                    elapsed_str.append(f"{int(seconds):02}s")
                if not elapsed_str and milliseconds > 0:
                    elapsed_str.append(f"{int(milliseconds):03}ms")

                elapsed_display = f" ({' '.join(elapsed_str)})"
            else:
                elapsed_display = ""

            if Settings.STDOUT_DATE_FIELDS_SHOW_DATE:
                formatted_datetime = f"{datetime_object.strftime('%m/%d/%Y %H:%M:%S.%f')[:-3]}{elapsed_display}"
            else:
                formatted_datetime = f"{datetime_object.strftime('%H:%M:%S.%f')[:-3]}{elapsed_display}"

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
            return player_ip

        def format_player_intermediate_ports(player_ports: Player_Ports):
            player_ports.intermediate = [port for port in reversed(player_ports.list) if port not in {player_ports.first, player_ports.last}]
            if player_ports.intermediate:
                return ", ".join(map(str, player_ports.intermediate))
            else:
                return ""

        def add_down_arrow_char_to_sorted_table_field(field_names: list[str], target_field: str):
            for i, field in enumerate(field_names):
                if field == target_field:
                    field_names[i] += " \u2193"
                    break

        global iplookup_core__thread, global_pps_counter, tshark_latency

        session_connected_sorted_key = Settings.stdout_fields_mapping[Settings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY]
        session_disconnected_sorted_key = Settings.stdout_fields_mapping[Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY]

        stdout_connected_players_table__field_names = [
            field_name
            for field_name in [
                field_name
                for field_name in Settings.stdout_fields_mapping.keys()
                if not field_name == "Last Seen"
            ]
            if field_name not in Settings.STDOUT_FIELDS_TO_HIDE and (Settings.USERIP_ENABLED or field_name != "Usernames")
        ]
        add_down_arrow_char_to_sorted_table_field(stdout_connected_players_table__field_names, Settings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY)
        logging_connected_players_table__field_names = [
            field_name
            for field_name in [
                field_name
                for field_name in Settings.stdout_fields_mapping.keys()
                if not field_name == "Last Seen"
            ]
            if field_name and (Settings.USERIP_ENABLED or field_name != "Usernames")
        ]
        add_down_arrow_char_to_sorted_table_field(logging_connected_players_table__field_names, Settings.STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY)

        stdout_disconnected_players_table__field_names = [
            field_name
            for field_name in [
                field_name
                for field_name in Settings.stdout_fields_mapping.keys()
                if not field_name == "PPS"
            ]
            if field_name not in Settings.STDOUT_FIELDS_TO_HIDE and (Settings.USERIP_ENABLED or field_name != "Usernames")
        ]
        add_down_arrow_char_to_sorted_table_field(stdout_disconnected_players_table__field_names, Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY)
        logging_disconnected_players_table__field_names = [
            field_name
            for field_name in [
                field_name
                for field_name in Settings.stdout_fields_mapping.keys()
                if not field_name == "PPS"
            ]
            if field_name and (Settings.USERIP_ENABLED or field_name != "Usernames")
        ]
        add_down_arrow_char_to_sorted_table_field(logging_disconnected_players_table__field_names, Settings.STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY)

        printer = PrintCacher()
        global_pps_t1 = time.perf_counter()
        global_pps_rate = 0
        last_userip_parse_time = None
        is_arp_enabled = "Enabled" if interfaces_options[user_interface_selection]["is_arp"] else "Disabled"
        padding_width = calculate_padding_width(109, 44, len(str(Settings.CAPTURE_IP_ADDRESS)), len(str(Settings.CAPTURE_INTERFACE_NAME)), len(str(is_arp_enabled)))
        stdout__scanning_on_network_interface = f"{' ' * padding_width}Scanning on network interface:{Fore.YELLOW}{Settings.CAPTURE_INTERFACE_NAME}{Fore.RESET} at IP:{Fore.YELLOW}{Settings.CAPTURE_IP_ADDRESS}{Fore.RESET} (ARP:{Fore.YELLOW}{is_arp_enabled}{Fore.RESET})"
        two_take_one__plugin__ip_to_usernames: dict[str, list[str]] = {}

        # NOTE: The log file content is read only once because the plugin is no longer supported.
        if TWO_TAKE_ONE__PLUGIN__LOG_PATH.exists() and TWO_TAKE_ONE__PLUGIN__LOG_PATH.is_file():
            with TWO_TAKE_ONE__PLUGIN__LOG_PATH.open("r", encoding="utf-8") as f:
                for line in f:
                    match = RE_TWO_TAKE_ONE_USER_PATTERN.match(line)
                    if match:
                        username = match.group("username")
                        if not isinstance(username, str):
                            continue

                        ip = match.group("ip")
                        if not isinstance(ip, str):
                            continue

                        if ip not in two_take_one__plugin__ip_to_usernames:
                            two_take_one__plugin__ip_to_usernames[ip] = []
                        if not username in two_take_one__plugin__ip_to_usernames[ip]:
                            two_take_one__plugin__ip_to_usernames[ip].append(username)

        while True:
            if ScriptControl.has_crashed():
                return

            session_connected__padding_country_name = 0
            session_disconnected__padding_country_name = 0
            session_connected: list[Player] = []
            session_disconnected: list[Player] = []
            main_loop__t1 = time.perf_counter()

            if Settings.USERIP_ENABLED:
                if last_userip_parse_time is None or time.perf_counter() - last_userip_parse_time >= 1.0:
                    UserIP_Databases.reset()
                    for userip_file in USERIP_DATABASES_PATH.glob("*.ini"):
                        userip_settings, userip_data = parse_userip_ini_file(userip_file)
                        UserIP_Databases.add(userip_file.stem, userip_settings, userip_data)
                    UserIP_Databases.build()

                    last_userip_parse_time = time.perf_counter()

            for player in PlayersRegistry.iterate_players_from_registry():
                if Settings.USERIP_ENABLED:
                    if player.ip in UserIP_Databases.ips_set:
                        userip_data = UserIP_Databases.get_userip_info(player.ip)

                        player.userip.is_listed = True
                        player.userip.database_name = userip_data.database_name
                        player.userip.settings = userip_data.settings
                        player.userip.usernames = userip_data.usernames
                    else:
                        player.userip.reset()

                if TWO_TAKE_ONE__PLUGIN__LOG_PATH.exists() and TWO_TAKE_ONE__PLUGIN__LOG_PATH.is_file():
                    if player.ip in two_take_one__plugin__ip_to_usernames:
                        for username in two_take_one__plugin__ip_to_usernames[player.ip]:
                            if username not in player.two_take_one.usernames:
                                player.two_take_one.usernames.append(username)

                player.usernames = concat_lists_no_duplicates(player.two_take_one.usernames, player.userip.usernames)

                if (
                    not player.datetime.left
                    and (datetime.now() - player.datetime.last_seen).total_seconds() >= Settings.STDOUT_DISCONNECTED_PLAYERS_TIMER
                ):
                    player.datetime.left = player.datetime.last_seen
                    if Settings.USERIP_ENABLED:
                        if player.userip.is_listed:
                            player.userip.detection.as_processed_userip_task = False
                            threading.Thread(target=process_userip_task, args=(player, "disconnected"), daemon=True).start()

                if not player.iplookup.maxmind.is_initialized:
                    player.iplookup.maxmind.country, player.iplookup.maxmind.country_short, player.iplookup.maxmind.country_iso = get_country_info(player.ip)
                    player.iplookup.maxmind.city, player.iplookup.maxmind.city_short = get_city_info(player.ip)
                    player.iplookup.maxmind.asn, player.iplookup.maxmind.asn_short = get_asn_info(player.ip)

                    player.iplookup.maxmind.is_initialized = True

                if player.datetime.left:
                    session_disconnected.append(player)
                else:
                    session_connected__padding_country_name = get_minimum_padding(player.iplookup.maxmind.country, session_connected__padding_country_name, 27)

                    if (player_timedelta := (datetime.now() - player.pps.t1)).total_seconds() >= 1.0:
                        player.pps.rate = round(player.pps.counter / player_timedelta.total_seconds())
                        player.pps.counter = 0
                        player.pps.t1 = datetime.now()
                        player.pps.is_first_calculation = False

                    session_connected.append(player)

            session_connected.sort(key=attrgetter(session_connected_sorted_key))
            session_disconnected.sort(key=attrgetter(session_disconnected_sorted_key))

            if Settings.CAPTURE_PROGRAM_PRESET == "GTA5":
                if SessionHost.player:
                    if SessionHost.player.datetime.left:
                        SessionHost.player = None
                # TODO: We should also potentially needs to check that not more then 1s passed before each disconnected
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
                printer.cache_print("  * https://github.com/BUZZARDGTA")
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

            seconds_elapsed = time.perf_counter() - global_pps_t1
            if seconds_elapsed >= 1:
                global_pps_rate = round(global_pps_counter / seconds_elapsed)
                global_pps_counter = 0
                global_pps_t1 = time.perf_counter()

            # For reference, in a GTA Online session, the packets per second (PPS) typically range from 0 (solo session) to 1500 (public session, 32 players).
            # If the packet rate exceeds these ranges, we flag them with yellow or red color to indicate potential issues (such as scanning unwanted packets outside of the GTA game).
            # Also these values averagely indicates the max performances my script can run at during my testings. Luckely it's just enough to process GTA V game.
            if global_pps_rate >= 3000:
                pps_color = Fore.RED
            elif global_pps_rate >= 1500:
                pps_color = Fore.YELLOW
            else:
                pps_color = Fore.GREEN

            color_restarted_time = Fore.GREEN if tshark_restarted_times == 0 else Fore.RED
            padding_width = calculate_padding_width(109, 71, len(str(plural(average_latency_seconds))), len(str(average_latency_rounded)), len(str(Settings.CAPTURE_OVERFLOW_TIMER)), len(str(plural(tshark_restarted_times))), len(str(tshark_restarted_times)), len(str(global_pps_rate)))
            printer.cache_print(f"{' ' * padding_width}Captured packets average second{plural(average_latency_seconds)} latency:{latency_color}{average_latency_rounded}{Fore.RESET}/{latency_color}{Settings.CAPTURE_OVERFLOW_TIMER}{Fore.RESET} (tshark restarted time{plural(tshark_restarted_times)}:{color_restarted_time}{tshark_restarted_times}{Fore.RESET}) PPS:{pps_color}{global_pps_rate}{Fore.RESET}")
            printer.cache_print(f"-" * 109)

            stdout_connected_players_table = PrettyTable()
            stdout_connected_players_table.set_style(TableStyle.SINGLE_BORDER)
            stdout_connected_players_table.title = f"Player{plural(len(session_connected))} connected in your session ({len(session_connected)}):"
            stdout_connected_players_table.field_names = stdout_connected_players_table__field_names
            stdout_connected_players_table.align = "l"
            for player in session_connected:
                if (
                    Settings.USERIP_ENABLED
                    and player.userip.usernames
                ):
                    player_color = Fore.WHITE + getattr(Back, player.userip.settings.COLOR) + Style.BRIGHT
                    player_reset = Fore.RESET + Back.RESET + Style.RESET_ALL
                else:
                    player_color = Fore.GREEN
                    player_reset = Fore.RESET

                row = []
                row.append(f"{player_color}{format_player_datetime(player.datetime.first_seen)}{player_reset}")
                row.append(f"{player_color}{format_player_datetime(player.datetime.last_rejoin)}{player_reset}")
                if Settings.USERIP_ENABLED:
                    row.append(f"{player_color}{format_player_usernames(player.usernames)}{player_reset}")
                row.append(f"{player_color}{player.rejoins}{player_reset}")
                row.append(f"{player_color}{player.total_packets}{player_reset}")
                row.append(f"{player_color}{player.packets}{player_reset}")
                row.append(f"{format_player_pps(player_color, player.pps.is_first_calculation, player.pps.rate)}{player_reset}")
                row.append(f"{player_color}{format_player_ip(player.ip)}{player_reset}")
                if "Last Port" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.ports.last}{player_reset}")
                if "Intermediate Ports" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{format_player_intermediate_ports(player.ports)}{player_reset}")
                if "First Port" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.ports.first}{player_reset}")
                if "Country" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.country:<{session_connected__padding_country_name}} ({player.iplookup.maxmind.country_iso}){player_reset}")
                if "City" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.city_short}{player_reset}")
                if "ASN" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.asn_short}{player_reset}")
                if "Mobile" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.mobile}{player_reset}")
                if "VPN" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.proxy}{player_reset}")
                if "Hosting" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.hosting}{player_reset}")
                stdout_connected_players_table.add_row(row)

            stdout_disconnected_players_table = PrettyTable()
            stdout_disconnected_players_table.set_style(TableStyle.SINGLE_BORDER)
            stdout_disconnected_players_table.title = f"Player{plural(len(session_disconnected))} who've left your session ({len_session_disconnected_message}):"
            stdout_disconnected_players_table.field_names = stdout_disconnected_players_table__field_names
            stdout_disconnected_players_table.align = "l"
            for player in session_disconnected:
                if (
                    Settings.USERIP_ENABLED
                    and player.userip.usernames
                ):
                    player_color = Fore.WHITE + getattr(Back, player.userip.settings.COLOR) + Style.BRIGHT
                    player_reset = Fore.RESET + Back.RESET + Style.RESET_ALL
                else:
                    player_color = Fore.RED
                    player_reset = Fore.RESET

                row = []
                row.append(f"{player_color}{format_player_datetime(player.datetime.first_seen)}{player_reset}")
                row.append(f"{player_color}{format_player_datetime(player.datetime.last_rejoin)}{player_reset}")
                row.append(f"{player_color}{format_player_datetime(player.datetime.last_seen)}{player_reset}")
                if Settings.USERIP_ENABLED:
                    row.append(f"{player_color}{format_player_usernames(player.usernames)}{player_reset}")
                row.append(f"{player_color}{player.rejoins}{player_reset}")
                row.append(f"{player_color}{player.total_packets}{player_reset}")
                row.append(f"{player_color}{player.packets}{player_reset}")
                row.append(f"{player_color}{player.ip}{player_reset}")
                if "Last Port" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.ports.last}{player_reset}")
                if "Intermediate Ports" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{format_player_intermediate_ports(player.ports)}{player_reset}")
                if "First Port" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.ports.first}{player_reset}")
                if "Country" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.country:<{session_connected__padding_country_name}} ({player.iplookup.maxmind.country_iso}){player_reset}")
                if "City" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.city_short}{player_reset}")
                if "ASN" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.maxmind.asn_short}{player_reset}")
                if "Mobile" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.mobile}{player_reset}")
                if "VPN" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.proxy}{player_reset}")
                if "Hosting" not in Settings.STDOUT_FIELDS_TO_HIDE:
                    row.append(f"{player_color}{player.iplookup.ipapi.hosting}{player_reset}")
                stdout_disconnected_players_table.add_row(row)

            printer.cache_print("")
            printer.cache_print(stdout_connected_players_table.get_string())
            printer.cache_print(stdout_disconnected_players_table.get_string())
            printer.cache_print("")

            cls()
            printer.flush_cache()

            if Settings.STDOUT_SESSIONS_LOGGING:
                logging_connected_players_table = PrettyTable()
                logging_connected_players_table.set_style(TableStyle.SINGLE_BORDER)
                logging_connected_players_table.title = f"Player{plural(len(session_connected))} connected in your session ({len(session_connected)}):"
                logging_connected_players_table.field_names = logging_connected_players_table__field_names
                logging_connected_players_table.align = "l"
                for player in session_connected:
                    row = []
                    row.append(f"{format_player_datetime(player.datetime.first_seen, False)}")
                    row.append(f"{format_player_datetime(player.datetime.last_rejoin, False)}")
                    row.append(f"{format_player_usernames(player.usernames)}")
                    row.append(f"{player.rejoins}")
                    row.append(f"{player.total_packets}")
                    row.append(f"{player.packets}")
                    row.append(f"{format_player_pps(player_color, player.pps.is_first_calculation, player.pps.rate)}")
                    row.append(f"{format_player_ip(player.ip)}")
                    row.append(f"{player.ports.last}")
                    row.append(f"{format_player_intermediate_ports(player.ports)}")
                    row.append(f"{player.ports.first}")
                    row.append(f"{player.iplookup.maxmind.country:<{session_connected__padding_country_name}} ({player.iplookup.maxmind.country_iso})")
                    row.append(f"{player.iplookup.maxmind.city}")
                    row.append(f"{player.iplookup.maxmind.asn}")
                    row.append(f"{player.iplookup.ipapi.mobile}")
                    row.append(f"{player.iplookup.ipapi.proxy}")
                    row.append(f"{player.iplookup.ipapi.hosting}")
                    logging_connected_players_table.add_row(row)

                logging_disconnected_players_table = PrettyTable()
                logging_disconnected_players_table.set_style(TableStyle.SINGLE_BORDER)
                logging_disconnected_players_table.title = f"Player{plural(len(session_disconnected_all))} who've left your session ({len(session_disconnected_all)}):"
                logging_disconnected_players_table.field_names = logging_disconnected_players_table__field_names
                logging_disconnected_players_table.align = "l"
                for player in session_disconnected_all:
                    row = []
                    row.append(f"{format_player_datetime(player.datetime.first_seen, False)}")
                    row.append(f"{format_player_datetime(player.datetime.last_rejoin, False)}")
                    row.append(f"{format_player_datetime(player.datetime.last_seen, False)}")
                    row.append(f"{format_player_usernames(player.usernames)}")
                    row.append(f"{player.rejoins}")
                    row.append(f"{player.total_packets}")
                    row.append(f"{player.packets}")
                    row.append(f"{player.ip}")
                    row.append(f"{player.ports.last}")
                    row.append(f"{format_player_intermediate_ports(player.ports)}")
                    row.append(f"{player.ports.first}")
                    row.append(f"{player.iplookup.maxmind.country:<{session_connected__padding_country_name}} ({player.iplookup.maxmind.country_iso})")
                    row.append(f"{player.iplookup.maxmind.city}")
                    row.append(f"{player.iplookup.maxmind.asn}")
                    row.append(f"{player.iplookup.ipapi.mobile}")
                    row.append(f"{player.iplookup.ipapi.proxy}")
                    row.append(f"{player.iplookup.ipapi.hosting}")
                    logging_disconnected_players_table.add_row(row)

                # Check if the directories exist, if not create them
                if not SESSIONS_LOGGING_PATH.parent.exists():
                    SESSIONS_LOGGING_PATH.parent.mkdir(parents=True)  # Create the directories if they don't exist

                # Check if the file exists, if not create it
                if not SESSIONS_LOGGING_PATH.exists():
                    SESSIONS_LOGGING_PATH.touch()  # Create the file if it doesn't exist

                with SESSIONS_LOGGING_PATH.open("w", encoding="utf-8") as f:
                    stdout_without_vt100 = ANSI_ESCAPE.sub("", logging_connected_players_table.get_string() + "\n" + logging_disconnected_players_table.get_string())
                    f.write(stdout_without_vt100)

            og_process_refreshing__time_elapsed = time.perf_counter() - main_loop__t1

            if Settings.STDOUT_REFRESHING_TIMER == 0:
                safe_print("\033[K" + f"Scanning IPs, refreshing display as fast as possible (last refresh took: ~{round(og_process_refreshing__time_elapsed)} second{plural(og_process_refreshing__time_elapsed)})", end="\r")
                time.sleep(0.1)
                continue

            if og_process_refreshing__time_elapsed > Settings.STDOUT_REFRESHING_TIMER + 1.0:
                safe_print("\033[K" + f"Scanning IPs, refreshing display took longer than expected, refreshing in ~{round(og_process_refreshing__time_elapsed)} second{plural(og_process_refreshing__time_elapsed)} ...", end="\r")
                time.sleep(0.1)
                continue

            while True:
                total_refreshing__time_elapsed = time.perf_counter() - main_loop__t1

                if isinstance(Settings.STDOUT_REFRESHING_TIMER, float):
                    seconds_left = max(Settings.STDOUT_REFRESHING_TIMER - total_refreshing__time_elapsed, 0.1)
                    seconds_left = round(seconds_left, 1)
                    remaining_sleep_seconds = 0
                    eta = max(round(seconds_left + og_process_refreshing__time_elapsed, 1), 0.1)
                else:
                    seconds_left = max(Settings.STDOUT_REFRESHING_TIMER - total_refreshing__time_elapsed, 1)
                    seconds_left = round(seconds_left)
                    remaining_sleep_seconds = 0.9
                    eta = max(round(seconds_left + og_process_refreshing__time_elapsed), 1)

                safe_print("\033[K" + f"Scanning IPs, refreshing display in {eta} second{plural(eta)} ...", end="\r")
                time.sleep(0.1)

                total_refreshing__time_elapsed = time.perf_counter() - main_loop__t1
                if total_refreshing__time_elapsed > Settings.STDOUT_REFRESHING_TIMER:
                    break

                if remaining_sleep_seconds > 0:
                    time.sleep(remaining_sleep_seconds)

def packet_callback(packet: Packet):
    global tshark_restarted_times, global_pps_counter

    packet_datetime = packet.frame.datetime

    packet_latency = datetime.now() - packet_datetime
    tshark_latency.append(packet_latency)
    if packet_latency >= timedelta(seconds=Settings.CAPTURE_OVERFLOW_TIMER):
        tshark_restarted_times += 1
        raise PacketCaptureOverflow("Packet capture time exceeded 3 seconds.")

    if packet.ip.src == Settings.CAPTURE_IP_ADDRESS:
        target_ip = packet.ip.dst
        target_port = packet.udp.dstport
    elif packet.ip.dst == Settings.CAPTURE_IP_ADDRESS:
        target_ip = packet.ip.src
        target_port = packet.udp.srcport
    else:
        raise ValueError("Neither the source nor destination address matches the specified <CAPTURE_IP_ADDRESS>.")

    if not target_port:
        stdout_crash_text = textwrap.dedent(f"""
            ERROR:
                Developer didn't expect this scenario to be possible.

            INFOS:
                A player port was not found.
                This situation already happened to me,
                but at this time I had not the `target_ip` info
                from the packet, so it was useless.

                Note for the future:
                If `target_ip` is a false positive (not a player),
                always `continue` on a packet with no port.

            DEBUG:
                target_ip: {target_ip}
                target_port: {target_port}
        """.removeprefix("\n").removesuffix("\n"))
        terminate_script("EXIT", stdout_crash_text, stdout_crash_text)

    global_pps_counter += 1

    player = PlayersRegistry.get_player(target_ip)
    if player is None:
        PlayersRegistry.add_player(
            Player(target_ip, target_port, packet_datetime)
        )
        return

    if Settings.USERIP_ENABLED:
        if player.userip.is_listed and not player.userip.detection.as_processed_userip_task:
            player.userip.detection.as_processed_userip_task = True
            player.userip.detection.type = "Static IP"
            threading.Thread(target=process_userip_task, args=(player, "connected"), daemon=True).start()

    # No matter what:
    player.datetime.last_seen = packet_datetime
    player.total_packets += 1
    player.pps.counter += 1

    if player.datetime.left: # player left, rejoined now.
        player.datetime.left = None
        player.datetime.last_rejoin = packet_datetime
        player.rejoins += 1
        player.packets = 1

        if Settings.STDOUT_RESET_PORTS_ON_REJOINS:
            player.ports.reset(target_port)
            return
    else:
        player.packets += 1

    # player connected, has not been reset
    if target_port not in player.ports.list:
        player.ports.list.append(target_port)
    player.ports.last = target_port

cls()
title(TITLE)

tshark_restarted_times = 0
global_pps_counter = 0

stdout_render_core__thread = threading.Thread(target=stdout_render_core, daemon=True)
stdout_render_core__thread.start()

iplookup_core__thread = threading.Thread(target=iplookup_core, daemon=True)
iplookup_core__thread.start()

with Threads_ExceptionHandler():
    while True:
        try:
            capture.apply_on_packets(callback=packet_callback)
        except PacketCaptureOverflow:
            continue