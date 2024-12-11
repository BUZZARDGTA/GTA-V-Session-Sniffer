## Configuration

Before proceeding, ensure you are using Windows 10 or above.

Additionally, make sure you have [Wireshark](https://www.wireshark.org/) (v4.2.9) installed on your system.

Furthermore, for packet sniffing functionality, you'll require either [Npcap](https://nmap.org/npcap/) or [Winpcap](https://www.winpcap.org/).<br>
It's worth noting that this step can be omitted as [Npcap](https://nmap.org/npcap/) is already included by default within the [Wireshark](https://www.wireshark.org/) installation.

#### Editing Settings

#### Example Settings file:
```
CAPTURE_TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT=False
CAPTURE_INTERFACE_NAME=Ethernet 2
CAPTURE_IP_ADDRESS=192.168.1.101
CAPTURE_MAC_ADDRESS=D8:BB:C1:8F:1B:E6
CAPTURE_ARP=True
CAPTURE_BLOCK_THIRD_PARTY_SERVERS=True
CAPTURE_PROGRAM_PRESET=GTA5
CAPTURE_VPN_MODE=False
CAPTURE_OVERFLOW_TIMER=3.0
CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER=None
CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER=None
STDOUT_SHOW_ADVERTISING_HEADER=False
STDOUT_SESSIONS_LOGGING=True
STDOUT_RESET_PORTS_ON_REJOINS=True
STDOUT_FIELDS_TO_HIDE=['Intermediate Ports', 'First Port', 'Continent', 'R. Code', 'City', 'District', 'ZIP Code', 'Lat', 'Lon', 'Time Zone', 'Offset', 'Currency', 'Organization', 'AS', 'ASN / ISP']
STDOUT_DATE_FIELDS_SHOW_DATE=False
STDOUT_DATE_FIELDS_SHOW_TIME=False
STDOUT_DATE_FIELDS_SHOW_ELAPSED=True
STDOUT_FIELD_SHOW_COUNTRY_CODE=True
STDOUT_FIELD_SHOW_CONTINENT_CODE=True
STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY=Last Rejoin
STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY=Last Seen
STDOUT_FIELD_COUNTRY_MAX_LEN=20
STDOUT_FIELD_CITY_MAX_LEN=20
STDOUT_FIELD_CONTINENT_MAX_LEN=20
STDOUT_FIELD_REGION_MAX_LEN=20
STDOUT_FIELD_ORGANIZATION_MAX_LEN=20
STDOUT_FIELD_ISP_MAX_LEN=20
STDOUT_FIELD_ASN_ISP_MAX_LEN=20
STDOUT_FIELD_AS_MAX_LEN=20
STDOUT_FIELD_AS_NAME_MAX_LEN=20
STDOUT_DISCONNECTED_PLAYERS_TIMER=10.0
STDOUT_DISCONNECTED_PLAYERS_COUNTER=6
STDOUT_REFRESHING_TIMER=0.1
USERIP_ENABLED=True
DISCORD_PRESENCE=True
```

To edit the script settings, open the `Settings.ini` file.<br>
This file is created upon the first script launch and automatically updates thereafter.

Please note that any changes made to the file will take effect only after restarting the script.<br>
If unsure about a setting, remove its line. The script will analyze the file and reset missing settings to defaults upon restart.

For detailed explanations of each setting, **click to expand below:**

<details>
<summary>📖 Settings Details (Click to Expand/Collapse)</summary>

* `<CAPTURE_TSHARK_PATH>`<br>
The full path to your "tshark.exe" executable.<br>
If not set, it will attempt to detect tshark from your Wireshark installation.

* `<CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT>`<br>
Allows you to skip the network interface selection by automatically<br>
using the `<CAPTURE_INTERFACE_NAME>`, `<CAPTURE_IP_ADDRESS>` and `<CAPTURE_MAC_ADDRESS>` settings.

* `<CAPTURE_INTERFACE_NAME>`<br>
The network interface from which packets will be captured.

* `<CAPTURE_IP_ADDRESS>`<br>
The IP address of a network interface on your computer from which packets will be captured.<br>
If the `<CAPTURE_ARP>` setting is enabled, it can be from any device on your home network.
Valid example value: "x.x.x.x"

* `<CAPTURE_MAC_ADDRESS>`<br>
The MAC address of a network interface on your computer from which packets will be captured.<br>
If the `<CAPTURE_ARP>` setting is enabled, it can be from any device on your home network.<br>
Valid example value: "xx:xx:xx:xx:xx:xx" or "xx-xx-xx-xx-xx-xx"

* `<CAPTURE_ARP>`<br>
Allows you to capture from devices located outside your computer but within your home network, such as gaming consoles.

* `<CAPTURE_BLOCK_THIRD_PARTY_SERVERS>`<br>
Determine if you want or not to block the annoying IP ranges from servers that shouldn't be detected.

* `<CAPTURE_PROGRAM_PRESET>`<br>
A program preset that will help capturing the right packets for your program.<br>
Supported program presets are only "GTA5" and "Minecraft".<br>
Note that Minecraft only supports Bedrock Edition.<br>
Please also note that Minecraft have only been tested on PCs.<br>
I do not have information regarding it's functionality on consoles.

* `<CAPTURE_VPN_MODE>`<br>
Setting this to False will add filters to exclude unrelated IPs from the output.<br>
However, if you are scanning trough a VPN `<CAPTURE_INTERFACE_NAME>`, you have to set it to True.

* `<CAPTURE_OVERFLOW_TIMER>`<br>
This timer represents the duration between the timestamp of a captured packet and the current time.<br>
When this timer is reached, the tshark process will be restarted.<br>
Valid values include any number greater than or equal to 3.

* `<CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER>`<br>
**For advanced users**; Allows you to specify a custom Tshark capture filter, which will be prepended to the filter used in the script.<br>
Learn more: [Wireshark Capture Filters](https://wiki.wireshark.org/CaptureFilters) / [Tshark Capture Filters](https://tshark.dev/capture/capture_filters/)

* `<CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER>`<br>
**For advanced users**; Allows you to specify a custom Tshark display filter, which will be prepended to the filter used in the script.<br>
Learn more: [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters) / [Tshark Display Filters](https://tshark.dev/analyze/packet_hunting/packet_hunting/)

* `<STDOUT_SHOW_ADVERTISING_HEADER>`<br>
Determine if you want or not to show the developer's advertisements in the script's display.

* `<STDOUT_SESSIONS_LOGGING>`<br>
Determine if you want to log console's output to "SessionsLogging" folder.<br>
It is synced with the console output and contains all fields.

* `<STDOUT_RESET_PORTS_ON_REJOINS>`<br>
When a player rejoins, clear their previously detected ports list.

* `<STDOUT_FIELDS_TO_HIDE>`<br>
Specifies a list of fields you wish to hide from the output.<br>
It can only hides field names that are not essential to the script's functionality.<br>
Valid values include any of the following field names:
{Settings.stdout_hideable_fields}

* `<STDOUT_DATE_FIELDS_SHOW_ELAPSED_TIME>`<br>
Shows or not the elapsed time from which a player has been captured in "First Seen", "Last Rejoin" and "Last Seen" fields.

* `<STDOUT_DATE_FIELDS_SHOW_DATE>`<br>
Shows or not the date from which a player has been captured in "First Seen", "Last Rejoin" and "Last Seen" fields.

* `<STDOUT_FIELD_SHOW_CONTINENT_CODE>`<br>
Specify whether to display the continent's ISO 2-letter code in parentheses next to the continent name.

* `<STDOUT_FIELD_SHOW_COUNTRY_CODE>`<br>
Specify whether to display the country's ISO 2-letter code in parentheses next to the country name.

* `<STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY>`<br>
Specifies the fields from the connected players by which you want the output data to be sorted.<br>
Valid values include any field names. For example: Last Rejoin

* `<STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY>`<br>
Specifies the fields from the disconnected players by which you want the output data to be sorted.<br>
Valid values include any field names. For example: Last Seen

* `<STDOUT_FIELD_COUNTRY_MAX_LEN>`<br>
Maximum allowed length for the "Country" field.

* `<STDOUT_FIELD_CITY_MAX_LEN>`<br>
Maximum allowed length for the "City" field.

* `<STDOUT_FIELD_CONTINENT_MAX_LEN>`<br>
Maximum allowed length for the "Continent" field.

* `<STDOUT_FIELD_REGION_MAX_LEN>`<br>
Maximum allowed length for the "Region" field.

* `<STDOUT_FIELD_ORGANIZATION_MAX_LEN>`<br>
Maximum allowed length for the "Organization" field.

* `<STDOUT_FIELD_ISP_MAX_LEN>`<br>
Maximum allowed length for the "ISP" field.

* `<STDOUT_FIELD_ASN_ISP_MAX_LEN>`<br>
Maximum allowed length for the "ASN / ISP" field.

* `<STDOUT_FIELD_AS_MAX_LEN>`<br>
Maximum allowed length for the "AS" field.

* `<STDOUT_FIELD_AS_NAME_MAX_LEN>`<br>
Maximum allowed length for the "AS Name" field.

* `<STDOUT_DISCONNECTED_PLAYERS_TIMER>`<br>
The duration after which a player will be moved as disconnected on the console if no packets are received within this time.<br>
Valid values include any number greater than or equal to 3.

* `<STDOUT_DISCONNECTED_PLAYERS_COUNTER>`<br>
The maximum number of players showing up in disconnected players list.<br>
Valid values include any number greater than or equal to 0.<br>
Setting it to 0 will make it unlimitted.

* `<STDOUT_REFRESHING_TIMER>`<br>
Minimum time interval between which this will refresh the console display.

* `<USERIP_ENABLED>`<br>
Determine if you want or not to enable detections from the UserIP databases.

</details>

#### Scan trough a VPN

When using a VPN, make sure that you scan from your actual VPN interface.<br>
Additionally, ensure that in the `Settings.ini` file, the setting `<CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT>` is set to `True` value.

#### Scan for a console

In order to scan for a console (PS3/PS4/PS5 and Xbox 360/Xbox One/Xbox Series X), you'll need to follow these steps:

1. Open the `Settings.ini` file.
2. If not already done, set `<CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT>` to `True` value, so that it forces entering the "Capture network interface selection" screen at script's startup. (you can disable it later)
3. Enable the `<CAPTURE_ARP>` setting by setting its value to `True`. (This setting allows you to view all currently connected external devices within your local network in the script's "Capture network interface selection" screen)
4. Ensure that your console is currently running and **connected to internet through your PC's internet connection (Wired / Hotspot)**.
5. Start the script and wait for it to enter the "Capture network interface selection" screen.
6. Then, you'll need to identify the console's IP and MAC Address and select it accordingly.

#### Resolving Country, City and ASN fields.

The script relies on [MaxMind’s GeoIP2 databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) to resolve player information.<br>
Upon startup, it automatically attempts to check for updates and downloads the latest version from the [PrxyHunter/GeoLite2](https://github.com/PrxyHunter/GeoLite2) repository.

In the event that this repository is deleted, you will need to manually download the following MaxMind GeoLite2 databases: `GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb`.<br>
You can obtain copies of these databases by signing up for GeoLite2 on the [MaxMind](https://www.maxmind.com/) official website and downloading them from there.<br>
Then you will need to create a new folder named `GeoLite2 Databases` within the script's directory, and place the database files there.

Please note that I am not allowed to publicly distribute their database in my project due to their strict [license](https://www.maxmind.com/en/site-license-overview).<br>
You must obtain it directly from [MaxMind](https://www.maxmind.com/) website.

#### Resolving Mobile, Proxy and Hosting fields.

The script relies on the free [ip-api](https://ip-api.com/) API website to resolve player's "Mobile", "VPN" and "Hosting" fields.<br>
This free and limited usage allows for a maximum resolution of (100 \* 15) = 1500 IPs per minute.

## UserIP INI databases Configuration

#### What's an UserIP database ?

In earlier versions, there was only one database `Blacklist.ini` for blacklisting users.<br>
Since [v1.1.8](https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/releases/tag/v1.1.8), you can create multiple lists with custom behaviors to suit your needs.

For example, I personally maintain four lists:

* Searchlist.ini: For people whose IPs I am searching for.
* Blacklist.ini: For individuals whose GTA5 process I want to suspend.
* Enemylist.ini: For users I want to be notified about when they join the session.
* Friendlist.ini: For users I don't want notifications for but wish to highlight in green.

Throughout the INI file, any text following a `;` or `##` symbol is treated as a comment.

Simply create a folder named `UserIP Databases` and add any *.ini files for the script to read.<br>
To create these files, follow these guidelines:

#### UserIP Settings

These are settings specific for each UserIP database files configuration.

If you don't know what value to choose for a specifc setting, set it's value to None.<br>
The program will automatically analyzes this file and if needed will regenerate it if it contains errors.

For detailed explanations of each UserIP database settings, **click to expand below:**

<details>
<summary>📖 UserIP Database Settings Details (Click to Expand/Collapse)</summary>

* `<ENABLED>`<br>
Determine if you want or not to enable this UserIP database.

* `<COLOR>`<br>
Determine which color will be applied on the script's output for these users.
Valid values are either one of the following colors:<br>
`BLACK`, `RED`, `GREEN`, `YELLOW`, `BLUE`, `MAGENTA`, `CYAN`, `WHITE`

* `<NOTIFICATIONS>`<br>
Determine if you want or not to display a notification when a user is detected.

* `<VOICE_NOTIFICATIONS>`<br>
This setting determines the voice that will play when a user is detected or when they disconnect.<br>
Valid values are either `Male` or `Female`.<br>
Set it to `False` to disable this setting.

* `<LOG>`<br>
Determine if you want or not to log the user in the UserIP logging file.

* `<PROTECTION>`<br>
Determine if you want or not a protection when a user is found.<br>
Valid values include any of the following protections:<br>
`Suspend_Process`, `Exit_Process`, `Restart_Process`, `Shutdown_PC`, `Restart_PC`<br>
Set it to `False` value to disable this setting.

* `<PROTECTION_PROCESS_PATH>`<br>
The file path of the process that will be used for the `<PROTECTION>` setting.<br>
Please note that UWP apps are not supported.

* `<PROTECTION_RESTART_PROCESS_PATH>`<br>
The file path of the process that will be started when<br>
the `<PROTECTION>` setting is set to the `Restart_Process` value.<br>
Please note that UWP apps are not supported.

* `<PROTECTION_SUSPEND_PROCESS_MODE>`<br>
Specifies the duration (in seconds) for which the `<PROTECTION_PROCESS_PATH>` process will be suspended when `<PROTECTION>` is set to `Suspend_Process`.<br>
    * Floating-point number: Specify a duration in seconds (e.g., 2.5 for 2.5 seconds).<br>
    * `Auto`: Keep the process suspended as long as the IP is detected in the session.<br>
    * `Manual`: Suspend the process indefinitely until the user manually resumes it.

</details>

#### UserIP Entries

You need to list the entries under the `[UserIP]` section of the INI file in this format:<br>
`<USERNAME>=<IP>`

#### Example UserIP file:
```
[Settings]
ENABLED=True
COLOR=RED
LOG=True
NOTIFICATIONS=True
VOICE_NOTIFICATIONS=Male
PROTECTION=False
PROTECTION_PROCESS_PATH=E:\Games\GTAV\GTA5.exe
PROTECTION_RESTART_PROCESS_PATH=D:\Desktop\Grand Theft Auto V.url
PROTECTION_SUSPEND_PROCESS_MODE=Auto

[UserIP]
username1=0.0.0.0
username2=127.0.0.1
username3=255.255.255.255
```
