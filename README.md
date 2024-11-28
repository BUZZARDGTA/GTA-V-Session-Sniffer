# GTA V Session Sniffer

## Description

Compatible with both PC and all consoles (PlayStation and Xbox).<br />
Thoroughly tested on PC, Xbox One, PlayStation 5, and PlayStation 3 ensuring 100% compatibility.

To be clear, the script does not explicitly indicate which IP corresponds to which in-game username\*.<br />
This functionality used to be possible on old-gen consoles (PS3 and Xbox 360) but has been patched in next-gen consoles.

- Scan players who:
  - Are trying to connect.
  - Are currently connected.
  - Have left your session.

**Officially Tested and Supported Video Games\*\*:**

| Supported Video Games               | Officially Tested Platforms |
| :---------------------------------- | :-------------------------: |
| Grand Theft Auto 5                  |      PC, Xbox One, PS5      |
| Minecraft Bedrock Edition (Friends) |           PC, PS3           |

\*_Since v1.1.4, you can now view usernames in real-time on PC using ~~either 2Take1 or~~ Stand mod menu~~s~~:_
- ~~_[GTA_V_Session_Sniffer-plugin-2Take1-Lua](https://github.com/Illegal-Services/GTA_V_Session_Sniffer-plugin-2Take1-Lua)_~~ \[ARCHIVED\]<br />
- _[GTA_V_Session_Sniffer-plugin-Stand-Lua](https://github.com/BUZZARDGTA/GTA_V_Session_Sniffer-plugin-Stand-Lua)<br />_

\*\*_Technically the script works for literally every P2P (Peer-To-Peer) video games.<br />
But please note that additional servers (e.g., game servers) won't be filtered from the script's output if they are not indexed within the list above_

## Advantages

- The script has a configuration file that allows for more advanced customization of its behavior.
- You can use the script without a modded video game or cracked program.
- The script is entirely **FREE TO USE** and **OPEN SOURCE**.

## Showcase

|                                                         Console Output                                                         |
| :----------------------------------------------------------------------------------------------------------------------------: |
| ![WindowsTerminal_2024-11-07_01-25](https://github.com/user-attachments/assets/5df228a1-1465-44a1-928b-9cc894e14f7f)           |

## Configuration

### Prerequisites / Dependencies

Before proceeding, ensure you are using Windows 10 or above.

Additionally, make sure you have [Wireshark](https://www.wireshark.org/) (v4.2.8) installed on your system.

Furthermore, for packet sniffing functionality, you'll require either [Npcap](https://nmap.org/npcap/) or [Winpcap](https://www.winpcap.org/).<br />
It's worth noting that this step can be omitted as [Npcap](https://nmap.org/npcap/) is already included by default within the [Wireshark](https://www.wireshark.org/) installation.

### Editing Settings

To edit the script settings, open the `Settings.ini` file.<br>
This file is created upon the first script launch and automatically updates thereafter.

Please note that any changes made to the file will take effect only after restarting the script.<br>
If you're unsure about a specific setting, set its value to None. The script will analyze the file and regenerate it if errors are found.

For detailed explanations of each setting, please refer to the sections below.

#### <CAPTURE_TSHARK_PATH>
The full path to your "tshark.exe" executable.<br>
If not set, it will attempt to detect tshark from your Wireshark installation.

#### <CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT>
Allows you to skip the network interface selection by automatically<br>
using the `<CAPTURE_INTERFACE_NAME>`, `<CAPTURE_IP_ADDRESS>` and `<CAPTURE_MAC_ADDRESS>` settings.

#### <CAPTURE_INTERFACE_NAME>
The network interface from which packets will be captured.

#### <CAPTURE_IP_ADDRESS>
The IP address of a network interface on your computer from which packets will be captured.<br>
If the `<CAPTURE_ARP>` setting is enabled, it can be from any device on your home network.
Valid example value: "x.x.x.x"

#### <CAPTURE_MAC_ADDRESS>
The MAC address of a network interface on your computer from which packets will be captured.<br>
If the `<CAPTURE_ARP>` setting is enabled, it can be from any device on your home network.<br>
Valid example value: "xx:xx:xx:xx:xx:xx" or "xx-xx-xx-xx-xx-xx"

#### <CAPTURE_ARP>
Allows you to capture from devices located outside your computer but within your home network, such as gaming consoles.

#### <CAPTURE_BLOCK_THIRD_PARTY_SERVERS>
Determine if you want or not to block the annoying IP ranges from servers that shouldn't be detected.

#### <CAPTURE_PROGRAM_PRESET>
A program preset that will help capturing the right packets for your program.<br>
Supported program presets are only "GTA5" and "Minecraft".<br>
Note that Minecraft only supports Bedrock Edition.<br>
Please also note that Minecraft have only been tested on PCs.<br>
I do not have information regarding it's functionality on consoles.

#### <CAPTURE_VPN_MODE>
Setting this to False will add filters to exclude unrelated IPs from the output.<br>
However, if you are scanning trough a VPN `<CAPTURE_INTERFACE_NAME>`, you have to set it to True.

#### <CAPTURE_OVERFLOW_TIMER>
This timer represents the duration between the timestamp of a captured packet and the current time.<br>
When this timer is reached, the tshark process will be restarted.<br>
Valid values include any number greater than or equal to 3.

#### <STDOUT_SHOW_ADVERTISING_HEADER>
Determine if you want or not to show the developer's advertisements in the script's display.

#### <STDOUT_SESSIONS_LOGGING>
Determine if you want to log console's output to "SessionsLogging" folder.<br>
It is synced with the console output and contains all fields.

#### <STDOUT_RESET_PORTS_ON_REJOINS>
When a player rejoins, clear their previously detected ports list.

#### <STDOUT_FIELDS_TO_HIDE>
Specifies a list of fields you wish to hide from the output.<br>
It can only hides field names that are not essential to the script's functionality.<br>
Valid values include any of the following field names:
{Settings.stdout_hideable_fields}

#### <STDOUT_DATE_FIELDS_SHOW_ELAPSED_TIME>
Shows or not the elapsed time from which a player has been captured in "First Seen", "Last Rejoin" and "Last Seen" fields.

#### <STDOUT_DATE_FIELDS_SHOW_DATE>
Shows or not the date from which a player has been captured in "First Seen", "Last Rejoin" and "Last Seen" fields.

#### <STDOUT_FIELD_SHOW_CONTINENT_CODE>
Specify whether to display the continent's ISO 2-letter code in parentheses next to the continent name.

#### <STDOUT_FIELD_SHOW_COUNTRY_CODE>
Specify whether to display the country's ISO 2-letter code in parentheses next to the country name.

#### <STDOUT_FIELD_CONNECTED_PLAYERS_SORTED_BY>
Specifies the fields from the connected players by which you want the output data to be sorted.<br>
Valid values include any field names. For example: Last Rejoin

#### <STDOUT_FIELD_DISCONNECTED_PLAYERS_SORTED_BY>
Specifies the fields from the disconnected players by which you want the output data to be sorted.<br>
Valid values include any field names. For example: Last Seen

#### <STDOUT_FIELD_COUNTRY_MAX_LEN>
Maximum allowed length for the "Country" field.

#### <STDOUT_FIELD_CITY_MAX_LEN>
Maximum allowed length for the "City" field.

#### <STDOUT_FIELD_CONTINENT_MAX_LEN>
Maximum allowed length for the "Continent" field.

#### <STDOUT_FIELD_REGION_MAX_LEN>
Maximum allowed length for the "Region" field.

#### <STDOUT_FIELD_ORGANIZATION_MAX_LEN>
Maximum allowed length for the "Organization" field.

#### <STDOUT_FIELD_ISP_MAX_LEN>
Maximum allowed length for the "ISP" field.

#### <STDOUT_FIELD_ASN_ISP_MAX_LEN>
Maximum allowed length for the "ASN / ISP" field.

#### <STDOUT_FIELD_AS_MAX_LEN>
Maximum allowed length for the "AS" field.

#### <STDOUT_FIELD_AS_NAME_MAX_LEN>
Maximum allowed length for the "AS Name" field.

#### <STDOUT_DISCONNECTED_PLAYERS_TIMER>
The duration after which a player will be moved as disconnected on the console if no packets are received within this time.<br>
Valid values include any number greater than or equal to 3.

#### <STDOUT_DISCONNECTED_PLAYERS_COUNTER>
The maximum number of players showing up in disconnected players list.<br>
Valid values include any number greater than or equal to 0.<br>
Setting it to 0 will make it unlimitted.

#### <STDOUT_REFRESHING_TIMER>
Minimum time interval between which this will refresh the console display.

#### <USERIP_ENABLED>
Determine if you want or not to enable detections from the UserIP databases.

### Scan trough a VPN

When using a VPN, make sure that you scan from your actual VPN interface.<br />
Additionally, ensure that in the `Settings.ini` file, the setting `<CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT>` is set to `True` value.

### Scan for a console

In order to scan for a console (PS3/PS4/PS5 and Xbox 360/Xbox One/Xbox Series X), you'll need to follow these steps:

1. Open the `Settings.ini` file.
2. If not already done, set `<CAPTURE_NETWORK_INTERFACE_CONNECTION_PROMPT>` to `True` value, so that it forces entering the "Capture network interface selection" screen at script's startup. (you can disable it later)
3. Enable the `<CAPTURE_ARP>` setting by setting its value to `True`. (This setting allows you to view all currently connected external devices within your local network in the script's "Capture network interface selection" screen)
4. Ensure that your console is currently running and **connected to internet through your PC's internet connection (Wired / Hotspot)**.
5. Start the script and wait for it to enter the "Capture network interface selection" screen.
6. Then, you'll need to identify the console's IP and MAC Address and select it accordingly.

### Resolving Country, City and ASN fields.

The script relies on [MaxMind’s GeoIP2 databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) to resolve player information.<br />
Upon startup, it automatically attempts to check for updates and downloads the latest version from the [PrxyHunter/GeoLite2](https://github.com/PrxyHunter/GeoLite2) repository.

In the event that this repository is deleted, you will need to manually download the following MaxMind GeoLite2 databases: `GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb`.<br />
You can obtain copies of these databases by signing up for GeoLite2 on the [MaxMind](https://www.maxmind.com/) official website and downloading them from there.<br />
Then you will need to create a new folder named `GeoLite2 Databases` within the script's directory, and place the database files there.

Please note that I am not allowed to publicly distribute their database in my project due to their strict [license](https://www.maxmind.com/en/site-license-overview).<br />
You must obtain it directly from [MaxMind](https://www.maxmind.com/) website.

### Resolving Mobile, Proxy and Hosting fields.

The script relies on the free [ip-api](https://ip-api.com/) API website to resolve player's "Mobile", "VPN" and "Hosting" fields.<br />
This free and limited usage allows for a maximum resolution of (100 \* 15) = 1500 IPs per minute.

## Troubleshooting

### Scanner is stuck

When the scanner is stuck at `"Scanning IPs, refreshing display in x seconds ..."`, it typically indicates one of the following situation:

- You are not currently in an online session with a minimum of 2 players.<br />
- The configuration for the script may not be set up correctly.<br />
  Please refer to [Editing Settings](#Editing-Settings) for detailed instructions.

### Some players are undetected

On GTA V, occasionally, players may go undetected, but it's crucial to emphasize that this is not specific to the script.<br />
Similar occurrences happen even with mod-menus, affecting the same individuals as those encountered with the script.<br />
This occurs because players can be connected through dedicated game servers (the exact circumstances of which I am not familiar with).<br />
Furthermore, mod menus now have the capability to enforce this connection by providing a feature for IP protection, commonly referred to as "Force Relay Connections".

### Unrelated / False Positive IPs detected

The display of unrelated IPs is possible in certain scenarios.<br />
I have made efforts to minimize this occurrence by optimizing the `CAPTURE_FILTER` and `DISPLAY_FILTER` from the source code.<br />
If you have other Peer-To-Peer applications running, such as a BitTorrent client, it may contribute to this issue.<br />
To mitigate this, I recommend closing all other Peer-To-Peer applications while using the script.

Furthermore, you can enhance the filtering process by setting `<CAPTURE_BLOCK_THIRD_PARTY_SERVERS>` to the `True` value in your `Settings.ini` file.<br />
You can also, adjust `<CAPTURE_PROGRAM_PRESET>` to correspond to the program you are scanning.<br />
These configurations help minimize the display of unrelated IPs.

### About Screen Refreshing

Refreshing the display of the script positions your terminal's cursor at the very bottom of the script.<br />
However, if you are using Windows Terminal, this issue is somewhat resolved because the view sticks to the top of the page by scrolling there initially.<br />
I would recommend using [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) for an optimal experience.

## UserIP INI databases Tutorial

### What's an UserIP database ?

In earlier versions, there was only one database `Blacklist.ini` for blacklisting users.<br>
Since [v1.1.8](https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/releases/tag/v1.1.8), you can create multiple lists with custom behaviors to suit your needs.

For example, I personally maintain four lists:

* Searchlist.ini: For people whose IPs I am searching for.
* Blacklist.ini: For individuals whose GTA5 process I want to suspend.
* Enemylist.ini: For users I want to be notified about when they join the session.
* Friendlist.ini: For users I don't want notifications for but wish to highlight in green.

Throughout the INI file, any text following a `;` or `#` symbol is treated as a comment.

Simply create a folder named `UserIP Databases` and add any *.ini files for the script to read.<br>
To create these files, follow these guidelines:

### UserIP Settings

These are settings specific for each UserIP database files configuration.

If you don't know what value to choose for a specifc setting, set it's value to None.<br>
The program will automatically analyzes this file and if needed will regenerate it if it contains errors.

#### \<ENABLED\>
Determine if you want or not to enable this UserIP database.

#### \<COLOR\>
Determine which color will be applied on the script's output for these users.
Valid values are either one of the following colors:<br>
`BLACK`, `RED`, `GREEN`, `YELLOW`, `BLUE`, `MAGENTA`, `CYAN`, `WHITE`

#### \<NOTIFICATIONS\>
Determine if you want or not to display a notification when a user is detected.

#### \<VOICE_NOTIFICATIONS\>
This setting determines the voice that will play when a user is detected or when they disconnect.<br>
Valid values are either `Male` or `Female`.<br>
Set it to `False` to disable this setting.

#### \<LOG\>
Determine if you want or not to log the user in the UserIP logging file.

#### \<PROTECTION\>
Determine if you want or not a protection when a user is found.<br>
Valid values include any of the following protections:<br>
`Suspend_Process`, `Exit_Process`, `Restart_Process`, `Shutdown_PC`, `Restart_PC`<br>
Set it to `False` value to disable this setting.

#### \<PROTECTION_PROCESS_PATH\>
The file path of the process that will be used for the `<PROTECTION>` setting.<br>
Please note that UWP apps are not supported.

#### \<PROTECTION_RESTART_PROCESS_PATH\>
The file path of the process that will be started when<br>
the `<PROTECTION>` setting is set to the `Restart_Process` value.<br>
Please note that UWP apps are not supported.

#### \<PROTECTION_SUSPEND_PROCESS_MODE\>
Specifies the duration (in seconds) for which the `<PROTECTION_PROCESS_PATH>` process will be suspended when `<PROTECTION>` is set to `Suspend_Process`.<br>

- Floating-point number: Specify a duration in seconds (e.g., 2.5 for 2.5 seconds).<br>
- `Auto`: Keep the process suspended as long as the IP is detected in the session.<br>
- `Manual`: Suspend the process indefinitely until the user manually resumes it.

### UserIP Entries

You need to list the entries under the `[UserIP]` section of the INI file in this format:<br>
`<USERNAME>=<IP>`

#### Example UserIP file:
```
[Settings]
ENABLED=True
COLOR=RED
NOTIFICATIONS=True
VOICE_NOTIFICATIONS=Male
LOG=True
PROTECTION=False
PROTECTION_PROCESS_PATH=E:\Games\GTAV\GTA5.exe
PROTECTION_RESTART_PROCESS_PATH=D:\Desktop\Grand Theft Auto V.url
PROTECTION_SUSPEND_PROCESS_MODE=Auto

[UserIP]
username1=0.0.0.0
username2=127.0.0.1
username3=255.255.255.255
```

## Tips and Tricks

### General Tips and Tricks

- You can handily zoom in or out on your terminal's output by using the keyboard shortcut `[CTRL] + [mouse scroll]` or `[CTRL] + [+]`, and `[CTRL] + [-]`.
- You can pause your terminal's output by using the keyboard shortcut `[CTRL] + [S]` and resume it with `[CTRL] + [Q]`.

### GTA V Tips and Tricks

#### Obtaining / Resolving someones IP address

- The GTA V game port is `6672`; unfortunately, I don't have any clue what the other ports mean.
- If somebody joins the session, you can obtain their IP address from the most recent entry in "connected players" list.
- If somebody leaves the session, you can obtain their IP address from the most recent entry in "disconnected players" list.
- One way to obtain someone's IP address is by saving all entries from the "connected players" list during the current session. Save each IPs under the in-game username(s) you are tracking in the `UserIP Databases\Searchlist.ini` file.
  In a future session, if you receive a notification from the searchlist database and the person you're searching for is in your session, it confirms that you have successfully obtained their IP address.
- A similar method to the above one is that you can notice when someone has been flagged as disconnected and reconnected to your session by monitoring the "Rejoins" field.<br />
  This can help you track a player who has been seen in another session, or joined your session again.
- You can invite them to your private lobby; in this case, the only IP address displayed will be that of your victim.
- You can analyze the country information. If you know your victim's country and the script shows only one person hailing from that country, it is highly likely to be them.<br />
  You can view someone's country if they have publicly provided it on their Rockstar Games Social Club profile. To do so, visit this address: https://socialclub.rockstargames.com/member/Player_Username/ and replace 'Player_Username' with their actual username.
- Most of the time, when joining a new session, the host is typically the player whose "First Seen" field in the connected players output shows the oldest date and time.
- If you're playing on PC and want to obtain someone's IP address, if they are indexed on this website, you can try using [gtaresolver.com](https://gtaresolver.com/) website to resolve someone's IP address from their in-game username.

## Contact Support

If you need assistance or have any inquiries, feel free to reach me out. I'm here to help!

- [GitHub Issues](https://github.com/Illegal-Services/GTA-V-Session-Sniffer/issues)
- [GitHub Discussions](https://github.com/Illegal-Services/GTA-V-Session-Sniffer/discussions)

You can also contact me privately via:

- Email: BUZZARDGTA@protonmail.com
- Discord: waitingforharukatoaddme
- Telegram: [@waitingforharukatoaddme](https://t.me/waitingforharukatoaddme)

## Requirements

- [Windows](https://www.microsoft.com/windows) 10 or 11 (x86/x64)
- [Wireshark](https://www.wireshark.org/) v4.2.8
- _optional:_ [MaxMind GeoLite2](https://www.maxmind.com/)
- [Npcap](https://nmap.org/npcap/) or [Winpcap](https://www.winpcap.org/)

## Credits

[@Grub4K](https://github.com/Grub4K) - General help during the source code development.<br />
[@\_txshia\_](https://instagram.com/_txshia_) - Testings of the script on Xbox One console.<br />
[@2jang](https://github.com/2jang) - Helped me fixing ARP parsing issues (https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/issues/7 and https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/pull/8)<br />
@anonymous - Testings of the script on PS5 console.<br />
@Rosalyn - Giving me the force and motivation.<br />
@Butters333 - Gived me new ideas for things to code:
  - The ability to hide the date or time, allowing users to display only the elapsed time, date, time, or any combination of these fields, depending on their preference.
  - Support for displaying any IP lookup fields in the console output and logs.

