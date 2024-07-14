# GTA V Session Sniffer

## Description

Compatible with both PC and all consoles (PlayStation and Xbox).<br />
Thoroughly tested on PC, Xbox One, PlayStation 5, and PlayStation 3 ensuring 100% compatibility.

To be clear, the script does not explicitly indicate which IP corresponds to which in-game username.<br />
This functionality used to be possible on old-gen consoles (PS3 and Xbox 360) but has been patched in next-gen consoles.

- Scan players who:
  - Are trying to connect.
  - Are currently connected.
  - Have left your session.

**Officially Tested and Supported Video Games\*:**

| Supported Video Games               | Officially Tested Platforms |
| :---------------------------------- | :-------------------------: |
| Grand Theft Auto 5                  |      PC, Xbox One, PS5      |
| Minecraft Bedrock Edition (Friends) |           PC, PS3           |

\*_Technically the script works for literally every P2P (Peer-To-Peer) video games.<br />
But please note that additional servers (e.g., game servers) won't be filtered from the script's output if they are not indexed within the list above_

## Advantages

- The script has a configuration file that allows for more advanced customization of its behavior.
- You can use the script without a modded video game or cracked program.
- The script is entirely **FREE TO USE** and **OPEN SOURCE**.

## Showcase

|                                                          CMD console                                                           |
| :----------------------------------------------------------------------------------------------------------------------------: |
| ![CMD console](https://github.com/Illegal-Services/GTA-V-Session-Sniffer/assets/62464560/bced180a-c4a6-4bba-929d-9a265f91dcf9)

## Configuration

### Prerequisites / Dependencies

Before proceeding, ensure you are using Windows 8 or above.

Additionally, make sure you have [Wireshark](https://www.wireshark.org/) installed on your system.

Furthermore, for packet sniffing functionality, you'll require either [Npcap](https://nmap.org/npcap/) or [Winpcap](https://www.winpcap.org/).<br />
It's worth noting that this step can be omitted as [Npcap](https://nmap.org/npcap/) is already included by default within the [Wireshark](https://www.wireshark.org/) installation.

### Editing Settings

In order to edit the settings from the script you only have to open the file `Settings.ini`.<br />
It is generated the first time you launch the script and is automatically updated thereafter.<br />
However, the settings are only refreshed upon script startup.<br />
Therefore, if you've made any changes and wish to apply them, you'll need to restart the script.

_If you are curious about all the settings that you can manually configure, you can refer to each comments in the `Settings.ini` file for deeper documentation on each setting._

### Scan trough a VPN

When using a VPN, make sure that you scan from your actual VPN interface.<br />
Additionally, ensure that in the `"Settings.ini"` file, the setting `<NETWORK_INTERFACE_CONNECTION_PROMPT>` is set to `True` value.

### Scan for a console

In order to scan for a console (PS3/PS4/PS5 and Xbox 360/Xbox One/Xbox Series X), you'll need to follow these steps:

1. Open the `"Settings.ini"` file.
2. If not already done, set `<NETWORK_INTERFACE_CONNECTION_PROMPT>` to `True` value, so that it forces entering the "Capture network interface selection" screen at script's startup. (you can disable it later)
3. Enable the `<ARP>` setting by setting its value to `True`. (This setting allows you to view all currently connected external devices within your local network in the script's "Capture network interface selection" screen)
4. Ensure that your console is currently running and **connected to internet through your PC's internet connection (Wired / Hotspot)**.
5. Start the script and wait for it to enter the "Capture network interface selection" screen.
6. Then, you'll need to identify the console's IP and MAC Address and select it accordingly.

### Resolving Country, City and ASN fields.

The script relies on [MaxMind’s GeoIP2 databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) to resolve player information.<br />
Upon startup, it automatically attempts to check for updates and downloads the latest version from the [PrxyHunter/GeoLite2](https://github.com/PrxyHunter/GeoLite2) repository.

In the event that this repository is deleted, you will need to manually download the following MaxMind GeoLite2 databases: `GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb` and `GeoLite2-Country.mmdb`.<br />
You can obtain copies of these databases by signing up for GeoLite2 on the [MaxMind](https://www.maxmind.com/) official website and downloading them from there.<br />
Then you will need to create a new folder named "GeoLite2 Databases" within the script's directory, and place the database files there.

Please note that I am not allowed to publicly distribute their database in my project due to their strict [license](https://www.maxmind.com/en/site-license-overview).<br />
You must obtain it directly from [MaxMind](https://www.maxmind.com/) website.

### Resolving Mobile, Proxy and Hosting fields.

The script relies on the free [ip-api](https://ip-api.com/) API website to resolve player's "Mobile", "Proxy/VPN/Tor" and "Hosting/Data Center" fields.<br />
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

Furthermore, you can enhance the filtering process by setting `<BLOCK_THIRD_PARTY_SERVERS>` to the `True` value in your `Settings.ini` file.<br />
You can also, adjust `<PROGRAM_PRESET>` to correspond to the program you are scanning.<br />
These configurations help minimize the display of unrelated IPs.

### About Screen Refreshing

Refreshing the display of the script positions your terminal's cursor at the very bottom of the script.<br />
However, if you are using Windows Terminal on Windows 10 or 11, this issue is somewhat resolved because the terminal sticks to the top of the page by scrolling there initially.<br />
I would recommend using [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) for an optimal experience.

## Tips and Tricks

### General Tips and Tricks

- You can handily zoom in or out on your terminal's output by using the keyboard shortcut `[CTRL] + [mouse scroll]` or `[CTRL] + [+]`, and `[CTRL] + [-]`.
- You can pause your terminal's output by using the keyboard shortcut `[CTRL] + [S]` and resume it with `[CTRL] + [Q]`.
- The port in [brackets] is the first detected, while the <ins>underlined</ins> is the last detected.
- Using my other project [PC Blacklist Sniffer](https://github.com/Illegal-Services/PC-Blacklist-Sniffer) allows you to detect people you blacklisted from your sessions.
- If you want to know more information about a specific IP or Port, I'd recommend you to check out the [Illegal Services](https://illegal-services.com/) application IP Lookup / Port Scanning.<br />

### GTA V Tips and Tricks

#### Obtaining / Resolving someones IP address

- The GTA V game port is `6672`; unfortunately, I don't have any clue what the other ports mean.
- If somebody joins the session, you can obtain their IP address from the most recent entry in "connected players" list.
- If somebody leaves the session, you can obtain their IP address from the most recent entry in "disconnected players" list.
- One way to obtain someone's IP address is to save all entries from "connected players" list during the current session while they are connected to your session.<br />
  When you find that person in another session, do the same thing and compare the "connected players" list, if an IP address matches, it likely means you've obtained their IP address.
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

- [Windows](https://www.microsoft.com/windows) 8 / 8.1 / 10 or 11 (x86/x64)
- [Wireshark](https://www.wireshark.org/)
- _optional:_ [MaxMind GeoLite2](https://www.maxmind.com/)
- [Npcap](https://nmap.org/npcap/) or [Winpcap](https://www.winpcap.org/)

## Credits

[@Grub4K](https://github.com/Grub4K) - General help during the source code development.<br />
[@\_txshia\_](https://instagram.com/_txshia_) - Testings of the script on Xbox One console.<br />
@anonymous - Testings of the script on PS5 console.<br />
@Rosalyn - Giving me the force and motivation.<br />
