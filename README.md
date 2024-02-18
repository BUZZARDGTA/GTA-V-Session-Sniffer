# GTA V Session Sniffer

## Description

Compatible with both PC and all consoles (Playstation and Xbox).<br />
Thoroughly tested on PC, Xbox One and Playstation 3 ensuring 100% compatibility.

- Scan players who:
  - Are trying to connect.
  - Are currently connected.
  - Have left your session.

**Officially Tested and Supported Video Games\*:**

| Supported Video Games               | Officially Tested Platforms |
| :---------------------------------- | :-------------------------: |
| Grand Theft Auto 5                  |        PC, Xbox One         |
| Minecraft Bedrock Edition (Friends) |           PC, PS3           |

\*_Technically the script works for literally every P2P (Peer-To-Peer) video games.<br />
But please note that additional servers (e.g., game servers) won't be filtered from the script's output if they are not indexed within the list above_

## Advantages

- The script has a configuration file that allows for more advanced customization of its behavior.
- You can use the script without a modded video game or cracked program.
- The script is entierly **FREE TO USE** and **OPEN SOURCE**.

## Showcase

|                                                      CMD console                                                      |
| :-------------------------------------------------------------------------------------------------------------------: |
| ![CMD console](https://user-images.githubusercontent.com/62464560/211445700-4c58b314-c784-4708-880a-1375285d6066.png) |

## Configuration

### Prerequisites / Dependencies

Before proceeding, ensure you are using Windows 8 or above.

Additionally, make sure you have [Wireshark](https://www.wireshark.org/) installed on your system.

Furthermore, for packet sniffing functionality, you'll require either [Npcap](https://nmap.org/npcap/) or [Winpcap](https://www.winpcap.org/).<br />
It's worth noting that this step can be omitted as [Npcap](https://nmap.org/npcap/) is already included by default within the [Wireshark](https://www.wireshark.org/) installation.

### Manual Configuration

The script is primarily designed for automatic configuration on PCs.<br />
However, manual configuration is requiered in the following scenarios:

- You don't get it working on PC (automatic configuration failed).
- You want to scan for your console (PS3/PS4/PS5 and Xbox 360/Xbox One/Xbox Series X).

For manual configuration, modify the `Settings.ini` file as follows:

- Set `<IP_AND_MAC_ADDRESS_AUTOMATIC>` to `False` value.
- Set both `<MAC_ADDRESS>` and `<IP_ADDRESS>` to the respective addresses of your PC or console from which you want to scan for players.

_If you are curious about all the other settings that you can manually configure, you can refer to each comments in the `Settings.ini` file for deeper documentation on each setting._

### Resolving countrys

In order to resolve country information from players within the script, you need to download the MaxMind Database `GeoLite2-Country.mmdb`. Obtain a copy of this database by signing up for GeoLite2 on their website and downloading it from there.

Please note that I am not allowed to publicly distribute their database in my project due to their strict [license](https://www.maxmind.com/en/site-license-overview).<br />
You must obtain it directly from [MaxMind](https://www.maxmind.com/).

## Troubleshooting

### Scanner is stuck

When the scanner is stuck at `"Scanning IPs, refreshing display in x seconds ..."`, it typically indicates one of the following situation:

- You are not currently in an online session with a minimum of 2 players.<br />
  The scanner only updates the script's display when packets are received.<br />
  I'll try to fix this annoying behavior in a future version.
- The configuration for the script may not be set up correctly.<br />
  Please refer to [Manual Configuration](#manual-configuration) for detailed instructions.

### Players undetected

On GTA V, occasionally, players may go undetected, but it's crucial to emphasize that this is not specific to the script.<br />
Similar occurrences happen even with mod-menus, affecting the same individuals as those encountered with the script.<br />
This occurs because players can be connected through dedicated game servers (the exact circumstances of which I am not familiar with).<br />
Furthermore, mod menus now have the capability to enforce this connection by providing a feature for IP protection, commonly referred to as "Force Relay Connections".

### Unrelated / False Positive IPs detected

The display of unrelated IPs is possible in certain scenarios.<br />
I have made efforts to minimize this occurrence by optimizing the `BPF_FILTER` and `DISPLAY_FILTER` from the source code.<br />
If you have other Peer-To-Peer applications running, such as a BitTorrent client, it may contribute to this issue.<br />
To mitigate this, I recommend closing all other Peer-To-Peer applications while using the script.

Furthermore, you can enhance the filtering process by setting `<BLOCK_THIRD_PARTY_SERVERS>` to the `True` value in your `Settings.ini` file.
You can also, adjust `<PROGRAM_PRESET>` to correspond to the program you are scanning.<br />
These configurations help minimize the display of unrelated IPs.

### VPN Issues

I've observed that using a VPN on PC renders the script ineffective, as it captures only the VPN traffic itself.<br />
Unfortunately, I do not have a solution for this issue.

### About Screen Refreshing

Refreshing the display of the script positions your terminal's cursor at the very bottom of the script.<br />
This problem is kind of resolved if you are using Windows Terminal from Windows 10 or 11.<br />
I would recommend using [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) for an optimal experience.

## Contact Support

If you need assistance or have any inquiries, feel free to reach me out. I'm here to help!

- [GitHub Issues](https://github.com/Illegal-Services/GTA-V-Session-Sniffer/issues)
- [GitHub Discussions](https://github.com/Illegal-Services/GTA-V-Session-Sniffer/discussions)

You can also contact me privately via:

- Email: BUZZARDGTA@protonmail.com
- Discord: waitingforharukatoaddme
- Telegram: [@mathieudummy](https://t.me/mathieudummy)

## Requirements

- [Windows](https://www.microsoft.com/windows) 8 / 8.1 / 10 or 11 (x86/x64)
- [Wireshark](https://www.wireshark.org/)
- _optional:_ [MaxMind GeoLite2](https://www.maxmind.com/)
- [Npcap](https://nmap.org/npcap/) or [Winpcap](https://www.winpcap.org/)

## Credits

[@Grub4K](https://github.com/Grub4K) - General help during the source code development.<br />
[@\_txshia\_](https://instagram.com/_txshia_) - Testings of the script on Xbox One console.<br />
@Rosalyn - Giving me the force and motivation.<br />
