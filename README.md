<div align="center">

# Session Sniffer

![WindowsTerminal_2024-12-02_18-25](https://github.com/user-attachments/assets/ff855c9b-cbad-4381-b826-4ef2fe7560ba)

</div>

## Description

Session Sniffer is a packet sniffer (also known as an IP grabber/puller/sniffer) specifically designed for peer-to-peer (P2P) video games on PC and consoles (PlayStation and Xbox). It can identify players who:
- Are trying to connect.
- Are currently connected.
- Have left your session.
- Have rejoined your session.

## Advantages

- Unlike other similar software, it is completely **FREE TO USE** and **OPEN SOURCE**.
- Works without requiring a modded video game or cracked program.
- Includes a configuration file for advanced customization.
- Includes a setting to scan for game server(s).
- Includes a setting to fully save sessions into a log file.
- Warns you about specific user IPs upon detection.
- Protects you from specific user IPs upon detection.
- Logs specific user IPs to a file upon detection.

## Officially Supported Video Games

| Supported Video Games               | Tested Platforms  |
| :---------------------------------- | :---------------: |
| Grand Theft Auto 5                  | PC, Xbox One, PS5 |
| Minecraft Bedrock Edition (Friends) |      PC, PS3      |

Technically, the script works for literally every P2P (Peer-To-Peer) video games.<br>
However, please note that additional servers (e.g., game servers) will not be filtered from the script's output unless they are listed above.

## About Usernames Decryption/Resolving

To clarify, the script does not explicitly decrypt or resolve in-game usernames associated with IPs\*.<br>
This functionality used to be possible on old-gen consoles (PS3 and Xbox 360) but has been patched in next-gen.<br>
You can, however, manually assign a username to each IP using UserIP database files.

\*_Since v1.1.4, you can now view usernames on GTA V in real-time on PC using either ~~2Take1 /~~ Stand or Cherax mod menus:_
- ~~_[GTA_V_Session_Sniffer-plugin-2Take1-Lua](https://github.com/BUZZARDGTA/GTA_V_Session_Sniffer-plugin-2Take1-Lua)_~~ \[ARCHIVED\]<br>
- _[GTA_V_Session_Sniffer-plugin-Stand-Lua](https://github.com/BUZZARDGTA/GTA_V_Session_Sniffer-plugin-Stand-Lua)<br />_
- _[GTA_V_Session_Sniffer-plugin-Cherax-Lua](https://github.com/BUZZARDGTA/GTA_V_Session_Sniffer-plugin-Cherax-Lua)<br />_

## Requirements

- [Windows](https://www.microsoft.com/windows) 10 or 11 (x86/x64)
- [Wireshark](https://www.wireshark.org/) v4.2.9
- [Npcap](https://nmap.org/npcap/) or [Winpcap](https://www.winpcap.org/)
- _optional:_ [MaxMind GeoLite2](https://www.maxmind.com/)

## Contact Support

If you need assistance or have any inquiries, feel free to reach me out. I'm here to help!

- [GitHub Issues](https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/issues)
- [GitHub Discussions](https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer/discussions)

You can also contact me privately via:

- Email: BUZZARDGTA@protonmail.com
- Discord: waitingforharukatoaddme
- Telegram: [@waitingforharukatoaddme](https://t.me/waitingforharukatoaddme)
