# Troubleshooting

## Scanner is stuck

When the scanner is stuck at `"Scanning IPs, refreshing display in x second ..."`, it typically indicates one of the following situations:

- You are not currently in an online session with at least one other player.
- The configuration for the script may not be set up correctly.  
  Please refer to [Script Settings Configuration](SCRIPT_CONFIGURATION.md#script-settings-configuration) for detailed instructions.
- As mentioned just below in [Some players are undetected](#some-players-are-undetected), any of the following may be causing the issue:
  - **In GTA V**, if you're using a mod menu, you might have the "Force Relay Connection" feature enabled, which is typically found in the "Protections" menu.
  - P2P traffic might be blocked by your firewall, VPN, or even ISP.

## Some players are undetected

- **In GTA V**, some players may occasionally go undetected, but it's important to note that this issue is not specific to the script as the same players may also be undetected by mod menus username IP resolving.  
  This happens because players may be connected through the dedicated game servers (details are not fully known), or they might be connected via someone else's connection as a "relay" (specifics remain unclear).  
  Additionally, on PC, some players may use features like "Force Relay Connections", which are only available through mod menus, to mask their presence by forcing their connection through the dedicated game server.
- Certain firewalls, VPNs, or even some rare Internet Service Providers (ISPs) can also block Peer-To-Peer (P2P) traffic, resulting in very few or no packets being sniffed from these players.

## Unrelated / False Positive IPs Detected

The display of unrelated IPs can occur in certain scenarios.  
Efforts have been made to to minimize this occurrence by optimizing the `CAPTURE_FILTER` and `DISPLAY_FILTER` in the source code.  
If you have other Peer-To-Peer (P2P) applications running, such as a BitTorrent client, they may contribute to this issue.  
To mitigate this, it is recommended to close all other P2P applications while using the script.

Additionally, you can enhance the filtering process by setting `<CAPTURE_BLOCK_THIRD_PARTY_SERVERS>` to `True` in your `Settings.ini` file.  
You can also adjust `<CAPTURE_PROGRAM_PRESET>` to correspond to the program you are scanning.  
These configurations help minimize the display of unrelated IPs.
Read [📖 Settings Details](SCRIPT_CONFIGURATION.md#editing-settings) for more informations about these settings.

Furthermore, if none of these solutions worked, you can manually block IPs by editing the `<CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER>` or `<CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER>`.
For example:

```ini
<CAPTURE_PREPEND_CUSTOM_CAPTURE_FILTER> = "not net 10.0.0.0/24 and not (host 10.0.0.1 or host 10.0.0.2)"
<CAPTURE_PREPEND_CUSTOM_DISPLAY_FILTER> = "ip.addr != 10.0.0.0/24 and not (ip.addr >= 10.0.0.0 and ip.addr <= 10.0.0.255) and not (ip.addr == 10.0.0.1 or ip.addr == 10.0.0.2)"
```

This capture and display filter serves as an example and demonstrates various ways to block an IP, multiple IPs, or an IP range/CIDR.

## About Screen Refreshing

Refreshing the display of the script positions your terminal's cursor at the very bottom of the script.  
However, if you are using Windows Terminal, this issue is somewhat resolved because the view sticks to the top of the page by scrolling there initially.  
I recommend using [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) for an optimal experience.
