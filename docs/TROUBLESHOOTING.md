# Troubleshooting

## Scanner is stuck

When the scanner is stuck at `"Scanning IPs, refreshing display in x seconds ..."`, it typically indicates one of the following situation:

- You are not currently in an online session with a minimum of 2 players.  
- The configuration for the script may not be set up correctly.  
  Please refer to [Script Settings Configuration](SCRIPT_CONFIGURATION.md#script-settings-configuration) for detailed instructions.

## Some players are undetected

- **In GTA V**, some players may occasionally go undetected, but it's important to note that this issue is not specific to the script as the same players may also be undetected by mod menus username IP resolving.  
  This happens because players may be connected through the dedicated game servers (details are not fully known), or they might be connected via someone else's connection as a "relay" (specifics remain unclear).  
  Additionally, on PC, some players may use features like "Force Relay Connections", which are only available through mod menus, to mask their presence by forcing their connection through the dedicated game server.
- Certain firewalls, VPNs, or even some Internet Service Providers (ISPs) can also block Peer-To-Peer (P2P) traffic, resulting in very few or no packets being sniffed from these players.

## Unrelated / False Positive IPs detected

The display of unrelated IPs is possible in certain scenarios.  
I have made efforts to minimize this occurrence by optimizing the `CAPTURE_FILTER` and `DISPLAY_FILTER` from the source code.  
If you have other Peer-To-Peer applications running, such as a BitTorrent client, it may contribute to this issue.  
To mitigate this, I recommend closing all other Peer-To-Peer applications while using the script.

Furthermore, you can enhance the filtering process by setting `<CAPTURE_BLOCK_THIRD_PARTY_SERVERS>` to the `True` value in your `Settings.ini` file.  
You can also, adjust `<CAPTURE_PROGRAM_PRESET>` to correspond to the program you are scanning.  
These configurations help minimize the display of unrelated IPs.

## About Screen Refreshing

Refreshing the display of the script positions your terminal's cursor at the very bottom of the script.  
However, if you are using Windows Terminal, this issue is somewhat resolved because the view sticks to the top of the page by scrolling there initially.  
I would recommend using [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) for an optimal experience.
