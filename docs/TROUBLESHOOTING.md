# Troubleshooting

## Scanner is stuck

When the scanner is stuck at `"Scanning IPs, refreshing display in x seconds ..."`, it typically indicates one of the following situation:

- You are not currently in an online session with a minimum of 2 players.<br>
- The configuration for the script may not be set up correctly.<br>
  Please refer to [Editing Settings](#Editing-Settings) for detailed instructions.

## Some players are undetected

On GTA V, occasionally, players may go undetected, but it's crucial to emphasize that this is not specific to the script.<br>
Similar occurrences happen even with mod-menus, affecting the same individuals as those encountered with the script.<br>
This occurs because players can be connected through dedicated game servers (the exact circumstances of which I am not familiar with).<br>
Furthermore, mod menus now have the capability to enforce this connection by providing a feature for IP protection, commonly referred to as "Force Relay Connections".

## Unrelated / False Positive IPs detected

The display of unrelated IPs is possible in certain scenarios.<br>
I have made efforts to minimize this occurrence by optimizing the `CAPTURE_FILTER` and `DISPLAY_FILTER` from the source code.<br>
If you have other Peer-To-Peer applications running, such as a BitTorrent client, it may contribute to this issue.<br>
To mitigate this, I recommend closing all other Peer-To-Peer applications while using the script.

Furthermore, you can enhance the filtering process by setting `<CAPTURE_BLOCK_THIRD_PARTY_SERVERS>` to the `True` value in your `Settings.ini` file.<br>
You can also, adjust `<CAPTURE_PROGRAM_PRESET>` to correspond to the program you are scanning.<br>
These configurations help minimize the display of unrelated IPs.

## About Screen Refreshing

Refreshing the display of the script positions your terminal's cursor at the very bottom of the script.<br>
However, if you are using Windows Terminal, this issue is somewhat resolved because the view sticks to the top of the page by scrolling there initially.<br>
I would recommend using [Windows Terminal](https://learn.microsoft.com/en-us/windows/terminal/) for an optimal experience.