TITLE = "Session Sniffer"
VERSION = "v1.3.0 - 03/01/2024 (20:30)"
USER_SHELL_FOLDERS_REG_KEY = R"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
USERIP_INI_SETTINGS_LIST = ["ENABLED", "COLOR", "NOTIFICATIONS", "VOICE_NOTIFICATIONS", "LOG", "PROTECTION", "PROTECTION_PROCESS_PATH", "PROTECTION_RESTART_PROCESS_PATH", "PROTECTION_SUSPEND_PROCESS_MODE"]
WIRESHARK_RECOMMENDED_FULL_VERSION = "TShark (Wireshark) 4.2.9 (v4.2.9-0-g2acaabc9099c)."
WIRESHARK_RECOMMENDED_VERSION_NUMBER = "4.2.9"
WIRESHARK_REQUIRED_DL = "https://www.wireshark.org/download/win64/"
GITHUB_RELEASE_API__GEOLITE2 = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest"
GITHUB_RELEASE_API__GEOLITE2__BACKUP = "https://api.github.com/repos/PrxyHunter/GeoLite2/releases/latest"
GUI_COLUMN_HEADERS_TOOLTIP_MAPPING = {
    "Usernames": "Displays the username(s) of players from your UserIP database files.\n\nFor GTA V PC users who have used the Session Sniffer mod menu plugin,\nit automatically resolves usernames while the plugin is running,\nor shows previously resolved players that were seen by the plugin.",
    "First Seen": "The very first time the player was observed across all sessions.",
    "Last Rejoin": "The most recent time the player rejoined your session.",
    "Last Seen": "The most recent time the player was active in your session.",
    "Rejoins": "The number of times the player has left and joined again your session across all sessions.",
    "T. Packets": "The total number of packets exchanged by the player across all sessions.",
    "Packets": "The number of packets exchanged by the player during the current session.",
    "PPS": "The number of Packets Per Second exchanged by the player.",
    "IP Address": "The IP address of the player.",
    "Last Port": "The port used by the player's last captured packet.",
    "Intermediate Ports": "The ports used by the player between the first and last captured packets.",
    "First Port": "The port used by the player's first captured packet.",
    "Continent": "The continent of the player's IP location.",
    "Country": "The country of the player's IP location.",
    "Region": "The region of the player's IP location.",
    "R. Code": "The region code of the player's IP location.",
    "City": "The city associated with the player's IP location (typically representing the ISP or an intermediate location, not the player's home address city).",
    "District": "The district of the player's IP location.",
    "ZIP Code": "The ZIP/postal code of the player's IP location.",
    "Lat": "The latitude of the player's IP location.",
    "Lon": "The longitude of the player's IP location.",
    "Time Zone": "The time zone of the player's IP location.",
    "Offset": "The time zone offset of the player's IP location.",
    "Currency": "The currency associated with the player's IP location.",
    "Organization": "The organization associated with the player's IP address.",
    "ISP": "The Internet Service Provider of the player's IP address.",
    "ASN / ISP": "The Autonomous System Number or Internet Service Provider of the player.",
    "AS": "The Autonomous System code of the player's IP.",
    "ASN": "The Autonomous System Number name associated with the player's IP.",
    "Mobile": "Indicates if the player is using a mobile network (e.g., through a cellular hotspot or mobile data).",
    "VPN": "Indicates if the player is using a VPN, Proxy, or Tor relay.",
    "Hosting": "Indicates if the player is using a hosting provider (similar to VPN).",
}