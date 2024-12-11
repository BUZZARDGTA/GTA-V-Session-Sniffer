import time
from typing import Optional
from pypresence import Presence
from pypresence.exceptions import DiscordNotFound, PipeClosed, ResponseTimeout

DISCORD_PRESENCE_CLIENT_ID = 1313304495958261781
DISCORD_RPC_TITLE = "Sniffin' my babies IPs."
DISCORD_RPC_BUTTONS = [
    {
        "label": "GitHub Repo",
        "url": "https://github.com/BUZZARDGTA/GTA-V-Session-Sniffer"
    }
]

class DiscordRPCManager:
    """Manages Discord Rich Presence updates and connection."""

    def __init__(self):
        self.discord_rpc = Presence(DISCORD_PRESENCE_CLIENT_ID)
        self.is_connected = False
        self.start_time: Optional[int] = None
        self.last_update_time: Optional[float] = None

    def connect(self):
        """Attempts to connect to Discord RPC."""
        if self.is_connected:
            return True

        try:
            self.discord_rpc.connect()
            self.is_connected = True
        except DiscordNotFound:
            self.is_connected = False

        return self.is_connected

    def update(self, state_message: Optional[str] = None):
        """
        Attempts to update the Discord Rich Presence.

        Args:
            state_message (optional): If provided, the state message to display in Discord presence.
        """
        if not self.connect():
            return

        if self.start_time is None:
            self.start_time = int(time.time())

        try:
            self.discord_rpc.update(
                **({} if state_message is None else {"state": state_message}),
                details = DISCORD_RPC_TITLE,
                start = self.start_time,
                #large_image = "image_name",  # Name of the uploaded image in Discord app assets
                #large_text = "Hover text for large image",  # Tooltip for the large image
                #small_image = "image_name_small",  # Optional small image
                #small_text = "Hover text for small image",  # Tooltip for the small image
                buttons = DISCORD_RPC_BUTTONS
            )
        except (PipeClosed, ResponseTimeout):
            self.is_connected = False
            self.start_time = None

        self.last_update_time = time.perf_counter()