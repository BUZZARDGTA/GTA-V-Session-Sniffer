# Standard Python Libraries
from pathlib import Path

# Local Python Libraries (Included with Project)
from Modules.utils import get_documents_folder, resource_path

CHERAX__PLUGIN__LOG_PATH = get_documents_folder() / "Cherax/Lua/GTA_V_Session_Sniffer-plugin/log.txt"
TTS_PATH = resource_path(Path("TTS/"))