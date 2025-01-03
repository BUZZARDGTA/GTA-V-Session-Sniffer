# Standard Python Libraries
from pathlib import Path
import sys

# Add the project root directory to the Python path
sys.path.append(str(Path(__file__).resolve().parents[2]))

# Local Python Libraries (Included with Project)
from Modules.utils import Version
from Modules.consts import VERSION


def generate_tag(current_version: Version):
    return f"v{current_version.major}.{current_version.minor}.{current_version.patch}-alpha/{current_version.date_time.year}.{current_version.date_time.month:02d}.{current_version.date_time.day:02d}/{current_version.date_time.hour:02d}.{current_version.date_time.minute:02d}"


if __name__ == "__main__":
    tag = generate_tag(Version(VERSION))
    print(tag)

    sys.exit(0)