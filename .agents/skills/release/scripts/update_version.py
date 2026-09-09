"""Update the Session Sniffer project version for a release."""

import argparse
import re
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

VERSION_PATTERN = re.compile(r'(?P<prefix>v\d+\.\d+\.\d+)(?:rc\.(?P<rc>\d+))?(?:\+\d{8}\.\d{4})?')

VERSION_LINE_PATTERN = re.compile(
    r"(^\s*version\s*=\s*['\"])(?P<version>[^'\"]+)(['\"])",
    re.MULTILINE,
)


class VersionNotFoundError(Exception):
    """Raised when the project version cannot be found."""

    def __init__(self) -> None:
        """Initialize the exception."""
        super().__init__('Version not found in pyproject.toml.')


class UnsupportedVersionError(Exception):
    """Raised when the project version has an unsupported format."""

    def __init__(self, version: str) -> None:
        """Initialize the exception."""
        super().__init__(f'Unsupported project version format: {version}')


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Update the Session Sniffer project version for a release.')
    parser.add_argument(
        'release_type',
        choices=('rc', 'final'),
        help='Release type to create.',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show the new version without modifying pyproject.toml.',
    )

    return parser.parse_args()


def main() -> None:
    """Update the project version with the current UTC build timestamp."""
    arguments = parse_arguments()

    project_root = Path(__file__).resolve().parents[4]
    pyproject_path = project_root / 'pyproject.toml'

    with pyproject_path.open('rb') as file:
        pyproject_data = tomllib.load(file)

    try:
        current_version = str(pyproject_data['project']['version'])
    except KeyError as error:
        raise VersionNotFoundError from error

    version_match = VERSION_PATTERN.fullmatch(current_version)

    if version_match is None:
        raise UnsupportedVersionError(current_version)

    base_version = version_match.group('prefix')
    current_rc = version_match.group('rc')

    if arguments.release_type == 'rc':
        next_rc = 1 if current_rc is None else int(current_rc) + 1
        version_without_timestamp = f'{base_version}rc.{next_rc}'
    else:
        version_without_timestamp = base_version

    utc_time = datetime.now(tz=UTC)
    timestamp = utc_time.strftime('%Y%m%d.%H%M')
    new_version = f'{version_without_timestamp}+{timestamp}'

    with pyproject_path.open('r', encoding='utf-8', newline='') as file:
        content = file.read()

    match = VERSION_LINE_PATTERN.search(content)

    if match is None:
        raise VersionNotFoundError

    updated_content = content[: match.start('version')] + new_version + content[match.end('version') :]

    output = f'Previous version: {current_version}\nNew version:      {new_version}\nUTC timestamp:    {utc_time.strftime("%Y-%m-%dT%H:%M:%SZ")}\n'

    if arguments.dry_run:
        output += 'Dry run: pyproject.toml was not modified.\n'
    else:
        with pyproject_path.open('w', encoding='utf-8', newline='') as file:
            file.write(updated_content)

    sys.stdout.write(output)


if __name__ == '__main__':
    main()
