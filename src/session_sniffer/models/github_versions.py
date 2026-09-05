"""Pydantic models for GitHub Versions API responses.

This module provides validation for the version checking API response
from the Session-Sniffer versions endpoint.
"""

from packaging.version import Version
from pydantic import BaseModel


class VersionInfo(BaseModel):
    """Model for individual version information."""

    version: str
    release_url: str
    download_url: str
    sha256: str
    file_size: int | None = None
    is_prerelease: bool = False

    @property
    def is_release_prerelease(self) -> bool:
        """Return True if this version represents a pre-release."""
        return self.is_prerelease or Version(self.version).is_prerelease


class GithubVersionsResponse(BaseModel):
    """Model for the complete GitHub versions API response.

    Used to validate the versions JSON response published for Session Sniffer releases.
    """

    latest_stable: VersionInfo
    latest_prerelease: VersionInfo
