"""Cognee Community NuGet v3 (.NET Package Registry) Connector.

Provides structured ingestion of NuGet package metadata, target-framework dependencies,
upstream deprecation notices (with recommended replacement packages), and vulnerability advisories.
"""

from .nuget import (
    DOCUMENT_SOURCE_ATTR,
    NuGetDeprecationNotice,
    NuGetEndpoints,
    NuGetPackageMetadata,
    NuGetPackageVersion,
    NuGetVulnerability,
    build_nuget_auth_headers,
    discover_v3_endpoints,
    nuget_source,
    parse_catalog_entry,
    parse_project_manifest,
    parse_registration_index,
    sync_packages,
)

__all__ = [
    "DOCUMENT_SOURCE_ATTR",
    "NuGetDeprecationNotice",
    "NuGetEndpoints",
    "NuGetPackageMetadata",
    "NuGetPackageVersion",
    "NuGetVulnerability",
    "build_nuget_auth_headers",
    "discover_v3_endpoints",
    "nuget_source",
    "parse_catalog_entry",
    "parse_project_manifest",
    "parse_registration_index",
    "sync_packages",
]
