"""Cognee Community Packagist / Composer (PHP Package Registry) Connector.

Provides structured ingestion of Packagist Composer v2 metadata, version constraints,
maintainer abandonment replacement notices, PKSA security advisories, and incremental
synchronization via Packagist's /metadata/changes.json cursor feed.
"""

from .packagist import (
    DOCUMENT_SOURCE_ATTR,
    PackagistChangeAction,
    PackagistPackageMetadata,
    PackagistReleaseVersion,
    PackagistSecurityAdvisory,
    build_packagist_headers,
    expand_composer_v2_versions,
    packagist_source,
    parse_composer_manifest,
    parse_metadata_changes,
    parse_packagist_package,
    parse_security_advisories,
    sync_packagist_packages,
)

__all__ = [
    "DOCUMENT_SOURCE_ATTR",
    "PackagistChangeAction",
    "PackagistPackageMetadata",
    "PackagistReleaseVersion",
    "PackagistSecurityAdvisory",
    "build_packagist_headers",
    "expand_composer_v2_versions",
    "packagist_source",
    "parse_composer_manifest",
    "parse_metadata_changes",
    "parse_packagist_package",
    "parse_security_advisories",
    "sync_packagist_packages",
]
