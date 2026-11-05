"""NuGet v3 (.NET Package Registry) Data Source Connector for Cognee.

Table of Contents:
------------------
1. Constants & Data Structures
   - DOCUMENT_SOURCE_ATTR
   - NuGetEndpoints (@dataclass)
   - NuGetDeprecationNotice (@dataclass)
   - NuGetVulnerability (@dataclass)
   - NuGetPackageVersion (@dataclass)
   - NuGetPackageMetadata (@dataclass)
2. Auth & Service Discovery
   - build_nuget_auth_headers
   - discover_v3_endpoints
3. Project Manifest Selection (.csproj, Directory.Packages.props, packages.lock.json)
   - parse_project_manifest
4. Package Ingestion & Externalized Registration Page Parsing
   - parse_catalog_entry
   - parse_registration_index
5. Incremental Sync, Forget-on-Delete Tombstones & dlt Source
   - sync_packages
   - nuget_source
"""

import base64
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
import json
import logging
import re
from typing import Any
import xml.etree.ElementTree as ET

logger = logging.getLogger("cognee.connector.nuget")

DOCUMENT_SOURCE_ATTR = "_cognee_document_source"
DEFAULT_NUGET_INDEX_URL = "https://api.nuget.org/v3/index.json"
UNLISTED_SENTINEL_PUBLISHED = "1900-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# 1. Constants & Data Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NuGetEndpoints:
    """Dynamically resolved endpoints from the NuGet v3 service index."""

    registration_base_url: str
    search_service_url: str
    catalog_url: str


@dataclass(frozen=True)
class NuGetDeprecationNotice:
    """Upstream package deprecation warning and migration advice."""

    reasons: list[str]
    message: str
    alternate_package_id: str | None
    alternate_package_range: str | None


@dataclass(frozen=True)
class NuGetVulnerability:
    """Known security advisory linked to a package version."""

    advisory_url: str
    severity: str  # "0" (Low), "1" (Moderate), "2" (High), "3" (Critical)


@dataclass(frozen=True)
class NuGetPackageVersion:
    """Detailed metadata for a specific package release."""

    version: str
    listed: bool
    published: str
    authors: list[str]
    description: str
    license_expression: str | None
    project_url: str | None
    dependency_groups: dict[str, list[str]]
    deprecation: NuGetDeprecationNotice | None
    vulnerabilities: list[NuGetVulnerability]
    is_deleted_tombstone: bool = False


@dataclass(frozen=True)
class NuGetPackageMetadata:
    """Aggregated package documentation and catalog history."""

    package_id: str
    title: str
    description: str
    commit_id: str
    commit_timestamp: str
    total_versions_count: int
    latest_version: str
    versions: list[NuGetPackageVersion]


# ---------------------------------------------------------------------------
# 2. Auth & Service Discovery
# ---------------------------------------------------------------------------


def build_nuget_auth_headers(
    api_key: str | None = None,
    bearer_token: str | None = None,
    basic_username: str | None = None,
    basic_password: str | None = None,
    user_agent: str = "cognee-community-connector-nuget/0.1.0",
) -> dict[str, str]:
    """Construct HTTP headers for public or private NuGet v3 feeds.

    Supports X-NuGet-ApiKey, Bearer tokens (Azure Artifacts / GitHub Packages),
    and Basic authentication (BaGet / private feeds).
    """
    headers: dict[str, str] = {
        "User-Agent": user_agent,
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
    }
    if api_key:
        headers["X-NuGet-ApiKey"] = api_key
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    elif basic_username and basic_password is not None:
        raw = f"{basic_username}:{basic_password}".encode("utf-8")
        encoded = base64.b64encode(raw).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
    return headers


def discover_v3_endpoints(
    service_index_json: str | dict[str, Any],
) -> NuGetEndpoints:
    """Extract authoritative API endpoints from a NuGet v3 service index.

    Args:
        service_index_json: Raw JSON string or parsed dictionary from index.json.

    Returns:
        NuGetEndpoints dataclass.
    """
    data = json.loads(service_index_json) if isinstance(service_index_json, str) else service_index_json
    resources = data.get("resources", [])

    reg_url = ""
    search_url = ""
    catalog_url = ""

    for res in resources:
        res_type = str(res.get("@type", ""))
        res_id = str(res.get("@id", ""))

        if "RegistrationsBaseUrl/Versioned" in res_type or ("RegistrationsBaseUrl" in res_type and not reg_url):
            reg_url = res_id
        elif "SearchQueryService" in res_type and not search_url:
            search_url = res_id
        elif "Catalog/3.0.0" in res_type and not catalog_url:
            catalog_url = res_id

    reg_url = reg_url or "https://api.nuget.org/v3/registration5-gz-semver2/"
    search_url = search_url or "https://azuresearch-usnc.nuget.org/query"
    catalog_url = catalog_url or "https://api.nuget.org/v3/catalog0/index.json"

    return NuGetEndpoints(
        registration_base_url=reg_url,
        search_service_url=search_url,
        catalog_url=catalog_url,
    )


# ---------------------------------------------------------------------------
# 3. Project Manifest Selection (.csproj, Directory.Packages.props, packages.lock.json)
# ---------------------------------------------------------------------------


def parse_project_manifest(manifest_content: str, filename: str = "Project.csproj") -> list[str]:
    """Extract deduplicated NuGet package IDs from .csproj, Directory.Packages.props, or packages.lock.json.

    Args:
        manifest_content: Raw XML or JSON text of the manifest file.
        filename: Name or path of the manifest to determine format.

    Returns:
        Sorted list of unique package IDs.
    """
    content = manifest_content.strip()
    found_ids: set[str] = set()

    if filename.endswith(".json") or content.startswith("{"):
        data = json.loads(content)
        dependencies = data.get("dependencies", {})
        if isinstance(dependencies, dict):
            for _tfm, pkgs in dependencies.items():
                if isinstance(pkgs, dict):
                    for pkg_id in pkgs.keys():
                        if pkg_id.strip():
                            found_ids.add(pkg_id.strip())
        return sorted(found_ids)

    # Parse MSBuild XML (.csproj or Directory.Packages.props)
    try:
        root = ET.fromstring(content)
        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag_name in ("PackageReference", "PackageVersion"):
                pkg_id = elem.attrib.get("Include") or elem.attrib.get("Update")
                if pkg_id and pkg_id.strip():
                    found_ids.add(pkg_id.strip())
    except ET.ParseError:
        # Fallback regex for partial XML snippets
        for match in re.finditer(r'<(?:PackageReference|PackageVersion)\s+[^>]*Include=["\']([^"\']+)["\']', content):
            found_ids.add(match.group(1).strip())

    return sorted(found_ids)


# ---------------------------------------------------------------------------
# 4. Package Ingestion & Externalized Registration Page Parsing
# ---------------------------------------------------------------------------


def parse_catalog_entry(
    entry: dict[str, Any],
    listed: bool = True,
    published: str = "",
) -> NuGetPackageVersion:
    """Parse a single version leaf from a registration index or page."""
    version = str(entry.get("version", ""))
    entry_listed = entry.get("listed", listed)
    entry_published = str(entry.get("published", published))

    if entry_published.startswith("1900-01-01") or entry_listed is False:
        is_tombstone = True
        actual_listed = False
    else:
        is_tombstone = False
        actual_listed = True

    deprecation_obj = None
    raw_dep = entry.get("deprecation")
    if isinstance(raw_dep, dict):
        alt = raw_dep.get("alternatePackage", {}) or {}
        deprecation_obj = NuGetDeprecationNotice(
            reasons=[str(r) for r in raw_dep.get("reasons", [])],
            message=str(raw_dep.get("message", "")),
            alternate_package_id=alt.get("id"),
            alternate_package_range=alt.get("range"),
        )

    vulnerabilities: list[NuGetVulnerability] = []
    for vuln in entry.get("vulnerabilities", []):
        if isinstance(vuln, dict):
            vulnerabilities.append(
                NuGetVulnerability(
                    advisory_url=str(vuln.get("advisoryUrl", "")),
                    severity=str(vuln.get("severity", "")),
                )
            )

    dep_groups: dict[str, list[str]] = {}
    for group in entry.get("dependencyGroups", []):
        if isinstance(group, dict):
            tfm = str(group.get("targetFramework", "any"))
            dependencies = [
                f"{d.get('id', '')} ({d.get('range', '*')})"
                for d in group.get("dependencies", [])
                if isinstance(d, dict)
            ]
            dep_groups[tfm] = dependencies

    authors_raw = entry.get("authors", "")
    if isinstance(authors_raw, str):
        authors = [a.strip() for a in authors_raw.split(",") if a.strip()]
    elif isinstance(authors_raw, list):
        authors = [str(a).strip() for a in authors_raw if str(a).strip()]
    else:
        authors = []

    return NuGetPackageVersion(
        version=version,
        listed=actual_listed,
        published=entry_published,
        authors=authors,
        description=str(entry.get("description", "")),
        license_expression=entry.get("licenseExpression"),
        project_url=entry.get("projectUrl"),
        dependency_groups=dep_groups,
        deprecation=deprecation_obj,
        vulnerabilities=vulnerabilities,
        is_deleted_tombstone=is_tombstone,
    )


def parse_registration_index(
    registration_json: str | dict[str, Any],
    include_unlisted: bool = False,
    page_fetcher: Callable[[str], dict[str, Any]] | None = None,
    cached_page_commits: dict[str, str] | None = None,
) -> NuGetPackageMetadata:
    """Parse a package registration index document, handling both inline and externalized pages.

    Large NuGet packages externalize leaf items behind page URLs (`@id` on each registration page
    when inline `items` is absent). When `page_fetcher` is provided, only pages whose
    `commitTimeStamp` changed relative to `cached_page_commits` are fetched.

    Args:
        registration_json: JSON string or dict of registration index.
        include_unlisted: If False, unlisted/tombstoned versions are flagged as `_deleted`.
        page_fetcher: Optional callable taking a page `@id` URL and returning its parsed JSON dict.
        cached_page_commits: Optional mapping of page `@id` -> last synced `commitTimeStamp`.

    Returns:
        NuGetPackageMetadata dataclass.
    """
    data = json.loads(registration_json) if isinstance(registration_json, str) else registration_json
    pages = data.get("items", [])

    all_versions: list[NuGetPackageVersion] = []
    package_id = ""
    latest_version = ""
    commit_id = str(data.get("commitId", ""))
    commit_ts = str(data.get("commitTimeStamp", ""))
    page_cache = cached_page_commits or {}

    for page in pages:
        if not isinstance(page, dict):
            continue

        page_id = str(page.get("@id", ""))
        page_commit_ts = str(page.get("commitTimeStamp", ""))

        # Skip unchanged externalized pages if commitTimeStamp matches cached state
        if page_id and page_commit_ts and page_cache.get(page_id) == page_commit_ts and "items" not in page:
            continue

        leaves = page.get("items")
        if leaves is None and page_id and page_fetcher is not None:
            fetched_page = page_fetcher(page_id)
            leaves = fetched_page.get("items", [])

        if not isinstance(leaves, list):
            continue

        for leaf in leaves:
            if not isinstance(leaf, dict):
                continue
            cat_entry = leaf.get("catalogEntry", {})
            if isinstance(cat_entry, dict):
                if not package_id:
                    package_id = str(cat_entry.get("id", ""))
                parsed_ver = parse_catalog_entry(
                    entry=cat_entry,
                    listed=bool(leaf.get("listed", True)),
                    published=str(leaf.get("published", "")),
                )
                if not include_unlisted and parsed_ver.is_deleted_tombstone:
                    all_versions.append(parsed_ver)
                else:
                    all_versions.append(parsed_ver)
                latest_version = parsed_ver.version

    return NuGetPackageMetadata(
        package_id=package_id or "Unknown",
        title=package_id or "Unknown",
        description=all_versions[-1].description if all_versions else "",
        commit_id=commit_id,
        commit_timestamp=commit_ts,
        total_versions_count=len(all_versions),
        latest_version=latest_version,
        versions=all_versions,
    )


# ---------------------------------------------------------------------------
# 5. Incremental Sync, Forget-on-Delete Tombstones & dlt Source
# ---------------------------------------------------------------------------


def _render_searchable_document_text(pkg_id: str, v: NuGetPackageVersion) -> str:
    """Format package release metadata, deprecations, and advisories into Cognee searchable text."""
    lines = [
        f"Package: {pkg_id}@{v.version}",
        f"Description: {v.description}",
    ]
    if v.authors:
        lines.append(f"Authors: {', '.join(v.authors)}")
    if v.license_expression:
        lines.append(f"License: {v.license_expression}")
    if v.dependency_groups:
        tfms = "; ".join(f"{tfm}: {', '.join(deps) or 'none'}" for tfm, deps in v.dependency_groups.items())
        lines.append(f"Target Frameworks & Dependencies: {tfms}")
    if v.deprecation:
        alt = v.deprecation.alternate_package_id or "none"
        lines.append(
            f"DEPRECATED ({', '.join(v.deprecation.reasons)}): {v.deprecation.message} "
            f"| Recommended replacement: {alt} ({v.deprecation.alternate_package_range or '*'})"
        )
    if v.vulnerabilities:
        vulns = ", ".join(f"{vuln.advisory_url} (severity={vuln.severity})" for vuln in v.vulnerabilities)
        lines.append(f"Security Vulnerabilities: {vulns}")
    return "\n".join(lines)


def sync_packages(
    packages_data: list[dict[str, Any]],
    previous_state: dict[str, Any] | None = None,
    include_unlisted: bool = False,
    selected_package_ids: list[str] | None = None,
    deleted_catalog_ids: list[str] | None = None,
    page_fetcher: Callable[[str], dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Execute incremental synchronization with change detection and forget-on-delete tombstones.

    Args:
        packages_data: List of parsed registration dictionaries.
        previous_state: Dict storing package_id -> {commit_id, commit_timestamp, latest_version, versions}.
        include_unlisted: Whether unlisted versions should be retained as active documents.
        selected_package_ids: Optional explicit list of currently selected package IDs to detect deselections.
        deleted_catalog_ids: Optional list of package IDs with `nuget:PackageDelete` catalog events.
        page_fetcher: Optional callable to resolve externalized registration pages.

    Returns:
        Tuple of (emitted_documents: list[dict], updated_state: dict).
    """
    state: dict[str, Any] = dict(previous_state or {})
    emitted_documents: list[dict[str, Any]] = []
    seen_package_ids: set[str] = set()
    deleted_upstream = {p.lower() for p in (deleted_catalog_ids or [])}

    for pkg_dict in packages_data:
        meta = parse_registration_index(
            pkg_dict,
            include_unlisted=include_unlisted,
            page_fetcher=page_fetcher,
        )
        pkg_id = meta.package_id
        seen_package_ids.add(pkg_id)

        if pkg_id.lower() in deleted_upstream:
            emitted_documents.append({
                "id": f"nuget:{pkg_id.lower()}",
                "package_id": pkg_id,
                "version": meta.latest_version or "*",
                "_deleted": True,
            })
            state.pop(pkg_id, None)
            continue

        prev_entry = state.get(pkg_id, {})
        prev_commit = prev_entry.get("commit_timestamp", "")
        prev_commit_id = prev_entry.get("commit_id", "")

        if prev_commit and prev_commit == meta.commit_timestamp and (not prev_commit_id or prev_commit_id == meta.commit_id):
            logger.debug(f"Skipping unchanged package {pkg_id} ({prev_commit})")
            continue

        for v in meta.versions:
            is_deleted = v.is_deleted_tombstone if not include_unlisted else False
            doc: dict[str, Any] = {
                "id": f"nuget:{pkg_id.lower()}@{v.version}",
                "package_id": pkg_id,
                "version": v.version,
                "listed": v.listed,
                "published": v.published,
                "description": v.description,
                "authors": v.authors,
                "license_expression": v.license_expression,
                "project_url": v.project_url,
                "dependency_groups": v.dependency_groups,
                "deprecation": asdict(v.deprecation) if v.deprecation else None,
                "vulnerabilities": [asdict(vuln) for vuln in v.vulnerabilities],
                "text": _render_searchable_document_text(pkg_id, v),
                "_deleted": is_deleted,
            }
            emitted_documents.append(doc)

        state[pkg_id] = {
            "commit_id": meta.commit_id,
            "commit_timestamp": meta.commit_timestamp,
            "latest_version": meta.latest_version,
            "versions": [v.version for v in meta.versions],
        }

    # Emit tombstones for deselected packages or catalog deletions present in previous_state
    selected_lower = {p.lower() for p in selected_package_ids} if selected_package_ids is not None else None
    for prev_pkg_id in list(state.keys()):
        is_deselected = selected_lower is not None and prev_pkg_id.lower() not in selected_lower
        is_catalog_deleted = prev_pkg_id.lower() in deleted_upstream
        if is_deselected or is_catalog_deleted:
            prev_info = state.pop(prev_pkg_id, {})
            prev_versions = prev_info.get("versions", [prev_info.get("latest_version", "*")])
            for ver in prev_versions:
                emitted_documents.append({
                    "id": f"nuget:{prev_pkg_id.lower()}@{ver}",
                    "package_id": prev_pkg_id,
                    "version": ver,
                    "_deleted": True,
                })

    return emitted_documents, state


def nuget_source(
    packages_data: list[dict[str, Any]],
    previous_state: dict[str, Any] | None = None,
    include_unlisted: bool = False,
    selected_package_ids: list[str] | None = None,
    deleted_catalog_ids: list[str] | None = None,
    page_fetcher: Callable[[str], dict[str, Any]] | None = None,
) -> Iterable[dict[str, Any]]:
    """Pulled document-path source yielding NuGet package & version documents with merge tombstones."""
    docs, _ = sync_packages(
        packages_data=packages_data,
        previous_state=previous_state,
        include_unlisted=include_unlisted,
        selected_package_ids=selected_package_ids,
        deleted_catalog_ids=deleted_catalog_ids,
        page_fetcher=page_fetcher,
    )
    yield from docs


setattr(nuget_source, DOCUMENT_SOURCE_ATTR, True)
setattr(nuget_source, "write_disposition", "merge")
